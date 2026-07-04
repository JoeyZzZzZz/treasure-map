# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Triage read view — rank atlas candidate instances for manual reverse-engineering.

Pure read path over the atlas: it selects instances, computes a deterministic
review-ordering score from already-stored neutral fields, and presents each
candidate with a human-actionable review status and its evidence_ref anchor.

The score orders how much a candidate warrants manual reverse-engineering; it is a
review-ordering signal only (NOT a security judgment), it is never written back to
the atlas, and it never alters the stored reachability_status (a mechanism state).
The review-status words (to-verify / reachable / gated) are a presentation-only
relabel of the raw schema values (unknown / confirmed / blocked); the underlying
field is untouched.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# Presentation-only relabel of the raw reachability_status schema values. This maps the
# mechanism state to a word the reviewer can act on; it is NEVER written back to the atlas
# and the stored field keeps its original confirmed/blocked/unknown value.
REVIEW_STATUS_BY_REACHABILITY: dict[str, str] = {
    "confirmed": "reachable",  # a clean source->sink flow was seen within one function
    "unknown": "to-verify",  # the triage body: a lead that warrants manual reverse-engineering
    "blocked": "gated",  # a filter/guard was identified on the path (likely dormant/false)
}

# --- review-ordering weight table (deterministic; ordering signal only, never stored) ---
# All inputs are existing neutral fields. The status gaps are intentionally larger than the
# total spread of the fine signals, so a pure score-descending order keeps the tiers stacked
# (every reachable above every to-verify above every gated) while the fine signals rank
# candidates WITHIN a tier. None of these weights is a security claim — they order review.
_STATUS_WEIGHT: dict[str, float] = {"confirmed": 6.0, "unknown": 3.0, "blocked": 0.0}

# A filter on the path (blocking_mechanism set) lowers review order — it is more likely
# already-mitigated. No identified filter raises it.
_FILTER_ABSENT_WEIGHT = 0.5
_FILTER_PRESENT_WEIGHT = -0.5

# Specific neutral form notes (also stored in blocking_mechanism) that name a structural shape
# manual review found rarely carries a live issue: an exec sink that bypasses the shell, a
# numeric validator on the path, or a constant supplied by the sole caller. They downweight much
# harder than a generic filter so the form sinks to the bottom of its tier — but it STAYS a listed
# candidate (never removed, never graded blocked). Each maps a mechanism to ordering, not judgment.
_FORM_DOWNWEIGHT: dict[str, float] = {
    "no_shell_exec": -2.0,
    "numeric_sanitized": -2.0,
    "caller_constant": -2.5,
    # the sink's dangerous argument is a fixed .rodata string constant (not a controllable value)
    "const_sink_arg": -2.5,
    # the value reaching the sink was constrained to a safe character set (MAC/IP/base64 form)
    "charset_constrained": -2.0,
    # a dangerous sink with no recognized in-function source (the recall fallback): listed for
    # completeness but ranked low — the controlled input, if any, was not seen reaching it here.
    "bare_sink": -1.5,
    # copy-sink size-source notes: the write length was shown bounded, so the copy is a low-yield
    # form. A literal / sizeof length is non-controllable (demote hard, like a constant arg); a
    # clamp / pointer guard only REFERENCES the length (coverage unjudged — demote mildly so the
    # candidate stays visible, never buried). A variable / source-length / untraced length gets NO
    # note and keeps its normal rank (a copy not proven bounded is never silently downweighted).
    "const_size": -2.5,
    "sizeof_bound": -2.5,
    "clamp_size": -1.0,
    "pointer_guard_size": -1.0,
}


def _filter_weight(blocking_mechanism: str | None) -> float:
    """Review-order contribution of the path-guard / form field. No mechanism raises order; a
    recognized low-yield form downweights hard; any other identified guard downweights mildly."""
    if blocking_mechanism is None:
        return _FILTER_ABSENT_WEIGHT
    return _FORM_DOWNWEIGHT.get(blocking_mechanism, _FILTER_PRESENT_WEIGHT)


# Code provenance: custom code is likelier to hold a fresh lead; recognized stock OSS is a
# known component, not a new lead. vendor_modified_oss / unknown are neutral.
_ORIGIN_WEIGHT: dict[str, float] = {
    "custom": 0.4,
    "stock_oss_known": -0.6,
    "vendor_modified_oss": 0.0,
    "unknown": 0.0,
}

# Input source class as stored on the pattern. A recognized external-input shape ranks above
# an unclassified one. (The strong/weak source split is not persisted on the instance, so the
# stored source_class is the only signal available here.)
_SOURCE_CLASS_WEIGHT: dict[str, float] = {"external_input": 0.3}

# Sink class, ordered by the operation the sink performs (command execution and format-string
# injection — both RCE-class interpreters — above buffer copy above string formatting). This is an
# ordering weight, not a magnitude-of-harm claim.
_SINK_CLASS_WEIGHT: dict[str, float] = {"cmd": 0.4, "fmt_string": 0.4, "copy": 0.2, "format": 0.0}

# Entry-reach: whether a rootfs entry point (a startup/maintenance script, a web asset) was found
# to invoke this candidate's binary (derived from the L0.5 script_calls / web_endpoints evidence,
# carried in flow_evidence.entry_reach). A proven entry path PROMOTES a candidate within its tier
# so a network/script-reachable sink surfaces above a same-class same-status local-only one. It is
# a SECOND-LEVEL key, deliberately smaller than the sink-class gap, so it never reverses the
# status or sink-class order. ★ Asymmetric on purpose: only ``found`` promotes; ``unknown`` is
# strictly neutral and NEVER demotes — an unknown may just be a coverage gap (no script parsed
# that calls the binary), and demoting it could bury a real lead. Promote-proven, never punish.
_ENTRY_REACH_WEIGHT: dict[str, float] = {"found": 0.15}


def _bounds() -> tuple[float, float]:
    """Min/max possible raw score, derived from the weight tables (for [0,1] display scaling)."""
    fine_lo = (
        min(_FILTER_PRESENT_WEIGHT, *_FORM_DOWNWEIGHT.values())
        + min(_ORIGIN_WEIGHT.values())
        + min(0.0, *_SOURCE_CLASS_WEIGHT.values())
        + min(_SINK_CLASS_WEIGHT.values())
    )
    fine_hi = (
        _FILTER_ABSENT_WEIGHT
        + max(_ORIGIN_WEIGHT.values())
        + max(0.0, *_SOURCE_CLASS_WEIGHT.values())
        + max(_SINK_CLASS_WEIGHT.values())
        + max(0.0, *_ENTRY_REACH_WEIGHT.values())  # entry-reach only promotes (never negative)
    )
    return min(_STATUS_WEIGHT.values()) + fine_lo, max(_STATUS_WEIGHT.values()) + fine_hi


_SCORE_LO, _SCORE_HI = _bounds()


@dataclass(frozen=True)
class TriageCandidate:
    """One ranked candidate for manual review. A lead, never a confirmed result.

    score is a deterministic review-ordering value in [0, 1] (higher = warrants
    reverse-engineering sooner); review_status is the presentation relabel; reachability_status
    is the untouched raw schema value.
    """

    score: float
    review_status: str
    reachability_status: str
    function: str | None
    sink_anchor: str | None
    source_class: str
    sink_class: str
    blocking_mechanism: str | None
    origin: str
    source_run_id: str | None
    evidence_ref: str | None
    # Which binary to open in the decompiler. Read straight from the atlas (NOT a read-time
    # join back to analysis.db), so a candidate is locatable even when the source build is gone.
    binary_path: str | None
    # entry-reach status (found / unknown) parsed from the stored flow_evidence — a derived,
    # evidence-backed signal, NOT a verdict. found promotes within the tier; unknown is neutral.
    entry_reach: str = "unknown"
    # source_kind (free_string / charset_safe / charset_maybe / unknown) parsed from the stored
    # flow_evidence — the FINE-GRAINED controllability signal the coarse source_class folds away
    # (free_string = a free, controllable string reached the sink argument). Surfaced so a consumer
    # can tell a genuinely controllable source from a globals/constant forward; it is a read-only
    # fact, NOT a verdict, and it never affects the score (source_class alone drives ordering).
    # ``unknown`` when the evidence is absent or carries no source_kind.
    source_kind: str = "unknown"
    # The pattern's structural fingerprint (the same key cross_firmware_patterns / pattern_density
    # group by), surfaced so a consumer can pivot from a recurring pattern to its instances. A
    # presentation-only field — it never affects the score or ordering.
    structural_fingerprint: str | None = None


def _entry_reach_status(flow_evidence: str | None) -> str:
    """Parse ``entry_reach.status`` from the stored flow_evidence JSON; ``unknown`` when absent.

    Conservative: any missing/unparsable evidence or absent entry_reach reports ``unknown`` (a
    coverage gap, never "unreachable"), so the asymmetric scorer leaves it untouched."""
    if not flow_evidence:
        return "unknown"
    try:
        data = json.loads(flow_evidence)
    except (ValueError, TypeError):
        return "unknown"
    reach = data.get("entry_reach") if isinstance(data, dict) else None
    if isinstance(reach, dict) and reach.get("status") == "found":
        return "found"
    return "unknown"


def _source_kind_from_evidence(flow_evidence: str | None) -> str:
    """Surface ``source_kind`` from the stored flow_evidence JSON; ``unknown`` when absent.

    A pure read of the value the evidence layer already recorded (free_string / charset_safe /
    charset_maybe / unknown) — this does NOT recompute the classification, it only exposes it.
    Conservative: any missing / unparsable evidence, or an absent / non-string source_kind, reports
    ``unknown`` (never fabricates a class)."""
    if not flow_evidence:
        return "unknown"
    try:
        data = json.loads(flow_evidence)
    except (ValueError, TypeError):
        return "unknown"
    kind = data.get("source_kind") if isinstance(data, dict) else None
    return kind if isinstance(kind, str) and kind else "unknown"


def _sink_provenance_records(flow_evidence: str | None) -> list[dict[str, Any]]:
    """The full sink_arg_provenance list (Ghidra def-use fact) from the stored flow_evidence.

    A pure read of what the analysis layer already recorded; empty list when the evidence is
    absent, unparsable, or carries no provenance. Never recomputes or invents provenance."""
    if not flow_evidence:
        return []
    try:
        data = json.loads(flow_evidence)
    except (ValueError, TypeError):
        return []
    prov = data.get("sink_arg_provenance") if isinstance(data, dict) else None
    if not isinstance(prov, list):
        return []
    return [r for r in prov if isinstance(r, dict)]


def _sink_provenance_summary(flow_evidence: str | None) -> tuple[dict[str, Any], ...]:
    """Per-sink summary of sink_arg_provenance (summary-first: the FULL writer/vararg detail is
    fetched on demand via ``get_sink_provenance``, so a multi-sink candidate never blows the token
    budget). One compact dict per sink: idx / name / addr / kind / resolved / writer_count? /
    nearest_dominating_writer?. A surfaced fact only — never a verdict, never a score input."""
    out: list[dict[str, Any]] = []
    for rec in _sink_provenance_records(flow_evidence):
        prov = rec.get("provenance")
        prov = prov if isinstance(prov, dict) else {}
        kind = prov.get("kind", "unknown")
        summary: dict[str, Any] = {
            "sink_idx": rec.get("sink_idx"),
            "sink": rec.get("sink"),
            "sink_addr": rec.get("sink_addr"),
            "kind": kind,
            # "resolved" states only whether def-use reached a concrete origin; a false value is an
            # honest boundary marker, NEVER a downweight or a "safe" verdict.
            "resolved": kind not in ("indirect_unresolved", "unresolved"),
        }
        if "writer_count" in prov:
            summary["writer_count"] = prov.get("writer_count")
        writers = prov.get("writers")
        if isinstance(writers, list):
            # How many writers are on EVERY path to the sink (sound CHK-dominating). Distinguishes
            # "already resolved to 1-3 dominating writers" from the raw writer_count, which also
            # counts the mutually-exclusive branch writers (noise) — a high writer_count with a low
            # dominating_writer_count is resolved, not ambiguous.
            summary["dominating_writer_count"] = sum(
                1 for w in writers if isinstance(w, dict) and w.get("dominates_sink")
            )
        if prov.get("nearest_dominating_writer"):
            ndw = prov.get("nearest_dominating_writer")
            summary["nearest_dominating_writer"] = ndw
            # Inline ONLY the nearest dominating writer's format string: an all-constant fmt is
            # often judgeable (not controllable) with zero extra fetch; one fmt stays compact.
            if isinstance(writers, list):
                for w in writers:
                    if isinstance(w, dict) and w.get("writer") == ndw and w.get("fmt") is not None:
                        summary["nearest_dominating_writer_fmt"] = w.get("fmt")
                        break
        out.append(summary)
    return tuple(out)


def _fmt_arity(fmt: str) -> int:
    """Number of arguments a printf-style format string consumes: one per conversion specifier
    (``%%`` excluded), plus one for each ``*`` width/precision taken from an argument. Mirrors the
    ExportFunctions specifier scan so the read-side trim never drops a genuinely-consumed arg."""
    n = 0
    i = 0
    length = len(fmt)
    while i < length:
        if fmt[i] != "%":
            i += 1
            continue
        j = i + 1
        if j < length and fmt[j] == "%":  # literal %%
            i = j + 1
            continue
        stars = 0
        while j < length and fmt[j] in "-+ 0#":  # flags
            j += 1
        while j < length and (fmt[j].isdigit() or fmt[j] == "*"):  # width
            if fmt[j] == "*":
                stars += 1
            j += 1
        if j < length and fmt[j] == ".":  # precision
            j += 1
            while j < length and (fmt[j].isdigit() or fmt[j] == "*"):
                if fmt[j] == "*":
                    stars += 1
                j += 1
        while j < length and fmt[j] in "hljztL":  # length modifiers
            j += 1
        if j >= length:
            break
        n += 1 + stars  # the conversion char + any *-supplied width/precision
        i = j + 1
    return n


def _trim_writer_varargs(writer: dict[str, Any]) -> dict[str, Any]:
    """Drop varargs the format string never consumes. A snprintf/echo call site may pass more stack
    slots than its fmt uses (uninitialized-slot noise the decompiler surfaces); leaving them in
    reads as 'unresolved inputs' and wrongly inflates controllability. Only trims when a fmt is
    present and there are demonstrably more varargs than it consumes."""
    fmt = writer.get("fmt")
    varargs = writer.get("varargs")
    if not isinstance(fmt, str) or not isinstance(varargs, list):
        return writer
    arity = _fmt_arity(fmt)
    if len(varargs) <= arity:
        return writer
    out = dict(writer)
    out["varargs"] = varargs[:arity]
    # honest marker: args past the format's arity were dropped as fmt-unconsumed, NOT lost origin.
    out["varargs_trimmed_to_fmt_arity"] = True
    return out


def _present_provenance(prov: dict[str, Any], *, dominating_only: bool) -> dict[str, Any]:
    """Read-side presentation of a stack_buf provenance: dominating writers first (so the agent
    reads the sound ones without scanning the branch-noise tail), fmt-arity vararg trim applied, and
    optionally only the dominating writers. Non-stack_buf provenance is returned unchanged."""
    writers = prov.get("writers")
    if not isinstance(writers, list):
        return prov
    trimmed = [_trim_writer_varargs(w) if isinstance(w, dict) else w for w in writers]
    dom = [w for w in trimmed if isinstance(w, dict) and w.get("dominates_sink")]
    non = [w for w in trimmed if not (isinstance(w, dict) and w.get("dominates_sink"))]
    out = dict(prov)
    out["writers"] = dom if dominating_only else dom + non
    return out


def _present_record(rec: dict[str, Any], *, dominating_only: bool) -> dict[str, Any]:
    prov = rec.get("provenance")
    if not isinstance(prov, dict):
        return rec
    out = dict(rec)
    out["provenance"] = _present_provenance(prov, dominating_only=dominating_only)
    return out


def get_sink_provenance(
    conn: sqlite3.Connection,
    evidence_ref: str,
    sink_idx: int | None = None,
    *,
    dominating_only: bool = False,
) -> dict[str, Any]:
    """Full sink_arg_provenance detail for a candidate (the on-demand companion to the explain
    summary). Returns every sink's record when ``sink_idx`` is None, otherwise the one record with
    that idx. Writers are presented dominating-first with fmt-arity vararg trimming; pass
    ``dominating_only`` to return only the sound dominating writers. Read-only; a surfaced def-use
    fact, never a verdict. Unknown ref / idx is reported honestly, never as an empty-but-successful
    result."""
    row = conn.execute(
        "SELECT flow_evidence FROM instance WHERE evidence_ref = ? ORDER BY instance_id LIMIT 1",
        (evidence_ref,),
    ).fetchone()
    if row is None:
        return {"evidence_ref": evidence_ref, "found": False, "note": "no_such_evidence_ref"}
    records = _sink_provenance_records(row[0])
    if not records:
        return {"evidence_ref": evidence_ref, "found": False, "note": "no_sink_provenance"}
    if sink_idx is None:
        return {
            "evidence_ref": evidence_ref,
            "found": True,
            "records": [_present_record(r, dominating_only=dominating_only) for r in records],
        }
    for rec in records:
        if rec.get("sink_idx") == sink_idx:
            return {
                "evidence_ref": evidence_ref,
                "found": True,
                "sink_idx": sink_idx,
                "record": _present_record(rec, dominating_only=dominating_only),
            }
    return {
        "evidence_ref": evidence_ref,
        "found": False,
        "sink_idx": sink_idx,
        "note": "sink_idx_out_of_range",
        "available_sink_idx": [r.get("sink_idx") for r in records],
    }


def _raw_score(
    reachability_status: str,
    blocking_mechanism: str | None,
    origin: str,
    source_class: str,
    sink_class: str,
    entry_reach: str = "unknown",
) -> float:
    score = _STATUS_WEIGHT.get(reachability_status, 0.0)
    score += _filter_weight(blocking_mechanism)
    score += _ORIGIN_WEIGHT.get(origin, 0.0)
    score += _SOURCE_CLASS_WEIGHT.get(source_class, 0.0)
    score += _SINK_CLASS_WEIGHT.get(sink_class, 0.0)
    score += _ENTRY_REACH_WEIGHT.get(entry_reach, 0.0)  # found promotes; unknown -> 0 (neutral)
    return score


def review_score(
    reachability_status: str,
    blocking_mechanism: str | None,
    origin: str,
    source_class: str,
    sink_class: str,
    entry_reach: str = "unknown",
) -> float:
    """Deterministic review-ordering score in [0, 1] (ordering signal only, never stored)."""
    raw = _raw_score(
        reachability_status, blocking_mechanism, origin, source_class, sink_class, entry_reach
    )
    norm = (raw - _SCORE_LO) / (_SCORE_HI - _SCORE_LO)
    return round(min(1.0, max(0.0, norm)), 2)


def _candidate(row: sqlite3.Row) -> TriageCandidate:
    reach = row["reachability_status"]
    entry_reach = _entry_reach_status(_row_get(row, "flow_evidence"))
    return TriageCandidate(
        score=review_score(
            reach,
            row["blocking_mechanism"],
            row["origin"],
            row["source_class"],
            row["sink_class"],
            entry_reach,
        ),
        review_status=REVIEW_STATUS_BY_REACHABILITY.get(reach, reach),
        reachability_status=reach,
        function=row["source_anchor"],
        sink_anchor=row["sink_anchor"],
        source_class=row["source_class"],
        sink_class=row["sink_class"],
        blocking_mechanism=row["blocking_mechanism"],
        origin=row["origin"],
        source_run_id=row["source_run_id"],
        evidence_ref=row["evidence_ref"],
        binary_path=row["binary_path"],
        entry_reach=entry_reach,
        source_kind=_source_kind_from_evidence(_row_get(row, "flow_evidence")),
        structural_fingerprint=_row_get(row, "structural_fingerprint"),
    )


def _row_get(row: sqlite3.Row, key: str) -> str | None:
    """Read an optional column from a sqlite Row (returns None when the column is not selected)."""
    return row[key] if key in row.keys() else None


# Display order of the presentation review statuses (highest-intent first). Shared by the CLI
# renderer and the MCP candidate list so the two fold/show the same statuses.
_SECTION_ORDER = ("to-verify", "reachable", "gated")


def sink_matches(candidate: TriageCandidate, sink: str) -> bool:
    """True if a --sink value names this candidate's sink — by concrete callee (system / popen /
    syslog / strcpy …) OR by sink class (cmd / fmt_string / copy / format). Case-insensitive."""
    needle = sink.lower()
    return (candidate.sink_anchor or "").lower() == needle or candidate.sink_class.lower() == needle


def shown_statuses(status: str | None, *, include_gated: bool, sink: str | None) -> set[str]:
    """Which review statuses to display, matching the CLI triage semantics exactly.

    A --sink filter or status='all' shows every status (so a recalled-but-low sink is never hidden
    by the default fold); an explicit status shows only that one; otherwise the default shows
    to-verify + reachable, with gated folded unless include_gated."""
    if status == "all" or sink is not None:
        return set(_SECTION_ORDER)
    if status is not None:
        return {status}
    base = {"to-verify", "reachable"}
    if include_gated:
        base.add("gated")
    return base


def filter_candidates(
    candidates: list[TriageCandidate],
    *,
    sink: str | None = None,
    status: str | None = None,
    include_gated: bool = False,
) -> list[TriageCandidate]:
    """Apply the shared sink/status/include_gated filters to a ranked list (input order kept)."""
    statuses = shown_statuses(status, include_gated=include_gated, sink=sink)
    return [
        c
        for c in candidates
        if c.review_status in statuses and (sink is None or sink_matches(c, sink))
    ]


def triage(conn: sqlite3.Connection, *, run_id: str | None = None) -> list[TriageCandidate]:
    """Return atlas candidates ranked by review-ordering score (descending).

    Read-only: selects instances joined to their pattern, scores each, and sorts by score
    descending with a deterministic tie-break. Returns every candidate (gated included); the
    caller decides whether to fold the gated rows. Nothing is written back to the atlas.

    run_id, if given, restricts to one firmware run (source_run_id); otherwise all runs.
    """
    sql = (
        "SELECT i.reachability_status, i.blocking_mechanism, i.origin, i.source_anchor, "
        "i.sink_anchor, i.source_run_id, i.evidence_ref, i.binary_path, i.flow_evidence, "
        "p.source_class, p.sink_class, p.structural_fingerprint "
        "FROM instance i JOIN pattern p ON p.pattern_id = i.pattern_id"
    )
    params: list[str] = []
    if run_id is not None:
        sql += " WHERE i.source_run_id = ?"
        params.append(run_id)
    rows = conn.execute(sql, params).fetchall()
    candidates = [_candidate(r) for r in rows]
    candidates.sort(key=lambda c: (-c.score, c.function or "", c.evidence_ref or ""))
    return candidates


# ── single-candidate explanation (why the score; structure; honest bounds; where to verify) ──
#
# This view explains why a candidate ranks high and where to verify it by hand. It presents
# evidence and bounds; it does NOT declare a candidate real, does NOT claim cross-function
# reachability, and prints NO triggering input. The terminus is "a human/AI can read it and
# knows where to verify".


@dataclass(frozen=True)
class ScoreComponent:
    """One signal's contribution to the review-ordering score, with an honest mechanism note.

    weight is the exact value the signal adds in _raw_score; the components sum to the raw score
    and, normalized into [score_lo, score_hi], equal the candidate's review_score.
    """

    signal: str
    value: str
    weight: float
    note: str


@dataclass(frozen=True)
class CandidateExplanation:
    """A read-only, single-candidate analysis view. A lead with stated bounds, never a verdict."""

    candidate: TriageCandidate
    call_sequence_shape: str | None
    components: tuple[ScoreComponent, ...]
    raw_score: float
    score_lo: float
    score_hi: float
    score: float
    claims_does: tuple[str, ...]
    claims_does_not: tuple[str, ...]
    verify_steps: tuple[str, ...]
    # The source signals promoted to the explain TOP LEVEL (mirrors ``score``, which likewise
    # duplicates candidate.score): a consumer reads the top of the explain record, so the coarse
    # controllability class (source_class) and the fine one (source_kind) must be directly visible
    # here, not only nested inside ``candidate``. Both echo the same-named candidate fields.
    source_class: str
    source_kind: str
    # Summary-first sink_arg_provenance (Ghidra def-use fact) at the explain TOP LEVEL: one compact
    # entry per command/format sink in this candidate's function (idx / kind / resolved /
    # nearest_dominating_writer). The full writer + fmt + vararg detail is fetched on demand with
    # ``get_sink_provenance`` so a many-sink candidate never overruns the token budget. A surfaced
    # fact only; nothing here feeds recall, the score, or the grade.
    sink_arg_provenance_summary: tuple[dict[str, Any], ...]


def _reachability_note(status: str) -> str:
    if status == "confirmed":
        return (
            "a source->sink flow was seen WITHIN ONE function (L1 at most); NOT caller-confirmed, "
            "NOT cross-function — the tool did not trace who calls this function"
        )
    if status == "blocked":
        return "a filter/guard was identified on the in-function path (likely dormant)"
    return "not shown reachable within the function — a lead to verify, not a reachability result"


def _origin_note(origin: str) -> str:
    if origin == "custom":
        return "custom code (likelier to hold a fresh lead than a known component)"
    if origin == "stock_oss_known":
        return "recognized stock OSS — a known component, not a new lead"
    return "origin not decided (neutral)"


def _source_note(source_class: str) -> str:
    if source_class == "external_input":
        return (
            "a label that an external-input-class call appears in this function — NOT a proof the "
            "external input reaches this sink's argument"
        )
    return "source class not recognized as external input (neutral)"


def _entry_reach_note(entry_reach: str) -> str:
    if entry_reach == "found":
        return (
            "a rootfs entry point (startup/maintenance script or web asset) was found to invoke "
            "this binary — a derived, evidence-backed reachability signal (promotes within tier); "
            "NOT a proof the candidate's input arrives from that entry"
        )
    return (
        "no rootfs entry point invoking this binary was found — reported as unknown, NOT "
        "unreachable (may be a coverage gap); neutral, never lowers the order"
    )


def score_breakdown(
    reachability_status: str,
    blocking_mechanism: str | None,
    origin: str,
    source_class: str,
    sink_class: str,
    *,
    sink_anchor: str | None = None,
    entry_reach: str = "unknown",
) -> list[ScoreComponent]:
    """Itemize the score: one ScoreComponent per signal, each weight from the real tables.

    The component weights sum to _raw_score(...); normalizing that sum into [score_lo, score_hi]
    reproduces review_score(...) exactly. No item is invented — each maps to one stored field.
    """
    filter_value = "none" if blocking_mechanism is None else blocking_mechanism
    filter_weight = _filter_weight(blocking_mechanism)
    if blocking_mechanism is None:
        filter_note = (
            "no sanitizer identified on the in-function path "
            "(generic name match — may miss a custom guard)"
        )
    elif blocking_mechanism in _FORM_DOWNWEIGHT:
        filter_note = (
            f"a low-yield form was recognized ('{blocking_mechanism}'): a shape manual review "
            "found rarely carries a live issue, so it ranks low — still a listed lead, verify it"
        )
    else:
        filter_note = (
            f"a '{blocking_mechanism}'-class guard was identified "
            "(generic name match; may misjudge)"
        )
    sink_value = sink_class if sink_anchor is None else f"{sink_class} ({sink_anchor})"
    return [
        ScoreComponent(
            "reachability",
            reachability_status,
            _STATUS_WEIGHT.get(reachability_status, 0.0),
            _reachability_note(reachability_status),
        ),
        ScoreComponent("filter", filter_value, filter_weight, filter_note),
        ScoreComponent("origin", origin, _ORIGIN_WEIGHT.get(origin, 0.0), _origin_note(origin)),
        ScoreComponent(
            "source_class",
            source_class,
            _SOURCE_CLASS_WEIGHT.get(source_class, 0.0),
            _source_note(source_class),
        ),
        ScoreComponent(
            "sink_class",
            sink_value,
            _SINK_CLASS_WEIGHT.get(sink_class, 0.0),
            "the operation the sink performs (an ordering weight, not a magnitude-of-harm claim)",
        ),
        ScoreComponent(
            "entry_reach",
            entry_reach,
            _ENTRY_REACH_WEIGHT.get(entry_reach, 0.0),
            _entry_reach_note(entry_reach),
        ),
    ]


def _verify_steps(candidate: TriageCandidate) -> tuple[str, ...]:
    fn = candidate.function or "the function"
    ref = candidate.evidence_ref or "<evidence_ref>"
    sink = candidate.sink_anchor or "the sink"
    where = f" in {candidate.binary_path}" if candidate.binary_path else ""
    return (
        f"Open {fn}{where} ({ref}) in Ghidra and confirm whether the argument reaching {sink} "
        "comes from a truly externally-controllable input.",
        f"Trace callers: which functions call {fn}, and whether any passes controllable data in "
        "(cross-function flow is not done by the tool — verify by hand).",
        "Confirm the path is genuinely unsanitized (the tool's filter check is a generic name "
        "match and can miss a custom guard).",
    )


def explain_candidate(conn: sqlite3.Connection, evidence_ref: str) -> CandidateExplanation | None:
    """Return a single-candidate explanation for the instance with this evidence_ref, or None.

    Read-only. Builds the score breakdown from the real weights, the candidate structure, the
    honest claim bounds, and a manual-verification checklist. Returns None when no instance
    carries the given evidence_ref (the caller turns that into a friendly error).
    """
    rows = conn.execute(
        "SELECT i.reachability_status, i.blocking_mechanism, i.origin, i.source_anchor, "
        "i.sink_anchor, i.source_run_id, i.evidence_ref, i.binary_path, i.flow_evidence, "
        "p.source_class, p.sink_class, p.call_sequence_shape, p.structural_fingerprint "
        "FROM instance i JOIN pattern p ON p.pattern_id = i.pattern_id "
        "WHERE i.evidence_ref = ? "
        "ORDER BY i.instance_id",
        (evidence_ref,),
    ).fetchall()
    if not rows:
        return None
    if len(rows) > 1:
        # evidence_ref is meant to anchor one instance (run + function + sink); a duplicate is
        # not expected. Defend deterministically: take the lowest instance_id, never a random one.
        logger.warning(
            "evidence_ref %s matched %d instances; using the lowest instance_id",
            evidence_ref,
            len(rows),
        )
    row = rows[0]

    candidate = _candidate(row)
    components = score_breakdown(
        candidate.reachability_status,
        candidate.blocking_mechanism,
        candidate.origin,
        candidate.source_class,
        candidate.sink_class,
        sink_anchor=candidate.sink_anchor,
        entry_reach=candidate.entry_reach,
    )
    raw = sum(c.weight for c in components)
    claims_does = (
        "within one function, an external-input-class call reaches this sink with no identified "
        "sanitizer — a shape that warrants reviewing this candidate early.",
    )
    claims_does_not = (
        "confirm the caller passes a controllable value (caller / cross-function flow not done);",
        "track the external input to this sink's argument (external_input is a class label, not a "
        "trace);",
        "establish this is a real, reachable, or controllable issue — it is a lead, not a verdict.",
    )
    return CandidateExplanation(
        candidate=candidate,
        call_sequence_shape=row["call_sequence_shape"],
        components=tuple(components),
        raw_score=raw,
        score_lo=_SCORE_LO,
        score_hi=_SCORE_HI,
        score=candidate.score,
        claims_does=claims_does,
        claims_does_not=claims_does_not,
        verify_steps=_verify_steps(candidate),
        source_class=candidate.source_class,
        source_kind=candidate.source_kind,
        sink_arg_provenance_summary=_sink_provenance_summary(_row_get(row, "flow_evidence")),
    )
