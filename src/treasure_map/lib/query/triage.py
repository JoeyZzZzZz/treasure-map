# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Triage read view — a multi-dimensional, honestly-annotated map of atlas candidate instances.

Pure read path over the atlas. Each candidate is a point on the map carrying a three-state
annotation on every dimension layer (controllability / source_writability / reachability /
filtering / sink_impact / writer / completeness). There is NO collapsed score: a single composable
sort spec (``sort_candidates`` / ``apply_view``) projects the layers into a lens. The DEFAULT lens
spines on sink-impact, bands by impact x controllability, and sinks ONLY provably-safe
candidates — a '?' never sinks (the demotion iron law). Every lens rides that same iron law, so no
angle can bury a candidate by "not yet known".

Nothing here is a verdict or a written-back value; the review-status words (to-verify / reachable /
gated) remain a presentation-only relabel of the raw reachability_status, kept for the status
filter. tmap annotates facts; the security judgement is the consumer's.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import dataclass, field
from typing import Any

from treasure_map.lib.query.nvram import _web_settable
from treasure_map.lib.query.sink_impact import (
    CONSTRAINED_MARKERS,
    NVRAM_GETTERS,
    PROVABLY_CONSTANT_MARKERS,
    impact_tier,
)

logger = logging.getLogger(__name__)

# Presentation-only relabel of the raw reachability_status schema values. This maps the
# mechanism state to a word the reviewer can act on; it is NEVER written back to the atlas
# and the stored field keeps its original confirmed/blocked/unknown value.
REVIEW_STATUS_BY_REACHABILITY: dict[str, str] = {
    "confirmed": "reachable",  # a clean source->sink flow was seen within one function
    "unknown": "to-verify",  # the triage body: a lead that warrants manual reverse-engineering
    "blocked": "gated",  # a filter/guard was identified on the path (likely dormant/false)
}

# The map's default lens label + the honest phase-1 caveats. Surfaced verbatim in every candidate
# listing so a consumer never reads the map as complete: the demotion gate, the optimistic 'free',
# the nvram double-optimism, the near-always-'?' filtering, and the no-reduction contract.
DEFAULT_LENS_LABEL = (
    "current lens: sink-impact x controllability-exposure, only PROVEN-SAFE sinks leave the first "
    "screen — switchable (--sort-by / --filter / --view)"
)
PHASE1_CAVEATS: tuple[str, ...] = (
    "demotion gate ~= only provably-constant this phase; proven-blocked / filter-dominates almost "
    "never fire, so junk that is merely 'washed' is NOT sunk",
    "'free' is OPTIMISTIC: path convergence-transforms are not subtracted yet, so a value "
    "washed by inet_ntop / a whitelist / a fixed-width parse can still read as free",
    "nvram-source 'free' is doubly optimistic: web_settable proves only the KEY is web-settable, "
    "NOT that the getter->sink path is transform-free",
    "filtering is ~= always '?': tmap does a generic name-match only and cannot prove a sanitizer "
    "covers the path — it does NOT save you from reading the filter code",
    "triage RE-RANKS the view, it does not reduce candidates: only provably-safe items leave the "
    "first screen; every candidate stays listed and queryable",
)


@dataclass(frozen=True)
class Dimension:
    """One map layer's honest three-state annotation for a candidate — a FACT, never a verdict.

    ``state`` is the glyph-level three-state: ``proven`` (✓ established, ``value`` carries the
    reading), ``excluded`` (✗ established not-applicable / ruled out), ``unknown`` (? not
    established — ``note`` says what is missing and why). ``value`` is the concrete reading (e.g.
    ``free`` / ``cmd`` / ``found``); ``source`` names where it came from; ``note`` carries the
    reason for a ? or an honest caveat on a ✓. The red line: a ? is NEVER rendered as ✓ or ✗."""

    name: str
    state: str  # "proven" | "excluded" | "unknown"
    value: str
    source: str
    note: str = ""


@dataclass(frozen=True)
class TriageCandidate:
    """One candidate = a point on the map, with a three-state annotation on every dimension layer.

    A lead, never a confirmed result. There is NO collapsed score: ``dimensions`` carries the
    honest per-layer facts (controllability / source_writability / reachability / filtering /
    sink_impact / writer / completeness), and the composable sort spec (see ``sort_candidates``)
    projects them into a lens. ``review_status`` is the presentation relabel of the raw
    ``reachability_status`` schema value (both untouched, kept for the status filter).
    """

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
    # evidence-backed signal, NOT a verdict. Feeds the reachability dimension.
    entry_reach: str = "unknown"
    # source_kind (free_string / charset_safe / charset_maybe / unknown) parsed from the stored
    # flow_evidence — the FINE-GRAINED controllability signal the coarse source_class folds away.
    # Feeds the controllability dimension. ``unknown`` when the evidence carries no source_kind.
    source_kind: str = "unknown"
    # The pattern's structural fingerprint (the same key cross_firmware_patterns / pattern_density
    # group by), surfaced so a consumer can pivot from a recurring pattern to its instances.
    structural_fingerprint: str | None = None
    # The nvram key feeding the sink argument, when the def-use provenance resolved the source to an
    # nvram getter: its web-settability drives the controllability annotation. None when the
    # source is not a resolved nvram getter. A surfaced fact, never a verdict.
    nvram_source_key: str | None = None
    # The honest three-state map layers. Every dimension is a first-class, queryable /
    # sortable / filterable annotation here — NOT buried in flow_evidence JSON for the agent to dig.
    dimensions: tuple[Dimension, ...] = field(default_factory=tuple)

    def dim(self, name: str) -> Dimension:
        """The named dimension layer; a ``unknown`` placeholder if it was not computed (defensive —
        every candidate normally carries all layers)."""
        for d in self.dimensions:
            if d.name == name:
                return d
        return Dimension(name, "unknown", "unknown", "not computed")


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


# Vararg source kinds that are a CONFIRMED controllable origin (an attacker-influenceable value can
# reach the format argument). external_input/multiple are included defensively for other firmwares /
# upstream layers even though the current extractor emits call_return/param.
_CONTROLLABLE_VARARG_KINDS = frozenset({"call_return", "param", "multiple", "external_input"})
# printf conversions that consume a POINTER argument (the value is an address, its pointee unknown).
_STRING_PTR_CONVERSIONS = frozenset({"s", "p"})


def _is_hex_literal(value: Any) -> bool:
    """True if ``value`` is a 0x-form hex literal string (e.g. "0x432f"). Belt-and-suspenders for
    provenance produced before the extractor emitted value_kind: a bare 0x value is ambiguous."""
    if not isinstance(value, str) or len(value) <= 2 or value[:2].lower() != "0x":
        return False
    return all(c in "0123456789abcdefABCDEF" for c in value[2:])


def _is_ambiguous_0x(source: dict[str, Any]) -> bool:
    """True if a constant source's value is an ambiguous 0x — the extractor confirmed a constant
    value 0x… but could NOT tell an integer literal from a pointer address (DataType unavailable:
    a two-firmware probe found 0 pointers over 13162 such constants). Trusts the extractor's
    ``value_kind`` when present; falls back to detecting a bare 0x value for older provenance."""
    vk = source.get("value_kind")
    if vk == "ambiguous_0x":
        return True
    if vk == "literal_string":
        return False
    return _is_hex_literal(source.get("value"))


def _conversion_char(spec: Any) -> str | None:
    """The conversion character of a spec like "%s"/"%ld"/"%d" (the last letter), or None."""
    if not isinstance(spec, str):
        return None
    for ch in reversed(spec):
        if ch.isalpha():
            return ch.lower()
    return None


def _classify_vararg(vararg: Any) -> str:
    """Classify ONE format vararg as 'controllable' | 'const' | 'unknown' — spec-precise, honest
    about the boundary: anything not CONFIRMED constant or CONFIRMED controllable is 'unknown',
    never silently folded into constant. An ambiguous_0x constant is judged BY THE SPEC (the
    reliable oracle): an integer conversion pins it to a known integer literal; a %s/%p leaves it a
    constant pointer whose pointee is unknown; no spec leaves it undetermined. See below."""
    source = vararg.get("source") if isinstance(vararg, dict) else None
    source = source if isinstance(source, dict) else {}
    kind = source.get("kind")
    if kind in _CONTROLLABLE_VARARG_KINDS:
        return "controllable"
    if kind != "constant":
        # unresolved / indirect_unresolved / stack_buf / missing / None / anything unconfirmed:
        # not pinned to a known literal -> honest "unknown", never assumed constant.
        return "unknown"
    if not _is_ambiguous_0x(source):
        return "const"  # a confirmed literal-string constant (value known, not controllable)
    # ambiguous_0x: the SPEC, not the value, decides what the 0x means (the red line).
    conv = _conversion_char(vararg.get("spec"))
    if conv is None or conv in _STRING_PTR_CONVERSIONS:
        # %s/%p -> constant POINTER, pointee unknown -> unknown; no spec -> cannot disambiguate.
        return "unknown"
    # %d/%x/%u/%i/%c/%o/... -> a by-value spec: the 0x is a KNOWN integer literal (e.g. 0x432f).
    return "const"


def _fmt_args_provenance(fmt: Any, varargs: Any) -> str:
    """Three-state, spec-precise verdict on the format arguments of the nearest dominating writer:

    - ``all_constant``  — every vararg is a CONFIRMED literal constant (a known literal string, or
     an ambiguous_0x pinned to an integer literal by an integer spec), or the fmt consumes no
     arguments at all. Asserts only that the format arguments introduce no CONTROLLABLE injection
     (format-string / command injection); it does NOT assert the command is safe under other threat
     models (a controllable integer's overflow/length issues land in has_controllable, not here).
     Read as "arguments not controllable, no injection surface", not "harmless".
    - ``has_controllable`` — at least one vararg is a confirmed controllable source (call_return /
     param / multiple / external_input): a real controllable injection surface.
    - ``undetermined``  — at least one vararg cannot be confirmed constant AND none is confirmed
     controllable: an untraceable source (unresolved/stack_buf/missing), an ambiguous_0x under a
     %s/%p or with no spec (a constant pointer, pointee unknown), or an arity shortfall (fewer
     varargs extracted than the fmt consumes). An honest "don't know", never coerced to yes/no.

    tmap is a data substrate: each state is a FACT, never a guess, and never a score input.
    Precedence has_controllable > undetermined > all_constant — a confirmed controllable arg is the
    actionable headline even if another arg is also undetermined."""
    varargs = varargs if isinstance(varargs, list) else []
    classes = [_classify_vararg(va) for va in varargs]
    # Arity shortfall: the fmt consumes more args than were extracted -> the missing ones are
    # unknown. Never conclude "all constant" on incomplete data.
    arity = _fmt_arity(fmt) if isinstance(fmt, str) else 0
    if len(varargs) < arity:
        classes.append("unknown")
    if "controllable" in classes:
        return "has_controllable"
    if "unknown" in classes:
        return "undetermined"
    return "all_constant"


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
                        # Three-state, spec-precise: are the inlined command's format arguments
                        # constant / controllable / undetermined? Lets the agent judge the args'
                        # controllability without fetching the full writer detail.
                        summary["fmt_args_provenance"] = _fmt_args_provenance(
                            w.get("fmt"), w.get("varargs")
                        )
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


# ── nvram fact transport: recover the nvram key feeding the sink from stored provenance ──


def _nvram_key_from_source(source: Any) -> str | None:
    """The nvram key if ``source`` is a call_return from an nvram getter, else None.

    The key is the getter's first constant string argument (``const_args[0]``) — the exact shape the
    def-use extractor records for ``nvram_get("wan_proto")``. A getter with no resolved const key
    yields None (honest: the key was not recovered), never a fabricated key."""
    if not isinstance(source, dict) or source.get("kind") != "call_return":
        return None
    if source.get("callee") not in NVRAM_GETTERS:
        return None
    const_args = source.get("const_args")
    if isinstance(const_args, list) and const_args and isinstance(const_args[0], str):
        return const_args[0] or None
    return None


def _nvram_source_key(flow_evidence: str | None) -> str | None:
    """Scan the stored sink_arg_provenance for a resolved nvram-getter source and return its key.

    Looks at each sink's top-level provenance AND the varargs of its stack-buffer writers (where an
    nvram value most often enters, via ``snprintf("...%s...", nvram_get(key))``). Returns the first
    resolved key; None when no sink's value came from a recognized nvram getter."""
    for rec in _sink_provenance_records(flow_evidence):
        prov = rec.get("provenance")
        prov = prov if isinstance(prov, dict) else {}
        key = _nvram_key_from_source(prov)
        if key is not None:
            return key
        for w in prov.get("writers") or []:
            if not isinstance(w, dict):
                continue
            for va in w.get("varargs") or []:
                if isinstance(va, dict):
                    key = _nvram_key_from_source(va.get("source"))
                    if key is not None:
                        return key
    return None


def _flow_path_obj(flow_evidence: str | None) -> dict[str, Any]:
    """The stored flow_evidence.flow_path dict (sink_arg / one_hop / wrapper markers); {} when
    absent or unparsable."""
    if not flow_evidence:
        return {}
    try:
        data = json.loads(flow_evidence)
    except (ValueError, TypeError):
        return {}
    fp = data.get("flow_path") if isinstance(data, dict) else None
    return fp if isinstance(fp, dict) else {}


def _sanitizer_records(flow_evidence: str | None) -> list[dict[str, Any]]:
    """The stored flow_evidence.sanitizer_seen list; [] when absent or unparsable."""
    if not flow_evidence:
        return []
    try:
        data = json.loads(flow_evidence)
    except (ValueError, TypeError):
        return []
    san = data.get("sanitizer_seen") if isinstance(data, dict) else None
    return [s for s in san if isinstance(s, dict)] if isinstance(san, list) else []


# ── the seven map layers: each an honest three-state Dimension, never a verdict ──


def _dim_controllability(
    source_kind: str, blocking_mechanism: str | None, web_settable: dict[str, Any] | None
) -> Dimension:
    """Attacker byte-freedom over the sink argument: free / constrained / constant / unknown.

    Order (fact transport): a provably-constant marker wins (constant, the only proven-safe
    controllability this phase); else if the source is an nvram getter, combine its web-settability
    (free / constrained / unknown); else fall back to the text-level source_kind."""
    if blocking_mechanism in PROVABLY_CONSTANT_MARKERS:
        return Dimension(
            "controllability",
            "proven",
            "constant",
            f"blocking_mechanism={blocking_mechanism}",
            "provably-constant sink argument (compile-time constant, not attacker-controllable) — "
            "the only 'safe' controllability tmap asserts this phase; this is what sinks a "
            "candidate out of the first screen",
        )
    if web_settable is not None:  # source resolved to an nvram getter with a key
        st = web_settable.get("in_router_defaults")
        if st is True:
            return Dimension(
                "controllability",
                "proven",
                "free",
                "nvram source key web_settable=true (router_defaults)",
                "free via source-writability: the key IS web-settable. DOUBLE-OPTIMISTIC — proves "
                "only the source is writable, NOT that the getter->sink path is transform-free "
                "",
            )
        if st is False:
            return Dimension(
                "controllability",
                "proven",
                "constrained",
                "nvram source key not in router_defaults (located, complete)",
                "the source key is not web-settable (router_defaults located + complete)",
            )
        return Dimension(
            "controllability",
            "unknown",
            "unknown",
            "nvram source key web-settability uncertain",
            "cannot combine source-writability: router_defaults not located / incomplete — not "
            "assumed controllable nor safe",
        )
    if source_kind == "free_string":
        return Dimension(
            "controllability",
            "proven",
            "free",
            "source_kind=free_string",
            "OPTIMISTIC: convergence-transforms not subtracted — a value washed by "
            "inet_ntop / a whitelist / a fixed-width parse may still read as free",
        )
    if source_kind == "charset_safe":
        return Dimension(
            "controllability",
            "proven",
            "constrained",
            "source_kind=charset_safe",
            "sink argument built inline by a charset-safe converter (MAC / IP / base64 shape)",
        )
    if blocking_mechanism in CONSTRAINED_MARKERS:
        return Dimension(
            "controllability",
            "proven",
            "constrained",
            f"blocking_mechanism={blocking_mechanism}",
            "the value was constrained to a safe charset / numeric shape",
        )
    return Dimension(
        "controllability",
        "unknown",
        "unknown",
        f"source_kind={source_kind}",
        "controllable direction not established — NOT proven safe, NOT proven controllable; a ? "
        "never sinks",
    )


def _dim_source_writability(
    nvram_key: str | None, web_settable: dict[str, Any] | None
) -> Dimension:
    """If the source is an nvram key, can the web UI set it? web_settable / not_settable /
    table_not_located. ✗ not-applicable when the source is not a resolved nvram key."""
    if nvram_key is None or web_settable is None:
        return Dimension(
            "source_writability",
            "excluded",
            "n/a",
            "source is not a resolved nvram key",
            "web-settability applies only when the sink source is an nvram getter with a key",
        )
    st = web_settable.get("in_router_defaults")
    src = web_settable.get("source") or ""
    if st is True:
        return Dimension(
            "source_writability",
            "proven",
            "web_settable",
            f"router_defaults[{nvram_key}]",
            f"key '{nvram_key}' is a web-settable member ({src})",
        )
    if st is False:
        return Dimension(
            "source_writability",
            "excluded",
            "not_settable",
            f"router_defaults (located, complete): '{nvram_key}' absent",
            f"key '{nvram_key}' is not web-settable",
        )
    return Dimension(
        "source_writability",
        "unknown",
        "table_not_located",
        "router_defaults",
        web_settable.get("reason") or "web-settability uncertain (table not located / incomplete)",
    )


def _dim_reachability(entry_reach: str) -> Dimension:
    """Is there an external entry to this binary? found / unknown (from flow_evidence.entry_reach).
    A ? is a coverage gap, NEVER 'unreachable' — it never sinks."""
    if entry_reach == "found":
        return Dimension(
            "reachability",
            "proven",
            "found",
            "flow_evidence.entry_reach (rootfs script / web-asset invocation)",
            "a rootfs entry invokes this binary — NOT proof the input arrives from that entry",
        )
    return Dimension(
        "reachability",
        "unknown",
        "unknown",
        "flow_evidence.entry_reach",
        "no rootfs entry found — reported unknown, NOT unreachable (a coverage gap or an "
        "indirect/dispatch-table call); a ? never sinks",
    )


def _dim_filtering(flow_evidence: str | None) -> Dimension:
    """Is there sanitization on the path? Near-always '?' this phase: tmap does a generic
    name-match only and cannot prove a sanitizer covers the path, so it claims neither present
    or proven-absent — it does not save the agent from reading the filter code."""
    san = _sanitizer_records(flow_evidence)
    if any(s.get("on_path") for s in san):
        note = (
            "a sanitizer-shaped call sits on the path, but coverage is UNJUDGED (a static read "
            "cannot prove it covers the path) — still '?', read the filter code yourself"
        )
    elif san:
        note = (
            "sanitizer-shaped calls exist but none on the sink's path (generic name-match; a "
            "custom guard may still exist) — '?'"
        )
    else:
        note = (
            "no sanitizer-shaped callee recognized (generic name-match only; a custom guard may "
            "still exist) — '?', tmap does not save you from reading the filter code"
        )
    return Dimension("filtering", "unknown", "unknown", "flow_evidence.sanitizer_seen", note)


def _dim_sink_impact(sink_class: str, overrides: dict[str, int] | None = None) -> Dimension:
    """What sink is this + its potential-impact tier. The value is the OPEN-set sink_class;
    the tier is a visible, OVERRIDABLE judgement (default cmd=fmt>copy>log)."""
    tier = impact_tier(sink_class, overrides)
    tname = {3: "high", 2: "medium", 1: "low"}.get(tier, "lowest (unmapped class)")
    return Dimension(
        "sink_impact",
        "proven",
        sink_class or "unknown",
        "sink callee classification",
        f"impact tier {tier} ({tname}); default order cmd=fmt>copy>log — a visible, OVERRIDABLE "
        "judgement, not a magnitude-of-harm claim",
    )


def _dim_writer(flow_evidence: str | None) -> Dimension:
    """Who writes the sink argument's value? located / via_wrapper / not_traced, from the def-use
    provenance. A ? (not_traced) never sinks."""
    if _flow_path_obj(flow_evidence).get("sink_via_wrapper"):
        return Dimension(
            "writer",
            "proven",
            "via_wrapper",
            "flow_evidence.flow_path.wrapper",
            "the value is forwarded one hop through a thin wrapper to the real sink",
        )
    for rec in _sink_provenance_records(flow_evidence):
        prov = rec.get("provenance")
        prov = prov if isinstance(prov, dict) else {}
        if prov.get("kind") == "constant":
            return Dimension(
                "writer",
                "proven",
                "located",
                "sink_arg_provenance (constant)",
                "the sink argument resolves to a constant writer",
            )
        if prov.get("nearest_dominating_writer"):
            return Dimension(
                "writer",
                "proven",
                "located",
                f"sink_arg_provenance (dominating writer {prov.get('nearest_dominating_writer')})",
                "a sound dominating writer for the sink argument was located",
            )
    return Dimension(
        "writer",
        "unknown",
        "not_traced",
        "sink_arg_provenance",
        "no dominating writer resolved (unresolved / untraced stack buffer) — who writes the value "
        "was not established; a ? never sinks",
    )


def _dim_completeness() -> Dimension:
    """Was the containing function fully decompiled? '?' this phase: the per-function A4 signal
    lives in analysis.db, and triage is atlas-only. Honestly deferred, never faked complete."""
    return Dimension(
        "completeness",
        "unknown",
        "unknown",
        "A4 per-function decompile completeness (not wired into the atlas-only triage this phase)",
        "cross-check partially_incomplete_binaries at the listing top level (A4) for this binary — "
        "a partial binary means some of its functions never decompiled",
    )


def _build_dimensions(
    conn: sqlite3.Connection,
    *,
    flow_evidence: str | None,
    source_kind: str,
    blocking_mechanism: str | None,
    sink_class: str,
    entry_reach: str,
    nvram_key: str | None,
) -> tuple[Dimension, ...]:
    """The seven honest map layers for one candidate. web_settable is looked up once (atlas
    nvram_defaults) when the source resolved to an nvram key, and shared by two layers."""
    web_settable = _web_settable(conn, nvram_key) if nvram_key else None
    return (
        _dim_controllability(source_kind, blocking_mechanism, web_settable),
        _dim_source_writability(nvram_key, web_settable),
        _dim_reachability(entry_reach),
        _dim_filtering(flow_evidence),
        _dim_sink_impact(sink_class),
        _dim_writer(flow_evidence),
        _dim_completeness(),
    )


def _candidate(conn: sqlite3.Connection, row: sqlite3.Row) -> TriageCandidate:
    reach = row["reachability_status"]
    fe = _row_get(row, "flow_evidence")
    entry_reach = _entry_reach_status(fe)
    source_kind = _source_kind_from_evidence(fe)
    sink_class = row["sink_class"]
    blocking = row["blocking_mechanism"]
    nvram_key = _nvram_source_key(fe)
    return TriageCandidate(
        review_status=REVIEW_STATUS_BY_REACHABILITY.get(reach, reach),
        reachability_status=reach,
        function=row["source_anchor"],
        sink_anchor=row["sink_anchor"],
        source_class=row["source_class"],
        sink_class=sink_class,
        blocking_mechanism=blocking,
        origin=row["origin"],
        source_run_id=row["source_run_id"],
        evidence_ref=row["evidence_ref"],
        binary_path=row["binary_path"],
        entry_reach=entry_reach,
        source_kind=source_kind,
        structural_fingerprint=_row_get(row, "structural_fingerprint"),
        nvram_source_key=nvram_key,
        dimensions=_build_dimensions(
            conn,
            flow_evidence=fe,
            source_kind=source_kind,
            blocking_mechanism=blocking,
            sink_class=sink_class,
            entry_reach=entry_reach,
            nvram_key=nvram_key,
        ),
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


# ── composable sort spec: ONE sort function projected into lenses ──
#
# A view = {filter predicate, spine axis}. Everything else RIDES under every view, not overridable:
#  - the composite secondary key (impact x controllability-certainty), same meaning in any lens
#  - the only-UP tertiary keys (found / located / complete promote; their ? never demotes)
#  - the demotion IRON LAW: only a PROVEN-SAFE fact sinks a candidate; a ? NEVER sinks
# The agent changes only the spine (--sort-by) and the filters; the iron law is fixed. This is what
# makes every lens safe: no angle can bury a candidate by "not yet known".

_CONTROLLABILITY_RANK: dict[str, int] = {"free": 3, "constrained": 2, "unknown": 1, "constant": 0}
_REACH_RANK: dict[str, int] = {"found": 2, "unknown": 1, "blocked": 0}
_VALID_SPINES = frozenset({"impact", "sink_impact", "reachability", "controllability", "by-sink"})


def _is_proven_safe(c: TriageCandidate) -> bool:
    """Does the candidate carry a PROVEN-SAFE fact (the only thing that may sink it)?

    This phase the sole reliably-provable safe fact is a compile-time-constant controllability:
    proven-blocked reachability and filter-dominates are not computable yet. When they are,
    OR them in here — the sort and every view inherit the change with no other edit."""
    return c.dim("controllability").value == "constant"


def _sort_atoms(c: TriageCandidate, overrides: dict[str, int] | None) -> dict[str, int]:
    ctrl = c.dim("controllability").value
    reach = c.dim("reachability").value
    return {
        "proven_safe": int(_is_proven_safe(c)),
        "impact": impact_tier(c.sink_class, overrides),
        "controllability": _CONTROLLABILITY_RANK.get(ctrl, 1),
        "reach_rank": _REACH_RANK.get(reach, 1),
        "reach_promote": 1 if reach == "found" else 0,
        "writer_promote": 1 if c.dim("writer").value == "located" else 0,
        "completeness_promote": 1 if c.dim("completeness").value == "complete" else 0,
    }


def _sort_key(
    c: TriageCandidate, *, spine: str, overrides: dict[str, int] | None
) -> tuple[Any, ...]:
    a = _sort_atoms(c, overrides)
    # [0] iron law: not-safe (0) before proven-safe (1) — proven-safe always sinks, in EVERY lens.
    key: list[Any] = [a["proven_safe"]]
    # [1..] the spine (the pivot axis; negated so higher rank ranks earlier)
    if spine == "reachability":
        key.append(-a["reach_rank"])
    elif spine == "controllability":
        key.append(-a["controllability"])
    elif spine == "by-sink":
        key.append(-a["impact"])
        key.append(c.sink_class or "")  # group by exact class within a tier
    else:  # impact / sink_impact / default
        key.append(-a["impact"])
    # composite secondary (rides under every lens): band by impact, then controllability-certainty
    key.append(-a["impact"])
    key.append(-a["controllability"])
    # tertiary only-UP promotes (a proven positive lifts; its ? stays put, never demotes)
    key.append(-a["reach_promote"])
    key.append(-a["writer_promote"])
    key.append(-a["completeness_promote"])
    # deterministic tiebreak
    key.append(c.function or "")
    key.append(c.evidence_ref or "")
    return tuple(key)


def sort_candidates(
    candidates: list[TriageCandidate],
    *,
    spine: str = "impact",
    impact_overrides: dict[str, int] | None = None,
) -> list[TriageCandidate]:
    """Project the candidate map into one lens. ``spine`` picks the pivot axis (default ``impact``);
    the composite key, the only-up tertiary keys, and the demotion iron law ride under EVERY spine
    and are not overridable. ``impact_overrides`` (from ``parse_impact_order``) re-orders the impact
    tiers only — the ordering STRUCTURE (impact then controllability) stays fixed."""
    sp = spine if spine in _VALID_SPINES else "impact"
    return sorted(candidates, key=lambda c: _sort_key(c, spine=sp, overrides=impact_overrides))


_DIMENSION_NAMES = frozenset(
    {
        "controllability",
        "source_writability",
        "reachability",
        "filtering",
        "sink_impact",
        "writer",
        "completeness",
    }
)


def filter_by_dimension(
    candidates: list[TriageCandidate], dim: str, value: str
) -> list[TriageCandidate]:
    """Filter by one dimension's value: ``controllability=free`` / ``sink_impact=cmd`` /
    ``reachability=found`` / ``writer=located`` / ``source=nvram`` ... ``source=nvram`` is the
    shorthand for a resolved nvram source key. An unknown dimension name is a no-op (returns all).
    """
    v = value.lower()
    if dim == "source":
        if v == "nvram":
            return [c for c in candidates if c.nvram_source_key is not None]
        return candidates
    if dim in ("sink_impact", "sink_class", "sink"):
        return [c for c in candidates if (c.sink_class or "").lower() == v]
    if dim in _DIMENSION_NAMES:
        return [c for c in candidates if c.dim(dim).value.lower() == v]
    return candidates


# Preset lenses: {filter, spine, desc}. Each is a starting {filter, spine} plus a when-to-use note
# (``desc``) so a consumer knows which lens fits which hunting goal — the iron law + composite key
# ride under all of them. A convergence-transform ("close-the-gap") lens is deliberately deferred to
# a later phase; the value set stays open, so a new preset is one row here.
VIEWS: dict[str, dict[str, Any]] = {
    "default": {
        "filter": None,
        "spine": "impact",
        "desc": "Balanced starting lens: high-impact sinks first, controllability-certainty first "
        "within a tier. Use when you don't yet know where to look.",
    },
    "by-sink": {
        "filter": None,
        "spine": "by-sink",
        "desc": "Sweep one sink class systematically: use when walking every sink of a kind (e.g. "
        "read every system()/exec command sink). Controllable first within a class; constant junk "
        "sinks to the bottom.",
    },
    "nvram-source": {
        "filter": ("source", "nvram"),
        "spine": "impact",
        "desc": "Hunt nvram-mediated bugs — the router-bug hotspot. Only candidates whose source "
        "is an nvram getter; web_settable becomes the most informative controllability signal.",
    },
    "reachable-only": {
        "filter": ("reachability", "found"),
        "spine": "impact",
        "desc": "Prune to the web-asset-linked attack surface: only entry_reach=found candidates. "
        "NOTE this is string-level web-asset (asp) association, NOT call-graph reachability (the "
        "true reachability of an indirect/dispatch call is still '?' this phase), so this view "
        "DROPS reachability-'?' candidates that may still be reachable — do not read it as 'all "
        "reachable candidates'.",
    },
}


def apply_view(
    candidates: list[TriageCandidate],
    *,
    view: str | None = None,
    sort_by: str | None = None,
    dim_filters: list[tuple[str, str]] | None = None,
    impact_overrides: dict[str, int] | None = None,
) -> list[TriageCandidate]:
    """Resolve a ``view`` preset (+ explicit ``sort_by`` / ``dim_filters`` overrides) into a
    filtered, sorted list. ``dim_filters`` is a list of (dim, value). The demotion iron law rides
    regardless of the chosen spine — no lens can bury a ? candidate."""
    spine = "impact"
    filters: list[tuple[str, str]] = []
    if view and view in VIEWS:
        preset = VIEWS[view]
        spine = preset["spine"]
        if preset["filter"]:
            filters.append(preset["filter"])
    if sort_by:
        spine = sort_by
    if dim_filters:
        filters.extend(dim_filters)
    out = list(candidates)
    for d, val in filters:
        out = filter_by_dimension(out, d, val)
    return sort_candidates(out, spine=spine, impact_overrides=impact_overrides)


def triage(conn: sqlite3.Connection, *, run_id: str | None = None) -> list[TriageCandidate]:
    """Return the atlas candidate map — each candidate with its honest dimension layers — ordered by
    the DEFAULT lens: sink-impact spine, impact x controllability composite, only-up tertiary
    keys, and the demotion iron law (only a proven-safe fact sinks; a ? never sinks). Re-project
    with ``sort_candidates`` / ``apply_view``. Read-only; nothing is written back.

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
    candidates = [_candidate(conn, r) for r in rows]
    return sort_candidates(candidates, spine="impact")


# ── single-candidate explanation (the dimension layers; honest bounds; where to verify) ──
#
# This view presents every dimension layer's honest three-state annotation (state + value +
# source), the lens caveats, and where to verify by hand. There is NO score to decompose — the
# dimensions ARE the explanation. It does NOT declare a candidate real, does NOT claim
# cross-function reachability, and prints NO triggering input.


@dataclass(frozen=True)
class CandidateExplanation:
    """A read-only, single-candidate map view. A lead with stated bounds, never a verdict.

    ``dimensions`` carries every layer's honest three-state annotation; ``caveats`` states the
    phase-1 optimism/blind-spots. No score, no score breakdown — the layers are the fact."""

    candidate: TriageCandidate
    call_sequence_shape: str | None
    # Every map layer's honest annotation (state / value / source / note) — the explanation itself.
    dimensions: tuple[Dimension, ...]
    # The current lens label + the honest phase-1 caveats, surfaced so the explain view never reads
    # as complete (optimistic 'free', near-always-'?' filtering, no-reduction contract).
    lens_label: str
    caveats: tuple[str, ...]
    claims_does: tuple[str, ...]
    claims_does_not: tuple[str, ...]
    verify_steps: tuple[str, ...]
    # Signals promoted to the explain TOP LEVEL so a consumer reads them without descending into
    # ``candidate``: the coarse source class, the fine source_kind, the controllability annotation,
    # and the sink-impact class. Each echoes the same-named candidate field / dimension value.
    source_class: str
    source_kind: str
    controllability: str
    sink_impact: str
    # Summary-first sink_arg_provenance (Ghidra def-use fact) at the explain TOP LEVEL: one compact
    # entry per command/format sink in this candidate's function (idx / kind / resolved /
    # nearest_dominating_writer). The full writer + fmt + vararg detail is fetched on demand with
    # ``get_sink_provenance`` so a many-sink candidate never overruns the token budget. A surfaced
    # fact only; nothing here feeds recall or a grade.
    sink_arg_provenance_summary: tuple[dict[str, Any], ...]


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

    Read-only. Presents every dimension layer's honest three-state annotation, the lens caveats,
    the honest claim bounds, and a manual-verification checklist. Returns None when no instance
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

    candidate = _candidate(conn, row)
    claims_does = (
        "present each dimension layer as an observed FACT about this candidate (controllability, "
        "source-writability, reachability, filtering, sink impact, writer, completeness) with its "
        "three-state, value, and source.",
    )
    claims_does_not = (
        "declare the candidate attackable, reachable, or real — every layer is a fact; the "
        "judgement is yours;",
        "trace cross-function flow (who calls this function is not followed here);",
        "prove safety on a '?' layer — a '?' is a coverage gap, never 'safe'.",
    )
    return CandidateExplanation(
        candidate=candidate,
        call_sequence_shape=row["call_sequence_shape"],
        dimensions=candidate.dimensions,
        lens_label=DEFAULT_LENS_LABEL,
        caveats=PHASE1_CAVEATS,
        claims_does=claims_does,
        claims_does_not=claims_does_not,
        verify_steps=_verify_steps(candidate),
        source_class=candidate.source_class,
        source_kind=candidate.source_kind,
        controllability=candidate.dim("controllability").value,
        sink_impact=candidate.dim("sink_impact").value,
        sink_arg_provenance_summary=_sink_provenance_summary(_row_get(row, "flow_evidence")),
    )
