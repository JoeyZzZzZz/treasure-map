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

import logging
import sqlite3
from dataclasses import dataclass

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

# A filter on the path (blocking_mechanism set) lowers review order — it is more likely a
# false positive / already-mitigated. No identified filter raises it.
_FILTER_ABSENT_WEIGHT = 0.5
_FILTER_PRESENT_WEIGHT = -0.5

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

# Sink class, ordered by the operation the sink performs (command execution above buffer copy
# above string formatting). This is an ordering weight, not a magnitude-of-harm claim.
_SINK_CLASS_WEIGHT: dict[str, float] = {"cmd": 0.4, "copy": 0.2, "format": 0.0}


def _bounds() -> tuple[float, float]:
    """Min/max possible raw score, derived from the weight tables (for [0,1] display scaling)."""
    fine_lo = (
        _FILTER_PRESENT_WEIGHT
        + min(_ORIGIN_WEIGHT.values())
        + min(0.0, *_SOURCE_CLASS_WEIGHT.values())
        + min(_SINK_CLASS_WEIGHT.values())
    )
    fine_hi = (
        _FILTER_ABSENT_WEIGHT
        + max(_ORIGIN_WEIGHT.values())
        + max(0.0, *_SOURCE_CLASS_WEIGHT.values())
        + max(_SINK_CLASS_WEIGHT.values())
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


def _raw_score(
    reachability_status: str,
    blocking_mechanism: str | None,
    origin: str,
    source_class: str,
    sink_class: str,
) -> float:
    score = _STATUS_WEIGHT.get(reachability_status, 0.0)
    score += _FILTER_ABSENT_WEIGHT if blocking_mechanism is None else _FILTER_PRESENT_WEIGHT
    score += _ORIGIN_WEIGHT.get(origin, 0.0)
    score += _SOURCE_CLASS_WEIGHT.get(source_class, 0.0)
    score += _SINK_CLASS_WEIGHT.get(sink_class, 0.0)
    return score


def review_score(
    reachability_status: str,
    blocking_mechanism: str | None,
    origin: str,
    source_class: str,
    sink_class: str,
) -> float:
    """Deterministic review-ordering score in [0, 1] (ordering signal only, never stored)."""
    raw = _raw_score(reachability_status, blocking_mechanism, origin, source_class, sink_class)
    norm = (raw - _SCORE_LO) / (_SCORE_HI - _SCORE_LO)
    return round(min(1.0, max(0.0, norm)), 2)


def _candidate(row: sqlite3.Row) -> TriageCandidate:
    reach = row["reachability_status"]
    return TriageCandidate(
        score=review_score(
            reach,
            row["blocking_mechanism"],
            row["origin"],
            row["source_class"],
            row["sink_class"],
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
    )


def triage(conn: sqlite3.Connection, *, run_id: str | None = None) -> list[TriageCandidate]:
    """Return atlas candidates ranked by review-ordering score (descending).

    Read-only: selects instances joined to their pattern, scores each, and sorts by score
    descending with a deterministic tie-break. Returns every candidate (gated included); the
    caller decides whether to fold the gated rows. Nothing is written back to the atlas.

    run_id, if given, restricts to one firmware run (source_run_id); otherwise all runs.
    """
    sql = (
        "SELECT i.reachability_status, i.blocking_mechanism, i.origin, i.source_anchor, "
        "i.sink_anchor, i.source_run_id, i.evidence_ref, i.binary_path, "
        "p.source_class, p.sink_class "
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


def score_breakdown(
    reachability_status: str,
    blocking_mechanism: str | None,
    origin: str,
    source_class: str,
    sink_class: str,
    *,
    sink_anchor: str | None = None,
) -> list[ScoreComponent]:
    """Itemize the score: one ScoreComponent per signal, each weight from the real tables.

    The component weights sum to _raw_score(...); normalizing that sum into [score_lo, score_hi]
    reproduces review_score(...) exactly. No item is invented — each maps to one stored field.
    """
    filter_value = "none" if blocking_mechanism is None else blocking_mechanism
    filter_weight = _FILTER_ABSENT_WEIGHT if blocking_mechanism is None else _FILTER_PRESENT_WEIGHT
    filter_note = (
        "no sanitizer identified on the in-function path "
        "(generic name match — may miss a custom guard)"
        if blocking_mechanism is None
        else f"a '{blocking_mechanism}'-class guard was identified "
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
        "i.sink_anchor, i.source_run_id, i.evidence_ref, i.binary_path, "
        "p.source_class, p.sink_class, p.call_sequence_shape "
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
    )
