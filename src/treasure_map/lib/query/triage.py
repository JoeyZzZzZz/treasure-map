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

import sqlite3
from dataclasses import dataclass

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
        "i.sink_anchor, i.source_run_id, i.evidence_ref, "
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
