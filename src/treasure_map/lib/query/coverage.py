# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""What has been looked at, what has not, and how far through a class the reader is.

The annotation layer records conclusions. Until now it could only be read by asking for it, so the
one question a reader most needs answered — "which of these have I already been through?" — had no
answer on the map itself. The result is a reader who re-reads what they have read, or worse, stops
partway believing the ground is covered.

This module answers it from what is already stored: an annotation exists for a candidate, or it
does not. Nothing new is written; the states below are derived from the annotation's own verdict
plus the basis freshness the overlay layer already re-derives.

★ TWO LAYERS STAY APART. Presence is a TOOL-SIDE FACT about the annotation layer's state, not a
dimension of the candidate and not the annotation's content. It rides in its own key, exactly as
the ledger marker does, and never joins ``dimensions``.

★ PROGRESS IS MEASURED IN PAGES, NOT IN FINISHED CLASSES. A class on a large firmware runs to
thousands of candidates; "N of N done" is both unreachable and an incentive to clear the board by
dismissing things. A page is a unit someone can actually finish, and the remainder is stated every
time so finishing one is never read as finishing the class.

★ WHAT THIS CANNOT DO, stated because the alternative is to imply otherwise:

  * It cannot make anyone read carefully. It can only make shallow work land as an OPEN state
    rather than a clean-looking dismissal, and make the shape of a batch of dismissals visible.
  * It is exhaustive over the CANDIDATE SET, not over the firmware. A sink that never became a
    candidate — missed by recall, or by the classifier — is not in the set being paged through, so
    no amount of paging reaches it. That is a recall question, answered elsewhere.
  * Every count here is bounded by the analysis that produced the candidates. A run with binaries
    that failed to decompile has candidates that were never generated at all, which is why no
    completion signal is emitted without the run's blind-spot ledger beside it.
"""

from __future__ import annotations

import math
import sqlite3
from dataclasses import dataclass, field
from typing import Any

from treasure_map.lib.overlay import _VERDICTS, Basis, basis_delta
from treasure_map.lib.query.sink_impact import impact_tier

# ── the states a candidate can be in ──────────────────────────────────────────────────
#
# Three layers, plus side channels for annotations that cannot be taken at face value. Every
# candidate is in exactly one; the side channels are NOT counted as concluded.

UNSEEN = "none"  # no annotation exists
OPEN = "inconclusive"  # looked at, could not decide — itself a conclusion, and it stays in view
CONCLUDED = "concluded"  # a verdict in the current vocabulary was reached
NEEDS_RELABEL = "needs_relabel"  # the verdict word is retired; re-state it in current terms
NEEDS_RECHECK = "needs_recheck"  # the facts it rested on have moved, though the anchor still holds

# Not a row state: a dangling annotation has no current candidate to sit on, so it can only be
# reported on the envelope.
DANGLING = "dangling"

# The verdicts that count as a conclusion reached. ``inconclusive`` is deliberately NOT here: it is
# an honest "looked, cannot say", and counting it as done would make it the cheap way to clear a
# page.
_CONCLUDED_VERDICTS = frozenset(_VERDICTS) - {"inconclusive"}

# How the dismissal verdicts differ in what they cost to assert. This is why the distribution is
# reported: `safe` demands a structured evidence basis, while `excluded` needs only a sentence, so
# a page cleared entirely with `excluded` looks exactly like a page cleared in a hurry — and this
# is the only place that difference becomes visible.
_WEIGHT_BY_VERDICT = {
    "safe": "dismissed_with_evidence",
    "excluded": "dismissed_by_rationale",
    "inconclusive": "open",
    "suspicious": "carried_forward",
    "exploitable": "carried_forward",
}

DEFAULT_PAGE_SIZE = 20


@dataclass(frozen=True)
class Annotation:
    """The minimum an annotation contributes to coverage: its verdict and its basis freshness."""

    verdict: str
    basis_state: str


@dataclass(frozen=True)
class CoverageIndex:
    """Every annotation keyed by the candidate it anchors to.

    ★ Cost note, since this is loaded whether or not the annotation view is on: the size of this
    index is the number of ANNOTATIONS a person has written, never the number of candidates. The
    basis re-derivation runs once per annotation for the same reason. Both scale with how much
    someone has annotated, which is the only quantity here a reader controls."""

    by_ref: dict[str, Annotation] = field(default_factory=dict)

    def state_for(self, evidence_ref: str | None) -> str:
        """The coverage state of one candidate — ``none`` when nothing has been recorded for it."""
        if not evidence_ref:
            return UNSEEN
        annotation = self.by_ref.get(evidence_ref)
        return UNSEEN if annotation is None else annotation_state(annotation)


def annotation_state(annotation: Annotation) -> str:
    """One annotation's coverage state, in precedence order.

    A retired verdict is reported before anything else about it can be read: the word no longer
    means what the vocabulary says, so neither "concluded" nor "open" can be claimed from it. A
    moved basis comes next — the conclusion may still stand, but it was reached on facts that have
    since changed, so it is due a look rather than counted as settled."""
    if annotation.verdict not in _VERDICTS:
        return NEEDS_RELABEL
    if annotation.basis_state not in ("unchanged", "unverifiable"):
        return NEEDS_RECHECK
    return CONCLUDED if annotation.verdict in _CONCLUDED_VERDICTS else OPEN


def load_coverage_index(atlas: sqlite3.Connection) -> CoverageIndex:
    """Read every annotation's ref, verdict and live basis state.

    ★ Loaded UNCONDITIONALLY, on the same footing as the ledger marker: whether a candidate has
    been looked at is a fact about the world, not a view someone opts into. What stays behind the
    view switch is the annotation's CONTENT — who wrote it, on what basis, how it re-ranks.

    The basis state is re-derived rather than read from the stored column, because the stored one
    records what was true when the annotation was written. An annotation whose candidate has since
    disappeared was perfectly resolvable at write time, so reading the stored value would report it
    as healthy — which is exactly the case that most needs surfacing."""
    try:
        rows = atlas.execute(
            # ★ The snapshot lives in `basis_state`, despite the name. `verdict_basis` is a
            # different thing entirely — the justification a `safe` verdict owes — and reading it
            # here would hand Basis.from_json a shape it does not understand, leaving every
            # annotation looking unverifiable.
            "SELECT anchor_ref, verdict, basis_state FROM overlay WHERE anchor_kind = ?",
            ("evidence_ref",),
        ).fetchall()
    except sqlite3.OperationalError:
        return CoverageIndex()  # no overlay table (older atlas) -> nothing has been looked at
    by_ref: dict[str, Annotation] = {}
    for row in rows:
        ref = row["anchor_ref"]
        if not ref:
            continue
        state = basis_delta(atlas, ref, Basis.from_json(row["basis_state"]))["state"]
        by_ref[ref] = Annotation(verdict=row["verdict"], basis_state=state)
    return CoverageIndex(by_ref=by_ref)


# ── paging order ──────────────────────────────────────────────────────────────────────


def canonical_page_key(sink_class: str | None, evidence_ref: str | None) -> tuple[int, str]:
    """The order candidates are paged through — stable, total, and independent of the view.

    ★ NO IMPACT OVERRIDE. ``impact_tier`` accepts an override map, and an override REPLACES the
    default table, so a candidate's tier — and therefore its page — would move when someone passes
    a different ``--impact-order``. Working through pages 1..N would then miss candidates that
    quietly moved to a page already passed. The order here is pinned to the default table for that
    reason, and it ignores filters and lens choices for the same one.

    The tie-break is the WHOLE evidence_ref compared as a string. Its internal structure is never
    parsed — two spellings exist in the wild and neither is a contract — but a whole-string sort is
    total and stable, which is all the ordering needs.

    Higher impact first, so working front-to-back reaches command execution before logging."""
    return (-impact_tier(sink_class or ""), evidence_ref or "")


# ── the progress report ───────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class CoverageReport:
    """What a scope's coverage looks like right now. Every number is recomputed from the
    annotations on each read — no page number, and no notion of "done", is ever stored."""

    total: int
    seen: int
    unseen: int
    page_size: int
    pages_total: int
    pages_remaining: int
    states: dict[str, int]
    verdict_shape: dict[str, int]
    next_page: list[dict[str, Any]]
    dangling: list[str]


def _page_count(items: int, page_size: int) -> int:
    return math.ceil(items / page_size) if items > 0 else 0


def coverage_report(
    candidates: list[Any],
    index: CoverageIndex,
    *,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> CoverageReport:
    """Coverage over one scope of candidates.

    ``next_page`` names the candidates to work through next, AT CANDIDATE LEVEL — a page number
    alone would leave a reader to work out which candidates it holds, and the whole point is that
    the ones nobody has looked at are named. It is the first ``page_size`` unseen candidates in
    canonical order, recomputed each call, so annotating any of them simply removes it from the
    next answer.

    ``dangling`` lists annotations whose candidate is not in this scope's set at all. They are
    reported rather than counted: an annotation with nothing to attach to is neither a conclusion
    about a live candidate nor something to quietly drop."""
    states: dict[str, int] = {UNSEEN: 0, OPEN: 0, CONCLUDED: 0, NEEDS_RELABEL: 0, NEEDS_RECHECK: 0}
    shape: dict[str, int] = {}
    unseen: list[Any] = []
    for candidate in candidates:
        state = index.state_for(getattr(candidate, "evidence_ref", None))
        states[state] = states.get(state, 0) + 1
        if state == UNSEEN:
            unseen.append(candidate)
            continue
        annotation = index.by_ref.get(candidate.evidence_ref)
        if annotation is not None:
            weight = _WEIGHT_BY_VERDICT.get(annotation.verdict, "retired_word")
            shape[weight] = shape.get(weight, 0) + 1

    unseen.sort(key=lambda c: canonical_page_key(c.sink_class, c.evidence_ref))
    in_scope = {getattr(c, "evidence_ref", None) for c in candidates}
    dangling = sorted(
        ref
        for ref, annotation in index.by_ref.items()
        if ref not in in_scope and annotation.basis_state == "anchor_unresolved"
    )
    total = len(candidates)
    return CoverageReport(
        total=total,
        seen=total - len(unseen),
        unseen=len(unseen),
        page_size=page_size,
        pages_total=_page_count(total, page_size),
        pages_remaining=_page_count(len(unseen), page_size),
        states=states,
        verdict_shape=shape,
        next_page=[
            {
                "evidence_ref": c.evidence_ref,
                "binary": getattr(c, "binary_path", None),
                "function": getattr(c, "function", None),
                "sink_class": c.sink_class,
            }
            for c in unseen[:page_size]
        ],
        dangling=dangling,
    )
