# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""The opt-in overlay-on ordering pass: an agent's own annotations as an OUTERMOST band bias.

Default OFF. With the overlay on, the annotations an agent recorded over the read-only map become
a three-band bias applied AFTER the base lens has ordered the list: what the agent marked
suspicious floats, what it marked excluded/safe sinks, and an annotation whose basis has since
moved floats back up for re-review instead of staying quietly sunk.

Three properties make this safe to bolt onto the base map:

* It is a pure RE-RANK, never a reduction — ``sorted`` only reorders, so a sunk candidate stays in
  the corpus, queryable and filterable (the same never-drop rule the base lens itself rides).
* The band is decided by the ANNOTATION ALONE; it never consults a base-map fact. That is exactly
  what lets an agent's ``suspicious`` float a candidate the base map sank as provably constant —
  the agent is contradicting the map, and the row renders BOTH halves so the layers stay
  distinguishable rather than one silently overwriting the other.
* The base sort engine knows nothing about it. That engine runs first and unchanged, and this is a
  STABLE outermost re-sort over its output, so band-internal order is still the base lens order.

An annotation that can no longer be verified counts as moved, not as clean: an excluded/safe row
whose basis reads ``unverifiable`` re-surfaces alongside the changed ones, because a judgement
resting on a basis nobody can check is not a reason to keep a candidate out of sight.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # import only for typing — the storage layer must not depend on this view
    from treasure_map.lib.query.triage import TriageCandidate

# Band ordering: small sorts earlier.
FLOAT, NEUTRAL, SINK = 0, 1, 2

# The verdicts that sink a candidate — and that re-surface once their basis moves.
_SUNK_VERDICTS = ("excluded", "safe")


def overlay_band(annotation: dict[str, Any] | None) -> int:
    """Which band one annotation biases its candidate into (``None`` = unannotated -> NEUTRAL).

    ``suspicious`` floats. ``excluded`` / ``safe`` sink, but ONLY while their basis still reads
    ``unchanged`` — once it has moved (or cannot be verified) the candidate floats back up for
    re-review, so a stale dismissal can never bury a candidate for good. ``to-review`` /
    ``in-progress`` are work-in-flight, not a judgement, so they keep the base-map position.
    """
    if annotation is None:
        return NEUTRAL
    verdict, basis_state = annotation["verdict"], annotation["basis_state"]
    if verdict in _SUNK_VERDICTS and basis_state != "unchanged":
        return FLOAT  # a dismissal whose basis moved: re-surface for re-review, never leave it sunk
    if verdict == "suspicious":
        return FLOAT
    if verdict in _SUNK_VERDICTS:
        return SINK
    return NEUTRAL


def apply_overlay_view(
    ranked: list[TriageCandidate], overlays_by_ref: dict[str, dict[str, Any]]
) -> list[TriageCandidate]:
    """Re-rank an already-ordered candidate list by its overlay annotations — never reduce it.

    Applied as the LAST ordering pass, after the base lens has fully sorted ``ranked``: the sort is
    stable, so within each band the base lens order survives untouched. An empty
    ``overlays_by_ref`` is a no-op ordering-wise (every candidate lands in NEUTRAL), which is what
    makes the overlay-off path read identically to a map with no overlay at all.
    """

    def band(c: TriageCandidate) -> int:
        ref = c.evidence_ref
        # No ref means nothing could have been annotated against it — base-map position, unbiased.
        return overlay_band(overlays_by_ref.get(ref) if ref else None)

    return sorted(ranked, key=band)
