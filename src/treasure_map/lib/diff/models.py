# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Frozen result models for the cross-entity diff primitive.

No behavior. Field names are neutral mechanism terms (a later consumer may map
scope_origin / the diff text onto its own storage) — this layer does not import or
know about any downstream store.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

# The neutral comparison axis the operator supplies. The real pairing (which device,
# which versions) stays in external operator notes; only the axis is recorded here.
Axis = Literal["version", "mod", "sibling"]

# How a single function resolved across the two entities.
#   changed              — both sides have a body and the bodies differ (the main signal)
#   changed_unverifiable — exactly one side has a body (e.g. one version's decompilation
#                          timed out): we cannot tell whether it changed, so we flag rather
#                          than guess (degrade-and-flag; never silently 'unchanged')
#   skipped_no_body      — neither side has a body (both timed out): no information, not a
#                          change; dropped like 'unchanged' (counted, never a lead)
ChangeKind = Literal[
    "unchanged", "added", "removed", "changed", "changed_unverifiable", "skipped_no_body"
]


@dataclass(frozen=True)
class FuncRef:
    """A neutral reference to one matched function (no vendor/firmware identity)."""

    binary_name: str
    func_name: str | None
    func_id: int


@dataclass(frozen=True)
class ChangeLead:
    """One located change between the two entities.

    func_ref_a / func_ref_b are None on the side where the function is absent
    (added => a is None; removed => b is None). change_description is reserved and
    always None now: the diff consumer recovers the change from the deterministic
    unified diff itself, so the primitive no longer asks an LLM to describe it.
    """

    change_kind: ChangeKind
    scope_origin: Axis
    func_ref_a: FuncRef | None
    func_ref_b: FuncRef | None
    pseudocode_hash_a: str | None
    pseudocode_hash_b: str | None
    change_description: str | None = None


@dataclass(frozen=True)
class DiffStats:
    matched: int  # functions resolved to a pairing (present on both sides)
    unchanged: int  # hash-equal pairings, both with a body (dropped, no lead)
    added: int  # present in B only
    removed: int  # present in A only
    changed: int  # both sides have a body and the bodies differ (the main signal)
    changed_unverifiable: int  # exactly one side has a body — flagged, not described
    skipped_no_body: int  # neither side has a body (both timed out) — not a change, dropped


@dataclass(frozen=True)
class DiffResult:
    leads: tuple[ChangeLead, ...]
    stats: DiffStats
