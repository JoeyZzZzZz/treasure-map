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
ChangeKind = Literal["unchanged", "added", "removed", "changed"]


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
    (added => a is None; removed => b is None). change_description is the neutral
    mechanism-level sentence, present only for a 'changed' lead with a usable diff.
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
    unchanged: int  # hash-equal pairings (dropped, no lead, no LLM)
    added: int  # present in B only
    removed: int  # present in A only
    changed: int  # matched but pseudocode differs
    m_assist_calls: int  # M-tier function_match_assist calls actually made
    verdict_calls: int  # L-tier patch_verdict calls actually made


@dataclass(frozen=True)
class DiffResult:
    leads: tuple[ChangeLead, ...]
    stats: DiffStats
