# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Cross-entity diff primitive.

Given two analysis databases and a neutral axis, locate functions that changed and
describe each change in mechanism-only terms. Returns in-memory results; writes
nothing, judges nothing, and depends on no downstream store.
"""

from __future__ import annotations

from treasure_map.lib.diff.differ import run_diff
from treasure_map.lib.diff.models import (
    Axis,
    ChangeKind,
    ChangeLead,
    DiffResult,
    DiffStats,
    FuncRef,
)

__all__ = [
    "Axis",
    "ChangeKind",
    "ChangeLead",
    "DiffResult",
    "DiffStats",
    "FuncRef",
    "run_diff",
]
