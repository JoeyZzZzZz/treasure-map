# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Analyzers — compose the static primitives and write neutral atlas instances.

A1 (diff_analyzer): diff-driven. Composes R-diff + R2; writes graded L0/L1 instances.
A2 (analyzer2): pattern-driven. Composes R-pattern + R2; writes the rich callseq-v1
patterns/instances. Both append-only, L0/L1 only; public_finding stays empty in M2.
"""

from __future__ import annotations

from treasure_map.lib.hunt.analyzer2 import Analyzer2Stats, run_analyzer2
from treasure_map.lib.hunt.diff_analyzer import AnalyzerStats, run_diff_analyzer

__all__ = [
    "Analyzer2Stats",
    "AnalyzerStats",
    "run_analyzer2",
    "run_diff_analyzer",
]
