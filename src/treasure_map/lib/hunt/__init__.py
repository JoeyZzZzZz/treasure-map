# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Analyzers — compose the static primitives and write neutral atlas instances.

A1 (analyzer1): the diff-driven analyzer. Composes R-diff + R2 and writes graded
L0/L1 instances into the atlas. public_finding stays empty by construction in M2.
"""

from __future__ import annotations

from treasure_map.lib.hunt.analyzer1 import AnalyzerStats, run_analyzer1

__all__ = ["AnalyzerStats", "run_analyzer1"]
