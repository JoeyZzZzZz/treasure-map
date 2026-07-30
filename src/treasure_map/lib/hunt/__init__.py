# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Analyzers — compose the static primitives and write neutral atlas instances.

A2 (analyzer2): pattern-driven. Composes R-pattern + R2; writes the rich callseq-v1
patterns/instances, append-only, L0/L1 only; public_finding stays empty in M2. The former
diff-driven analyzer (self-built alignment + reachability grading) was retired: version
comparison now runs through the map-model diff pipeline (lib/diff/layer0 + layer2), which
projects existing annotations and never grades.
"""

from __future__ import annotations

from treasure_map.lib.hunt.analyzer2 import Analyzer2Stats, run_analyzer2

__all__ = [
    "Analyzer2Stats",
    "run_analyzer2",
]
