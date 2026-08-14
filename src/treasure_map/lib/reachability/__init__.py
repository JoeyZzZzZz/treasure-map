# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Reachability grading primitive (intra-procedural v1).

Grades a candidate (a function's pseudocode + callees + the sink it reaches) as
confirmed / blocked / unknown. Pure-static, hermetic (no LLM); a single-function
heuristic that is honest about its limits — "unknown" is first-class. Returns a graded
lead, never a claimed bug; depends on no downstream store.
"""

from __future__ import annotations

from treasure_map.lib.reachability.grader import grade_candidate
from treasure_map.lib.reachability.models import ReachabilityStatus, ReachabilityVerdict

__all__ = ["ReachabilityStatus", "ReachabilityVerdict", "grade_candidate"]
