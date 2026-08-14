# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Frozen result models for the reachability grading primitive.

No behavior. A verdict is a graded LEAD, never a claimed bug: "confirmed" means a path
was confirmed within one function (provenance L1 at most), not that anything can be
triggered. Field names mirror the cross-firmware instance columns (neutral) without
importing that layer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

# How reachable the sink is from an external-input origin, as far as a single-function
# (intra-procedural) static read can tell. "unknown" is first-class and expected to
# dominate — it is the honest answer when caller control cannot be proven here.
ReachabilityStatus = Literal["confirmed", "blocked", "unknown"]


@dataclass(frozen=True)
class ReachabilityVerdict:
    """A graded verdict for one candidate.

    blocking_mechanism is a neutral description of why a path is blocked (set only for
    "blocked"); basis is a one-line neutral reason for the verdict; degraded is True when
    the input was too incomplete to grade (degrade-and-flag, never a silent miss).
    """

    status: ReachabilityStatus
    blocking_mechanism: str | None
    basis: str
    degraded: bool = False


@dataclass(frozen=True)
class ReachabilityStats:
    graded: int
    confirmed: int
    blocked: int
    unknown: int
    degraded: int
