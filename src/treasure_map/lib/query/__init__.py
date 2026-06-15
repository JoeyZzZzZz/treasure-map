# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Neutral read-side aggregation views over the atlas.

density / twins / dormant — mechanism aggregations only. Every row is a lead/candidate;
nothing here scores, ranks, or judges.
"""

from __future__ import annotations

from treasure_map.lib.query.triage import (
    REVIEW_STATUS_BY_REACHABILITY,
    TriageCandidate,
    review_score,
    triage,
)
from treasure_map.lib.query.views import (
    FINE_FP_ALGO_VERSION,
    DensityRow,
    LedgerRow,
    TwinRow,
    density,
    dormant,
    ledger,
    twins,
)

__all__ = [
    "FINE_FP_ALGO_VERSION",
    "REVIEW_STATUS_BY_REACHABILITY",
    "DensityRow",
    "LedgerRow",
    "TriageCandidate",
    "TwinRow",
    "density",
    "dormant",
    "ledger",
    "review_score",
    "triage",
    "twins",
]
