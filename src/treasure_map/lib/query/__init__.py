# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Neutral read-side aggregation views over the atlas.

density / twins / dormant — mechanism aggregations only. Every row is a lead/candidate;
nothing here scores, ranks, or judges.
"""

from __future__ import annotations

from treasure_map.lib.query.exploit_ledger import list_cve_patterns, list_moat
from treasure_map.lib.query.nvram import get_nvram_key_flow
from treasure_map.lib.query.runs import (
    get_run,
    list_runs,
    runs_where_function_exists,
)
from treasure_map.lib.query.sink_impact import (
    DEFAULT_SINK_IMPACT,
    impact_tier,
    parse_impact_order,
)
from treasure_map.lib.query.string_edges import (
    edges_reaching_callee,
    get_string_keyed_edges,
)
from treasure_map.lib.query.triage import (
    DEFAULT_LENS_LABEL,
    PHASE1_CAVEATS,
    REVIEW_STATUS_BY_REACHABILITY,
    VIEWS,
    CandidateExplanation,
    Dimension,
    TriageCandidate,
    apply_view,
    canonical_view,
    explain_candidate,
    filter_by_dimension,
    filter_candidates,
    filter_match_count,
    get_sink_provenance,
    only_refusal,
    reachability_match_count,
    reducible,
    shown_statuses,
    sink_matches,
    sort_candidates,
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
    "DEFAULT_LENS_LABEL",
    "DEFAULT_SINK_IMPACT",
    "FINE_FP_ALGO_VERSION",
    "PHASE1_CAVEATS",
    "REVIEW_STATUS_BY_REACHABILITY",
    "VIEWS",
    "CandidateExplanation",
    "DensityRow",
    "Dimension",
    "LedgerRow",
    "TriageCandidate",
    "TwinRow",
    "apply_view",
    "canonical_view",
    "density",
    "dormant",
    "edges_reaching_callee",
    "explain_candidate",
    "get_string_keyed_edges",
    "filter_by_dimension",
    "filter_candidates",
    "filter_match_count",
    "get_nvram_key_flow",
    "get_run",
    "get_sink_provenance",
    "impact_tier",
    "ledger",
    "list_cve_patterns",
    "list_moat",
    "list_runs",
    "only_refusal",
    "parse_impact_order",
    "reachability_match_count",
    "reducible",
    "runs_where_function_exists",
    "shown_statuses",
    "sink_matches",
    "sort_candidates",
    "triage",
    "twins",
]
