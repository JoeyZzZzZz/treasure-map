# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Intra-procedural reachability grading (honest v1).

grade_candidate reads ONE function and returns confirmed / blocked / unknown. This is a
single-function heuristic, NOT an inter-procedural data-flow engine: it cannot prove
attacker control across call boundaries, so "confirmed" is rare and tightly gated and
"unknown" is the expected, correct answer for most candidates. Under any doubt the
verdict is "unknown". A "confirmed" verdict means a path confirmed within one function
(provenance L1 at most) — it is not a claim that anything can be triggered, and nothing
here may treat a verdict as a confirmed defect or a publishable result.
"""

from __future__ import annotations

from treasure_map.lib.reachability.filters import (
    has_inline_bound,
    validator_on_path,
    validator_present,
)
from treasure_map.lib.reachability.models import ReachabilityVerdict
from treasure_map.lib.reachability.taint import flows_into, locate_sink_arg, origin_of

_BASIS_NO_CALLEES = "no callees were recorded for the function"
_BASIS_NO_BODY = "no pseudocode was available for the function"
_BASIS_NO_SINK = "the sink call or its argument could not be located in the function"
_BASIS_PARAM = (
    "the value reaching the sink derives from a function parameter; caller control is "
    "not provable within a single function"
)
_BASIS_WEAK = (
    "the value reaching the sink comes from a locally-influenced source "
    "(environment/config/device-self/file); external controllability is not establishable "
    "within a single function"
)
_BASIS_AMBIGUOUS = (
    "a validator-style call is present but its relationship to the value reaching the "
    "sink is unclear"
)
_BASIS_CONFIRMED = (
    "the value reaching the sink originates from an in-function strong (network/request) "
    "source and flows to the sink unfiltered, fully visible within this function"
)
_BASIS_ORIGIN_UNKNOWN = "the origin of the value reaching the sink could not be determined here"


def grade_candidate(
    pseudocode: str,
    callees: list[str],
    sink_name: str,
    *,
    source_class: str | None = None,
) -> ReachabilityVerdict:
    """Grade one candidate as confirmed / blocked / unknown.

    source_class is accepted for interface symmetry with the detection layer; the grade
    is decided from the pseudocode, callees, and sink alone. See the module docstring for
    the deliberate intra-procedural limits.
    """
    if not callees:
        return ReachabilityVerdict("unknown", None, _BASIS_NO_CALLEES, degraded=True)
    if not pseudocode or not pseudocode.strip():
        return ReachabilityVerdict("unknown", None, _BASIS_NO_BODY, degraded=True)

    sink_arg = locate_sink_arg(pseudocode, sink_name)
    if sink_arg is None:
        return ReachabilityVerdict("unknown", None, _BASIS_NO_SINK, degraded=True)

    # A validator anywhere on the data-flow path into the sink blocks it — even when the
    # validated value reaches the sink under renamed intermediates (copies/format calls).
    path_vars = {sink_arg} | flows_into(pseudocode, sink_arg)
    blocked, mechanism = validator_on_path(callees, pseudocode, path_vars)
    if blocked:
        return ReachabilityVerdict("blocked", mechanism, mechanism or "")

    origin = origin_of(pseudocode, sink_arg)
    if origin == "parameter":
        # Hard invariant: a parameter-sourced, unfiltered sink is NEVER confirmed.
        return ReachabilityVerdict("unknown", None, _BASIS_PARAM)
    if origin == "weak_source":
        # Locally-influenced input: external controllability is not establishable here.
        return ReachabilityVerdict("unknown", None, _BASIS_WEAK)
    if origin == "strong_source":
        bounded, bound_mechanism = has_inline_bound(pseudocode)
        if bounded:
            # A demonstrable clamp limits the value — bounded, not an unfiltered flow.
            return ReachabilityVerdict("blocked", bound_mechanism, bound_mechanism or "")
        if validator_present(callees):
            # A validator exists but is not clearly on this value — prefer unknown.
            return ReachabilityVerdict("unknown", None, _BASIS_AMBIGUOUS)
        return ReachabilityVerdict("confirmed", None, _BASIS_CONFIRMED)

    return ReachabilityVerdict("unknown", None, _BASIS_ORIGIN_UNKNOWN, degraded=True)
