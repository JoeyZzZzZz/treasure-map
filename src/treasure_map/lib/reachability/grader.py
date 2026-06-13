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
    has_validator,
    validator_on_path,
    validator_present,
)
from treasure_map.lib.reachability.models import ReachabilityVerdict
from treasure_map.lib.reachability.taint import _taint_sets, flows_into, locate_sink_arg

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
_BASIS_COVERED = "a validator covers every input reaching the sink"


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

    # Identify the tainted values that actually flow into the sink, and whether each is
    # COVERED by a validator anywhere on its flow line to the sink. A sink blocks only when
    # EVERY such input is covered — a covered input must never mask an uncovered sibling.
    flow = flows_into(pseudocode, sink_arg)
    path_vars = {sink_arg} | flow
    strong, weak, par = _taint_sets(pseudocode)

    flow_of = {var: flows_into(pseudocode, var) for var in path_vars}
    covered_vars = {var for var in path_vars if has_validator(callees, pseudocode, var)[0]}

    def _is_covered(value: str) -> bool:
        # value is covered if a validated var sits on the same flow line (either direction):
        # the var itself, a value it derives from, or a value that derives from it.
        return any(
            w == value or w in flow_of.get(value, set()) or value in flow_of.get(w, set())
            for w in covered_vars
        )

    tainted = path_vars & (strong | weak | par)
    uncovered = {value for value in tainted if not _is_covered(value)}

    if tainted and not uncovered:
        return ReachabilityVerdict("blocked", _BASIS_COVERED, _BASIS_COVERED)

    # Grade by the most-severe UNCOVERED input — a covered sibling cannot rescue it.
    if uncovered & par:
        # Hard invariant: a parameter contribution makes the path unprovable -> never confirmed.
        return ReachabilityVerdict("unknown", None, _BASIS_PARAM)
    if uncovered & strong:
        bounded, bound_mechanism = has_inline_bound(pseudocode)
        if bounded:
            # A demonstrable clamp limits the value — bounded, not an unfiltered flow.
            return ReachabilityVerdict("blocked", bound_mechanism, bound_mechanism or "")
        if validator_present(callees) and not validator_on_path(callees, pseudocode, path_vars)[0]:
            # A validator exists but touches nothing on the sink's flow path — cannot relate
            # it; prefer unknown over a confident confirm (mis-block caution).
            return ReachabilityVerdict("unknown", None, _BASIS_AMBIGUOUS)
        return ReachabilityVerdict("confirmed", None, _BASIS_CONFIRMED)
    if uncovered & weak:
        # Locally-influenced input: external controllability is not establishable here.
        return ReachabilityVerdict("unknown", None, _BASIS_WEAK)

    return ReachabilityVerdict("unknown", None, _BASIS_ORIGIN_UNKNOWN, degraded=True)
