# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Intra-procedural reachability grading (honest v1).

grade_candidate reads ONE function. This is a single-function heuristic, NOT an
inter-procedural data-flow engine: it cannot prove attacker control across call boundaries,
so "confirmed" is rare and tightly gated and "unknown" is the expected, correct answer for
most candidates. Under any doubt the verdict is "unknown".

v1 emits only "confirmed" / "unknown". "blocked" stays a valid ReachabilityStatus and is
reserved for the deep data-flow engine (R2-deep): deciding NON-reachability soundly needs
path-/alias-sensitivity an intra-procedural regex read does not have, and a false "blocked"
would route a live path into the dormant partition and halt investigation — the one error
v1 must never make. So a would-be "blocked" (a validator appears to cover the inputs) grades
"unknown" with an honest basis. The validator/clamp/taint machinery stays wired — it gates
"confirmed" (a validator on the path, a parameter contribution, or a clamp demotes a
would-be "confirmed" to "unknown") and is reused by R2-deep.

A "confirmed" verdict means a path confirmed within one function (provenance L1 at most) —
it is not a claim that anything can be triggered, and nothing here may treat a verdict as a
confirmed defect or a publishable result.
"""

from __future__ import annotations

from collections.abc import Mapping

from treasure_map.lib.pattern.classes import COPY, FMT_STRING, FORMAT
from treasure_map.lib.reachability.copy_size import (
    SIZE_APPEND_CONST,
    SIZE_APPEND_VARIABLE,
    SIZE_CAP_CONST,
    SIZE_CAP_VARIABLE,
    SIZE_CLAMP,
    SIZE_CONST,
    SIZE_NO_BOUND,
    SIZE_POINTER_GUARD,
    SIZE_SIZEOF,
    SIZE_SOURCE_LEN,
    SIZE_UNTRACED,
    SIZE_VARIABLE,
    classify_copy_size,
    classify_format_size,
    copy_size_form_note,
)
from treasure_map.lib.reachability.filters import (
    has_inline_bound,
    has_validator,
    validator_on_path,
    validator_present,
)
from treasure_map.lib.reachability.models import ReachabilityVerdict
from treasure_map.lib.reachability.taint import (
    _seed_sets,
    abi_unrecovered,
    flows_into,
    locate_format_arg,
    locate_sink_arg,
)

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
_BASIS_COVERED_UNVERIFIED = (
    "a validator-style call appears to cover the inputs reaching the sink, but an "
    "intra-procedural read cannot prove this path is bounded; the verdict is unknown, "
    "not blocked — deep data-flow analysis (R2-deep) is required to decide non-reachability"
)
_BASIS_CLAMP = (
    "a clamp may bound the value on the path; a clean unfiltered flow is not provable here, "
    "so the result is unknown rather than confirmed"
)
_BASIS_ABI = (
    "the decompiler did not soundly recover this function's frame (unrecovered calling "
    "convention / in_stack/unaff/extraout placeholders); a clean source-to-sink flow is not "
    "fully visible within the function, so the verdict is unknown, not confirmed — deep "
    "data-flow analysis (R2-deep) is required"
)

# Copy sinks are graded on the WRITE LENGTH (the danger axis), not on whether taint reaches the
# destination pointer. A copy never confirms within one function: proving the length is truly
# unbounded and externally controllable needs cross-function (protocol/caller) context, so the
# verdict is always unknown — with a size-source form note for the provably-bounded cases.
_COPY_BASIS: dict[str, str] = {
    SIZE_CONST: (
        "the copy's write length is a literal constant; the write is bounded and the length is "
        "not externally controllable"
    ),
    SIZE_SIZEOF: (
        "the copy's write length is a sizeof() of an object; the write is bounded to the object "
        "size, not externally controllable"
    ),
    SIZE_CLAMP: (
        "an upper-bound clamp referencing the copy's length variable is present, but an "
        "intra-procedural read cannot prove it dominates this copy; the verdict is unknown, not "
        "confirmed"
    ),
    SIZE_POINTER_GUARD: (
        "a pointer/bound guard referencing the copy's length is present, but an intra-procedural "
        "read cannot prove it dominates this copy; the verdict is unknown, not confirmed"
    ),
    SIZE_SOURCE_LEN: (
        "the copy's write length is the source string's own length; this is bounded only if an "
        "upstream caller limited the source, which is not establishable within one function — a "
        "lead to verify, not a bounded-safe form"
    ),
    SIZE_VARIABLE: (
        "the copy's write length is a variable with no visible upper bound within this function; "
        "whether it is externally controllable and unbounded is for a later layer to decide"
    ),
    SIZE_UNTRACED: (
        "the copy's length argument could not be resolved within this function; kept as a lead "
        "rather than assumed bounded"
    ),
}


# What each formatter write-length kind states — the fact, and where it stops. Each says
# something about the CALL and nothing about the destination's capacity, which is the line these
# sentences exist to hold: a cap is not a capacity, and an append amount is not a total.
_FORMAT_BASIS: dict[str, str] = {
    SIZE_NO_BOUND: (
        "this formatter takes no length parameter, so no upper limit on the write exists in the "
        "call; how much is written depends on the values formatted, which is not decided here"
    ),
    SIZE_CAP_CONST: (
        "the write is capped at a literal constant; whether the destination is that large is not "
        "known here, so this bounds the write and not the overflow"
    ),
    SIZE_CAP_VARIABLE: (
        "the write is capped at a variable; both the cap's value and the destination's capacity "
        "are outside what this read establishes"
    ),
    SIZE_APPEND_CONST: (
        "a literal constant number of bytes is APPENDED; the total written is that plus whatever "
        "the destination already holds, which is not known here"
    ),
    SIZE_APPEND_VARIABLE: (
        "a variable number of bytes is APPENDED; neither that amount nor the destination's "
        "existing contents are established here"
    ),
}


def grade_candidate(
    pseudocode: str,
    callees: list[str],
    sink_name: str,
    *,
    source_class: str | None = None,
    copy_occurrence: int | None = None,
    stub_names: Mapping[int, str] | None = None,
) -> ReachabilityVerdict:
    """Grade one candidate as confirmed / unknown (``blocked`` is reserved, never emitted here).

    v1 returns only "confirmed" or "unknown"; a would-be "blocked" grades "unknown" (see the
    module docstring — deciding non-reachability soundly is left to the deep engine, so "blocked"
    stays a valid but unused ReachabilityStatus). source_class is accepted for interface symmetry
    with the detection layer; the grade is decided from the pseudocode, callees, and sink alone.

    ``copy_occurrence`` selects WHICH call to ``sink_name`` this candidate is about (0-based).
    ``None`` means the caller holds no callsite, and each branch then keeps its own historical
    default: the length readers fall back to the first call, and the format-string reader falls back
    to the first NON-LITERAL call across the function. Those two defaults differ, which is why this
    is threaded as None rather than as 0 — passing 0 would silently turn "no callsite in hand" into
    "callsite zero" and make a function whose first printf is literal grade as unreadable.

    ``stub_names`` is the binary's resolved lazy-binding stub table (see analyze/stub_resolve). It
    is threaded to every reader below so that a sink call the decompiler named after its stub is
    graded like any other; with none, such a call is invisible and the verdict degrades honestly to
    "the sink call or its argument could not be located".
    """
    if not callees:
        return ReachabilityVerdict("unknown", None, _BASIS_NO_CALLEES, degraded=True)
    if not pseudocode or not pseudocode.strip():
        return ReachabilityVerdict("unknown", None, _BASIS_NO_BODY, degraded=True)

    if sink_name in COPY:
        # Copy sinks are graded on the write length (danger axis), never confirmed in one
        # function. classify_copy_size reads the length source; a provably-bounded length
        # (const/sizeof/clamp/pointer_guard) carries a downweight form note, a suspect or
        # unbounded length carries none (kept at its normal rank — never silently demoted).
        cs = classify_copy_size(
            pseudocode, sink_name, occurrence=copy_occurrence or 0, stub_names=stub_names
        )
        basis = _COPY_BASIS.get(cs.kind, _BASIS_ORIGIN_UNKNOWN)
        return ReachabilityVerdict("unknown", copy_size_form_note(cs.kind), basis)

    if sink_name in FORMAT:
        # A buffer formatter writes into a destination, so it is graded on the WRITE LENGTH — the
        # same axis as a copy, and for the same reason never "confirmed" from inside one function.
        #
        # It must not fall through to the general branch below. That one reads argument 0 as a
        # command string and runs the seed/validator flow over it; for a formatter argument 0 is
        # the DESTINATION POINTER, so a covered-looking pointer would produce a reachability
        # verdict about the wrong value entirely. Whatever a formatter's write length turns out to
        # be, the verdict here is 'unknown': the facts are about the call, and none of them
        # establishes that a write is or is not reachable.
        fs = classify_format_size(
            pseudocode, sink_name, occurrence=copy_occurrence or 0, stub_names=stub_names
        )
        basis = _FORMAT_BASIS.get(fs.kind, _BASIS_ORIGIN_UNKNOWN)
        # copy_size_form_note holds none of the five formatter kinds, so this is structurally None
        # — a formatter is never demoted on its length. Called rather than hardcoded so the two
        # cannot disagree if a kind is ever added.
        return ReachabilityVerdict("unknown", copy_size_form_note(fs.kind), basis)

    # Format-string sinks are graded on the FORMAT argument (the danger axis), per-sink position;
    # a literal format yields no identifier (safe). Every other sink is graded on arg0 (command
    # string) exactly as before — the cmd path is byte-for-byte unchanged.
    if sink_name in FMT_STRING:
        sink_arg = locate_format_arg(pseudocode, sink_name, stub_names, copy_occurrence)
    else:
        sink_arg = locate_sink_arg(pseudocode, sink_name, stub_names, copy_occurrence or 0)
    if sink_arg is None:
        return ReachabilityVerdict("unknown", None, _BASIS_NO_SINK, degraded=True)

    # The dangerous SEED inputs that reach the sink, and whether each is covered by a
    # validator on its own path INTO the sink. blocked requires a trustworthy flow set and
    # that EVERY dangerous seed is cleanly, directly covered; ANY doubt grades unknown so a
    # possibly-reachable path is never hidden in the dormant partition.
    flow = flows_into(pseudocode, sink_arg)  # cleaned flow set
    path = {sink_arg} | flow
    strong_seeds, weak_seeds, par_seeds = _seed_sets(pseudocode)
    dangerous = (strong_seeds | weak_seeds | par_seeds) & path

    covered_vars = {var for var in path if has_validator(callees, pseudocode, var)[0]}
    cover_flow = {w: flows_into(pseudocode, w) for w in covered_vars}

    def _is_covered(seed: str) -> bool:
        # Covered iff a validated variable W sits on the seed's path to the sink: W is the
        # seed itself, or the seed flows into W (single direction, toward the sink).
        return any(w == seed or seed in cover_flow[w] for w in covered_vars)

    uncovered = {seed for seed in dangerous if not _is_covered(seed)}

    if dangerous and not uncovered:
        # Appears fully covered — BUT an intra-procedural regex read cannot prove this is sound
        # (cross-branch validator leakage, base+offset aliasing). Per the no-silent-miss rule,
        # v1 NEVER downgrades a possibly-reachable path to blocked: the verdict is unknown (NOT
        # degraded — the input was complete; v1 simply cannot prove non-reachability). The
        # filter-present vs filter-absent verdict is deferred to the deep data-flow engine.
        return ReachabilityVerdict("unknown", None, _BASIS_COVERED_UNVERIFIED)

    # Grade by the most-severe UNCOVERED seed. No path here may return blocked.
    if uncovered & par_seeds:
        # Hard invariant: a parameter contribution makes the path unprovable -> never confirmed.
        return ReachabilityVerdict("unknown", None, _BASIS_PARAM)
    if uncovered & strong_seeds:
        if validator_present(callees) and not validator_on_path(callees, pseudocode, path)[0]:
            # A validator exists but touches nothing on the sink's flow path — cannot relate
            # it; prefer unknown over a confident confirm (mis-block caution).
            return ReachabilityVerdict("unknown", None, _BASIS_AMBIGUOUS)
        if par_seeds & path:
            # A parameter also reaches the sink — caller contribution -> not confirmable.
            return ReachabilityVerdict("unknown", None, _BASIS_PARAM)
        if has_inline_bound(pseudocode)[0]:
            # A clamp may bound the value: downgrade a would-be confirm to unknown (never
            # blocked — a function-wide clamp does not prove THIS path is bounded).
            return ReachabilityVerdict("unknown", None, _BASIS_CLAMP)
        if abi_unrecovered(pseudocode):
            # The decompiler did not soundly recover the frame (unrecovered calling
            # convention / in_stack/unaff/extraout placeholders). "confirmed" claims a clean
            # flow fully visible in this function, which is not establishable here. Downgrade
            # to unknown (never blocked); R2-deep must decide. Closes the intra-procedural
            # false-confirm on stripped MIPS/ARM firmware.
            return ReachabilityVerdict("unknown", None, _BASIS_ABI)
        return ReachabilityVerdict("confirmed", None, _BASIS_CONFIRMED)
    if uncovered & weak_seeds:
        # Locally-influenced input: external controllability is not establishable here.
        return ReachabilityVerdict("unknown", None, _BASIS_WEAK)

    return ReachabilityVerdict("unknown", None, _BASIS_ORIGIN_UNKNOWN, degraded=True)
