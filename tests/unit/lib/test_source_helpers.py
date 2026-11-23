# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The per-binary value-getter mechanism (E-2a H8, the three NEW-MAJOR points).

A binary's own value-getter helpers are carried in ``sink_vocabulary.SourceHelpers`` and handed,
as an EXPLICIT parameter, to every reader that asks "is this callee a source" (the A class). The
readers
that consume an already-computed ``source_class`` / ``structural_fingerprint`` (the B class) take
no table and follow by themselves.

What is pinned here:
  * every A-class reader reads the table it is passed, and only that table;
  * one name means different things in two binaries — including when the two bodies are byte for
    byte the same, which is what the memoized readers key on (the cache-crosstalk hazard);
  * a helper's value is WEAK input: it labels and it seeds, and it never grades a candidate
    ``confirmed``;
  * with no table passed, every reading is what it was before the mechanism existed.

Which functions QUALIFY as a helper is not decided here (no criterion is wired yet): these
fixtures hand the table in directly, so the mechanism is tested apart from the detector.
Fixtures use synthetic names throughout.
"""

from __future__ import annotations

import pytest

from treasure_map.lib.hunt.downweight import _caller_only_constants, detect_form_signal
from treasure_map.lib.hunt.evidence import build_flow_evidence, free_sources_called
from treasure_map.lib.pattern.models import FuncRef
from treasure_map.lib.pattern.shapes import classify, pattern_cmd
from treasure_map.lib.pattern.sink_vocabulary import (
    NO_HELPERS,
    RETURN_SLOT,
    SOURCE_STRONG,
    SourceHelpers,
)
from treasure_map.lib.reachability import grade_candidate
from treasure_map.lib.reachability.taint import (
    _derives_map,
    _seed_sets,
    free_taint_reaches,
)

# One binary's table: a helper that hands its value back as its return, and one that writes it
# into its second argument. Synthetic names; the mechanism is name-based inside one binary.
RETURNING = "cfg_lookup"
WRITING = "cfg_fetch"
HELPERS = SourceHelpers(frozenset({(RETURNING, RETURN_SLOT), (WRITING, 1)}))
# A fixed source that is BOTH strong and a return-value source, so an assignment of its result
# seeds strong: the premise the weak-bucket tooth below rests on.
_STRONG_RETURN = "websGetVar"

# A caller of the returning helper that hands the value to a command sink with nothing between.
# Plain locals only, no validator-named call, no clamp, no unrecovered-frame marker — built so
# that seeding the value STRONG would grade confirmed (which is what A-E2a-3 forbids).
CALLER_BODY = (
    "void send_cmd(void){ char *pcVar1; char acStack_90[128]; "
    f'pcVar1 = (char *){RETURNING}("name"); '
    'snprintf(acStack_90,0x80,"ping %s",pcVar1); system(acStack_90); }'
)
CALLER_CALLEES = [RETURNING, "snprintf", "system"]


def _ref(binary: str) -> FuncRef:
    return FuncRef(binary_name=binary, func_name="send_cmd", func_id=1)


# ── the A class reads the table it is handed ────────────────────────────────────────────────────


def test_classify_counts_a_call_to_the_binarys_helper_as_a_source() -> None:
    """``shapes.classify`` buckets a call to one of the binary's helpers into ``source``, so the
    shape detector's ``source_class`` reads ``external_input`` — and with no table it does not.

    MUTATION (verified RED, ``1 failed`` each): ignore the argument (``names & SOURCE`` alone) ->
    the helper is not a source -> RED; fold the helper names into the module-level SOURCE instead
    -> the no-table half labels it too -> RED."""
    assert classify(CALLER_CALLEES, HELPERS).source == frozenset({RETURNING})
    assert classify(CALLER_CALLEES).source == frozenset()
    assert classify(CALLER_CALLEES, NO_HELPERS).source == frozenset()


def test_classify_counts_the_candidates_own_helper_function_as_a_source() -> None:
    """丁 (whole-function self-source): a candidate whose OWN function is an admitted helper reads
    that function as a weak source — a value getter parses external input (it is why it was
    admitted), so its body handles that input even when it calls no source NAME of its own. Passing
    ``func_name`` is what enables it; without it, or when the function is not a helper, the body
    reads unknown exactly as before.

    MUTATION (verified RED): drop the ``func_name in helpers.names`` clause -> a getter whose body
    calls no source and no helper reads unknown, leaving the getter sourceless (the B-1 anchor's
    local-buffer copy never lifts)."""
    body_callees = ["strstr", "strcpy"]  # a getter body: libc parse + copy, no SOURCE, no helper
    assert classify(body_callees, HELPERS, RETURNING).source == frozenset({RETURNING})
    assert classify(body_callees, HELPERS, WRITING).source == frozenset({WRITING})
    assert classify(body_callees, HELPERS, "not_a_helper").source == frozenset()  # not a helper
    assert classify(body_callees, HELPERS).source == frozenset()  # func_name omitted = old reading


def test_the_shape_detector_labels_the_candidate_from_the_binarys_table() -> None:
    """The command detector's candidate reads ``external_input`` in the binary whose table holds
    the helper and ``unknown`` in one whose does not — and the two carry DIFFERENT structural
    fingerprints, which is the whole of how the B-class readers follow (A-E2a-7).

    MUTATION (verified RED, ``1 failed``): the detectors drop the table (``classify(callees)``) ->
    both read unknown and the fingerprints are equal -> RED."""
    (with_table,) = pattern_cmd(_ref("alpha"), CALLER_CALLEES, CALLER_BODY, None, HELPERS)
    (without,) = pattern_cmd(_ref("beta"), CALLER_CALLEES, CALLER_BODY, None, NO_HELPERS)
    assert with_table.source_class == "external_input"
    assert without.source_class == "unknown"
    assert with_table.structural_fingerprint != without.structural_fingerprint


def test_a_fingerprint_change_re_keys_the_grouping_the_b_class_reads() -> None:
    """A-E2a-7: the two B-class readers key on the stored ``structural_fingerprint`` — the shape
    group key is a different key once the fingerprint moves, so they re-group with no code change
    of their own.

    MUTATION (verified RED, ``1 failed``): build the shape key without the fingerprint -> the two
    keys are equal -> RED."""
    from treasure_map.lib.query.same_shape_siblings import f2_key

    (with_table,) = pattern_cmd(_ref("alpha"), CALLER_CALLEES, CALLER_BODY, None, HELPERS)
    (without,) = pattern_cmd(_ref("beta"), CALLER_CALLEES, CALLER_BODY, None, NO_HELPERS)
    assert f2_key(with_table.structural_fingerprint, "system", "free_string") != f2_key(
        without.structural_fingerprint, "system", "free_string"
    )


@pytest.mark.parametrize(
    ("call", "seeded", "table"),
    [
        (f'pcVar1 = {RETURNING}("name");', "pcVar1", HELPERS),
        (f'{WRITING}("name",acStack_30);', "acStack_30", HELPERS),
    ],
    ids=["returns_the_value", "writes_an_out_parameter"],
)
def test_a_helper_seeds_exactly_the_value_it_hands_on_and_only_weakly(
    call: str, seeded: str, table: SourceHelpers
) -> None:
    """A helper taints the one value it hands on — the variable its return is assigned to, or the
    argument it writes — and seeds it WEAK, never strong.

    MUTATION (verified RED, ``2 failed``): seed a helper's value strong (``target = strong``) ->
    the weak set is empty -> RED. MUTATION (verified RED, ``1 failed``): read the out positions as
    the return slot -> the written argument is not seeded -> RED."""
    body = f"void f(void){{ char *pcVar1; char acStack_30[32]; {call} }}"
    strong, weak, par = _seed_sets(body, table)
    assert weak == frozenset({seeded})
    assert strong == frozenset()
    assert par == frozenset()
    assert _seed_sets(body) == (frozenset(), frozenset(), frozenset())


def test_a_helpers_value_reaching_a_command_grades_unknown_never_confirmed() -> None:
    """A-E2a-3: the WEAK bucket is what keeps a helper from grading a candidate ``confirmed`` —
    not the grader, which is unchanged. The fixture confirms when the same value is seeded strong.

    MUTATION (verified RED, ``1 failed`` each): seed a helper's value strong -> confirmed -> RED;
    let the weak bucket confirm in the grader -> confirmed -> RED."""
    from treasure_map.lib.reachability.grader import _BASIS_WEAK

    verdict = grade_candidate(CALLER_BODY, CALLER_CALLEES, "system", helpers=HELPERS)
    assert verdict.status == "unknown"
    assert verdict.basis == _BASIS_WEAK
    # The premise, asserted rather than assumed: this body is one a STRONG return source confirms
    # on, so "unknown" above is the bucket's doing and not the fixture's. _STRONG_RETURN is named
    # explicitly — an arbitrary member of SOURCE_STRONG may be a buffer source, which seeds
    # nothing through an assignment and would make the premise pass for the wrong reason.
    assert _STRONG_RETURN in SOURCE_STRONG
    strong_body = CALLER_BODY.replace(RETURNING, _STRONG_RETURN)
    strong_callees = [_STRONG_RETURN, "snprintf", "system"]
    assert grade_candidate(strong_body, strong_callees, "system").status == "confirmed"


def test_the_flow_evidence_reports_the_helpers_value_as_a_free_string() -> None:
    """The evidence layer's ``source_kind`` reads a helper's value as a free string, and
    ``free_sources_called`` names the helper — the two places a body is read for sources, one
    through the taint walk and one through the module-level call pattern.

    MUTATION (verified RED, ``1 failed`` each): drop the helper branch from ``_source_kind`` ->
    unknown -> RED; add the helper names to the module-level ``_SOURCE_CALL_RE`` instead of
    matching them per set -> the no-table half names it -> RED."""
    ev = build_flow_evidence(
        pseudocode=CALLER_BODY,
        callees=CALLER_CALLEES,
        sink_arg="acStack_90",
        entry_sites=None,
        helpers=HELPERS,
    )
    assert ev["source_kind"] == "free_string"
    bare = build_flow_evidence(
        pseudocode=CALLER_BODY, callees=CALLER_CALLEES, sink_arg="acStack_90", entry_sites=None
    )
    assert bare["source_kind"] == "unknown"
    assert free_sources_called(CALLER_BODY, HELPERS) == [RETURNING]
    assert free_sources_called(CALLER_BODY) == []


def test_free_taint_reaches_follows_a_helpers_value() -> None:
    """``free_taint_reaches`` — the parameter-specific guard every downweight is suppressed by —
    counts a helper's value as free.

    MUTATION (verified RED, ``1 failed``): drop the table from the seed read inside it -> the
    value is not free -> RED."""
    assert free_taint_reaches(CALLER_BODY, "acStack_90", safe_vars=set(), helpers=HELPERS)
    assert not free_taint_reaches(CALLER_BODY, "acStack_90", safe_vars=set())


def test_the_downweight_entry_point_carries_the_table_to_its_readers() -> None:
    """The table reaches the A-class reading THROUGH the public entry point: a function whose sink
    argument is its own parameter, whose callers all pass a literal, but which calls its binary's
    helper, no longer reads ``caller_constant``. Without the table the same call reads it, so this
    pins the pass-through and not just the reader.

    MUTATION (verified RED, ``1 failed``): ``detect_form_signal`` drops the table on its way to
    ``_caller_only_constants`` -> the note is written -> RED."""
    body = f'void fwd(char *param_1){{ {RETURNING}("name"); system(param_1); }}'
    args = {
        "sink_name": "system",
        "pseudocode": body,
        "callees": [RETURNING, "system"],
        "sink_arg": "param_1",
        "func_name": "fwd",
        "callers_pseudocode": ['void c(void){ fwd("/sbin/reboot"); }'],
        "sink_form": "var",
    }
    assert detect_form_signal(**args, helpers=HELPERS) is None
    assert detect_form_signal(**args) == "caller_constant"


def test_a_function_that_calls_its_binarys_helper_is_not_caller_constant() -> None:
    """``_caller_only_constants`` refuses a function that takes input directly — a call to the
    binary's own helper is taking input, so the one-hop "every caller passes a literal" reading no
    longer applies to it.

    MUTATION (verified RED, ``1 failed``): test only ``callees & SOURCE`` -> the helper call is
    missed and the function reads caller-constant -> RED."""
    body = f'void fwd(char *param_1){{ {RETURNING}("name"); system(param_1); }}'
    callers = ['void c(void){ fwd("/sbin/reboot"); }']
    common = {"pseudocode": body, "sink_arg": "param_1"}
    assert not _caller_only_constants(
        "fwd", [RETURNING, "system"], callers, **common, helpers=HELPERS
    )
    assert _caller_only_constants("fwd", [RETURNING, "system"], callers, **common)


def test_a_helper_name_is_not_read_as_a_flow_variable() -> None:
    """A helper's NAME is a callee name, never a value: where it appears other than as a call (its
    address handed to a register), it must not become a dependency edge — the same pollution rule
    the fixed source names have.

    MUTATION (verified RED, ``1 failed``): drop the helper names from the identifier filter -> the
    name becomes a dependency of the variable -> RED."""
    body = f"void f(void){{ void *pvVar1; pvVar1 = {RETURNING}; }}"
    assert _derives_map(body, HELPERS).get("pvVar1") == frozenset()
    assert _derives_map(body).get("pvVar1") == frozenset({RETURNING})


# ── one name, two binaries ─────────────────────────────────────────────────────────────────────


def test_one_name_is_a_helper_in_its_own_binary_only() -> None:
    """A-E2a-5: the same callee name, in two binaries, with the table holding it in only one: the
    other binary's caller is labelled exactly as before.

    MUTATION (verified RED, ``1 failed``): resolve helper names from a module-wide set instead of
    the per-binary table -> the second binary's caller is labelled too -> RED."""
    tables = {"alpha": HELPERS, "beta": NO_HELPERS}
    labels = {
        binary: pattern_cmd(_ref(binary), CALLER_CALLEES, CALLER_BODY, None, table)[0].source_class
        for binary, table in tables.items()
    }
    assert labels == {"alpha": "external_input", "beta": "unknown"}


def test_two_binaries_reading_one_body_do_not_share_a_cached_answer() -> None:
    """★ A-E2a-6 (the cache-crosstalk hazard): the memoized readings are keyed on the body text
    AND on the binary's table, so two binaries whose CALLER BODIES are byte for byte identical —
    the key the text-only cache used — seed differently when only one of them holds the helper.

    The hunt reads every binary's functions in one flat pass and never clears these caches, so a
    text-only key would hand the second binary whatever the first one computed: a silent
    mis-seeding, in whichever direction the pass happened to run.

    MUTATION (verified RED, ``1 failed``): key ``_seed_sets`` on the text alone (a dict cache the
    hunt never clears, the natural implementation) -> the second read returns the first's answer
    -> RED. Both orders are asserted, so the mutation is red whichever one runs first."""
    body = CALLER_BODY  # the same object for both reads, as the hunt hands it
    assert _seed_sets(body, HELPERS)[1] == frozenset({"pcVar1"})
    assert _seed_sets(body, NO_HELPERS)[1] == frozenset()
    # and in the other order, on a body neither has read yet
    other = body.replace("send_cmd", "send_cmd2")
    assert _seed_sets(other, NO_HELPERS)[1] == frozenset()
    assert _seed_sets(other, HELPERS)[1] == frozenset({"pcVar1"})


def test_the_helper_table_is_hashable_and_equal_by_its_slots() -> None:
    """The table is the cache key, so it has to hash and compare by value — two tables built from
    the same slots are one key, and the derived name set is not part of the comparison.

    MUTATION (verified RED, ``1 failed`` each): let ``out_positions`` return the return slot too
    -> RED; derive ``names`` from something other than the slots (an empty set) -> RED."""
    one = SourceHelpers(frozenset({(RETURNING, RETURN_SLOT)}))
    same = SourceHelpers(frozenset({(RETURNING, RETURN_SLOT)}))
    other = SourceHelpers(frozenset({(RETURNING, 1)}))
    assert one == same and hash(one) == hash(same)
    assert one != other and one != NO_HELPERS
    assert len({one, same, other, NO_HELPERS}) == 3
    assert one.names == same.names == frozenset({RETURNING})
    assert one.returns_value(RETURNING) and not other.returns_value(RETURNING)
    assert other.out_positions(RETURNING) == (1,) and one.out_positions(RETURNING) == ()
    assert NO_HELPERS.names == frozenset() and not NO_HELPERS.slots
