# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The taint layer's call recognition (R2): seeds and derivation edges are found through
``call_offsets`` + ``call_args_at`` + ``arg_ref``, so a source or builder whose arguments carry
their own parentheses — a cast, a nested call — is no longer invisible."""

from __future__ import annotations

import pytest

from treasure_map.lib.reachability.taint import (
    _call_names,
    _derives_map,
    _seed_sets,
    flows_into,
)


def test_a_buffer_source_with_a_parenthesised_argument_is_seeded() -> None:
    """A buffer-output source whose buffer argument carries a cast / address-of is seen, and the
    buffer it writes is seeded — the old 'no parentheses in the arguments' call regex missed it.

    MUTATION (verified RED): read the arguments with ``str.split(',')`` over a regex that bans
    inner parentheses -> the buffer is never seeded."""
    strong, _weak, _par = _seed_sets("void f(int fd){ char buf[512]; recv(fd,(char *)&buf,n); }")
    assert "buf" in strong


def test_recvfrom_seeds_its_buffer_through_a_later_const_addr_argument() -> None:
    """``recvfrom(fd, buf, n, 0, (sockaddr *)0x0, ...)`` — the parenthesised later arguments do not
    hide the call, and the buffer (argument 1) is seeded."""
    strong, _weak, _par = _seed_sets(
        "void f(int fd){ char buf[512]; recvfrom(fd,buf,0x200,0,(sockaddr *)0x0,p); }"
    )
    assert "buf" in strong


def test_a_builder_with_a_nested_call_argument_makes_a_derivation_edge() -> None:
    """A FORMAT/COPY builder whose source argument is itself a call is seen, so the destination
    derives from that argument's variables (the backward flow walk reaches them).

    MUTATION (verified RED): a call regex that bans inner parentheses skips this builder -> the
    destination has no dependency and ``flows_into`` returns nothing."""
    pc = 'void f(char *a,char *b){ char dst[64]; snprintf(dst,64,"%s",esc(a,b)); system(dst); }'
    deps = _derives_map(pc)
    assert "dst" in deps and deps["dst"]
    assert {"a", "b"} & flows_into(pc, "dst")


def test_a_callee_name_inside_a_string_is_not_a_call() -> None:
    """A name written inside a string literal is not a call: it must not pollute the derivation
    callee set, and a source named only in a message is not seeded."""
    strong, weak, _par = _seed_sets('void f(void){ char b[8]; syslog(1,"recv() failed"); }')
    assert "b" not in strong and "b" not in weak


def test_call_names_ignores_a_name_written_inside_a_string() -> None:
    """``_call_names`` (the derivation callee set) must skip a ``name(`` written inside a string
    literal. A real flow variable that happens to share that name is dropped from the dependency
    edges if the string hit pollutes the callee set, so the backward flow misses it.

    MUTATION (verified RED / HM27): count every ``name(`` match, string-embedded ones included ->
    ``x`` joins the callee set, is pruned from the builder's dependency idents, and the flow misses
    it."""
    pc = 'void f(char *x){ char cmd[64]; syslog(1,"x("); snprintf(cmd,64,"%s",x); system(cmd); }'
    assert "x" not in _call_names(pc)  # 'x(' sits inside a string, so 'x' is not a callee
    assert "x" in flows_into(pc, "cmd")  # and so 'x' is kept as a dependency of cmd


# ── config-store getters: weak sources, seeded only where their value lands ─────────────────────
#
# Every argument in these fixtures is a distinct plain local (never param_N / in_stack_* / unaff_*,
# which are caller-supplied seeds of their own), so a getter seeded at the wrong position taints a
# different, named variable and the assertion sees it.

_SEEDED_GETTERS = [
    # (call, the one variable it must seed)
    ("apmib_get(local_10,local_14);", "local_14"),
    ("pcVar1 = (char *)config_get(local_10);", "pcVar1"),
    ("tcapi_get(local_10,local_14,local_18);", "local_18"),
    ("tcapi_staticGet(local_10,local_14,local_18);", "local_18"),
    ("uci_get_option(local_10,local_14,local_18,local_1c,local_20);", "local_1c"),
]


@pytest.mark.parametrize(("call", "seeded"), _SEEDED_GETTERS)
def test_a_config_store_getter_seeds_exactly_the_value_it_writes_as_weak(
    call: str, seeded: str
) -> None:
    """Each seeded config-store getter taints the one value it produces — its output buffer, or the
    variable its return is assigned to — and only that, and only as WEAK input.

    MUTATION (verified RED, 5 failed): drop the five entries from the seeding tables -> nothing is
    seeded. Seed apmib_get at argument 0 -> local_10 instead of local_14 (1 failed). Move the five
    into SOURCE_STRONG -> the seeds land in strong (5 failed)."""
    strong, weak, par = _seed_sets(f"void f(void){{ {call} }}")
    assert weak == {seeded}
    assert strong == frozenset()
    assert par == frozenset()


def test_the_unfixed_position_getters_have_no_seeding_entry() -> None:
    """The two getters with no fixed value position are absent from both seeding tables, so
    ``_seed_source`` falls through to its seed-nothing end for them.

    MUTATION (verified RED, 1 failed): give uci_lookup_ptr a buffer position; list uci_get as a
    return source."""
    from treasure_map.lib.reachability import taint

    for name in ("uci_lookup_ptr", "uci_get"):
        assert name in taint._SOURCE_NAMES, name  # a source all the same
        assert name not in taint._BUFFER_SOURCE_ARG, name
        assert name not in taint._RETURN_SOURCES, name


@pytest.mark.parametrize(
    "call",
    [
        # the value is a field of the lookup struct, two indirections from the argument
        "uci_lookup_ptr(local_10,local_14,local_18,1);",
        # one name, two call shapes: an out-argument, or the return of a two-argument call
        "uci_get(local_10,local_14,local_18);",
        "iVar2 = uci_get(local_10,local_14);",
    ],
)
def test_a_getter_whose_value_position_is_not_fixed_seeds_nothing(call: str) -> None:
    """``uci_lookup_ptr`` and ``uci_get`` are sources (they set the source label) but seed no
    taint: no single argument or return carries the value for every call, and seeding the struct
    root would taint everything it points to.

    MUTATION (verified RED): give uci_lookup_ptr a buffer position (1) -> local_14 is seeded (1
    failed); list uci_get as a return source -> iVar2 is seeded (1 failed)."""
    strong, weak, _par = _seed_sets(f"void f(void){{ {call} }}")
    assert weak == frozenset()
    assert strong == frozenset()


_WEAK_TO_SINK = [
    ("apmib_get(0x2d6,acStack_30);", "acStack_30", ["apmib_get"]),
    ('pcVar1 = (char *)config_get("wan_proto");', "pcVar1", ["config_get"]),
    ('tcapi_get("Wan_Common","Mode",acStack_30);', "acStack_30", ["tcapi_get"]),
    ('tcapi_staticGet("Wan_Common","Mode",acStack_30);', "acStack_30", ["tcapi_staticGet"]),
    (
        'uci_get_option("network","lan","proto",acStack_30,0x20);',
        "acStack_30",
        ["uci_get_option"],
    ),
]


@pytest.mark.parametrize(("call", "value", "getters"), _WEAK_TO_SINK)
def test_a_stored_setting_reaching_a_command_unfiltered_grades_unknown_weak(
    call: str, value: str, getters: list[str]
) -> None:
    """A config-store value that reaches ``system()`` with nothing in between grades ``unknown`` on
    the weak basis, never ``confirmed``: a stored setting is not shown to be remotely controllable
    within one function. The weak bucket is what holds this, not the grader.

    The fixture is built so that moving a getter to SOURCE_STRONG WOULD confirm: plain locals only
    (no caller-supplied placeholder takes the parameter branch first), no validator-named call (no
    covered/ambiguous branch), no clamp and no unrecovered-frame marker.

    MUTATION (verified RED): move the five getters into SOURCE_STRONG -> confirmed (5 failed);
    drop them from the seeding tables -> the origin-unknown basis instead of the weak one
    (5 failed)."""
    from treasure_map.lib.reachability import grade_candidate
    from treasure_map.lib.reachability.grader import _BASIS_WEAK

    pseudo = (
        "void f(void){ char acStack_30[32]; char local_128[128]; "
        f'{call} snprintf(local_128,0x80,"ping %s",{value}); system(local_128); }}'
    )
    verdict = grade_candidate(pseudo, [*getters, "snprintf", "system"], "system")
    assert verdict.status == "unknown"
    assert verdict.basis == _BASIS_WEAK
    assert verdict.degraded is False
