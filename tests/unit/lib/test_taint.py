# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The taint layer's call recognition (R2): seeds and derivation edges are found through
``call_offsets`` + ``call_args_at`` + ``arg_ref``, so a source or builder whose arguments carry
their own parentheses — a cast, a nested call — is no longer invisible."""

from __future__ import annotations

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
