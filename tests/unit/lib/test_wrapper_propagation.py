# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for lib/hunt/wrapper_propagation — factor ① one-hop thin-wrapper propagation.

Synthetic, vendor-neutral FuncRows. The finder recovers the D-2 blind spot (a function whose
command sink hides inside a thin wrapper it calls) while staying narrow: one hop, intra-binary,
and only for functions that have no command sink of their own. These tests pin that boundary.
"""

from __future__ import annotations

import json

from treasure_map.lib.diff.loader import FuncRow
from treasure_map.lib.hunt.wrapper_propagation import find_wrapper_propagated_candidates


def _fn(
    func_id: int,
    name: str,
    pseudocode: str,
    callees: list[str],
    *,
    binary_id: int = 1,
    binary: str = "netd",
) -> FuncRow:
    return FuncRow(
        func_id=func_id,
        binary_id=binary_id,
        binary_name=binary,
        binary_path=f"sbin/{binary}",
        binary_sha256=str(binary_id).zfill(64),
        name=name,
        address=f"{func_id:08x}",
        pseudocode=pseudocode,
        pseudocode_hash=f"h{func_id}",
        callees=json.dumps(callees),
    )


# The thin wrapper present in most fixtures: body ≈ system(param).
_WRAPPER = _fn(1, "do_cmd", "void do_cmd(char* param_1){ system(param_1); }", ["system"])

# The thin FORMAT-STRING wrapper: forwards a parameter into printf's format position (arg0).
_FMT_WRAPPER = _fn(1, "log_msg", "void log_msg(char* param_1){ printf(param_1); }", ["printf"])


def _names(cands) -> set[str]:
    return {c.func.name for c in cands}


def test_caller_of_thin_wrapper_becomes_candidate() -> None:
    caller = _fn(
        2,
        "set_route",
        'void set_route(void){ char cmd[128]; snprintf(cmd,128,"route %s",x); do_cmd(cmd); }',
        ["snprintf", "do_cmd"],
    )
    cands = find_wrapper_propagated_candidates([_WRAPPER, caller])
    assert _names(cands) == {"set_route"}
    (c,) = cands
    assert c.wrapper_name == "do_cmd"
    assert c.wrapped_sink == "system"


def test_function_with_direct_cmd_sink_is_not_propagated() -> None:
    # Already a direct command candidate (the shape scan owns it) -> not recovered here.
    direct = _fn(
        2,
        "has_system",
        'void has_system(char* p){ char c[64]; snprintf(c,64,"%s",p); system(c); do_cmd(c); }',
        ["snprintf", "system", "do_cmd"],
    )
    assert find_wrapper_propagated_candidates([_WRAPPER, direct]) == []


def test_wrapper_itself_is_not_a_propagated_candidate() -> None:
    # do_cmd calls system directly -> excluded by the direct-cmd-sink rule (its own bare_sink).
    assert find_wrapper_propagated_candidates([_WRAPPER]) == []


def test_cross_binary_wrapper_is_not_propagated() -> None:
    # The wrapper lives in a different binary -> a cross-binary hop, a blind spot, not propagated.
    wrapper_libb = _fn(
        1,
        "do_cmd",
        "void do_cmd(char* param_1){ system(param_1); }",
        ["system"],
        binary_id=2,
        binary="libb",
    )
    caller_a = _fn(
        2,
        "caller",
        'void caller(void){ char c[64]; snprintf(c,64,"%s",x); do_cmd(c); }',
        ["snprintf", "do_cmd"],
    )
    assert find_wrapper_propagated_candidates([wrapper_libb, caller_a]) == []


def test_multi_hop_wrapper_is_not_propagated() -> None:
    # f -> middle -> do_cmd: the wrapper is not a DIRECT callee of f -> one-hop rule excludes it.
    middle = _fn(2, "middle", "void middle(char* a){ do_cmd(a); }", ["do_cmd"])
    f = _fn(
        3,
        "outer",
        'void outer(void){ char c[64]; snprintf(c,64,"%s",x); middle(c); }',
        ["snprintf", "middle"],
    )
    cands = find_wrapper_propagated_candidates([_WRAPPER, middle, f])
    # 'middle' itself is a one-hop caller of do_cmd (recovered); 'outer' is two hops (not).
    assert _names(cands) == {"middle"}


def test_component_binary_wrapper_propagated() -> None:
    """★ A wrapper in a widely-shipped stock binary forwards its caller's argument to a sink
    exactly as one anywhere else does.

    This pass used to skip such a binary by name, so the caller was never recovered — a recall
    decision taken on the label rather than on the code. Which project the binary came from is for
    the read side to weigh; it is not grounds for the recall pass to never look.

    MUTATION: put a name-based ``continue`` back in the registration pass -> RED.
    """
    wrapper = _fn(1, "do_cmd", "void do_cmd(char* p){ system(p); }", ["system"], binary="busybox")
    caller = _fn(
        2,
        "applet",
        'void applet(void){ char c[64]; snprintf(c,64,"%s",x); do_cmd(c); }',
        ["snprintf", "do_cmd"],
        binary="busybox",
    )
    (c,) = find_wrapper_propagated_candidates([wrapper, caller])
    assert c.func.name == "applet"
    assert c.func.binary_name == "busybox"


def test_lib_binary_wrapper_propagated() -> None:
    """The other half of the retired heuristic, and the costlier one: ``lib*`` matched every
    shared object in the firmware, custom ones included.

    MUTATION: put the name-based ``continue`` back -> RED.
    """
    wrapper = _fn(
        1, "do_cmd", "void do_cmd(char* p){ system(p); }", ["system"], binary="libshared.so"
    )
    caller = _fn(
        2,
        "forward",
        'void forward(void){ char c[64]; snprintf(c,64,"%s",x); do_cmd(c); }',
        ["snprintf", "do_cmd"],
        binary="libshared.so",
    )
    (c,) = find_wrapper_propagated_candidates([wrapper, caller])
    assert c.func.name == "forward"
    assert c.func.binary_name == "libshared.so"


def test_no_wrapper_means_no_candidates() -> None:
    a = _fn(
        1,
        "a",
        'void a(void){ char c[64]; snprintf(c,64,"%s",x); notify(c); }',
        ["snprintf", "notify"],
    )
    assert find_wrapper_propagated_candidates([a]) == []


def test_deterministic_wrapper_pick_when_several() -> None:
    # Caller invokes two wrappers once each: one candidate per call, ordered by wrapper name.
    w2 = _fn(2, "run_sh", 'void run_sh(char* param_1){ popen(param_1,"r"); }', ["popen"])
    caller = _fn(
        3,
        "multi",
        'void multi(void){ char c[64]; snprintf(c,64,"%s",x); do_cmd(c); run_sh(c); }',
        ["snprintf", "do_cmd", "run_sh"],
    )
    cands = find_wrapper_propagated_candidates([_WRAPPER, w2, caller])
    assert [(c.wrapper_name, c.occurrence) for c in cands] == [("do_cmd", 0), ("run_sh", 0)]


# ── the format-string axis (缺口①): symmetric one-hop propagation through a thin fmt wrapper ──


def test_caller_of_thin_fmt_wrapper_becomes_fmt_candidate() -> None:
    # The D-2 blind spot on the format-string axis: f builds a message and forwards it to a thin
    # format wrapper; the printf-family sink lives inside the wrapper, invisible to the shape scan.
    caller = _fn(
        2,
        "handle_req",
        'void handle_req(void){ char m[128]; snprintf(m,128,"got %s",x); log_msg(m); }',
        ["snprintf", "log_msg"],
    )
    (c,) = find_wrapper_propagated_candidates([_FMT_WRAPPER, caller])
    assert c.func.name == "handle_req"
    assert c.wrapper_name == "log_msg"
    assert c.wrapped_sink == "printf"
    assert c.sink_class == "fmt_string"


def test_function_with_direct_fmt_sink_is_not_propagated() -> None:
    # Already a direct format-string candidate (the shape scan owns it) -> not recovered here.
    direct = _fn(
        2,
        "has_fmt",
        "void has_fmt(char* p){ fprintf(stderr, p, 0); log_msg(p); }",
        ["fprintf", "log_msg"],
    )
    assert find_wrapper_propagated_candidates([_FMT_WRAPPER, direct]) == []


def test_cross_binary_fmt_wrapper_is_not_propagated() -> None:
    wrapper_libb = _fn(
        1,
        "log_msg",
        "void log_msg(char* param_1){ printf(param_1); }",
        ["printf"],
        binary_id=2,
        binary="libb",
    )
    caller_a = _fn(
        2,
        "caller",
        'void caller(void){ char m[64]; snprintf(m,64,"%s",x); log_msg(m); }',
        ["snprintf", "log_msg"],
    )
    assert find_wrapper_propagated_candidates([wrapper_libb, caller_a]) == []


def test_cmd_and_fmt_axes_both_recovered_for_one_function() -> None:
    # A function that forwards through BOTH a cmd wrapper and a fmt wrapper (and has neither sink
    # directly) is recovered once per axis — two candidates, distinct sink classes.
    caller = _fn(
        2,
        "dispatch",
        'void dispatch(void){ char m[64]; snprintf(m,64,"%s",x); do_cmd(m); log_msg(m); }',
        ["snprintf", "do_cmd", "log_msg"],
    )
    cands = find_wrapper_propagated_candidates([_WRAPPER, _FMT_WRAPPER, caller])
    assert {c.sink_class for c in cands} == {"cmd", "fmt_string"}
    assert {c.func.name for c in cands} == {"dispatch"}
    by_axis = {c.sink_class: c for c in cands}
    assert by_axis["cmd"].wrapped_sink == "system"
    assert by_axis["fmt_string"].wrapped_sink == "printf"


# ── a stripped binary: the wrapped sink call is spelled after its lazy-binding stub ───────────


def test_a_wrapper_whose_sink_call_is_stub_rendered_is_found_with_the_stub_table() -> None:
    """In a stripped binary the wrapper body reads `FUN_00412000(param_1)` while its (ingest-
    relabelled) callee list already says `system`. With the binary's stub table the call is found
    and the wrapper's callers are recovered; without it the wrapper is not recognised — the gap
    this table closes. The table is per binary: another binary's table does not apply.

    MUTATION (verified RED): stop passing `stub_names` to is_thin_cmd_wrapper in
    find_wrapper_propagated_candidates -> no candidate with the table either."""
    wrapper = _fn(1, "do_cmd", "void do_cmd(char* param_1){ FUN_00412000(param_1); }", ["system"])
    caller = _fn(
        2,
        "set_route",
        'void set_route(void){ char cmd[128]; snprintf(cmd,128,"route %s",x); do_cmd(cmd); }',
        ["snprintf", "do_cmd"],
    )
    assert find_wrapper_propagated_candidates([wrapper, caller]) == []
    cands = find_wrapper_propagated_candidates([wrapper, caller], {1: {0x412000: "system"}})
    assert _names(cands) == {"set_route"}
    assert cands[0].wrapped_sink == "system"
    # a table for another binary says nothing about this one
    assert find_wrapper_propagated_candidates([wrapper, caller], {2: {0x412000: "system"}}) == []


# ── one candidate per CALL to a wrapper ─────────────────────────────────────────────────────────


def test_one_candidate_per_call_in_text_order() -> None:
    """Each call to a wrapper forwards its own argument, so each is its own candidate: two calls to
    do_cmd and one to run_sh give three, ordered by wrapper name then occurrence, each naming its
    wrapper's own entry.

    MUTATION (verified RED): emit only occurrence 0 per wrapper in ``_axis_candidates`` -> two."""
    w2 = _fn(7, "run_sh", 'void run_sh(char* param_1){ popen(param_1,"r"); }', ["popen"])
    caller = _fn(
        9,
        "multi",
        "void multi(void){ run_sh(a); do_cmd(b); do_cmd(c); }",
        ["do_cmd", "run_sh"],
    )
    cands = find_wrapper_propagated_candidates([_WRAPPER, w2, caller])
    assert [(c.wrapper_name, c.occurrence, c.wrapper_addr) for c in cands] == [
        ("do_cmd", 0, _WRAPPER.address),
        ("do_cmd", 1, _WRAPPER.address),
        ("run_sh", 0, w2.address),
    ]


def test_direct_sink_on_the_axis_skips_every_wrapper_call() -> None:
    caller = _fn(
        9,
        "both",
        "void both(void){ system(a); do_cmd(b); do_cmd(c); }",
        ["system", "do_cmd"],
    )
    assert find_wrapper_propagated_candidates([_WRAPPER, caller]) == []


def test_unlocatable_wrapper_call_keeps_one_function_level_candidate() -> None:
    """The callee list names the wrapper but the text calls it through a pointer: one candidate,
    occurrence None — never dropped, never guessed onto a call.

    MUTATION (verified RED): drop the fallback in ``_axis_candidates`` -> no candidate."""
    caller = _fn(
        9,
        "indirect",
        "void indirect(void){ code *ptr; ptr = do_cmd; (*ptr)(a); }",
        ["do_cmd"],
    )
    (c,) = find_wrapper_propagated_candidates([_WRAPPER, caller])
    assert (c.wrapper_name, c.occurrence, c.wrapper_addr) == ("do_cmd", None, _WRAPPER.address)


def test_calls_are_counted_with_the_stub_table_the_readers_use() -> None:
    """A call rendered after its stub (``FUN_<addr>(…)``) counts as a call to the wrapper when the
    binary's stub table resolves it, in text order with the plain calls — the same enumeration the
    per-call argument readers use, so candidate k and the call whose argument is read agree.

    MUTATION (verified RED): count calls without ``stub_names`` in ``_axis_candidates`` -> one
    candidate, and occurrence 1 then reads a call that does not exist."""
    from treasure_map.lib.hunt.analyzer2 import _wrapper_sink_arg

    pc = "void f(void){ FUN_00012340(first); do_cmd(second); }"
    caller = _fn(9, "f", pc, ["do_cmd"])
    stubs = {0x12340: "do_cmd"}
    cands = find_wrapper_propagated_candidates([_WRAPPER, caller], {1: stubs})
    assert [c.occurrence for c in cands] == [0, 1]
    read = [_wrapper_sink_arg(pc, "do_cmd", None, stubs, c.occurrence) for c in cands]
    assert read == ["first", "second"]
