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
    cands = find_wrapper_propagated_candidates([_WRAPPER, caller], set())
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
    assert find_wrapper_propagated_candidates([_WRAPPER, direct], set()) == []


def test_wrapper_itself_is_not_a_propagated_candidate() -> None:
    # do_cmd calls system directly -> excluded by the direct-cmd-sink rule (its own bare_sink).
    assert find_wrapper_propagated_candidates([_WRAPPER], set()) == []


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
    assert find_wrapper_propagated_candidates([wrapper_libb, caller_a], set()) == []


def test_multi_hop_wrapper_is_not_propagated() -> None:
    # f -> middle -> do_cmd: the wrapper is not a DIRECT callee of f -> one-hop rule excludes it.
    middle = _fn(2, "middle", "void middle(char* a){ do_cmd(a); }", ["do_cmd"])
    f = _fn(
        3,
        "outer",
        'void outer(void){ char c[64]; snprintf(c,64,"%s",x); middle(c); }',
        ["snprintf", "middle"],
    )
    cands = find_wrapper_propagated_candidates([_WRAPPER, middle, f], set())
    # 'middle' itself is a one-hop caller of do_cmd (recovered); 'outer' is two hops (not).
    assert _names(cands) == {"middle"}


def test_oss_binary_is_excluded() -> None:
    wrapper = _fn(1, "do_cmd", "void do_cmd(char* p){ system(p); }", ["system"], binary="busybox")
    caller = _fn(
        2,
        "applet",
        'void applet(void){ char c[64]; snprintf(c,64,"%s",x); do_cmd(c); }',
        ["snprintf", "do_cmd"],
        binary="busybox",
    )
    assert find_wrapper_propagated_candidates([wrapper, caller], {"busybox"}) == []


def test_no_wrapper_means_no_candidates() -> None:
    a = _fn(
        1,
        "a",
        'void a(void){ char c[64]; snprintf(c,64,"%s",x); notify(c); }',
        ["snprintf", "notify"],
    )
    assert find_wrapper_propagated_candidates([a], set()) == []


def test_deterministic_wrapper_pick_when_several() -> None:
    # Caller invokes two wrappers; the candidate names one deterministically (first by name).
    w2 = _fn(2, "run_sh", 'void run_sh(char* param_1){ popen(param_1,"r"); }', ["popen"])
    caller = _fn(
        3,
        "multi",
        'void multi(void){ char c[64]; snprintf(c,64,"%s",x); do_cmd(c); run_sh(c); }',
        ["snprintf", "do_cmd", "run_sh"],
    )
    (c,) = find_wrapper_propagated_candidates([_WRAPPER, w2, caller], set())
    assert c.wrapper_name == "do_cmd"  # 'do_cmd' < 'run_sh'


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
    (c,) = find_wrapper_propagated_candidates([_FMT_WRAPPER, caller], set())
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
    assert find_wrapper_propagated_candidates([_FMT_WRAPPER, direct], set()) == []


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
    assert find_wrapper_propagated_candidates([wrapper_libb, caller_a], set()) == []


def test_cmd_and_fmt_axes_both_recovered_for_one_function() -> None:
    # A function that forwards through BOTH a cmd wrapper and a fmt wrapper (and has neither sink
    # directly) is recovered once per axis — two candidates, distinct sink classes.
    caller = _fn(
        2,
        "dispatch",
        'void dispatch(void){ char m[64]; snprintf(m,64,"%s",x); do_cmd(m); log_msg(m); }',
        ["snprintf", "do_cmd", "log_msg"],
    )
    cands = find_wrapper_propagated_candidates([_WRAPPER, _FMT_WRAPPER, caller], set())
    assert {c.sink_class for c in cands} == {"cmd", "fmt_string"}
    assert {c.func.name for c in cands} == {"dispatch"}
    by_axis = {c.sink_class: c for c in cands}
    assert by_axis["cmd"].wrapped_sink == "system"
    assert by_axis["fmt_string"].wrapped_sink == "printf"
