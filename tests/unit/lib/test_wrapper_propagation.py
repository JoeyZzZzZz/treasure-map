# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
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
        pseudocode=pseudocode,
        pseudocode_hash=f"h{func_id}",
        callees=json.dumps(callees),
    )


# The thin wrapper present in most fixtures: body ≈ system(param).
_WRAPPER = _fn(1, "do_cmd", "void do_cmd(char* param_1){ system(param_1); }", ["system"])


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
