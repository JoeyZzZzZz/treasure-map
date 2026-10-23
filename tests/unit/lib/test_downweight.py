# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for lib/hunt/downweight — FP-suppression form signals + library recognition.

Pure functions over synthetic, vendor-neutral pseudocode. Each form note is a neutral
mechanism label; recognition is conservative (silent under doubt) so recall is never reduced.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from treasure_map.lib.hunt.downweight import (
    CALLER_CONSTANT,
    CHARSET_CONSTRAINED,
    CONST_SINK_ARG,
    NO_SHELL_EXEC,
    NUMERIC_SANITIZED,
    detect_form_signal,
)

from ..boundary_words import listed_words_in

_SRC = Path(__file__).resolve().parents[3] / "src" / "treasure_map"
_DOWNWEIGHT = _SRC / "lib" / "hunt" / "downweight.py"


# ── exec without a shell ────────────────────────────────────────────────────────────


def test_execl_without_shell_is_no_shell_exec() -> None:
    pc = (
        "void h(char* p){ char c[64]; recv(fd,c,64); "
        'snprintf(c,64,"/usr/bin/tool %s",p); execl(c,c,0); }'
    )
    assert (
        detect_form_signal(
            sink_name="execl", pseudocode=pc, callees=["recv", "snprintf", "execl"], sink_arg="c"
        )
        == NO_SHELL_EXEC
    )


def test_execl_via_bin_sh_dash_c_is_not_downweighted() -> None:
    # An exec that launches "/bin/sh" "-c" IS shell-like — must NOT be flagged no_shell_exec.
    pc = 'void h(char* p){ char c[64]; snprintf(c,64,"reboot %s",p); execl("/bin/sh","-c",c,0); }'
    assert (
        detect_form_signal(
            sink_name="execl", pseudocode=pc, callees=["snprintf", "execl"], sink_arg="c"
        )
        is None
    )


def test_system_is_never_no_shell_exec() -> None:
    pc = 'void h(char* p){ char c[64]; snprintf(c,64,"x %s",p); system(c); }'
    assert (
        detect_form_signal(
            sink_name="system", pseudocode=pc, callees=["snprintf", "system"], sink_arg="c"
        )
        is None
    )


def test_mixed_system_and_execl_is_not_no_shell_exec() -> None:
    # Reverse: the function's cmd capability is NOT all exec-no-shell (it also calls system),
    # so it is shell-capable and must not be downweighted no_shell — even though an exec is present.
    pc = (
        "void h(char* p){ char c[64]; snprintf(c,64,"
        '"tool %s",p); if (p) execl(c,c,0); else system(c); }'
    )
    assert (
        detect_form_signal(
            sink_name="system",  # the danger-anchored sink
            pseudocode=pc,
            callees=["snprintf", "execl", "system"],
            sink_arg="c",
        )
        is None
    )


# ── numeric sanitization on the path ─────────────────────────────────────────────────


def test_numeric_validated_value_is_numeric_sanitized() -> None:
    # the value n on the path to the sink is the result of strtol -> numeric, so it cannot
    # carry shell syntax even though the cmd format still interpolates with %s.
    pc = (
        "void h(char* p){ char c[32]; long n = strtol(p,0,10); "
        'snprintf(c,32,"cmd %d",n); system(c); }'
    )
    assert (
        detect_form_signal(
            sink_name="system",
            pseudocode=pc,
            callees=["strtol", "snprintf", "system"],
            sink_arg="c",
            sink_form="var",
        )
        == NUMERIC_SANITIZED
    )


def test_no_numeric_validator_is_not_numeric_sanitized() -> None:
    pc = 'void h(char* p){ char c[32]; snprintf(c,32,"cmd %s",p); system(c); }'
    assert (
        detect_form_signal(
            sink_name="system", pseudocode=pc, callees=["snprintf", "system"], sink_arg="c"
        )
        is None
    )


# ── caller-constant (one hop) ────────────────────────────────────────────────────────


def test_caller_passes_only_constant_is_caller_constant() -> None:
    # The sink function takes no in-function source; its single caller passes a string literal.
    pc = "void run(char* param_1){ system(param_1); }"
    caller = 'void boot(void){ run("/etc/init.d/rcS start"); }'
    assert (
        detect_form_signal(
            sink_name="system",
            pseudocode=pc,
            callees=["system"],
            sink_arg="param_1",
            sink_form="var",
            func_name="run",
            callers_pseudocode=[caller],
        )
        == CALLER_CONSTANT
    )


def test_caller_passes_variable_is_not_caller_constant() -> None:
    pc = "void run(char* param_1){ system(param_1); }"
    caller = "void h(char* q){ run(q); }"  # passes a variable, not a literal
    assert (
        detect_form_signal(
            sink_name="system",
            pseudocode=pc,
            callees=["system"],
            sink_arg="param_1",
            func_name="run",
            callers_pseudocode=[caller],
        )
        is None
    )


def test_function_with_own_source_is_not_caller_constant() -> None:
    # If the function pulls external input itself, a constant caller arg is not the whole story.
    pc = "void run(char* param_1){ char b[32]; recv(fd,b,32); system(b); }"
    caller = 'void boot(void){ run("const"); }'
    assert (
        detect_form_signal(
            sink_name="system",
            pseudocode=pc,
            callees=["recv", "system"],
            sink_arg="b",
            func_name="run",
            callers_pseudocode=[caller],
        )
        is None
    )


def test_no_callers_is_not_caller_constant() -> None:
    pc = "void run(char* param_1){ system(param_1); }"
    assert (
        detect_form_signal(
            sink_name="system",
            pseudocode=pc,
            callees=["system"],
            sink_arg="param_1",
            func_name="run",
            callers_pseudocode=[],
        )
        is None
    )


def test_caller_all_constant_args_is_caller_constant() -> None:
    # Every caller argument is a literal -> the dangerous parameter is a caller constant.
    pc = "void run(char* param_1, char* param_2){ system(param_2); }"
    caller = 'void boot(void){ run("prefix", "/etc/init.d/rcS start"); }'
    assert (
        detect_form_signal(
            sink_name="system",
            pseudocode=pc,
            callees=["system"],
            sink_arg="param_2",
            sink_form="var",
            func_name="run",
            callers_pseudocode=[caller],
        )
        == CALLER_CONSTANT
    )


def test_caller_constant_plus_tainted_arg_is_not_caller_constant() -> None:
    # Reverse: f("prefix", tainted) — one constant arg, one controllable arg. A constant in
    # SOME slot is not enough; a controllable value can reach the dangerous parameter -> no drop.
    pc = "void run(char* param_1, char* param_2){ system(param_2); }"
    caller = 'void h(char* q){ run("prefix", q); }'
    assert (
        detect_form_signal(
            sink_name="system",
            pseudocode=pc,
            callees=["system"],
            sink_arg="param_2",
            func_name="run",
            callers_pseudocode=[caller],
        )
        is None
    )


# ── .rodata constant sink argument (gate vs content) ──────────────────────────────────


def test_constant_sink_argument_is_const_sink_arg() -> None:
    # The command string is a fixed .rodata constant — the highest-frequency cmd false positive.
    pc = 'void f(void){ system("/sbin/reboot"); }'
    assert (
        detect_form_signal(sink_name="system", pseudocode=pc, callees=["system"], sink_arg="sbin")
        == CONST_SINK_ARG
    )


def test_external_input_gating_a_branch_still_const_sink_arg() -> None:
    # External input EXISTS (getenv) and gates a branch, but it never flows INTO the sink's
    # argument (a constant). Gate != content — the constant command is still downweighted.
    pc = 'void f(void){ char* m = getenv("MODE"); if (m != 0) { system("/sbin/reboot"); } }'
    assert (
        detect_form_signal(
            sink_name="system",
            pseudocode=pc,
            callees=["getenv", "system"],
            sink_arg="sbin",
        )
        == CONST_SINK_ARG
    )


def test_free_string_alongside_a_constant_call_is_not_downweighted() -> None:
    # ★ Red-line regression: the function has BOTH a constant system("...") and a system(free_var)
    # whose argument is a free-string source. The old whole-function regex saw the constant and
    # wrongly downweighted the tainted candidate to const_sink_arg. Parameter-specific now: the
    # anchored candidate's OWN sink_arg is free-reached, so const_sink_arg must NOT fire (Gate A).
    pc = (
        'void f(void){ system("ubus call system board"); '
        "char* cmd = json_object_get_string(o); system(cmd); }"
    )
    assert (
        detect_form_signal(
            sink_name="system",
            pseudocode=pc,
            callees=["system", "json_object_get_string"],
            sink_arg="cmd",
        )
        is None
    )


def test_external_input_flowing_into_sink_arg_is_not_downweighted() -> None:
    # Reverse: the external value actually flows INTO the sink argument (content, not gate) —
    # not a constant, not constrained -> must NOT be downweighted (source_class stays lit).
    pc = 'void f(void){ char* m = getenv("X"); char c[64]; snprintf(c,64,"echo %s",m); system(c); }'
    assert (
        detect_form_signal(
            sink_name="system",
            pseudocode=pc,
            callees=["getenv", "snprintf", "system"],
            sink_arg="c",
        )
        is None
    )


# ── safe-charset-constrained source (ether_ntoa / inet_ntop / base64) ──────────────────


def test_ether_ntoa_via_intermediate_variable_is_not_downweighted() -> None:
    # Charset is INLINE-ONLY: once the converter result is bound to an intermediate variable (s)
    # before the command builder, the value is no longer value-tracked here -> NOT downweighted
    # (the evidence layer marks it charset_maybe instead). Retracted from an earlier behaviour.
    pc = (
        "void f(struct ether_addr* mac){ char* s = ether_ntoa(mac); char c[64]; "
        'snprintf(c,64,"arp -s %s",s); system(c); }'
    )
    assert (
        detect_form_signal(
            sink_name="system",
            pseudocode=pc,
            callees=["ether_ntoa", "snprintf", "system"],
            sink_arg="c",
        )
        is None
    )


def test_charset_safe_plus_free_source_into_same_sink_is_not_downweighted() -> None:
    # Reverse: the SAME sink argument is built from BOTH a charset-safe value (ether_ntoa) AND a
    # free string source (nvram_get). One safe contributor does not make the argument safe -> the
    # free path bypassing the converter must suppress the downweight.
    pc = (
        "void f(struct ether_addr* mac){ char* s = ether_ntoa(mac); char* v = nvram_get(0); "
        'char c[96]; snprintf(c,96,"set %s %s",s,v); system(c); }'
    )
    assert (
        detect_form_signal(
            sink_name="system",
            pseudocode=pc,
            callees=["ether_ntoa", "nvram_get", "snprintf", "system"],
            sink_arg="c",
        )
        is None
    )


# ── inline charset-safe converter on the cmd path (same recognition as the assigned form) ──
#
# The assigned form (lhs = conv(...)) above already downweights a system() candidate. These
# cover the realistic command-building shape where the converter RESULT is passed inline into
# the format builder with no intermediate variable — the form a cmd_injection_shape candidate
# typically takes, and the one that previously escaped the downweight on the cmd path.


def test_inline_ether_ntoa_into_system_is_charset_constrained() -> None:
    # snprintf(c,...,ether_ntoa(mac)); system(c) — no `s = ether_ntoa(...)` to name the result.
    pc = (
        "void f(struct ether_addr* mac){ char c[64]; "
        'snprintf(c,64,"arp -s %s",ether_ntoa(mac)); system(c); }'
    )
    assert (
        detect_form_signal(
            sink_name="system",
            pseudocode=pc,
            callees=["ether_ntoa", "snprintf", "system"],
            sink_arg="c",
            sink_form="var",
        )
        == CHARSET_CONSTRAINED
    )


def test_inline_inet_ntop_into_system_is_charset_constrained() -> None:
    pc = (
        "void f(int fd){ char c[80]; char ip[16]; "
        'snprintf(c,80,"route add %s",inet_ntop(2,&fd,ip,16)); system(c); }'
    )
    assert (
        detect_form_signal(
            sink_name="system",
            pseudocode=pc,
            callees=["inet_ntop", "snprintf", "system"],
            sink_arg="c",
            sink_form="var",
        )
        == CHARSET_CONSTRAINED
    )


def test_inline_charset_on_copy_path_is_unchanged() -> None:
    # The same rule on the copy path (no regression / same recognition): a strcpy destination built
    # inline from a charset-safe converter is charset_constrained just like the cmd path.
    pc = "void f(struct ether_addr* mac){ char d[64]; strcpy(d, ether_ntoa(mac)); }"
    assert (
        detect_form_signal(
            sink_name="strcpy",
            pseudocode=pc,
            callees=["ether_ntoa", "strcpy"],
            sink_arg="d",
            sink_form="var",
        )
        == CHARSET_CONSTRAINED
    )


def test_inline_charset_then_free_append_is_not_downweighted() -> None:
    # ★ recall-neutral: an inline converter builds the buffer, but a later strcat appends a free
    # parameter to the SAME buffer. The all-writes rule disqualifies the buffer -> no downweight.
    pc = (
        "void f(struct ether_addr* mac, char* p){ char c[96]; "
        'snprintf(c,96,"x %s",ether_ntoa(mac)); strcat(c,p); system(c); }'
    )
    assert (
        detect_form_signal(
            sink_name="system",
            pseudocode=pc,
            callees=["ether_ntoa", "snprintf", "strcat", "system"],
            sink_arg="c",
        )
        is None
    )


def test_inline_charset_mixed_with_free_arg_is_not_downweighted() -> None:
    # ★ recall-neutral: the SAME builder mixes a charset-safe converter with a free nvram value.
    # One benign contributor does not make the command safe -> no downweight.
    pc = (
        "void f(struct ether_addr* mac){ char* v = nvram_get(0); char c[96]; "
        'snprintf(c,96,"%s %s",ether_ntoa(mac),v); system(c); }'
    )
    assert (
        detect_form_signal(
            sink_name="system",
            pseudocode=pc,
            callees=["ether_ntoa", "nvram_get", "snprintf", "system"],
            sink_arg="c",
        )
        is None
    )


def test_inline_charset_mixed_with_raw_param_is_not_downweighted() -> None:
    # ★ recall-neutral: a raw parameter sits alongside the converter result in the command -> the
    # free param bypasses the converter, so the command must NOT be downweighted.
    pc = (
        "void f(struct ether_addr* mac, char* raw){ char c[96]; "
        'snprintf(c,96,"%s %s",ether_ntoa(mac),raw); system(c); }'
    )
    assert (
        detect_form_signal(
            sink_name="system",
            pseudocode=pc,
            callees=["ether_ntoa", "snprintf", "system"],
            sink_arg="c",
        )
        is None
    )


def test_buffer_seeded_by_param_then_inline_converter_is_not_downweighted() -> None:
    # ★ recall-neutral: the buffer is first aliased to a free parameter, then a converter writes
    # it. The plain-assignment write (c = p) is not charset-benign -> the buffer is disqualified.
    pc = (
        "void f(struct ether_addr* mac, char* p){ char* c = p; "
        'snprintf(c,64,"%s",ether_ntoa(mac)); system(c); }'
    )
    assert (
        detect_form_signal(
            sink_name="system",
            pseudocode=pc,
            callees=["ether_ntoa", "snprintf", "system"],
            sink_arg="c",
        )
        is None
    )


# ── charset is INLINE-ONLY: a value through an intermediate buffer is NOT downweighted ─
#
# The retraction: charset recognition does not value-track through any intermediate variable
# (no one-hop, no two-hop). A command built from a converter laundered through a buffer is left
# at its normal score and surfaced to the agent as `charset_maybe` (see test_evidence.py).


def _charset_via_buffer(copy: str) -> str:
    return (
        f"void f(struct ether_addr* x){{ char b[32]; char cmd[128]; char* p=ether_ntoa(x); "
        f'{copy}(b,p,32); snprintf(cmd,128,"echo %s",b); system(cmd); }}'
    )


def test_charset_via_strncpy_buffer_is_not_downweighted() -> None:
    # Intermediate buffer (strncpy) -> the converter no longer reaches the sink inline -> NOT
    # downweighted (retracted from the brief one-hop-chaining behaviour).
    assert (
        detect_form_signal(
            sink_name="system",
            pseudocode=_charset_via_buffer("strncpy"),
            callees=["ether_ntoa", "strncpy", "snprintf", "system"],
            sink_arg="cmd",
        )
        is None
    )


def test_charset_via_strlcpy_buffer_is_not_downweighted() -> None:
    assert (
        detect_form_signal(
            sink_name="system",
            pseudocode=_charset_via_buffer("strlcpy"),
            callees=["ether_ntoa", "strlcpy", "snprintf", "system"],
            sink_arg="cmd",
        )
        is None
    )


def test_free_source_via_buffer_is_not_downweighted() -> None:
    # ★ recall-neutral: a free nvram string laundered through the SAME buffer shape must NOT be
    # downweighted (the class of a free string through an intermediate buffer).
    pc = (
        "void g(void){ char b[32]; char cmd[128]; char* v=nvram_get(0); "
        'strlcpy(b,v,32); snprintf(cmd,128,"echo %s",b); system(cmd); }'
    )
    assert (
        detect_form_signal(
            sink_name="system",
            pseudocode=pc,
            callees=["nvram_get", "strlcpy", "snprintf", "system"],
            sink_arg="cmd",
        )
        is None
    )


def test_charset_buffer_with_later_free_append_is_not_downweighted() -> None:
    # ★ recall-neutral: a charset buffer that later receives a free strcat append is disqualified
    # by the all-writes rule.
    pc = (
        "void f(struct ether_addr* x, char* u){ char b[64]; char cmd[128]; "
        'strlcpy(b,ether_ntoa(x),32); strcat(b,u); snprintf(cmd,128,"echo %s",b); system(cmd); }'
    )
    assert (
        detect_form_signal(
            sink_name="system",
            pseudocode=pc,
            callees=["ether_ntoa", "strlcpy", "strcat", "snprintf", "system"],
            sink_arg="cmd",
        )
        is None
    )


def test_free_source_two_buffers_deep_is_not_downweighted() -> None:
    # ★ recall-neutral at depth: a free recv buffer copied through two intermediate buffers still
    # reaches the command unconstrained -> not downweighted (the guard holds at every hop).
    pc = (
        "void f(int fd){ char b1[32]; char b2[32]; char cmd[128]; char raw[64]; recv(fd,raw,64); "
        'strncpy(b1,raw,32); strncpy(b2,b1,32); snprintf(cmd,128,"echo %s",b2); system(cmd); }'
    )
    assert (
        detect_form_signal(
            sink_name="system",
            pseudocode=pc,
            callees=["recv", "strncpy", "snprintf", "system"],
            sink_arg="cmd",
        )
        is None
    )


# ── retired: deciding a function's origin from its symbol NAME ───────────────────────


def test_no_code_reads_a_symbol_name_to_decide_a_library_origin() -> None:
    """The retired guess leaves no callable behind — checked as CODE, not as text.

    It read a symbol name and answered "this is third-party library code", which is the same
    reasoning the by-name binary exclusion was retired for: it holds only while symbols are named
    the way upstream names them, and a stripped firmware does not promise that. It was weak as well
    as unsound — a few libraries' exported API prefixes covered a small share of instances, while
    the same libraries' internal functions went through unlabelled.

    Parsed rather than grepped for a specific reason: the retirement NOTE in downweight.py names
    both symbols on purpose, so that someone about to re-add this reads why it went first. A text
    scan would either fail on that note or force it to be deleted, and the note is the part worth
    keeping. This looks at names the code actually uses — definitions, imports, calls.

    MUTATION (must go RED): re-add ``def library_origin`` anywhere under src/, or call it."""
    import ast

    retired = {"library_origin", "_THIRD_PARTY_SYMBOL_RE"}
    offenders: list[str] = []
    for path in sorted(_SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            used: set[str] = set()
            if isinstance(node, ast.Name):
                used = {node.id}
            elif isinstance(node, ast.Attribute):
                used = {node.attr}
            elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                used = {node.name}
            elif isinstance(node, ast.ImportFrom):
                used = {a.name for a in node.names} | {a.asname or "" for a in node.names}
            if used & retired:
                offenders.append(f"{path.relative_to(_SRC)}:{getattr(node, 'lineno', '?')}")
    assert not offenders, f"retired symbol still live in: {offenders}"


# ── boundary: neutral, no banned vocabulary, no vendor strings ───────────────────────


def test_downweight_module_is_boundary_clean() -> None:
    banned = re.compile(
        r"\b(vuln\w*|exploit\w*|payload|\bpoc\b)\b",
        re.IGNORECASE,
    )
    text = _DOWNWEIGHT.read_text()
    assert not banned.search(text)
    assert not listed_words_in(text)
    assert not re.search(r"§|PRD\s", text)


# ── a constant command form written as a stub-rendered call ─────────────────────────


def test_a_constant_command_named_after_its_stub_is_recognised() -> None:
    """The const-command downweight locates its call through the shared authority.

    ``system("/sbin/reboot")`` is the highest-frequency command false positive, and on a stripped
    binary that same call is often rendered ``FUN_<stub-addr>("/sbin/reboot")``. Without a resolved
    stub table the note does not fire and the candidate keeps its normal rank — the fail-safe
    direction, a missed downweight rather than a wrong one. With the table it is recognised.

    Asserted through detect_form_signal, the real caller, rather than the private helper: a note
    that fires in the helper but never reaches the write path would be no downweight at all.

    MUTATION (measured: 1 failed each, this test alone): drop the stub_names forward in
    detect_form_signal, or in _sink_arg_is_literal -> the second assertion reads None. Both hops
    were measured separately, which is what says the chain is connected end to end rather than
    merely present at one end."""
    pseudo = 'void f(void){ FUN_0041eb38("/sbin/reboot"); }'
    kwargs: dict[str, object] = {
        "sink_name": "system",
        "pseudocode": pseudo,
        "callees": ["system"],
        "sink_arg": None,
    }
    assert detect_form_signal(**kwargs) is None  # type: ignore[arg-type]
    assert (
        detect_form_signal(**kwargs, stub_names={0x41EB38: "system"})  # type: ignore[arg-type]
        == CONST_SINK_ARG
    )


# ── caller_constant: the parameter, every call, every caller ─────────────────────────


def _cc(pc: str, caller: str, sink_arg: str | None, **kw: object) -> str | None:
    return detect_form_signal(
        sink_name="system",
        pseudocode=pc,
        callees=["system"],
        sink_arg=sink_arg,
        sink_form=kw.pop("sink_form", "var"),  # these fixtures forward a plain var parameter
        func_name="run",
        callers_pseudocode=[caller],
        **kw,  # type: ignore[arg-type]
    )


def test_a_second_call_with_a_variable_is_not_caller_constant() -> None:
    """MUTATION: read only each caller's first call -> RED."""
    pc = "void run(char *param_1){ system(param_1); }"
    caller = 'void boot(void){ run("/etc/rc start"); run(websGetVar(wp,"cmd","")); }'
    assert _cc(pc, caller, "param_1") is None


def test_the_danger_value_must_be_the_parameter_itself() -> None:
    """The callers pass param_1; the sink runs a global. What callers pass is not what reaches the
    sink.

    MUTATION: drop the 'sink argument is a parameter' check -> RED."""
    pc = "void run(int param_1){ log_level(param_1); system(g_cmd); }"
    assert _cc(pc, "void boot(void){ run(1); }", "g_cmd") is None


def test_only_the_sinks_parameter_position_is_checked() -> None:
    pc = "void run(char *param_1, char *param_2){ log(param_1); system(param_2); }"
    assert _cc(pc, 'void h(char *q){ run(q, "/etc/rc start"); }', "param_2") == CALLER_CONSTANT


def test_the_calls_own_literal_is_checked_before_the_caller_hint() -> None:
    """When both signals hold for one candidate — its call passes a literal, and its sink argument
    names a parameter every caller passes a constant for — the call's own literal is the note:
    it is read off this call site, while caller_constant is a hint read from callers that may not
    all be known, and only the former is a provably-constant marker. The parameter carries a
    recovered name rather than a ``param_N`` placeholder, because the literal check counts a
    placeholder parameter as a caller-supplied value and would not hold.

    MUTATION: check caller_constant before the call's own literal -> RED (caller_constant)."""
    pc = 'void run(char *cmd){ system("/sbin/reboot"); }'
    assert _cc(pc, 'void boot(void){ run("start"); }', "cmd") == CONST_SINK_ARG


def test_a_rewritten_parameter_is_not_caller_constant() -> None:
    """MUTATION: ignore writes to the parameter in the body -> RED."""
    pc = 'void run(char *param_1){ param_1 = nvram_get("x"); system(param_1); }'
    assert _cc(pc, 'void boot(void){ run("/etc/rc"); }', "param_1") is None


def test_a_function_whose_address_is_taken_is_not_caller_constant() -> None:
    """A callback has callers no call site shows.

    MUTATION: drop the address-taken check -> RED."""
    pc = "void run(char *param_1){ system(param_1); }"
    caller = 'void boot(void){ run("/etc/rc"); register_handler("x", run); }'
    assert _cc(pc, caller, "param_1") is None


def test_no_shell_exec_is_a_command_axis_note_only() -> None:
    """A path candidate in a function whose only command sinks are exec-family must not carry the
    command-side note (it also blocked the path's own literal check).

    MUTATION: emit no_shell_exec for any sink class -> RED."""
    pc = 'void f(char *param_1){ execv("/bin/x", argv); fopen(param_1, "r"); }'
    common = dict(pseudocode=pc, callees=["execv", "fopen"], sink_arg="param_1")
    assert detect_form_signal(sink_name="execv", sink_class="cmd", **common) == "no_shell_exec"  # type: ignore[arg-type]
    assert detect_form_signal(sink_name="fopen", sink_class="path_sink", **common) is None  # type: ignore[arg-type]


def test_a_dosystem_template_with_a_variable_is_not_a_constant_command() -> None:
    """doSystem("ifconfig %s up", name) runs what name holds; the literal is only the template.

    MUTATION: accept any literal first argument for doSystem -> RED."""

    def note(pc: str) -> str | None:
        return detect_form_signal(
            sink_name="doSystem", pseudocode=pc, callees=["doSystem"], sink_arg=None
        )

    assert note('void f(char *n){ doSystem("ifconfig %s up", n); }') is None
    assert note('void f(void){ doSystem("ifconfig %s up", "br0"); }') == CONST_SINK_ARG
    assert note('void f(void){ doSystem("reboot 100%% now"); }') == CONST_SINK_ARG


# ── R5: numeric_sanitized is "every write to the sink buffer is safe" ─────────────────────────


def _num(body: str, sink_arg: str = "b", form: str = "var", sink: str = "fopen") -> str | None:
    pc = "void f(char *x)\n{\n  int i;\n  char b [64];\n" + body + "\n}"
    return detect_form_signal(
        sink_name=sink,
        pseudocode=pc,
        callees=["atoi", sink],
        sink_arg=sink_arg,
        sink_class="path_sink",
        sink_form=form,
    )


# (name, body, is numeric_sanitized). Every body validates x with atoi (the premise).
_R5 = [
    ("integer format", 'i = atoi(x);\n  sprintf(b,"/proc/%d",i);\n  fopen(b,"r");', True),
    ("%s literal", 'i = atoi(x);\n  sprintf(b,"%s/%d","lit",i);\n  fopen(b,"r");', True),
    (
        "offset memset",
        'i = atoi(x);\n  memset(b + 4,0,0x3c);\n  sprintf(b,"/proc/%d",i);\n  fopen(b,"r");',
        True,
    ),
    (
        "element write",
        'i = atoi(x);\n  b[0] = \'\\0\';\n  sprintf(b,"/proc/%d",i);\n  fopen(b,"r");',
        True,
    ),
    ("%s non-literal", 'i = atoi(x);\n  snprintf(b,0x40,"/x/%s-%d",g,i);\n  fopen(b,"w");', False),
    ("vararg count mismatch", 'i = atoi(x);\n  sprintf(b,"/x/%d/%s",i);\n  fopen(b,"r");', False),
    (
        "offset strcpy",
        'i = atoi(x);\n  sprintf(b,"/proc/%d",i);\n  strcpy(b + 6,y);\n  fopen(b,"r");',
        False,
    ),
    ("escape call", 'i = atoi(x);\n  sprintf(b,"/proc/%d",i);\n  foo(b);\n  fopen(b,"r");', False),
    ("alias store", 'i = atoi(x);\n  sprintf(b,"/proc/%d",i);\n  q = &b;\n  fopen(b,"r");', False),
    (
        "F2 not enclosing",
        'i = atoi(x);\n  if (c) {\n    sprintf(b,"/proc/%d",i);\n  }\n  fopen(b,"r");',
        False,
    ),
    (
        "L5 stat writes buf",
        'i = atoi(x);\n  sprintf(b,"/proc/%d",i);\n  stat(y,b);\n  fopen(b,"r");',
        False,
    ),
]


@pytest.mark.parametrize("name,body,want", _R5)
def test_numeric_sanitized_needs_every_buffer_write_safe(name: str, body: str, want: bool) -> None:
    """numeric_sanitized fires only when every write to the sink buffer up to the sink is a safe
    write (literal / constant memset / integer or literal-%s format), nothing escapes or aliases
    it, and it is a local array.

    MUTATION (verified RED): accept a %s with a non-literal vararg -> the ``%s non-literal`` case
    turns True; drop the escape/alias scan -> ``escape call`` / ``alias store`` turn True; drop F1
    -> the global/parameter cases below turn True; drop F2 -> ``F2 not enclosing`` turns True."""
    assert (_num(body) == NUMERIC_SANITIZED) is want, name


def test_numeric_sanitized_requires_a_local_array_buffer() -> None:
    """F1: the buffer must be a local array — a global or a parameter is not provably bounded.

    MUTATION (verified RED): drop the local-array requirement -> both turn numeric_sanitized."""
    glob = (
        "void f(char *x)\n{\n  int i;\n  i = atoi(x);\n"
        '  snprintf(&DAT_0041,0x20,"/proc/%d",i);\n  fopen(&DAT_0041,"w");\n}'
    )
    assert (
        detect_form_signal(
            sink_name="fopen",
            pseudocode=glob,
            callees=["atoi", "fopen"],
            sink_arg="DAT_0041",
            sink_class="path_sink",
            sink_form="addr_of",
        )
        is None
    )
    par = (
        "void f(char *param_1,char *x)\n{\n  int i;\n  i = atoi(x);\n"
        '  sprintf(param_1,"/proc/%d",i);\n  fopen(param_1,"r");\n}'
    )
    assert (
        detect_form_signal(
            sink_name="fopen",
            pseudocode=par,
            callees=["atoi", "fopen"],
            sink_arg="param_1",
            sink_class="path_sink",
            sink_form="var",
        )
        is None
    )


def test_a_loaded_sink_argument_is_never_read_as_safe() -> None:
    """R3: a numeric / charset downweight is trusted only when the root IS the value. A value read
    through a pointer (form ``load``) is never recognized as safe, even when the premise holds.

    MUTATION (verified RED): drop the SAFE_FORMS gate -> the load form is downweighted."""
    body = 'i = atoi(x);\n  sprintf(b,"/proc/%d",i);\n  fopen(b,"r");'
    assert _num(body, form="var") == NUMERIC_SANITIZED  # the var form IS recognized
    assert _num(body, form="load") is None  # the same body read through a pointer is not
