# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for lib/hunt/downweight — FP-suppression form signals + library recognition.

Pure functions over synthetic, vendor-neutral pseudocode. Each form note is a neutral
mechanism label; recognition is conservative (silent under doubt) so recall is never reduced.
"""

from __future__ import annotations

import re
from pathlib import Path

from treasure_map.lib.hunt.downweight import (
    CALLER_CONSTANT,
    CHARSET_CONSTRAINED,
    CONST_SINK_ARG,
    NO_SHELL_EXEC,
    NUMERIC_SANITIZED,
    detect_form_signal,
    library_origin,
)

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
    # Bug1 reverse: the function's cmd capability is NOT all exec-no-shell (it also calls system),
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
        'snprintf(c,32,"cmd %s",n); system(c); }'
    )
    assert (
        detect_form_signal(
            sink_name="system",
            pseudocode=pc,
            callees=["strtol", "snprintf", "system"],
            sink_arg="c",
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
            func_name="run",
            callers_pseudocode=[caller],
        )
        == CALLER_CONSTANT
    )


def test_caller_constant_plus_tainted_arg_is_not_caller_constant() -> None:
    # Bug2 reverse: f("prefix", tainted) — one constant arg, one controllable arg. A constant in
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


# ── .rodata constant sink argument (#12: gate vs content) ─────────────────────────────


def test_constant_sink_argument_is_const_sink_arg() -> None:
    # The command string is a fixed .rodata constant — the highest-frequency cmd false positive.
    pc = 'void f(void){ system("/sbin/reboot"); }'
    assert (
        detect_form_signal(sink_name="system", pseudocode=pc, callees=["system"], sink_arg="sbin")
        == CONST_SINK_ARG
    )


def test_external_input_gating_a_branch_still_const_sink_arg() -> None:
    # #12: external input EXISTS (getenv) and gates a branch, but it never flows INTO the sink's
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


def test_external_input_flowing_into_sink_arg_is_not_downweighted() -> None:
    # #12 reverse: the external value actually flows INTO the sink argument (content, not gate) —
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


# ── safe-charset-constrained source (②: ether_ntoa / inet_ntop / base64) ───────────────


def test_ether_ntoa_constrained_value_is_charset_constrained() -> None:
    # The value reaching the sink is a MAC address rendered by ether_ntoa -> constrained to a safe
    # character set (hex + ':'), so it cannot carry shell syntax even via the %s command format.
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
        == CHARSET_CONSTRAINED
    )


def test_charset_safe_plus_free_source_into_same_sink_is_not_downweighted() -> None:
    # ② reverse: the SAME sink argument is built from BOTH a charset-safe value (ether_ntoa) AND a
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


# ── inline charset-safe converter on the cmd path (②: same口径 as the assigned form) ───
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
        )
        == CHARSET_CONSTRAINED
    )


def test_inline_charset_on_copy_path_is_unchanged() -> None:
    # Same口径 on the copy path (no regression / same recognition): a strcpy destination built
    # inline from a charset-safe converter is charset_constrained just like the cmd path.
    pc = "void f(struct ether_addr* mac){ char d[64]; strcpy(d, ether_ntoa(mac)); }"
    assert (
        detect_form_signal(
            sink_name="strcpy",
            pseudocode=pc,
            callees=["ether_ntoa", "strcpy"],
            sink_arg="d",
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


# ── charset through a ONE-HOP intermediate buffer (factor ②: conv -> buf -> sink) ─────
#
# A command built from a value laundered through one intermediate buffer (the realistic
# `conv(); strncpy(buf,...); snprintf(cmd,...,buf); system(cmd)` shape). Recall-neutral: the
# all-writes rule + free_taint_reaches still suppress any free value, at any hop.


def _charset_via_buffer(copy: str) -> str:
    return (
        f"void f(struct ether_addr* x){{ char b[32]; char cmd[128]; char* p=ether_ntoa(x); "
        f'{copy}(b,p,32); snprintf(cmd,128,"echo %s",b); system(cmd); }}'
    )


def test_charset_via_strncpy_buffer_is_constrained() -> None:
    assert (
        detect_form_signal(
            sink_name="system",
            pseudocode=_charset_via_buffer("strncpy"),
            callees=["ether_ntoa", "strncpy", "snprintf", "system"],
            sink_arg="cmd",
        )
        == CHARSET_CONSTRAINED
    )


def test_charset_via_strlcpy_buffer_is_constrained() -> None:
    # strlcpy is not in the global COPY set (the dependency graph cannot follow it). The one-hop
    # charset recognizer handles it explicitly, so this realistic shape is now downweighted.
    assert (
        detect_form_signal(
            sink_name="system",
            pseudocode=_charset_via_buffer("strlcpy"),
            callees=["ether_ntoa", "strlcpy", "snprintf", "system"],
            sink_arg="cmd",
        )
        == CHARSET_CONSTRAINED
    )


def test_free_source_via_buffer_is_not_downweighted() -> None:
    # ★ recall-neutral: a free nvram string laundered through the SAME buffer shape must NOT be
    # downweighted (this is the function-B class — a free string through an intermediate buffer).
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


# ── factor ⑤: one-hop caller-constant downweight covers the cmd path ──────────────────


def test_caller_constant_covers_cmd_sink() -> None:
    # A function whose sole one-hop caller invokes it with only a string literal -> the cmd sink's
    # dangerous parameter is a caller constant (downweighted). Confirms cmd-path coverage.
    pc = "void run(char* param_1){ system(param_1); }"
    caller = 'void boot(void){ run("/etc/init.d/rcS"); }'
    assert (
        detect_form_signal(
            sink_name="system",
            pseudocode=pc,
            callees=["system"],
            sink_arg="param_1",
            func_name="run",
            callers_pseudocode=[caller],
        )
        == CALLER_CONSTANT
    )


def test_caller_variable_does_not_make_cmd_caller_constant() -> None:
    pc = "void run(char* param_1){ system(param_1); }"
    caller = "void boot(char* v){ run(v); }"
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


# ── library / symbol recognition (function granularity) ──────────────────────────────


def test_known_library_symbols_are_stock_oss() -> None:
    for name in (
        "SSL_read",
        "EVP_DecryptUpdate",
        "mbedtls_ssl_handshake",
        "json_object_get",
        "curl_easy_setopt",
        "cJSON_Parse",
        "_ZN6apache6thrift9TXxxxE",
    ):
        assert library_origin(name) == "stock_oss_known", name


def test_unknown_symbols_are_not_classified() -> None:
    # Custom-looking names never become a library origin (and NEVER default to custom).
    for name in ("handle_request", "ssl_helper", "my_json_parse", "main", None):
        assert library_origin(name) is None, name


# ── boundary: neutral, no banned vocabulary, no vendor strings ───────────────────────


def test_downweight_module_is_boundary_clean() -> None:
    banned = re.compile(
        r"\b(vuln\w*|exploit\w*|payload|\bpoc\b|finding|incomplete_patch|fix_quality)\b",
        re.IGNORECASE,
    )
    text = _DOWNWEIGHT.read_text()
    assert not banned.search(text)
    assert not re.search(r"§|PRD\s", text)
