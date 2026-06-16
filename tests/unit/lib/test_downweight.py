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
