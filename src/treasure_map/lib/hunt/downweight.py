# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Recognize already-low-yield candidate forms and the third-party-library origin.

These are FP-suppression signals, not verdicts: each names a neutral structural form known
(from manual review) to rarely carry a live issue, so review-ordering can rank it low. A
recognized form is recorded in the instance's existing neutral fields — `blocking_mechanism`
(a categorical form note) or `origin` (`stock_oss_known`) — and the read-side score table
lowers it. Nothing here removes a candidate or grades reachability; under doubt it stays silent
(no form note), so a real candidate is never hidden.

Name-based and intra-procedural by design (like the validator filters): it can miss, and it
prefers to stay silent rather than mislabel. Library recognition fires only on strongly
namespaced public symbols and never defaults to `custom` (a false `custom` would wrongly inflate
the custom/unknown breadth count; a false `stock` is recoverable on review).
"""

from __future__ import annotations

import re

from treasure_map.lib.pattern.classes import SOURCE
from treasure_map.lib.reachability.taint import flows_into

# Neutral categorical form notes stored in blocking_mechanism. Each describes a mechanism, not
# a quality judgment. The read-side review-ordering table maps these to a strong downweight.
NO_SHELL_EXEC = "no_shell_exec"
NUMERIC_SANITIZED = "numeric_sanitized"
CALLER_CONSTANT = "caller_constant"

# exec-family sinks that replace the process image directly (execve(2) path) — no shell, so
# shell metacharacters in an argument are inert. system/popen/doSystem run via a shell and are
# deliberately NOT here.
_EXEC_NO_SHELL: frozenset[str] = frozenset(
    {"execl", "execlp", "execle", "execv", "execvp", "execve"}
)

# A shell explicitly launched through an exec sink ("/bin/sh -c <cmd>") is shell-like after all.
_SHELL_TARGET_RE = re.compile(r'"/bin/sh"|"/bin/bash"|"-c"')

# Numeric conversion / digit-check callees: a value passed through one is constrained to a
# number and cannot carry shell syntax.
_NUMERIC_VALIDATORS: frozenset[str] = frozenset(
    {
        "atoi",
        "atol",
        "atoll",
        "strtol",
        "strtoll",
        "strtoul",
        "strtoull",
        "strtoimax",
        "strtoumax",
        "isdigit",
        "isxdigit",
    }
)

# Strongly namespaced public third-party C/C++ library symbols (NOT vendor symbols). A match
# means stock OSS even when statically linked into a custom-named binary — which the
# binary-granularity OSS exclusion cannot see.
_THIRD_PARTY_SYMBOL_RE = re.compile(
    r"(?:"
    r"^_ZN6apache|^_ZN6thrift|^apache::|^thrift::"  # apache thrift (mangled / demangled)
    r"|^mbedtls_|^mbedtls::"  # mbed TLS
    r"|^SSL_|^EVP_|^BIO_|^X509_|^RSA_|^EC_|^CRYPTO_|^OPENSSL_"  # openssl
    r"|^json_object_|^json_tokener_|^json_c_"  # json-c
    r"|^cJSON_"  # cJSON
    r"|^curl_|^Curl_"  # curl
    r"|^xmlParse|^xmlNode|^xmlDoc|^xmlFree"  # libxml2
    r")"
)


def library_origin(func_name: str | None) -> str | None:
    """Return 'stock_oss_known' if the symbol names a known public library, else None.

    Conservative: only strongly namespaced symbols match. Never returns 'custom' — an
    unrecognized symbol stays 'unknown' upstream (a false 'custom' would wrongly inflate the
    custom/unknown breadth count; a false 'stock' is recoverable on review)."""
    if not func_name:
        return None
    return "stock_oss_known" if _THIRD_PARTY_SYMBOL_RE.search(func_name) else None


def _exec_is_no_shell(sink_name: str, pseudocode: str) -> bool:
    if sink_name not in _EXEC_NO_SHELL:
        return False
    return not _SHELL_TARGET_RE.search(pseudocode)


def _value_is_numeric(pseudocode: str, callees: list[str], sink_arg: str) -> bool:
    """A numeric validator constrains a value on the sink's flow path (path-aware)."""
    present = {c.strip() for c in callees} & _NUMERIC_VALIDATORS
    if not present:
        return False
    path = {sink_arg} | flows_into(pseudocode, sink_arg)
    for conv in present:
        for var in path:
            # conv( ... var ... )  — the path variable is validated/converted, OR
            if re.search(rf"\b{re.escape(conv)}\s*\([^;{{}}]*\b{re.escape(var)}\b", pseudocode):
                return True
            # var = ... conv(...)  — the path variable is the conversion's result.
            if re.search(rf"\b{re.escape(var)}\b\s*=[^;]*\b{re.escape(conv)}\s*\(", pseudocode):
                return True
    return False


def _call_arglist(caller_pseudocode: str, func_name: str) -> str | None:
    """Return the paren-balanced argument text of the first call to func_name, or None."""
    for m in re.finditer(rf"\b{re.escape(func_name)}\s*\(", caller_pseudocode):
        i = m.end() - 1  # at the '('
        depth = 0
        for j in range(i, len(caller_pseudocode)):
            ch = caller_pseudocode[j]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return caller_pseudocode[i + 1 : j]
    return None


def _caller_only_constants(
    func_name: str | None, callees: list[str], callers_pseudocode: list[str]
) -> bool:
    """One-hop: the function pulls no in-function source and EVERY direct caller passes a
    string literal in its call to it (so the value is a caller-supplied constant).

    Conservative — returns False when there are no callers, when any caller's call cannot be
    located, or when any caller passes no literal. Strictly one hop (no transitive propagation;
    multi-hop / cross-artifact constant tracing is L3, out of scope here)."""
    if not func_name or not callers_pseudocode:
        return False
    if {c.strip() for c in callees} & SOURCE:
        # the function takes external input directly; a constant caller arg is not the whole story
        return False
    for caller_src in callers_pseudocode:
        args = _call_arglist(caller_src, func_name)
        if args is None or '"' not in args:
            return False
    return True


def detect_form_signal(
    *,
    sink_name: str | None,
    pseudocode: str,
    callees: list[str],
    sink_arg: str | None,
    func_name: str | None = None,
    callers_pseudocode: list[str] | None = None,
) -> str | None:
    """Return one neutral form note to downweight this candidate, or None.

    Checked strongest-safe first. Returns None under any doubt (no downweight), so recall is
    never reduced — a missed downweight only leaves a candidate at its normal score."""
    if _caller_only_constants(func_name, callees, callers_pseudocode or []):
        return CALLER_CONSTANT
    if sink_arg is not None and _value_is_numeric(pseudocode, callees, sink_arg):
        return NUMERIC_SANITIZED
    if sink_name is not None and _exec_is_no_shell(sink_name, pseudocode):
        return NO_SHELL_EXEC
    return None
