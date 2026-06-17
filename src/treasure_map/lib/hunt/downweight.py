# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Recognize already-low-yield candidate forms and the third-party-library origin.

These are FP-suppression signals, not verdicts: each names a neutral structural form known
(from manual review) to rarely carry a live issue, so review-ordering can rank it low. A
recognized form is recorded in the instance's existing neutral fields — `blocking_mechanism`
(a categorical form note) or `origin` (`stock_oss_known`) — and the read-side score table
lowers it. Nothing here removes a candidate or grades reachability; under doubt it stays silent
(no form note), so a real candidate is never hidden.

★ Parameter-specific by construction. A form downweight fires ONLY when the sink's dangerous
argument truly comes only from the recognized safe/constant source. If any free value — an
unsanitized string source or a caller-supplied parameter — also reaches that argument by a route
that bypasses the safe source, the downweight is suppressed (`free_taint_reaches`). Recognizing
"a safe thing exists in the function" is NOT the same as "the sink's dangerous argument is only
that safe thing"; conflating the two is how a constant-prefixed-but-tainted call, a branch-gating
(not value-flowing) external input, or a mixed safe+free format string would be wrongly hidden.

Name-based and intra-procedural by design (like the validator filters): it can miss, and it
prefers to stay silent rather than mislabel. Library recognition fires only on strongly
namespaced public symbols and never defaults to `custom` (a false `custom` would wrongly inflate
the custom/unknown breadth count; a false `stock` is recoverable on review).
"""

from __future__ import annotations

import re

from treasure_map.lib.pattern.classes import CMD, SOURCE
from treasure_map.lib.reachability.taint import flows_into, free_taint_reaches

# Neutral categorical form notes stored in blocking_mechanism. Each describes a mechanism, not
# a quality judgment. The read-side review-ordering table maps these to a strong downweight.
NO_SHELL_EXEC = "no_shell_exec"
NUMERIC_SANITIZED = "numeric_sanitized"
CALLER_CONSTANT = "caller_constant"
CONST_SINK_ARG = "const_sink_arg"
CHARSET_CONSTRAINED = "charset_constrained"

# exec-family sinks that replace the process image directly (execve(2) path) — no shell, so
# shell metacharacters in an argument are inert. system/popen/doSystem run via a shell and are
# deliberately NOT here.
_EXEC_NO_SHELL: frozenset[str] = frozenset(
    {"execl", "execlp", "execle", "execv", "execvp", "execve"}
)

# A shell explicitly launched through an exec sink ("/bin/sh -c <cmd>") is shell-like after all.
_SHELL_TARGET_RE = re.compile(r'"/bin/sh"|"/bin/bash"|"-c"')

# Shell-running command sinks whose FIRST argument is the command string itself. For these a
# literal first argument is a constant command (const_sink_arg). Exec-family sinks are excluded:
# their first argument is the program path (a constant path is normal) and the controllable argv
# is a later argument, so a literal first argument says nothing about the dangerous value.
_SHELL_RUN_SINKS: frozenset[str] = frozenset({"system", "popen", "doSystem"})

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

# Converters whose OUTPUT is constrained to a safe character set (no shell metacharacters): MAC /
# IP address formatting and base64 ENCODING. NOT exhaustive — the list only needs to be useful;
# a missing converter merely leaves one safe candidate at its normal score (never a false miss),
# and a new device's converter is a one-line addition, not a defect. (base64/b64 DECODE is the
# opposite — it yields arbitrary bytes — and is treated as an input source elsewhere, not here.)
_CHARSET_SAFE: frozenset[str] = frozenset(
    {
        "ether_ntoa",
        "inet_ntoa",
        "inet_ntop",
        "base64_encode",
        "b64_encode",
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


def _cmd_callees(callees: list[str]) -> set[str]:
    return {c.strip() for c in callees} & CMD


def _exec_is_no_shell(callees: list[str], pseudocode: str) -> bool:
    """The function's WHOLE command-sink capability is exec-without-a-shell.

    Bug1 fix — parameter-specific: it is not enough that the anchored sink is an exec; the
    function must have NO shell-running command sink at all (`cmd ⊆ exec-no-shell`). A function
    that calls both system and execl is shell-capable and must never be downweighted no_shell."""
    cmd = _cmd_callees(callees)
    if not cmd or not (cmd <= _EXEC_NO_SHELL):
        return False
    return not _SHELL_TARGET_RE.search(pseudocode)


def _sink_arg_is_literal(pseudocode: str, sink_name: str) -> bool:
    """True when the sink's first argument is a direct string literal (a .rodata constant).

    `system("/sbin/reboot")` — the dangerous argument is a fixed string, not a controllable
    value, so it is the highest-frequency command false positive. Matching the literal directly
    (not via a variable) keeps this parameter-specific: a variable argument that a free value can
    reach does not match here, so it is never wrongly downweighted. Restricted to shell-running
    sinks — an exec-family first argument is the program path, not the command."""
    if sink_name not in _SHELL_RUN_SINKS:
        return False
    return re.search(rf'\b{re.escape(sink_name)}\s*\(\s*"', pseudocode) is not None


def _constrained_results(pseudocode: str, path: set[str], converters: frozenset[str]) -> set[str]:
    """Variables on ``path`` that are the RESULT of a constraining converter (`lhs = …conv(…)`).

    Conversion-result only: a value laundered to a safe form is the conversion's output, not its
    input. This keeps the safe set sound — if a raw input ALSO reaches the sink by another route
    it is not in this set, so the bypass guard still sees it."""
    results: set[str] = set()
    for stmt in re.split(r"[;\n{}]", pseudocode):
        assign = re.match(r"\s*[^=]*?\b([A-Za-z_]\w*)\s*=\s*(?!=)(.*)", stmt)
        if assign is None:
            continue
        lhs, rhs = assign.group(1), assign.group(2)
        if lhs not in path:
            continue
        if any(re.search(rf"\b{re.escape(conv)}\s*\(", rhs) for conv in converters):
            results.add(lhs)
    return results


def _value_is_constrained(pseudocode: str, sink_arg: str, converters: frozenset[str]) -> bool:
    """The sink argument's value is the result of a ``converters`` conversion AND no free value
    bypasses it. Parameter-specific: a converter merely appearing in the function is not enough."""
    path = {sink_arg} | flows_into(pseudocode, sink_arg)
    safe = _constrained_results(pseudocode, path, converters)
    if not safe:
        return False
    return not free_taint_reaches(pseudocode, sink_arg, safe_vars=safe)


def _split_args(arglist: str) -> list[str]:
    """Split a call's argument text on top-level commas (respecting string literals)."""
    parts: list[str] = []
    depth = 0
    in_str = False
    buf: list[str] = []
    i = 0
    while i < len(arglist):
        ch = arglist[i]
        if in_str:
            buf.append(ch)
            if ch == "\\" and i + 1 < len(arglist):
                buf.append(arglist[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
            buf.append(ch)
        elif ch in "([":
            depth += 1
            buf.append(ch)
        elif ch in ")]":
            depth -= 1
            buf.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    if buf:
        parts.append("".join(buf))
    return parts


_LITERAL_ARG_RE = re.compile(r'^\s*(?:"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)\'|[+-]?\d[\w.]*)\s*$')


def _all_args_literal(arglist: str) -> bool:
    """True when EVERY argument is a string / char / numeric literal (no controllable identifier).

    Bug2 fix — parameter-specific: a constant in some argument slot is not enough; a single
    non-literal argument means a controllable value may reach the sink's dangerous parameter, so
    `f("prefix", tainted)` must not be downweighted."""
    args = _split_args(arglist)
    if not args:
        return False
    return all(_LITERAL_ARG_RE.match(a) for a in args)


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
    """One-hop: the function pulls no in-function source and EVERY direct caller passes ONLY
    string/numeric literals in its call to it (so the dangerous parameter is a caller constant).

    Conservative — returns False when there are no callers, when any caller's call cannot be
    located, or when any caller passes a non-literal argument (a controllable value could reach
    the dangerous parameter; `f("prefix", tainted)` is NOT a caller constant). Strictly one hop
    (no transitive propagation; multi-hop / cross-artifact constant tracing is L3, out of scope)."""
    if not func_name or not callers_pseudocode:
        return False
    if {c.strip() for c in callees} & SOURCE:
        # the function takes external input directly; a constant caller arg is not the whole story
        return False
    for caller_src in callers_pseudocode:
        args = _call_arglist(caller_src, func_name)
        if args is None or not _all_args_literal(args):
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

    Every branch is parameter-specific (see the module docstring): it fires only when the sink's
    dangerous argument truly comes only from the recognized safe/constant source. Returns None
    under any doubt (no downweight), so recall is never reduced — a missed downweight only leaves
    a candidate at its normal score."""
    if _caller_only_constants(func_name, callees, callers_pseudocode or []):
        return CALLER_CONSTANT
    if sink_name is not None and _sink_arg_is_literal(pseudocode, sink_name):
        return CONST_SINK_ARG
    if sink_arg is not None and _value_is_constrained(pseudocode, sink_arg, _NUMERIC_VALIDATORS):
        return NUMERIC_SANITIZED
    if sink_arg is not None and _value_is_constrained(pseudocode, sink_arg, _CHARSET_SAFE):
        return CHARSET_CONSTRAINED
    if _exec_is_no_shell(callees, pseudocode):
        return NO_SHELL_EXEC
    return None
