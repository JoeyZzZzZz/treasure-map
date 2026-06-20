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

from treasure_map.lib.pattern.classes import CMD, COPY, FORMAT, SOURCE
from treasure_map.lib.reachability.taint import _IDENT_RE, flows_into, free_taint_reaches

# Leading callee name of a call expression (used to find builder calls in a statement).
_CALL_RE_HEAD = re.compile(r"\b([A-Za-z_]\w*)\s*\(")

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


def _is_converter_call(text: str, converters: frozenset[str]) -> bool:
    """True when ``text`` (one call argument or assignment RHS) is a single inline converter
    call — `conv(...)`, allowing a leading cast `(type)` / address-of `&` / deref `*`. The
    converter's OUTPUT is charset-constrained by construction regardless of its inputs, so this
    recognizes the laundering even when the result is never bound to its own variable."""
    m = re.match(r"^[&*]?\s*(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(", text.strip())
    return m is not None and m.group(1) in converters


def _is_charset_benign(text: str, converters: frozenset[str]) -> bool:
    """True when ``text`` cannot introduce a free value: a literal (string/char/numeric/size
    constant) or a single inline charset-safe converter call. A bare identifier or any
    non-converter call is NOT benign — it may carry a free, uncontrolled value."""
    return bool(_LITERAL_ARG_RE.match(text.strip())) or _is_converter_call(text, converters)


def _names_var(text: str, names: set[str]) -> bool:
    """True when ``text`` is a bare reference to a variable in ``names`` (optional cast / & / *),
    and NOT a call. Distinguishes `buf_a` (a copied-in value) from `conv(buf_a)` (a call)."""
    if not names:
        return False
    m = re.match(r"^[&*]?\s*(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*$", text.strip())
    return m is not None and m.group(1) in names


# Bounded string-copy callees that move a value into their FIRST-argument buffer but are NOT in
# the global COPY set the taint graph uses. Recognizing them HERE — only to grow the charset-safe
# set under the all-writes rule + the free_taint_reaches guard — lets a one-hop intermediate
# buffer be recognized even when the global taint graph does not track the copy callee (e.g.
# strlcpy breaks the dependency edge). Never used for recall, shape detection, or grading.
_CHARSET_COPY_EXTRA: frozenset[str] = frozenset({"strlcpy", "strlcat", "stpcpy", "stpncpy"})

# One converter round + ONE intermediate-buffer hop (conv -> buf -> sink). The chain is capped at
# a single intermediate variable on purpose: a longer chain (conv -> buf1 -> buf2 -> sink) is a
# known blind spot — the structured flow evidence records it as untraced rather than the recognizer
# silently following it. (The free-value guard below still applies at every depth, so recall is
# never reduced regardless of the cap.)
_CHARSET_CHAIN_ROUNDS = 2


def _inline_constrained_results(pseudocode: str, converters: frozenset[str]) -> set[str]:
    """Variables built ONLY from charset-safe converter results / literals — including one hop
    through an intermediate buffer — where the converter result is not bound to its own
    `lhs = conv(...)` variable.

    Handles `snprintf(c,"...%s",ether_ntoa(x)); system(c)` (inline, no intermediate) AND the
    one-hop intermediate-buffer shape `strncpy(buf,ether_ntoa(x),n); snprintf(c,"...%s",buf);
    system(c)` (the value laundered through a bounded copy before the command builder), even when
    the copy callee is one the global taint graph does not track.

    Recall-safe by an all-writes rule applied at EVERY level: a variable qualifies ONLY when each
    write to it (a format/copy builder destination or a plain assignment) is a literal, an inline
    charset-safe converter, or a copy from an already-qualified variable — AND its lineage involves
    a converter. So a later free write (`strcat(c,user)`), a free value mixed into the same builder
    (`snprintf(c,"%s %s",ether_ntoa(x),raw)`), or a free seed feeding the intermediate buffer
    (`strncpy(buf,nvram_get(0),n)`) disqualifies the variable. The propagation is capped at one
    intermediate hop; a deeper chain is left unrecognized (a blind spot), never followed silently.
    The free_taint_reaches guard in the caller still applies at every depth."""
    builders = FORMAT | COPY | _CHARSET_COPY_EXTRA
    # Collect every write once: (destination, [value-arg, ...]). Builder destinations are the
    # first argument; a plain assignment's single "value arg" is its RHS.
    writes: list[tuple[str, list[str]]] = []
    for stmt in re.split(r"[;\n{}]", pseudocode):
        for name in {m.group(1) for m in _CALL_RE_HEAD.finditer(stmt)} & builders:
            args = _call_arglist(stmt, name)
            if args is None:
                continue
            parts = _split_args(args)
            if not parts:
                continue
            dst_ident = _IDENT_RE.search(parts[0])
            if dst_ident is None:
                continue
            writes.append((dst_ident.group(0), parts[1:]))
        assign = re.match(r"\s*[^=]*?\b([A-Za-z_]\w*)\s*=\s*(?!=)(.*)", stmt)
        if assign is not None:
            writes.append((assign.group(1), [assign.group(2)]))

    qualified: set[str] = set()
    for _ in range(_CHARSET_CHAIN_ROUNDS):
        all_benign: dict[str, bool] = {}
        has_converter: dict[str, bool] = {}
        for dst, value_args in writes:
            benign = True
            converter = False
            for arg in value_args:
                if _is_converter_call(arg, converters) or _names_var(arg, qualified):
                    converter = True  # a converter, or a value copied from an already-safe var
                elif not _is_charset_benign(arg, converters):
                    benign = False
            all_benign[dst] = all_benign.get(dst, True) and benign
            has_converter[dst] = has_converter.get(dst, False) or converter
        new_qualified = {v for v, ok in all_benign.items() if ok and has_converter.get(v)}
        if new_qualified == qualified:
            break
        qualified = new_qualified
    return qualified


def _value_is_constrained(pseudocode: str, sink_arg: str, converters: frozenset[str]) -> bool:
    """The sink argument's value is the result of a ``converters`` conversion AND no free value
    bypasses it. Parameter-specific: a converter merely appearing in the function is not enough."""
    path = {sink_arg} | flows_into(pseudocode, sink_arg)
    safe = _constrained_results(pseudocode, path, converters)
    # Inline form: a value built directly from charset-safe converter results / literals, with no
    # intermediate `lhs = conv(...)` to name the output. Intersected with the sink path and still
    # guarded by free_taint_reaches below (the all-writes rule in the helper closes the
    # multi-write / mixed-free cases), so this only ADDS recognitions, never relaxes the guard.
    safe |= _inline_constrained_results(pseudocode, converters) & path
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
