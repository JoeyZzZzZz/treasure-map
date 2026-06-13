# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Intra-procedural taint helpers — a single-function read, nothing more.

These helpers see one function's pseudocode at a time. They can often tell whether the
value reaching a sink came from an external-input call made in THIS function (and how
strongly that input is externally controllable), or from a function parameter
(caller-supplied), but they cannot trace control across call boundaries. When the origin
is not clear within the function, they say so ("unknown") rather than guess. This is a
deliberately shallow heuristic, not a data-flow engine.

Taint follows REAL flow, not mere co-occurrence: a source call taints only the value it
actually produces — the assigned variable for a return-value source, or the specific
buffer argument for a buffer-output source — never every identifier that happens to be
passed to it.
"""

from __future__ import annotations

import re
from typing import Literal

from treasure_map.lib.pattern.classes import CMD, COPY, FORMAT, SOURCE, SOURCE_STRONG, SOURCE_WEAK

OriginKind = Literal["strong_source", "weak_source", "parameter", "unknown"]

# Identifiers that are NOT variables and must not become flow edges (they pollute the flow
# set and let an unrelated validator spuriously "cover" a dangerous input). Callee names are
# detected per-function; these cover C/Ghidra type words and control keywords.
_CALL_CLASS_NAMES = SOURCE | FORMAT | COPY | CMD
_TYPE_WORDS = frozenset(
    {
        "char",
        "int",
        "uint",
        "void",
        "short",
        "long",
        "size_t",
        "ssize_t",
        "bool",
        "unsigned",
        "signed",
        "float",
        "double",
        "const",
        "static",
        "struct",
        "union",
        "enum",
        "sizeof",
        "byte",
        "word",
        "dword",
        "qword",
        "code",
        "undefined",
        "return",
        "if",
        "else",
        "for",
        "while",
        "do",
        "switch",
        "case",
        "goto",
        "break",
        "continue",
    }
)
# Ghidra-style sized type words (undefined4, uint32, int8, ...) and the leftover of a split
# hex literal (0x96 -> "x96" once the leading 0 is dropped by the identifier regex).
_SIZED_TYPE_RE = re.compile(r"^(?:undefined|uint|int|u|byte|word|dword|qword|ushort|uchar)\d+$")
_HEX_FRAGMENT_RE = re.compile(r"^x[0-9a-fA-F]+$")
_HEX_LITERAL_RE = re.compile(r"\b0[xX][0-9a-fA-F]+\b")

# Return-value sources: the tainted value is the call's return, bound to the assigned LHS.
_RETURN_SOURCES: frozenset[str] = frozenset(
    {
        "getenv",
        "nvram_get",
        "nvram_safe_get",
        "nvram_bufget",
        "websGetVar",
        "webGetVar",
        "getKeyValue",
        "get_cgi",
        "b64_decode",
        "base64_decode",
    }
)

# Buffer-output sources: the source writes into one argument buffer, at a known position.
_BUFFER_SOURCE_ARG: dict[str, int] = {
    "recv": 1,
    "recvfrom": 1,
    "read": 1,
    "fread": 0,
    "fgets": 0,
    "gets": 0,
}

_CALL_RE = re.compile(r"([A-Za-z_]\w*)\s*\(([^()]*)\)")
_ASSIGN_RE = re.compile(r"\s*[^=]*?\b([A-Za-z_]\w*)\s*=\s*(?!=)(.*)")
_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
_PARAM_RE = re.compile(r"param_\d+")


def locate_sink_arg(pseudocode: str, sink_name: str) -> str | None:
    """Return the identifier feeding the sink's first argument (the command string).

    Targets the first argument, which is the command/destination for system/popen-style
    sinks. Returns None when the sink call or a usable argument identifier is not found.
    """
    match = re.search(rf"\b{re.escape(sink_name)}\s*\(\s*([^,)]+)", pseudocode)
    if not match:
        return None
    ident = _IDENT_RE.search(match.group(1))
    return ident.group(0) if ident else None


def _arg_ident(args: str, pos: int) -> str | None:
    """Return the leading identifier of the comma-separated argument at ``pos``."""
    parts = args.split(",")
    if pos >= len(parts):
        return None
    ident = _IDENT_RE.search(parts[pos])
    return ident.group(0) if ident else None


def _seed_source(
    name: str,
    args: str,
    lhs: str | None,
    rhs: str,
    strong: set[str],
    weak: set[str],
) -> None:
    """Seed taint for one source call onto the value it actually produces."""
    target = strong if name in SOURCE_STRONG else weak
    if name in _RETURN_SOURCES:
        # Return-value source: only the assigned variable carries the input.
        if lhs is not None and name in rhs:
            target.add(lhs)
        return
    pos = _BUFFER_SOURCE_ARG.get(name)
    if pos is not None:
        # Buffer-output source: only the buffer argument it writes into.
        buf = _arg_ident(args, pos)
        if buf is not None:
            target.add(buf)
    # Sources we cannot precisely attribute (e.g. scanf-family) seed nothing — under-taint
    # is the safe direction (it biases toward "unknown", never toward over-claiming).


def _taint_sets(pseudocode: str) -> tuple[set[str], set[str], set[str]]:
    """Return (strong_tainted, weak_tainted, param_tainted) variable-name sets.

    strong_tainted: variables fed by a STRONG (network/request) in-function source.
    weak_tainted: variables fed by a WEAK (env/config/device-self/file) in-function source.
    param_tainted: variables that are, or derive from, a function parameter.
    Propagation runs to a fixed point over real assignments and formatter/copy builders.
    """
    statements = re.split(r"[;\n{}]", pseudocode)
    strong: set[str] = set()
    weak: set[str] = set()
    par: set[str] = set(_PARAM_RE.findall(pseudocode))

    prev = (-1, -1, -1)
    for _ in range(len(statements) + 2):
        for stmt in statements:
            assign = _ASSIGN_RE.match(stmt)
            lhs = assign.group(1) if assign else None
            rhs = assign.group(2) if assign else ""

            for name, args in _CALL_RE.findall(stmt):
                if name in SOURCE_STRONG or name in SOURCE_WEAK:
                    _seed_source(name, args, lhs, rhs, strong, weak)
                if name in FORMAT or name in COPY:
                    # Builders: first arg is the destination, the rest are inputs; the
                    # destination inherits whatever taint flows in.
                    ids = _IDENT_RE.findall(args)
                    if ids:
                        dst, rest = ids[0], set(ids[1:])
                        if rest & strong:
                            strong.add(dst)
                        if rest & weak:
                            weak.add(dst)
                        if rest & par:
                            par.add(dst)

            if lhs is not None:
                rhs_idents = set(_IDENT_RE.findall(rhs))
                if rhs_idents & strong:
                    strong.add(lhs)
                if rhs_idents & weak:
                    weak.add(lhs)
                if rhs_idents & par:
                    par.add(lhs)

        snapshot = (len(strong), len(weak), len(par))
        if snapshot == prev:
            break
        prev = snapshot

    return strong, weak, par


def _dep_idents(text: str, call_names: set[str]) -> set[str]:
    """Plausible variable identifiers in ``text`` — pollution (callee names, type words,
    hex fragments) removed so the flow set stays trustworthy."""
    cleaned = _HEX_LITERAL_RE.sub(" ", text)
    out: set[str] = set()
    for ident in _IDENT_RE.findall(cleaned):
        if ident in call_names or ident in _CALL_CLASS_NAMES or ident in _TYPE_WORDS:
            continue
        if _SIZED_TYPE_RE.match(ident) or _HEX_FRAGMENT_RE.match(ident):
            continue
        out.add(ident)
    return out


def _derives_map(pseudocode: str) -> dict[str, set[str]]:
    """Map each variable to the variables it is directly assigned/built from.

    Edges come from the same real assignment/builder forms the forward taint uses:
    `lhs = ... X ...` and formatter/copy builders `f(dst, ... X ...)` (dst derives from
    the remaining args). Identifiers are cleaned (callee names / type words / hex fragments
    dropped) so the flow set is not polluted; conservative — only explicit edges recorded.
    """
    call_names = {m.group(1) for m in _CALL_RE.finditer(pseudocode)}
    deps: dict[str, set[str]] = {}
    for stmt in re.split(r"[;\n{}]", pseudocode):
        assign = _ASSIGN_RE.match(stmt)
        if assign is not None:
            lhs, rhs = assign.group(1), assign.group(2)
            deps.setdefault(lhs, set()).update(_dep_idents(rhs, call_names) - {lhs})
        for name, args in _CALL_RE.findall(stmt):
            if name in FORMAT or name in COPY:
                parts = args.split(",")
                dst_match = _IDENT_RE.search(parts[0]) if parts else None
                if dst_match is not None:
                    dst = dst_match.group(0)
                    rest = _dep_idents(",".join(parts[1:]), call_names) - {dst}
                    deps.setdefault(dst, set()).update(rest)
    return deps


def _seed_sets(pseudocode: str) -> tuple[set[str], set[str], set[str]]:
    """Return the directly-seeded (strong, weak, parameter) inputs — pre-propagation.

    These are the ORIGINATING tainted values (a source's buffer/return, or a parameter),
    not the propagated copies. Coverage is judged against these seeds so that validating a
    seed (or any variable on its path to the sink) counts, while a validated, unrelated
    intermediate cannot mask a seed.
    """
    strong: set[str] = set()
    weak: set[str] = set()
    par: set[str] = set(_PARAM_RE.findall(pseudocode))
    for stmt in re.split(r"[;\n{}]", pseudocode):
        assign = _ASSIGN_RE.match(stmt)
        lhs = assign.group(1) if assign else None
        rhs = assign.group(2) if assign else ""
        for name, args in _CALL_RE.findall(stmt):
            if name in SOURCE_STRONG or name in SOURCE_WEAK:
                _seed_source(name, args, lhs, rhs, strong, weak)
    return strong, weak, par


def flows_into(pseudocode: str, sink_var: str) -> set[str]:
    """Return the variables that flow into ``sink_var`` (its backward dependency set).

    Walks the assignment/builder edges backward from sink_var to a fixed point. The
    returned set does NOT include sink_var itself. Used to recognize a validator applied
    to the value reaching the sink even after intermediate copies/format calls rename it.
    """
    deps = _derives_map(pseudocode)
    seen: set[str] = set()
    stack = [sink_var]
    while stack:
        current = stack.pop()
        for src in deps.get(current, ()):
            if src not in seen:
                seen.add(src)
                stack.append(src)
    return seen


def origin_of(pseudocode: str, var: str) -> OriginKind:
    """Classify where ``var`` reaching a sink originates, within this function.

    Parameter origin wins over any in-function source under doubt: any caller-supplied
    contribution makes the path unprovable here, which must never grade as confirmed. A
    strong source outranks a weak one only when no parameter contributes.
    """
    strong, weak, par = _taint_sets(pseudocode)
    if var in par or _PARAM_RE.fullmatch(var):
        return "parameter"
    if var in strong:
        return "strong_source"
    if var in weak:
        return "weak_source"
    return "unknown"
