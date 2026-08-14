# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
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

from treasure_map.lib.pattern.classes import (
    CMD,
    COPY,
    FMT_STRING,
    FORMAT,
    SOURCE,
    SOURCE_STRONG,
    SOURCE_WEAK,
    format_string_ident,
)

OriginKind = Literal["strong_source", "weak_source", "parameter", "unknown"]

# Identifiers that are NOT variables and must not become flow edges (they pollute the flow
# set and let an unrelated validator spuriously "cover" a dangerous input). Callee names are
# detected per-function; these cover C/Ghidra type words and control keywords.
_CALL_CLASS_NAMES = SOURCE | FORMAT | COPY | CMD | FMT_STRING
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
        # JSON string getters: the returned pointer carries the external value (see classes.py).
        "json_object_get_string",
        "json_object_get_string_len",
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

# Caller-supplied values, including the ones the decompiler could not bind to a recovered
# parameter slot. On MIPS/ARM with an unrecovered calling convention, arguments and
# callee-saved caller state surface as in_stack_*/unaff_*/in_<reg> rather than param_N. They
# are caller-supplied for grading purposes, so the parameter-origin rule (caller control is
# unprovable within one function -> never confirmed) must apply to them too. param_\d+ alone
# missed them, which is the root cause of intra-procedural false-confirms on stripped MIPS
# firmware. The alternatives are anchored to the decompiler's generated prefixes and do NOT
# match ordinary stack locals (acStack_*/auStack_*/local_*) or names like in_addr.
_CALLER_SUPPLIED_RE = re.compile(
    r"param_\d+"
    r"|in_stack_[0-9a-fx]+"
    r"|unaff_\w+"
    r"|in_(?:a[0-3]|v[01]|t\d|s[0-8]|k[01]|at|gp|sp|fp|ra)\b",
    re.IGNORECASE,
)

# Markers that the decompiler did NOT soundly recover the frame/ABI. A "confirmed" verdict
# claims a clean source-to-sink flow fully visible within the function; that claim is unsound
# when arguments / caller state surface as placeholders. extraout_* is a prior call's output
# the decompiler could not thread through normal flow; the explicit "unknown calling
# convention" comment is best-effort (only some decompiler versions emit it into getC()).
_ABI_UNRECOVERED_RE = re.compile(
    r"in_stack_[0-9a-fx]+"
    r"|unaff_\w+"
    r"|extraout_\w+"
    r"|in_(?:a[0-3]|v[01]|t\d|s[0-8]|k[01]|at|gp|sp|fp|ra)\b"
    r"|unknown calling convention",
    re.IGNORECASE,
)


def abi_unrecovered(pseudocode: str) -> bool:
    """True when the decompiler did not soundly recover this function's frame/ABI.

    Used to demote a would-be ``confirmed`` to ``unknown`` (never to invent ``blocked``): a
    confirmed flow must be fully visible within the function, which is not establishable when
    arguments/caller state appear as in_stack_*/unaff_*/in_<reg>/extraout_* placeholders.
    """
    return _ABI_UNRECOVERED_RE.search(pseudocode) is not None


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


def locate_format_arg(pseudocode: str, sink_name: str) -> str | None:
    """Return the identifier feeding a format-string sink's FORMAT argument (the danger axis).

    The format position is per-sink (fprintf -> arg1, printf -> arg0, …); a literal format
    argument is safe and yields None. Returns the first non-literal format argument's identifier,
    or None when every call passes a literal / the call is unreadable."""
    return format_string_ident(pseudocode, sink_name)


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
    par: set[str] = set(_CALLER_SUPPLIED_RE.findall(pseudocode))

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
    par: set[str] = set(_CALLER_SUPPLIED_RE.findall(pseudocode))
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


def free_taint_reaches(pseudocode: str, sink_var: str, *, safe_vars: set[str]) -> bool:
    """True if a free value reaches ``sink_var`` BYPASSING the recognized safe source.

    A free value is an in-function source-call output (strong/weak) or a caller-supplied
    parameter. ``safe_vars`` are the variables a constraining converter laundered to a safe
    form (e.g. the result of a numeric/charset conversion): the backward walk prunes at them,
    so a value that reaches the sink only THROUGH the converter is not counted as free, while a
    value that reaches the sink by any other route is. This is the parameter-specific guard:
    a downweight that recognizes one safe source must still be suppressed when some other,
    uncontrolled path also reaches the same dangerous argument.
    """
    deps = _derives_map(pseudocode)
    strong, weak, par = _seed_sets(pseudocode)
    free = (strong | weak | par) - safe_vars
    seen = {sink_var}
    stack = [sink_var]
    while stack:
        current = stack.pop()
        if current in safe_vars:
            continue  # the converter laundered everything upstream of here
        if current in free:
            return True
        for src in deps.get(current, ()):
            if src not in seen:
                seen.add(src)
                stack.append(src)
    return False


def origin_of(pseudocode: str, var: str) -> OriginKind:
    """Classify where ``var`` reaching a sink originates, within this function.

    Parameter origin wins over any in-function source under doubt: any caller-supplied
    contribution makes the path unprovable here, which must never grade as confirmed. A
    strong source outranks a weak one only when no parameter contributes.
    """
    strong, weak, par = _taint_sets(pseudocode)
    if var in par or _CALLER_SUPPLIED_RE.fullmatch(var):
        return "parameter"
    if var in strong:
        return "strong_source"
    if var in weak:
        return "weak_source"
    return "unknown"
