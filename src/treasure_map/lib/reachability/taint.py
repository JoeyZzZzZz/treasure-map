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

from treasure_map.lib.pattern.classes import COPY, FORMAT, SOURCE_STRONG, SOURCE_WEAK

OriginKind = Literal["strong_source", "weak_source", "parameter", "unknown"]

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
