# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Intra-procedural taint helpers — a single-function read, nothing more.

These helpers see one function's pseudocode at a time. They can often tell whether the
value reaching a sink came from an external-input call made in THIS function, or from a
function parameter (caller-supplied), but they cannot trace control across call
boundaries. When the origin is not clear within the function, they say so ("unknown")
rather than guess. This is a deliberately shallow heuristic, not a data-flow engine.
"""

from __future__ import annotations

import re
from typing import Literal

from treasure_map.lib.pattern.classes import COPY, FORMAT, SOURCE

OriginKind = Literal["in_function_source", "parameter", "unknown"]

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


def _taint_sets(pseudocode: str) -> tuple[set[str], set[str]]:
    """Return (source_tainted, param_tainted) variable-name sets for the function.

    source_tainted: variables fed by an external-input call made in this function.
    param_tainted: variables that are, or derive from, a function parameter.
    Propagation runs to a fixed point over simple assignments and formatter/copy builders.
    """
    statements = re.split(r"[;\n{}]", pseudocode)
    src: set[str] = set()
    par: set[str] = set(_PARAM_RE.findall(pseudocode))

    prev = (-1, -1)
    for _ in range(len(statements) + 2):
        for stmt in statements:
            assign = _ASSIGN_RE.match(stmt)
            lhs = assign.group(1) if assign else None
            rhs = assign.group(2) if assign else ""

            for name, args in _CALL_RE.findall(stmt):
                arg_idents = set(_IDENT_RE.findall(args))
                if name in SOURCE:
                    # Buffer-output sources taint the buffers passed to them.
                    src |= arg_idents
                    # Return-value sources taint the assigned variable.
                    if lhs is not None and name in rhs:
                        src.add(lhs)
                if name in FORMAT or name in COPY:
                    # Builders: first arg is the destination, the rest are inputs.
                    ids = _IDENT_RE.findall(args)
                    if ids:
                        dst, rest = ids[0], set(ids[1:])
                        if rest & src:
                            src.add(dst)
                        if rest & par:
                            par.add(dst)

            if lhs is not None:
                rhs_idents = set(_IDENT_RE.findall(rhs))
                if rhs_idents & src:
                    src.add(lhs)
                if rhs_idents & par:
                    par.add(lhs)

        if (len(src), len(par)) == prev:
            break
        prev = (len(src), len(par))

    return src, par


def origin_of(pseudocode: str, var: str) -> OriginKind:
    """Classify where ``var`` reaching a sink originates, within this function.

    Parameter origin wins over in-function source under doubt: any caller-supplied
    contribution makes the path unprovable here, which must never grade as confirmed.
    """
    src, par = _taint_sets(pseudocode)
    if var in par or _PARAM_RE.fullmatch(var):
        return "parameter"
    if var in src:
        return "in_function_source"
    return "unknown"
