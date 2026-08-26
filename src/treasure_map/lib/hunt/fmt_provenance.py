# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Recover the FORMAT STRING a caller hands to a thin format-string wrapper (the fmt axis's
one-hop provenance).

A candidate recovered through a thin fmt wrapper has its real sink one function away, so nothing
in its own body was traced and the map has to say "not verified". This module closes the common
half of that gap without leaving the hunt layer: the danger on the fmt axis is the FORMAT argument
itself (a controllable format lets an attacker's conversions read and write memory), and a
caller that passes a string literal there has
handed over a value that is constant by inspection.

Two things make this a purely textual, hunt-layer job — which is exactly why the fmt axis is
separable from the command axis:

* the format position is FIXED by the wrapper's signature, so one index lookup finds it;
* "is this argument a constant" needs no dominance analysis, because the only answer accepted here
  is a literal spelled out at the call site.

★ IRON LAW — this module NEVER models the format's varargs. On the fmt axis the varargs are the
harmless half: they are data being formatted, and they reach a log or a stream, not a shell. Only
the format itself carries the injection. Putting a format template plus its varargs into a
stack_buf-shaped record would hand the read side a writer whose ``%s`` vararg it would judge as an
injection surface — reading the fmt axis with the command axis's rules, which is precisely the
cmd/fmt inversion this codebase treats as a false-negative source. The inversion is prevented
STRUCTURALLY, by never building such a record here, not by a check somewhere downstream.

★ Silence is the safe answer. Anything other than a literal at the format position — a variable, a
constructed buffer, a pointer to data the decompiler never resolved — yields NO record, and the
candidate falls back to the honest "the forwarded value was never traced" reading. An empty
provenance is reversible (someone looks again); a wrongly-emitted constant is not (it asserts safe).
"""

from __future__ import annotations

import re
from typing import Any

# The literal escapes a decompiler emits inside a C string, mapped back to the byte they stand for.
# Only these; an unknown escape keeps its backslash rather than being silently dropped.
_C_ESCAPES = {
    "n": "\n",
    "t": "\t",
    "r": "\r",
    "0": "\0",
    "\\": "\\",
    '"': '"',
    "'": "'",
}


def call_arguments(pseudocode: str, callee: str) -> list[str] | None:
    """The argument expressions of the FIRST call to ``callee``, split at top level.

    Depth- and string-aware, unlike a plain ``split(",")``: a nested call
    (``log(2, "%s", f(a, b))``) and a comma inside a string literal both keep their argument
    together, so argument N is really argument N. Returns None when the call is not found.
    """
    match = re.search(rf"\b{re.escape(callee)}\s*\(", pseudocode)
    if match is None:
        return None
    args: list[str] = []
    current: list[str] = []
    depth = 1
    in_string = False
    escaped = False
    for ch in pseudocode[match.end() :]:
        if in_string:
            current.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
            current.append(ch)
        elif ch in "([{":
            depth += 1
            current.append(ch)
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                args.append("".join(current))
                return [a.strip() for a in args]
            current.append(ch)
        elif ch == "," and depth == 1:
            args.append("".join(current))
            current = []
        else:
            current.append(ch)
    return None  # unterminated call: the body was truncated, so no argument list is trustworthy


def _string_literal(expr: str) -> str | None:
    """The content of ``expr`` when it is exactly one C string literal, else None.

    Exactly one: a cast around it (``(char *)"x"``) or a concatenation is not accepted, because
    what this feeds is a claim that the argument IS this constant, and the strictest reading is the
    one that cannot over-claim. Escapes are decoded so the stored value is the string the program
    actually holds rather than its source spelling."""
    text = expr.strip()
    if len(text) < 2 or not text.startswith('"') or not text.endswith('"'):
        return None
    body = text[1:-1]
    out: list[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == '"':
            return None  # a second literal (an adjacent-string concatenation) — not a single one
        if ch == "\\" and i + 1 < len(body):
            nxt = body[i + 1]
            out.append(_C_ESCAPES.get(nxt, "\\" + nxt))
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def format_argument(pseudocode: str, wrapper_name: str, index: int) -> str | None:
    """The caller's argument at the wrapper's format POSITION, verbatim, or None.

    None when the call cannot be read or has fewer arguments than the wrapper's signature declares
    — a mismatch means the two views disagree and nothing here should pick one."""
    if index < 0:
        return None
    args = call_arguments(pseudocode, wrapper_name)
    if args is None or index >= len(args):
        return None
    return args[index]


def constant_format_record(
    *, pseudocode: str, wrapper_name: str, wrapped_sink: str, index: int | None
) -> list[dict[str, Any]]:
    """A one-record ``sink_arg_provenance`` list when the caller's format argument is a literal
    spelled out at the call site; otherwise an EMPTY list.

    The record's shape is the one the read side already understands — ``sink`` matching the
    candidate's anchored sink so the verdict is scoped to it, and a ``constant`` provenance whose
    ``value_kind`` says the value is a real literal string rather than an ambiguous address. No new
    verdict logic lives here: this states the fact, and the existing classifier draws the reading.

    Returns [] for every uncertain shape, listed here because each is a deliberate decline:

    * ``index is None`` — the wrapper's format position could not be established.
    * a variable (``pcVar2``, ``param_1``, a stack buffer) — a variable format IS the dangerous
      shape on this axis. It may well hold a constant on every path, but proving that needs EVERY
      reaching definition, and enumerating one branch of several is how a "constant" gets asserted
      about a value another branch controls.
    * an unresolved data pointer (``&DAT_000198b4``) — see the note below.
    * an integer literal — a number in a format position is not a readable format string, so the
      call site is not understood well enough to make a claim about it.

    ★ On data pointers, checked against real firmware rather than assumed: a defined string is
    INLINED by the decompiler (that is why a literal format appears as ``"...%s"`` in the text at
    all), so a ``DAT_`` name is what the decompiler emits precisely when it did NOT recognise a
    string there. The two are mutually exclusive by construction, and the measurement agrees — of
    36 data-pointer format arguments across two firmware images, 0 resolved to a recorded string.
    A resolver for them would therefore be code that never fires, so there is none, and these stay
    uncertain: the honest reading of "the decompiler could not tell what is there".
    """
    if index is None:
        return []
    arg = format_argument(pseudocode, wrapper_name, index)
    if arg is None:
        return []
    value = _string_literal(arg)
    if value is None:
        return []
    return [
        {
            "sink": wrapped_sink,
            "arg_idx": index,
            "provenance": {
                "kind": "constant",
                "value": value,
                "value_kind": "literal_string",
            },
            # Provenance recovered by reading the call site one hop up, not by the extractor's
            # def-use pass. Recorded so a consumer can tell the two apart; it is the same KIND of
            # fact (this argument is this literal), established a different way.
            "recovered_by": "fmt_wrapper_callsite",
        }
    ]
