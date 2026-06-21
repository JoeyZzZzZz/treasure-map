# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Copy-sink size-source classification — the danger axis of a buffer copy.

A buffer copy (memcpy/memmove/strncpy/strcpy) is dangerous when its WRITE LENGTH is
externally controllable with no dominating upper bound (<= destination capacity). The
length, not the destination pointer, is the axis to read: ``memcpy(dst, src, 4)`` is
bounded, ``memcpy(dst, src, n)`` with an uncontrolled ``n`` is not — yet both have the
same first argument.

This module classifies WHERE a copy's length comes from, intra-procedurally:

  const          — a literal constant (4 / 0x2c): the write length is fixed, not controllable.
  sizeof         — sizeof(...) of an object: bounded to the object size.
  clamp          — an upper-bound check/clamp REFERENCING the length variable is present (a
                   coverage-unjudged signal — a single read cannot prove it dominates the copy).
  pointer_guard  — a pointer/bound comparison referencing the length (e.g. ``bound < base + n``).
  source_len     — the length is the SOURCE string length (``strncpy(dst, src, strlen(src))`` /
                   ``strcpy(dst, var)``): equivalent to unbounded unless an upstream caller
                   limited the source — a suspect, NOT a safe form.
  variable       — a variable with no visible upper bound within the function.
  untraced       — the length argument could not be resolved here.

It is mechanism classification, NOT a verdict: it never says "safe" or "dangerous". Only the
provably-controlled kinds (const / sizeof / clamp / pointer_guard) map to a downweight form
note; the suspect/unbounded/untraced kinds map to None so a copy that cannot be proven bounded
is kept at its normal rank (prove-bounded-to-demote, never prove-dangerous-to-keep). Like the
rest of the reachability layer this is a shallow single-function read that prefers to keep a
candidate over silently dropping a possibly-real one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from treasure_map.lib.reachability.taint import _IDENT_RE

# Size-source kinds (mechanism labels, not verdicts).
SIZE_CONST = "const"
SIZE_SIZEOF = "sizeof"
SIZE_CLAMP = "clamp"
SIZE_POINTER_GUARD = "pointer_guard"
SIZE_SOURCE_LEN = "source_len"
SIZE_VARIABLE = "variable"
SIZE_UNTRACED = "untraced"

# Neutral form notes (stored in blocking_mechanism; the read-side score downweights them). Only
# the provably-length-controlled kinds get one — the suspect/unbounded kinds stay un-noted so a
# copy that cannot be proven bounded keeps its normal review rank.
CONST_SIZE = "const_size"
SIZEOF_BOUND = "sizeof_bound"
CLAMP_SIZE = "clamp_size"
POINTER_GUARD_SIZE = "pointer_guard_size"

_FORM_NOTE: dict[str, str] = {
    SIZE_CONST: CONST_SIZE,
    SIZE_SIZEOF: SIZEOF_BOUND,
    SIZE_CLAMP: CLAMP_SIZE,
    SIZE_POINTER_GUARD: POINTER_GUARD_SIZE,
}

# Copies whose write length is an explicit third argument.
_SIZED_COPY: frozenset[str] = frozenset({"memcpy", "memmove", "strncpy"})
# Copies with an IMPLICIT length = the source string length (no length argument).
_UNSIZED_COPY: frozenset[str] = frozenset({"strcpy"})

# String-length callees: a length taken from one is the source's own length (source_len).
_STRLEN_RE = re.compile(r"\b(?:strlen|strnlen|wcslen)\s*\(")
_NUM_LITERAL_RE = re.compile(r"^\s*[+-]?(?:0[xX][0-9a-fA-F]+|\d+)[uUlL]*\s*$")
_STRING_LITERAL_RE = re.compile(r'^\s*L?"(?:[^"\\]|\\.)*"\s*$')
# Comparison constant for a clamp: a hex literal or a NON-zero decimal (a ``> 0`` style guard is
# not an upper bound, so a bare 0 is deliberately not accepted — it must not demote a real copy).
_BOUND_CONST = r"(?:0[xX][0-9a-fA-F]+|[1-9]\d*)"


@dataclass(frozen=True)
class CopySize:
    """The size-source classification of one copy call.

    kind is one of the SIZE_* labels. size_text is the raw length expression (or, for an
    unsized strcpy, the source argument that determines the length). size_var is its leading
    identifier when the length is not a literal. clamps lists the upper-bound/guard shapes seen
    referencing size_var (each is coverage-unjudged — presence only, never a dominance claim).
    """

    kind: str
    size_text: str | None
    size_var: str | None
    clamps: tuple[str, ...] = ()


def copy_size_form_note(kind: str) -> str | None:
    """Return the downweight form note for a provably-length-controlled kind, else None."""
    return _FORM_NOTE.get(kind)


def _split_top(arglist: str) -> list[str]:
    """Split a call's argument text on top-level commas (respecting strings / parens / brackets)."""
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


def _first_call_args(pseudocode: str, name: str) -> list[str] | None:
    """Top-level arguments of the FIRST call to ``name``, or None when not located."""
    for m in re.finditer(rf"\b{re.escape(name)}\s*\(", pseudocode):
        i = m.end() - 1  # at the '('
        depth = 0
        for j in range(i, len(pseudocode)):
            ch = pseudocode[j]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return _split_top(pseudocode[i + 1 : j])
    return None


def _lead_ident(text: str) -> str | None:
    m = _IDENT_RE.search(text)
    return m.group(0) if m else None


def _clamps_for(pseudocode: str, var: str) -> tuple[str, ...]:
    """Upper-bound / clamp shapes that REFERENCE ``var`` (coverage-unjudged presence only).

    Tied to the length variable on purpose: a clamp on some other variable proves nothing about
    this copy, so it must not demote it. Only upper-bound shapes count (``>`` / ``>=`` against a
    non-zero constant, a min()/ternary clamp, or a re-assign guard) — a lower-bound or ``> 0``
    check does not bound the write. Includes the check-then-abort form (``if (CONST < v) ...``),
    which need not re-assign v to be a guard."""
    v = re.escape(var)
    shapes: tuple[tuple[str, str], ...] = (
        (rf"if\s*\(\s*{v}\s*>=?\s*{_BOUND_CONST}", "if (v >= CONST)"),
        (rf"if\s*\(\s*{_BOUND_CONST}\s*<=?\s*{v}\b", "if (CONST <= v)"),
        (rf"\b{v}\s*=\s*[^;]*\?\s*{v}\s*:\s*{_BOUND_CONST}", "v = (...) ? v : CONST"),
        (rf"\b{v}\s*=\s*(?:min|MIN|fmin)\s*\(", "v = min(...)"),
        (rf"if\s*\([^)]*\b{v}\b[^)]*\)\s*{v}\s*=\s*{_BOUND_CONST}", "if (...v...) v = CONST"),
    )
    return tuple(label for pat, label in shapes if re.search(pat, pseudocode))


def _pointer_guards(pseudocode: str, var: str) -> tuple[str, ...]:
    """Pointer/bound comparisons referencing ``var`` (e.g. ``bound < base + n``).

    Conservative: the length variable must appear in a comparison that adds it to another value
    (a source-room proof). Presence only, coverage-unjudged."""
    v = re.escape(var)
    shapes: tuple[tuple[str, str], ...] = (
        (rf"\w+\s*[<>]=?\s*\w+\s*\+\s*{v}\b", "X < base + v"),
        (rf"\b{v}\s*\+\s*\w+\s*[<>]=?\s*\w+", "v + X < bound"),
        (rf"\w+\s*\+\s*{v}\s*[<>]=?\s*\w+", "base + v < bound"),
    )
    return tuple(label for pat, label in shapes if re.search(pat, pseudocode))


def classify_copy_size(pseudocode: str, sink_name: str) -> CopySize:
    """Classify the size source of the first ``sink_name`` copy call in ``pseudocode``.

    Returns a CopySize. An unreadable call or a non-copy ``sink_name`` yields ``untraced``."""
    args = _first_call_args(pseudocode, sink_name)
    if args is None:
        return CopySize(SIZE_UNTRACED, None, None)

    if sink_name in _UNSIZED_COPY:
        # strcpy(dst, src): the write length is the source string length.
        if len(args) < 2:
            return CopySize(SIZE_UNTRACED, None, None)
        src = args[1].strip()
        if _STRING_LITERAL_RE.match(src):
            return CopySize(SIZE_CONST, src, None)  # copying a fixed literal is bounded
        return CopySize(SIZE_SOURCE_LEN, src, _lead_ident(src))

    if sink_name not in _SIZED_COPY:
        return CopySize(SIZE_UNTRACED, None, None)

    if len(args) < 3:
        return CopySize(SIZE_UNTRACED, None, None)
    size = args[2].strip()
    if _NUM_LITERAL_RE.match(size):
        return CopySize(SIZE_CONST, size, None)
    if "sizeof" in size:
        return CopySize(SIZE_SIZEOF, size, None)
    if _STRLEN_RE.search(size):
        return CopySize(SIZE_SOURCE_LEN, size, _lead_ident(size))
    var = _lead_ident(size)
    if var is None:
        return CopySize(SIZE_UNTRACED, size, None)
    clamps = _clamps_for(pseudocode, var)
    if clamps:
        return CopySize(SIZE_CLAMP, size, var, clamps)
    guards = _pointer_guards(pseudocode, var)
    if guards:
        return CopySize(SIZE_POINTER_GUARD, size, var, guards)
    return CopySize(SIZE_VARIABLE, size, var)
