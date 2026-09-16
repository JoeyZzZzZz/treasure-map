# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
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
from collections.abc import Mapping
from dataclasses import dataclass

from treasure_map.lib.pattern.classes import FORMAT, call_offsets
from treasure_map.lib.reachability.taint import _IDENT_RE

# Size-source kinds (mechanism labels, not verdicts).
SIZE_CONST = "const"
SIZE_SIZEOF = "sizeof"
SIZE_CLAMP = "clamp"
SIZE_POINTER_GUARD = "pointer_guard"
SIZE_SOURCE_LEN = "source_len"
SIZE_VARIABLE = "variable"
SIZE_UNTRACED = "untraced"

# Write-length kinds for the buffer FORMATTERS. Separate labels rather than reused copy ones,
# because what their size argument MEANS is different and collapsing them would state a stronger
# fact than the call supports:
#   cap_*     — snprintf/vsnprintf take a maximum to write. That bounds the WRITE, and says
#               nothing about whether the destination is that big; "capped at n" is the fact,
#               "safe" is not.
#   append_*  — strncat takes how much to APPEND. The total written is that plus whatever the
#               destination already holds, which this pass does not know. Reading it as a total
#               would be the same mistake as reading a cap as a capacity, one step worse.
#   no_bound  — sprintf/vsprintf/strcat have no length parameter at all. The fact is the absence
#               of any limit in the call, which is a fact about the call and not a claim about
#               what reaches it.
# None of the five is in _FORM_NOTE below, so none of them can ever demote a candidate.
SIZE_CAP_CONST = "cap_const"
SIZE_CAP_VARIABLE = "cap_variable"
SIZE_APPEND_CONST = "append_const"
SIZE_APPEND_VARIABLE = "append_variable"
SIZE_NO_BOUND = "no_bound"

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

# Which argument of a buffer formatter carries a length, and what that length MEANS. Lives here
# rather than in the call-class vocabulary for the same reason _SIZED_COPY does: the position is
# inseparable from the kind it produces, and splitting them across two modules is how the two
# drift. Absent from the map = the call takes no length at all.
#
# ★ The position is not guessable and reading the wrong one is not a small error: snprintf's cap
# is argument 1 and sprintf's FORMAT STRING is argument 1, so a single "read args[2] as the size"
# rule reads snprintf's format string as a length — measured as wrong on 100% of them. Every entry
# below is the callee's real signature.
_CAP_ARG: dict[str, int] = {
    "snprintf": 1,  # snprintf(dst, CAP, fmt, ...)
    "vsnprintf": 1,  # vsnprintf(dst, CAP, fmt, ap)
}
_APPEND_ARG: dict[str, int] = {
    "strncat": 2,  # strncat(dst, src, HOW MUCH TO APPEND)
}

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


def _call_args(
    pseudocode: str, name: str, occurrence: int, stub_names: Mapping[int, str] | None = None
) -> list[str] | None:
    """Top-level arguments of the ``occurrence``-th call to ``name`` (0-based), or None.

    The call positions come from ``classes.call_offsets`` — the same authority the detector counts
    callsites with. That is what makes "candidate for the 2nd memcpy" and "the arguments of the 2nd
    memcpy" the same call: a second regex here would agree with the first only until one of them
    was adjusted, and then a candidate would silently carry another call's length.

    None when the call is not there — an occurrence past the end, or a callee the body never spells
    out. The caller reports that as ``untraced``, never as an absence of length.

    ``stub_names`` reaches the authority so a call the decompiler rendered as ``FUN_<addr>(…)`` is
    one of the calls counted here — otherwise the occurrence a candidate was anchored at would not
    exist for this reader and its length would read ``untraced``."""
    offsets = call_offsets(pseudocode, name, stub_names)
    if occurrence < 0 or occurrence >= len(offsets):
        return None
    i = offsets[occurrence]  # at the '('
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


def classify_format_size(
    pseudocode: str,
    sink_name: str,
    *,
    occurrence: int = 0,
    stub_names: Mapping[int, str] | None = None,
) -> CopySize:
    """Classify the write-length of the ``occurrence``-th ``sink_name`` FORMATTER call.

    The buffer formatters (snprintf/sprintf/vsnprintf/vsprintf/strcat/strncat) write into a
    destination exactly as a copy does, and until now none of them was read on that axis at all —
    the whole family produced no candidate, so a formatter that overruns its destination was not a
    low-ranked lead, it was absent.

    What comes back is a length FACT, never a verdict. Three of them, by what the call's signature
    actually provides:

      "there is no length parameter"      — sprintf / vsprintf / strcat        -> no_bound
      "the write is capped at n"          — snprintf / vsnprintf (arg 1)       -> cap_*
      "n more bytes are appended"         — strncat (arg 2)                    -> append_*

    None of them says whether the destination is big enough, because the call does not say. A cap
    is not a capacity and an append amount is not a total; the destination's size is a fact about
    the destination, and this reads a call. That is why none of the five kinds carries a form note
    (see ``_FORM_NOTE``): a candidate here is never demoted on the strength of a number that does
    not answer the question.

    ★ A constant does not change which kind applies. ``snprintf(dst, 64, "no percent here")`` is
    cap_const, NOT no_bound — the call really does carry a cap, and saying otherwise would emit a
    length fact that is simply false about the call. The kind comes from the SIGNATURE; whether the
    format string is a literal is a separate axis the detector records separately.

    An unreadable call, an occurrence that is not there, or a non-formatter ``sink_name`` yields
    ``untraced``."""
    if sink_name not in FORMAT:
        return CopySize(SIZE_UNTRACED, None, None)
    args = _call_args(pseudocode, sink_name, occurrence, stub_names)
    if args is None:
        return CopySize(SIZE_UNTRACED, None, None)

    pos = _CAP_ARG.get(sink_name)
    const_kind, var_kind = SIZE_CAP_CONST, SIZE_CAP_VARIABLE
    if pos is None:
        pos = _APPEND_ARG.get(sink_name)
        const_kind, var_kind = SIZE_APPEND_CONST, SIZE_APPEND_VARIABLE
    if pos is None:
        # No length parameter in the signature at all. Not a failure to read one — there is none.
        return CopySize(SIZE_NO_BOUND, None, None)
    if pos >= len(args):
        return CopySize(SIZE_UNTRACED, None, None)

    size = args[pos].strip()
    if _NUM_LITERAL_RE.match(size):
        return CopySize(const_kind, size, None)
    if "sizeof" in size:
        # A sizeof still bounds only the WRITE here, not the destination's capacity relative to
        # what gets formatted into it, so it stays a cap/append kind rather than borrowing the
        # copy path's sizeof — which does carry a form note and would demote this.
        return CopySize(const_kind, size, None)
    var = _lead_ident(size)
    if var is None:
        return CopySize(SIZE_UNTRACED, size, None)
    return CopySize(var_kind, size, var)


def classify_copy_size(
    pseudocode: str,
    sink_name: str,
    *,
    occurrence: int = 0,
    stub_names: Mapping[int, str] | None = None,
) -> CopySize:
    """Classify the size source of the ``occurrence``-th ``sink_name`` copy call in ``pseudocode``.

    ``occurrence`` is 0-based and defaults to the first call — the historical reading, kept as the
    default so a caller with no callsite in hand behaves exactly as before. It is a property of the
    CALL, which is why it has to be selectable: a function that copies a literal 4 bytes and then a
    caller-supplied length holds both facts, and reading only the first reports the safe one for
    both.

    The clamp/guard search around the length variable stays whole-function on purpose. It is
    already a presence-only signal that never claims to dominate the copy (see ``_clamps_for``);
    narrowing it to a text window would not turn it into a dominance proof, and would drop real
    guards written before the loop the copy sits in.

    Returns a CopySize. An unreadable call, an occurrence that is not there, or a non-copy
    ``sink_name`` yields ``untraced``."""
    args = _call_args(pseudocode, sink_name, occurrence, stub_names)
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
