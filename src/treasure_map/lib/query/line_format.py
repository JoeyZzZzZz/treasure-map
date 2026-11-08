# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Format-string evidence that a number after a string argument is a source line number — the one
test the drift reading (lib/query/drift_reading) and the recompile reading
(lib/query/recompile_only) share, so the two cannot read the same line two ways.

The evidence is a string LITERAL (one quoted token; never the code between two literals) holding a
``%…s`` conversion followed later by a ``%…d`` / ``%…u`` / ``%…i`` / ``%…x`` one — a
name-then-line log format such as ``"%s:%d"``. A conversion is spelled exactly: ``%``, optional
flags / width / precision (``-+ #0-9.``), an optional length modifier (``hh h ll l L j z t``),
then the conversion letter; ``%%`` is a literal percent sign and no conversion.

It counts on the site's own line, or on the line before only when that line's statement is not
finished (it does not end with ``;``, ``{`` or ``}``): a call folded over two lines. A finished
statement on the line before — another call's format — says nothing about this line's number."""

from __future__ import annotations

import re
from collections.abc import Sequence

# One conversion: ``%%`` (no conversion), or flags/width/precision, a length modifier, a letter.
_CONVERSION = re.compile(r"%(?:%|[-+ #0-9.]*(?:hh|h|ll|l|L|j|z|t)?([A-Za-z]))")
# The conversion letters that can print a line number after the name's ``%s``.
_LINE_LETTERS = frozenset("duix")
# The tokens that end a statement (or open / close a block): a line ending in one is finished.
_STATEMENT_END = frozenset({";", "{", "}"})


def name_line_format(literal: str) -> bool:
    """Whether one quoted string token holds a ``%…s`` conversion followed later by a
    ``%…d/u/i/x`` one. A token that is not a quoted literal is never evidence."""
    if len(literal) < 2 or not (literal.startswith('"') and literal.endswith('"')):
        return False
    seen_s = False
    for m in _CONVERSION.finditer(literal[1:-1]):
        letter = m.group(1)
        if letter == "s":
            seen_s = True
        elif seen_s and letter is not None and letter in _LINE_LETTERS:
            return True
    return False


def statement_continues(tokens: Sequence[str]) -> bool:
    """Whether a line (its tokens) leaves its statement open — it has tokens and does not end with
    ``;``, ``{`` or ``}``."""
    return bool(tokens) and tokens[-1] not in _STATEMENT_END


def format_evidence(line: Sequence[str], prev: Sequence[str]) -> bool:
    """Whether a site's line (its tokens) holds a name-then-line format literal, or the line
    before (``prev``) holds one and its statement continues onto the site's line."""
    if any(name_line_format(t) for t in line):
        return True
    return statement_continues(prev) and any(name_line_format(t) for t in prev)
