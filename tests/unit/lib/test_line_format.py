# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The name-then-line format evidence (lib/query/line_format) the drift reading and the recompile
reading share. Synthetic tokens only."""

from __future__ import annotations

import pytest

from treasure_map.lib.query import line_format as lf
from treasure_map.lib.query.drift_reading import _TOK as DRIFT_TOK
from treasure_map.lib.query.recompile_only import _TOK as RECOMPILE_TOK


def _toks(line: str) -> list[str]:
    return DRIFT_TOK.findall(line)


@pytest.mark.parametrize(
    ("literal", "evidence"),
    [
        ('"%s:%d"', True),
        ('"%-20s line %d"', True),
        ('"%s(%lu)"', True),
        ('"%s: %x"', True),  # the line printed in hex
        ('"%ls at %5i"', True),
        ('"%d bytes %d"', False),  # no ``%…s`` conversion: the ``s`` is a plain letter
        ('"%x status %u"', False),
        ('"%d items, %d"', False),
        ('"%d then %s"', False),  # the number comes first
        ('"%%s then %d"', False),  # ``%%`` is a percent sign, the ``s`` a plain letter
        ('"%s"', False),
        ('"%d"', False),
        ("%s:%d", False),  # not a quoted literal
    ],
)
def test_a_conversion_counts_only_when_spelled_as_one(literal: str, evidence: bool) -> None:
    """Only a real ``%…s`` conversion followed by a real ``%…d/u/i/x`` one is evidence.

    Mutation: the old loose pattern (``_CONVERSION`` -> ``%(?:%|[^"%]*([A-Za-z]))``: anything up to
    the last letter before the next ``%``) -> ``"%d bytes %d"`` / ``"%x status %u"`` / ``"%d
    items, %d"`` read as evidence (and two real formats lose theirs) -> 5 failed. Mutation: any
    ``%`` is evidence (``return "%" in literal`` at the top) -> 8 failed."""
    assert lf.name_line_format(literal) is evidence


def test_the_code_between_two_literals_is_never_a_format() -> None:
    """``check_len("t",n % sz,m % idx,"admin",5)``: the ``%`` operators between two literals hold
    a ``% s``-then-``% i`` shape when the whole line is read as text; only a literal is read.

    Mutation: read the whole line as one literal (``any(name_line_format(t) for t in line)`` ->
    ``name_line_format('"' + " ".join(line) + '"')``) -> True -> 1 failed."""
    line = _toks('check_len("t",n % sz,m % idx,"admin",5);')
    assert lf.format_evidence(line, []) is False


@pytest.mark.parametrize(
    ("prev", "evidence"),
    [
        ('log_msg("%s:%d",', True),  # a call folded onto the site's line
        ('log_msg("%s:%d","fn_x",0x2a);', False),  # a finished statement
        ('if (log_msg("%s:%d","fn_x",1) == 0) {', False),  # a block opens
        ("", False),  # no line before
    ],
)
def test_the_line_before_counts_only_while_its_statement_continues(
    prev: str, evidence: bool
) -> None:
    """A format on the line before is evidence for a call folded onto the site's line; a finished
    statement there (``;``), or a block brace, is another statement's format and says nothing.

    Mutation: drop the continuation test (``statement_continues(prev) and`` removed) -> the
    finished and the braced line read as evidence -> 2 failed. Mutation: ignore the line before
    (``return statement_continues(prev) and …`` -> ``return False``) -> the folded call -> 1
    failed."""
    assert lf.format_evidence(_toks('"fn",10);'), _toks(prev)) is evidence
    # the site's own line is evidence whatever stands before it
    assert lf.format_evidence(_toks('log_msg("%s:%d","fn",10);'), _toks(prev)) is True


def test_both_readings_tokenize_a_line_the_same_way() -> None:
    """The shared test reads tokens; the two readings feed it their own tokenizer, which must cut
    string literals the same way for the two to read one line alike."""
    line = 'log_msg("%s:\\"%d\\"",n % sz,"fn",10); /* "%s %d" */'
    assert DRIFT_TOK.findall(line) == RECOMPILE_TOK.findall(line)
