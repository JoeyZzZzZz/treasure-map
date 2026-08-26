# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the fmt-wrapper call-site reader (lib/hunt/fmt_provenance).

The end-to-end behaviour lives in test_analyzer2's C-FMT block; these pin the two pieces of
mechanics that are easy to get subtly wrong and whose breakage would be invisible there:
argument SPLITTING (get it wrong and index N is not argument N) and what counts as a literal.
"""

from __future__ import annotations

from treasure_map.lib.hunt.facts import fmt_wrapper_format_index, signature_slots
from treasure_map.lib.hunt.fmt_provenance import (
    call_arguments,
    constant_format_record,
    format_argument,
)


def test_arguments_split_at_top_level_only() -> None:
    """A comma inside a nested call or a string must not split an argument — index N has to be
    argument N, or the reader judges a value the sink never sees.

    MUTATION (must go RED): split on every comma (drop the depth check in call_arguments)."""
    pc = 'void f(void){ log_at(2, "a, b", fmt(x, y), z); }'
    assert call_arguments(pc, "log_at") == ["2", '"a, b"', "fmt(x, y)", "z"]
    assert format_argument(pc, "log_at", 1) == '"a, b"'
    assert format_argument(pc, "log_at", 2) == "fmt(x, y)"


def test_unreadable_or_short_call_yields_nothing() -> None:
    # No call, a truncated body, or fewer arguments than the signature declares: each is a
    # disagreement between the two views, and none of them is resolved by picking one.
    assert call_arguments("void f(void){ }", "log_at") is None
    assert call_arguments("void f(void){ log_at(2, ", "log_at") is None
    assert format_argument("void f(void){ log_at(2); }", "log_at", 1) is None
    assert format_argument('void f(void){ log_at(2, "x"); }', "log_at", -1) is None


def test_only_a_lone_literal_counts_as_constant() -> None:
    # Escapes are decoded (the value stored is what the program holds, not its source spelling);
    # a cast, a concatenation, a variable, a data pointer and a number are all declined.
    def rec(expr: str) -> list[dict[str, object]]:
        return constant_format_record(
            pseudocode=f"void f(void){{ W(2,{expr}); }}",
            wrapper_name="W",
            wrapped_sink="vfprintf",
            index=1,
        )

    (only,) = rec(r'"done: %s\n"')
    assert only["sink"] == "vfprintf"
    assert only["provenance"] == {
        "kind": "constant",
        "value": "done: %s\n",
        "value_kind": "literal_string",
    }
    for expr in ('(char *)"x"', '"a" "b"', "pcVar2", "&DAT_000198b4", "0x2f", "param_1"):
        assert rec(expr) == [], expr


def test_no_index_declines_rather_than_guessing() -> None:
    # An unestablished format position reads NO argument. Guessing one (say 0) judges a stream or
    # level — a different value than the one reaching the sink, and usually a constant-looking one.
    assert (
        constant_format_record(
            pseudocode='void f(void){ W("tag","%s"); }',
            wrapper_name="W",
            wrapped_sink="vfprintf",
            index=None,
        )
        == []
    )


def test_unnamed_slot_does_not_shift_the_format_position() -> None:
    """A typed-but-unnamed parameter occupies its POSITION instead of vanishing.

    Dropping it renumbers everything after it: in `f(int, char *param_2)` the format would be
    reported at position 0, so the caller's argument 0 gets judged while argument 1 is what
    reaches the sink — a wrong-but-plausible constant, which is worse than no answer.

    MUTATION (must go RED): drop unnamed slots instead of recording them as None (index over
    signature_params_ordered rather than signature_slots)."""
    pc = "void log_x(int,char *param_2){ FILE *s; vfprintf(s,param_2,0); }"
    assert signature_slots(pc) == [None, "param_2"]
    assert fmt_wrapper_format_index(pc, "vfprintf") == 1
    # `(void)` is no parameters at all, not one unnamed slot
    assert signature_slots("void f(void){ }") == []
