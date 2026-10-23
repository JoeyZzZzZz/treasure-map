# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""``classes.arg_ref`` — one call argument read into (form, root, path, cast, lead).

The shared reader behind every "the variable behind an argument" site. Synthetic, vendor-neutral
inputs only; the shapes are the ones real decompiler output takes."""

from __future__ import annotations

import pytest

from treasure_map.lib.pattern.classes import SAFE_FORMS, arg_ref, is_type_word

# (text, form, lead, root, path, cast_type)
_TABLE = [
    ('"/x/y z"', "literal", None, None, None, None),
    ("*(char **)(p_2 + 4)", "load", "load", "p_2", "*(char **)(p_2 + 4)", None),
    ("(size_t)n0", "cast", "var", "n0", None, "size_t"),
    ("0xe - v3", "arith", "var", "v3", None, None),
    ("0x400U - v3", "arith", "var", "v3", None, None),
    ("p->len", "load", "load", "p", "p->len", None),
    ("p[7]", "load", "load", "p", "p[7]", None),
    ("p[7] - v5", "arith", "load", "p", "p[7]", None),
    ("s.u.e.length", "load", "load", "s", "s.u.e.length", None),
    ("(char *)p_2[1]", "load", "load", "p_2", "p_2[1]", "char *"),
    ("(char *)&buf", "addr_of", "var", "buf", None, "char *"),
    ("(char *)(p + 4)", "arith", "var", "p", None, "char *"),
    ("(char *)*p", "load", "load", "p", "*p", "char *"),
    ("(uint)n & 0x1f", "arith", "var", "n", None, "uint"),
    ("(Cls *)p_1", "cast", "var", "p_1", None, "Cls *"),
    ("strlen(src)", "call", "call", "src", None, None),
    ("(size_t)0x40", "literal", None, None, None, "size_t"),
    ("(char *)0x401234", "const_addr", None, None, None, "char *"),
    ("(char *)0x0", "const_addr", None, None, None, "char *"),
    ("buf + 4", "arith", "var", "buf", None, None),
    ("n * sizeof(int)", "arith", "var", "n", None, None),
    ("&arr[1]", "arith", "load", "arr", "arr[1]", None),
    ("PTR_s_HDD<_d>_write_error__x___0080f218", "none", None, None, None, None),
    ("size_t", "none", None, None, None, None),
]


@pytest.mark.parametrize("text,form,lead,root,path,cast", _TABLE)
def test_arg_ref_reads_each_shape(
    text: str, form: str, lead: str | None, root: str | None, path: str | None, cast: str | None
) -> None:
    r = arg_ref(text)
    assert (r.form, r.lead, r.root, r.path, r.cast_type) == (form, lead, root, path, cast), text


def test_a_symbol_label_with_angles_is_one_atom_not_a_comparison() -> None:
    """A Ghidra ``PTR_``/``s_`` label carrying ``<``/``>`` is a single non-variable token.

    Two rules guard this, either enough on its own: the symbol-label match, and ``<``/``>`` being
    an operator only with whitespace on both sides. MUTATION (verified RED, compound): disabling
    BOTH (the label match AND the whitespace rule) splits the label into an ``arith`` with a bogus
    root; disabling either alone leaves the other."""
    r = arg_ref("PTR_s_HDD<_d>_write_error__x___0080f218")
    assert r.form == "none" and r.root is None


def test_a_number_cast_to_a_pointer_is_a_constant_address() -> None:
    """``(char *)0x401234`` is a constant address, not a loaded value and not a plain literal — so
    a sink argument of this form reports a constant-address boundary, never reached_sink.

    MUTATION (verified RED): drop the pointer-cast test -> it reads as a plain literal."""
    assert arg_ref("(char *)0x401234").form == "const_addr"
    assert arg_ref("(size_t)0x40").form == "literal"  # a non-pointer numeric cast stays a number


def test_safe_forms_are_only_var_addr_of_cast() -> None:
    assert SAFE_FORMS == frozenset({"var", "addr_of", "cast"})
    assert arg_ref("(char *)*p").form not in SAFE_FORMS  # a load is never a safe form
    assert arg_ref("x + y").form not in SAFE_FORMS


def test_is_type_word_covers_ghidra_and_fixed_width() -> None:
    for t in ("char", "size_t", "uint32", "int8", "uint16_t", "undefined4", "ushort", "FILE"):
        assert is_type_word(t), t
    for v in ("buf", "n0", "param_1", "inet_aton", "init_config"):
        assert not is_type_word(v), v
