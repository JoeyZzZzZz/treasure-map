# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for copy-sink size-source classification (the buffer-copy danger axis).

Hermetic: synthetic, vendor-neutral pseudocode strings. Proves the prove-bounded-to-demote
asymmetry — a provably-bounded length is classified (and downweighted), a length not proven
bounded is KEPT (no downweight). The recall-neutral cases (a truly unbounded copy, a
source-length copy, an unrelated clamp) must never be demoted.
"""

from __future__ import annotations

from treasure_map.lib.reachability.copy_size import (
    SIZE_CLAMP,
    SIZE_CONST,
    SIZE_POINTER_GUARD,
    SIZE_SIZEOF,
    SIZE_SOURCE_LEN,
    SIZE_UNTRACED,
    SIZE_VARIABLE,
    classify_copy_size,
    copy_size_form_note,
)

# ── provably-bounded lengths: classified + downweighted ─────────────────────────────


def test_literal_constant_size_is_const() -> None:
    cs = classify_copy_size("memcpy(dst, src, 0x2c);", "memcpy")
    assert cs.kind == SIZE_CONST
    assert copy_size_form_note(cs.kind) == "const_size"


def test_decimal_constant_size_is_const() -> None:
    assert classify_copy_size("memcpy(dst, src, 4);", "memcpy").kind == SIZE_CONST


def test_sizeof_size_is_sizeof() -> None:
    cs = classify_copy_size("memcpy(dst, src, sizeof(dst));", "memcpy")
    assert cs.kind == SIZE_SIZEOF
    assert copy_size_form_note(cs.kind) == "sizeof_bound"


def test_strncpy_with_sizeof_minus_one_is_sizeof() -> None:
    # strncpy(dst, src, sizeof(dst) - 1) — bounded to the destination object.
    assert classify_copy_size("strncpy(dst, src, sizeof(dst) - 1);", "strncpy").kind == SIZE_SIZEOF


def test_strcpy_of_string_literal_is_const() -> None:
    cs = classify_copy_size('strcpy(dst, "a fixed banner");', "strcpy")
    assert cs.kind == SIZE_CONST


def test_check_then_abort_clamp_is_clamp() -> None:
    # if (CONST < n) goto/abort — an upper-bound guard that need not re-assign n.
    pseudo = "n = get_len(); if (0x100 < n) goto fail; memcpy(dst, src, n);"
    cs = classify_copy_size(pseudo, "memcpy")
    assert cs.kind == SIZE_CLAMP
    assert cs.clamps  # at least one shape recorded for the evidence layer
    assert copy_size_form_note(cs.kind) == "clamp_size"


def test_reassign_clamp_is_clamp() -> None:
    pseudo = "if (n > 0x20) n = 0x20; memcpy(dst, src, n);"
    assert classify_copy_size(pseudo, "memcpy").kind == SIZE_CLAMP


def test_pointer_guard_is_pointer_guard() -> None:
    pseudo = "if (bound < base + n) return -1; memcpy(dst, base, n);"
    cs = classify_copy_size(pseudo, "memcpy")
    assert cs.kind == SIZE_POINTER_GUARD
    assert copy_size_form_note(cs.kind) == "pointer_guard_size"


# ── lengths NOT proven bounded: KEPT, no downweight (recall-neutral) ─────────────────


def test_recv_length_variable_is_variable_and_not_demoted() -> None:
    # n = recv(...); memcpy(dst, src, n) with no clamp -> a real unbounded copy. MUST keep.
    pseudo = "n = recv(fd, src, 0x400); memcpy(dst, src, n);"
    cs = classify_copy_size(pseudo, "memcpy")
    assert cs.kind == SIZE_VARIABLE
    assert copy_size_form_note(cs.kind) is None  # never silently demoted


def test_source_length_strncpy_is_suspect_not_safe() -> None:
    # strncpy(dst, src, strlen(src)) — equivalent to unbounded unless the source was limited
    # upstream. A suspect, NOT a bounded-safe form: no downweight.
    cs = classify_copy_size("strncpy(dst, src, strlen(src));", "strncpy")
    assert cs.kind == SIZE_SOURCE_LEN
    assert copy_size_form_note(cs.kind) is None


def test_strcpy_of_variable_is_source_len() -> None:
    cs = classify_copy_size("strcpy(dst, src);", "strcpy")
    assert cs.kind == SIZE_SOURCE_LEN
    assert copy_size_form_note(cs.kind) is None


def test_unrelated_clamp_does_not_demote_unbounded_copy() -> None:
    # A clamp on a DIFFERENT variable must not bound this copy's length -> stays variable.
    pseudo = "if (0x10 < other) other = 0x10; n = recv(fd, src, 0x400); memcpy(dst, src, n);"
    cs = classify_copy_size(pseudo, "memcpy")
    assert cs.kind == SIZE_VARIABLE
    assert copy_size_form_note(cs.kind) is None


def test_greater_than_zero_is_not_an_upper_bound() -> None:
    # if (n > 0) ... is a non-empty check, not an upper bound -> must NOT be read as a clamp.
    pseudo = "n = recv(fd, src, 0x400); if (n > 0) memcpy(dst, src, n);"
    assert classify_copy_size(pseudo, "memcpy").kind == SIZE_VARIABLE


def test_struct_field_length_is_variable() -> None:
    pseudo = "memcpy(dst, src, hdr->len);"
    cs = classify_copy_size(pseudo, "memcpy")
    assert cs.kind == SIZE_VARIABLE
    assert cs.size_var == "hdr"


def test_memmove_is_classified_on_size() -> None:
    assert classify_copy_size("memmove(dst, src, n);", "memmove").kind == SIZE_VARIABLE
    assert classify_copy_size("memmove(dst, src, 8);", "memmove").kind == SIZE_CONST


# ── untraced ─────────────────────────────────────────────────────────────────────────


def test_absent_call_is_untraced() -> None:
    cs = classify_copy_size('snprintf(c, 64, "%s", x);', "memcpy")
    assert cs.kind == SIZE_UNTRACED
    assert copy_size_form_note(cs.kind) is None


def test_non_copy_sink_is_untraced() -> None:
    assert classify_copy_size("system(cmd);", "system").kind == SIZE_UNTRACED
