# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for copy-sink size-source classification (the buffer-copy danger axis).

Hermetic: synthetic, vendor-neutral pseudocode strings. Proves the prove-bounded-to-demote
asymmetry — a provably-bounded length is classified (and downweighted), a length not proven
bounded is KEPT (no downweight). The recall-neutral cases (a truly unbounded copy, a
source-length copy, an unrelated clamp) must never be demoted.
"""

from __future__ import annotations

from treasure_map.lib.pattern.classes import COPY
from treasure_map.lib.reachability.copy_size import (
    _SIZED_COPY,
    _UNSIZED_COPY,
    SIZE_APPEND_CONST,
    SIZE_APPEND_VARIABLE,
    SIZE_CAP_CONST,
    SIZE_CAP_VARIABLE,
    SIZE_CLAMP,
    SIZE_CONST,
    SIZE_NO_BOUND,
    SIZE_POINTER_GUARD,
    SIZE_SIZEOF,
    SIZE_SOURCE_LEN,
    SIZE_UNTRACED,
    SIZE_VARIABLE,
    classify_copy_size,
    classify_format_size,
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


# ── which CALL is classified ─────────────────────────────────────────────────────────


def test_each_call_is_classified_on_its_own_length() -> None:
    """INV-2. The length belongs to the CALL, so ``occurrence`` selects which call is read.

    The first copy below is a fixed 4 bytes and the second a caller-supplied length. Reading only
    the first reports ``const`` for both — and ``const`` is a marker that sinks a candidate out of
    the first screen, so the second call would be demoted on the first call's evidence.

    MUTATION (must go RED): ignore ``occurrence`` and read the first call again."""
    pseudo = "memcpy(dst, src, 4); memcpy(other, src, len);"
    assert classify_copy_size(pseudo, "memcpy").kind == SIZE_CONST  # default: the first call
    assert classify_copy_size(pseudo, "memcpy", occurrence=0).kind == SIZE_CONST
    second = classify_copy_size(pseudo, "memcpy", occurrence=1)
    assert second.kind == SIZE_VARIABLE
    assert second.size_var == "len"
    assert copy_size_form_note(second.kind) is None  # not proven bounded -> not demoted


def test_occurrence_past_the_last_call_is_untraced() -> None:
    """An occurrence that is not there is ``untraced`` — the absence of a fact, not a safe length.

    It is unreachable through the detector (which counts the calls it emits for), so this pins the
    behaviour for every other caller: the failure direction has to be the one that keeps a
    candidate at its normal rank, never a bounded-looking kind that would demote it.

    MUTATION (must go RED): clamp the occurrence into range (read the last call, or the first)."""
    pseudo = "memcpy(dst, src, 4);"
    assert classify_copy_size(pseudo, "memcpy", occurrence=1).kind == SIZE_UNTRACED
    assert classify_copy_size(pseudo, "memcpy", occurrence=-1).kind == SIZE_UNTRACED


def test_occurrence_counts_calls_to_its_own_callee() -> None:
    """``occurrence`` is an ordinal within ONE callee, not a position among all copy calls.

    The detector carries both numbers for this reason: here the second memcpy is the THIRD copy
    call in the function, and indexing by the position-among-all would read past the end.

    MUTATION (must go RED): count occurrences across callee names."""
    pseudo = "memcpy(a, b, 4); strcpy(x, y); memcpy(c, d, n);"
    assert classify_copy_size(pseudo, "memcpy", occurrence=1).size_var == "n"
    assert classify_copy_size(pseudo, "strcpy", occurrence=0).kind == SIZE_SOURCE_LEN


# ── buffer formatters: the length comes from the SIGNATURE ───────────────────────────


def test_each_formatter_family_reports_what_its_signature_provides() -> None:
    """The three facts, one per signature shape. None of them is a verdict about the destination.

    A cap bounds the WRITE; whether the destination is that large is a fact about the destination,
    which the call does not carry. An append amount is not a total — the destination's existing
    contents are added to it. And a formatter with no length parameter is not "untraced": there is
    nothing to trace, which is a different and stronger statement.

    MUTATION (must go RED): map any family to a copy kind. SIZE_CONST for a const cap is the
    tempting one, and it would demote every capped formatter — SIZE_CONST is in _FORM_NOTE."""
    assert classify_format_size('snprintf(d, 64, "%s", x);', "snprintf").kind == SIZE_CAP_CONST
    assert classify_format_size('snprintf(d, n, "%s", x);', "snprintf").kind == SIZE_CAP_VARIABLE
    assert classify_format_size("vsnprintf(d, 64, f, ap);", "vsnprintf").kind == SIZE_CAP_CONST
    assert classify_format_size("strncat(d, s, 8);", "strncat").kind == SIZE_APPEND_CONST
    assert classify_format_size("strncat(d, s, k);", "strncat").kind == SIZE_APPEND_VARIABLE
    assert classify_format_size('sprintf(d, "%s", x);', "sprintf").kind == SIZE_NO_BOUND
    assert classify_format_size("vsprintf(d, f, ap);", "vsprintf").kind == SIZE_NO_BOUND
    assert classify_format_size("strcat(d, s);", "strcat").kind == SIZE_NO_BOUND


def test_a_constant_format_string_does_not_remove_a_cap() -> None:
    """★ The kind comes from the signature, never from how readable the format string is.

    ``snprintf(dst, 64, "no percent here")`` really does carry a cap. Calling it unbounded because
    nothing expands into it would emit a length fact that is false about the call — and on one real
    firmware there are 11 of exactly this shape. Which is why "how much of the format could be
    read" is recorded as its own axis instead of being folded into the length.

    MUTATION (must go RED): decide the kind from whether the format string contains a %."""
    assert classify_format_size('snprintf(d, 64, "no percent here");', "snprintf").kind == (
        SIZE_CAP_CONST
    )
    assert classify_format_size('sprintf(d, "no percent here");', "sprintf").kind == SIZE_NO_BOUND


def test_reading_a_fixed_argument_position_would_read_the_format_string() -> None:
    """Why the position is per-callee and not "the third argument, like a copy".

    snprintf's cap is argument 1 and sprintf's FORMAT STRING is argument 1; snprintf's argument 2
    is its format. A single fixed rule borrowed from memcpy would hand the classifier a format
    literal as a length on every snprintf in the firmware. Pinned here as an assertion about the
    arguments themselves so the reason survives the code.

    MUTATION (must go RED): use one position for the whole family."""
    from treasure_map.lib.reachability.copy_size import _call_args

    args = _call_args('snprintf(dst, 64, "%s", x);', "snprintf", 0)
    assert args is not None
    assert args[1].strip() == "64"  # the cap
    assert args[2].strip() == '"%s"'  # the format — what a memcpy-shaped rule would have read
    assert classify_format_size('snprintf(dst, 64, "%s", x);', "snprintf").size_text == "64"


def test_no_formatter_length_can_demote_a_candidate() -> None:
    """MC-a2, at the source: none of the five kinds carries a form note, structurally.

    Only a length that PROVES the total write is bounded may demote, and none of these does — a cap
    leaves the destination's size unknown, an append leaves the total unknown, and no_bound is the
    absence of a limit. Asserted through ``copy_size_form_note`` rather than by inspecting the
    table, so adding a kind to _FORM_NOTE is what turns it red.

    MUTATION (must go RED): add any formatter kind to _FORM_NOTE."""
    for kind in (
        SIZE_CAP_CONST,
        SIZE_CAP_VARIABLE,
        SIZE_APPEND_CONST,
        SIZE_APPEND_VARIABLE,
        SIZE_NO_BOUND,
    ):
        assert copy_size_form_note(kind) is None, kind


def test_an_unreadable_formatter_call_is_untraced_not_unbounded() -> None:
    """The failure direction: what could not be read is never reported as a stronger fact.

    ``no_bound`` states that the signature HAS no length parameter. A call whose arguments could
    not be parsed has not established that, and saying so would turn a parsing gap into a claim
    about the code.

    MUTATION (must go RED): return SIZE_NO_BOUND when the arguments cannot be read."""
    assert classify_format_size("nothing here;", "snprintf").kind == SIZE_UNTRACED
    assert classify_format_size('snprintf(d, 64, "%s");', "snprintf", occurrence=3).kind == (
        SIZE_UNTRACED
    )
    assert classify_format_size("memcpy(d, s, 4);", "memcpy").kind == SIZE_UNTRACED


# ── the copy aliases added to the sink vocabulary read their length like their base ─────


def test_mempcpy_is_classified_on_size() -> None:
    # mempcpy(dst, src, n) has memcpy's (dst, src, n) shape; the length is arg2 either way.
    assert classify_copy_size("mempcpy(dst, src, n);", "mempcpy").kind == SIZE_VARIABLE
    assert classify_copy_size("mempcpy(dst, src, 8);", "mempcpy").kind == SIZE_CONST


def test_wmemcpy_is_classified_on_size() -> None:
    # wmemcpy(dst, src, n): n counts wide characters, but only the length's SOURCE is classified,
    # not its byte magnitude, so a variable count is variable and a literal count is const.
    assert classify_copy_size("wmemcpy(dst, src, n);", "wmemcpy").kind == SIZE_VARIABLE
    assert classify_copy_size("wmemcpy(dst, src, 8);", "wmemcpy").kind == SIZE_CONST


def test_wmemcpy_sizeof_length_is_not_a_sizeof_bound() -> None:
    """A wide-character copy takes an ELEMENT count; sizeof() yields BYTES, so ``sizeof(dst)`` as a
    wmemcpy length is the classic unit error (it copies element-width times too many bytes), not a
    proof the write fits. It must NOT earn the demoting ``sizeof_bound`` note a byte copy's sizeof
    does -- washing that overrun into 'bounded' is exactly the false safety to avoid. A byte copy
    (memcpy) keeps its sizeof bound; a literal element count stays const (a fixed count is bounded
    whatever the unit).

    MUTATION (must go RED): drop the wide-copy special case so wmemcpy's sizeof returns SIZE_SIZEOF
    (sizeof_bound) like memcpy's."""
    w = classify_copy_size("wmemcpy(dst, src, sizeof(dst));", "wmemcpy")
    assert w.kind == SIZE_VARIABLE
    assert copy_size_form_note(w.kind) is None  # kept live, never demoted
    # a byte copy's sizeof is a genuine bound and is unchanged:
    assert classify_copy_size("memcpy(dst, src, sizeof(dst));", "memcpy").kind == SIZE_SIZEOF
    assert copy_size_form_note(SIZE_SIZEOF) == "sizeof_bound"


def test_every_copy_sink_has_a_length_reading_and_the_two_tables_agree() -> None:
    """The COPY vocabulary and the length tables cannot drift: a length-taking copy that is NOT in
    _SIZED_COPY reads SIZE_UNTRACED for every call (``if sink_name not in _SIZED_COPY: return
    untraced``), so it would emit candidates whose length silently never traces. Encoded as a set
    identity rather than a spot check, so any copy name added to one table without the other turns
    this red instead of shipping an always-untraced sink.

    MUTATION (must go RED): remove ``mempcpy`` (or ``wmemcpy``) from _SIZED_COPY — the identity
    breaks here and the two classification tests above flip to SIZE_UNTRACED."""
    assert "mempcpy" in _SIZED_COPY
    assert "wmemcpy" in _SIZED_COPY
    assert COPY == (_SIZED_COPY | _UNSIZED_COPY)
    assert not (_SIZED_COPY & _UNSIZED_COPY)


def test_a_copy_name_outside_the_sized_table_reads_untraced() -> None:
    """The failure this guards: a copy sink whose length position was never registered reports its
    length as untraced, not as some default value. ``wmemset`` is a name deliberately NOT collected
    (it fills a constant, it is not a taint-moving copy) — used here only as a stand-in for 'a copy
    callee absent from _SIZED_COPY', to pin the untraced behavior.

    MUTATION (must go RED): make the size reader fall through to reading args[2] for any callee."""
    assert "wmemset" not in _SIZED_COPY
    assert classify_copy_size("wmemset(dst, 0, n);", "wmemset").kind == SIZE_UNTRACED
