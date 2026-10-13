# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The signals BinDiff similarity is blind to (lib/query/sameness): address-normalised pseudocode
sameness and the length-constant deltas, as pure functions. No database — the view's wiring is
exercised in test_patch_view."""

from __future__ import annotations

from treasure_map.lib.query import sameness as sm

# ── normalisation: addresses collapse, constants do not ──────────────────────────────────────


def test_an_address_shift_normalises_but_a_small_constant_does_not() -> None:
    """★ The point of the whole reading: a function identical but for the addresses its synthetic
    symbols carry reads the same; a function whose only change is a size constant does NOT — else
    the length change would normalise away.

    MUTATION: add ``0x[0-9a-f]{1,}`` (any hex) to the address regex -> 0x100 and 0xff collapse and
    the second assertion goes RED."""
    a = "iVar1 = FUN_00012340(DAT_000200f8); puts(s_hi_0001ccd0);"
    b = "iVar1 = FUN_00099990(DAT_00077abc); puts(s_hi_00088eee);"
    assert sm.normalize_pseudocode(a) == sm.normalize_pseudocode(b)  # only addresses moved

    lo = "strncpy(dst,src,0x100);"
    hi = "strncpy(dst,src,0xff);"
    assert sm.normalize_pseudocode(lo) != sm.normalize_pseudocode(hi)  # a constant stays put

    dec = "if (n < 256) {}"
    dec2 = "if (n < 255) {}"
    assert sm.normalize_pseudocode(dec) != sm.normalize_pseudocode(dec2)  # 256->255 is not hidden


def test_pair_reading_tells_no_body_apart_from_an_empty_body() -> None:
    """A reader must not have to recompute WHY a body was missing: ``no_body`` (a side absent from
    the functions table — an import/PLT stub) is kept apart from ``unavailable`` (present, empty).

    MUTATION: drop the ``NO_BODY in (sa, sb)`` branch (call every missing body 'unavailable') ->
    RED."""
    bodies_a = {"1000": "FUN_00001000();", "2000": None}  # 2000 present but empty
    bodies_b = {"1000": "FUN_00009999();"}  # 3000 absent -> an import/PLT stub
    assert sm.pair_reading(bodies_a, bodies_b, "1000", "1000") == (
        True,
        None,
    )  # addresses only moved
    assert sm.pair_reading(bodies_a, bodies_b, "2000", "1000") == (None, sm.UNAVAILABLE)  # a empty
    assert sm.pair_reading(bodies_a, bodies_b, "1000", "3000") == (None, sm.NO_BODY)  # b absent
    assert sm.pair_reading(None, bodies_b, "1000", "1000") == (
        None,
        sm.UNAVAILABLE,
    )  # a db unreadable


# ── states: a match is only "identical" when the callees are proven equal ─────────────────────


def test_sameness_state_keeps_unverified_apart_and_prefers_a_changed_callee_set() -> None:
    """MUTATION: fold callee_state 'undetermined' into 'equal' (-> identical) or treat it as
    'differs' -> RED; drop the 'differs callee wins over no body' rule -> the last two lines go
    RED."""
    assert sm.sameness_state(True, "equal", None) == sm.IDENTICAL
    assert sm.sameness_state(True, "undetermined", None) == sm.IDENTICAL_CALLEE_UNVERIFIED
    assert (
        sm.sameness_state(True, "differs", None) == sm.DIFFERS
    )  # text matched, a FUN_ call changed
    assert sm.sameness_state(False, "equal", None) == sm.DIFFERS  # the text itself differs
    assert (
        sm.sameness_state(None, "equal", sm.NO_BODY) == sm.NO_BODY
    )  # no body, nothing proves change
    assert sm.sameness_state(None, "undetermined", sm.UNAVAILABLE) == sm.UNAVAILABLE
    # No body to read, but the callee sets differ -> that alone is proof of change.
    assert sm.sameness_state(None, "differs", sm.NO_BODY) == sm.DIFFERS
    assert sm.sameness_state(None, "differs", sm.UNAVAILABLE) == sm.DIFFERS


# ── the length-constant signals ──────────────────────────────────────────────────────────────


def test_const_delta_fires_on_a_changed_value_of_the_same_kind() -> None:
    """MUTATION: compare across differing kinds (drop the ``a_kind != b_kind`` guard) -> a
    const->cap_const pair reads as a value delta -> RED in the cross-kind test below."""
    assert sm.const_delta("const", "0x40", "const", "0x3f") == {
        "size_kind": "const",
        "from": "0x40",
        "to": "0x3f",
    }
    # cap_const 0x200 -> 0x400: base-0 parse
    assert sm.const_delta("cap_const", "0x200", "cap_const", "0x400") == {
        "size_kind": "cap_const",
        "from": "0x200",
        "to": "0x400",
    }
    assert sm.const_delta("const", "0x40", "const", "0x40") is None  # equal
    assert sm.const_delta("const", "0x40", "const", "64") is None  # one number, two spellings
    # ★ an off-by-one length IS a real delta — never filtered as "±1 noise" (that would drop the
    # exact off-by-one fixes this signal exists to surface).
    assert sm.const_delta("const", "256", "const", "255") == {
        "size_kind": "const",
        "from": "256",
        "to": "255",
    }


def test_a_non_constant_or_cross_kind_size_is_not_a_value_delta() -> None:
    """A non-constant kind is never compared as a number; a kind change is a shift, not a delta.

    MUTATION: let ``const`` compare against ``cap_const`` as a delta -> RED."""
    assert sm.const_delta("variable", "n", "variable", "m") is None
    assert sm.const_delta("const", "0x40", "cap_const", "0x80") is None  # a kind shift
    assert sm.const_delta(None, None, "const", "0x1") is None  # a side with no size axis


def test_kind_shift_reports_a_changed_kind_both_sides_present() -> None:
    """MUTATION: report a shift when only one side has a size kind -> RED (the None cases)."""
    assert sm.kind_shift("const", "untraced") == {"from_kind": "const", "to_kind": "untraced"}
    assert sm.kind_shift("const", "const") is None  # same kind
    assert sm.kind_shift("const", None) is None  # b has no size axis
    assert sm.kind_shift(None, "const") is None  # a has no size axis
