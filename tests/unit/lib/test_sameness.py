# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The signals BinDiff similarity is blind to (lib/query/sameness): address-normalised pseudocode
sameness and the length-constant deltas, as pure functions. No database — the view's wiring is
exercised in test_patch_view."""

from __future__ import annotations

import pytest

from treasure_map.lib.query import sameness as sm


def _skel(text: str) -> str:
    """The skeleton text alone: what two bodies must share before their large literals are
    compared position by position."""
    return sm.skeleton(text)[0]


# ── normalisation: addresses collapse, constants do not ──────────────────────────────────────


def test_an_address_shift_normalises_but_a_small_constant_does_not() -> None:
    """★ The point of the whole reading: a function identical but for the addresses its synthetic
    symbols carry reads the same; a function whose only change is a size constant does NOT — else
    the length change would normalise away.

    MUTATION: add ``0x[0-9a-f]{1,}`` (any hex) to the address regex -> 0x100 and 0xff collapse and
    the second assertion goes RED."""
    a = "iVar1 = FUN_00012340(DAT_000200f8); puts(s_hi_0001ccd0);"
    b = "iVar1 = FUN_00099990(DAT_00077abc); puts(s_hi_00088eee);"
    assert _skel(a) == _skel(b)  # only addresses moved

    lo = "strncpy(dst,src,0x100);"
    hi = "strncpy(dst,src,0xff);"
    assert _skel(lo) != _skel(hi)  # a constant stays put

    dec = "if (n < 256) {}"
    dec2 = "if (n < 255) {}"
    assert _skel(dec) != _skel(dec2)  # 256->255 is not hidden


def test_the_switch_and_branch_labels_normalise_too() -> None:
    """Ghidra writes a switch label as switchD_<addr>_caseD_<n> and a branch label as
    joined_r0x<addr> / code_r0x<addr>: two identical functions whose code moved differ only there
    and must read the same — while the case number itself stays.

    MUTATION: end the address at a word boundary (no mid-name address) or drop the ``r0x`` form ->
    RED."""
    a = "goto switchD_004492cc_caseD_3; if (x) goto joined_r0x00449e60; y = code_r0x00449e70;"
    b = "goto switchD_00449338_caseD_3; if (x) goto joined_r0x00449ecc; y = code_r0x00449ee0;"
    assert _skel(a) == _skel(b)
    assert _skel("switchD_004492cc_caseD_3;") != _skel("switchD_004492cc_caseD_4;")


def _same(a: str, b: str) -> bool:
    return _skel(a) == _skel(b)


def test_an_address_mid_name_is_blanked_only_in_the_two_labels_that_carry_one() -> None:
    """★ Mid-name, only the switch and the numbered branch label carry an address (exactly eight
    hex digits); every other hex-looking word inside a name is part of what the code says — a real
    symbol, the text a string label spells out, a local's access offset — and blanking it would
    read two different bodies as identical. Constants are never touched.

    MUTATION: restore the earlier mid-name rule (an address may be followed by ``_`` anywhere) ->
    the second group goes RED; restore the plain word-boundary rule (no mid-name labels, no
    ``r0x``) -> the first group goes RED."""
    for a, b in (
        ("goto switchD_004492cc_caseD_3;", "goto switchD_00449338_caseD_3;"),
        ("goto switchD_000b7c68_default;", "goto switchD_000b7d00_default;"),
        ("goto LAB_0008f0a0_1;", "goto LAB_0008f5e0_1;"),
        ("if (x) goto joined_r0x00449e60;", "if (x) goto joined_r0x00449ecc;"),
        ("y = code_r0x00449e70;", "y = code_r0x00449ee0;"),
        ("FUN_00012a40();", "FUN_00013b50();"),
        ("puts(s_hi_0001ccd0);", "puts(s_hi_0001cd00);"),
    ):
        assert _same(a, b), (a, b)
    for a, b in (
        ("p->cb = CRYPTO_cbc128_encrypt;", "p->cb = CRYPTO_cfb128_encrypt;"),
        (
            "puts(s_abcdefabcdefabcdefabcdefabcdefab_001a2464);",
            "puts(s_fedcbafedcbafedcbafedcbafedcbafe_001a2464);",
        ),
        ("x = l._153920_4_;", "x = l._253920_4_;"),
        ("puts(s_deadbeef_00412345);", "puts(s_cafebabe_00412345);"),
        ("goto switchD_004492cc_caseD_3;", "goto switchD_004492cc_caseD_4;"),
        ("uVar1 = 0x40;", "uVar1 = 0x3f;"),
    ):
        assert not _same(a, b), (a, b)


def _body(
    pseudocode: str | None, size: int | None = None, ranges: list[list[int]] | None = None
) -> sm.Body:
    return {"pseudocode": pseudocode, "size_bytes": size, "body_ranges": ranges or []}


def test_pair_reading_tells_no_body_apart_from_an_empty_body() -> None:
    """A reader must not have to recompute WHY a body was missing: ``no_body`` (a side absent from
    the functions table — an import/PLT stub) is kept apart from ``unavailable`` (present, empty).

    MUTATION: drop the ``NO_BODY in (sa, sb)`` branch (call every missing body 'unavailable') ->
    RED."""
    bodies_a = {"1000": _body("FUN_00001000();"), "2000": _body(None)}  # 2000 present but empty
    bodies_b = {"1000": _body("FUN_00009999();")}  # 3000 absent -> an import/PLT stub
    assert sm.pair_reading(bodies_a, bodies_b, "1000", "1000", None, None) == (
        True,
        None,
        (),
    )  # addresses only moved
    assert sm.pair_reading(bodies_a, bodies_b, "2000", "1000", None, None) == (
        None,
        sm.UNAVAILABLE,
        (),
    )  # a empty
    assert sm.pair_reading(bodies_a, bodies_b, "1000", "3000", None, None) == (
        None,
        sm.NO_BODY,
        (),
    )  # b absent
    assert sm.pair_reading(None, bodies_b, "1000", "1000", None, None) == (
        None,
        sm.UNAVAILABLE,
        (),
    )  # a db unreadable


# ── states: a match is only "identical" when the callees are proven equal ─────────────────────


def test_sameness_state_keeps_unverified_apart_and_prefers_a_changed_callee_set() -> None:
    """MUTATION: fold callee_state 'undetermined' into 'equal' (-> identical) or treat it as
    'differs' -> RED; drop the 'differs callee wins over no body' rule -> the last two lines go
    RED."""
    assert sm.sameness_state(True, "equal", None, ()) == sm.IDENTICAL
    assert sm.sameness_state(True, "undetermined", None, ()) == sm.IDENTICAL_CALLEE_UNVERIFIED
    assert (
        sm.sameness_state(True, "differs", None, ()) == sm.DIFFERS
    )  # text matched, a FUN_ call changed
    assert sm.sameness_state(False, "equal", None, ()) == sm.DIFFERS  # the text itself differs
    assert (
        sm.sameness_state(None, "equal", sm.NO_BODY, ()) == sm.NO_BODY
    )  # no body, nothing proves change
    assert sm.sameness_state(None, "undetermined", sm.UNAVAILABLE, ()) == sm.UNAVAILABLE
    # No body to read, but the callee sets differ -> that alone is proof of change.
    assert sm.sameness_state(None, "differs", sm.NO_BODY, ()) == sm.DIFFERS
    assert sm.sameness_state(None, "differs", sm.UNAVAILABLE, ()) == sm.DIFFERS


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


# ── N1: the try/catch annotation's addresses ─────────────────────────────────────────────────


def test_a_try_annotation_address_is_blanked_and_no_other_bare_hex() -> None:
    """T12. The try/catch annotation names code addresses that move with the code; any other
    comment (a WARNING) keeps its bare hex, and a small constant always stays put. "entry from" in
    a string or comment is not "try from".

    MUTATION: drop the ``try from`` restriction (blank bare hex in every comment) -> the WARNING
    pair reads equal -> RED."""
    a = "/* try { // try from 00406208 to 0040620f has its CatchHandler @ 00406d84 */\nfoo();"
    b = "/* try { // try from 00407308 to 0040730f has its CatchHandler @ 00407e84 */\nfoo();"
    assert sm.literal_reading(a, b, None, None) == (True, False)
    wa = "/* WARNING: Unknown calling convention at 00406208 */\nfoo();"
    wb = "/* WARNING: Unknown calling convention at 00407308 */\nfoo();"
    assert sm.literal_reading(wa, wb, None, None)[0] is False
    ea = "/* delete an entry from 00406208 */\nfoo();"
    eb = "/* delete an entry from 00407308 */\nfoo();"
    assert sm.literal_reading(ea, eb, None, None)[0] is False
    assert sm.literal_reading("x = 0x60;", "x = 0x64;", None, None)[0] is False


# ── N0: a large literal, position by position ───────────────────────────────────────────────


def test_a_large_literal_is_an_address_only_when_both_values_lie_in_their_images() -> None:
    """T13. A value the same on both sides is never looked up; a value that changed reads as a
    moved address only when each side's value lies in that side's image; a large constant that
    changed outside the image is a difference.

    MUTATION: blank each side by its own image (the old one-side-at-a-time rule) -> the unchanged
    0x100000 outside A's image stays raw on A and is blanked on B -> RED."""
    image_a = [(0x400000, 0x500000)]
    image_b = [(0x100000, 0x200000), (0x400000, 0x500000)]
    same = "p = 0x100000;"
    assert sm.literal_reading(same, same, image_a, image_b) == (True, False)
    big_a, big_b = "if (n < 0x7fffffff) {}", "if (n < 0xffffffff) {}"
    assert sm.literal_reading(big_a, big_b, image_a, image_b) == (False, False)
    moved_a, moved_b = "p = (char *)0x412340;", "p = (char *)0x412560;"
    assert sm.literal_reading(moved_a, moved_b, image_a, image_b) == (True, False)
    assert sm.literal_reading("f(0x412340);", "f(0x412340, 0x412340);", image_a, image_b) == (
        False,
        False,
    )


def test_a_moved_literal_read_on_an_unknown_image_is_named_not_trusted() -> None:
    """T13b. A changed value read as an address only because a side's image is unknown makes the
    match ``literal_basis_unknown`` (identical_text_unverified); a value the same on both sides
    needs no image and adds nothing.

    MUTATION: mark ``relied`` whenever an image is unknown, whatever the values -> the unchanged
    literal is flagged -> RED."""
    image = [(0x400000, 0x500000)]
    a, b = "p = (char *)0x412340;", "p = (char *)0x412560;"
    assert sm.literal_reading(a, b, None, image) == (True, True)
    assert sm.literal_reading(a, a, None, image) == (True, False)
    bodies_a, bodies_b = {"1000": _body(a)}, {"2000": _body(b)}
    matches, reason, reasons = sm.pair_reading(bodies_a, bodies_b, "1000", "2000", None, image)
    assert (matches, reason, reasons) == (True, None, (sm.LITERAL_BASIS_UNKNOWN,))
    assert sm.sameness_state(matches, "equal", reason, reasons) == sm.IDENTICAL_TEXT_UNVERIFIED
    same = sm.pair_reading({"1000": _body(a)}, {"2000": _body(a)}, "1000", "2000", None, image)
    assert same == (True, None, ())


# ── W: the decompiler's own "incomplete" notes ───────────────────────────────────────────────


def _reasons(text: str) -> tuple[str, ...]:
    return sm.pair_reading({"1": _body(text)}, {"2": _body(text)}, "1", "2", None, None)[2]


def test_a_text_match_the_decompiler_marked_incomplete_is_not_identical() -> None:
    """T14. Either jumptable note makes an otherwise equal text identical_text_unverified.

    MUTATION: match ``jumptable`` on "Could not recover jumptable" alone -> the second note is
    missed -> RED."""
    first = "/* WARNING: Could not recover jumptable at 0x0040b668. Too many branches */\nf();"
    second = "/* WARNING: Could not find normalized switch variable to match jumptable */\nf();"
    for text in (first, second):
        reasons = _reasons(text)
        assert reasons == ("decompile_incomplete:jumptable",), text
        assert sm.sameness_state(True, "equal", None, reasons) == sm.IDENTICAL_TEXT_UNVERIFIED


def test_the_three_later_markers_match_their_raw_text() -> None:
    """T14b. ``Switch with N destination removed`` carries a number, so it is a pattern, not a
    fixed string; the other two later markers match as written.

    MUTATION: write switch_destination_removed as the fixed text "Switch with destination
    removed" -> the numbered note is missed -> RED."""
    cases = {
        "/* WARNING: Switch with 3 destination removed at 0x1234 */": "switch_destination_removed",
        "/* WARNING: Ignoring partial resolution of indirect */": "indirect_partially_resolved",
        "/* WARNING: Exceeded maximum restarts with more pending */": (
            "decompile_restarts_exceeded"
        ),
    }
    for text, tag in cases.items():
        assert _reasons(text + "\nf();") == (f"decompile_incomplete:{tag}",), text
    assert _reasons("/* WARNING: Load size is inaccurate */\nf();") == ()  # not a hiding marker


# ── S: the two body byte counts ──────────────────────────────────────────────────────────────


def test_two_byte_counts_that_differ_qualify_a_text_match_and_mark_the_structure() -> None:
    """T15 / T16. Equal texts over byte counts that differ: body_size_differs, and hidden_region
    says structure_differs. Equal counts with a W marker: hidden_region says unknown — never
    identical.

    MUTATION: look at the byte counts only when a W marker hit -> the first pair reads identical
    -> RED; read equal counts as an unchanged body (``identical``) -> RED."""
    a, b = _body("f();", size=1064), _body("f();", size=1060)
    matches, _, reasons = sm.pair_reading({"1": a}, {"2": b}, "1", "2", None, None)
    assert matches is True and reasons == (sm.BODY_SIZE_DIFFERS,)
    assert sm.sameness_state(True, "equal", None, reasons) == sm.IDENTICAL_TEXT_UNVERIFIED
    region = sm.hidden_region(a, b, reasons, similarity=0.949, instructions=264)
    assert region is not None
    assert region["body"] == "structure_differs" and region["markers"] == []
    assert region["size_bytes"] == {"a": 1064, "b": 1060}
    w = "/* WARNING: Treating indirect jump as call */\nf();"
    wa, wb = _body(w, size=40), _body(w, size=40)
    w_reasons = sm.pair_reading({"1": wa}, {"2": wb}, "1", "2", None, None)[2]
    w_region = sm.hidden_region(wa, wb, w_reasons, similarity=1.0, instructions=10)
    assert w_region is not None and w_region["body"] == "unknown"


def test_a_byte_count_missing_on_one_side_adds_nothing() -> None:
    """T15b. A side with no recorded byte count proves nothing about the size: no reason, and the
    match stays identical when nothing else qualifies it.

    MUTATION: read a missing count as unequal -> body_size_differs -> RED."""
    a, b = _body("f();", size=1064), _body("f();", size=None)
    matches, reason, reasons = sm.pair_reading({"1": a}, {"2": b}, "1", "2", None, None)
    assert reasons == ()
    assert sm.sameness_state(matches, "equal", reason, reasons) == sm.IDENTICAL
    assert sm.hidden_region(a, b, reasons, similarity=1.0, instructions=1) is None


def test_a_marker_address_is_placed_in_or_out_of_its_own_closed_body_ranges() -> None:
    """T17. Ghidra's body range includes its max: an address equal to ``hi`` is inside. A marker
    naming no address is null.

    MUTATION: read the ranges half-open -> the ``hi`` marker reads outside -> RED; return true
    for every marker -> the outside one reads inside -> RED."""
    text = (
        "/* WARNING: Removing unreachable block (ram,0x00001010) */\n"
        "/* WARNING: Removing unreachable block (ram,0x00002000) */\n"
        "/* WARNING: Removing unreachable block (ram,0x000010ff) */\n"
        "/* WARNING: Treating indirect jump as call */\nf();"
    )
    a = _body(text, size=256, ranges=[[0x1000, 0x10FF]])
    reasons = sm.pair_reading({"1": a}, {"2": a}, "1", "2", None, None)[2]
    region = sm.hidden_region(a, a, reasons, similarity=1.0, instructions=64)
    assert region is not None
    on_a = [(m["tag"], m["addr"], m["in_own_body"]) for m in region["markers"] if m["side"] == "a"]
    assert on_a == [
        ("unreachable_block_removed", "0x00001010", True),
        ("unreachable_block_removed", "0x00002000", False),
        ("unreachable_block_removed", "0x000010ff", True),
        ("indirect_jump_as_call", None, None),
    ]


def test_an_empty_body_on_both_sides_is_unavailable_never_identical() -> None:
    """T28 (n1). A row whose pseudocode is empty is in the table (so not no_body) but has nothing to
    compare; two of them must not compare equal.

    MUTATION: test the body dict's truth instead of its ``pseudocode`` (a dict is always true) ->
    two empty bodies compare as identical -> RED."""
    bodies_a, bodies_b = {"1": _body(None, size=8)}, {"2": _body(None, size=8)}
    assert sm.pair_reading(bodies_a, bodies_b, "1", "2", None, None) == (None, sm.UNAVAILABLE, ())
    assert sm.sameness_state(None, "equal", sm.UNAVAILABLE, ()) == sm.UNAVAILABLE


# ── pseudocode_delta: the lexical shape of a difference ──────────────────────────────────────


def test_a_size_only_change_is_a_number_substitution() -> None:
    """T20. A buffer whose size moved reads as a substitution of numbers and nothing else, and the
    pair still differs.

    MUTATION: normalise small constants away -> the texts compare equal -> RED."""
    a = "void f(void)\n{\n  char buf[0x60];\n  memcpy(buf,src,0x60);\n}"
    b = "void f(void)\n{\n  char buf[0x64];\n  memcpy(buf,src,0x64);\n}"
    assert sm.literal_reading(a, b, None, None)[0] is False
    delta = sm.pseudocode_delta(a, b, None, None)
    assert delta["kind"] == "substitution_only" and delta["structural_spans"] == 0
    assert delta["substitutions"] == {
        "number": {"total": 2, "first": [["0x60", "0x64"], ["0x60", "0x64"]]}
    }
    assert delta["calls"] == {}


def test_dropped_calls_are_counted_by_name() -> None:
    """T21. Three calls cut to one is structural, and the call counts say which callee moved.

    MUTATION: count calls as a set -> both sides read 1 -> the callee is not listed -> RED."""
    a = 'void f(void)\n{\n  system("a");\n  system("b");\n  system("c");\n}'
    b = 'void f(void)\n{\n  system("a");\n}'
    delta = sm.pseudocode_delta(a, b, None, None)
    assert delta["kind"] == "structural" and delta["structural_spans"] >= 1
    assert delta["calls"] == {"system": {"a": 3, "b": 1}}


def test_a_spacing_only_difference_is_layout_and_still_differs() -> None:
    """T22. Only the spacing differs: the token streams agree (layout_only), yet the texts are not
    the same and the pair is never read as identical.

    MUTATION: strip whitespace before the text comparison -> the pair reads identical -> RED."""
    a = "void f(void)\n{\n  x = y + 1;\n}"
    b = "void f(void)\n{\n  x  =  y+1;\n\n}"
    assert sm.literal_reading(a, b, None, None)[0] is False
    assert sm.pseudocode_delta(a, b, None, None)["kind"] == "layout_only"


def test_a_delta_over_the_line_cap_is_not_computed(monkeypatch: pytest.MonkeyPatch) -> None:
    """T23. Above the cap the delta says so and does not run (or raise).

    MUTATION: drop the cap branch -> a delta is computed -> RED."""
    monkeypatch.setattr(sm, "DELTA_LINE_CAP", 3)
    a = "\n".join(f"x{i} = {i};" for i in range(5))
    b = "\n".join(f"x{i} = {i + 1};" for i in range(5))
    assert sm.pseudocode_delta(a, b, None, None) == {"kind": "not_computed", "reason": "too_large"}
