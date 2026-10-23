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
    b = "iVar1 = FUN_00407fb8(DAT_00077abc); puts(s_hi_00088eee);"
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
        ("FUN_0040caf0();", "FUN_0040a554();"),
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
        None,  # a match carries no bodies block
    )  # addresses only moved
    assert sm.pair_reading(bodies_a, bodies_b, "2000", "1000", None, None) == (
        None,
        sm.UNAVAILABLE,
        (),
        {  # a empty (size unrecorded -> size_unknown), b ok
            "a": {"status": sm.SIZE_UNKNOWN, "size_bytes": None},
            "b": {"status": "ok", "size_bytes": None},
        },
    )
    assert sm.pair_reading(bodies_a, bodies_b, "1000", "3000", None, None) == (
        None,
        sm.NO_BODY,
        (),
        {  # b absent from the table -> no_body
            "a": {"status": "ok", "size_bytes": None},
            "b": {"status": sm.NO_BODY, "size_bytes": None},
        },
    )
    assert sm.pair_reading(None, bodies_b, "1000", "1000", None, None) == (
        None,
        sm.UNAVAILABLE,
        (),
        {  # a db unreadable -> db_unavailable
            "a": {"status": sm.DB_UNAVAILABLE, "size_bytes": None},
            "b": {"status": "ok", "size_bytes": None},
        },
    )


def test_body_status_splits_an_empty_body_by_the_exporter_s_own_reason() -> None:
    """``_body_status`` tells the six per-side causes apart, reusing layer0._decompile_status for
    the present-but-empty body: a design-skipped micro-stub, a real empty decompile and an
    unrecorded size are not one ``unavailable``.

    MUTATION: fold ``failed`` back into one empty bucket (drop the decompile_empty/size_unknown
    rename) -> RED; read ``bodies is None`` as no_body instead of db_unavailable -> RED."""
    assert sm._body_status(None, "1") == sm.DB_UNAVAILABLE  # db unreadable
    assert sm._body_status({}, "1") == sm.NO_BODY  # absent from the table
    assert sm._body_status({"1": _body("f();", size=4)}, "1") == "ok"  # has pseudocode
    assert sm._body_status({"1": _body(None, size=8)}, "1") == sm.SKIPPED_MICRO  # empty, < MIN
    assert sm._body_status({"1": _body(None, size=64)}, "1") == sm.DECOMPILE_EMPTY  # empty, >= MIN
    assert sm._body_status({"1": _body(None, size=0)}, "1") == sm.SIZE_UNKNOWN  # empty, size 0
    assert (
        sm._body_status({"1": _body(None, size=None)}, "1") == sm.SIZE_UNKNOWN
    )  # empty, unrecorded


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


# ── the try/catch annotation's addresses ─────────────────────────────────────────────────────


def test_a_try_annotation_address_is_blanked_and_no_other_bare_hex() -> None:
    """The try/catch annotation names code addresses that move with the code; any other
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


def _try_body(start: int, end: int, handler: int) -> str:
    return (
        f"/* try {{ // try from {start:08x} to {end:08x} has its CatchHandler @ {handler:08x} */\n"
        "foo();"
    )


def test_a_try_annotation_matches_only_when_every_address_moved_with_the_entry() -> None:
    """Entries 0x1000 -> 0x2000. The blanked try/catch addresses keep a match only when each
    moved by exactly that offset (or none moved); a handler that moved by another offset reads
    differs, and its delta is a comment substitution, not layout. A body with no annotation is not
    touched.

    MUTATION: drop the offset check from pair_reading -> the handler pair matches -> RED; compare
    only each annotation's first two values (miss the handler) -> RED; blank the annotation in the
    delta whatever the offsets -> the delta is layout_only -> RED."""
    base = _try_body(0x406208, 0x40620F, 0x406D84)
    moved = _try_body(0x407208, 0x40720F, 0x407D84)
    handler_off = _try_body(0x407208, 0x40720F, 0x407E84)

    def read(a: str, b: str) -> tuple[bool | None, str | None, tuple[str, ...], object]:
        return sm.pair_reading({"1000": _body(a)}, {"2000": _body(b)}, "1000", "2000", None, None)

    assert read(base, moved) == (True, None, (), None)
    assert read(base, handler_off) == (False, None, (), None)
    assert read(base, base) == (True, None, (), None)  # the entry moved, the annotation did not
    assert read("FUN_00401000();", "FUN_00402000();") == (True, None, (), None)  # no annotation
    delta = sm.pseudocode_delta(base, handler_off, None, None, "1000", "2000")
    assert delta["kind"] != "layout_only"
    assert "comment" in delta["substitutions"]


# ── a large literal, position by position ───────────────────────────────────────────────────


def test_a_large_literal_is_an_address_only_when_both_values_lie_in_their_images() -> None:
    """A value the same on both sides is never looked up; a value that changed reads as a
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
    moved_a, moved_b = "p = (char *)0x41e8c8;", "p = (char *)0x41eae8;"
    assert sm.literal_reading(moved_a, moved_b, image_a, image_b) == (True, False)
    assert sm.literal_reading("f(0x41e8c8);", "f(0x41e8c8, 0x41e8c8);", image_a, image_b) == (
        False,
        False,
    )


def test_a_moved_literal_read_on_an_unknown_image_is_named_not_trusted() -> None:
    """A changed value read as an address only because a side's image is unknown makes the
    match ``literal_basis_unknown`` (identical_text_unverified); a value the same on both sides
    needs no image and adds nothing.

    MUTATION: mark ``relied`` whenever an image is unknown, whatever the values -> the unchanged
    literal is flagged -> RED."""
    image = [(0x400000, 0x500000)]
    a, b = "p = (char *)0x41e8c8;", "p = (char *)0x41eae8;"
    assert sm.literal_reading(a, b, None, image) == (True, True)
    assert sm.literal_reading(a, a, None, image) == (True, False)
    bodies_a, bodies_b = {"1000": _body(a)}, {"2000": _body(b)}
    matches, reason, reasons, _bodies = sm.pair_reading(
        bodies_a, bodies_b, "1000", "2000", None, image
    )
    assert (matches, reason, reasons) == (True, None, (sm.LITERAL_BASIS_UNKNOWN,))
    assert sm.sameness_state(matches, "equal", reason, reasons) == sm.IDENTICAL_TEXT_UNVERIFIED
    same = sm.pair_reading({"1000": _body(a)}, {"2000": _body(a)}, "1000", "2000", None, image)
    assert same == (True, None, (), None)


# ── W: the decompiler's own "incomplete" notes ───────────────────────────────────────────────


def _reasons(text: str) -> tuple[str, ...]:
    return sm.pair_reading({"1": _body(text)}, {"2": _body(text)}, "1", "2", None, None)[2]


def test_a_text_match_the_decompiler_marked_incomplete_is_not_identical() -> None:
    """Either jumptable note makes an otherwise equal text identical_text_unverified.

    MUTATION: match ``jumptable`` on "Could not recover jumptable" alone -> the second note is
    missed -> RED."""
    first = "/* WARNING: Could not recover jumptable at 0x00408218. Too many branches */\nf();"
    second = "/* WARNING: Could not find normalized switch variable to match jumptable */\nf();"
    for text in (first, second):
        reasons = _reasons(text)
        assert reasons == ("decompile_incomplete:jumptable",), text
        assert sm.sameness_state(True, "equal", None, reasons) == sm.IDENTICAL_TEXT_UNVERIFIED


def test_the_three_later_markers_match_their_raw_text() -> None:
    """``Switch with N destination removed`` carries a number, so it is a pattern, not a
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


# ── the two body byte counts ─────────────────────────────────────────────────────────────────


def test_two_byte_counts_that_differ_qualify_a_text_match_and_mark_the_structure() -> None:
    """Equal texts over byte counts that differ: body_size_differs, and hidden_region
    says structure_differs. Equal counts with a W marker: hidden_region says unknown — never
    identical.

    MUTATION: look at the byte counts only when a W marker hit -> the first pair reads identical
    -> RED; read equal counts as an unchanged body (``identical``) -> RED."""
    a, b = _body("f();", size=1064), _body("f();", size=1060)
    matches, _, reasons, _bodies = sm.pair_reading({"1": a}, {"2": b}, "1", "2", None, None)
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
    """A side with no recorded byte count proves nothing about the size: no reason, and the
    match stays identical when nothing else qualifies it.

    MUTATION: read a missing count as unequal -> body_size_differs -> RED."""
    a, b = _body("f();", size=1064), _body("f();", size=None)
    matches, reason, reasons, _bodies = sm.pair_reading({"1": a}, {"2": b}, "1", "2", None, None)
    assert reasons == ()
    assert sm.sameness_state(matches, "equal", reason, reasons) == sm.IDENTICAL
    assert sm.hidden_region(a, b, reasons, similarity=1.0, instructions=1) is None


def test_a_marker_address_is_placed_in_or_out_of_its_own_closed_body_ranges() -> None:
    """Ghidra's body range includes its max: an address equal to ``hi`` is inside. A marker
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


def test_an_empty_body_on_both_sides_is_never_identical() -> None:
    """A row whose pseudocode is empty is in the table (so not no_body) but has nothing to
    compare; two of them must not compare equal. Two micro-functions under _DECOMPILE_MIN_SIZE read
    skipped_micro (a design skip); two empty bodies of a decompilable size read unavailable.

    MUTATION: test the body dict's truth instead of its ``pseudocode`` (a dict is always true) ->
    two empty bodies compare as identical -> RED."""
    bodies_a, bodies_b = {"1": _body(None, size=8)}, {"2": _body(None, size=8)}
    assert sm.pair_reading(bodies_a, bodies_b, "1", "2", None, None) == (
        None,
        sm.SKIPPED_MICRO_STATE,
        (),
        {  # both empty and under _DECOMPILE_MIN_SIZE -> skipped_micro, by design not a failure
            "a": {"status": sm.SKIPPED_MICRO, "size_bytes": 8},
            "b": {"status": sm.SKIPPED_MICRO, "size_bytes": 8},
        },
    )
    assert sm.sameness_state(None, "equal", sm.SKIPPED_MICRO_STATE, ()) == "skipped_micro"
    big_a, big_b = {"1": _body(None, size=40)}, {"2": _body(None, size=40)}
    matches, reason, _r, _b = sm.pair_reading(big_a, big_b, "1", "2", None, None)
    assert (matches, reason) == (None, sm.UNAVAILABLE)
    assert sm.sameness_state(None, "equal", sm.UNAVAILABLE, ()) == sm.UNAVAILABLE


def _no_text_reason(a: dict | None, b: dict | None) -> tuple[str | None, tuple[str, str]]:
    """(pair reason, (a status, b status)) of one pair at addresses 1 / 2; None bodies = the side's
    analysis.db could not be read."""
    _m, reason, _r, bodies = sm.pair_reading(a, b, "1", "2", None, None)
    assert bodies is not None
    return reason, (bodies["a"]["status"], bodies["b"]["status"])


def test_a_pair_reads_skipped_micro_only_when_every_side_without_text_is_micro() -> None:
    """skipped_micro is the pair state when the sides without text are all design-skipped
    micro-functions (one beside a body with text, or both); a micro side beside an empty decompile,
    an unrecorded size or an unreadable analysis.db stays unavailable — the stronger gap names the
    pair — and a stub side stays no_body. The undetermined reading maps the same way.

    MUTATION (verified RED): read skipped_micro whenever EITHER side is micro
    (``SKIPPED_MICRO in (sa, sb)``) -> the three mixed pairs read skipped_micro -> RED.
    MUTATION (verified RED): pair_reading never returns skipped_micro -> the micro pairs RED."""
    micro, text = _body(None, size=6), _body("int f(void){return 1;}", size=24)
    cases = {
        "one_side": ({"1": text}, {"2": micro}),
        "both": ({"1": micro}, {"2": micro}),
        "micro+decompile_empty": ({"1": micro}, {"2": _body(None, size=40)}),
        "micro+size0": ({"1": micro}, {"2": _body(None, size=0)}),
        "micro+db_unavailable": ({"1": micro}, None),
        "micro+no_body": ({"1": micro}, {}),
    }
    got = {name: _no_text_reason(a, b) for name, (a, b) in cases.items()}
    assert got == {
        "one_side": (sm.SKIPPED_MICRO_STATE, ("ok", sm.SKIPPED_MICRO)),
        "both": (sm.SKIPPED_MICRO_STATE, (sm.SKIPPED_MICRO, sm.SKIPPED_MICRO)),
        "micro+decompile_empty": (sm.UNAVAILABLE, (sm.SKIPPED_MICRO, sm.DECOMPILE_EMPTY)),
        "micro+size0": (sm.UNAVAILABLE, (sm.SKIPPED_MICRO, sm.SIZE_UNKNOWN)),
        "micro+db_unavailable": (sm.UNAVAILABLE, (sm.SKIPPED_MICRO, sm.DB_UNAVAILABLE)),
        "micro+no_body": (sm.NO_BODY, (sm.SKIPPED_MICRO, sm.NO_BODY)),
    }
    proposed = {
        name: sm.undetermined_pair_state(None, "equal", reason, (), None)
        for name, (reason, _s) in got.items()
    }
    assert proposed == {
        "one_side": sm.U_SKIPPED_MICRO,
        "both": sm.U_SKIPPED_MICRO,
        "micro+decompile_empty": sm.U_UNAVAILABLE,
        "micro+size0": sm.U_UNAVAILABLE,
        "micro+db_unavailable": sm.U_UNAVAILABLE,
        "micro+no_body": sm.U_NO_BODY,
    }
    assert sm.U_SKIPPED_MICRO in sm.U_STATES and len(sm.U_STATES) == 8
    assert sm.NOT_LISTED_NAME[sm.SKIPPED_MICRO_STATE] == "aligned_pseudocode_skipped_micro"


# ── pseudocode_delta: the lexical shape of a difference ──────────────────────────────────────


def _without_hunk(delta: dict) -> dict:
    """A delta with its inline_hunk set aside: every other field, as it was before the hunk."""
    return {k: v for k, v in delta.items() if k != "inline_hunk"}


def test_a_size_only_change_is_a_number_substitution() -> None:
    """A buffer whose size moved reads as a substitution of numbers and nothing else, and the
    pair still differs.

    MUTATION: normalise small constants away -> the texts compare equal -> RED."""
    a = "void f(void)\n{\n  char buf[0x60];\n  memcpy(buf,src,0x60);\n}"
    b = "void f(void)\n{\n  char buf[0x64];\n  memcpy(buf,src,0x64);\n}"
    assert sm.literal_reading(a, b, None, None)[0] is False
    delta = sm.pseudocode_delta(a, b, None, None, "1000", "2000")
    assert delta["kind"] == "substitution_only" and delta["structural_spans"] == 0
    assert delta["substitutions"] == {
        "number": {"total": 2, "first": [["0x60", "0x64"], ["0x60", "0x64"]]}
    }
    assert delta["calls"] == {}


def test_dropped_calls_are_counted_by_name() -> None:
    """Three calls cut to one is structural, and the call counts say which callee moved.

    MUTATION: count calls as a set -> both sides read 1 -> the callee is not listed -> RED."""
    a = 'void f(void)\n{\n  system("a");\n  system("b");\n  system("c");\n}'
    b = 'void f(void)\n{\n  system("a");\n}'
    delta = sm.pseudocode_delta(a, b, None, None, "1000", "2000")
    assert delta["kind"] == "structural" and delta["structural_spans"] >= 1
    assert delta["calls"] == {"system": {"a": 3, "b": 1}}


def test_a_spacing_only_difference_is_layout_and_still_differs() -> None:
    """Only the spacing differs: the token streams agree (layout_only), yet the texts are not
    the same and the pair is never read as identical.

    MUTATION: strip whitespace before the text comparison -> the pair reads identical -> RED."""
    a = "void f(void)\n{\n  x = y + 1;\n}"
    b = "void f(void)\n{\n  x  =  y+1;\n\n}"
    assert sm.literal_reading(a, b, None, None)[0] is False
    assert sm.pseudocode_delta(a, b, None, None, "1000", "2000")["kind"] == "layout_only"


def test_a_delta_over_the_line_product_cap_is_not_computed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Above the line-pair bound the delta says so and does not run (or raise).

    MUTATION: drop the line-product branch -> a delta is computed -> RED."""
    monkeypatch.setattr(sm, "DELTA_LINE_PRODUCT_CAP", 24)  # 5 x 5 lines = 25 pairs
    a = "\n".join(f"x{i} = {i};" for i in range(5))
    b = "\n".join(f"x{i} = {i + 1};" for i in range(5))
    delta = sm.pseudocode_delta(a, b, None, None, "1000", "2000")
    assert _without_hunk(delta) == {"kind": "not_computed", "reason": "too_large"}
    # every line differs, so no identical head / tail to set aside: the hunk is withheld too
    assert delta["inline_hunk"] == {
        "withheld": "too_large",
        "lines": {"a": 5, "b": 5},
        "read_with": "get_pseudocode",
    }


def test_a_changed_block_over_the_token_product_cap_is_not_computed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The cost is the token-pair product of a changed block, so a few long lines rewritten
    whole are as expensive as many short ones: bounded by the product, not by the line count.
    A smaller rewrite of the same function is still computed.

    MUTATION: drop the token-product branch -> the large block is computed -> RED."""
    monkeypatch.setattr(sm, "DELTA_TOKEN_PRODUCT_CAP", 400)
    wide_a = "x = " + " + ".join(f"a{i}" for i in range(12)) + ";"
    wide_b = "x = " + " + ".join(f"b{i}" for i in range(12)) + ";"
    wide = sm.pseudocode_delta(wide_a, wide_b, None, None, "1000", "2000")
    assert _without_hunk(wide) == {"kind": "not_computed", "reason": "too_large"}
    assert wide["inline_hunk"]["withheld"] == "too_large"  # the middle's tokens are over the cap
    small = sm.pseudocode_delta("x = a1;", "x = b1;", None, None, "1000", "2000")
    assert small["kind"] == "substitution_only"


def test_the_token_cap_path_withholds_without_rematching_the_trimmed_middle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the whole-body TOKEN cap is hit, the hunk is withheld straight away: the identical head
    and tail are set aside only to count the middle's lines, the middle is NOT matched again (it
    would, in practice, hit the same cap at up to twice the cost). ``_delta_blocks`` is called
    exactly once on this path.

    MUTATION (audit A1): restore the ``blocks is None`` branch to call ``_trimmed_hunk`` (which
    re-trims and re-matches) -> ``_delta_blocks`` is called twice -> RED.
    """
    monkeypatch.setattr(sm, "DELTA_TOKEN_PRODUCT_CAP", 400)
    calls = {"n": 0}
    real = sm._delta_blocks

    def counting(la: list[str], lb: list[str]) -> object:
        calls["n"] += 1
        return real(la, lb)

    monkeypatch.setattr(sm, "_delta_blocks", counting)
    wide_a = "x = " + " + ".join(f"a{i}" for i in range(12)) + ";"
    wide_b = "x = " + " + ".join(f"b{i}" for i in range(12)) + ";"
    delta = sm.pseudocode_delta(wide_a, wide_b, None, None, "1000", "2000")
    assert _without_hunk(delta) == {"kind": "not_computed", "reason": "too_large"}
    assert delta["inline_hunk"]["withheld"] == "too_large"
    assert calls["n"] == 1, "the trimmed middle must not be matched a second time"


def test_a_too_large_delta_whose_trimmed_middle_shows_nothing_gets_a_zero_count_hunk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A delta over the LINE cap whose changed middle — once the identical head and tail are set
    aside — differs only in layout gets a ZERO-COUNT hunk, not a bare ``not_computed`` with no hunk.
    Otherwise the reader cannot tell the middle held nothing to show from an oversight.

    MUTATION (audit A5): return None instead of the zero-count hunk when ``_inline_hunk`` finds
    nothing on the trimmed path -> the delta carries no ``inline_hunk`` -> RED.
    """
    monkeypatch.setattr(sm, "DELTA_LINE_PRODUCT_CAP", 10)
    # over the cap whole (4 x 5 lines); trimmed to a middle that differs only in layout (a blank
    # line and spacing), so the middle computes as layout_only and _inline_hunk shows nothing.
    a = "void f(void)\n{\n  x = y + 1;\n}"
    b = "void f(void)\n{\n  x  =  y+1;\n\n}"
    delta = sm.pseudocode_delta(a, b, None, None, "1000", "2000")
    assert _without_hunk(delta) == {"kind": "not_computed", "reason": "too_large"}
    assert delta["inline_hunk"] == {
        "structural_lines": 0,
        "groups": 0,
        "structural": [],
        "substitution_groups": [],
    }


def test_two_number_substitutions_of_the_same_step_are_one_group() -> None:
    """Numbers are grouped by step, not by value: two changes of the same step (0x40->0x3f and
    0x100->0xff, both -1) are ONE group with ``total`` 2, so a single size-fix shift read across
    several lines is reported once.

    MUTATION (audit S14): group numbers by their old->new value pair instead of by step -> two
    groups -> RED.
    """
    d = sm.pseudocode_delta("a = 0x40;\nb = 0x100;", "a = 0x3f;\nb = 0xff;", None, None, "1", "2")
    groups = d["inline_hunk"]["substitution_groups"]
    assert len(groups) == 1
    assert groups[0]["kind"] == "number" and groups[0]["step"] == -1 and groups[0]["total"] == 2


def test_a_local_name_substitution_needs_both_sides_to_look_local() -> None:
    """``local_or_comment`` is for a decompiler local renamed to another decompiler local — both
    sides must look like one. ``local_10 -> local_14`` is local_or_comment; ``local_10 -> buf_len``
    (a real name on the B side) is a plain ``ident``, not hidden among the renames.

    MUTATION (audit S17): treat it as local_or_comment when EITHER side looks local -> the
    local_10 -> buf_len change lands local_or_comment -> RED.
    """
    both = sm.pseudocode_delta("x = local_10;", "x = local_14;", None, None, "1", "2")
    assert both["inline_hunk"]["substitution_groups"][0]["kind"] == "local_or_comment"
    one = sm.pseudocode_delta("x = local_10;", "x = buf_len;", None, None, "1", "2")
    assert one["inline_hunk"]["substitution_groups"][0]["kind"] == "ident"


def test_a_substitution_shows_the_original_token_not_the_normalised_one() -> None:
    """A changed token is shown as its side's ORIGINAL text, even when the line was aligned on the
    address-normalised text. A's ``0x401050`` sits in the mirror range and normalises to ``0x#``;
    ``first`` must still carry ``0x401050``, so the reader sees the real value.

    MUTATION (audit S20): take the normalised token in ``_shown_pair`` -> ``first`` carries ``0x#``
    -> RED.
    """
    d = sm.pseudocode_delta(
        "foo(0x401050);",
        "foo(0x999999);",
        [(0x400000, 0x4FFFFF)],
        [(0x800000, 0x8FFFFF)],
        "400000",
        "800000",
    )
    first = d["inline_hunk"]["substitution_groups"][0]["first"]
    assert first[0][0] == "0x401050", "the A side's own original text, not the normalised 0x#"


def test_structural_runs_merge_within_the_context_window_and_split_beyond_it() -> None:
    """Two structural blocks with at most ``2 * INLINE_HUNK_CONTEXT`` (4) lines between them are
    shown as one run (no context line printed twice); 5 lines apart, as two.

    MUTATIONs (audit S09/S09b): make the merge test ``<`` instead of ``<=`` -> the 4-line gap
    splits -> RED; raise the window by one (``2 * INLINE_HUNK_CONTEXT + 1``) -> the 5-line gap
    merges -> RED.
    """

    def runs(gap: int) -> int:
        ctx = "".join(f"c{i}();\n" for i in range(gap))
        a = "head();\ndelA();\n" + ctx + "delB();\ntail();"
        b = "head();\n" + ctx + "tail();"
        return len(sm.pseudocode_delta(a, b, None, None, "1", "2")["inline_hunk"]["structural"])

    assert runs(4) == 1, "a 4-line gap (== 2*INLINE_HUNK_CONTEXT) merges into one run"
    assert runs(5) == 2, "a 5-line gap stays two runs"


def test_the_token_cap_is_one_budget_for_the_whole_delta(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Changed blocks each under the token cap must still be refused once their products add up
    past it: the time is the SUM over blocks, and a per-block cap let many blocks, each just under
    it, run several times longer than any one block could.

    MUTATION: check each block's product alone instead of the running total -> the two-block body
    is computed -> RED."""
    monkeypatch.setattr(sm, "DELTA_TOKEN_PRODUCT_CAP", 400)

    def block(tag: str, k: int) -> list[str]:
        return [f"x{k} = {tag}{k} + {tag}{k + 1};"]  # one changed line: a small token block

    one_a = "\n".join(block("a", 0) + ["keep();"])
    one_b = "\n".join(block("b", 0) + ["keep();"])
    assert sm.pseudocode_delta(one_a, one_b, None, None, "1000", "2000")["kind"] != "not_computed"
    many_a = "\n".join(sum((block("a", k) + [f"keep{k}();"] for k in range(12)), []))
    many_b = "\n".join(sum((block("b", k) + [f"keep{k}();"] for k in range(12)), []))
    many = sm.pseudocode_delta(many_a, many_b, None, None, "1000", "2000")
    assert _without_hunk(many) == {"kind": "not_computed", "reason": "too_large"}
    assert many["inline_hunk"]["withheld"] == "too_large"


def test_the_line_cap_sits_at_five_million_pairs() -> None:
    """The line cap is a measured bound (a larger one ran into the tens of seconds), so it is
    pinned by behaviour at its real value: 2236 x 2236 lines (4,999,696 pairs) is computed,
    2237 x 2237 (5,004,169) is refused before any matching runs.

    MUTATION: raise DELTA_LINE_PRODUCT_CAP back to 25_000_000 -> the 2237-line body is computed
    -> RED."""

    def body(n: int, changed: int) -> str:
        return "\n".join(f"x{i} = {i + (1 if i == changed else 0)};" for i in range(n))

    assert (
        sm.pseudocode_delta(body(2236, -1), body(2236, 7), None, None, "1000", "2000")["kind"]
        == "substitution_only"
    )
    refused = sm.pseudocode_delta(body(2237, -1), body(2237, 7), None, None, "1000", "2000")
    assert _without_hunk(refused) == {"kind": "not_computed", "reason": "too_large"}


def test_the_token_budget_stays_at_five_million_pairs() -> None:
    """The token budget is pinned at its measured value: one changed block just under it ran about
    3s, and a block-count multiple of that is what the budget exists to stop. Raising it is a
    decision to re-measure, not a constant to tweak.

    MUTATION: raise DELTA_TOKEN_PRODUCT_CAP to 20_000_000 -> RED."""
    assert sm.DELTA_TOKEN_PRODUCT_CAP == 5_000_000


# ── line_number_form: a __FILE__/__LINE__ shift is demoted, a real change is not ──────────────


def _lnf(a: str, b: str, name_a: str | None = None, name_b: str | None = None) -> dict | None:
    """``line_number_form`` through the public path (pseudocode_delta threads the names)."""
    return sm.pseudocode_delta(a, b, None, None, "1000", "2000", name_a, name_b).get(
        "line_number_form"
    )


def test_a_file_line_argument_shift_is_recognised_as_line_number_form() -> None:
    """A number that is a top-level call argument right after a source-path (or own-function-name)
    string, shifted by one constant step, is line_number_form — the shape a __FILE__/__LINE__ bump
    leaves. Two such sites in one body share the one step. A call that spans lines is parsed on the
    whole text, so it is still recognised.

    MUTATION: drop the name_a/name_b parameter (never thread the names) -> the func-name case stops
    being recognised -> RED; parse only inside the changed line block -> the cross-line call is
    missed -> RED."""
    assert _lnf('log("foo.c", 10);', 'log("foo.c", 20);') == {"delta": 10, "sites": 1}
    assert _lnf('f("a.c", 10);\nf("a.c", 20);', 'f("a.c", 17);\nf("a.c", 27);') == {
        "delta": 7,
        "sites": 2,
    }
    assert _lnf('log("foo.c",\n10);', 'log("foo.c",\n17);') == {"delta": 7, "sites": 1}
    # the string is the side's own function name, passed in (synthetic names are passed as None)
    assert _lnf('chk("myfn", 5);', 'chk("myfn", 12);', "myfn", "myfn") == {"delta": 7, "sites": 1}
    assert _lnf('chk("myfn", 5);', 'chk("myfn", 12);') is None  # names not given -> not matched


def test_a_real_number_change_is_never_line_number_form() -> None:
    """Only a number that is a top-level call argument immediately after a STRING LITERAL that is a
    source path or the function name counts. A size, a port, a non-path/name string, a structural
    position and a mixed-kind substitution all stay in the read-first head.

    MUTATION: accept any number in a call that also carries a format string -> the snprintf size is
    matched -> RED."""
    # the changed number's preceding argument is not a lone string literal
    assert (
        _lnf('snprintf(b, 0x40, "%s=%d", "max", 0x20);', 'snprintf(b, 0x40, "%s=%d", "max", 0x80);')
        is None
    )
    assert (
        _lnf('log("%s:%d", &DAT_00001234, 0x1f90);', 'log("%s:%d", &DAT_00001234, 0x2000);') is None
    )
    assert _lnf("memcpy(dst, src, 0x60);", "memcpy(dst, src, 0x64);") is None
    # the preceding string is neither a source path nor the function name
    assert _lnf('set("max", 5);', 'set("max", 7);') is None
    assert _lnf('print("%d items", 5);', 'print("%d items", 7);') is None
    # the number is not a call argument at all (a structural position)
    assert _lnf("x = 10;", "x = 20;") is None
    # a mixed-kind (ident + number) substitution does not count
    assert _lnf('log("foo.c", a, 10);', 'log("foo.c", b, 20);') is None


def test_line_number_form_needs_one_consistent_nonzero_step() -> None:
    """Every changed number must shift by the same nonzero step; a mix of steps, or no change, is
    not a line-number bump.

    MUTATION: drop the equal-step check (keep the last step) -> the two-step body matches -> RED."""
    assert _lnf('f("a.c", 10);\ng("b.c", 0x40);', 'f("a.c", 17);\ng("b.c", 0x3f);') is None


def test_a_source_path_is_the_whole_string_not_its_suffix() -> None:
    """The string before the shifted number reads as a source path only when the WHOLE string is a
    path-like token ending in .c / .cc / .cpp / .h — a message or a format that merely ends in one,
    or begins with one, is not a path, so the pair stays in the read-first head.

    MUTATION: test the suffix alone (``endswith``) -> the message and the format are demoted -> RED;
    anchor only the start (``match`` for ``fullmatch``) -> "util.c: bad" and "net.cfg" (whose
    start reads as "net.c") are demoted -> RED.
    """
    assert _lnf('err(1, "cannot open config.c", 5);', 'err(1, "cannot open config.c", 6);') is None
    assert _lnf('cfg_set(b, "%s/%s.h", 0x20);', 'cfg_set(b, "%s/%s.h", 0x40);') is None
    assert _lnf('err(1, "util.c: bad", 5);', 'err(1, "util.c: bad", 6);') is None
    assert _lnf('load("net.cfg", 5);', 'load("net.cfg", 6);') is None
    assert _lnf('log("src/net/sock-io.c", 10);', 'log("src/net/sock-io.c", 11);') == {
        "delta": 1,
        "sites": 1,
    }
    assert _lnf('log("ui/view.cpp", 3);', 'log("ui/view.cpp", 5);') == {"delta": 2, "sites": 1}


def test_the_shifted_number_must_be_a_whole_call_argument() -> None:
    """The changed number must be an argument on its own; one inside an argument expression
    (``x + 10``) is a computed value, not a line number, even right after a source path.

    MUTATION: accept a number anywhere inside the argument -> the ``x + 10`` pair is demoted -> RED.
    """
    assert _lnf('f("a.c", x + 10);', 'f("a.c", x + 11);') is None


def test_a_statement_bound_ends_the_walk_back_to_the_call() -> None:
    """The walk back from the number to its call's ``(`` stops at a statement bound (``;`` ``{``
    ``}``) — so a brace in an earlier argument (a compound literal) ends it too, and the pair stays
    in the read-first head: the walk never reaches past one to find a call.

    MUTATION: walk past the statement bounds -> the compound-literal call is read and demoted ->
    RED."""
    assert (
        _lnf('log((struct pos){1, 2}, "a.c", 10);', 'log((struct pos){1, 2}, "a.c", 11);') is None
    )


# ── inline_hunk: the changed lines themselves, from the original text (S4) ────────────────────

# Handwritten bodies (no firmware text) and their delta as it was BEFORE inline_hunk existed
# (computed at 7e61b2e): the hunk is added on top and must never move any of these fields.
_DELTA_CASES = {
    "structural_deleted_call": (
        "int handler(int a)\n"
        "{\n"
        "  char buf[64];\n"
        "  int n;\n"
        "\n"
        "  n = read_input(buf);\n"
        "  if (n > 0) {\n"
        "    FUN_00409748(buf);\n"
        "  }\n"
        "  log_it(n);\n"
        "  return n;\n"
        "}\n",
        "int handler(int a)\n"
        "{\n"
        "  char buf[64];\n"
        "  int n;\n"
        "\n"
        "  n = read_input(buf);\n"
        "  if (n > 0) {\n"
        "  }\n"
        "  log_it(n);\n"
        "  return n;\n"
        "}\n",
        "00401000",
        "00402000",
        "handler",
        "handler",
    ),
    "structural_copy_swap": (
        "void set_key(char *dst, char *src)\n{\n  strcpy(dst, src);\n  return;\n}\n",
        'void set_key(char *dst, char *src)\n{\n  snprintf(dst, 0x40, "%s", src);\n  return;\n}\n',
        "00401100",
        "00402100",
        "set_key",
        "set_key",
    ),
    "number_substitution": (
        "void f(void)\n"
        "{\n"
        "  char b[64];\n"
        "  memset(b, 0, 0x40);\n"
        "  fgets(b, 0x40, fp);\n"
        "  return;\n"
        "}\n",
        "void f(void)\n"
        "{\n"
        "  char b[64];\n"
        "  memset(b, 0, 0x3f);\n"
        "  fgets(b, 0x3f, fp);\n"
        "  return;\n"
        "}\n",
        "00401200",
        "00402200",
        None,
        None,
    ),
    "local_rename_and_comment": (
        "void g(void)\n"
        "{\n"
        "  int local_10;\n"
        "  /* old note */\n"
        "  local_10 = get();\n"
        "  use(local_10);\n"
        "  return;\n"
        "}\n",
        "void g(void)\n"
        "{\n"
        "  int local_14;\n"
        "  /* new note */\n"
        "  local_14 = get();\n"
        "  use(local_14);\n"
        "  return;\n"
        "}\n",
        "00401300",
        "00402300",
        None,
        None,
    ),
    "ident_and_string_substitution": (
        'void h(void)\n{\n  call_a("old");\n  call_a("old");\n  return;\n}\n',
        'void h(void)\n{\n  call_b("new");\n  call_b("new");\n  return;\n}\n',
        "00401400",
        "00402400",
        None,
        None,
    ),
    "layout_only": (
        "void k(void)\n{\n  foo(1, 2);\n  return;\n}\n",
        "void k(void)\n{\n  foo(1,\n      2);\n  return;\n}\n",
        "00401500",
        "00402500",
        None,
        None,
    ),
    "address_shift_only": (
        "void m(void)\n{\n  FUN_00401000(DAT_00412345);\n  return;\n}\n",
        "void m(void)\n{\n  FUN_00403000(DAT_00418888);\n  return;\n}\n",
        "00401600",
        "00402600",
        None,
        None,
    ),
    "line_number_form": (
        "void report(int e)\n"
        "{\n"
        '  log_at("src/net.c", 120, e);\n'
        '  log_at("src/net.c", 131, e);\n'
        "  return;\n"
        "}\n",
        "void report(int e)\n"
        "{\n"
        '  log_at("src/net.c", 122, e);\n'
        '  log_at("src/net.c", 133, e);\n'
        "  return;\n"
        "}\n",
        "00401700",
        "00402700",
        "report",
        "report",
    ),
    "two_blocks_mergeable": (
        "void p(void)\n"
        "{\n"
        "  a1();\n"
        "  a2();\n"
        "  a3();\n"
        "  x1();\n"
        "  a4();\n"
        "  a5();\n"
        "  x2();\n"
        "  a6();\n"
        "  a7();\n"
        "  a8();\n"
        "}\n",
        "void p(void)\n"
        "{\n"
        "  a1();\n"
        "  a2();\n"
        "  a3();\n"
        "  a4();\n"
        "  a5();\n"
        "  y2(1);\n"
        "  a6();\n"
        "  a7();\n"
        "  a8();\n"
        "}\n",
        "00401800",
        "00402800",
        None,
        None,
    ),
}

_DELTA_GOLDEN = {
    "structural_deleted_call": {
        "kind": "structural",
        "structural_spans": 1,
        "substitutions": {},
        "calls": {"unnamed": {"a": 1, "b": 0}},
    },
    "structural_copy_swap": {
        "kind": "structural",
        "structural_spans": 1,
        "substitutions": {"ident": {"total": 1, "first": [["strcpy", "snprintf"]]}},
        "calls": {"snprintf": {"a": 0, "b": 1}, "strcpy": {"a": 1, "b": 0}},
    },
    "number_substitution": {
        "kind": "substitution_only",
        "structural_spans": 0,
        "substitutions": {"number": {"total": 2, "first": [["0x40", "0x3f"], ["0x40", "0x3f"]]}},
        "calls": {},
    },
    "local_rename_and_comment": {
        "kind": "substitution_only",
        "structural_spans": 0,
        "substitutions": {
            "comment": {"total": 1, "first": [["/* old note */", "/* new note */"]]},
            "ident": {
                "total": 3,
                "first": [
                    ["local_10", "local_14"],
                    ["local_10", "local_14"],
                    ["local_10", "local_14"],
                ],
            },
        },
        "calls": {},
    },
    "ident_and_string_substitution": {
        "kind": "substitution_only",
        "structural_spans": 0,
        "substitutions": {
            "ident": {"total": 2, "first": [["call_a", "call_b"], ["call_a", "call_b"]]},
            "string": {"total": 2, "first": [['"old"', '"new"'], ['"old"', '"new"']]},
        },
        "calls": {"call_a": {"a": 2, "b": 0}, "call_b": {"a": 0, "b": 2}},
    },
    "layout_only": {"kind": "layout_only", "structural_spans": 0, "substitutions": {}, "calls": {}},
    "address_shift_only": {
        "kind": "layout_only",
        "structural_spans": 0,
        "substitutions": {},
        "calls": {},
    },
    "line_number_form": {
        "kind": "substitution_only",
        "structural_spans": 0,
        "substitutions": {"number": {"total": 2, "first": [["120", "122"], ["131", "133"]]}},
        "calls": {},
        "line_number_form": {"delta": 2, "sites": 2},
    },
    "two_blocks_mergeable": {
        "kind": "structural",
        "structural_spans": 2,
        "substitutions": {"ident": {"total": 1, "first": [["x2", "y2"]]}},
        "calls": {"x1": {"a": 1, "b": 0}, "x2": {"a": 1, "b": 0}, "y2": {"a": 0, "b": 1}},
    },
}


def _hunk(name: str) -> dict | None:
    a, b, fa, fb, na, nb = _DELTA_CASES[name]
    return sm.pseudocode_delta(a, b, None, None, fa, fb, na, nb).get("inline_hunk")


def test_the_hunk_leaves_every_other_field_of_the_delta_as_it_was() -> None:
    """★ inline_hunk is added on top: with it set aside, the delta of every case is byte for byte
    what it was before the hunk existed, and the hunk is the LAST field.

    MUTATION (verified RED): read the subs from structural blocks only -> RED; let the gate turn a
    delta not_computed -> RED; normalise decompiler locals before the line match -> RED."""
    import json

    for name, (a, b, fa, fb, na, nb) in _DELTA_CASES.items():
        delta = sm.pseudocode_delta(a, b, None, None, fa, fb, na, nb)
        assert json.dumps(_without_hunk(delta)) == json.dumps(_DELTA_GOLDEN[name]), name
        if "inline_hunk" in delta:
            assert list(delta)[-1] == "inline_hunk", name


def test_a_deleted_call_is_shown_with_its_original_name() -> None:
    """★ The lines are aligned on the normalised text, where FUN_00409748 reads FUN_@, but shown as
    the original text has them, with two context lines on each side.

    MUTATION (verified RED): show the normalised line -> '-FUN_@(buf);' -> RED; context 0 -> RED."""
    assert _hunk("structural_deleted_call") == {
        "structural_lines": 1,
        "groups": 0,
        "structural": [
            [" n = read_input(buf);", " if (n > 0) {", "-FUN_00409748(buf);", " }", " log_it(n);"]
        ],
        "substitution_groups": [],
    }


def test_a_structural_block_shows_both_sides() -> None:
    """A replaced call is shown on both sides (the A side's line and the B side's), not the A side
    alone; only the context comes from one side."""
    (run,) = (_hunk("structural_copy_swap") or {})["structural"]
    assert "-strcpy(dst, src);" in run
    assert '+snprintf(dst, 0x40, "%s", src);' in run


def test_a_local_rename_is_a_group_never_aligned_away() -> None:
    """★ local_10 -> local_14 is another stack slot (maybe another buffer): it is grouped, with the
    comment change, as local_or_comment — every occurrence counted, the first ones placed by the
    1-based line of each side's original text — and never folded into the text the lines are
    aligned on (the delta still records the three ident substitutions, see the golden).

    MUTATION (verified RED): normalise decompiler-local names before the line match -> the rename
    is gone from the hunk -> RED; group each local pair apart -> two groups -> RED."""
    assert _hunk("local_rename_and_comment") == {
        "structural_lines": 0,
        "groups": 1,
        "structural": [],
        "substitution_groups": [
            {
                "kind": "local_or_comment",
                "total": 4,
                "first": [
                    ["local_10", "local_14", 3, 3],
                    ["/* old note */", "/* new note */", 4, 4],
                    ["local_10", "local_14", 5, 5],
                    ["local_10", "local_14", 6, 6],
                ],
            }
        ],
    }


def test_the_local_name_rule_is_the_decompiler_s_own_names() -> None:
    """The rename rule matches the names a decompiler makes up — and no real symbol of the same
    shape outside those prefixes."""
    made_up = [
        "local_10",
        "param_1",
        "in_v0",
        "extraout_v0",
        "unaff_s0",
        "auStack_870",
        "uStack_14",
        "piStack_8",
        "uVar1",
        "iVar22",
        "bVar3",
        "auVar4",
    ]
    real = ["memcpy", "localtime", "parameter", "var1", "Var1", "stack_top", "uVar"]
    assert all(sm._DECOMPILER_LOCAL.match(n) for n in made_up)
    assert not any(sm._DECOMPILER_LOCAL.match(n) for n in real)


def test_numbers_group_by_step_and_names_by_pair() -> None:
    """Each like substitution is one line: numbers by their step (0x40 -> 0x3f is -1), an identifier
    or a string by its pair, each with its total and first places."""
    num = _hunk("number_substitution") or {}
    assert num["substitution_groups"] == [
        {
            "kind": "number",
            "step": -1,
            "total": 2,
            "first": [["0x40", "0x3f", 4, 4], ["0x40", "0x3f", 5, 5]],
        }
    ]
    names = _hunk("ident_and_string_substitution") or {}
    assert [(g["kind"], g["total"]) for g in names["substitution_groups"]] == [
        ("ident", 2),
        ("string", 2),
    ]
    assert names["groups"] == 2


def test_close_runs_merge_and_far_runs_do_not() -> None:
    """Two structural blocks with at most four (2 x 2) lines between them are one run, so no
    context line is printed twice; further apart they are two runs, each with its own context.

    MUTATION (verified RED): never merge -> the 2-line gap gives two runs -> RED."""
    (merged,) = (_hunk("two_blocks_mergeable") or {})["structural"]
    assert merged == [
        " a2();",
        " a3();",
        "-x1();",
        " a4();",
        " a5();",
        "-x2();",
        "+y2(1);",
        " a6();",
        " a7();",
    ]
    a = "\n".join(["{", *[f"k{i}();" for i in range(12)], "}"])
    b = a.replace("k1();", "z1(2);").replace("k9();", "z9(1);")
    runs = sm.pseudocode_delta(a, b, None, None, "1000", "2000")["inline_hunk"]["structural"]
    assert [r[2:4] for r in runs] == [["-k1();", "+z1(2);"], ["-k9();", "+z9(1);"]]


def test_a_context_line_whose_b_text_differs_is_given_on_both_sides() -> None:
    """A context line matches only once addresses are normalised: its B text is given beside it
    (``=``), so neither side's real address is lost."""
    a = "void f(void)\n{\n  g = FUN_00401000(1);\n  drop();\n  return;\n}"
    b = "void f(void)\n{\n  g = FUN_00403000(1);\n  return;\n}"
    (run,) = sm.pseudocode_delta(a, b, None, None, "1000", "2000")["inline_hunk"]["structural"]
    assert run == [
        " {",
        " g = FUN_00401000(1);",
        "=g = FUN_00403000(1);",
        "-drop();",
        " return;",
        " }",
    ]


def test_places_are_lines_of_the_original_text_counting_blank_ones() -> None:
    """A group's places are 1-based lines of each side's original text, blank lines counted, as
    get_pseudocode returns it — not positions in the blank-free text the lines are aligned on.

    MUTATION (verified RED): number the normalised lines -> 3 / 3 -> RED."""
    a = "void f(void)\n{\n\n\n  n = 0x40;\n}"
    b = "void f(void)\n{\n\n  n = 0x3f;\n}"
    (group,) = sm.pseudocode_delta(a, b, None, None, "1000", "2000")["inline_hunk"][
        "substitution_groups"
    ]
    assert group["first"] == [["0x40", "0x3f", 5, 4]]


def test_the_gate_withholds_the_hunk_and_never_the_delta() -> None:
    """★ Over 50 (structural lines + substitution groups) the hunk is withheld with both counts and
    the place to read instead; the delta's own fields stay whole (kind, spans, calls). At 50 it is
    still given. A withheld hunk is never an empty one.

    MUTATION (verified RED): give the hunk over the gate -> RED; turn the delta not_computed over
    the gate -> RED; count context lines in the gate -> the 50-line case is withheld -> RED."""
    keep = [f"keep{i}();" for i in range(6)]

    def body(changed: list[str]) -> str:
        return "\n".join(["{", *keep[:3], *changed, *keep[3:], "}"])

    at_gate = sm.pseudocode_delta(
        body([f"a{i}();" for i in range(25)]),
        body([f"b{i}(1);" for i in range(25)]),
        None,
        None,
        "1",
        "2",
    )
    assert at_gate["inline_hunk"]["structural_lines"] == 50
    assert "withheld" not in at_gate["inline_hunk"]
    over = sm.pseudocode_delta(
        body([f"a{i}();" for i in range(26)]),
        body([f"b{i}(1);" for i in range(25)]),
        None,
        None,
        "1",
        "2",
    )
    assert over["kind"] == "structural" and over["structural_spans"] >= 1
    assert over["calls"]["a0"] == {"a": 1, "b": 0}
    assert over["inline_hunk"] == {
        "withheld": "over_gate",
        "structural_lines": 51,
        "groups": 0,
        "read_with": "get_pseudocode",
    }


def test_nothing_to_show_has_no_hunk() -> None:
    """A layout-only difference (and a pure address shift) has no hunk at all, not an empty one."""
    assert _hunk("layout_only") is None
    assert _hunk("address_shift_only") is None


def test_no_block_position_is_output() -> None:
    """The hunk names no block position: a run is lines of text, and the only numbers are its two
    counts and each group's step, total and first places.

    MUTATION (verified RED): add the blocks' i1/i2/j1/j2 to the hunk -> RED."""
    for name in _DELTA_CASES:
        h = _hunk(name)
        if h is None:
            continue
        assert set(h) == {"structural_lines", "groups", "structural", "substitution_groups"}
        assert all(isinstance(line, str) for run in h["structural"] for line in run)
        for g in h["substitution_groups"]:
            assert set(g) <= {"kind", "step", "total", "first"}
            assert all(len(f) == 4 for f in g["first"])


def test_a_too_large_delta_still_shows_its_changed_middle(monkeypatch: pytest.MonkeyPatch) -> None:
    """★ A function too large to align whole is still not_computed, but with its identical leading
    and trailing lines set aside the changed middle is matched and shown, its places mapped back
    past the set-aside head; a middle still over the cap is withheld with its line counts.

    MUTATION (verified RED): do not set the head and tail aside -> withheld -> RED; forget the head
    offset -> wrong line -> RED."""
    monkeypatch.setattr(sm, "DELTA_LINE_PRODUCT_CAP", 99)  # 10 x 10 lines = 100 pairs
    lines = [f"x{i} = {i};" for i in range(10)]
    a = "\n".join(lines)
    b = "\n".join(lines[:6] + ["x6 = 60;"] + lines[7:])
    delta = sm.pseudocode_delta(a, b, None, None, "1000", "2000")
    assert _without_hunk(delta) == {"kind": "not_computed", "reason": "too_large"}
    assert delta["inline_hunk"]["substitution_groups"] == [
        {"kind": "number", "step": 54, "total": 1, "first": [["6", "60", 7, 7]]}
    ]
    monkeypatch.setattr(sm, "DELTA_LINE_PRODUCT_CAP", 3)  # the middle (2 x 2) is over this one
    b2 = "\n".join(lines[:6] + ["x6 = 60;", "x7 = 70;"] + lines[8:])
    withheld = sm.pseudocode_delta(a, b2, None, None, "1000", "2000")["inline_hunk"]
    assert withheld == {
        "withheld": "too_large",
        "lines": {"a": 2, "b": 2},
        "read_with": "get_pseudocode",
    }


# ── the guard scan: comparisons the B side's structural change introduces ─────────────────────


def _scan(a: str, b: str) -> dict:
    return sm.pseudocode_delta_and_guards(a, b, None, None, "1000", "2000")[1]


def _guard_tuples(scan: dict) -> list[tuple]:
    return [
        (g["var"], g["relation"], g["const"], g.get("cast"), g["const_class"])
        for g in scan["guards"]
    ]


def test_a_comparison_added_in_a_structural_block_is_a_guard_at_its_original_line() -> None:
    """G1: a B-only ``if (uVar3 > 0x40)`` in a structural block is one guard, nonzero, its line_b
    the 1-based line of the ORIGINAL B text (a blank line counted). A guard whose variable has no
    cast carries no ``cast`` key at all (one with a cast does: G2b).

    MUTATION (verified RED, 1 failed): write ``cast: null`` on every guard -> RED."""
    a = "n = read(buf);\nfoo(n);"
    b = "n = read(buf);\n\nif (uVar3 > 0x40) {\n  bar();\n}\nfoo(n);"
    scan = _scan(a, b)
    assert scan["state"] == "done"
    assert scan["guards"] == [
        {
            "var": "uVar3",
            "const": "0x40",
            "relation": ">",
            "const_class": "nonzero",
            "line_b": 3,
        }
    ]
    assert scan["var_const_total"] == 1
    assert scan["by_const_class"] == {"zero": 0, "nonzero": 1}


def test_a_constant_on_the_left_is_read_with_the_variable_first() -> None:
    """G2: ``0x40 < uVar3`` is read ``uVar3 > 0x40`` — a syntax normalisation only.

    MUTATION (verified RED, 1 failed): keep the relation as written when the constant is on the
    left -> RED."""
    assert _guard_tuples(_scan("foo();", "if (0x40 < uVar3) bar();")) == [
        ("uVar3", ">", "0x40", None, "nonzero")
    ]


def test_an_ordering_inside_an_equality_is_read_by_cs_precedence() -> None:
    """G2b: in ``(int)x < 0 == bVar1`` the ``<`` binds tighter: it is the one guard
    ``x < 0`` (cast ``(int)``); the ``==`` has a compound left operand and is counted as other.

    MUTATION M18 (verified RED, 1 failed): make the ordering operators boundaries of an
    equality's scan too -> the ``==`` reads ``0 == bVar1`` (a second guard) -> RED."""
    scan = _scan("foo();", "if ((int)x < 0 == bVar1) bar();")
    assert _guard_tuples(scan) == [("x", "<", "0", "(int)", "zero")]
    assert scan["guards"][0].get("cast") == "(int)"
    assert scan["other_comparisons"] == {"var_var": 0, "call": 0, "field": 0, "other": 1}


def test_a_constant_on_the_left_of_a_bound_flips_the_bound() -> None:
    """G2 (bounds): ``0x40 <= n`` reads ``n >= 0x40`` and ``0x40 >= n`` reads ``n <= 0x40``.

    MUTATION (verified RED, 1 failed): flip ``<=`` to ``<`` (and ``>=`` to ``>``) -> RED."""
    assert _guard_tuples(_scan("foo();", "if (0x40 <= n) bar();")) == [
        ("n", ">=", "0x40", None, "nonzero")
    ]
    assert _guard_tuples(_scan("foo();", "if (0x40 >= n) bar();")) == [
        ("n", "<=", "0x40", None, "nonzero")
    ]


def test_at_most_one_cast_is_set_aside() -> None:
    """``(int)(uint)x < 5`` has two casts: the operand is compound, so no guard.

    MUTATION (verified RED, 1 failed): set aside every leading cast -> ``x < 5`` is a guard ->
    RED."""
    scan = _scan("foo();", "if ((int)(uint)x < 5) bar();")
    assert scan["guards"] == []
    assert scan["other_comparisons"]["other"] == 1


def test_an_address_taken_after_a_cast_is_no_guard() -> None:
    """``(uint)&local_10 < 0x10`` and ``*(int *)&local_10 < 5``: the ``&`` after a cast's ``)``
    takes an address, so the operand is compound — not the variable ``local_10``. A ``&`` after
    a parenthesised expression, a call or ``sizeof (type)`` stays binary, and ``<`` binds tighter:
    ``(a + b) & n < 5`` holds the guard ``n < 5``.

    MUTATION (verified RED, 1 failed): read every ``&`` after ``)`` as binary -> ``local_10 <
    0x10`` and ``local_10 < 5`` are guards -> RED."""
    assert _scan("foo();", "if ((uint)&local_10 < 0x10) bar();")["guards"] == []
    assert _scan("foo();", "if (*(int *)&local_10 < 5) bar();")["guards"] == []
    for binary in ("(a + b) & n < 5", "f(x) & n < 5", "sizeof(int) & n < 5"):
        assert _guard_tuples(_scan("foo();", f"if ({binary}) bar();")) == [
            ("n", "<", "5", None, "nonzero")
        ], binary


def _marks(scan: dict) -> list[tuple]:
    return [(g["var"], g["line_b"], g.get("renumbered_in_a")) for g in scan["guards"]]


def _lines(*lines: str) -> str:
    return "\n".join(lines)


def test_a_guard_whose_local_was_only_renumbered_is_marked() -> None:
    """A's ``uVar9`` is B's ``uVar13`` (the block match substitutes one for the other on four
    lines). ``if (uVar13 == 0x74)`` falls in a structural block, so the rule introduces it; under
    the renaming A holds it as often, so it is marked ``renumbered_in_a`` {``a_name``: ``uVar9``}
    and counted — and still given, with every count as the rule has it."""
    a = _lines("uVar9 = get();", "use(uVar9);", "keep(uVar9);", "start();")
    a += _lines("", "if (uVar9 == 0x74) {", "  one();", "}", "end();")
    b = _lines("uVar13 = get();", "use(uVar13);", "keep(uVar13);", "start();", "extra(1);")
    b += _lines("", "if (uVar13 == 0x74) {", "  two(2);", "}", "end();")
    scan = _scan(a, b)
    assert _marks(scan) == [("uVar13", 6, {"a_name": "uVar9"})]
    assert scan.get("renumbered_in_a") == 1
    assert scan["var_const_total"] == 1


def test_a_renaming_seen_once_marks_nothing() -> None:
    """The only ``uVar9`` -> ``uVar13`` substitution is the comparison's own: one sighting is no
    renaming, so the guard is not marked and the scan has no count.

    MUTATION (verified RED, 1 failed): keep the pairs seen once -> marked -> RED."""
    a = _lines("start();", "if (uVar9 == 0x74) {", "  one();", "}", "end();")
    b = _lines("start();", "if (uVar13 == 0x74) {", "  two(2);", "}", "end();")
    scan = _scan(a, b)
    assert _marks(scan) == [("uVar13", 2, None)]
    assert "renumbered_in_a" not in scan


def test_a_negated_and_renumbered_comparison_is_not_marked() -> None:
    """A's ``if (local_48 != 0)`` is B's ``if (local_44 == 0)``: the renaming holds (three
    substitutions), but renamed, A's comparison is ``local_44 != 0`` — not B's. Not marked: the
    mark matches the comparison as written, not what it tests."""
    a = _lines("local_48 = get();", "use(local_48);", "keep(local_48);", "start();")
    a += _lines("", "if (local_48 != 0) {", "  one();", "}", "end();")
    b = _lines("local_44 = get();", "use(local_44);", "keep(local_44);", "start();")
    b += _lines("", "if (local_44 == 0) {", "  two(2);", "}", "end();")
    la, *_rest = sm._delta_lines(a, None, False)
    lb, *_rest = sm._delta_lines(b, None, False)
    blocks = sm._delta_blocks(la, lb)
    assert blocks is not None and sm._renumbering(blocks) == {"local_48": "local_44"}
    assert _marks(_scan(a, b)) == [("local_44", 5, None)]


def test_a_copied_comparison_marks_only_the_one_the_a_block_holds() -> None:
    """A holds ``uVar9 == 0x74`` once; B holds ``uVar13 == 0x74`` in the same block and once more in
    a copy further down. Both are introduced; renamed, the A block takes back the first — so the
    first is marked and the copy is not.

    MUTATION (verified RED, 1 failed): rename in the whole-function count only, not in the
    block subtraction -> the copy is marked instead -> RED."""
    a = _lines("uVar9 = get();", "use(uVar9);", "keep(uVar9);", "start();")
    a += _lines("", "if (uVar9 == 0x74) {", "  one();", "}", "mid();", "end();")
    b = _lines("uVar13 = get();", "use(uVar13);", "keep(uVar13);", "start();")
    b += _lines("", "if (uVar13 == 0x74) {", "  two(2);", "}", "mid();")
    b += _lines("", "if (uVar13 == 0x74) {", "  copied();", "}", "end();")
    scan = _scan(a, b)
    assert _marks(scan) == [("uVar13", 5, {"a_name": "uVar9"}), ("uVar13", 9, None)]
    assert scan.get("renumbered_in_a") == 1


def test_a_local_renamed_to_two_names_is_no_renaming() -> None:
    """``uVar9`` is substituted by ``uVar13`` on some lines and by ``uVar14`` on others (each pair
    seen three times): it maps to no one name, so neither comparison is marked.

    MUTATION (verified RED, 1 failed): drop the one-to-one check -> one of them is marked ->
    RED."""
    a = _lines("uVar9 = get();", "use(uVar9);", "put(uVar9);", "keep(uVar9);", "start();")
    a += _lines("", "if (uVar9 == 0x74) {", "  one();", "}")
    a += _lines("", "if (uVar9 == 0x75) {", "  three();", "}", "end();")
    b = _lines("uVar13 = get();", "use(uVar13);", "put(uVar14);", "keep(uVar14);", "start();")
    b += _lines("", "if (uVar13 == 0x74) {", "  two(2);", "}")
    b += _lines("", "if (uVar14 == 0x75) {", "  four(4);", "}", "end();")
    scan = _scan(a, b)
    assert [m[2] for m in _marks(scan)] == [None, None]
    assert "renumbered_in_a" not in scan


def test_renaming_never_adds_a_guard() -> None:
    """A's own ``uVar13`` (B's ``uVar14``) is compared ``== 1``, and so is B's ``uVar13`` (A's
    ``uVar9``) — a coincidence of names that the rule reads as an unchanged comparison. Renamed, B's
    ``uVar13 == 1`` would be introduced; it is NOT added: the guards and every count are the
    rule's, the renaming only marks.

    MUTATION (verified RED, 1 failed): add the guards only the renamed rule introduces ->
    ``uVar13 == 1`` appears, var_const_total 2 -> RED."""
    a = _lines("uVar9 = get();", "use(uVar9);", "uVar13 = other();", "keep(uVar13);", "start();")
    a += _lines("", "if (uVar13 == 1) {", "  one();", "}", "end();")
    b = _lines("uVar13 = get();", "use(uVar13);", "uVar14 = other();", "keep(uVar14);")
    b += _lines("", "start();", "if ((uVar13 == 1) && (flag != 0)) {", "  two(2);", "}", "end();")
    scan = _scan(a, b)
    assert _marks(scan) == [("flag", 6, None)]
    assert scan["var_const_total"] == 1
    assert scan["by_const_class"] == {"zero": 1, "nonzero": 0}


def test_the_b_names_are_the_identifiers_of_the_b_text() -> None:
    """``b_names`` (never output; a guard link reads it) holds every identifier of the original B
    text — not a word inside a string or a comment, not the digits of a number, not a keyword —
    and only a scan with a guard carries it."""
    b = (
        "void f(char *param_1) {\n  /* old copy */\n  if (param_1 == 0) return;\n"
        '  system("killall worker");\n  memcpy(d, (char *)s, 0x800);\n}'
    )
    names = _scan("foo();", b)["b_names"]
    assert {"f", "param_1", "system", "memcpy", "d", "s", "char", "void"} <= names
    assert not {"killall", "worker", "old", "copy", "x800", "return", "if"} & names
    assert "b_names" not in _scan("foo();", "bar();")


def test_the_identifier_reader_reads_the_tokenisers_identifiers() -> None:
    """The fast reader behind ``b_names`` gives exactly the identifier tokens of the tokeniser, on
    text that mixes every token kind (a multi-line comment, a string with an escaped quote, a char
    literal, hex and decimal numbers with suffixes, a number running into a name, a blanked
    address name).

    MUTATION (verified RED, 2 failed — this test and the b_names one): leave numbers out of the
    reader's skipped tokens -> the tail of ``0x800`` reads as a name -> RED."""
    text = (
        "void f(char *p) {\n/* a word\nacross lines */ int n = 0x800U + 12uL;\n"
        's = "say \\"hi\\" now"; c = \'q\'; x1y = 3abc; DAT_@ = p->next; // tail words\n'
        "if (n <= 0x1fgh) return; }"
    )
    want = {t for k, t, _s in sm._tokens_at(text) if k == "ident"}
    got = {name for name in sm._IDENTIFIERS.findall(text) if name}
    assert got == want
    assert {"x800", "hi", "tail", "word", "q"}.isdisjoint(got)


def test_a_cast_added_on_the_variable_is_another_comparison() -> None:
    """G2c: ``uVar3 < 0x20`` becoming ``(int)uVar3 < 0x20`` in one structural block is a guard, and
    ``cast`` shows the difference is the variable's cast.

    MUTATION M20 (verified RED, 1 failed): drop the variable's cast from the key -> the two
    compare equal -> no guard -> RED."""
    scan = _scan("a();\nif (uVar3 < 0x20) {", "b();\nif ((int)uVar3 < 0x20) {")
    assert _guard_tuples(scan) == [("uVar3", "<", "0x20", "(int)", "nonzero")]


def test_a_null_constant_retyped_is_the_same_comparison() -> None:
    """G2d: ``p == (byte *)0x0`` becoming ``p == (char *)0x0`` (the decompiler retyped the null
    constant) in a structural block — the block also holds a changed call — is no guard.

    MUTATION M22 (verified RED, 1 failed): keep the constant's cast in the key -> a guard -> RED."""
    scan = _scan("if (p == (byte *)0x0) {\na();", "if (p == (char *)0x0) {\nb(1, 2);")
    assert scan["state"] == "done"
    assert scan["guards"] == []


def test_a_cast_null_constant_is_zero() -> None:
    """G3: ``pcVar2 == (char *)0x0`` gives const ``0x0`` (its cast set aside), const_class zero.

    MUTATION M9 (verified RED, 1 failed): read the class from the constant with its cast ->
    nonzero -> RED."""
    assert _guard_tuples(_scan("foo();", "if (pcVar2 == (char *)0x0) bar();")) == [
        ("pcVar2", "==", "0x0", None, "zero")
    ]


def test_a_moved_address_is_no_new_comparison_and_the_name_is_shown_as_written() -> None:
    """G4: in one structural block, ``DAT_00412a0 == 0`` (A) and ``DAT_00413b0 == 0`` (B) are the
    same comparison once the address is normalised; the new ``DAT_00413c4 > 5`` is shown by the
    name the original B text writes.

    MUTATION M4 (verified RED, 1 failed): key the comparisons on the original tokens -> the
    moved one is a guard -> RED. MUTATION M5 (verified RED, 1 failed): show the normalised
    tokens -> ``DAT_@`` -> RED."""
    a = "if (DAT_00412a0 == 0) {"
    b = "if ((DAT_00413b0 == 0) && (flag != 0)) {\nif (DAT_00413c4 > 5) {"
    guards = _guard_tuples(_scan(a, b))
    assert guards == [("flag", "!=", "0", None, "zero"), ("DAT_00413c4", ">", "5", None, "nonzero")]


def test_a_threshold_changed_in_a_substitution_block_is_not_a_guard() -> None:
    """G5: ``len > 0x100`` -> ``len > 0x40`` alone is a substitution-only change (the hunk's
    substitution groups show it): the scan is done and holds no guard.

    MUTATION M6 (verified RED, 1 failed): read substitution-only blocks too -> RED."""
    scan = _scan("if (len > 0x100) {\nfoo();", "if (len > 0x40) {\nfoo();")
    assert scan == {
        "state": "done",
        "var_const_total": 0,
        "by_const_class": {"zero": 0, "nonzero": 0},
        "other_comparisons": {"var_var": 0, "call": 0, "field": 0, "other": 0},
        "guards": [],
    }


def test_an_incomplete_operand_is_no_guard_and_is_counted_by_kind() -> None:
    """G6: an operand that is not one variable or one constant (after one cast) is no guard:
    ``iVar11 + 1 < (int)param_2``, ``*p != 0`` and ``x < 0x10 + y`` are counted as other; two
    variables are var_var, a call call, a member read field.

    MUTATION M12 (verified RED, 1 failed): take only the token next to the operator as the
    operand -> ``*p != 0`` and ``x < 0x10 + y`` read as guards -> RED."""
    b = "\n".join(
        [
            "if (iVar11 + 1 < (int)param_2) {",
            "if (*p != 0) {",
            "if (x < 0x10 + y) {",
            "if (a < b) {",
            "if (f(x) < 3) {",
            "if (s->n > 4) {",
        ]
    )
    scan = _scan("foo();", b)
    assert scan["guards"] == []
    assert scan["other_comparisons"] == {"var_var": 1, "call": 1, "field": 1, "other": 3}


def test_a_moved_comparison_is_not_introduced() -> None:
    """G7: the same ``if (n > 0x40)`` deleted near the top and inserted far below falls in two
    blocks, so each block alone would call it new; across the whole function B holds it no more
    often than A, so it is not a guard. With two in B against one in A, exactly one is.

    MUTATION M13 (verified RED, 1 failed): drop the whole-function count -> the moved one is a
    guard -> RED."""
    filler = [f"step_{c}();" for c in "abcdefgh"]
    a = "\n".join(["start();", "if (n > 0x40) {", *filler, "end();"])
    b = "\n".join(["start();", *filler, "if (n > 0x40) {", "end();"])
    assert _scan(a, b)["guards"] == []
    twice = "\n".join(["start();", *filler, "if (n > 0x40) {", "x();", "if (n > 0x40) {", "end();"])
    assert _guard_tuples(_scan(a, twice)) == [("n", ">", "0x40", None, "nonzero")]


def test_past_the_store_limit_the_guards_are_counted_not_kept() -> None:
    """G8 (scan side): more introduced guards than GUARD_STORE_LIMIT keeps the first ones in B
    order; var_const_total and by_const_class count all of them."""
    n = sm.GUARD_STORE_LIMIT + 7
    b = "\n".join(f"if (v{i} > {i + 1}) {{" for i in range(n))
    scan = _scan("foo();", b)
    assert scan["var_const_total"] == n
    assert scan["by_const_class"] == {"zero": 0, "nonzero": n}
    assert len(scan["guards"]) == sm.GUARD_STORE_LIMIT
    assert [g["var"] for g in scan["guards"][:3]] == ["v0", "v1", "v2"]


def _count_blocks(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    calls: list[int] = []
    real = sm._delta_blocks

    def counting(la: list[str], lb: list[str]) -> object:
        calls.append(1)
        return real(la, lb)

    monkeypatch.setattr(sm, "_delta_blocks", counting)
    return calls


def test_a_too_large_body_reads_its_matched_middle_and_says_when_none_was_matched(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """G9: on the line-cap path the changed middle's ONE block match serves the hunk and the scan,
    whose line_b is mapped back past the set-aside head; when the middle is over the cap too the
    scan is not_extracted (too_large) with no guards key. On the token-cap path the scan is
    not_extracted after the one match that hit the cap — nothing is re-matched.

    MUTATION (verified RED, 1 failed): forget the head offset in the scan -> wrong line_b -> RED;
    re-match the middle for the scan -> _delta_blocks called twice -> RED."""
    lines = [f"x{i} = {i};" for i in range(10)]
    a = "\n".join(lines)
    b = "\n".join(lines[:6] + ["if (x6 > 0x60) {", "}"] + lines[6:])
    monkeypatch.setattr(sm, "DELTA_LINE_PRODUCT_CAP", 99)
    calls = _count_blocks(monkeypatch)
    delta, scan = sm.pseudocode_delta_and_guards(a, b, None, None, "1000", "2000")
    assert delta["kind"] == "not_computed"
    assert calls == [1]
    assert scan["state"] == "done"
    assert [(g["var"], g["line_b"]) for g in scan["guards"]] == [("x6", 7)]
    monkeypatch.setattr(sm, "DELTA_LINE_PRODUCT_CAP", 1)
    calls.clear()
    b_over = "\n".join(lines[:6] + ["if (x6 > 0x60) {", "x6 = 61;"] + lines[7:])
    _delta, over = sm.pseudocode_delta_and_guards(a, b_over, None, None, "1000", "2000")
    assert over == {"state": "not_extracted", "reason": "too_large"}
    assert calls == []  # the middle (1 x 2 lines) is over the cap: never matched
    monkeypatch.setattr(sm, "DELTA_LINE_PRODUCT_CAP", 10_000)
    monkeypatch.setattr(sm, "DELTA_TOKEN_PRODUCT_CAP", 4)
    calls.clear()
    _delta, token_cap = sm.pseudocode_delta_and_guards(a, b_over, None, None, "1000", "2000")
    assert token_cap == {"state": "not_extracted", "reason": "too_large"}
    assert "guards" not in token_cap
    assert calls == [1]


def test_a_hunk_withheld_by_the_gate_does_not_withhold_the_scan() -> None:
    """G9 (gate): a change over INLINE_HUNK_GATE withholds the hunk; the blocks were matched, so
    the scan is read as usual."""
    many = [f"call_{i}(x);" for i in range(sm.INLINE_HUNK_GATE + 5)]
    b = "\n".join(["if (len >= 0x200) {", *many, "}"])
    delta, scan = sm.pseudocode_delta_and_guards("foo();", b, None, None, "1000", "2000")
    assert delta["inline_hunk"]["withheld"] == "over_gate"
    assert _guard_tuples(scan) == [("len", ">=", "0x200", None, "nonzero")]


def test_the_delta_is_the_same_whichever_entry_point_reads_it() -> None:
    """G10 / I2: pseudocode_delta is the first half of pseudocode_delta_and_guards, byte for byte,
    and carries no guard key and no block position.

    MUTATION M11 (verified RED, 3 failed): put the scan into the delta's return -> RED here, in
    the S4 contract test and in the view's cached-delta check."""
    import json

    for name, (a, b, fa, fb, na, nb) in _DELTA_CASES.items():
        delta = sm.pseudocode_delta(a, b, None, None, fa, fb, na, nb)
        both = sm.pseudocode_delta_and_guards(a, b, None, None, fa, fb, na, nb)
        assert json.dumps(delta) == json.dumps(both[0]), name
        assert not {"guards", "guard_scan", "state", "var_const_total"} & set(delta), name
