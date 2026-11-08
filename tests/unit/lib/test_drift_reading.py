# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The drift reading (lib/query/drift_reading): whether an aligned similarity-1 pair's two
pseudocode texts differ only by shifted line numbers or addresses — a navigation fact that moves
nothing. Zero real data: ImageReaders built in memory, and the World of test_patch_view end to
end."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import pytest

from tests.unit.lib.test_patch_view import DIFF, World, _ref
from treasure_map import mcp_app
from treasure_map.lib.query import drift_reading as dr
from treasure_map.lib.query import patch_view as pv
from treasure_map.lib.query import sameness
from treasure_map.lib.storage.connection import open_db

_DELTA = {"kind": "substitution_only", "calls": {}}


@pytest.fixture(autouse=True)
def _current(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every diff reads as current (its stamps are not under test here), and the view caches are
    cleared between worlds (they key on one shared diff_id)."""
    pv._clear_view_caches()
    monkeypatch.setattr(
        pv,
        "diff_source_staleness",
        lambda atlas, diff_id: {
            "source_stale": False,
            "source_stale_reason": None,
            "toolchain_checked": True,
        },
    )


def _reader(blocks: list[tuple[int, int, bytes, bool]] | None = None, **kw: Any) -> dr.ImageReader:
    """An ImageReader over ``blocks`` (default: one initialized block at 0x1000)."""
    if blocks is None:
        blocks = [(0x1000, 0x1000, bytes(0x1000), True)]
    return dr.ImageReader(blocks=blocks, little_endian=True, ok=True, **kw)


def _body(line: str) -> str:
    return "void foo(void)\n{\n  " + line + "\n}\n"


def _read(
    ta: str,
    tb: str,
    *,
    ra: dr.ImageReader | None = None,
    rb: dr.ImageReader | None = None,
    aligned: frozenset[tuple[str, str]] = frozenset(),
    callee_state: str | None = "equal",
    sizes: tuple[int | None, int | None] = (100, 100),
    delta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return dr.drift_reading(
        ta,
        tb,
        delta or _DELTA,
        ra or _reader(),
        rb or _reader(),
        aligned,
        "foo",
        "foo",
        callee_state,
        sizes[0],
        sizes[1],
    )


def test_a_line_number_argument_shift_reads_drift_only() -> None:
    """A number right after the same source-path / own-name / identifier string argument on both
    sides is a line number: the pair reads ``drift_only``.

    MUTATION (verified RED, 1 failed): drop L_str_path/own/ident from the explained rules -> the
    site is unexplained -> not_drift_only -> RED."""
    got = _read(_body('log("foo.c",10);'), _body('log("foo.c",12);'))
    assert got["state"] == dr.DRIFT_ONLY
    assert got["sites"] == {"line": 1, "address": 0}


def test_a_real_constant_change_is_not_drift_only() -> None:
    """A changed number that is NOT a line-number / address site keeps the pair must-read
    (fail-closed, site by site).

    MUTATION (verified RED, 1 failed): make _explained accept C_num -> drift_only -> RED."""
    got = _read(_body("buf[10] = 0;"), _body("buf[20] = 0;"))
    assert got["state"] == dr.NOT_DRIFT_ONLY and "C_num" in got["why"]


def test_a_bare_address_to_the_same_string_is_an_address_shift() -> None:
    """Two different bare numbers that each point at the START of the SAME C string in the image
    are an address shift; pointing at DIFFERENT strings is a constant change, not drift.

    MUTATION (verified RED, 1 failed): read any two string heads as A_strptr whatever their text
    (the string-head guard's ``sa == sb`` -> True) -> the different-string pair reads drift_only
    -> RED."""
    a = bytearray(0x1000)
    a[0x100 : 0x100 + 6] = b"same\x00\x00"
    a[0x200 : 0x200 + 6] = b"same\x00\x00"  # same text at a different address
    a[0x300 : 0x300 + 6] = b"diff\x00\x00"
    reader = _reader([(0x1000, 0x1000, bytes(a), True)])
    # 0x1100 and 0x1200 both start "same" -> address shift
    same = _read(_body("p = 0x1100;"), _body("p = 0x1200;"), ra=reader, rb=reader)
    assert same["state"] == dr.DRIFT_ONLY and same["sites"]["address"] == 1
    # 0x1100 ("same") vs 0x1300 ("diff") -> constant change
    diff = _read(_body("p = 0x1100;"), _body("p = 0x1300;"), ra=reader, rb=reader)
    assert diff["state"] == dr.NOT_DRIFT_ONLY


def _got_reader() -> tuple[dr.ImageReader, int, int]:
    """A reader over a MIPS-like GOT of 8 local pointer slots at 0x2000, each holding 0x9999 (the
    same target), with the two gp-relative offsets that reach slots 0 and 1."""
    got = b"".join(struct.pack("<I", 0x9999) for _ in range(8))
    gp = 0x2000 + 0x7FF0
    reader = _reader(
        [(0x2000, len(got), got, True)],
        pltgot=0x2000,
        gp=gp,
        local_gotno=8,
        gotsym=0,
        symtab=0,
    )
    return reader, 0x2000 - gp, 0x2004 - gp  # an offset is slot_va - gp (negative on MIPS)


def test_a_base_relative_offset_is_explained_only_when_the_base_is_proven_gp() -> None:
    """A base+offset whose base is a frame pointer / parameter / local is NOT explained (its two
    offsets could reach anything), even when those offsets WOULD resolve as gp-relative: only a
    base the text names as the global pointer is read as a GOT address shift.

    MUTATION (verified RED, 1 failed): drop the gp-name requirement in classify_site (resolve every
    base+offset through the GOT) -> the parameter-base pair resolves to the same target -> RED."""
    reader, off0, off1 = _got_reader()
    # same offsets that resolve gp-relative to one target, but the base is a parameter, not gp
    nongp = _read(
        _body(f"x = *(int *)(param_1 - {-off0:#x});"),
        _body(f"x = *(int *)(param_1 - {-off1:#x});"),
        ra=reader,
        rb=reader,
    )
    assert nongp["state"] == dr.NOT_DRIFT_ONLY and "U_baseoff" in nongp["why"]
    # a gp base whose GOT info is missing stays unexplained (fail closed)
    gp_unresolved = _read(_body("x = *(int *)(gp + 0x10);"), _body("x = *(int *)(gp + 0x14);"))
    assert gp_unresolved["state"] == dr.NOT_DRIFT_ONLY


def test_a_gp_relative_offset_to_the_same_got_target_is_an_address_shift() -> None:
    """With the dynamic info present, a gp-named base whose two offsets resolve to the same local
    GOT pointer is an address shift (A_got).

    MUTATION (verified RED, 1 failed): make got_target ignore the local/global split (return the
    slot address itself) -> the two offsets give different 'targets' -> not_drift_only -> RED."""
    reader, off0, off1 = _got_reader()
    ta = _body(f"x = *(int *)(gp - {-off0:#x});")
    tb = _body(f"x = *(int *)(gp - {-off1:#x});")
    got_read = _read(ta, tb, ra=reader, rb=reader)
    assert got_read["state"] == dr.DRIFT_ONLY and got_read["sites"]["address"] == 1
    assert reader.got_target(off0) == reader.got_target(off1) == ("ptr", 0x9999)


def test_cstring_at_reads_only_a_string_head_not_a_tail() -> None:
    """``cstring_at`` returns a string only at its START (the previous byte NUL or the block start),
    so a bare address pointing into the MIDDLE of a string is not read as a string pointer.

    MUTATION (verified RED, 1 failed): drop the previous-byte-NUL head check -> a mid-string
    address returns the tail -> RED."""
    buf = bytearray(0x400)
    buf[0x100 : 0x100 + 8] = b"abcdef\x00\x00"
    reader = _reader([(0x1000, 0x400, bytes(buf), True)])
    assert reader.cstring_at(0x1100) == b"abcdef"  # the head
    assert reader.cstring_at(0x1102) is None  # mid-string: not a head


def test_the_callee_set_and_size_gate_keeps_an_otherwise_drift_only_pair() -> None:
    """Even when every site is an explained shift, the pair is not drift-only unless its callee set
    is proven equal and both body sizes are recorded equal — the text cannot see a call added in a
    block the decompiler dropped as dead.

    MUTATION (verified RED, 1 failed each): drop the callee_state gate -> the undetermined-callee
    pair reads drift_only -> RED; drop the size gate -> the unequal-size pair reads drift_only."""
    a, b = _body('log("foo.c",10);'), _body('log("foo.c",12);')
    assert _read(a, b, callee_state="undetermined")["state"] == dr.NOT_DRIFT_ONLY
    assert _read(a, b, callee_state="differs")["state"] == dr.NOT_DRIFT_ONLY
    assert _read(a, b, sizes=(100, 104))["state"] == dr.NOT_DRIFT_ONLY
    assert _read(a, b, sizes=(None, None))["state"] == dr.NOT_DRIFT_ONLY


def test_a_changed_call_count_or_structural_delta_is_not_drift_only() -> None:
    """A call count difference, or a non-substitution delta, is never drift.

    MUTATION (verified RED, 1 failed): ignore delta['calls'] -> a call-count change reads
    drift_only -> RED."""
    a, b = _body('log("foo.c",10);'), _body('log("foo.c",12);')
    calls = {"kind": "substitution_only", "calls": {"system": {"a": 0, "b": 1}}}
    assert _read(a, b, delta=calls)["state"] == dr.NOT_DRIFT_ONLY
    assert _read(a, b, delta={"kind": "structural"})["state"] == dr.NOT_DRIFT_ONLY


def test_an_unreadable_input_reads_undetermined_not_no_change() -> None:
    """A side whose image or delta could not be read is ``undetermined``, never drift or "no
    change".

    MUTATION (verified RED, 1 failed): treat a not-computed delta as substitution_only -> it is
    read site by site and may come out drift_only/not -> RED on the undetermined assertion."""
    a, b = _body('log("foo.c",10);'), _body('log("foo.c",12);')
    bad = dr.ImageReader(blocks=[], little_endian=True, ok=False)
    assert _read(a, b, ra=bad)["state"] == dr.UNDETERMINED
    assert _read(a, b, delta={"kind": "not_computed", "reason": "too_large"})["state"] == (
        dr.UNDETERMINED
    )


def test_the_reading_never_calls_the_r_bucket_line_number_form(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The S-bucket drift path is independent of sameness._line_number_form (the R bucket's
    reading): it never calls it, so neither changes the other.

    MUTATION (verified RED, 1 failed): make drift_reading call sameness._line_number_form -> the
    patched raise below breaks it -> RED."""

    def boom(*_a: Any, **_k: Any) -> None:
        raise AssertionError("drift_reading must not call _line_number_form")

    monkeypatch.setattr(sameness, "_line_number_form", boom)
    got = _read(_body('log("foo.c",10);'), _body('log("foo.c",12);'))
    assert got["state"] == dr.DRIFT_ONLY


def _drift_world(tmp: Path, a_line: str, b_line: str, *, callees: list[str] | None = None) -> World:
    w = World(tmp)
    w.pair("00001000", "00002000", 0.97, 1.0, name_a="foo", name_b="foo")
    cs = callees if callees is not None else ["log"]
    w.fn("a", "00001000", cs, name="foo", pseudocode=_body(a_line), size_bytes=100)
    w.fn("b", "00002000", cs, name="foo", pseudocode=_body(b_line), size_bytes=100)
    w.block("a", "0x1000", 0x1000)
    w.block("b", "0x1000", 0x1000)
    w.commit()
    return w


def test_a_bucket_s_entry_carries_the_drift_fact_end_to_end(tmp_path: Path) -> None:
    """Through get_diff_patch_view: a bucket S entry (aligned, similarity 1, pseudocode differs)
    carries ``drift``; a line-number shift reads drift_only, a constant change does not.

    MUTATION (verified RED, 1 failed): never attach page_drift in _render -> no drift field ->
    RED."""
    w = _drift_world(tmp_path, 'log("foo.c",10);', 'log("foo.c",12);')
    page = mcp_app.make_tools(w.path)["get_diff_patch_view"](DIFF, bucket="S")
    (entry,) = page["entries"]
    assert entry.get("drift", {}).get("state") == dr.DRIFT_ONLY
    # it stays listed (must-read), the fact moves nothing
    assert entry["pseudocode_sameness"] == sameness.DIFFERS

    w2 = _drift_world(tmp_path / "two", "buf[10] = 0;", "buf[20] = 0;")
    page2 = mcp_app.make_tools(w2.path)["get_diff_patch_view"](DIFF, bucket="S")
    (entry2,) = page2["entries"]
    assert entry2.get("drift", {}).get("state") == dr.NOT_DRIFT_ONLY


def test_the_drift_fact_survives_the_summary_projection(tmp_path: Path) -> None:
    """detail='summary' keeps ``drift`` (a compact fact).

    MUTATION (verified RED, 1 failed): drop 'drift' from _SUMMARY_COPY -> the summary loses it ->
    RED."""
    w = _drift_world(tmp_path, 'log("foo.c",10);', 'log("foo.c",12);')
    page = mcp_app.make_tools(w.path)["get_diff_patch_view"](DIFF, bucket="S", detail="summary")
    (entry,) = page["entries"]
    assert entry.get("drift", {}).get("state") == dr.DRIFT_ONLY


def _lines_body(*lines: str) -> str:
    return "void foo(void)\n{\n" + "".join(f"  {ln}\n" for ln in lines) + "}\n"


# ── line-number sites: strong / weak evidence, one step ──────────────────────────────────────


def test_an_identifier_string_argument_without_format_evidence_is_not_a_line_number() -> None:
    """A number after an identifier-shaped string with no format string on its line or the line
    before is a WEAK line-number site; with no strong site in the pair it is a constant change.

    MUTATION (verified RED, 1 failed): make _line_site_strong return True -> the length argument
    reads as a line number -> drift_only -> RED."""
    cmp = _read(_body('iVar1 = strncmp(s,"word",5);'), _body('iVar1 = strncmp(s,"word",6);'))
    assert cmp["state"] == dr.NOT_DRIFT_ONLY and "no strong line site" in cmp["why"]
    cpy = _read(_body('strncpy(d,"abcd",0x10);'), _body('strncpy(d,"abcd",0x20);'))
    assert cpy["state"] == dr.NOT_DRIFT_ONLY


def test_a_format_string_with_a_name_and_a_number_makes_the_site_strong() -> None:
    """``log("%s:%d","fn",10)`` -> 12: the format string (``%s`` then ``%d``) on the site's line on
    both sides makes the identifier-string site strong, so the pair reads drift_only; a format
    string on the line before counts too when the call continues from it onto the site's line.

    MUTATION (verified RED, 1 failed): make line_format.name_line_format return False -> the
    site is weak with no strong one -> not_drift_only -> RED."""
    got = _read(_body('log("%s:%d","fn",10);'), _body('log("%s:%d","fn",12);'))
    assert got.get("state") == dr.DRIFT_ONLY and got.get("sites") == {"line": 1, "address": 0}
    before = _read(
        _lines_body('log("%s line %d",', '    "fn",10);'),
        _lines_body('log("%s line %d",', '    "fn",12);'),
    )
    assert before.get("state") == dr.DRIFT_ONLY


def test_a_weak_site_beside_a_strong_one_with_the_same_step_is_explained() -> None:
    """A weak identifier-string site counts as a line number when the same pair also has a strong
    site, and both shift by the same step.

    MUTATION (verified RED, 1 failed): require every line site to be strong (``not strong`` ->
    ``strong < counts['line']``) -> not_drift_only -> RED."""
    got = _read(
        _lines_body('log("foo.c",10);', 'trace("fn",20);'),
        _lines_body('log("foo.c",12);', 'trace("fn",22);'),
    )
    assert got.get("state") == dr.DRIFT_ONLY and got.get("sites") == {"line": 2, "address": 0}


def test_line_number_sites_must_share_one_non_zero_step() -> None:
    """Two strong line-number sites that shift by different steps, or a site whose two spellings
    are the same value, are not a plain line shift (fail closed).

    MUTATION (verified RED, 1 failed each): drop ``len(steps) != 1`` -> the two-step pair reads
    drift_only -> RED; drop ``0 in steps`` -> the zero-step pair reads drift_only -> RED."""
    two = _read(
        _lines_body('log("foo.c",10);', 'log("foo.c",20);'),
        _lines_body('log("foo.c",12);', 'log("foo.c",23);'),
    )
    assert two["state"] == dr.NOT_DRIFT_ONLY and "one step" in two["why"]
    zero = _read(_body('log("foo.c",10);'), _body('log("foo.c",0xa);'))
    assert zero["state"] == dr.NOT_DRIFT_ONLY and "one step" in zero["why"]


def test_a_format_of_a_finished_statement_before_the_site_is_no_evidence() -> None:
    """A finished log call on the line before (``log_msg("%s:%d","fn_x",0x2a);``) says nothing
    about the next line's ``check_len(p,"admin",5)`` -> ``6``: the length stays a weak site, alone
    a constant change. The same for a format assigned to a variable on the line before.

    MUTATION (verified RED, 1 failed): drop the continuation test in line_format.format_evidence
    (``statement_continues(prev) and`` removed) -> both read drift_only -> RED."""
    after_log = _read(
        _lines_body('log_msg("%s:%d","fn_x",0x2a);', 'check_len(p,"admin",5);'),
        _lines_body('log_msg("%s:%d","fn_x",0x2a);', 'check_len(p,"admin",6);'),
    )
    assert after_log["state"] == dr.NOT_DRIFT_ONLY and "no strong line site" in after_log["why"]
    after_fmt = _read(
        _lines_body('fmt = "%s line %d";', 'log(fmt,"fn",10);'),
        _lines_body('fmt = "%s line %d";', 'log(fmt,"fn",12);'),
    )
    assert after_fmt["state"] == dr.NOT_DRIFT_ONLY and "no strong line site" in after_fmt["why"]


def test_a_format_without_a_string_conversion_is_no_evidence() -> None:
    """``log("%d bytes %d","fn",10)`` -> ``12``: the literal has two number conversions and no
    ``%…s`` one (the ``s`` of ``bytes`` is a letter), so it is no name-then-line format and the
    site stays weak — not drift_only.

    MUTATION (verified RED, 1 failed): any ``%`` is evidence (``return "%" in literal`` at the top
    of line_format.name_line_format) -> drift_only -> RED; the old loose pattern (``_CONVERSION``
    -> ``%(?:%|[^"%]*([A-Za-z]))``) -> drift_only -> RED."""
    got = _read(_body('log("%d bytes %d","fn",10);'), _body('log("%d bytes %d","fn",12);'))
    assert got["state"] == dr.NOT_DRIFT_ONLY and "no strong line site" in got["why"]


def test_a_lone_line_number_variable_is_never_a_strong_site() -> None:
    """``uVar1 = 10;`` passed as ``log("foo.c",uVar1)`` -> ``12`` with no other line-number site:
    the variable site is weak (its evidence sits on another line), so the pair has no strong site
    and reads not drift_only — named as such, not as a plain constant.

    MUTATION (verified RED, 1 failed): L_var strong (``if rule == "L_var": return False`` ->
    ``return True`` in _line_site_strong) -> drift_only -> RED."""
    got = _read(
        _lines_body("uVar1 = 10;", 'log("foo.c",uVar1);'),
        _lines_body("uVar1 = 12;", 'log("foo.c",uVar1);'),
    )
    assert got["state"] == dr.NOT_DRIFT_ONLY
    assert "no strong line site" in got["why"], got


def test_an_assigned_number_never_passed_after_a_name_is_a_constant() -> None:
    """``uVar1 = 0x40;`` used as ``memcpy(d,s,uVar1)`` -> ``0x42``, beside a strong line-number
    site of the same step (``log("foo.c",10)`` -> ``12``): the variable is never passed after a
    name or path string, so its number is a constant change — not drift_only, at that site.

    MUTATION (verified RED, 1 failed): drop the use test of L_var (the two
    ``_passed_after_name`` conditions removed) -> the assignment reads L_var beside the strong
    site -> drift_only -> RED."""
    got = _read(
        _lines_body("uVar1 = 0x40;", "memcpy(d,s,uVar1);", 'log("foo.c",10);'),
        _lines_body("uVar1 = 0x42;", "memcpy(d,s,uVar1);", 'log("foo.c",12);'),
    )
    assert got["state"] == dr.NOT_DRIFT_ONLY
    assert got["why"] == "unexplained site: C_num", got


def _str_image(*texts: tuple[int, bytes], ptrs: tuple[tuple[int, int], ...] = ()) -> bytes:
    """A 0x1000-byte initialized image (to be placed at 0x1000) with NUL-terminated ``texts`` at
    their offsets and little-endian 32-bit ``ptrs`` (offset, value)."""
    buf = bytearray(0x1000)
    for off, text in texts:
        buf[off : off + len(text) + 1] = text + b"\x00"
    for off, value in ptrs:
        buf[off : off + 4] = struct.pack("<I", value)
    return bytes(buf)


def test_a_pointer_argument_is_strong_only_when_it_points_at_a_path_or_the_own_name() -> None:
    """A number after a pointer to a source-path string (or the own name) is a strong line site; a
    pointer to another identifier string is weak (no strong site -> not_drift_only).

    MUTATION (verified RED, 1 failed): make L_ptr always strong in _line_site_strong -> the
    identifier pointer reads drift_only -> RED."""
    img = _str_image((0x100, b"src/foo.c"), (0x200, b"other_name"), (0x300, b"foo"))
    r = _reader([(0x1000, 0x1000, img, True)])
    path = _read(
        _body("log(s_src_foo_c_00001100,10);"), _body("log(s_src_foo_c_00001100,12);"), ra=r, rb=r
    )
    assert path.get("state") == dr.DRIFT_ONLY and path.get("sites") == {"line": 1, "address": 0}
    ident = _read(
        _body("log(s_other_name_00001200,10);"),
        _body("log(s_other_name_00001200,12);"),
        ra=r,
        rb=r,
    )
    assert ident["state"] == dr.NOT_DRIFT_ONLY and "no strong line site" in ident["why"]


def test_a_number_that_is_a_string_head_is_read_as_a_pointer_before_a_line_number() -> None:
    """``log("foo",0x1100)`` vs ``log("foo",0x1300)``: both numbers start a C string in the image.
    Different texts -> a constant change, even though the argument before is the own name; a head
    on one side only -> undecidable (not_drift_only); the same text -> an address shift.

    MUTATION (verified RED, 1 failed): drop the string-head guard at the top of _num_site -> the
    site reads L_str_own -> drift_only -> RED."""
    img = _str_image((0x100, b"same"), (0x200, b"same"), (0x300, b"diff"))
    r = _reader([(0x1000, 0x1000, img, True)])
    differ = _read(_body('log("foo",0x1100);'), _body('log("foo",0x1300);'), ra=r, rb=r)
    assert differ["state"] == dr.NOT_DRIFT_ONLY and "C_num" in differ["why"]
    one_side = _read(_body('log("foo",0x1100);'), _body('log("foo",0x1500);'), ra=r, rb=r)
    assert one_side["state"] == dr.NOT_DRIFT_ONLY and "C_num" in one_side["why"]
    same = _read(_body('log("foo",0x1100);'), _body('log("foo",0x1200);'), ra=r, rb=r)
    assert same.get("state") == dr.DRIFT_ONLY and same.get("sites") == {"line": 0, "address": 1}


def test_a_line_number_through_a_variable_is_read_on_the_sites_own_line() -> None:
    """``uVar1 = 10;`` passed as ``log("foo.c",uVar1)`` is a (weak) line-number site when the
    site's own line is that assignment; beside a strong site with the same step the pair reads
    drift_only.

    MUTATION (verified RED, 1 failed): never return L_var in _num_site -> C_num -> RED."""
    got = _read(
        _lines_body("uVar1 = 10;", 'log("foo.c",uVar1);', 'log("foo.c",20);'),
        _lines_body("uVar1 = 12;", 'log("foo.c",uVar1);', 'log("foo.c",22);'),
    )
    assert got.get("state") == dr.DRIFT_ONLY and got.get("sites") == {"line": 2, "address": 0}


def test_a_line_number_variable_does_not_explain_another_constant_in_the_function() -> None:
    """A function that has a line-number variable does not explain an unrelated changed constant on
    another line (``memcpy(d,s,0x40)`` -> ``0x80``): that site's own line is no assignment.

    MUTATION (verified RED, 1 failed): read L_var function-wide (the first ``<var> = <num> ;``
    line of side a stands for the site's line on both sides) -> drift_only -> RED."""
    both = _read(
        _lines_body("uVar1 = 10;", 'log("foo.c",uVar1);', 'log("foo.c",20);', "memcpy(d,s,0x40);"),
        _lines_body("uVar1 = 12;", 'log("foo.c",uVar1);', 'log("foo.c",22);', "memcpy(d,s,0x80);"),
    )
    assert both["state"] == dr.NOT_DRIFT_ONLY and "C_num" in both["why"]
    only = _read(
        _lines_body("uVar1 = 10;", 'log("foo.c",uVar1);', 'log("foo.c",20);', "memcpy(d,s,0x40);"),
        _lines_body("uVar1 = 10;", 'log("foo.c",uVar1);', 'log("foo.c",20);', "memcpy(d,s,0x80);"),
    )
    assert only["state"] == dr.NOT_DRIFT_ONLY and "C_num" in only["why"]


def test_a_number_in_a_decompiler_comment_line_is_an_address_shift() -> None:
    """A number on a line that starts a ``/*`` comment on both sides is an address shift
    (A_comment); the same number change on a code line is not.

    MUTATION (verified RED, 1 failed): restore the old check ``ra[k - 1 : k] == ["/*"]`` (the
    tokenizer splits ``/*`` into two tokens) -> the comment number reads as C_num -> RED."""
    got = _read(
        _lines_body("/* WARNING: jump at 0x00003234 */", "x = 1;"),
        _lines_body("/* WARNING: jump at 0x00003238 */", "x = 1;"),
    )
    assert got.get("state") == dr.DRIFT_ONLY and got.get("sites") == {"line": 0, "address": 1}
    code = _read(_body("x = 0x00003234 / 4;"), _body("x = 0x00003238 / 4;"))
    assert code["state"] == dr.NOT_DRIFT_ONLY


def _dynamic_db(tmp: Path) -> str:
    """A temp analysis.db with one little-endian MIPS-like binary: a ``.got`` of 8 local slots at
    0x2000 (each 0x9999), listed AFTER a ``.dynamic`` block at 0x3000 that names it."""
    db = tmp / "analysis.db"
    conn = open_db(db)
    conn.execute(
        "INSERT INTO binaries (name, sha256, arch) VALUES ('libx', ?, 'MIPS:LE:32:default')",
        ("c" * 64,),
    )
    got = b"".join(struct.pack("<I", 0x9999) for _ in range(8))
    tags = [(3, 0x2000), (0x7000000A, 8), (0x70000013, 0), (6, 0), (5, 0), (0, 0)]
    dyn = b"".join(struct.pack("<II", t, v) for t, v in tags)
    for name, start, data in ((".dynamic", "0x3000", dyn), (".got", "0x2000", got)):
        conn.execute(
            "INSERT INTO data_blocks (binary_id, block_name, start_addr, size, bytes, initialized) "
            "VALUES (1, ?, ?, ?, ?, 1)",
            (name, start, len(data), data),
        )
    conn.commit()
    conn.close()
    return str(db)


def test_read_image_finds_the_dynamic_block_by_its_name(tmp_path: Path) -> None:
    """read_image picks the ``.dynamic`` block by ``block_name``, so a MIPS image yields its global
    pointer and a gp-relative pair to the same GOT target reads A_got end to end.

    MUTATION (verified RED, 1 failed): match ``.dynamic`` against the start-address column (the
    old column order: ``name == ".dynamic"`` -> ``_s == ".dynamic"``) -> gp None -> RED."""
    reader = dr.read_image(_dynamic_db(tmp_path), "c" * 64)
    assert reader.ok and reader.gp == 0x2000 + 0x7FF0
    assert reader.pltgot == 0x2000 and reader.local_gotno == 8
    gp = 0x2000 + 0x7FF0
    got = _read(
        _body(f"x = *(int *)(gp - {gp - 0x2000:#x});"),
        _body(f"x = *(int *)(gp - {gp - 0x2004:#x});"),
        ra=reader,
        rb=reader,
    )
    assert got.get("state") == dr.DRIFT_ONLY and got.get("sites") == {"line": 0, "address": 1}


def test_a_fun_label_pair_is_a_shift_only_when_the_pair_is_aligned() -> None:
    """``FUN_a`` -> ``FUN_b`` is an address shift only when (a, b) is an aligned pair of the diff.

    MUTATION (verified RED, 1 failed): accept any FUN pair as A_fun (audit M4) -> the unaligned
    pair reads drift_only -> RED."""
    ta, tb = _body("FUN_00401000(p);"), _body("FUN_00402000(p);")
    yes = _read(ta, tb, aligned=frozenset({("00401000", "00402000")}))
    assert yes.get("state") == dr.DRIFT_ONLY and yes.get("sites") == {"line": 0, "address": 1}
    no = _read(ta, tb, aligned=frozenset({("00401000", "00403000")}))
    assert no["state"] == dr.NOT_DRIFT_ONLY and "U_fun" in no["why"]


def test_a_string_label_pair_is_a_shift_only_when_its_text_is_the_same() -> None:
    """``s_hello_A`` -> ``s_hello_B`` is an address shift; ``s_hello_A`` -> ``s_world_B`` is not.

    MUTATION (verified RED, 1 failed): accept any string-label pair (audit M5) -> RED."""
    yes = _read(_body("puts(s_hello_00401000);"), _body("puts(s_hello_00402000);"))
    assert yes.get("state") == dr.DRIFT_ONLY and yes.get("sites") == {"line": 0, "address": 1}
    no = _read(_body("puts(s_hello_00401000);"), _body("puts(s_world_00402000);"))
    assert no["state"] == dr.NOT_DRIFT_ONLY and "C_strlabel" in no["why"]


def test_a_string_label_of_one_text_over_two_different_strings_is_a_changed_string() -> None:
    """``s_hello_00001100`` -> ``s_hello_00001200``: the label texts are the same (the decompiler
    shortens a string to its label), but the two images hold ``hello world`` and ``hello there``
    at the labels — a changed string, not an address shift; so is a string head on one side only
    (side B's label lands mid-string). The same string at both labels is a shift.

    MUTATION (verified RED, 1 failed): read the label by its text alone (``_strlabel_site``
    returns A_strlabel whenever the texts match) -> drift_only -> RED. MUTATION (verified RED, 1
    failed): compare the strings only when both heads read (``sa == sb`` -> ``sa is None or sb
    is None or sa == sb``) -> the one-sided pair reads drift_only -> RED."""
    ra = _reader([(0x1000, 0x1000, _str_image((0x100, b"hello world")), True)])
    rb = _reader([(0x1000, 0x1000, _str_image((0x200, b"hello there")), True)])
    rb_same = _reader([(0x1000, 0x1000, _str_image((0x200, b"hello world")), True)])
    rb_mid = _reader([(0x1000, 0x1000, _str_image((0x1FA, b"hello world")), True)])
    ta, tb = _body("puts(s_hello_00001100);"), _body("puts(s_hello_00001200);")
    differ = _read(ta, tb, ra=ra, rb=rb)
    assert differ["state"] == dr.NOT_DRIFT_ONLY and "C_strlabel" in differ["why"], differ
    one_side = _read(ta, tb, ra=ra, rb=rb_mid)
    assert rb_mid.cstring_at(0x1200) is None  # the precondition: no head at B's label
    assert one_side["state"] == dr.NOT_DRIFT_ONLY and "C_strlabel" in one_side["why"], one_side
    same = _read(ta, tb, ra=ra, rb=rb_same)
    assert same.get("state") == dr.DRIFT_ONLY and same.get("sites") == {"line": 0, "address": 1}


def test_a_dat_label_pair_is_a_shift_only_when_its_bytes_are_the_same() -> None:
    """``DAT_a`` -> ``DAT_b`` is an address shift when both point at the same 16 non-zero bytes;
    different bytes, or all-zero bytes, are not explained.

    MUTATION (verified RED, 1 failed each): accept any DAT pair (audit M2) -> the different-bytes
    pair reads drift_only -> RED; drop the all-zero test in content_at -> the zero pair reads
    drift_only -> RED."""
    buf = bytearray(0x1000)
    buf[0x100:0x110] = bytes(range(1, 17))
    buf[0x200:0x210] = bytes(range(1, 17))
    buf[0x300:0x310] = bytes(range(2, 18))
    r = _reader([(0x1000, 0x1000, bytes(buf), True)])
    yes = _read(_body("x = DAT_00001100;"), _body("x = DAT_00001200;"), ra=r, rb=r)
    assert yes.get("state") == dr.DRIFT_ONLY and yes.get("sites") == {"line": 0, "address": 1}
    no = _read(_body("x = DAT_00001100;"), _body("x = DAT_00001300;"), ra=r, rb=r)
    assert no["state"] == dr.NOT_DRIFT_ONLY and "U_dat" in no["why"]
    zero = _read(_body("x = DAT_00001500;"), _body("x = DAT_00001600;"), ra=r, rb=r)
    assert zero["state"] == dr.NOT_DRIFT_ONLY and "U_dat" in zero["why"]


def test_a_ptr_label_pair_is_a_shift_only_when_both_slots_point_at_the_same_content() -> None:
    """``PTR_DAT_a`` -> ``PTR_DAT_b`` is an address shift when the two slots hold pointers to the
    same string; pointers to different strings are not explained.

    MUTATION (verified RED, 1 failed): accept any PTR pair (audit M6) -> RED."""
    img = _str_image(
        (0x100, b"alpha"),
        (0x200, b"alpha"),
        (0x300, b"bravo"),
        ptrs=((0x800, 0x1100), (0x804, 0x1200), (0x808, 0x1300)),
    )
    r = _reader([(0x1000, 0x1000, img, True)])
    yes = _read(_body("p = PTR_DAT_00001800;"), _body("p = PTR_DAT_00001804;"), ra=r, rb=r)
    assert yes.get("state") == dr.DRIFT_ONLY and yes.get("sites") == {"line": 0, "address": 1}
    no = _read(_body("p = PTR_DAT_00001800;"), _body("p = PTR_DAT_00001808;"), ra=r, rb=r)
    assert no["state"] == dr.NOT_DRIFT_ONLY and "U_ptr" in no["why"]


def test_an_added_line_is_never_drift_only() -> None:
    """A line added on one side is not a shift, even when every other site is one.

    MUTATION (verified RED, 1 failed): skip an added/removed-line opcode instead of returning
    (``return`` -> ``continue``) -> the remaining line shift reads drift_only -> RED. The audit's
    M3 (let insert/delete opcodes through) is RED too (the strict zip raises)."""
    got = _read(
        _lines_body('log("foo.c",10);', "x = 1;"),
        _lines_body('log("foo.c",12);', "x = 1;", "y = 2;"),
    )
    assert got["state"] == dr.NOT_DRIFT_ONLY and "added or removed" in got["why"]


def test_an_all_zero_image_address_is_not_an_address_shift() -> None:
    """``memset(p,0,0x1100)`` -> ``0x1200`` over an all-zero initialized block: the two numbers
    point at bytes that tell nothing apart, so the site is not explained.

    MUTATION (verified RED, 1 failed): drop the all-zero test in content_at -> A_imgaddr ->
    drift_only -> RED."""
    got = _read(_body("memset(p,0,0x1100);"), _body("memset(p,0,0x1200);"))
    assert got["state"] == dr.NOT_DRIFT_ONLY and "C_num" in got["why"]


def test_an_entry_with_candidate_rows_carries_no_drift_fact(tmp_path: Path) -> None:
    """A bucket B entry (it has candidate rows) whose texts differ only by a line shift carries no
    ``drift`` key, on the default page and on bucket='B'; only bucket S entries get the fact. The
    same pair without candidate rows (bucket S) carries it — the text is drift-only.

    MUTATION (verified RED, 1 failed): drop ``e.shown_bucket == "S"`` from _page_drift's want ->
    the B entry carries drift -> RED."""
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.97, 1.0, name_a="foo", name_b="foo")
    a, b = _body('log("foo.c",10);'), _body('log("foo.c",12);')
    w.fn("a", "00001000", ["log"], name="foo", pseudocode=a, size_bytes=100)
    w.fn("b", "00002000", ["log"], name="foo", pseudocode=b, size_bytes=100)
    w.block("a", "0x1000", 0x1000)
    w.block("b", "0x1000", 0x1000)
    w.inst("a", _ref("runA", "00001000", "cmd", "0x10"), "cmd", "system")
    w.inst("b", _ref("runB", "00002000", "cmd", "0x10"), "cmd", "system")
    w.commit()
    tool = mcp_app.make_tools(w.path)["get_diff_patch_view"]
    entries = tool(DIFF)["entries"] + tool(DIFF, bucket="B")["entries"]
    mine = [e for e in entries if e["entry_id"] == "pair:00001000:00002000"]
    assert len(mine) == 2 and all(e["bucket"] == "B" for e in mine)
    assert all("drift" not in e for e in mine)
    s = _drift_world(tmp_path / "s", 'log("foo.c",10);', 'log("foo.c",12);')
    (entry,) = mcp_app.make_tools(s.path)["get_diff_patch_view"](DIFF, bucket="S")["entries"]
    assert entry.get("drift", {}).get("state") == dr.DRIFT_ONLY
