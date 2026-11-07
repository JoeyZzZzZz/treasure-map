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

from tests.unit.lib.test_patch_view import DIFF, World
from treasure_map import mcp_app
from treasure_map.lib.query import drift_reading as dr
from treasure_map.lib.query import patch_view as pv
from treasure_map.lib.query import sameness

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

    MUTATION (verified RED, 1 failed each): classify any two image addresses as A_imgaddr whatever
    their content -> the different-string pair reads drift_only -> RED; drop the previous-byte-NUL
    check in cstring_at -> a mid-string address reads as a string head."""
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
