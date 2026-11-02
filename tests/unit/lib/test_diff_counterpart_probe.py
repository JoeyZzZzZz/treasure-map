# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Layer-0: the counterpart probe of an unmatched function (W3) and the import-stub accounting (W4).

A presence row says only "this function is in no matched pair". The probe maps the function to the
other side through the nearest pair at or below it and reads what is there: a function that is
itself in no pair makes the row ``counterpart_suspected`` (a pairing the diff tool may have
missed); code the other side's extraction left outside every function, or a side whose leftover
code is not known, or no pair to map by, makes it ``unmatched_analysis_incomplete``; a PAIRED
function there (the spot a deleted function's successors move up into) leaves it determined.

The import stubs of a binary are paired by the import each one calls (binaries.stub_names) and
kept out of the function pairs and the presence rows, when both sides' tables are resolved.

Synthetic analysis.dbs + a tiny crafted .BinDiff; no firmware data. Mutations verified red (each
restored afterwards), recorded per test.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.writer import begin_run
from treasure_map.lib.binary_id import resolve_binary_in_db
from treasure_map.lib.diff.export_report import ExportReport
from treasure_map.lib.diff.layer0 import (
    COUNTERPART_SUSPECTED,
    BaselineDomain,
    probe_counterparts,
    run_layer0_parse,
)
from treasure_map.lib.query.diff_align import _GenerationCache, _partial_blindspots, get_diff_meta
from treasure_map.lib.storage.connection import open_db

_NO_RESIDUAL = "[]"  # the extraction left no instruction outside a function (known, complete)


def _analysis(
    path: Path,
    sha: str,
    funcs: list[tuple[int, str, int, list[tuple[int, int]] | None]],
    *,
    residual: str | None = _NO_RESIDUAL,
    truncated: int | None = 0,
    stubs: dict[int, str] | None = None,
) -> Path:
    """One binary 'lib.so'; funcs = (entry, name, size, body ranges or None)."""
    con = open_db(path)
    con.execute(
        "INSERT INTO binaries (id, name, path, sha256, last_seen_at, stub_names, "
        "promote_residual_ranges, promote_residual_ranges_truncated) "
        "VALUES (1, 'lib.so', 'lib.so', ?, '2026-01-01T00:00:00', ?, ?, ?)",
        (
            sha,
            json.dumps({f"{k:x}": v for k, v in stubs.items()}) if stubs is not None else None,
            residual,
            truncated,
        ),
    )
    for entry, name, size, ranges in funcs:
        con.execute(
            "INSERT INTO functions (binary_id, name, address, pseudocode, size_bytes, body_ranges) "
            "VALUES (1, ?, ?, 'int f(){}', ?, ?)",
            (
                name,
                f"0x{entry:x}",
                size,
                json.dumps([[f"0x{lo:x}", f"0x{hi:x}"] for lo, hi in ranges]) if ranges else "[]",
            ),
        )
    con.commit()
    con.close()
    return path


def _bindiff(path: Path, pairs: list[tuple[int, str, int, str]]) -> Path:
    con = sqlite3.connect(path)
    con.execute(
        "CREATE TABLE function (id INTEGER PRIMARY KEY, address1 BIGINT, name1 TEXT, "
        "address2 BIGINT, name2 TEXT, similarity DOUBLE, confidence DOUBLE, "
        "basicblocks INTEGER, edges INTEGER, instructions INTEGER)"
    )
    con.executemany(
        "INSERT INTO function (address1,name1,address2,name2,similarity,confidence,"
        "basicblocks,edges,instructions) VALUES (?,?,?,?,1.0,0.97,3,2,20)",
        pairs,
    )
    con.execute("CREATE TABLE file (id INT, filename TEXT, hash CHARACTER(40))")
    con.executemany(
        "INSERT INTO file (id, filename, hash) VALUES (?, ?, ?)",
        [(1, "before", "sha_a"), (2, "after", "sha_b")],
    )
    con.commit()
    con.close()
    return path


def _diff(
    tmp_path: Path,
    funcs_a: list[tuple[int, str, int, list[tuple[int, int]] | None]],
    funcs_b: list[tuple[int, str, int, list[tuple[int, int]] | None]],
    pairs: list[tuple[int, str, int, str]],
    **kw: Any,
) -> tuple[sqlite3.Connection, str]:
    side_kw = {s: {k[2:]: v for k, v in kw.items() if k.startswith(f"{s}_")} for s in "ab"}
    dba = _analysis(tmp_path / "a.db", "sha_a", funcs_a, **side_kw["a"])
    dbb = _analysis(tmp_path / "b.db", "sha_b", funcs_b, **side_kw["b"])
    con = open_atlas(tmp_path / "atlas.db")
    begin_run(con, "run_a", analysis_db_path=str(dba), tool_version="0.0.1")
    begin_run(con, "run_b", analysis_db_path=str(dbb), tool_version="0.0.1")
    bin_a, _ = resolve_binary_in_db(str(dba), "lib.so")
    bin_b, _ = resolve_binary_in_db(str(dbb), "lib.so")
    assert bin_a is not None and bin_b is not None
    r = run_layer0_parse(
        con,
        bindiff_path=_bindiff(tmp_path / "t.BinDiff", pairs),
        run_a_id="run_a",
        run_b_id="run_b",
        bin_a=bin_a,
        bin_b=bin_b,
        report_a=kw.get("report_a"),
        report_b=kw.get("report_b"),
    )
    return con, r.diff_id


def _presence(con: sqlite3.Connection, diff_id: str) -> dict[tuple[str, str], dict[str, Any]]:
    con.row_factory = sqlite3.Row
    try:
        return {
            (r["side"], r["addr"]): dict(r)
            for r in con.execute("SELECT * FROM function_presence WHERE diff_id = ?", (diff_id,))
        }
    finally:
        con.row_factory = None


# A: keep 0x1000 <-> B 0x1100 (shift +0x100) is the anchor; 0x7000 <-> 0x7400 (+0x400) a second
# one higher up. Each unmatched A function below lands its mapped address on a different case.
_A = [
    (0x1000, "keep", 0x40, None),
    (0x2000, "f_unpaired", 0x30, None),  # -> 0x2100: an unpaired B function there
    (0x3000, "f_occupied", 0x30, None),  # -> 0x3100: a PAIRED B function there
    (0x4000, "f_residual", 0x30, None),  # -> 0x4100: no function; leftover code at 0x4110
    (0x5000, "f_uncovered", 0x30, None),  # -> 0x5100: nothing, leftover code elsewhere
    (0x6000, "f_body", 0x30, None),  # -> 0x6100: inside an unpaired B function's body
    (0x0800, "f_low", 0x30, None),  # below every pair: unmappable
    (0x7000, "far", 0x40, None),
    (0x7800, "f_far", 0x30, None),  # nearest anchor below is 0x7000 (+0x400) -> 0x7c00
    (0x9000, "pp_a", 0x40, None),
]
_B = [
    (0x1100, "keep", 0x40, None),
    (0x2100, "b_unpaired", 0x30, None),
    (0x3100, "pp_b", 0x40, None),
    (0x60F0, "b_body", 0x40, [(0x60F0, 0x612F)]),
    (0x7400, "far", 0x40, None),
    (0x7900, "pp_b2", 0x40, None),  # where the FIRST anchor (+0x100) would map f_far: paired
    (0x7C00, "b_far", 0x30, None),  # where the nearest anchor below maps it: unpaired
    (0x9500, "pp_c", 0x40, None),
]
_PAIRS = [
    (0x1000, "keep", 0x1100, "keep"),
    (0x7000, "far", 0x7400, "far"),
    (0x9000, "pp_a", 0x3100, "pp_b"),
    (0x9100, "x_a", 0x7900, "pp_b2"),  # 0x9100 is not in A's inventory: an anchor only
]
_RESIDUAL_B = json.dumps([["0x4110", "0x4113"], ["0x8000", "0x8003"]])


def test_each_probe_outcome_lands_its_state(tmp_path: Path) -> None:
    """The six outcomes of the probe table, end to end through run_layer0_parse.

    Mutations (verified red): every found function read unpaired (``kind = PROBE_UNPAIRED``)
    -> f_occupied reads suspected; the residual check dropped (no F -> uncovered) -> f_residual
    reads complete; the probe not applied (``_probed_state`` returns the state as given) ->
    f_unpaired reads complete."""
    con, did = _diff(tmp_path, _A, _B, _PAIRS, b_residual=_RESIDUAL_B)
    p = _presence(con, did)
    a = {k[1]: v for k, v in p.items() if k[0] == "a"}
    assert "00002000" in a and "00003000" in a and "00004000" in a
    got = {
        addr: (r["presence_state"], r["presence_reason"], r["counterpart_probe"])
        for addr, r in a.items()
    }
    assert got["00002000"] == (
        COUNTERPART_SUSPECTED,
        "counterpart_unpaired_at_mapped_address",
        "unpaired",
    )
    assert a["00002000"]["counterpart_addr"] == "00002100"
    assert got["00003000"] == ("unmatched_analysis_complete", None, "occupied")
    assert a["00003000"]["counterpart_addr"] == "00003100"
    assert got["00004000"] == (
        "unmatched_analysis_incomplete",
        "other_side_code_outside_functions",
        "residual_code",
    )
    assert json.loads(a["00004000"]["counterpart_overlap"]) == [["0x4110", "0x4113"]]
    assert got["00005000"] == ("unmatched_analysis_complete", None, "uncovered")
    assert got["00000800"] == (
        "unmatched_analysis_incomplete",
        "counterpart_unmappable",
        "unmappable",
    )
    con.close()


def test_a_mapped_address_inside_a_function_body_finds_that_function(tmp_path: Path) -> None:
    """y = 0x6100 is no entry, but lies in b_body's body range [0x60f0, 0x612f].

    Mutation: ``_Coverage.owner`` reads entries only -> f_body reads residual-free ``uncovered``
    (complete), red here."""
    con, did = _diff(tmp_path, _A, _B, _PAIRS, b_residual=_RESIDUAL_B)
    row = _presence(con, did).get(("a", "00006000"))
    assert row is not None
    assert (row["presence_state"], row["counterpart_addr"]) == (
        COUNTERPART_SUSPECTED,
        "000060f0",
    )
    con.close()


def test_the_anchor_is_the_nearest_pair_at_or_below(tmp_path: Path) -> None:
    """f_far (0x7800) maps by 0x7000->0x7400 to 0x7c00 (unpaired b_far): suspected. The first pair
    (+0x100) would map it to 0x7900, a paired function (occupied); the nearest pair ABOVE is
    0x9000->0x3100, which maps it far below everything.

    Mutations (verified red): anchor = the lowest pair (``min(0, ...)``) -> occupied; anchor = the
    nearest pair above (``bisect_right(...)`` without ``- 1``, clamped) -> nothing there."""
    con, did = _diff(tmp_path, _A, _B, _PAIRS, b_residual=_RESIDUAL_B)
    row = _presence(con, did).get(("a", "00007800"))
    assert row is not None
    assert (row["presence_state"], row["counterpart_probe"], row["counterpart_addr"]) == (
        COUNTERPART_SUSPECTED,
        "unpaired",
        "00007c00",
    )
    con.close()


def test_unknown_or_truncated_leftover_code_leaves_existence_undetermined(tmp_path: Path) -> None:
    """No function at the mapped address, and the other side's leftover code is NULL (an
    extraction that did not record it) or truncated (a prefix cannot show a range absent):
    ``other_side_coverage_unknown``, never determined.

    Mutation (verified red): truncated read as known (``load_baseline`` ignores
    ``promote_residual_ranges_truncated``) -> the truncated case reads uncovered/complete."""
    for i, (res, trunc) in enumerate(((None, None), ("[]", 1))):
        con, did = _diff(tmp_path / str(i), _A, _B, _PAIRS, b_residual=res, b_truncated=trunc)
        row = _presence(con, did).get(("a", "00005000"))
        assert row is not None
        assert (row["presence_state"], row["presence_reason"], row["counterpart_probe"]) == (
            "unmatched_analysis_incomplete",
            "other_side_coverage_unknown",
            "coverage_unknown",
        ), (res, trunc)
        con.close()


def test_a_gap_row_keeps_its_state_and_still_carries_the_probe(tmp_path: Path) -> None:
    """A row the export gap already made incomplete is not moved by the probe (not even to
    suspected), and still says what the other side holds where it maps."""
    report = ExportReport(
        builder="fallback",
        entry_addresses_added=0,
        flow_graphs_dropped=0,
        dropped_functions=frozenset(),
        degenerate_functions=frozenset({"00002000"}),
    )
    con, did = _diff(tmp_path, _A, _B, _PAIRS, b_residual=_RESIDUAL_B, report_a=report)
    row = _presence(con, did).get(("a", "00002000"))
    assert row is not None
    assert (row["presence_state"], row["presence_reason"], row["counterpart_probe"]) == (
        "unmatched_analysis_incomplete",
        None,
        "unpaired",
    )
    assert row["export_gap"] == "degenerate_block"
    con.close()


def test_every_unmatched_row_is_probed_and_none_complete_sits_on_an_unpaired_function(
    tmp_path: Path,
) -> None:
    """Both sides: every presence row carries a probe, and no row that found an unpaired function
    at its mapped address reads determined (the A7 invariant)."""
    con, did = _diff(tmp_path, _A, _B, _PAIRS, b_residual=_RESIDUAL_B)
    rows = list(_presence(con, did).values())
    assert {r["side"] for r in rows} == {"a", "b"}
    assert all(r["counterpart_probe"] is not None for r in rows)
    assert not [
        r
        for r in rows
        if r["counterpart_probe"] == "unpaired"
        and r["presence_state"] == "unmatched_analysis_complete"
    ]
    con.close()


def test_probe_counterparts_directly() -> None:
    """The pure probe: size sets the mapped span the leftover ranges are checked against.

    Mutation: the span taken as the mapped address alone (``hi = y``) -> the overlap at y+0x20 is
    missed, red."""
    own = BaselineDomain(functions={"00002000": ("f", "ok")}, sizes={"00002000": 0x30})
    other = BaselineDomain(functions={}, residual_ranges=((0x2120, 0x2123),))
    got = probe_counterparts(
        frozenset({"00002000"}), own, other, [("00001000", "00001100")], frozenset()
    )
    assert got["00002000"].probe == "residual_code"
    assert got["00002000"].overlap == ((0x2120, 0x2123),)


# ── W4: import stubs ────────────────────────────────────────────────────────────────────────

_STUB_A = {0x400: "strcpy", 0x410: "system", 0x420: "only_a"}
_STUB_B = {0x400: "strcpy", 0x410: "system", 0x430: "only_b"}
_SA = [
    (0x400, "strcpy", 0x10, None),
    (0x410, "system", 0x10, None),
    (0x420, "only_a", 0x10, None),
    (0x1000, "keep", 0x40, None),
    (0x2000, "gone", 0x40, None),
]
_SB = [
    (0x400, "strcpy", 0x10, None),
    (0x410, "system", 0x10, None),
    (0x430, "only_b", 0x10, None),
    (0x1000, "keep", 0x40, None),
    (0x2200, "elsewhere", 0x40, None),
]
_SPAIRS = [
    (0x400, "strcpy", 0x400, "strcpy"),
    (0x410, "system", 0x430, "only_b"),
    (0x1000, "keep", 0x1000, "keep"),
    (0x2000, "gone", 0x420 + 0x10000, "x"),  # unpaired partner outside B's inventory
    (0x420, "only_a", 0x2200, "elsewhere"),  # a stub paired with a function that is not one
]


def _stub_report(*entries: str) -> ExportReport:
    return ExportReport(
        builder="fallback",
        entry_addresses_added=0,
        flow_graphs_dropped=0,
        dropped_functions=frozenset(),
        degenerate_functions=frozenset(entries),
    )


def test_stubs_are_paired_by_import_name_and_kept_out_of_pairs_and_presence(
    tmp_path: Path,
) -> None:
    """Both tables resolved: no alignment row and no presence row touches a stub; the ledger pairs
    by import name (strcpy, system), lists the one-sided names, and keeps the stub<->function pair
    as a mismatch fact, its non-stub partner then unmatched (and probed).

    Mutation: the stubs not taken out (``split_stub_pairs`` returns the parse as given) -> the
    stub rows (and their R entries) come back, red."""
    con, did = _diff(
        tmp_path,
        _SA,
        _SB,
        _SPAIRS,
        a_stubs=_STUB_A,
        b_stubs=_STUB_B,
        report_a=_stub_report("00000400", "00002000"),
        report_b=_stub_report("00000400"),
    )
    stub_addrs = {"00000400", "00000410", "00000420", "00000430"}
    align = con.execute(
        "SELECT addr_a, addr_b FROM function_alignment WHERE diff_id = ?", (did,)
    ).fetchall()
    assert align  # the non-stub pairs are still there
    assert not [r for r in align if r[0] in stub_addrs or r[1] in stub_addrs]
    pres = _presence(con, did)
    assert not [k for k in pres if k[1] in stub_addrs]
    assert ("b", "00002200") in pres  # the stub's non-stub partner is now unmatched, and probed
    assert pres[("b", "00002200")]["counterpart_probe"] is not None
    meta = get_diff_meta(con, did)["import_stubs"]
    assert meta is not None
    assert (meta["table_a"], meta["table_b"], meta["pairs"]) == ("resolved", "resolved", 2)
    assert (meta["a_only"], meta["b_only"]) == (["only_a"], ["only_b"])
    assert meta["pair_mismatch"] == [["00000420", "00002200"]]
    assert meta["export_gaps_on_stubs"] == {"a": 1, "b": 1}
    assert meta["export_gaps_on_code"] == {"a": 1, "b": 0}
    con.close()


def test_a_diff_with_only_stub_gaps_is_not_a_partial_blind_spot(tmp_path: Path) -> None:
    """list_diff_blindspots' partial list reads the gaps outside the stubs only.

    Mutation: the WHERE back on every gap (dropped + degenerate) -> this diff is listed, red."""
    con, did = _diff(
        tmp_path,
        _SA,
        _SB,
        _SPAIRS[:3],
        a_stubs=_STUB_A,
        b_stubs=_STUB_B,
        report_a=_stub_report("00000400"),
        report_b=_stub_report("00000400"),
    )
    listed = [r["diff_id"] for r in _partial_blindspots(con, _GenerationCache(con), None, None)]
    assert did not in listed
    con.close()


def test_an_unresolved_stub_table_leaves_the_stubs_to_the_pairing(tmp_path: Path) -> None:
    """One side's table NULL (not determined): nothing is taken out, the stubs stay pairs as
    BinDiff made them, the ledger says which table is unknown and counts nothing, and every gap
    counts as a code gap.

    Mutation (verified red): the ledger enabled on one resolved table (``and`` for ``or``, the
    unknown table read as empty) -> the stub pairs are dropped."""
    con, did = _diff(
        tmp_path,
        _SA,
        _SB,
        _SPAIRS[:3],
        a_stubs=_STUB_A,
        b_stubs=None,
        report_a=_stub_report("00000400"),
    )
    align = {
        r[0] for r in con.execute("SELECT addr_a FROM function_alignment WHERE diff_id=?", (did,))
    }
    assert "00000400" in align
    meta = get_diff_meta(con, did)["import_stubs"]
    assert meta is not None
    assert (meta["table_a"], meta["table_b"], meta["pairs"], meta["a_only"]) == (
        "resolved",
        "unknown",
        None,
        None,
    )
    assert meta["export_gaps_on_stubs"]["a"] is None
    assert meta["export_gaps_on_code"]["a"] == 1
    con.close()
