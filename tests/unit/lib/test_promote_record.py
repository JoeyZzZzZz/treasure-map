# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""What the function-promotion pass did, as a recorded fact: each function's ``origin``, and per
binary the functions created and the instructions still in no function after it (by kind, and as
address ranges). Carried from the extractor's JSON into analysis.db, rolled up onto the atlas run
row, and summarised by the scan.

★ The honesty rule throughout: a record that is absent (an export predating it, a pass that left
none) or does not hold together is NULL — "not recorded" — and never reads as 0 / "nothing left
outside a function" / "analysis".

Zero real data: hand-written extractor output and hand-built databases. The Ghidra behaviour itself
(the instruction walk finding what the block iterator skips) is guarded by the live rescan anchors,
not here; the two script-text tests below pin the parts of it a reader can check statically.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from treasure_map.lib.analyze import ghidra_ingest
from treasure_map.lib.analyze.elf_inventory import ElfRecord
from treasure_map.lib.analyze.ghidra_ingest import drop_extraction, ingest_ghidra_output
from treasure_map.lib.analyze.pipeline import promote_summary
from treasure_map.lib.atlas import begin_run, finish_run, open_atlas
from treasure_map.lib.facts import analysis_run_counts, promote_residual_counts
from treasure_map.lib.query import get_run, list_runs
from treasure_map.lib.storage.connection import open_db

_GHIDRA_DIR = Path(ghidra_ingest.__file__).parent / "ghidra"
_SCHEMA = Path(ghidra_ingest.__file__).parents[1] / "storage" / "schema.sql"
_ATLAS_SCHEMA = Path(ghidra_ingest.__file__).parents[1] / "storage" / "atlas_schema.sql"
_PROMOTE_COLS = (
    "promote_created",
    "promote_residual_insns",
    "promote_residual_start",
    "promote_residual_interior",
    "promote_residual_unowned",
    "promote_residual_ranges",
    "promote_residual_ranges_truncated",
    "promote_undefined_ranges",
    "promote_undefined_ranges_truncated",
    "promote_undefined_bytes",
    "promote_recovered",
    "promote_recover_rejected",
    "promote_recover_seeds",
    "promote_recover_lost_bytes",
    "promote_recover_noreturn_flips",
)

_PROMOTE = {
    "tried": 5,
    "created": 4,
    "residual_insns": 9,
    "residual_start": 2,
    "residual_interior": 6,
    "residual_unowned": 1,
    "residual_ranges": [["0x400100", "0x40010b"], ["0x400200", "0x400213"]],
    "residual_ranges_truncated": False,
    # W11: executable bytes never disassembled. W14: pointer-reached recovery + its two 0 guards.
    "undefined_ranges": [["0x400300", "0x40031f"]],
    "undefined_ranges_truncated": False,
    "undefined_bytes": 32,
    "recovered": 3,
    "recover_rejected": 1,
    "recover_seeds": 7,
    "recover_lost_insn_bytes": 0,
    "recover_noreturn_flips": 0,
}


def _ingest(
    tmp_path: Path, funcs: list[dict[str, Any]], extra: dict[str, Any] | None = None
) -> sqlite3.Connection:
    """One binary 'x' ingested from a hand-written extractor JSON; returns the open analysis.db."""
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    rec = ElfRecord(path=tmp_path / "x", name="x", arch="a", elf_type="executable", sha256="a" * 64)
    data = {"functions": funcs, "imports": [], "exports": [], "strings": [], **(extra or {})}
    (out / f"x_{rec.sha256[:8]}_ghidra.json").write_text(json.dumps(data))
    conn = open_db(tmp_path / "analysis.db")
    if conn.execute("SELECT 1 FROM binaries WHERE id = 1").fetchone() is None:
        conn.execute("INSERT INTO binaries (id, name, sha256) VALUES (1, 'x', ?)", (rec.sha256,))
    ingest_ghidra_output(conn, out, [rec], {rec.sha256: 1})
    return conn


def _fn(name: str, addr: str, **kw: Any) -> dict[str, Any]:
    return {"name": name, "address": addr, "size": 64, "callees": [], **kw}


def _promote_row(conn: sqlite3.Connection) -> dict[str, Any]:
    row = conn.execute(f"SELECT {', '.join(_PROMOTE_COLS)} FROM binaries WHERE id = 1").fetchone()
    return dict(zip(_PROMOTE_COLS, tuple(row), strict=True))


# ── ingest: origin + the promote record ─────────────────────────────────────────────────────


def test_origin_and_the_promote_record_are_stored(tmp_path: Path) -> None:
    """★ Each function's origin and the binary's promote record land as the extractor wrote them;
    residual_ranges keeps its [["0x<lo>","0x<hi>"], ...] form.

    MUTATION (verified RED): store origin as NULL always -> RED; leave the promote UPDATE out ->
    every column NULL -> RED; write the residual ranges as '[]' -> RED; drop "recovered" from
    _ORIGINS -> the recovered row reads NULL -> RED."""
    conn = _ingest(
        tmp_path,
        [
            _fn("FUN_00400000", "0x400000", origin="promoted"),
            _fn("main", "0x400400", origin="analysis"),
            _fn("FUN_00400300", "0x400300", origin="recovered"),  # W14
        ],
        {"promote": _PROMOTE},
    )
    origins = dict(conn.execute("SELECT name, origin FROM functions").fetchall())
    got = _promote_row(conn)
    conn.close()
    assert origins == {
        "FUN_00400000": "promoted",
        "main": "analysis",
        "FUN_00400300": "recovered",
    }
    assert got == {
        "promote_created": 4,
        "promote_residual_insns": 9,
        "promote_residual_start": 2,
        "promote_residual_interior": 6,
        "promote_residual_unowned": 1,
        "promote_residual_ranges": '[["0x400100","0x40010b"],["0x400200","0x400213"]]',
        "promote_residual_ranges_truncated": 0,
        "promote_undefined_ranges": '[["0x400300","0x40031f"]]',
        "promote_undefined_ranges_truncated": 0,
        "promote_undefined_bytes": 32,
        "promote_recovered": 3,
        "promote_recover_rejected": 1,
        "promote_recover_seeds": 7,
        "promote_recover_lost_bytes": 0,
        "promote_recover_noreturn_flips": 0,
    }


def test_an_export_without_the_record_reads_null_never_zero(tmp_path: Path) -> None:
    """★ No promote object / no origin (an export from a session whose pass recorded nothing, or
    one predating the record) is NULL everywhere — never 0 and never "analysis". An origin of
    another form is NULL too.

    MUTATION (verified RED): default a missing count to 0 in _promote_columns -> RED; default a
    missing origin to "analysis" -> RED."""
    conn = _ingest(tmp_path, [_fn("f", "0x1000"), _fn("g", "0x2000", origin="carved")])
    origins = [r[0] for r in conn.execute("SELECT origin FROM functions")]
    got = _promote_row(conn)
    conn.close()
    assert origins == [None, None]
    assert got == dict.fromkeys(_PROMOTE_COLS)


def test_truncated_ranges_are_flagged(tmp_path: Path) -> None:
    """The extractor capped the ranges: truncated is stored as 1, so a reader never takes the
    stored ranges for all of them.

    MUTATION (verified RED): store truncated as 0 always -> RED."""
    conn = _ingest(
        tmp_path, [_fn("f", "0x1000")], {"promote": {**_PROMOTE, "residual_ranges_truncated": True}}
    )
    got = _promote_row(conn)
    conn.close()
    assert got["promote_residual_ranges_truncated"] == 1
    assert got["promote_residual_insns"] == 9


@pytest.mark.parametrize(
    "broken",
    [
        {"residual_insns": 8},  # the kinds do not sum to the total
        {"created": -1},
        {"residual_unowned": True},  # a bool is not a count
        {"residual_ranges": [["0x1", "0x2", "0x3"]]},
        {"residual_ranges": [[1, 2]]},
        {"residual_ranges_truncated": "no"},
        # W11 / W14 fields join the same all-or-nothing rule:
        {"undefined_bytes": -1},
        {"undefined_ranges": [[1, 2]]},
        {"undefined_ranges_truncated": "no"},
        {"recovered": -1},
        {"recover_rejected": True},  # a bool is not a count
        {"recover_noreturn_flips": -1},
    ],
)
def test_a_record_that_does_not_hold_together_is_null(
    tmp_path: Path, broken: dict[str, Any]
) -> None:
    """A malformed record states nothing: all of its columns NULL, not the parts that parsed.

    MUTATION (verified RED): drop the sum check -> the first case stores 8 -> RED; drop the
    range-shape check -> the two range cases store -> RED; drop the undefined/recover checks ->
    those cases store -> RED."""
    conn = _ingest(tmp_path, [_fn("f", "0x1000")], {"promote": {**_PROMOTE, **broken}})
    got = _promote_row(conn)
    conn.close()
    assert got == dict.fromkeys(_PROMOTE_COLS)


@pytest.mark.parametrize(
    "missing",
    [
        "undefined_ranges",
        "undefined_ranges_truncated",
        "undefined_bytes",
        "recovered",
        "recover_rejected",
        "recover_seeds",
        "recover_lost_insn_bytes",
        "recover_noreturn_flips",
    ],
)
def test_a_record_missing_a_w11_or_w14_field_is_all_null(tmp_path: Path, missing: str) -> None:
    """★ W11/W14: a pre-W11 export carries the W1 fields but none of the undefined_*/recover_*
    ones. Missing ANY of them makes the WHOLE promote group NULL — never a partial row that reads
    the W1 counts while the undefined bytes silently read 0.

    MUTATION (verified RED): drop a new field from the _promote_columns completeness check -> that
    field's case stores a partial row -> RED."""
    rec = {k: v for k, v in _PROMOTE.items() if k != missing}
    conn = _ingest(tmp_path, [_fn("f", "0x1000")], {"promote": rec})
    got = _promote_row(conn)
    conn.close()
    assert got == dict.fromkeys(_PROMOTE_COLS)


def test_undefined_ranges_truncated_is_flagged(tmp_path: Path) -> None:
    """W11: the extractor capped the undefined ranges — truncated stored as 1, bytes still the full
    count, so a reader never takes the stored ranges for all of them.

    MUTATION (verified RED): store undefined truncation as 0 always -> RED."""
    conn = _ingest(
        tmp_path,
        [_fn("f", "0x1000")],
        {"promote": {**_PROMOTE, "undefined_ranges_truncated": True}},
    )
    got = _promote_row(conn)
    conn.close()
    assert got["promote_undefined_ranges_truncated"] == 1
    assert got["promote_undefined_bytes"] == 32


def test_a_reextraction_without_the_record_clears_the_earlier_one(tmp_path: Path) -> None:
    """★ The same binary re-ingested from an export carrying no record: the earlier session's
    numbers are cleared to NULL, not left standing as this extraction's; drop_extraction clears
    them too.

    MUTATION (verified RED): write the promote columns only when the export carries a record ->
    the first assertion keeps 4 -> RED; leave them out of drop_extraction -> RED."""
    _ingest(tmp_path, [_fn("f", "0x1000")], {"promote": _PROMOTE}).close()
    conn = _ingest(tmp_path, [_fn("f", "0x1000")])
    assert _promote_row(conn) == dict.fromkeys(_PROMOTE_COLS)
    conn.close()
    conn = _ingest(tmp_path, [_fn("f", "0x1000")], {"promote": _PROMOTE})
    assert _promote_row(conn)["promote_created"] == 4
    drop_extraction(conn, "a" * 64)
    assert _promote_row(conn) == dict.fromkeys(_PROMOTE_COLS)
    conn.close()


# ── the schema in both places ───────────────────────────────────────────────────────────────


def _legacy_db(path: Path) -> None:
    raw = sqlite3.connect(path)
    raw.execute(
        "CREATE TABLE binaries (id INTEGER PRIMARY KEY, name TEXT, sha256 TEXT UNIQUE, "
        "ghidra_ok INTEGER NOT NULL DEFAULT 0)"
    )
    raw.execute(
        "CREATE TABLE functions (id INTEGER PRIMARY KEY AUTOINCREMENT, binary_id INTEGER, "
        "name TEXT, address TEXT)"
    )
    raw.execute("INSERT INTO binaries (id, name, sha256, ghidra_ok) VALUES (1, 'webd', 'aa', 1)")
    raw.execute("INSERT INTO functions (binary_id, name, address) VALUES (1, 'main', '1000')")
    raw.commit()
    raw.close()


def test_an_older_database_gains_the_columns_as_null(tmp_path: Path) -> None:
    """★ A database built before the record existed gains every column on open, its rows read NULL
    (not recorded), and opening again does not raise.

    MUTATION (verified RED): drop ("binaries", "promote_residual_unowned", "INTEGER") from
    _ADDED_COLUMNS -> RED; drop ("functions", "origin", "TEXT") -> RED."""
    db = tmp_path / "legacy.db"
    _legacy_db(db)
    conn = open_db(db)
    bcols = {r[1] for r in conn.execute("PRAGMA table_info(binaries)")}
    fcols = {r[1] for r in conn.execute("PRAGMA table_info(functions)")}
    assert set(_PROMOTE_COLS) <= bcols, set(_PROMOTE_COLS) - bcols
    assert {"origin", "decompile_error"} <= fcols, {"origin", "decompile_error"} - fcols
    got = _promote_row(conn)
    fn = conn.execute("SELECT origin, decompile_error FROM functions").fetchone()
    conn.close()
    assert got == dict.fromkeys(_PROMOTE_COLS)
    assert tuple(fn) == (None, None)
    conn = open_db(db)  # idempotent
    conn.close()


def test_schema_sql_alone_declares_the_columns(tmp_path: Path) -> None:
    """The other half of the two-place rule, built from schema.sql alone (open_db would put a
    missing column back through the migration).

    MUTATION (verified RED): remove promote_residual_ranges from schema.sql -> RED while the
    migration test above stays green."""
    raw = sqlite3.connect(tmp_path / "s.db")
    raw.executescript(_SCHEMA.read_text())
    bcols = {r[1] for r in raw.execute("PRAGMA table_info(binaries)")}
    fcols = {r[1] for r in raw.execute("PRAGMA table_info(functions)")}
    raw.close()
    assert set(_PROMOTE_COLS) <= bcols
    assert {"origin", "decompile_error"} <= fcols


# ── the run-level roll-up ───────────────────────────────────────────────────────────────────


def _rollup_db(tmp_path: Path, rows: list[tuple[str, int, int | None, int | None]]) -> Path:
    """Binaries (name, ghidra_ok, residual_insns, residual_unowned); NULL = not recorded."""
    db = tmp_path / "analysis.db"
    conn = open_db(db)
    for i, (name, ok, insns, unowned) in enumerate(rows, start=1):
        conn.execute(
            "INSERT INTO binaries (id, name, sha256, ghidra_ok, promote_residual_insns, "
            "promote_residual_unowned, promote_created) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (i, name, f"{i:064x}", ok, insns, unowned, None if insns is None else 3),
        )
    conn.commit()
    conn.close()
    return db


def test_the_rollup_counts_binaries_with_residue_and_with_unowned(tmp_path: Path) -> None:
    """residual = extracted binaries with an instruction left outside any function; unowned =
    those with one in no code block. A binary whose extraction failed (ghidra_ok = 0) records
    nothing and is counted in neither — nor does it make the roll-up unknown.

    MUTATION (verified RED): count residual_insns >= 0 -> 3 -> RED; count the ghidra_ok = 0
    binary's NULL as unrecorded -> None -> RED."""
    db = _rollup_db(
        tmp_path, [("a", 1, 0, 0), ("b", 1, 7, 0), ("c", 1, 12, 4), ("dead", 0, None, None)]
    )
    conn = open_db(db)
    try:
        assert promote_residual_counts(conn) == {
            "promote_residual_binaries": 2,
            "promote_unowned_binaries": 1,
        }
        assert analysis_run_counts(conn)["promote_unowned_binaries"] == 1
    finally:
        conn.close()


def test_one_unrecorded_extracted_binary_makes_the_rollup_unknown(tmp_path: Path) -> None:
    """★ One extracted binary with no record: both counts are None, not the count over the
    others — that binary may hold residue, so "1 binary" would read as a complete count.

    MUTATION (verified RED): return the counts over the recorded binaries regardless -> RED."""
    db = _rollup_db(tmp_path, [("a", 1, 7, 2), ("old", 1, None, None)])
    conn = open_db(db)
    try:
        assert promote_residual_counts(conn) == {
            "promote_residual_binaries": None,
            "promote_unowned_binaries": None,
        }
    finally:
        conn.close()


def test_an_analysis_db_without_the_columns_rolls_up_to_unknown(tmp_path: Path) -> None:
    raw = sqlite3.connect(tmp_path / "old.db")
    raw.execute("CREATE TABLE binaries (id INTEGER PRIMARY KEY, name TEXT, ghidra_ok INTEGER)")
    raw.execute("CREATE VIEW current_binaries AS SELECT * FROM binaries")
    try:
        assert promote_residual_counts(raw) == {
            "promote_residual_binaries": None,
            "promote_unowned_binaries": None,
        }
    finally:
        raw.close()


def test_the_hunt_writes_the_rollup_onto_the_run_and_list_runs_returns_it(tmp_path: Path) -> None:
    """End to end: the hunt reads the roll-up from the analysis.db, finish_run writes it on the run
    row, list_runs returns it.

    MUTATION (verified RED): leave the two keyword arguments out of analyzer2's finish_run call ->
    the run row holds NULL -> RED; leave them out of _RUN_COLUMNS / _row_to_runrow -> RED."""
    from treasure_map.lib.hunt.analyzer2 import run_analyzer2

    db = _rollup_db(tmp_path, [("a", 1, 7, 0), ("b", 1, 12, 4), ("c", 1, 0, 0)])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="r", rehunt=True)
    conn = open_atlas(atlas)
    try:
        run = get_run(conn, "r")
        listed = {r.run_id: r for r in list_runs(conn)}
    finally:
        conn.close()
    assert run is not None
    assert (run.promote_residual_binaries, run.promote_unowned_binaries) == (2, 1)
    assert (listed["r"].promote_residual_binaries, listed["r"].promote_unowned_binaries) == (2, 1)


def test_finish_run_writes_none_as_null(tmp_path: Path) -> None:
    """None is written as NULL ("not recorded"), like functions_empty — a later finish_run with
    None replaces an earlier count rather than keeping it."""
    conn = open_atlas(tmp_path / "atlas.db")
    try:
        begin_run(conn, "r")
        finish_run(conn, "r", promote_residual_binaries=3, promote_unowned_binaries=1)
        finish_run(conn, "r")
        run = get_run(conn, "r")
    finally:
        conn.close()
    assert run is not None
    assert (run.promote_residual_binaries, run.promote_unowned_binaries) == (None, None)


def test_an_older_atlas_gains_the_run_columns(tmp_path: Path) -> None:
    """★ An atlas whose run table predates the columns gains them on open (NULL), idempotently.

    MUTATION (verified RED): drop the run-table migration loop -> no such column -> RED (an
    OperationalError, so the column check below is what states it)."""
    path = tmp_path / "atlas.db"
    conn = open_atlas(path)
    conn.execute("ALTER TABLE run DROP COLUMN promote_unowned_binaries")
    conn.execute("ALTER TABLE run DROP COLUMN promote_residual_binaries")
    conn.execute("INSERT INTO run (run_id) VALUES ('old')")
    conn.commit()
    conn.close()
    conn = open_atlas(path)
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(run)")}
        assert {"promote_residual_binaries", "promote_unowned_binaries"} <= cols
        run = get_run(conn, "old")
    finally:
        conn.close()
    assert run is not None and run.promote_residual_binaries is None
    open_atlas(path).close()


def test_atlas_schema_alone_declares_the_run_columns(tmp_path: Path) -> None:
    raw = sqlite3.connect(tmp_path / "s.db")
    raw.executescript(_ATLAS_SCHEMA.read_text())
    cols = {r[1] for r in raw.execute("PRAGMA table_info(run)")}
    raw.close()
    assert {"promote_residual_binaries", "promote_unowned_binaries"} <= cols


# ── the scan summary ────────────────────────────────────────────────────────────────────────


def _summary_db(tmp_path: Path) -> sqlite3.Connection:
    conn = open_db(tmp_path / "analysis.db")
    for i, (name, ok, created, insns, unowned) in enumerate(
        [
            ("a", 1, 10, 4, 0),
            ("b", 1, 2, 30, 5),
            ("c", 1, None, None, None),
            ("dead", 0, None, None, None),
        ],
        start=1,
    ):
        conn.execute(
            "INSERT INTO binaries (id, name, sha256, ghidra_ok, promote_created, "
            "promote_residual_insns, promote_residual_unowned) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (i, name, f"{i:064x}", ok, created, insns, unowned),
        )
    conn.commit()
    return conn


def test_promote_summary_sums_the_recorded_and_counts_the_rest(tmp_path: Path) -> None:
    """MUTATION (verified RED): count an unrecorded binary's NULL as 0 and drop `unrecorded` ->
    RED; name every binary with residue as unowned -> RED."""
    conn = _summary_db(tmp_path)
    try:
        assert promote_summary(conn) == {
            "binaries": 3,
            "unrecorded": 1,
            "created": 12,
            "residual_insns": 34,
            "unowned_binaries": ["b"],
        }
    finally:
        conn.close()


def test_the_scan_prints_the_promotion_line_and_names_unowned_binaries(tmp_path: Path) -> None:
    """The scan's summary carries one promotion line (created, left outside any function, how
    many binaries recorded nothing) and, on stderr, the binaries with instructions in no code
    block.

    MUTATION (verified RED): leave _report_promote out of report_extraction_state -> RED."""
    import click

    from treasure_map.cli.analyze_cli import report_extraction_state

    conn = _summary_db(tmp_path)
    try:
        promote = promote_summary(conn)
    finally:
        conn.close()

    class _R:
        incomplete_binaries: list[str] = []
        no_functions_binaries: list[str] = []
        kept_earlier_binaries: list[dict[str, Any]] = []
        reanalyze_pending = 0

    result = _R()
    result.promote = promote  # type: ignore[attr-defined]

    @click.command()
    def cmd() -> None:
        report_extraction_state(result, None)

    out = CliRunner().invoke(cmd, [])
    assert out.exit_code == 0, out.output
    assert "promoted functions: 12 created; 34 instructions left outside any function" in out.stdout
    assert "(not recorded for 1 binaries)" in out.stdout
    assert re.search(r"1 binaries have instructions in no code block.*: b$", out.stderr, re.M)


# ── the two Ghidra scripts, read as text ────────────────────────────────────────────────────


def _code(path: Path) -> str:
    """The script with its // comments removed, so a word in prose does not count as a call."""
    return "\n".join(re.sub(r"//.*$", "", line) for line in path.read_text().splitlines())


def test_promotion_never_walks_the_program_wide_block_iterator() -> None:
    """★ The program-wide block iterator gives up on whole address ranges (a labelled MIPS delay
    slot), and getCodeBlocksContaining(set) rests on the same iterator: the promotion pass must
    find its blocks by walking instructions instead.

    MUTATION (verified RED): put back `model.getCodeBlocks(monitor)` as the loop -> RED."""
    code = _code(_GHIDRA_DIR / "PromoteUndefined.java")
    assert "getInstructions(true)" in code
    assert "getCodeBlocks(" not in code
    assert "getCodeBlocksContaining(" not in code


def test_the_two_scripts_spell_the_handoff_the_same_way() -> None:
    """ExportFunctions reads what PromoteUndefined left in the session by the option category and
    bookmark category; a typo on either side would make every export read "not recorded".

    MUTATION (verified RED): change the bookmark category in ExportFunctions -> RED."""
    promote = (_GHIDRA_DIR / "PromoteUndefined.java").read_text()
    export = (_GHIDRA_DIR / "ExportFunctions.java").read_text()

    def const(text: str, name: str) -> str:
        m = re.search(rf'{name}\s*=\s*"([^"]+)"', text)
        assert m is not None, name
        return m.group(1)

    assert const(promote, "OPTIONS_CATEGORY") == const(export, "PROMOTE_OPTIONS")
    assert const(promote, "BOOKMARK_CATEGORY") == const(export, "PROMOTE_BOOKMARK")
    # W14: the recovered-function bookmark, read back as origin='recovered'.
    assert const(promote, "RECOVERED_BOOKMARK") == const(export, "PROMOTE_RECOVERED")
    # Every option ExportFunctions reads is one PromoteUndefined writes (now incl. the W11/W14
    # fields: undefined_ranges / undefined_bytes / recovered / recover_* ).
    written = set(re.findall(r'opts\.set\w+\("(\w+)"', promote))
    read = set(re.findall(r'opts\.(?:get\w+|contains)\("(\w+)"', export))
    assert read and read <= written, read - written
    assert {"undefined_ranges", "undefined_bytes", "recovered", "recover_lost_insn_bytes"} <= read


def test_w14_freezes_and_restores_no_return_discovery() -> None:
    """★ W14 re-analyses with no-return discovery FROZEN; without the freeze, re-analysis can newly
    mark an existing command wrapper non-returning and delete every instruction after each call to
    it. The original value is restored at the end.

    MUTATION (verified RED): drop the freeze setAnalysisOption(... "false") -> RED; drop the
    restoreNoReturn call -> RED; drop one initializeOptions -> RED."""
    code = _code(_GHIDRA_DIR / "PromoteUndefined.java")
    assert 'NO_RETURN_OPTION = "Non-Returning Functions - Discovered"' in code
    assert 'setAnalysisOption(currentProgram, NO_RETURN_OPTION, "false")' in code
    assert "restoreNoReturn(nrWas)" in code
    # the analyzer options are re-initialised after both the freeze and the restore
    assert code.count("initializeOptions()") >= 2
    # the recovery guard counts exist and are recorded (both 0 by design)
    assert "recover_lost_insn_bytes" in code
    assert "recover_noreturn_flips" in code


def test_w14_bookmarks_recovered_functions_and_export_reads_the_origin() -> None:
    """★ W14 bookmarks each recovered function under RECOVERED_BOOKMARK; ExportFunctions reads that
    bookmark to write origin='recovered', checked BEFORE the promoted bookmark.

    MUTATION (verified RED): make originField check the promoted bookmark first -> a recovered
    function reads 'promoted' -> RED; drop the recovered createFunction bookmark -> RED."""
    promote = _code(_GHIDRA_DIR / "PromoteUndefined.java")
    export = _code(_GHIDRA_DIR / "ExportFunctions.java")
    assert "RECOVERED_BOOKMARK" in promote and "createFunction(a, null)" in promote
    # originField resolves recovered -> promoted -> analysis, in that order.
    rec_at = export.index("PROMOTE_RECOVERED")
    prom_at = export.index("PROMOTE_BOOKMARK", export.index("originField"))
    assert rec_at < export.index('"recovered"')
    assert export.index("PROMOTE_RECOVERED", export.index("originField")) < prom_at
