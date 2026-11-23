# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The extractor's thunk targets, imported-function addresses and table-access observations: where
they are stored, what NULL means there, what clears them, the key list a row may carry, the shape
the extractor builds them in, and how the dispatch-table reader names a handler from the first two.

The Java side is run for real in tests/integration/test_table_access.py; here it is read as source
only (its structure) and every database is synthetic.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from tests.unit.lib.dispatch_image import Image
from tests.unit.lib.test_dispatch_tables import _table
from tests.unit.lib.test_ghidra_ingest import _make_record, _setup_db, _write_ghidra_json
from treasure_map.lib.analyze import ghidra_ingest as ingest_mod
from treasure_map.lib.analyze.ghidra_ingest import TABLE_ACCESS_ROW_KEYS, ingest_ghidra_output
from treasure_map.lib.diff.alignment import _thunk_spans
from treasure_map.lib.hunt import dispatch_tables as dt
from treasure_map.lib.storage.connection import open_db

_SRC = Path(__file__).resolve().parents[3] / "src" / "treasure_map"
_JAVA = _SRC / "lib" / "analyze" / "ghidra" / "ExportFunctions.java"
_SHA = "a" * 64


def _java() -> str:
    return _JAVA.read_text(encoding="utf-8")


def _table_access_section() -> str:
    """The extractor's table-access builder: from its banner to the next section's."""
    src = _java()
    start = src.index("// ============================ table-access observations")
    end = src.index("// ============================ sink_arg_provenance", start)
    return src[start:end]


def _export(**extra: Any) -> dict[str, Any]:
    """An extraction of two functions (entries 1000 and 1100), plus ``extra`` top-level keys."""
    return {
        "functions": [
            {"name": "fx_reader", "address": "00001000", "size": 64, "pseudocode": "x"},
            {"name": "fx_other", "address": "00001100", "size": 64, "pseudocode": "y"},
        ],
        "imports": [],
        "exports": [],
        "strings": [],
        **extra,
    }


def _ingest(tmp_path: Path, data: dict[str, Any]) -> sqlite3.Connection:
    conn, sha_to_id = _setup_db(tmp_path)
    out = tmp_path / "ghidra_output"
    _write_ghidra_json(out, "test_bin", _SHA, data)
    ingest_ghidra_output(conn, out, [_make_record("test_bin", _SHA)], sha_to_id)
    conn.commit()
    return conn


_ROWS = [
    {"k": "read", "at": "0x1004", "base": "0x2000", "bk": "imm", "off": 8, "form": "walk",
     "step": 12, "ptr": "phi7", "sz": 4, "bb": 1, "uses": ["icall@0x1008#b1"]},
    {"k": "pointer", "ptr": "phi7", "base": "0x2000", "bk": "imm", "form": "walk", "step": 12,
     "uses": ["arg:fx_note:0@0x100c#b1"]},
]  # fmt: skip


# ── where they are stored, and what NULL means ───────────────────────────────────────────────


def test_the_observations_are_stored_by_function_with_their_dominators_and_their_cut(
    tmp_path: Path,
) -> None:
    """Each row lands on its function, in the exported order, its kind in a column and the rest
    of it as JSON; the dominator list on a row of its own; a cut function gets a closing
    ``truncated`` row (so a prefix never reads as the whole); a function the binary does not have
    and a row of no known kind are skipped."""
    conn = _ingest(
        tmp_path,
        _export(
            table_access=[
                {
                    "f": "00001000",
                    "rows": [*_ROWS, {"k": "bogus"}],
                    "total": 900,
                    "truncated": True,
                    "idom": [-1, 0],
                },
                {"f": "00009999", "rows": _ROWS, "total": 2, "truncated": False},
            ]  # fmt: skip
        ),
    )
    fid = conn.execute("SELECT id FROM functions WHERE address = '00001000'").fetchone()[0]
    rows = conn.execute(
        "SELECT function_id, seq, kind, obs FROM table_access ORDER BY seq"
    ).fetchall()
    assert [(r[0], r[1], r[2]) for r in rows] == [
        (fid, 0, "read"),
        (fid, 1, "pointer"),
        (fid, 2, ingest_mod.TABLE_ACCESS_TRUNCATED),
    ]
    assert json.loads(rows[0][3]) == {k: v for k, v in _ROWS[0].items() if k != "k"}
    assert json.loads(rows[2][3]) == {"total": 900, "kept": 3}
    blocks = conn.execute("SELECT function_id, idom FROM table_access_blocks").fetchall()
    assert [tuple(b) for b in blocks] == [(fid, "[-1,0]")]


def test_an_export_without_observations_stores_none(tmp_path: Path) -> None:
    conn = _ingest(tmp_path, _export())
    assert conn.execute("SELECT COUNT(*) FROM table_access").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM table_access_blocks").fetchone()[0] == 0


def test_the_two_name_lists_keep_null_apart_from_empty(tmp_path: Path) -> None:
    """★ A list (empty or not) is stored as given; an export that predates the lists stores NULL —
    "not recorded", never "[]"."""
    given = _ingest(
        tmp_path / "a",
        _export(thunk_targets=[["0x1200", None, "fx_imp"]], external_symbols=[]),
    )
    assert tuple(
        given.execute("SELECT thunk_targets, external_symbols FROM binaries").fetchone()
    ) == (
        '[["0x1200",null,"fx_imp"]]',
        "[]",
    )
    absent = _ingest(tmp_path / "b", _export())
    assert tuple(
        absent.execute("SELECT thunk_targets, external_symbols FROM binaries").fetchone()
    ) == (
        None,
        None,
    )


def test_the_thunk_targets_never_ride_in_the_thunk_spans(tmp_path: Path) -> None:
    """★ A-E4-4. The targets go to a column of their own; thunk_spans stays [entry, ranges], which
    the diff's strict reader still reads (a third element would make it read the whole list as
    unknown).

    MUTATION (must go RED): store the targets as a third element of each thunk_spans entry ->
    the strict reader returns None."""
    thunks = [["0x1200", [["0x1200", "0x120f"]]]]
    conn = _ingest(tmp_path, _export(thunks=thunks, thunk_targets=[["0x1200", None, "fx_imp"]]))
    (spans,) = conn.execute("SELECT thunk_spans FROM binaries").fetchone()
    assert json.loads(spans) == thunks
    assert _thunk_spans(spans) is not None


def test_drop_extraction_clears_the_two_lists_and_both_tables(tmp_path: Path) -> None:
    """★ A-E4-1. After a dropped extraction the binary's thunk targets and imported-function
    addresses are NULL and it has no table-access row of either table — checked on a connection
    without foreign-key enforcement, so the clearing is the function's own, not a cascade.

    MUTATION (must go RED): leave either column out of the NULL list, or either table out of
    _EXTRACTION_TABLES."""
    conn = _ingest(
        tmp_path,
        _export(
            thunk_targets=[["0x1200", None, "fx_imp"]],
            external_symbols=[["0x9000", "fx_imp"]],
            table_access=[
                {"f": "00001000", "rows": _ROWS, "total": 2, "truncated": False, "idom": [-1, 0]}
            ],
        ),  # fmt: skip
    )
    conn.close()
    raw = sqlite3.connect(tmp_path / "analysis.db")
    assert raw.execute("PRAGMA foreign_keys").fetchone()[0] == 0
    ingest_mod.drop_extraction(raw, _SHA)
    raw.commit()
    assert tuple(
        raw.execute("SELECT thunk_targets, external_symbols FROM binaries").fetchone()
    ) == (
        None,
        None,
    )
    for table in ("table_access", "table_access_blocks"):
        assert raw.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0, table  # noqa: S608


def test_an_older_database_gains_the_lists_as_null_and_the_tables_empty(tmp_path: Path) -> None:
    """★ A-E4-3. A database from before the lists and tables opens; the lists are added as NULL
    (not recorded), never back-filled with "[]", and both tables exist, empty."""
    db = tmp_path / "old.db"
    conn = open_db(db)
    conn.execute("INSERT INTO binaries (name, sha256) VALUES ('fx_old', ?)", (_SHA,))
    conn.commit()
    conn.close()
    raw = sqlite3.connect(db)
    raw.execute("DROP TABLE table_access")
    raw.execute("DROP TABLE table_access_blocks")
    raw.execute("ALTER TABLE binaries DROP COLUMN thunk_targets")
    raw.execute("ALTER TABLE binaries DROP COLUMN external_symbols")
    raw.commit()
    raw.close()
    conn = open_db(db)
    assert tuple(
        conn.execute("SELECT thunk_targets, external_symbols FROM binaries").fetchone()
    ) == (
        None,
        None,
    )
    for table in ("table_access", "table_access_blocks"):
        assert conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0  # noqa: S608


# ── the key list, and the shape the extractor builds them in ─────────────────────────────────


def test_the_keys_a_row_may_carry_are_the_listed_ones(tmp_path: Path) -> None:
    """★ A-E4-5. Every key the extractor's table-access builder writes (each through taKey /
    taStr / taNum) is in TABLE_ACCESS_ROW_KEYS, and every listed key is written somewhere — so
    a key the extractor starts writing cannot go unlisted, nor a listed one go stale.

    MUTATION (must go RED): write a new key in the builder without listing it."""
    written = set(re.findall(r'\bta(?:Str|Num|Key)\(sb, "(\w+)"', _table_access_section()))
    assert written == TABLE_ACCESS_ROW_KEYS


def test_no_row_carries_a_dominator_set_and_the_dominators_are_one_row_per_function(
    tmp_path: Path,
) -> None:
    """★ A-E4-11. A row names its block only (bb, #bN); the dominators are one list per function
    in table_access_blocks, whose key is the function."""
    assert not any("dom" in k for k in TABLE_ACCESS_ROW_KEYS)
    conn = open_db(tmp_path / "s.db")
    pk = [r[1] for r in conn.execute("PRAGMA table_info(table_access_blocks)") if r[5]]
    assert pk == ["function_id"]


def test_the_builder_reads_the_one_decompile_and_adds_none() -> None:
    """★ A-E4-8. The builder is handed the HighFunction exportFunction already holds — the one its
    decompile produced — and makes no decompile of its own: one set of options, two decompile
    calls (the wrapper probe's and the main one), as before.

    MUTATION (must go RED): decompile again inside the builder, or build a second options
    object."""
    src = _java()
    assert src.count("new DecompileOptions()") == 1
    assert src.count(".decompileFunction(") == 2
    assert "decompileFunction" not in _table_access_section()
    assert src.count("buildTableAccess(func, hf)") == 1
    body = src[src.index("private String exportFunction(") :]
    assert body.index("hf = dr.getHighFunction();") < body.index("buildTableAccess(func, hf)")


def test_a_value_is_followed_six_merges_deep_and_a_pointer_three() -> None:
    """The use walk's depth: 6 for a value read (a key reaching its matcher through several phis
    was lost at 3), 3 for a walking pointer's own uses (no escape was lost there). The Ghidra run
    of the deep case is in tests/integration/test_table_access.py."""
    src = _java()
    assert re.findall(r"TA_USE_DEPTH = (\d+);", src) == ["6"]
    assert re.findall(r"TA_POINTER_DEPTH = (\d+);", src) == ["3"]


def test_a_function_is_cut_at_512_rows_and_never_under_300() -> None:
    """★ A-E4-10. The per-function limit: 512 (the largest function measured has 260 rows; the
    limit must not fall under about 300)."""
    (limit,) = re.findall(r"TA_ROW_LIMIT = (\d+);", _java())
    assert int(limit) == 512


def test_the_hunt_reads_no_observation() -> None:
    """★ A-E4-12. This batch only exports the observations: nothing in the hunt reads them, so
    no candidate and no ranking moves with them."""
    readers = [
        p.relative_to(_SRC).as_posix()
        for p in (_SRC / "lib" / "hunt").rglob("*.py")
        if "table_access" in p.read_text(encoding="utf-8")
    ]
    assert readers == []


# ── naming a handler from the two lists ──────────────────────────────────────────────────────


def _detect(tmp_path: Path, img: Image, **columns: str | None) -> dt.RunTables:
    db = tmp_path / "d.db"
    conn = open_db(db)
    img.write(conn, 1, name="fx", path=str(tmp_path / "missing.bin"), sha256=_SHA)
    for column, value in columns.items():
        conn.execute(f"UPDATE binaries SET {column} = ?", (value,))  # noqa: S608
    conn.commit()
    conn.close()
    return dt.detect_run(db, "r")


def _image() -> tuple[Image, int, int]:
    """A table of four records whose handlers are two functions, a thunk and an imported
    function: (image, the thunk, the import)."""
    img = Image()
    f1, f2 = img.func("fx_one"), img.func("fx_two")
    thunk = img.thunk()
    img.thunk_targets[thunk] = "fx_reached"
    imp = img.imported("fx_imported")
    _table(img, ["one", "two", "three", "four"], [f1, thunk, imp, f2])
    return img, thunk, imp


def test_a_thunk_is_named_after_its_target_and_an_import_after_itself(tmp_path: Path) -> None:
    """★ A-E4-6. A thunk handler reads as the function it reaches, still of kind ``thunk``; an
    imported handler reads as the import, of kind ``import``; the status note no longer lists an
    imported handler among what is not read.

    MUTATION (must go RED): handler_of ignores the thunk names, or the imports."""
    img, thunk, imp = _image()
    res = _detect(tmp_path, img)
    by_addr = {int(e.callee_addr, 16): e for e in res.edges}
    assert thunk in by_addr and imp in by_addr, sorted(by_addr)
    assert (by_addr[thunk].callee_name, by_addr[thunk].callee_kind) == ("fx_reached", "thunk")
    assert (by_addr[imp].callee_name, by_addr[imp].callee_kind) == ("fx_imported", "import")
    assert "an imported handler" not in dt.UNSUPPORTED_NOTE
    (status,) = res.statuses
    assert status.unsupported_note == dt.UNSUPPORTED_NOTE


def test_unrecorded_lists_leave_the_handlers_as_before_and_say_so(tmp_path: Path) -> None:
    """★ A-E4-2. NULL lists and '[]' lists give different results: with both NULL (not recorded)
    the thunk stays unnamed, the imported handler reads as the unnamed thunk Ghidra placed at its
    address (as before either list existed), and the status note says which list is missing; with
    '[]' (recorded, none) the note is the plain one.

    MUTATION (must go RED): read a NULL list as '[]' -> the notes are the same."""
    img, thunk, imp = _image()
    none = _detect(tmp_path / "n", img, thunk_targets=None, external_symbols=None)
    empty = _detect(tmp_path / "e", img, thunk_targets="[]", external_symbols="[]")
    for res in (none, empty):
        by_addr = {int(e.callee_addr, 16): e for e in res.edges}
        assert thunk in by_addr and imp in by_addr, sorted(by_addr)
        assert by_addr[thunk].callee_name is None
        # not recorded: the import is read as the unnamed thunk Ghidra placed there, as before
        assert (by_addr[imp].callee_name, by_addr[imp].callee_kind) == (None, "thunk")
    assert empty.statuses[0].unsupported_note == dt.UNSUPPORTED_NOTE
    assert none.statuses[0].unsupported_note == (
        f"{dt.UNSUPPORTED_NOTE}; {dt.TARGETS_NOT_RECORDED_NOTE}; {dt.IMPORTS_NOT_RECORDED_NOTE}"
    )


def test_an_unreadable_name_entry_is_counted(tmp_path: Path) -> None:
    img, _thunk, _imp = _image()
    res = _detect(
        tmp_path,
        img,
        thunk_targets=json.dumps([[7, None, "x"], ["0x1", None, None], ["0x2", None, 5]]),
        external_symbols=json.dumps([["0x2", "fx"], ["0x3"]]),
    )
    assert res.statuses[0].unsupported_note == (
        f"{dt.UNSUPPORTED_NOTE}; {dt.targets_unreadable_note(2)}; {dt.imports_unreadable_note(1)}"
    )
