# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Which binaries are the current scan's, and what a reopen of an analysis.db keeps.

A workspace re-scanned in place keeps the previous scan's binaries (ingest de-duplicates by
content, it never deletes), dated with an older ``last_seen_at``. The hunt reads the CURRENT ones
only — a removed or replaced binary must not come back as a candidate of this run — and a database
whose rows were never dated reads all of its binaries, not none."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.diff.loader import load_functions
from treasure_map.lib.pattern.scanner import scan
from treasure_map.lib.storage.connection import open_db

_BODY = "void handle(char *p){ char b[64]; recv(0, b, 64, 0); system(b); }"


def _db(tmp_path: Path, dates: tuple[str | None, str | None]) -> Path:
    db = tmp_path / "analysis.db"
    conn = open_db(db)
    for bid, name, seen in ((1, "old_daemon", dates[0]), (2, "new_daemon", dates[1])):
        conn.execute(
            "INSERT INTO binaries (id, name, path, sha256, last_seen_at) VALUES (?, ?, ?, ?, ?)",
            (bid, name, f"usr/sbin/{name}", str(bid) * 64, seen),
        )
        conn.execute(
            "INSERT INTO functions (binary_id, name, address, pseudocode, callees) "
            "VALUES (?, 'handle', '00001000', ?, ?)",
            (bid, _BODY, json.dumps(["recv", "system"])),
        )
    conn.commit()
    conn.close()
    return db


def test_the_hunt_reads_only_the_current_scans_binaries(tmp_path: Path) -> None:
    """MUTATION: join every binary again (drop the last_seen_at condition) in the hunt's
    function loader or the shape scan -> the replaced binary's candidate comes back -> RED."""
    db = _db(tmp_path, ("2026-01-01 00:00:00", "2026-02-01 00:00:00"))
    assert {f.binary_name for f in load_functions(db)} == {"new_daemon"}
    assert {m.func_ref.binary_name for m in scan(db).matches} == {"new_daemon"}


def _replaced_firmware_db(tmp_path: Path) -> Path:
    """The firmware under a workspace was replaced: the first scan held webd (1) and cfgd (2), the
    current scan holds a new webd (3) only. Each binary carries a defaults table, a static dispatch
    table and its detector status, as an extraction writes them; nothing deletes the first scan's.
    """
    db = tmp_path / "analysis.db"
    conn = open_db(db)
    for bid, name, seen in (
        (1, "webd", "2026-01-01 00:00:00"),
        (2, "cfgd", "2026-01-01 00:00:00"),
        (3, "webd", "2026-02-01 00:00:00"),
    ):
        conn.execute(
            "INSERT INTO binaries (id, name, path, sha256, last_seen_at) VALUES (?, ?, ?, ?, ?)",
            (bid, name, f"usr/sbin/{name}", str(bid) * 64, seen),
        )
        conn.execute(
            "INSERT INTO nvram_defaults (binary_id, key, default_value, flags, member_index) "
            "VALUES (?, ?, '1', 0, 0)",
            (bid, f"{name}_{bid}_key"),
        )
        conn.execute(
            "INSERT INTO string_tables (binary_id, table_addr, stride, entry_index, key, "
            "func_name, func_addr, func_kind, completeness_status) "
            "VALUES (?, '0x100', 8, 0, ?, 'handler', '0x200', 'direct', 'incomplete')",
            (bid, f"{name}_{bid}_cmd"),
        )
        conn.execute(
            "INSERT INTO detector_scan_status (binary_id, detector, scanned, found_count) "
            "VALUES (?, 'string_tables', 1, 1)",
            (bid,),
        )
    conn.execute(
        "INSERT INTO functions (binary_id, name, address, pseudocode, callees) "
        "VALUES (3, 'handle', '00001000', ?, ?)",
        (_BODY, json.dumps(["recv", "system"])),
    )
    conn.commit()
    conn.close()
    return db


@pytest.mark.parametrize(
    ("table", "sql", "expected"),
    [
        ("nvram_defaults", "SELECT binary, key FROM nvram_defaults", {("webd", "webd_3_key")}),
        (
            "string_tables",
            "SELECT binary, key FROM string_keyed_edge WHERE mechanism = 'static_string_table'",
            {("webd", "webd_3_cmd")},
        ),
        (
            "detector_scan_status",
            "SELECT binary, found_count FROM detector_scan_status WHERE detector = 'string_tables'",
            {("webd", 1)},
        ),
    ],
    ids=["nvram_defaults", "string_tables", "detector_scan_status"],
)
def test_the_hunt_carries_only_the_current_scans_tables_into_the_atlas(
    tmp_path: Path, table: str, sql: str, expected: set[tuple[object, ...]]
) -> None:
    """A replaced firmware's defaults table kept its keys reading as settable defaults of the new
    one, its dispatch tables kept answering ``get_string_keyed_edges``, and two status rows sat
    under one path. Read end to end, through the hunt, into the atlas.

    MUTATION (each measured RED on the assertion of its own case): join every binary again in
    the hunt's nvram_defaults loader -> the old webd's and cfgd's keys come back; in the
    string_tables loader -> their dispatch keys come back; in the detector-status loader -> three
    status rows instead of one (a list, not a set, so the old webd's row is not folded into the
    new one's).
    """
    from treasure_map.lib.hunt.analyzer2 import run_analyzer2

    db, atlas = _replaced_firmware_db(tmp_path), tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="r", rehunt=True)
    conn = open_atlas(atlas)
    try:
        rows = [tuple(r) for r in conn.execute(sql)]
    finally:
        conn.close()
    assert sorted(rows) == sorted(expected), (table, rows)


def test_a_database_whose_binaries_were_never_dated_reads_all_of_them(tmp_path: Path) -> None:
    """MUTATION: compare with `=` instead of `IS` (NULL = NULL is not true) -> nothing is read
    -> RED."""
    db = _db(tmp_path, (None, None))
    assert {f.binary_name for f in load_functions(db)} == {"old_daemon", "new_daemon"}
    conn = sqlite3.connect(db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM current_binaries").fetchone()[0] == 2
    finally:
        conn.close()


def test_an_existing_database_gets_the_current_view_definition(tmp_path: Path) -> None:
    """A database built with the older `=` view keeps it unless it is rebuilt on open.

    MUTATION: stop dropping the view before the schema runs -> the old view survives -> RED."""
    db = _db(tmp_path, (None, None))
    conn = sqlite3.connect(db)
    conn.execute("DROP VIEW current_binaries")
    conn.execute(
        "CREATE VIEW current_binaries AS SELECT * FROM binaries "
        "WHERE last_seen_at = (SELECT MAX(last_seen_at) FROM binaries)"
    )
    conn.commit()
    conn.close()
    open_db(db).close()
    conn = sqlite3.connect(db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM current_binaries").fetchone()[0] == 2
    finally:
        conn.close()


def test_reopening_a_database_keeps_its_script_calls(tmp_path: Path) -> None:
    """The shell-script evidence survives a reopen; only the inherited old-shape table goes.

    MUTATION: drop script_calls by name on every open again -> RED."""
    db = tmp_path / "analysis.db"
    conn = open_db(db)
    conn.execute(
        "INSERT INTO non_binary_files (id, kind, name, path) VALUES (1, 'shell_script', 'rcS', "
        "'etc/init.d/rcS')"
    )
    conn.execute(
        "INSERT INTO script_calls (file_id, command, raw_line, line_number) "
        "VALUES (1, '/usr/sbin/webd', '/usr/sbin/webd &', 3)"
    )
    conn.commit()
    conn.close()
    open_db(db).close()
    conn = sqlite3.connect(db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM script_calls").fetchone()[0] == 1
    finally:
        conn.close()


def test_the_inherited_old_shape_script_calls_is_replaced(tmp_path: Path) -> None:
    db = tmp_path / "analysis.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE script_calls (id INTEGER PRIMARY KEY, script_id INTEGER NOT NULL)")
    conn.commit()
    conn.close()
    open_db(db).close()
    conn = sqlite3.connect(db)
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(script_calls)")}
    finally:
        conn.close()
    assert "file_id" in cols and "script_id" not in cols


def test_a_fact_by_function_name_answers_from_the_current_scan(tmp_path: Path) -> None:
    """The replaced binary held a function of the same name: it must not make the answer
    ambiguous, or be the answer.

    MUTATION: join every binary again in the facts layer -> RED."""
    from treasure_map.lib import facts

    db = _db(tmp_path, ("2026-01-01 00:00:00", "2026-02-01 00:00:00"))
    conn = facts.open_analysis_ro(db)
    try:
        out = facts.get_pseudocode(conn, func="handle")
        hits = facts.get_functions_referencing_string(conn, text="recv(0")
    finally:
        conn.close()
    assert out.get("found") is True and out["anchor"]["binary"] == "new_daemon", out
    assert {h["binary"] for h in hits["functions"]} == {"new_daemon"}, hits


def test_an_analysis_db_from_before_a_late_column_still_answers(tmp_path: Path) -> None:
    """MUTATION: select f.unresolved_external_calls by name again -> OperationalError -> RED."""
    from treasure_map.lib import facts

    db = _db(tmp_path, (None, None))
    conn = sqlite3.connect(db)
    conn.execute("ALTER TABLE functions DROP COLUMN unresolved_external_calls")
    conn.commit()
    conn.close()
    conn = facts.open_analysis_ro(db)
    outcome = "ok"
    try:
        out = facts.get_pseudocode(conn, func="handle", binary="new_daemon")
    except sqlite3.OperationalError as exc:
        outcome, out = repr(exc), {}
    finally:
        conn.close()
    assert outcome == "ok" and out.get("found") is True
