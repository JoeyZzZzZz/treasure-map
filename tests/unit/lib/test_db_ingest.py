# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from treasure_map.lib.analyze.db_ingest import REANALYZE_ALL, ingest_elfs
from treasure_map.lib.analyze.elf_inventory import ElfRecord
from treasure_map.lib.storage.connection import _SCHEMA_PATH, open_db


def _make_record(name: str, sha: str, arch: str = "ARM:LE:32:v7") -> ElfRecord:
    return ElfRecord(
        path=Path(f"/fake/bin/{name}"),
        name=name,
        arch=arch,
        elf_type="executable",
        sha256=sha,
        dt_needed=["libc.so.0"],
        protections={"nx": True, "pie": False, "canary": False, "relro": "none", "fortify": False},
        size=4096,
    )


def test_ingest_elfs_round_trip(tmp_path: Path) -> None:
    conn = open_db(tmp_path / "analysis.db")
    records = [
        _make_record("httpd", "deadbeef"),
        _make_record("busybox", "cafebabe"),
    ]
    sha_to_id, dirty_shas = ingest_elfs(conn, records)
    assert len(sha_to_id) == 2
    assert "deadbeef" in sha_to_id
    assert "cafebabe" in sha_to_id

    rows = conn.execute("SELECT name, arch, sha256 FROM binaries ORDER BY name").fetchall()
    assert len(rows) == 2
    assert rows[0]["name"] == "busybox"
    assert rows[1]["arch"] == "ARM:LE:32:v7"
    conn.close()


def test_ingest_elfs_idempotent(tmp_path: Path) -> None:
    """Re-ingesting the same records must not raise or duplicate rows."""
    conn = open_db(tmp_path / "analysis.db")
    rec = _make_record("dropbear", "feedface")
    ingest_elfs(conn, [rec])
    ingest_elfs(conn, [rec])  # second call is a no-op for the row
    count = conn.execute("SELECT COUNT(*) FROM binaries").fetchone()[0]
    assert count == 1
    conn.close()


def test_ingest_elfs_bits_extracted(tmp_path: Path) -> None:
    """bits column should be parsed from the arch string."""
    conn = open_db(tmp_path / "analysis.db")
    ingest_elfs(conn, [_make_record("foo", "baddcafe", arch="MIPS:BE:32:default")])
    row = conn.execute("SELECT bits FROM binaries WHERE sha256='baddcafe'").fetchone()
    assert row["bits"] == 32
    conn.close()


def test_ingest_elfs_returns_existing_ids(tmp_path: Path) -> None:
    """IDs for pre-existing rows are returned even when INSERT is a no-op."""
    conn = open_db(tmp_path / "analysis.db")
    rec = _make_record("boa", "deadfeed")
    ids_first, _ = ingest_elfs(conn, [rec])
    ids_second, _ = ingest_elfs(conn, [rec])
    assert ids_first["deadfeed"] == ids_second["deadfeed"]
    conn.close()


def test_ingest_empty_list(tmp_path: Path) -> None:
    conn = open_db(tmp_path / "analysis.db")
    sha_to_id, dirty_shas = ingest_elfs(conn, [])
    assert sha_to_id == {}
    assert dirty_shas == set()
    conn.close()


def test_open_db_creates_schema(tmp_path: Path) -> None:
    conn = open_db(tmp_path / "new.db")
    tables = {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    assert "binaries" in tables
    assert "functions" in tables
    assert "xrefs" in tables
    conn.close()


# ── R-cleanup: dropped pre-judgment columns/tables + idempotent migration ─────


def _functions_columns(conn: sqlite3.Connection) -> set[str]:
    return {row[1] for row in conn.execute("PRAGMA table_info(functions)")}


def test_fresh_schema_omits_dropped_columns(tmp_path: Path) -> None:
    """A newly created db carries none of the removed pre-judgment fields/tables,
    but keeps the binary-level capa_tags placeholder."""
    conn = open_db(tmp_path / "new.db")
    fcols = _functions_columns(conn)
    for gone in ("summary", "func_types", "vuln_hints", "capa_tags"):
        assert gone not in fcols
    for table, col in (
        ("script_calls", "has_user_input"),
        ("script_calls", "vuln_hint"),
        ("config_entries", "vuln_hint"),
        ("credentials", "vuln_hint"),
        ("web_endpoints", "vuln_hint"),
    ):
        cols = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        assert col not in cols, f"{table}.{col} should be gone"

    no_libsum = conn.execute(
        "SELECT name FROM sqlite_master WHERE name='library_summaries'"
    ).fetchone()
    assert no_libsum is None

    bcols = {row[1] for row in conn.execute("PRAGMA table_info(binaries)")}
    assert "capa_tags" in bcols  # binary-level placeholder is retained
    conn.close()


def _build_pre_cleanup_db(db_path: Path) -> None:
    """Create a db shaped like one built before R-cleanup: current schema plus the
    columns/table/indexes this round removes, then a row of real data in each."""
    conn = sqlite3.connect(db_path)
    conn.executescript(_SCHEMA_PATH.read_text())
    conn.executescript(
        """
        ALTER TABLE functions ADD COLUMN summary TEXT;
        ALTER TABLE functions ADD COLUMN func_types TEXT DEFAULT '[]';
        ALTER TABLE functions ADD COLUMN vuln_hints TEXT DEFAULT '[]';
        ALTER TABLE functions ADD COLUMN capa_tags TEXT DEFAULT '[]';
        CREATE INDEX idx_functions_summary ON functions(summary);
        CREATE INDEX idx_functions_types   ON functions(func_types);
        CREATE INDEX idx_functions_vuln    ON functions(vuln_hints);
        CREATE TABLE library_summaries (id INTEGER PRIMARY KEY, purpose TEXT);
        ALTER TABLE script_calls  ADD COLUMN has_user_input INTEGER DEFAULT 0;
        ALTER TABLE script_calls  ADD COLUMN vuln_hint TEXT;
        CREATE INDEX idx_script_calls_ui ON script_calls(has_user_input);
        ALTER TABLE config_entries ADD COLUMN vuln_hint TEXT;
        CREATE INDEX idx_config_entries_hint ON config_entries(vuln_hint);
        ALTER TABLE credentials    ADD COLUMN vuln_hint TEXT;
        CREATE INDEX idx_credentials_hint ON credentials(vuln_hint);
        ALTER TABLE web_endpoints  ADD COLUMN vuln_hint TEXT;
        CREATE INDEX idx_web_endpoints_hint ON web_endpoints(vuln_hint);
        """
    )
    conn.execute("INSERT INTO binaries(name, capa_tags) VALUES('busybox', '[\"x\"]')")
    conn.execute(
        "INSERT INTO functions(binary_id, name, summary, func_types, callees) "
        "VALUES(1, 'main', 'one-liner', '[]', '[\"helper\"]')"
    )
    conn.execute("INSERT INTO library_summaries(purpose) VALUES('p')")
    conn.commit()
    conn.close()


def test_migration_drops_stale_columns_and_preserves_data(tmp_path: Path) -> None:
    db_path = tmp_path / "old.db"
    _build_pre_cleanup_db(db_path)

    conn = open_db(db_path)  # triggers _migrate

    fcols = _functions_columns(conn)
    for gone in ("summary", "func_types", "vuln_hints", "capa_tags"):
        assert gone not in fcols
    assert {"name", "callees", "binary_id"} <= fcols  # surviving columns intact

    # rows preserved through the column drops
    frow = conn.execute("SELECT name, callees FROM functions").fetchone()
    assert frow["name"] == "main"
    assert frow["callees"] == '["helper"]'
    brow = conn.execute("SELECT capa_tags FROM binaries").fetchone()
    assert brow["capa_tags"] == '["x"]'  # binary capa_tags retained with its value

    assert (
        conn.execute("SELECT name FROM sqlite_master WHERE name='library_summaries'").fetchone()
        is None
    )
    stale_indexes = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name IN "
        "('idx_functions_summary','idx_functions_types','idx_functions_vuln',"
        "'idx_script_calls_ui','idx_config_entries_hint','idx_credentials_hint',"
        "'idx_web_endpoints_hint')"
    ).fetchall()
    assert stale_indexes == []
    conn.close()


def test_migration_is_idempotent(tmp_path: Path) -> None:
    db_path = tmp_path / "old.db"
    _build_pre_cleanup_db(db_path)
    open_db(db_path).close()  # first migration
    conn = open_db(db_path)  # re-run must not raise and leaves schema stable
    fcols = _functions_columns(conn)
    assert "summary" not in fcols
    assert "name" in fcols
    assert conn.execute("SELECT name FROM functions").fetchone()["name"] == "main"
    conn.close()


def test_migration_adds_ghidra_status_to_old_db(tmp_path: Path) -> None:
    # ★ Red-line upgrade path: a database predating the tri-state column must gain it on open, so
    # the self-heal and the degrade-visibility query work for existing users without a rebuild.
    db_path = tmp_path / "legacy.db"
    raw = sqlite3.connect(db_path)
    raw.execute(
        "CREATE TABLE binaries (id INTEGER PRIMARY KEY, name TEXT, sha256 TEXT UNIQUE, "
        "ghidra_ok INTEGER NOT NULL DEFAULT 0)"
    )
    raw.commit()
    raw.close()
    conn = open_db(db_path)  # triggers the additive migration
    cols = {row[1] for row in conn.execute("PRAGMA table_info(binaries)")}
    assert "ghidra_status" in cols
    conn.close()


def _legacy_functions_db(db_path: Path) -> None:
    """A functions table with the pre-sink_provenance columns (simulates an old analysis.db)."""
    raw = sqlite3.connect(db_path)
    raw.execute(
        "CREATE TABLE functions (id INTEGER PRIMARY KEY, binary_id INTEGER, name TEXT, "
        "address TEXT, size_bytes INTEGER, pseudocode TEXT, pseudocode_hash TEXT, "
        "callees TEXT DEFAULT '[]', is_exported INTEGER DEFAULT 0)"
    )
    raw.execute(
        "INSERT INTO functions (id, binary_id, name, address) VALUES (1, 7, 'main', '0x1000')"
    )
    raw.commit()
    raw.close()


def test_migration_adds_sink_provenance_to_old_db(tmp_path: Path) -> None:
    # ★ Regression: 25041e9 added functions.sink_provenance to schema.sql (new DBs) but not to
    # _ADDED_COLUMNS (old DBs), so CREATE TABLE IF NOT EXISTS left the column missing on any
    # pre-existing analysis.db and ghidra_ingest crashed with "no column named sink_provenance".
    # A database built before the column must gain it on open, with existing rows preserved.
    db_path = tmp_path / "legacy.db"
    _legacy_functions_db(db_path)
    conn = open_db(db_path)  # triggers the additive migration
    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(functions)")}
        assert "sink_provenance" in cols
        # existing data survives and the new column back-fills to the '[]' default
        row = conn.execute("SELECT name, sink_provenance FROM functions WHERE id = 1").fetchone()
        assert row["name"] == "main"
        assert row["sink_provenance"] == "[]"
    finally:
        conn.close()


def test_migration_sink_provenance_is_idempotent(tmp_path: Path) -> None:
    # Re-running the migration on a DB that already has the column must not raise or duplicate it.
    db_path = tmp_path / "legacy2.db"
    _legacy_functions_db(db_path)
    open_db(db_path).close()  # first migration adds the column
    conn = open_db(db_path)  # second run must be a no-op
    try:
        cols = [row[1] for row in conn.execute("PRAGMA table_info(functions)")]
        assert cols.count("sink_provenance") == 1  # added exactly once, never duplicated
    finally:
        conn.close()


# ── Round 2: new ingest_elfs behaviour ───────────────────────────────────────


def test_ingest_returns_dirty_set_for_new_records(tmp_path: Path) -> None:
    """All new records are in dirty_shas."""
    conn = open_db(tmp_path / "analysis.db")
    records = [_make_record("httpd", "deadbeef"), _make_record("busybox", "cafebabe")]
    _, dirty_shas = ingest_elfs(conn, records)
    assert dirty_shas == {"deadbeef", "cafebabe"}
    conn.close()


def test_ingest_skips_already_done_in_dirty_set(tmp_path: Path) -> None:
    """Records with ghidra_ok=1 are excluded from dirty_shas on subsequent calls."""
    conn = open_db(tmp_path / "analysis.db")
    rec = _make_record("httpd", "deadbeef")

    _, dirty1 = ingest_elfs(conn, [rec])
    assert "deadbeef" in dirty1

    # Simulate successful Ghidra run
    conn.execute("UPDATE binaries SET ghidra_ok=1 WHERE sha256='deadbeef'")
    conn.commit()

    _, dirty2 = ingest_elfs(conn, [rec])
    assert "deadbeef" not in dirty2
    conn.close()


_DB_INGEST = "treasure_map.lib.analyze.db_ingest.has_substantial_text"


def _mark_done_with_functions(conn: sqlite3.Connection) -> None:
    conn.execute("UPDATE binaries SET ghidra_ok=1, ghidra_status='ok'")
    conn.execute("INSERT INTO functions (binary_id, name) SELECT id, 'f' FROM binaries")
    conn.commit()


def test_reanalyze_all_forces_every_binary_dirty(tmp_path: Path) -> None:
    conn = open_db(tmp_path / "analysis.db")
    recs = [_make_record("httpd", "deadbeef"), _make_record("rc", "cafebabe")]
    ingest_elfs(conn, recs)
    _mark_done_with_functions(conn)  # both done + have functions -> normally cached
    _, dirty = ingest_elfs(conn, recs, reanalyze=REANALYZE_ALL)
    assert dirty == {"deadbeef", "cafebabe"}  # escape hatch re-runs everything
    conn.close()


def test_reanalyze_by_name_forces_only_that_binary(tmp_path: Path) -> None:
    conn = open_db(tmp_path / "analysis.db")
    recs = [_make_record("httpd", "deadbeef"), _make_record("rc", "cafebabe")]
    ingest_elfs(conn, recs)
    _mark_done_with_functions(conn)
    _, dirty = ingest_elfs(conn, recs, reanalyze="rc")
    assert dirty == {"cafebabe"}  # only the named binary re-runs
    conn.close()


def test_self_heal_redirties_zero_function_code_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ★ Red-line self-heal: a row claiming done (ghidra_ok=1) but holding 0 functions despite real
    # code is a frozen bad state — re-dirtied so a re-run recovers it, without deleting the DB.
    conn = open_db(tmp_path / "analysis.db")
    rec = _make_record("rc", "deadbeef")
    ingest_elfs(conn, [rec])
    conn.execute("UPDATE binaries SET ghidra_ok=1, ghidra_status='ok' WHERE sha256='deadbeef'")
    conn.commit()  # no functions inserted -> the bad frozen state
    monkeypatch.setattr(_DB_INGEST, lambda _p: True)  # binary has code
    _, dirty = ingest_elfs(conn, [rec])
    assert "deadbeef" in dirty
    conn.close()


def test_self_heal_backfills_ok_empty_for_codefree_object(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A genuinely code-free done row (0 functions, no substantial .text) stays done and is marked
    # ok_empty so it is never flagged incomplete or needlessly re-analyzed.
    conn = open_db(tmp_path / "analysis.db")
    rec = _make_record("data.so", "deadbeef")
    ingest_elfs(conn, [rec])
    conn.execute("UPDATE binaries SET ghidra_ok=1 WHERE sha256='deadbeef'")  # legacy NULL status
    conn.commit()
    monkeypatch.setattr(_DB_INGEST, lambda _p: False)  # code-free
    _, dirty = ingest_elfs(conn, [rec])
    assert "deadbeef" not in dirty
    row = conn.execute("SELECT ghidra_status FROM binaries WHERE sha256='deadbeef'").fetchone()
    assert row[0] == "ok_empty"
    conn.close()


def test_ingest_updates_last_seen_at_for_all_records(tmp_path: Path) -> None:
    """last_seen_at is set after first ingest and updated on subsequent ingests."""
    conn = open_db(tmp_path / "analysis.db")
    rec = _make_record("httpd", "deadbeef")

    ingest_elfs(conn, [rec])
    ts1 = conn.execute("SELECT last_seen_at FROM binaries WHERE sha256='deadbeef'").fetchone()[
        "last_seen_at"
    ]
    assert ts1 is not None

    # Manually backdate to simulate older scan
    conn.execute("UPDATE binaries SET last_seen_at='1970-01-01T00:00:00' WHERE sha256='deadbeef'")
    conn.commit()

    # Second ingest should update last_seen_at
    ingest_elfs(conn, [rec])
    ts2 = conn.execute("SELECT last_seen_at FROM binaries WHERE sha256='deadbeef'").fetchone()[
        "last_seen_at"
    ]
    assert ts2 is not None
    assert ts2 > "1970-01-01T00:00:00"
    conn.close()


def test_current_binaries_view_returns_only_latest_session(tmp_path: Path) -> None:
    """current_binaries view returns only rows from the most recent ingest session."""
    conn = open_db(tmp_path / "analysis.db")
    rec1 = _make_record("httpd", "deadbeef")
    rec2 = _make_record("busybox", "cafebabe")

    ingest_elfs(conn, [rec1, rec2])

    # Backdate rec2 to simulate it being from an older scan
    conn.execute("UPDATE binaries SET last_seen_at='2020-01-01T00:00:00' WHERE sha256='cafebabe'")
    conn.commit()

    current = {row["name"] for row in conn.execute("SELECT name FROM current_binaries").fetchall()}
    assert current == {"httpd"}
    conn.close()


def test_ingest_writes_size_bytes(tmp_path: Path) -> None:
    """size_bytes is written from rec.size."""
    conn = open_db(tmp_path / "analysis.db")
    rec = _make_record("httpd", "deadbeef")  # _make_record sets size=4096
    ingest_elfs(conn, [rec])
    row = conn.execute("SELECT size_bytes FROM binaries WHERE sha256='deadbeef'").fetchone()
    assert row["size_bytes"] == 4096
    conn.close()
