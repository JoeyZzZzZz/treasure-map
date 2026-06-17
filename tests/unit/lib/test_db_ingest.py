# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import sqlite3
from pathlib import Path

from treasure_map.lib.analyze.db_ingest import ingest_elfs
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
        _make_record("httpd", "aaa111"),
        _make_record("busybox", "bbb222"),
    ]
    sha_to_id, dirty_shas = ingest_elfs(conn, records)
    assert len(sha_to_id) == 2
    assert "aaa111" in sha_to_id
    assert "bbb222" in sha_to_id

    rows = conn.execute("SELECT name, arch, sha256 FROM binaries ORDER BY name").fetchall()
    assert len(rows) == 2
    assert rows[0]["name"] == "busybox"
    assert rows[1]["arch"] == "ARM:LE:32:v7"
    conn.close()


def test_ingest_elfs_idempotent(tmp_path: Path) -> None:
    """Re-ingesting the same records must not raise or duplicate rows."""
    conn = open_db(tmp_path / "analysis.db")
    rec = _make_record("dropbear", "ccc333")
    ingest_elfs(conn, [rec])
    ingest_elfs(conn, [rec])  # second call is a no-op for the row
    count = conn.execute("SELECT COUNT(*) FROM binaries").fetchone()[0]
    assert count == 1
    conn.close()


def test_ingest_elfs_bits_extracted(tmp_path: Path) -> None:
    """bits column should be parsed from the arch string."""
    conn = open_db(tmp_path / "analysis.db")
    ingest_elfs(conn, [_make_record("foo", "ddd444", arch="MIPS:BE:32:default")])
    row = conn.execute("SELECT bits FROM binaries WHERE sha256='ddd444'").fetchone()
    assert row["bits"] == 32
    conn.close()


def test_ingest_elfs_returns_existing_ids(tmp_path: Path) -> None:
    """IDs for pre-existing rows are returned even when INSERT is a no-op."""
    conn = open_db(tmp_path / "analysis.db")
    rec = _make_record("boa", "eee555")
    ids_first, _ = ingest_elfs(conn, [rec])
    ids_second, _ = ingest_elfs(conn, [rec])
    assert ids_first["eee555"] == ids_second["eee555"]
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


# ── Round 2: new ingest_elfs behaviour ───────────────────────────────────────


def test_ingest_returns_dirty_set_for_new_records(tmp_path: Path) -> None:
    """All new records are in dirty_shas."""
    conn = open_db(tmp_path / "analysis.db")
    records = [_make_record("httpd", "aaa111"), _make_record("busybox", "bbb222")]
    _, dirty_shas = ingest_elfs(conn, records)
    assert dirty_shas == {"aaa111", "bbb222"}
    conn.close()


def test_ingest_skips_already_done_in_dirty_set(tmp_path: Path) -> None:
    """Records with ghidra_ok=1 are excluded from dirty_shas on subsequent calls."""
    conn = open_db(tmp_path / "analysis.db")
    rec = _make_record("httpd", "aaa111")

    _, dirty1 = ingest_elfs(conn, [rec])
    assert "aaa111" in dirty1

    # Simulate successful Ghidra run
    conn.execute("UPDATE binaries SET ghidra_ok=1 WHERE sha256='aaa111'")
    conn.commit()

    _, dirty2 = ingest_elfs(conn, [rec])
    assert "aaa111" not in dirty2
    conn.close()


def test_ingest_updates_last_seen_at_for_all_records(tmp_path: Path) -> None:
    """last_seen_at is set after first ingest and updated on subsequent ingests."""
    conn = open_db(tmp_path / "analysis.db")
    rec = _make_record("httpd", "aaa111")

    ingest_elfs(conn, [rec])
    ts1 = conn.execute("SELECT last_seen_at FROM binaries WHERE sha256='aaa111'").fetchone()[
        "last_seen_at"
    ]
    assert ts1 is not None

    # Manually backdate to simulate older scan
    conn.execute("UPDATE binaries SET last_seen_at='1970-01-01T00:00:00' WHERE sha256='aaa111'")
    conn.commit()

    # Second ingest should update last_seen_at
    ingest_elfs(conn, [rec])
    ts2 = conn.execute("SELECT last_seen_at FROM binaries WHERE sha256='aaa111'").fetchone()[
        "last_seen_at"
    ]
    assert ts2 is not None
    assert ts2 > "1970-01-01T00:00:00"
    conn.close()


def test_current_binaries_view_returns_only_latest_session(tmp_path: Path) -> None:
    """current_binaries view returns only rows from the most recent ingest session."""
    conn = open_db(tmp_path / "analysis.db")
    rec1 = _make_record("httpd", "aaa111")
    rec2 = _make_record("busybox", "bbb222")

    ingest_elfs(conn, [rec1, rec2])

    # Backdate rec2 to simulate it being from an older scan
    conn.execute("UPDATE binaries SET last_seen_at='2020-01-01T00:00:00' WHERE sha256='bbb222'")
    conn.commit()

    current = {row["name"] for row in conn.execute("SELECT name FROM current_binaries").fetchall()}
    assert current == {"httpd"}
    conn.close()


def test_ingest_writes_size_bytes(tmp_path: Path) -> None:
    """size_bytes is written from rec.size."""
    conn = open_db(tmp_path / "analysis.db")
    rec = _make_record("httpd", "aaa111")  # _make_record sets size=4096
    ingest_elfs(conn, [rec])
    row = conn.execute("SELECT size_bytes FROM binaries WHERE sha256='aaa111'").fetchone()
    assert row["size_bytes"] == 4096
    conn.close()
