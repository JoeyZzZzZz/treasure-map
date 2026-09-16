# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
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


def test_migration_adds_nvram_ops_to_old_db(tmp_path: Path) -> None:
    # gap②: functions.nvram_ops was added to schema.sql AND _ADDED_COLUMNS together. A database
    # built before it must gain the column on open (back-filling '[]'), so ghidra_ingest can write
    # it without "no column named nvram_ops"; existing rows are preserved.
    db_path = tmp_path / "legacy_nvram.db"
    _legacy_functions_db(db_path)
    conn = open_db(db_path)
    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(functions)")}
        assert "nvram_ops" in cols
        row = conn.execute("SELECT name, nvram_ops FROM functions WHERE id = 1").fetchone()
        assert row["name"] == "main"
        assert row["nvram_ops"] == "[]"
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


def _mark_done_with_pass_version(conn: sqlite3.Connection, sha: str, pv: str) -> None:
    conn.execute(
        "UPDATE binaries SET ghidra_ok=1, ghidra_status='ok', pass_version=? WHERE sha256=?",
        (pv, sha),
    )
    conn.commit()


def test_ingest_pass_version_unchanged_stays_cached(tmp_path: Path) -> None:
    # Fix A: a binary analyzed by the CURRENT pass is a cache hit — normal incremental scans stay
    # fast when the extraction pass has not changed.
    conn = open_db(tmp_path / "analysis.db")
    rec = _make_record("httpd", "deadbeef")
    ingest_elfs(conn, [rec], pass_version="passv1")
    _mark_done_with_pass_version(conn, "deadbeef", "passv1")

    _, dirty = ingest_elfs(conn, [rec], pass_version="passv1")
    assert "deadbeef" not in dirty  # same pass -> skip (no re-extraction)
    conn.close()


def test_ingest_pass_version_change_redirties_without_deletion(tmp_path: Path) -> None:
    # Fix A core: editing the extraction pass (new pass_version) re-dirties an already-done binary
    # even though sha256 and ghidra_ok are unchanged — no manual JSON/db deletion needed.
    conn = open_db(tmp_path / "analysis.db")
    rec = _make_record("httpd", "deadbeef")
    ingest_elfs(conn, [rec], pass_version="passv1")
    _mark_done_with_pass_version(conn, "deadbeef", "passv1")

    _, dirty = ingest_elfs(conn, [rec], pass_version="passv2")
    assert "deadbeef" in dirty  # pass changed -> re-extract automatically
    conn.close()


def test_ingest_null_pass_version_redirties_once(tmp_path: Path) -> None:
    # Upgrade path: a row analyzed before Fix A has pass_version=NULL ("unknown pass"), so the first
    # pass-aware scan re-extracts it once; after it is stamped, the same pass is a cache hit.
    conn = open_db(tmp_path / "analysis.db")
    rec = _make_record("httpd", "deadbeef")
    ingest_elfs(conn, [rec])  # legacy call: no pass_version -> stored NULL
    conn.execute("UPDATE binaries SET ghidra_ok=1, ghidra_status='ok' WHERE sha256='deadbeef'")
    conn.commit()

    _, dirty1 = ingest_elfs(conn, [rec], pass_version="passv1")
    assert "deadbeef" in dirty1  # NULL != current -> one-time re-extraction

    _mark_done_with_pass_version(conn, "deadbeef", "passv1")
    _, dirty2 = ingest_elfs(conn, [rec], pass_version="passv1")
    assert "deadbeef" not in dirty2  # now stamped -> cached


def test_migration_adds_pass_version_to_old_db(tmp_path: Path) -> None:
    # Fix A upgrade path: a binaries table predating pass_version must gain it on open (schema.sql +
    # _ADDED_COLUMNS both changed), preserving existing rows.
    db_path = tmp_path / "legacy.db"
    raw = sqlite3.connect(db_path)
    raw.execute(
        "CREATE TABLE binaries (id INTEGER PRIMARY KEY, name TEXT, sha256 TEXT UNIQUE, "
        "ghidra_ok INTEGER NOT NULL DEFAULT 0)"
    )
    raw.execute("INSERT INTO binaries (id, name, sha256, ghidra_ok) VALUES (1, 'httpd', 'ab', 1)")
    raw.commit()
    raw.close()
    conn = open_db(db_path)  # triggers the additive migration
    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(binaries)")}
        assert "pass_version" in cols
        row = conn.execute("SELECT name, pass_version FROM binaries WHERE id = 1").fetchone()
        assert row["name"] == "httpd" and row["pass_version"] is None  # back-fills NULL
    finally:
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


def test_reanalyze_name_scopes_over_pass_version_staleness(tmp_path: Path) -> None:
    # ★ The A + --reanalyze interaction: after editing the extraction pass (pass_version bumped),
    # Fix A marks EVERY binary stale. --reanalyze <name> must still re-run ONLY the named binary,
    # not the whole firmware — this is the fast iteration path. A subtractive "drop from
    # already_done" could not do this (A empties already_done), so targeting is required.
    conn = open_db(tmp_path / "analysis.db")
    recs = [_make_record("httpd", "deadbeef"), _make_record("rc", "cafebabe")]
    ingest_elfs(conn, recs, pass_version="passv1")
    _mark_done_with_functions(conn)  # both done under passv1
    conn.execute("UPDATE binaries SET pass_version='passv1'")
    conn.commit()

    # pass edited -> passv2: A alone would make BOTH dirty; --reanalyze rc must scope to rc only.
    _, dirty = ingest_elfs(conn, recs, reanalyze="rc", pass_version="passv2")
    assert dirty == {"cafebabe"}  # only rc, despite httpd also being pass-stale
    conn.close()


def test_reanalyze_name_ignores_other_new_binaries(tmp_path: Path) -> None:
    # Targeting means ONLY the match runs, even ignoring a genuinely-new (never-analyzed) binary.
    conn = open_db(tmp_path / "analysis.db")
    recs = [_make_record("rc", "cafebabe"), _make_record("newcomer", "0badf00d")]
    _, dirty = ingest_elfs(conn, recs, reanalyze="rc", pass_version="passv1")
    assert dirty == {"cafebabe"}  # the new binary is deliberately skipped under a scoped re-run
    conn.close()


def test_reanalyze_name_no_match_runs_nothing(tmp_path: Path) -> None:
    # A name matching no binary re-runs nothing (scoped to an empty set), rather than falling back
    # to "all stale" — the warning is logged so a typo does not silently masquerade as success.
    conn = open_db(tmp_path / "analysis.db")
    recs = [_make_record("httpd", "deadbeef"), _make_record("rc", "cafebabe")]
    _, dirty = ingest_elfs(conn, recs, reanalyze="does_not_exist", pass_version="passv1")
    assert dirty == set()
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


def test_self_heal_redirties_code_binary_wrongly_frozen_as_ok_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ★ THE silent-stale bug (real-firmware, reproduced): ghidra_status='ok_empty' was TRUSTED
    # forever, but it is derived from has_substantial_text, which returns False on any read error —
    # so a code-rich binary whose file was momentarily unreadable at analysis time (a temp/cpio
    # extraction cleaned, a migration, a race) got frozen as "legitimately empty". Every honesty net
    # then skipped it by trusting the stale label: it read as done+clean with 0 functions, silently,
    # forever. The current file — code-rich NOW — must OVERRIDE the stale label and re-dirty it.
    conn = open_db(tmp_path / "analysis.db")
    rec = _make_record("httpd", "deadbeef")
    ingest_elfs(conn, [rec])
    conn.execute(
        "UPDATE binaries SET ghidra_ok=1, ghidra_status='ok_empty' WHERE sha256='deadbeef'"
    )
    conn.commit()  # frozen: cached done, 0 functions, mislabeled ok_empty
    monkeypatch.setattr(_DB_INGEST, lambda _p: True)  # the file IS code-rich this scan
    _, dirty = ingest_elfs(conn, [rec])
    assert "deadbeef" in dirty  # re-dirtied despite the stale ok_empty — no longer silent


def test_ok_empty_is_reverified_not_trusted_when_file_stays_codefree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The other side of the same coin (acceptance #3): re-verifying ok_empty must NOT churn a
    # genuinely code-free object. Its file is still code-free this scan -> stays cached, stays
    # ok_empty, never re-analyzed. (Re-verification is authoritative, but authority cuts both ways.)
    conn = open_db(tmp_path / "analysis.db")
    rec = _make_record("data.so", "deadbeef")
    ingest_elfs(conn, [rec])
    conn.execute(
        "UPDATE binaries SET ghidra_ok=1, ghidra_status='ok_empty' WHERE sha256='deadbeef'"
    )
    conn.commit()
    monkeypatch.setattr(_DB_INGEST, lambda _p: False)  # still genuinely code-free
    _, dirty = ingest_elfs(conn, [rec])
    assert "deadbeef" not in dirty  # a real empty is never churned
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


def _rec_at(name: str, sha: str, path: Path) -> ElfRecord:
    return ElfRecord(
        path=path,
        name=name,
        arch="ARM:LE:32:v7",
        elf_type="shared_library",
        sha256=sha,
        dt_needed=[],
        protections={"nx": True, "pie": False, "canary": False, "relro": "none", "fortify": False},
        size=4096,
    )


def test_cached_rescan_refreshes_binaries_path(tmp_path: Path) -> None:
    # ★ A cached re-scan (same sha256) must pick up the CURRENT scan's path. Step 2's INSERT OR
    # IGNORE leaves the existing row untouched, so the path is refreshed only by Step 3's UPDATE.
    # Without that, a relative path an earlier scan wrote stays frozen and a cross-directory
    # `tmap diff` cannot locate the .so. ★ Reverting the `path = ?` addition to Step 3 reds this.
    conn = open_db(tmp_path / "analysis.db")
    rel = Path("../fw/lib.so")  # the old, frozen-relative state (from a scan in a different cwd)
    absolute = (tmp_path / "fw" / "lib.so").resolve()

    ingest_elfs(conn, [_rec_at("lib.so", "facefeed", rel)])  # earlier scan: relative path
    conn.execute("UPDATE binaries SET ghidra_ok = 1 WHERE sha256 = 'facefeed'")  # cached/done
    conn.commit()
    before = conn.execute(
        "SELECT path, last_seen_at FROM binaries WHERE sha256 = 'facefeed'"
    ).fetchone()
    assert before["path"] == str(rel) and not Path(before["path"]).is_absolute()  # frozen-relative

    # cached re-scan (same sha256 -> already_done, not re-run) carrying the CURRENT absolute path
    _, dirty = ingest_elfs(conn, [_rec_at("lib.so", "facefeed", absolute)])
    assert "facefeed" not in dirty  # genuinely cached, Ghidra not re-run

    after = conn.execute(
        "SELECT path, last_seen_at, ghidra_ok FROM binaries WHERE sha256 = 'facefeed'"
    ).fetchone()
    assert Path(after["path"]).is_absolute()  # ★ the fix: cached row picked up the absolute path
    assert after["path"] == str(absolute)  # exactly the current scan's path
    assert after["ghidra_ok"] == 1  # non-regression: the cached row is not churned
    assert after["last_seen_at"] >= before["last_seen_at"]  # non-regression: last_seen_at refreshed
    assert conn.execute("SELECT COUNT(*) FROM binaries").fetchone()[0] == 1  # no duplicate row
    conn.close()


# ── a timeout is deterministic: do not re-run it at a budget that already answered ────
#
# The cost this exists to stop, measured on real firmware: one 14MB binary that times out is
# re-attempted on every scan, burning the full isolated-retry budget each time to re-learn what
# the previous scan already recorded. Nothing about the attempt differs, so neither does the
# result. What follows is the set of things that CAN differ, each with its own test.

_BASE = 300  # config.ghidra.headless_timeout_seconds — the default, and the value in use
# The measured size of the real binary this change came from: 14.1MB, whose budget works out to
# 846s against an 1800s ceiling. Used verbatim so the "raising the ceiling changes nothing here"
# case below is the actual case, not a rounded stand-in for it.
_REAL_TIMED_OUT_SIZE = 14789215
# Over 30MB at base 300, which is where the doubled budget passes the ceiling and the ceiling
# starts to bind. Derived, not picked: 2 * int(300 * mb / 10) > 1800  ->  mb > 30.
_CEILING_BOUND_SIZE = 31 * 1024 * 1024


def _sized_file(tmp_path: Path, name: str, size_bytes: int) -> Path:
    """A file that exists only to have a SIZE. Sparse, so a 31MB fixture costs no disk.

    Real bytes are needed because the budget is computed from ``stat().st_size`` — a fabricated
    size would test the arithmetic and not the reading of it."""
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("wb") as fh:
        fh.truncate(size_bytes)
    return p


def _rec_for(path: Path, sha: str) -> ElfRecord:
    return ElfRecord(
        path=path,
        name=path.name,
        arch="ARM:LE:32:v7",
        elf_type="executable",
        sha256=sha,
        dt_needed=[],
        protections={},
        size=path.stat().st_size,
    )


def _record_failure(
    conn: sqlite3.Connection,
    sha: str,
    *,
    budget: int | None,
    pass_version: str | None,
    reason: str = "timeout",
) -> None:
    """Put a row in the state the pipeline leaves a failed attempt in."""
    conn.execute(
        "UPDATE binaries SET ghidra_ok=0, ghidra_status='failed', ghidra_status_reason=?, "
        "timeout_budget=?, timeout_pass_version=? WHERE sha256=?",
        (reason, budget, pass_version, sha),
    )
    conn.commit()


def _timed_out_at_current_budget(
    tmp_path: Path, size_bytes: int
) -> tuple[sqlite3.Connection, ElfRecord, int]:
    """A DB holding one binary that timed out at exactly the budget this scan would hand it."""
    from treasure_map.lib.analyze.ghidra_runner import retry_budget_seconds

    conn = open_db(tmp_path / "analysis.db")
    rec = _rec_for(_sized_file(tmp_path, "big_daemon", size_bytes), "deadbeef")
    ingest_elfs(conn, [rec], pass_version="p1", timeout_base=_BASE)
    budget = retry_budget_seconds(rec.path, _BASE)
    assert budget is not None
    _record_failure(conn, rec.sha256, budget=budget, pass_version="p1")
    return conn, rec, budget


def test_a_timeout_at_a_budget_this_scan_repeats_is_not_re_run(tmp_path: Path) -> None:
    """★ THE property. Same bytes, same extractor, same budget — so the same failure.

    Before this, a ``ghidra_ok=0`` row was dirty unconditionally, and a timeout is a ghidra_ok=0
    row. The re-run was guaranteed to end where the last one did; the only thing it produced was
    the wall-clock it consumed.

    MUTATION (must go RED): drop the skip from the dirty set (every ghidra_ok=0 row dirty again)."""
    conn, rec, _budget = _timed_out_at_current_budget(tmp_path, _REAL_TIMED_OUT_SIZE)
    _, dirty = ingest_elfs(conn, [rec], pass_version="p1", timeout_base=_BASE)
    assert rec.sha256 not in dirty
    conn.close()


def test_more_time_than_it_had_makes_the_retry_a_different_attempt(tmp_path: Path) -> None:
    """★ The load-bearing half: the skip must not outlive the reason for it.

    A raised ceiling means the binary would now get MORE than it failed under, so the next attempt
    is not the one that already happened. Getting this wrong is worse than not skipping at all: the
    binary would be frozen out of every future scan no matter how much time it was offered.

    ★ The fixture is deliberately CEILING-BOUND, asserted below rather than assumed. The budget is
    ``min(ceiling, 2 * scaled)``, so raising the ceiling only moves it for a binary whose doubled
    scaled budget the ceiling was actually clipping. On a smaller binary — the real 14MB one that
    prompted all this, whose budget is 846s against an 1800s ceiling — raising the ceiling changes
    nothing and NOT re-running is the correct answer. A test built on that binary would pass while
    testing nothing, which is why the control case below is here too.

    MUTATION (must go RED): compare against the phase-1 ``_dynamic_timeout`` instead of the
    isolated-retry budget — ``min(ceiling, scaled)`` does not move when the ceiling rises, so the
    binary stays skipped forever."""
    from treasure_map.lib.analyze import ghidra_runner
    from treasure_map.lib.analyze.ghidra_runner import _scaled_timeout

    conn, rec, budget = _timed_out_at_current_budget(tmp_path, _CEILING_BOUND_SIZE)
    size = rec.path.stat().st_size
    assert _scaled_timeout(size, _BASE) * 2 > ghidra_runner._TIMEOUT_CEILING_SECONDS, (
        "fixture is not ceiling-bound — raising the ceiling would legitimately not change its "
        "budget, and this test would pass without exercising anything"
    )
    assert budget == ghidra_runner._TIMEOUT_CEILING_SECONDS

    _, before = ingest_elfs(conn, [rec], pass_version="p1", timeout_base=_BASE)
    assert rec.sha256 not in before  # skipped at the old ceiling

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(ghidra_runner, "_TIMEOUT_CEILING_SECONDS", 2400)
        _, after = ingest_elfs(conn, [rec], pass_version="p1", timeout_base=_BASE)
    assert rec.sha256 in after  # ...and re-attempted once the ceiling is raised
    conn.close()


def test_a_raised_ceiling_that_changes_no_budget_changes_no_decision(tmp_path: Path) -> None:
    """The control for the test above, and the reason it needs a 31MB fixture.

    A binary well under the ceiling has a budget the ceiling is not clipping, so raising the ceiling
    hands it nothing new and skipping it stays right. Stated as a test because the tempting fixture
    — the real 14MB binary this whole change came from — behaves exactly this way, and a
    self-healing test written on it would be green without a self-heal behind it."""
    from treasure_map.lib.analyze import ghidra_runner
    from treasure_map.lib.analyze.ghidra_runner import _scaled_timeout

    conn, rec, budget = _timed_out_at_current_budget(tmp_path, _REAL_TIMED_OUT_SIZE)
    assert _scaled_timeout(rec.path.stat().st_size, _BASE) * 2 < 1800  # not ceiling-bound
    assert budget == 846

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(ghidra_runner, "_TIMEOUT_CEILING_SECONDS", 2400)
        _, dirty = ingest_elfs(conn, [rec], pass_version="p1", timeout_base=_BASE)
    assert rec.sha256 not in dirty
    conn.close()


def test_a_larger_base_timeout_re_runs_it(tmp_path: Path) -> None:
    """The other way the budget grows: the configured base. Same rule, no special case for it."""
    conn, rec, _budget = _timed_out_at_current_budget(tmp_path, _REAL_TIMED_OUT_SIZE)
    _, same = ingest_elfs(conn, [rec], pass_version="p1", timeout_base=_BASE)
    assert rec.sha256 not in same
    _, bigger = ingest_elfs(conn, [rec], pass_version="p1", timeout_base=_BASE * 2)
    assert rec.sha256 in bigger
    conn.close()


def test_an_edited_extractor_re_runs_it(tmp_path: Path) -> None:
    """A pass edit changes what the attempt would DO, so the old timeout stops answering for it.

    This needs its own recorded fingerprint: a row's ``pass_version`` describes the output it
    produced, and a failed attempt produces none, so the pipeline deliberately leaves that column
    alone on failure. Reading it here would find NULL on every timeout and the skip would never
    fire at all.

    MUTATION (must go RED): skip regardless of the recorded fingerprint."""
    conn, rec, _budget = _timed_out_at_current_budget(tmp_path, _REAL_TIMED_OUT_SIZE)
    _, unchanged = ingest_elfs(conn, [rec], pass_version="p1", timeout_base=_BASE)
    assert rec.sha256 not in unchanged
    _, edited = ingest_elfs(conn, [rec], pass_version="p2", timeout_base=_BASE)
    assert rec.sha256 in edited
    conn.close()


def test_changed_content_is_a_different_binary_and_runs(tmp_path: Path) -> None:
    """The content axis, which costs nothing to hold: rows are keyed BY sha256.

    Different bytes are a different row with no recorded timeout, so it is dirty as a new binary
    would be. Written down because "we also check the content" is easy to believe about code that
    does not, and here the check is the lookup itself."""
    conn, rec, _budget = _timed_out_at_current_budget(tmp_path, _REAL_TIMED_OUT_SIZE)
    changed = _rec_for(rec.path, "feedface")  # same file, new content hash
    _, dirty = ingest_elfs(conn, [changed], pass_version="p1", timeout_base=_BASE)
    assert "feedface" in dirty
    conn.close()


def test_a_non_timeout_failure_is_still_re_run_every_scan(tmp_path: Path) -> None:
    """Only timeouts are deterministic in the way this relies on. Nothing else changes behaviour.

    An import failure or a crash can be a one-off — a JVM under memory pressure, a race — and
    whether those self-heal on a retry has not been measured here, so they keep being retried
    exactly as before. Deciding otherwise would need attempt counts and a measured self-heal rate;
    inventing a policy for a failure nobody has hit is how a scan quietly stops looking.

    MUTATION (must go RED): drop the reason filter and skip any failed row."""
    from treasure_map.lib.analyze.ghidra_runner import retry_budget_seconds

    conn = open_db(tmp_path / "analysis.db")
    rec = _rec_for(_sized_file(tmp_path, "weird.so", _REAL_TIMED_OUT_SIZE), "deadbeef")
    ingest_elfs(conn, [rec], pass_version="p1", timeout_base=_BASE)
    budget = retry_budget_seconds(rec.path, _BASE)
    for reason in ("import_failed", "no_output", "incomplete"):
        _record_failure(conn, rec.sha256, budget=budget, pass_version="p1", reason=reason)
        _, dirty = ingest_elfs(conn, [rec], pass_version="p1", timeout_base=_BASE)
        assert rec.sha256 in dirty, reason
    conn.close()


def test_nothing_recorded_to_compare_against_means_re_run(tmp_path: Path) -> None:
    """A skip is positively earned. Absence of a fact is never read as "nothing changed".

    Two ways a timeout row can carry no comparison: it failed before any of this was recorded (both
    columns NULL on an older DB), or the caller tracks no pass version. Both re-run.

    MUTATION (must go RED): treat a NULL budget or a NULL fingerprint as a match."""
    conn, rec, budget = _timed_out_at_current_budget(tmp_path, _REAL_TIMED_OUT_SIZE)

    _record_failure(conn, rec.sha256, budget=None, pass_version="p1")
    _, no_budget = ingest_elfs(conn, [rec], pass_version="p1", timeout_base=_BASE)
    assert rec.sha256 in no_budget

    _record_failure(conn, rec.sha256, budget=budget, pass_version=None)
    _, no_fingerprint = ingest_elfs(conn, [rec], pass_version="p1", timeout_base=_BASE)
    assert rec.sha256 in no_fingerprint

    _record_failure(conn, rec.sha256, budget=budget, pass_version="p1")
    _, caller_tracks_no_pass = ingest_elfs(conn, [rec], pass_version=None, timeout_base=_BASE)
    assert rec.sha256 in caller_tracks_no_pass
    conn.close()


def test_a_binary_that_cannot_be_measured_is_re_run_and_said_out_loud(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The budget comes from the file's size, so an unreadable file has no budget to compare.

    Both silent answers are wrong here and in opposite directions — skip it and a binary vanishes
    from every future scan on a number nobody computed; re-run it quietly and it burns the budget
    forever with no trace. It re-runs, and it says why.

    MUTATION (must go RED): let the unmeasurable case fall through to a skip, or drop the log."""
    conn, rec, _budget = _timed_out_at_current_budget(tmp_path, _REAL_TIMED_OUT_SIZE)
    rec.path.unlink()
    with caplog.at_level("WARNING"):
        _, dirty = ingest_elfs(conn, [rec], pass_version="p1", timeout_base=_BASE)
    assert rec.sha256 in dirty
    assert any("cannot measure" in r.message for r in caplog.records)
    conn.close()


def test_the_escape_hatches_re_run_everything(tmp_path: Path) -> None:
    """--force-retry and either --reanalyze form ignore the skip: a judgement must be
    overridable, and this one is a judgement about wall clock, not about the binary."""
    conn, rec, _budget = _timed_out_at_current_budget(tmp_path, _REAL_TIMED_OUT_SIZE)
    _, forced = ingest_elfs(conn, [rec], pass_version="p1", timeout_base=_BASE, force_retry=True)
    assert rec.sha256 in forced
    _, all_ = ingest_elfs(
        conn, [rec], pass_version="p1", timeout_base=_BASE, reanalyze=REANALYZE_ALL
    )
    assert rec.sha256 in all_
    _, named = ingest_elfs(
        conn, [rec], pass_version="p1", timeout_base=_BASE, reanalyze="big_daemon"
    )
    assert rec.sha256 in named
    conn.close()


def test_a_caller_that_tracks_no_budget_skips_nothing(tmp_path: Path) -> None:
    """No ``timeout_base``, no skipping — the default behaviour is exactly what it was.

    Same convention ``pass_version`` already uses in this function: a caller that does not supply
    the dimension does not get it applied to them."""
    conn, rec, _budget = _timed_out_at_current_budget(tmp_path, _REAL_TIMED_OUT_SIZE)
    _, dirty = ingest_elfs(conn, [rec], pass_version="p1")
    assert rec.sha256 in dirty
    conn.close()


def test_skipping_the_re_run_does_not_remove_it_from_the_incomplete_surfacing(
    tmp_path: Path,
) -> None:
    """★ The hard gate: not re-running it is not the same as it being fine.

    A skipped binary keeps ghidra_ok=0, keeps ``failed``, keeps 0 functions and keeps its row in
    this scan — so it goes on being named as incomplete, with the timeout as the reason. The two
    are independent, and they have to be: a binary nobody could analyze reads as one with nothing
    in it to every consumer downstream, and "the scan got faster" would be the only visible
    difference.

    MUTATION (must go RED): have the skip mark the row ok_empty (the tempting way to stop it being
    re-examined) — it drops straight out of the surfacing."""
    from treasure_map.lib.facts import list_incomplete_binaries

    conn, rec, _budget = _timed_out_at_current_budget(tmp_path, _REAL_TIMED_OUT_SIZE)
    _, dirty = ingest_elfs(conn, [rec], pass_version="p1", timeout_base=_BASE)
    assert rec.sha256 not in dirty  # skipped...

    listed = list_incomplete_binaries(conn)
    assert [(e["binary"], e["reason"]) for e in listed] == [("big_daemon", "timeout")]
    conn.close()


def test_migration_adds_stub_names_to_old_db(tmp_path: Path) -> None:
    """A database built before the stub table existed must gain the column on open.

    Adding a column to schema.sql alone is not enough: CREATE TABLE IF NOT EXISTS never alters an
    existing table, so every pre-existing analysis.db would be missing it and the first ingest
    would fail with "no column named stub_names". Existing rows must survive, and re-opening must
    not raise.

    MUTATION (measured: 1 failed, this test alone): drop the ("binaries", "stub_names", "TEXT")
    entry from _ADDED_COLUMNS in storage/connection.py -> the column is absent here while a fresh
    database still has it."""
    db_path = tmp_path / "legacy.db"
    raw = sqlite3.connect(db_path)
    raw.execute(
        "CREATE TABLE binaries (id INTEGER PRIMARY KEY, name TEXT, sha256 TEXT UNIQUE, "
        "ghidra_ok INTEGER NOT NULL DEFAULT 0)"
    )
    raw.execute("INSERT INTO binaries (id, name, sha256) VALUES (1, 'webd', 'aa')")
    raw.commit()
    raw.close()

    conn = open_db(db_path)  # triggers the additive migration
    cols = {row[1] for row in conn.execute("PRAGMA table_info(binaries)")}
    assert "stub_names" in cols
    row = conn.execute("SELECT name, stub_names FROM binaries WHERE id = 1").fetchone()
    assert row["name"] == "webd"  # the pre-existing row survived
    # ★ NULL, not '{}': an old row was never looked at, which is a different answer from
    # "looked and found no stubs". Back-filling '{}' would state a fact nobody established.
    assert row["stub_names"] is None
    conn.close()

    conn = open_db(db_path)  # idempotent: re-running the migration must not raise
    assert "stub_names" in {row[1] for row in conn.execute("PRAGMA table_info(binaries)")}
    conn.close()


def test_schema_sql_alone_declares_the_stub_column(tmp_path: Path) -> None:
    """The other half of the two-place rule, asserted where it can actually fail.

    ★ Going through open_db could NOT test this: it applies schema.sql and then runs the additive
    migration, which would put a column missing from schema.sql straight back. The assertion would
    hold no matter which of the two places carried it, i.e. it would test nothing. Building the
    database from schema.sql ALONE is what makes "the canonical schema declares it" falsifiable.

    MUTATION (measured: 1 failed of 46, this test alone): remove stub_names from schema.sql ->
    red here while the old-database migration test above stays GREEN, which is the measurement
    that proves the migration really does mask the omission and that this test earns its place."""
    db_path = tmp_path / "schema_only.db"
    raw = sqlite3.connect(db_path)
    raw.executescript(_SCHEMA_PATH.read_text())
    cols = {row[1] for row in raw.execute("PRAGMA table_info(binaries)")}
    raw.close()
    assert "stub_names" in cols
