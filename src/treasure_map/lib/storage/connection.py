# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import sqlite3
from pathlib import Path

_SCHEMA_PATH = Path(__file__).parent / "schema.sql"

# Columns dropped by R-cleanup (LLM pre-judgment / dead placeholder fields). Each
# entry is (table, column, index_on_that_column_or_None). The schema no longer
# creates these; the migration removes them from databases built before this round.
# Idempotent: a column already absent is skipped, DROP INDEX/TABLE use IF EXISTS.
_DROPPED_COLUMNS: tuple[tuple[str, str, str | None], ...] = (
    ("functions", "summary", "idx_functions_summary"),
    ("functions", "func_types", "idx_functions_types"),
    ("functions", "vuln_hints", "idx_functions_vuln"),
    ("functions", "capa_tags", None),
    ("script_calls", "has_user_input", "idx_script_calls_ui"),
    ("script_calls", "vuln_hint", None),
    ("config_entries", "vuln_hint", "idx_config_entries_hint"),
    ("credentials", "vuln_hint", "idx_credentials_hint"),
    ("web_endpoints", "vuln_hint", "idx_web_endpoints_hint"),
)

# Tables dropped entirely (never read; no writer). DROP TABLE IF EXISTS is idempotent.
_DROPPED_TABLES: tuple[str, ...] = ("library_summaries",)

# Columns ADDED after the initial schema. CREATE TABLE IF NOT EXISTS does not alter an existing
# table, so a database built before the column existed needs an explicit, idempotent ALTER. Each
# entry is (table, column, column_def). Guarded by a presence check so it runs at most once.
_ADDED_COLUMNS: tuple[tuple[str, str, str], ...] = (
    # tri-state Ghidra outcome (ok / ok_empty / failed); back-fills as NULL on older DBs, which the
    # ingest self-heal treats as needing re-analysis when a claimed-done binary has 0 functions.
    ("binaries", "ghidra_status", "TEXT"),
    # sink_arg_provenance transport column; back-fills as '[]' on DBs built before it existed so
    # ghidra_ingest can write it without "no column named sink_provenance". Must match schema.sql.
    ("functions", "sink_provenance", "TEXT DEFAULT '[]'"),
    # gap② nvram_ops transport column (per-function nvram read/write ops); back-fills '[]' on older
    # DBs so ghidra_ingest can write it without "no column named nvram_ops". Must match schema.sql.
    ("functions", "nvram_ops", "TEXT DEFAULT '[]'"),
    # extraction-pass content hash; back-fills NULL on older DBs, which reads as "unknown pass" and
    # re-dirties every binary once (a correct one-time re-extraction) until the current hash is
    # stored. Must match schema.sql.
    ("binaries", "pass_version", "TEXT"),
)


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    """Column names of *table*; empty set if the table does not exist."""
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def _migrate(conn: sqlite3.Connection) -> None:
    """Drop stale pre-judgment columns/tables left over in databases built before
    R-cleanup. Preserves all rows and surviving columns; safe to run repeatedly."""
    for table in _DROPPED_TABLES:
        conn.execute(f"DROP TABLE IF EXISTS {table}")

    for table, column, index in _DROPPED_COLUMNS:
        present = _columns(conn, table)
        if column not in present:
            continue
        if index is not None:
            # A column cannot be dropped while an index references it.
            conn.execute(f"DROP INDEX IF EXISTS {index}")
        conn.execute(f"ALTER TABLE {table} DROP COLUMN {column}")

    for table, column, coldef in _ADDED_COLUMNS:
        if _columns(conn, table) and column not in _columns(conn, table):
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coldef}")


def open_db(db_path: Path) -> sqlite3.Connection:
    """Open (or create) the analysis SQLite database and apply the schema.

    The schema is idempotent (all statements use IF NOT EXISTS), so calling
    this on an existing database is safe and will not lose data. A migration
    pass then removes any stale columns/tables from older databases.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    schema = _SCHEMA_PATH.read_text()
    conn.executescript(schema)
    _migrate(conn)
    conn.commit()
    return conn
