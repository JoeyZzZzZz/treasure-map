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
