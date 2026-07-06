# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Atlas database connection — open or create atlas.db.

WARNING: Moving atlas.db requires sqlite3 .backup() or WAL wal_checkpoint(TRUNCATE)
first — never a bare cp. WAL side-files (.db-wal, .db-shm) hold unmerged pages;
copying the main file without them yields "database disk image is malformed" on open.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

_SCHEMA_PATH = Path(__file__).parent.parent / "storage" / "atlas_schema.sql"


def _column_names(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def _migrate(conn: sqlite3.Connection) -> None:
    """Apply in-place, idempotent migrations the IF-NOT-EXISTS schema cannot.

    CREATE TABLE IF NOT EXISTS never adds a column to (or renames a column on) a table that
    already exists, so an atlas written by an older schema would keep its old shape. These
    ALTER TABLEs run only when the target column is missing, so the rows are preserved.
    """
    inst_cols = _column_names(conn, "instance")
    if inst_cols and "origin" not in inst_cols:
        # SQLite >= 3.25 allows ADD COLUMN with NOT NULL DEFAULT and a column-level CHECK;
        # if a build rejects the CHECK, fall back to the plain column and rely on the
        # writer-side enum validation. Existing rows take the default 'unknown'.
        try:
            conn.execute(
                "ALTER TABLE instance ADD COLUMN origin TEXT NOT NULL DEFAULT 'unknown' "
                "CHECK (origin IN ('custom','vendor_modified_oss','stock_oss_known','unknown'))"
            )
        except sqlite3.OperationalError:
            conn.execute("ALTER TABLE instance ADD COLUMN origin TEXT NOT NULL DEFAULT 'unknown'")
    # Candidate locatability (added this round): nullable TEXT columns, so existing rows simply
    # carry NULL until re-hunted. Idempotent — each ADD runs only while its column is missing.
    if inst_cols and "binary_path" not in inst_cols:
        conn.execute("ALTER TABLE instance ADD COLUMN binary_path TEXT")
    if inst_cols and "binary_content_hash" not in inst_cols:
        conn.execute("ALTER TABLE instance ADD COLUMN binary_content_hash TEXT")
    # Neutral structural fact (added this round): thin command-forwarding wrapper + the sink it
    # forwards to. Existing rows take the default 0 / NULL until re-hunted. Idempotent.
    if inst_cols and "is_thin_cmd_wrapper" not in inst_cols:
        try:
            conn.execute(
                "ALTER TABLE instance ADD COLUMN is_thin_cmd_wrapper INTEGER NOT NULL "
                "DEFAULT 0 CHECK (is_thin_cmd_wrapper IN (0,1))"
            )
        except sqlite3.OperationalError:
            conn.execute(
                "ALTER TABLE instance ADD COLUMN is_thin_cmd_wrapper INTEGER NOT NULL DEFAULT 0"
            )
    if inst_cols and "wrapped_sink" not in inst_cols:
        conn.execute("ALTER TABLE instance ADD COLUMN wrapped_sink TEXT")
    # Structured flow evidence (added this round): nullable JSON TEXT; existing rows carry NULL
    # until re-hunted. Idempotent — runs only while the column is missing.
    if inst_cols and "flow_evidence" not in inst_cols:
        conn.execute("ALTER TABLE instance ADD COLUMN flow_evidence TEXT")

    pat_cols = _column_names(conn, "pattern")
    if "recurrence_breadth" in pat_cols and "device_spread" not in pat_cols:
        conn.execute("ALTER TABLE pattern RENAME COLUMN recurrence_breadth TO device_spread")
    if "device_category" in pat_cols:
        # Hard-removed (no real consumer): drop the legacy column in place. SQLite >= 3.35
        # supports DROP COLUMN; only evidence rows are protected from rebuild, not this
        # hand-filled, unconsumed field. Idempotent — runs only while the column exists.
        conn.execute("ALTER TABLE pattern DROP COLUMN device_category")

    # gap② A2 (added this round): the thin nvram wrapper a wrapper-indirect key edge was resolved
    # through. Nullable TEXT — existing rows carry NULL (a DIRECT edge) until re-hunted. Idempotent.
    nvkf_cols = _column_names(conn, "nvram_key_flow")
    if nvkf_cols and "via_wrapper" not in nvkf_cols:
        conn.execute("ALTER TABLE nvram_key_flow ADD COLUMN via_wrapper TEXT")


def open_atlas(db_path: Path) -> sqlite3.Connection:
    """Open (or create) the atlas SQLite database and apply the schema.

    The schema uses IF NOT EXISTS throughout, so re-applying it to an existing database is
    safe and preserves all rows. An older atlas is then brought forward in place by _migrate
    (adds instance.origin / binary_path / binary_content_hash / is_thin_cmd_wrapper /
    wrapped_sink / flow_evidence, renames pattern.recurrence_breadth -> device_spread, drops
    legacy pattern.device_category) — never by a table rebuild, so instance rows and all derived
    counts are kept.

    WARNING: Moving atlas.db requires sqlite3 .backup() or wal_checkpoint(TRUNCATE)
    before any file-copy — never a bare cp while WAL side-files exist.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    schema = _SCHEMA_PATH.read_text()
    conn.executescript(schema)
    _migrate(conn)
    conn.commit()
    return conn
