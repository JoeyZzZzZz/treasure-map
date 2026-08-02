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
    # exposure_shape (added this round): an exposure SHAPE (e.g. bare_sink), moved out of
    # blocking_mechanism so a danger form is never read as a mitigation. Nullable TEXT — old rows
    # carry NULL until re-hunted. Idempotent — runs only while the column is missing.
    if inst_cols and "exposure_shape" not in inst_cols:
        conn.execute("ALTER TABLE instance ADD COLUMN exposure_shape TEXT")

    # public_cve_pattern.origin (added this round): marks rows as externally imported material (not
    # tmap deterministic extraction). NOT NULL DEFAULT 'external_import'; existing rows take the
    # default. Idempotent — runs only while the column is missing. CHECK falls back to plain column.
    pcp_cols = _column_names(conn, "public_cve_pattern")
    if pcp_cols and "origin" not in pcp_cols:
        try:
            conn.execute(
                "ALTER TABLE public_cve_pattern ADD COLUMN origin TEXT NOT NULL "
                "DEFAULT 'external_import' CHECK (origin IN ('external_import'))"
            )
        except sqlite3.OperationalError:
            conn.execute(
                "ALTER TABLE public_cve_pattern ADD COLUMN origin TEXT NOT NULL "
                "DEFAULT 'external_import'"
            )

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

    # diff_meta.micro_skipped_a/b (added this round): design-skipped micro-function counts, kept
    # SEPARATE from functions_empty (which now means real failures only). An atlas that already
    # created diff_meta needs these columns; nullable INTEGER, existing rows carry NULL. Idempotent.
    dm_cols = _column_names(conn, "diff_meta")
    if dm_cols and "micro_skipped_a" not in dm_cols:
        conn.execute("ALTER TABLE diff_meta ADD COLUMN micro_skipped_a INTEGER")
    if dm_cols and "micro_skipped_b" not in dm_cols:
        conn.execute("ALTER TABLE diff_meta ADD COLUMN micro_skipped_b INTEGER")

    # diff_meta.binary_a/b (added this round): the diff's per-side TARGET binary (short name), so a
    # per-binary consumer (string_keyed_edge delta) filters to the diffed binary, not the whole
    # firmware. An atlas that already created diff_meta needs these columns; nullable TEXT, existing
    # rows carry NULL (the consumer refuses rather than silently skipping the filter). Idempotent.
    if dm_cols and "binary_a" not in dm_cols:
        conn.execute("ALTER TABLE diff_meta ADD COLUMN binary_a TEXT")
    if dm_cols and "binary_b" not in dm_cols:
        conn.execute("ALTER TABLE diff_meta ADD COLUMN binary_b TEXT")

    # diff_meta per-binary status (added this round): the scan-side ghidra_ok/status/reason model
    # ported to diff, so a FAILED binary persists a queryable blind-spot row and the next full diff
    # can skip already-ok binaries (incremental) and retry failed ones (self-healing). diff_ok /
    # diff_attempts are NOT NULL DEFAULT (a pre-feature row takes ok=0 / attempts=0, i.e. "failed /
    # never counted" -> re-diffed next run, which backfills the columns); the rest are nullable.
    # Idempotent — each ADD runs only while its column is missing.
    if dm_cols and "diff_ok" not in dm_cols:
        conn.execute("ALTER TABLE diff_meta ADD COLUMN diff_ok INTEGER NOT NULL DEFAULT 0")
    if dm_cols and "diff_status" not in dm_cols:
        conn.execute("ALTER TABLE diff_meta ADD COLUMN diff_status TEXT")
    if dm_cols and "diff_status_reason" not in dm_cols:
        conn.execute("ALTER TABLE diff_meta ADD COLUMN diff_status_reason TEXT")
    if dm_cols and "diff_attempts" not in dm_cols:
        conn.execute("ALTER TABLE diff_meta ADD COLUMN diff_attempts INTEGER NOT NULL DEFAULT 0")
    if dm_cols and "sha256_a" not in dm_cols:
        conn.execute("ALTER TABLE diff_meta ADD COLUMN sha256_a TEXT")
    if dm_cols and "sha256_b" not in dm_cols:
        conn.execute("ALTER TABLE diff_meta ADD COLUMN sha256_b TEXT")

    # dimension_delta.binary (added this round): the diff's target binary (short name), parsed from
    # subject_key at write time, so a per-binary consumer filters on a real column instead of a
    # brittle LIKE on the subject_key prefix. An atlas that already created dimension_delta needs
    # the column; nullable TEXT, existing rows carry NULL until re-diffed. Idempotent.
    dd_cols = _column_names(conn, "dimension_delta")
    if dd_cols and "binary" not in dd_cols:
        conn.execute("ALTER TABLE dimension_delta ADD COLUMN binary TEXT")


def open_atlas(db_path: Path) -> sqlite3.Connection:
    """Open (or create) the atlas SQLite database and apply the schema.

    The schema uses IF NOT EXISTS throughout, so re-applying it to an existing database is
    safe and preserves all rows. An older atlas is first brought forward in place by _migrate
    (adds instance.origin / binary_path / binary_content_hash / is_thin_cmd_wrapper /
    wrapped_sink / flow_evidence / dimension_delta.binary, renames pattern.recurrence_breadth ->
    device_spread, drops legacy pattern.device_category) — never by a table rebuild, so instance
    rows and all derived counts are kept.

    ★ ORDER IS LOAD-BEARING: _migrate MUST run BEFORE executescript. The schema now carries an
    index/constraint that references a MIGRATED-IN column (idx_dimdelta_bin on
    dimension_delta(diff_id, binary)); on an OLD atlas whose dimension_delta predates that column,
    running executescript first hits `CREATE INDEX ... (binary)` — IF NOT EXISTS guards only the
    index NAME, not the referenced column — and raises "no such column: binary", so executescript
    aborts and _migrate never runs: the atlas cannot be opened at all. Migrating first adds the
    column, so the later CREATE INDEX finds it. On a fresh DB every _migrate step is a no-op
    (_column_names returns empty for a table that does not exist yet), so this order is safe both
    ways. Do NOT reorder these two lines — any future schema object that references a migrated
    column would silently re-break every existing atlas.

    WARNING: Moving atlas.db requires sqlite3 .backup() or wal_checkpoint(TRUNCATE)
    before any file-copy — never a bare cp while WAL side-files exist.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    schema = _SCHEMA_PATH.read_text()
    _migrate(conn)  # ★ BEFORE executescript — see the load-bearing-order note above
    conn.executescript(schema)
    conn.commit()
    return conn
