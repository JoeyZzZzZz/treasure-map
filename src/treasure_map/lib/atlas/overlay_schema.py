# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The judgement layer's tables — ``overlay`` and ``overlay_history`` — created and migrated here,
from ``lib/storage/overlay_schema.sql``, their single definition.

Kept out of the atlas schema and of ``lib.atlas.connection`` on purpose: the hunt reads and writes
neither table, so nothing done here enters a hunt content row, and the module is excluded from the
hunt's code hash (``lib.rescan_version.CLOSURE_EXCLUDED``). An edit to the overlay's shape or to a
migration below therefore never reads every run as re-hunted.

★ ORDER IS LOAD-BEARING, twice over:

* ``ensure`` runs AFTER the atlas schema script (``open_atlas``): the atlas tables come first, the
  judgement layer on top of them.
* Inside ``ensure``, the migrations run BEFORE the schema script below. The script's indexes name
  columns an older overlay gains only by migrating, and ``CREATE INDEX IF NOT EXISTS`` guards only
  the index name, not the column it reads — creating first would fail on an old atlas and leave
  it unopenable. On a new atlas there is no overlay yet, so every migration is a no-op and the
  tables are created directly (never through the rebuild).

The rebuild: SQLite cannot alter a table's CHECK, so an overlay whose stored definition carries the
retired verdict CHECK, or an ``attributed_to`` CHECK that predates the human values, is rebuilt
ONCE from the overlay statement of the schema file (its name changed to ``overlay_new``; the
statement itself is never edited by string replacement). Every column of the old table is carried
across by name; one the new table lacks aborts the migration rather than being dropped. One
transaction (``BEGIN IMMEDIATE`` ... rename), and the migration is recorded in overlay_history.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "storage" / "overlay_schema.sql"
# The values attributed_to accepts (the schema's CHECK; lib/overlay validates writes against it).
ATTRIBUTIONS = ("agent", "agent-via-mcp", "human", "human-via-agent")
_OVERLAY_CREATE = re.compile(r"^CREATE TABLE IF NOT EXISTS overlay \(", re.I)
_VERDICT_CHECK = re.compile(r"CHECK\s*\(\s*verdict\b", re.I)


class OverlayMigrationError(RuntimeError):
    """The overlay could not be brought forward without losing something; nothing was changed."""


def _strip_comments(text: str) -> str:
    """``text`` without ``--`` line comments outside single-quoted strings."""
    out: list[str] = []
    i, n, in_str = 0, len(text), False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            in_str = ch != "'"
            i += 1
        elif ch == "'":
            in_str = True
            out.append(ch)
            i += 1
        elif text.startswith("--", i):
            while i < n and text[i] != "\n":
                i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def schema_text() -> str:
    return SCHEMA_PATH.read_text(encoding="utf-8")


def overlay_statement() -> str:
    """The schema file's ``CREATE TABLE IF NOT EXISTS overlay (...)`` statement, comments removed
    — the one definition both a new atlas and a rebuild use."""
    for stmt in _strip_comments(schema_text()).split(";"):
        body = stmt.strip()
        if _OVERLAY_CREATE.match(body):
            return body
    raise OverlayMigrationError(f"no overlay statement in {SCHEMA_PATH}")


def _columns(conn: sqlite3.Connection, table: str) -> list[str]:
    return [row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()]


def _stored_sql(conn: sqlite3.Connection) -> str | None:
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='overlay'"
    ).fetchone()
    return str(row[0]) if row is not None else None


def needs_rebuild(stored_sql: str) -> list[str]:
    """Why an existing overlay must be rebuilt (empty: it need not): its verdict CHECK (retired),
    or an attributed_to CHECK without the human values."""
    why = []
    code = _strip_comments(stored_sql)
    if _VERDICT_CHECK.search(code):
        why.append("verdict_check")
    if "'human-via-agent'" not in code:
        why.append("attributed_to_check")
    return why


def _rebuild(conn: sqlite3.Connection) -> int:
    """Rebuild ``overlay`` from the schema's statement, carrying every row and every column
    across; returns the rows carried. Atomic: an explicit ``BEGIN IMMEDIATE`` (a bare CREATE would
    commit itself), every statement through ``execute`` (``executescript`` would commit), and the
    transaction closed here."""
    create = _OVERLAY_CREATE.sub("CREATE TABLE overlay_new (", overlay_statement(), count=1)
    conn.commit()
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(create)
        old, new = _columns(conn, "overlay"), set(_columns(conn, "overlay_new"))
        lost = [c for c in old if c not in new]
        if lost:
            raise OverlayMigrationError(
                f"the overlay schema has no column for {lost}: the rebuild would drop them — "
                "nothing was changed"
            )
        cols = ",".join(old)
        conn.execute(f"INSERT INTO overlay_new ({cols}) SELECT {cols} FROM overlay")  # noqa: S608
        n = conn.execute("SELECT COUNT(*) FROM overlay_new").fetchone()[0]
        conn.execute("DROP TABLE overlay")
        conn.execute("ALTER TABLE overlay_new RENAME TO overlay")
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    return int(n)


def _migrate(conn: sqlite3.Connection) -> dict[str, Any]:
    """Bring an existing overlay forward; what was done (empty: nothing, or no overlay yet)."""
    stored = _stored_sql(conn)
    if stored is None:
        return {}
    done: dict[str, Any] = {}
    why = needs_rebuild(stored)
    if why:
        done["rebuilt"] = {"why": why, "rows": _rebuild(conn)}
    # Columns an overlay that was not rebuilt may lack (a rebuilt one has them all already).
    have = set(_columns(conn, "overlay"))
    added = []
    for col in ("run_id", "verdict_basis", "promoted_from"):
        if col not in have:
            conn.execute(f"ALTER TABLE overlay ADD COLUMN {col} TEXT")  # noqa: S608
            added.append(col)
    if added:
        done["columns_added"] = added
    # run_id from the anchor: everything before the first '#' (`> 1`, so a ref that starts with
    # '#' stays NULL, as the write path leaves it). Looked for first, then written: an UPDATE takes
    # the write lock even when it matches nothing.
    if conn.execute(
        "SELECT 1 FROM overlay WHERE run_id IS NULL AND instr(anchor_ref, '#') > 1 LIMIT 1"
    ).fetchone():
        cur = conn.execute(
            "UPDATE overlay SET run_id = substr(anchor_ref, 1, instr(anchor_ref, '#') - 1) "
            "WHERE run_id IS NULL AND instr(anchor_ref, '#') > 1"
        )
        done["run_id_backfilled"] = cur.rowcount
    # 'to-review' -> 'inconclusive': the layer records what was concluded, and "nothing decisive
    # could be established" is a conclusion.
    if conn.execute("SELECT 1 FROM overlay WHERE verdict = 'to-review' LIMIT 1").fetchone():
        cur = conn.execute(
            "UPDATE overlay SET verdict = 'inconclusive' WHERE verdict = 'to-review'"
        )
        done["to_review_renamed"] = cur.rowcount
    return done


def ensure(conn: sqlite3.Connection) -> None:
    """Migrate an existing overlay (first), then create the judgement layer's tables and indexes
    that are missing (second — see the module docstring for why in this order), and record a
    migration that did anything in overlay_history."""
    done = _migrate(conn)
    conn.executescript(schema_text())
    if done:
        conn.execute(
            "INSERT INTO overlay_history (event, channel, note) "
            "VALUES ('migration', 'migration', ?)",
            (json.dumps(done, sort_keys=True),),
        )
    conn.commit()
