# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The judgement layer's tables (lib/atlas/overlay_schema + lib/storage/overlay_schema.sql): kept
out of the hunt's code hash, created from one definition, an older overlay rebuilt from that same
definition with every constraint and every row, and overlay_history beside it."""

from __future__ import annotations

import re
import shutil
import sqlite3
from pathlib import Path

import pytest

from treasure_map.lib import rescan_version as rv
from treasure_map.lib.atlas import overlay_schema
from treasure_map.lib.atlas.connection import open_atlas

_PKG = Path(rv.__file__).resolve().parents[1]


def _hunt_hash(pkg: Path) -> str:
    return rv.code_version_of(pkg, rv.HUNT_ROOT)


@pytest.fixture
def pkg_copy(tmp_path: Path) -> Path:
    dest = tmp_path / "treasure_map"
    shutil.copytree(_PKG, dest, ignore=shutil.ignore_patterns("__pycache__"))
    return dest


# ── (a) the hunt's code hash ────────────────────────────────────────────────────────────────


def test_an_overlay_edit_leaves_the_hunt_hash_and_a_hunt_table_edit_moves_it(
    pkg_copy: Path,
) -> None:
    """★ Editing the overlay's schema file or its module never moves the hunt's code hash; editing
    a hunt table in the atlas schema does.

    MUTATION (verified RED): take lib.atlas.overlay_schema out of CLOSURE_EXCLUDED -> the module
    edit moves the hash -> RED."""
    before = _hunt_hash(pkg_copy)
    sql = pkg_copy / "lib" / "storage" / "overlay_schema.sql"
    sql.write_text(sql.read_text().replace("note          TEXT", "note          TEXT, extra TEXT"))
    mod = pkg_copy / "lib" / "atlas" / "overlay_schema.py"
    mod.write_text(mod.read_text() + "\n\ndef _an_edit() -> int:\n    return 1\n")
    assert _hunt_hash(pkg_copy) == before
    atlas_sql = pkg_copy / "lib" / "storage" / "atlas_schema.sql"
    text = atlas_sql.read_text()
    assert "CREATE TABLE IF NOT EXISTS instance (" in text
    atlas_sql.write_text(
        text.replace(
            "CREATE TABLE IF NOT EXISTS instance (",
            "CREATE TABLE IF NOT EXISTS instance (\n    zz_new TEXT,",
            1,
        )
    )
    assert _hunt_hash(pkg_copy) != before


# ── (b) the boundary between the two schemas ─────────────────────────────────────────────────

_OVERLAY_SQL_REF = re.compile(
    r"\b(?:FROM|INTO|UPDATE|TABLE(?:\s+IF\s+(?:NOT\s+)?EXISTS)?|JOIN|ON)\s+\"?overlay(?:_\w+)?\b",
    re.I,
)


def test_nothing_in_the_hunt_closure_touches_the_overlay_but_the_one_call() -> None:
    """★ No module the hunt's hash covers names the overlay tables in SQL, the atlas schema
    defines none of them, connection.py reaches them by exactly one call, and the overlay schema
    file defines nothing but overlay* tables and indexes.

    MUTATION (verified RED): put the run_id backfill back in connection._migrate -> RED."""
    closure = rv._closure(_PKG, rv.HUNT_ROOT)
    for module in sorted(closure):
        text = rv._module_path(_PKG, module).read_text()
        assert not _OVERLAY_SQL_REF.search(text), module
    atlas_sql = (_PKG / "lib" / "storage" / "atlas_schema.sql").read_text()
    assert not _OVERLAY_SQL_REF.search(overlay_schema._strip_comments(atlas_sql))
    conn_src = (_PKG / "lib" / "atlas" / "connection.py").read_text()
    assert conn_src.count("overlay_schema.ensure(") == 1
    own = overlay_schema._strip_comments(overlay_schema.schema_text())
    names = re.findall(r"CREATE\s+(?:TABLE|INDEX)\s+IF\s+NOT\s+EXISTS\s+(\w+)", own, re.I)
    targets = re.findall(r"\bON\s+(\w+)\s*\(", own, re.I)
    assert names and all(n.startswith(("overlay", "idx_overlay")) for n in names), names
    assert targets and all(t.startswith("overlay") for t in targets), targets


# ── (c) / (d) one definition, a rebuild that keeps everything ───────────────────────────────


def _norm(sql: str) -> str:
    text = overlay_schema._strip_comments(sql)
    text = re.sub(r"IF\s+NOT\s+EXISTS\s+", "", text, flags=re.I).replace('"', "")
    return " ".join(text.split())


def _table_sql(conn: sqlite3.Connection, name: str = "overlay") -> str:
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    return str(row[0])


# Today's live shape: no verdict CHECK, attributed_to limited to the agent values, all 12 columns.
_LIVE_SHAPE = """CREATE TABLE overlay (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    anchor_kind TEXT NOT NULL DEFAULT 'evidence_ref'
        CHECK (anchor_kind IN ('evidence_ref','diff_subject')),
    anchor_ref TEXT NOT NULL,
    run_id TEXT,
    verdict TEXT NOT NULL,
    rationale TEXT NOT NULL,
    attributed_to TEXT
        CHECK (attributed_to IS NULL OR attributed_to IN ('agent','agent-via-mcp')),
    basis_state TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    verdict_basis TEXT,
    promoted_from TEXT,
    UNIQUE (anchor_kind, anchor_ref))"""


def _live_shape(db: Path, extra_col: str | None = None) -> None:
    conn = open_atlas(db)
    conn.execute("DROP TABLE overlay")
    ddl = (
        _LIVE_SHAPE
        if extra_col is None
        else _LIVE_SHAPE.replace(
            "promoted_from TEXT,", f"promoted_from TEXT,\n    {extra_col} TEXT,"
        )
    )
    conn.execute(ddl)
    conn.execute(
        "INSERT INTO overlay (anchor_kind, anchor_ref, run_id, verdict, rationale, attributed_to, "
        "basis_state, verdict_basis, promoted_from) VALUES ('diff_subject', "
        "'a::b#function_pair#x', 'a::b', 'changed_real', 'r', 'agent-via-mcp', '{}', "
        "'{\"evidence\": [1]}', '{\"p\": 1}')"
    )
    conn.commit()
    conn.close()


def test_a_rebuilt_overlay_is_the_new_table_with_every_constraint_and_row(tmp_path: Path) -> None:
    """★ An overlay of today's shape (attributed_to without the human values) is rebuilt once,
    from the overlay schema file's statement: its definition then equals a new atlas's, UNIQUE,
    AUTOINCREMENT and both CHECKs hold, the human values are taken, and every column of the row
    is carried. The second open does not rebuild.

    MUTATION (verified RED): trigger the rebuild on the verdict CHECK only -> the live shape is
    never rebuilt, 'human' is refused -> RED; build overlay_new from a hand-written DDL without
    the UNIQUE -> the duplicate is taken -> RED."""
    fresh = open_atlas(tmp_path / "fresh.db")
    want = _norm(_table_sql(fresh))
    fresh.close()
    db = tmp_path / "atlas.db"
    _live_shape(db)
    conn = open_atlas(db)
    assert _norm(_table_sql(conn)) == want
    assert "AUTOINCREMENT" in _table_sql(conn)
    row = dict(conn.execute("SELECT * FROM overlay").fetchone())
    assert row["verdict_basis"] == '{"evidence": [1]}' and row["promoted_from"] == '{"p": 1}'
    assert (row["run_id"], row["attributed_to"], row["basis_state"]) == (
        "a::b",
        "agent-via-mcp",
        "{}",
    )
    for who in ("human", "human-via-agent"):
        conn.execute(
            "INSERT INTO overlay (anchor_ref, verdict, rationale, attributed_to) "
            "VALUES (?, 'safe', 'x', ?)",
            (f"r#a:{who}", who),
        )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO overlay (anchor_ref, verdict, rationale, attributed_to) "
            "VALUES ('r#a:bad', 'safe', 'x', 'alice')"
        )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO overlay (anchor_kind, anchor_ref, verdict, rationale) "
            "VALUES ('diff_subject', 'a::b#function_pair#x', 'safe', 'dup')"
        )
    events = conn.execute(
        "SELECT event, note FROM overlay_history WHERE event = 'migration'"
    ).fetchall()
    assert len(events) == 1 and '"rebuilt"' in events[0]["note"]
    conn.commit()
    conn.close()
    calls: list[int] = []
    real = overlay_schema._rebuild
    overlay_schema._rebuild = lambda c: calls.append(1) or real(c)  # type: ignore[assignment]
    try:
        open_atlas(db).close()
    finally:
        overlay_schema._rebuild = real  # type: ignore[assignment]
    assert calls == []


def test_a_new_atlas_creates_the_tables_and_never_rebuilds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ (d) A new atlas takes the tables straight from the schema file: the rebuild runs zero
    times and no migration is recorded.

    MUTATION (verified RED): call the rebuild whenever an overlay exists after the script -> RED."""
    calls: list[int] = []
    monkeypatch.setattr(overlay_schema, "_rebuild", lambda c: calls.append(1) or 0)
    conn = open_atlas(tmp_path / "new.db")
    assert calls == []
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"overlay", "overlay_history"} <= names
    assert conn.execute("SELECT COUNT(*) FROM overlay_history").fetchone()[0] == 0
    conn.close()


def test_a_column_the_new_table_lacks_aborts_the_rebuild_and_changes_nothing(
    tmp_path: Path,
) -> None:
    """★ An old overlay holding a column the schema file does not define is not rebuilt: the open
    fails naming the column, and the table and its row are as they were.

    MUTATION (verified RED): copy only the columns both tables share -> the column is dropped
    silently -> RED."""
    db = tmp_path / "atlas.db"
    _live_shape(db, extra_col="zz_kept")
    with pytest.raises(overlay_schema.OverlayMigrationError, match="zz_kept"):
        open_atlas(db)
    raw = sqlite3.connect(db)
    cols = {r[1] for r in raw.execute("PRAGMA table_info(overlay)")}
    tables = {r[0] for r in raw.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "zz_kept" in cols and "overlay_new" not in tables
    assert raw.execute("SELECT COUNT(*) FROM overlay").fetchone()[0] == 1
    raw.close()
