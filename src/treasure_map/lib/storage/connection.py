# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import sqlite3
from pathlib import Path

_SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def open_db(db_path: Path) -> sqlite3.Connection:
    """Open (or create) the analysis SQLite database and apply the schema.

    The schema is idempotent (all statements use IF NOT EXISTS), so calling
    this on an existing database is safe and will not lose data.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    schema = _SCHEMA_PATH.read_text()
    conn.executescript(schema)
    conn.commit()
    return conn
