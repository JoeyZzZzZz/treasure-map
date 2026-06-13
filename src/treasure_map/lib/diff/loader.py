# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Read-only loader for the function rows the diff primitive compares.

Both analysis databases are opened strictly read-only (file:...?mode=ro): the diff
primitive never writes to either input.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FuncRow:
    """One function row joined to its binary's name (presentation-neutral)."""

    func_id: int
    binary_id: int
    binary_name: str
    name: str | None
    pseudocode: str | None
    pseudocode_hash: str | None
    callees: str | None


_SELECT = """
SELECT f.id, f.binary_id, b.name AS binary_name, f.name,
       f.pseudocode, f.pseudocode_hash, f.callees
  FROM functions f
  JOIN binaries b ON b.id = f.binary_id
 ORDER BY b.name, f.id
"""


def load_functions(db_path: Path | str) -> list[FuncRow]:
    """Load all functions from an analysis.db, opened read-only.

    Raises sqlite3.OperationalError if the file does not exist (read-only mode does
    not create it) — a missing input is a caller error, surfaced rather than masked.
    """
    uri = f"file:{Path(db_path)}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(_SELECT).fetchall()
    finally:
        conn.close()
    return [
        FuncRow(
            func_id=r["id"],
            binary_id=r["binary_id"],
            binary_name=r["binary_name"],
            name=r["name"],
            pseudocode=r["pseudocode"],
            pseudocode_hash=r["pseudocode_hash"],
            callees=r["callees"],
        )
        for r in rows
    ]
