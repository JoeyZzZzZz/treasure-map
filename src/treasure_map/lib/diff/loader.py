# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
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
    """One function row joined to its binary's name, path, and content hash (neutral)."""

    func_id: int
    binary_id: int
    binary_name: str
    binary_path: str | None
    binary_sha256: str | None
    name: str | None
    # The function's entry address as the extractor recorded it (e.g. "000b32a0"). Unlike func_id
    # (a per-ingest AUTOINCREMENT rowid that shifts on every re-scan), this is a property of the
    # BINARY, so it is the stable anchor a re-scan-stable evidence_ref is built from.
    address: str | None
    pseudocode: str | None
    pseudocode_hash: str | None
    callees: str | None


_SELECT = """
SELECT f.id, f.binary_id, b.name AS binary_name, b.path AS binary_path,
       b.sha256 AS binary_sha256, f.name, f.address,
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
            binary_path=r["binary_path"],
            binary_sha256=r["binary_sha256"],
            name=r["name"],
            address=r["address"],
            pseudocode=r["pseudocode"],
            pseudocode_hash=r["pseudocode_hash"],
            callees=r["callees"],
        )
        for r in rows
    ]
