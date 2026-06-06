# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import logging
import sqlite3

from treasure_map.lib.analyze.elf_inventory import ElfRecord

logger = logging.getLogger(__name__)


def ingest_elfs(conn: sqlite3.Connection, records: list[ElfRecord]) -> dict[str, int]:
    """Insert ElfRecords into the *binaries* table.

    Uses INSERT OR IGNORE so re-runs are idempotent (sha256 is UNIQUE).
    Returns a mapping of sha256 → rowid for all records (including pre-existing ones).
    """
    sha_to_id: dict[str, int] = {}

    for rec in records:
        conn.execute(
            """INSERT OR IGNORE INTO binaries
               (name, path, arch, bits, sha256, file_type, dt_needed, protections)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                rec.name,
                str(rec.path),
                rec.arch,
                int(rec.arch.split(":")[2]) if len(rec.arch.split(":")) >= 3 else None,
                rec.sha256,
                rec.elf_type,
                rec.dt_needed_json(),
                rec.protections_json(),
            ),
        )

    conn.commit()

    # Resolve rowids (covers both newly inserted and pre-existing rows)
    shas = [r.sha256 for r in records]
    if shas:
        placeholders = ",".join("?" * len(shas))
        rows = conn.execute(
            f"SELECT id, sha256 FROM binaries WHERE sha256 IN ({placeholders})", shas
        ).fetchall()
        sha_to_id = {row["sha256"]: row["id"] for row in rows}

    logger.info("ingest_elfs: %d records → %d in DB", len(records), len(sha_to_id))
    return sha_to_id
