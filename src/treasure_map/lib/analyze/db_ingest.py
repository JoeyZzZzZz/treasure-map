# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import logging
import sqlite3
from datetime import UTC, datetime

from treasure_map.lib.analyze.elf_inventory import ElfRecord, has_substantial_text

logger = logging.getLogger(__name__)

# Sentinel for --reanalyze with no target: force re-analysis of EVERY binary this scan.
REANALYZE_ALL = "__all__"


def ingest_elfs(
    conn: sqlite3.Connection,
    records: list[ElfRecord],
    *,
    reanalyze: str | None = None,
) -> tuple[dict[str, int], set[str]]:
    """Ingest ELF records into the binaries table.

    Uses INSERT OR IGNORE so the same sha256 is never duplicated.  Updates
    last_seen_at for every sha256 in the current scan so the current_binaries
    view reflects this run.

    ``reanalyze`` forces re-analysis ignoring the cache: ``REANALYZE_ALL`` re-runs every binary;
    a name or path re-runs only the matching binary. It is the escape hatch for a binary frozen in
    a bad cached state.

    Returns:
        sha_to_id:  sha256 → binaries.id for all records in this scan
        dirty_shas: sha256 values that need Ghidra analysis — new rows, rows not yet marked usable
                    (ghidra_ok=0), rows force-selected by ``reanalyze``, or rows that claim to be
                    done but hold 0 functions despite carrying real code (the self-heal below)
    """
    scan_timestamp = datetime.now(UTC).isoformat()
    shas = [r.sha256 for r in records]
    ph = ",".join("?" * len(shas)) if shas else ""

    # Step 1: find which sha256 are already analyzed (a usable prior run: ghidra_ok=1, i.e. ok or
    # ok_empty). ghidra_status='failed' keeps ghidra_ok=0, so a failed run is never "already done".
    already_done: set[str] = set()
    if shas:
        done_rows = conn.execute(
            f"SELECT sha256 FROM binaries WHERE sha256 IN ({ph}) AND ghidra_ok = 1",
            shas,
        ).fetchall()
        already_done = {row["sha256"] for row in done_rows}

    # Step 1a: --reanalyze escape hatch — drop force-selected shas so they re-run.
    if reanalyze == REANALYZE_ALL:
        already_done = set()
    elif reanalyze:
        forced = {r.sha256 for r in records if reanalyze in (r.name, str(r.path))}
        already_done -= forced

    # Step 1b: ★ Red-line self-heal — a row marked done but holding 0 functions despite carrying
    # real code is a frozen bad state (a partial/empty run wrongly cached, e.g. a >200-byte shell).
    # Re-dirty it so a re-run recovers it, WITHOUT deleting the database. A legitimately code-free
    # object is marked ghidra_status='ok_empty' and is left done (never churned).
    if already_done:
        done_ph = ",".join("?" * len(already_done))
        zero_fn = {
            row["sha256"]
            for row in conn.execute(
                f"SELECT b.sha256 FROM binaries b WHERE b.sha256 IN ({done_ph}) "  # noqa: S608
                "AND COALESCE(b.ghidra_status, '') != 'ok_empty' "
                "AND NOT EXISTS (SELECT 1 FROM functions f WHERE f.binary_id = b.id)",
                list(already_done),
            ).fetchall()
        }
        rec_by_sha = {r.sha256: r for r in records}
        heal = {s for s in zero_fn if s in rec_by_sha and has_substantial_text(rec_by_sha[s].path)}
        if heal:
            logger.info("self-heal: %d code binaries had 0 functions -> redo", len(heal))
        # The rest of the zero-function done rows are genuinely code-free (or predate the status
        # column): backfill ok_empty so they read as legitimately empty and stop being flagged
        # incomplete — without re-analyzing them.
        code_free = zero_fn - heal
        if code_free:
            conn.executemany(
                "UPDATE binaries SET ghidra_status='ok_empty' WHERE sha256=?",
                [(s,) for s in code_free],
            )
        already_done -= heal

    # Step 2: INSERT OR IGNORE new rows (existing sha256 rows are untouched)
    for rec in records:
        bits: int | None = None
        parts = rec.arch.split(":") if rec.arch else []
        if len(parts) >= 3:
            try:
                bits = int(parts[2])
            except ValueError:
                pass

        conn.execute(
            """INSERT OR IGNORE INTO binaries
               (name, path, arch, bits, sha256, file_type,
                dt_needed, protections, size_bytes, last_seen_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                rec.name,
                str(rec.path),
                rec.arch,
                bits,
                rec.sha256,
                rec.elf_type,
                rec.dt_needed_json(),
                rec.protections_json(),
                rec.size,
                scan_timestamp,
            ),
        )

    # Step 3: touch last_seen_at for ALL records so current_binaries view is correct
    if shas:
        conn.executemany(
            "UPDATE binaries SET last_seen_at = ? WHERE sha256 = ?",
            [(scan_timestamp, sha) for sha in shas],
        )

    conn.commit()

    # Step 4: build sha_to_id map (covers both new and pre-existing rows)
    sha_to_id: dict[str, int] = {}
    if shas:
        id_rows = conn.execute(
            f"SELECT id, sha256 FROM binaries WHERE sha256 IN ({ph})", shas
        ).fetchall()
        sha_to_id = {row["sha256"]: row["id"] for row in id_rows}

    # Step 5: dirty = records not in already_done
    dirty_shas = {r.sha256 for r in records if r.sha256 not in already_done}

    logger.info(
        "ingest_elfs: %d records, %d already done, %d dirty",
        len(records),
        len(already_done),
        len(dirty_shas),
    )
    return sha_to_id, dirty_shas
