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
    pass_version: str | None = None,
) -> tuple[dict[str, int], set[str]]:
    """Ingest ELF records into the binaries table.

    Uses INSERT OR IGNORE so the same sha256 is never duplicated.  Updates
    last_seen_at for every sha256 in the current scan so the current_binaries
    view reflects this run.

    ``reanalyze`` forces re-analysis ignoring the cache. ``REANALYZE_ALL`` re-runs every binary. A
    name or path SCOPES the run to only the matching binary/binaries and ignores all other
    staleness — including Fix A's pass_version invalidation — so editing the extraction pass and
    then ``--reanalyze rc`` re-runs just rc (the fast iteration path), not the whole firmware. It
    is also the escape hatch for a single binary frozen in a bad cached state.

    ``pass_version`` is the current extraction-pass content hash. When given, a prior-done row whose
    stored pass_version differs (or is NULL, i.e. unknown) is treated as NOT done, so editing the
    Ghidra pass re-extracts every binary automatically without any manual JSON/db deletion. When
    None (callers that do not track the pass), only sha256 / ghidra_ok gate the cache, as before.

    Returns:
        sha_to_id:  sha256 → binaries.id for all records in this scan
        dirty_shas: sha256 values that need Ghidra analysis — new rows, rows not yet marked usable
                    (ghidra_ok=0), rows whose stored pass_version is stale, rows force-selected by
                    ``reanalyze``, or rows that claim done but hold 0 functions despite real code
    """
    scan_timestamp = datetime.now(UTC).isoformat()
    shas = [r.sha256 for r in records]
    ph = ",".join("?" * len(shas)) if shas else ""

    # Step 1: find which sha256 are already analyzed (a usable prior run: ghidra_ok=1, i.e. ok or
    # ok_empty). ghidra_status='failed' keeps ghidra_ok=0, so a failed run is never "already done".
    # When a pass_version is supplied, a row produced by a DIFFERENT pass (or an unknown/NULL one)
    # is excluded here so it re-dirties — the extraction logic is a cache-key dimension too.
    already_done: set[str] = set()
    if shas:
        if pass_version is None:
            done_rows = conn.execute(
                f"SELECT sha256 FROM binaries WHERE sha256 IN ({ph}) AND ghidra_ok = 1",
                shas,
            ).fetchall()
        else:
            done_rows = conn.execute(
                f"SELECT sha256 FROM binaries WHERE sha256 IN ({ph}) AND ghidra_ok = 1 "  # noqa: S608
                "AND COALESCE(pass_version, '') = ?",
                [*shas, pass_version],
            ).fetchall()
        already_done = {row["sha256"] for row in done_rows}

    # Step 1a: --reanalyze escape hatch. REANALYZE_ALL clears already_done so every binary re-runs.
    # A SPECIFIC name/path is NOT handled by subtracting from already_done — that only narrows the
    # dirty set when everything else is already_done, and Fix A's pass_version invalidation empties
    # already_done after a pass edit, so a subtractive drop would leave the whole firmware dirty.
    # A specific target is scoped in Step 5 instead (run ONLY the match).
    if reanalyze == REANALYZE_ALL:
        already_done = set()

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

    # Step 5: dirty set.
    if reanalyze and reanalyze != REANALYZE_ALL:
        # Targeted re-extraction — the fast iteration path. Run ONLY the binary/binaries whose name
        # or path matches, ignoring every other binary's staleness, INCLUDING Fix A's pass_version
        # invalidation that marks all binaries stale after a pass edit. This is what lets
        # `--reanalyze rc` re-run just rc after editing ExportFunctions, instead of the whole
        # firmware (which the plain, no-flag scan does — that is the full-update path).
        dirty_shas = {r.sha256 for r in records if reanalyze in (r.name, str(r.path))}
        if not dirty_shas:
            logger.warning("reanalyze target %r matched no binary — nothing to re-run", reanalyze)
    else:
        dirty_shas = {r.sha256 for r in records if r.sha256 not in already_done}

    logger.info(
        "ingest_elfs: %d records, %d already done, %d dirty",
        len(records),
        len(already_done),
        len(dirty_shas),
    )
    return sha_to_id, dirty_shas
