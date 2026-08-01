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

    Uses INSERT OR IGNORE so the same sha256 is never duplicated.  Refreshes last_seen_at AND
    path for every sha256 in the current scan (both are per-scan OBSERVED values, not
    content-identity) so the current_binaries view reflects this run and a cached (unchanged)
    binary still records the path THIS scan saw it at.

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

    # Step 1b: ★ Red-line self-heal — the "cached" flag (ghidra_ok=1) must not outlive the ARTIFACT
    # it claims. A row marked done but holding 0 functions has no artifact; whether that is a real
    # cached result or a silent-stale one is decided by the CURRENT file, never by a stored label.
    #
    # The stored ghidra_status='ok_empty' is DELIBERATELY NOT TRUSTED here. It was derived at
    # analysis time from has_substantial_text, which returns False on ANY read/parse error — so a
    # code-rich binary whose file was momentarily unreadable then (a temp/cpio extraction cleaned, a
    # migration to another machine, a race) was frozen as "legitimately empty" and, once frozen,
    # every honesty net that trusted the label skipped it: it read as done+clean with 0 functions,
    # forever, silently. That is the exact failure a re-scan months later on another machine hits.
    #
    # So re-verify code-richness against the file THIS scan sees: a done+0-function binary whose
    # file is code-rich NOW is re-dirtied (recovered on the re-run, no DB deletion), regardless of
    # its stored label; one whose file is genuinely code-free NOW is (re)marked ok_empty and left
    # cached (never churned). The current file is the authority; a label can be stale, bytes cannot.
    if already_done:
        done_ph = ",".join("?" * len(already_done))
        zero_fn = {
            row["sha256"]
            for row in conn.execute(
                f"SELECT b.sha256 FROM binaries b WHERE b.sha256 IN ({done_ph}) "  # noqa: S608
                "AND NOT EXISTS (SELECT 1 FROM functions f WHERE f.binary_id = b.id)",
                list(already_done),
            ).fetchall()
        }
        rec_by_sha = {r.sha256: r for r in records}
        # Re-checked against the CURRENT file — a stored ok_empty is re-examined, not believed.
        heal = {s for s in zero_fn if s in rec_by_sha and has_substantial_text(rec_by_sha[s].path)}
        if heal:
            logger.info(
                "self-heal: %d cached-but-empty binaries are code-rich -> re-analyze", len(heal)
            )
        # The rest are genuinely code-free NOW (or predate the status column): (re)mark ok_empty so
        # they read as legitimately empty and stop being flagged incomplete — without re-analyzing.
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

    # Step 3: refresh last_seen_at AND path for ALL records — both are per-scan OBSERVED values
    # (when the file was last seen / where it currently lives on THIS machine), NOT content-
    # identity. Step 2's INSERT OR IGNORE leaves a cached (unchanged-sha256) row untouched, so
    # without this the path would stay frozen at whatever an earlier scan wrote — e.g. a relative
    # path from a different cwd — which then breaks locating the .so for a cross-directory
    # `tmap diff`. path is a LOCATION property (same content can live at a new place), correctly
    # keyed by sha256; it is not a content property like arch/sha that must never move with the
    # scan. records dedupe by sha256, so no row is updated twice with conflicting paths.
    if records:
        conn.executemany(
            "UPDATE binaries SET last_seen_at = ?, path = ? WHERE sha256 = ?",
            [(scan_timestamp, str(r.path), r.sha256) for r in records],
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
