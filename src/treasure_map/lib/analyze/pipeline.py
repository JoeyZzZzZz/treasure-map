# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Analyze pipeline: scan_filesystem → ingest_elfs → ghidra_runner.run_all.

Each step is guarded by a Workspace checkpoint so interrupted runs resume
from the last completed step.  Week 2 scope ends here; function-level
ingestion and LLM calls are Week 3+.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from treasure_map.lib.analyze.db_ingest import ingest_elfs
from treasure_map.lib.analyze.elf_inventory import ElfRecord, scan_filesystem
from treasure_map.lib.analyze.ghidra_runner import GhidraRunner
from treasure_map.lib.config.config import Config
from treasure_map.lib.storage.connection import open_db
from treasure_map.lib.workspace.workspace import Workspace

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[str, dict[str, Any]], None]


@dataclass
class AnalyzeResult:
    db_path: Path
    binary_count: int
    ghidra_ok: int
    ghidra_failed: int
    elapsed: float


async def run_analyze(
    fs_root: Path,
    workspace: Workspace,
    config: Config,
    progress_callback: ProgressCallback | None = None,
) -> AnalyzeResult:
    """Orchestrate a full firmware analysis run.

    Steps (each idempotent via workspace checkpoint):
      1. find_elfs  — scan filesystem + ingest into binaries table
      2. ghidra     — run analyzeHeadless on all binaries

    Fail-fast: discovers analyzeHeadless before touching the filesystem so
    a missing Ghidra installation is reported immediately.
    """
    t0 = time.monotonic()

    # Fail-fast: raise GhidraNotFoundError before doing any disk work
    runner = GhidraRunner(config.ghidra)
    runner.get_headless()

    conn = open_db(workspace.db_path)
    try:
        records = _step_find_elfs(fs_root, conn, workspace, progress_callback)
        ghidra_ok, ghidra_failed = _step_ghidra(
            records, workspace, runner, config, progress_callback
        )
    finally:
        conn.close()

    return AnalyzeResult(
        db_path=workspace.db_path,
        binary_count=len(records),
        ghidra_ok=ghidra_ok,
        ghidra_failed=ghidra_failed,
        elapsed=time.monotonic() - t0,
    )


def _step_find_elfs(
    fs_root: Path,
    conn: sqlite3.Connection,
    workspace: Workspace,
    progress_callback: ProgressCallback | None,
) -> list[ElfRecord]:
    """Step 1: scan filesystem + ingest.  Skipped on checkpoint hit."""
    if workspace.is_done("find_elfs"):
        logger.info("find_elfs: checkpoint hit, loading from DB")
        return _load_records_from_db(conn)

    logger.info("find_elfs: scanning %s", fs_root)
    records = scan_filesystem(fs_root, progress_callback=progress_callback)
    ingest_elfs(conn, records)
    workspace.mark_done("find_elfs", {"binary_count": len(records)})
    logger.info("find_elfs: done — %d unique ELFs", len(records))
    return records


def _step_ghidra(
    records: list[ElfRecord],
    workspace: Workspace,
    runner: GhidraRunner,
    config: Config,
    progress_callback: ProgressCallback | None,
) -> tuple[int, int]:
    """Step 2: run Ghidra on all binaries.  Skipped on checkpoint hit.

    Returns (ok_count, failed_count) for this run; both are 0 when skipped.
    """
    if workspace.is_done("ghidra"):
        logger.info("ghidra: checkpoint hit, skipping")
        return 0, 0

    if not records:
        logger.info("ghidra: no ELFs to analyze")
        workspace.mark_done("ghidra", {"ok": 0, "failed": 0})
        return 0, 0

    ghidra_output_dir = workspace.path / "ghidra_output"
    logger.info("ghidra: analyzing %d binaries", len(records))
    results = runner.run_all(records, ghidra_output_dir, progress_callback)

    if len(results) != len(records):
        logger.warning(
            "ghidra: run_all returned %d results for %d records — possible runner bug",
            len(results),
            len(records),
        )

    ok = sum(1 for r in results if r.success)
    failed = len(results) - ok
    workspace.mark_done("ghidra", {"ok": ok, "failed": failed})
    logger.info("ghidra: done — ok=%d failed=%d", ok, failed)
    return ok, failed


def _load_records_from_db(conn: sqlite3.Connection) -> list[ElfRecord]:
    """Reconstruct ElfRecord list from the binaries table for resume.

    Restores dt_needed and protections from their JSON columns so that
    downstream steps (Week 3+ xrefs) have complete data without re-scanning.
    """
    rows = conn.execute(
        "SELECT name, path, arch, sha256, file_type, dt_needed, protections FROM binaries"
    ).fetchall()
    return [
        ElfRecord(
            path=Path(row["path"] or ""),
            name=row["name"],
            arch=row["arch"],  # NULL rows already filtered below
            elf_type=row["file_type"] or "unknown",
            sha256=row["sha256"],
            dt_needed=json.loads(row["dt_needed"]) if row["dt_needed"] else [],
            protections=json.loads(row["protections"]) if row["protections"] else {},
        )
        for row in rows
        if row["arch"]  # skip rows with NULL arch (shouldn't happen, but be defensive)
    ]
