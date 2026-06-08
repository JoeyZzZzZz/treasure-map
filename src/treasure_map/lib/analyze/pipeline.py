# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Analyze pipeline: scan_filesystem → ingest_elfs → ghidra_runner.run_all.

Binary-level idempotency: scan_filesystem always runs (fast).  Ghidra runs
only on dirty records — sha256 values that are new or still have ghidra_ok=0.
DB is the truth source; workspace step checkpoints are not used here.
Week 2 scope ends at Ghidra; function-level ingestion and LLM calls are Week 3+.
"""

from __future__ import annotations

import logging
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
    binary_count: int  # unique ELFs found in current scan
    dirty_count: int  # binaries that needed Ghidra this run
    ghidra_ok: int  # of dirty, how many Ghidra succeeded
    ghidra_failed: int  # of dirty, how many Ghidra failed
    ghidra_skipped: int  # binary_count - dirty_count (cache hits)
    db_path: Path
    elapsed: float


async def run_analyze(
    fs_root: Path,
    workspace: Workspace,
    config: Config,
    progress_callback: ProgressCallback | None = None,
) -> AnalyzeResult:
    """Orchestrate a full firmware analysis run.

    scan_filesystem always runs.  Ghidra runs only on dirty records.

    Fail-fast: discovers analyzeHeadless before scanning so a missing Ghidra
    installation is reported immediately rather than after a long ELF scan.
    """
    t0 = time.monotonic()

    # Fail-fast: raise GhidraNotFoundError before any disk work
    runner = GhidraRunner(config.ghidra)
    runner.get_headless()

    records = scan_filesystem(fs_root, progress_callback=progress_callback)

    conn = open_db(workspace.db_path)
    dirty_records: list[ElfRecord] = []
    ghidra_ok = 0
    ghidra_failed = 0
    try:
        _, dirty_shas = ingest_elfs(conn, records)
        dirty_records = [r for r in records if r.sha256 in dirty_shas]

        logger.info(
            "pipeline: %d total, %d dirty, %d cached",
            len(records),
            len(dirty_records),
            len(records) - len(dirty_records),
        )

        if dirty_records:
            ghidra_output_dir = workspace.path / "ghidra_output"
            ghidra_output_dir.mkdir(parents=True, exist_ok=True)
            results = runner.run_all(dirty_records, ghidra_output_dir, progress_callback)

            if len(results) != len(dirty_records):
                logger.warning(
                    "ghidra: run_all returned %d results for %d dirty records",
                    len(results),
                    len(dirty_records),
                )

            for rec, res in zip(dirty_records, results, strict=False):
                if res.success:
                    conn.execute(
                        "UPDATE binaries SET ghidra_ok=1 WHERE sha256=?",
                        (rec.sha256,),
                    )
                    ghidra_ok += 1
                else:
                    ghidra_failed += 1
            conn.commit()
        else:
            logger.info("ghidra: all binaries up-to-date (0 dirty)")
    finally:
        conn.close()

    return AnalyzeResult(
        binary_count=len(records),
        dirty_count=len(dirty_records),
        ghidra_ok=ghidra_ok,
        ghidra_failed=ghidra_failed,
        ghidra_skipped=len(records) - len(dirty_records),
        db_path=workspace.db_path,
        elapsed=time.monotonic() - t0,
    )
