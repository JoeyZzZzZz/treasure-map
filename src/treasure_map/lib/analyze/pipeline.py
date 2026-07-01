# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Analyze pipeline: scan_filesystem → ingest_elfs → ghidra_runner.run_all → ghidra_ingest.

Binary-level idempotency: scan_filesystem always runs (fast).  Ghidra runs
only on dirty records — sha256 values that are new or still have ghidra_ok=0.
DB is the truth source; workspace step checkpoints are not used here.
Week 2 scope: Ghidra. Week 3 Round A: Ghidra JSON ingest.
Week 3 Round B: xrefs + string classification (wipe-and-rebuild each run).
Week 3 Round C: non-binary ingester framework (wipe-and-rebuild each run).
Week 3 Round D: config_file ingester + per-kind sub_rows stats.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from treasure_map.lib.analyze.db_ingest import ingest_elfs
from treasure_map.lib.analyze.elf_inventory import ElfRecord, scan_filesystem
from treasure_map.lib.analyze.ghidra_ingest import IngestStats, ingest_ghidra_output
from treasure_map.lib.analyze.ghidra_runner import GhidraRunner
from treasure_map.lib.analyze.non_binary.orchestrator import NonBinaryStats, run_all_ingesters
from treasure_map.lib.analyze.xrefs import XrefStats, build_xrefs
from treasure_map.lib.config.config import Config
from treasure_map.lib.storage.connection import open_db
from treasure_map.lib.workspace.workspace import Workspace

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[str, dict[str, Any]], None]


@dataclass
class AnalyzeResult:
    db_path: Path
    binary_count: int  # unique ELFs found in current scan
    dirty_count: int  # binaries that needed Ghidra this run
    ghidra_ok: int  # of dirty, how many Ghidra succeeded
    ghidra_failed: int  # of dirty, how many Ghidra failed
    ghidra_skipped: int  # binary_count - dirty_count (cache hits)
    functions_ingested: int  # Round A: rows written to functions table
    imports_ingested: int
    exports_ingested: int
    strings_ingested: int
    layer0_xrefs: int  # Round B: callees × exports function-level
    layer1_xrefs: int  # Round B: import × export (sum func + lib)
    layer2_xrefs: int  # Round B: dt_needed library-level
    layer3_xrefs: int  # Round B: string_ipc soft links
    strings_classified: int  # Round B: strings.category filled
    total_xrefs: int  # Round B: sum of all layers
    non_binary_files_ingested: int  # Round C: rows written to non_binary_files
    script_calls_ingested: int  # Round C: rows written to script_calls
    config_entries_ingested: int  # Round D: rows written to config_entries
    credentials_ingested: int  # Round E: rows written to credentials
    web_endpoints_ingested: int  # Round F: rows written to web_endpoints
    elapsed: float
    # ★ Red-line (degrade must be visible): current-scan binaries that hold 0 functions but are NOT
    # legitimately code-free (ghidra_status != ok_empty) — analysis is incomplete for them, NOT
    # clean. The CLI warns and names them so they are never mistaken for "nothing to find".
    incomplete_binaries: list[str] = field(default_factory=list)


async def run_analyze(
    fs_root: Path,
    workspace: Workspace,
    config: Config,
    progress_callback: ProgressCallback | None = None,
    skip_non_binary: bool = False,
    skip_ingesters: frozenset[str] = frozenset(),
    reanalyze: str | None = None,
) -> AnalyzeResult:
    """Orchestrate a full firmware analysis run.

    scan_filesystem always runs.  Ghidra runs only on dirty records.
    After Ghidra, JSON output is ingested into functions/imports/exports/strings.

    ``reanalyze`` (REANALYZE_ALL or a binary name/path) forces re-analysis ignoring the cache.

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
    incomplete_binaries: list[str] = []
    ingest_stats = IngestStats()
    xref_stats = XrefStats()
    nb_stats = NonBinaryStats()
    try:
        sha_to_id, dirty_shas = ingest_elfs(conn, records, reanalyze=reanalyze)
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
                # ★ Red-line: persist the tri-state outcome. ghidra_ok stays a 0/1 usability flag
                # (ok/ok_empty -> 1) for back-compat; ghidra_status records WHICH of the three, so a
                # failed run is visibly not "clean" (ghidra_ok=0) and is retried next run.
                conn.execute(
                    "UPDATE binaries SET ghidra_ok=?, ghidra_status=? WHERE sha256=?",
                    (1 if res.success else 0, res.analysis_status, rec.sha256),
                )
                if res.success:
                    ghidra_ok += 1
                else:
                    ghidra_failed += 1
            conn.commit()
        else:
            logger.info("ghidra: all binaries up-to-date (0 dirty)")

        # Round A: ingest Ghidra JSON output into functions/imports/exports/strings
        ingest_stats = ingest_ghidra_output(
            conn,
            workspace.path / "ghidra_output",
            dirty_records,
            sha_to_id,
        )

        # Round B: build cross-binary xrefs + classify strings (wipe-and-rebuild)
        xref_stats = build_xrefs(conn)

        # ★ Red-line visibility: current-scan binaries that hold 0 functions and are NOT a
        # legitimately code-free object (ghidra_status != ok_empty). Truthful DB-derived set — it
        # includes a freshly-failed run AND any stale bad row not re-run — so "incomplete" is never
        # silently presented as "clean".
        incomplete_binaries = [
            row["name"]
            for row in conn.execute(
                "SELECT b.name FROM current_binaries b "
                "WHERE COALESCE(b.ghidra_status, '') != 'ok_empty' "
                "AND NOT EXISTS (SELECT 1 FROM functions f WHERE f.binary_id = b.id) "
                "ORDER BY b.name"
            ).fetchall()
        ]

        # Round C: non-binary ingester framework (wipe-and-rebuild)
        if not skip_non_binary:
            nb_stats = run_all_ingesters(
                conn,
                fs_root,
                skip_ingesters=skip_ingesters,
                progress_callback=progress_callback,
            )
    finally:
        conn.close()

    return AnalyzeResult(
        db_path=workspace.db_path,
        binary_count=len(records),
        dirty_count=len(dirty_records),
        ghidra_ok=ghidra_ok,
        ghidra_failed=ghidra_failed,
        ghidra_skipped=len(records) - len(dirty_records),
        functions_ingested=ingest_stats.functions_ingested,
        imports_ingested=ingest_stats.imports_ingested,
        exports_ingested=ingest_stats.exports_ingested,
        strings_ingested=ingest_stats.strings_ingested,
        layer0_xrefs=xref_stats.layer0_callees_exports,
        layer1_xrefs=xref_stats.layer1_total,
        layer2_xrefs=xref_stats.layer2_dt_needed,
        layer3_xrefs=xref_stats.layer3_string_ipc,
        strings_classified=xref_stats.strings_classified,
        total_xrefs=xref_stats.total_xrefs,
        non_binary_files_ingested=nb_stats.files_ingested,
        script_calls_ingested=nb_stats.sub_rows.get("shell_script", 0),
        config_entries_ingested=nb_stats.sub_rows.get("config_file", 0),
        credentials_ingested=nb_stats.sub_rows.get("credential", 0),
        web_endpoints_ingested=nb_stats.sub_rows.get("web_asset", 0),
        elapsed=time.monotonic() - t0,
        incomplete_binaries=incomplete_binaries,
    )
