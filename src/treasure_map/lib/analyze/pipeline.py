# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Analyze pipeline: scan_filesystem → ingest_elfs → ghidra_runner.run_all → ghidra_ingest.

Binary-level idempotency: scan_filesystem always runs (fast). Ghidra runs only on dirty
records — a binary that is new, has no successful extraction yet, was extracted by a different
pass_version, timed out under a different pass, or is cached but code-rich and empty (the
self-heal in db_ingest). The database is the source of truth; there are no step checkpoints.
xrefs, string classification and the non-binary ingesters are rebuilt on every run.

Each binary's result is committed the moment it arrives, so a scan that is interrupted keeps every
binary it finished: re-running the same command decompiles only the rest.
"""

from __future__ import annotations

import dataclasses
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from treasure_map.lib import rescan_version
from treasure_map.lib.analyze.db_ingest import ingest_elfs
from treasure_map.lib.analyze.elf_inventory import ElfRecord, scan_filesystem
from treasure_map.lib.analyze.ghidra_ingest import IngestStats, ingest_ghidra_output
from treasure_map.lib.analyze.ghidra_runner import _INTERRUPTED, GhidraResult, GhidraRunner
from treasure_map.lib.analyze.non_binary.orchestrator import NonBinaryStats, run_all_ingesters
from treasure_map.lib.analyze.symlinks import SymlinkCollector, write_symlinks
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
    functions_ingested: int  # rows written to functions table
    imports_ingested: int
    exports_ingested: int
    strings_ingested: int
    layer0_xrefs: int  # callees × exports function-level
    layer1_xrefs: int  # import × export (sum func + lib)
    layer2_xrefs: int  # dt_needed library-level
    layer3_xrefs: int  # string_ipc soft links
    strings_classified: int  # strings.category filled
    total_xrefs: int  # sum of all layers
    non_binary_files_ingested: int  # rows written to non_binary_files
    script_calls_ingested: int  # rows written to script_calls
    config_entries_ingested: int  # rows written to config_entries
    credentials_ingested: int  # rows written to credentials
    web_endpoints_ingested: int  # rows written to web_endpoints
    elapsed: float
    # ★ Red-line (degrade must be visible): current-scan binaries that hold 0 functions but are NOT
    # legitimately code-free (ghidra_status != ok_empty) — analysis is incomplete for them, NOT
    # clean. The CLI warns and names them so they are never mistaken for "nothing to find".
    incomplete_binaries: list[str] = field(default_factory=list)
    # Symbolic links inventoried under the firmware root this run (the fs_symlinks table the
    # cross-binary exec edge resolves its targets through). 0 is a real answer for a rootfs with
    # no links; it is never a "did not run" signal — the walk always runs.
    symlinks_recorded: int = 0
    # ★ Red-line (a skip must be visible): binaries NOT re-run this scan because they timed out at
    # a budget this scan would only repeat. Each is ``{binary, size_bytes, budget_seconds}``. They
    # are still counted incomplete and still named by ``incomplete_binaries`` — this list says why
    # no Ghidra time was spent on them, so "it went fast" is never mistaken for "it went clean".
    timeout_skipped: list[dict[str, Any]] = field(default_factory=list)
    # Current-scan binaries whose extraction ran to the end but recovered no function from code
    # that is there (``ghidra_status='no_functions'``). Also named by ``incomplete_binaries``; this
    # list says why re-running the same pass will not change them.
    no_functions_binaries: list[str] = field(default_factory=list)
    # Current-scan binaries this scan's pass FAILED on while they still hold the rows an earlier
    # pass wrote. Each is ``{binary, reason, earlier_pass}``; their candidates read
    # ``extraction_current=false``.
    kept_earlier_binaries: list[dict[str, Any]] = field(default_factory=list)
    # Current-scan binaries still marked by an unfinished bare ``--reanalyze``: they were asked to
    # be re-extracted and have not been yet. A later bare ``--reanalyze`` continues with them.
    reanalyze_pending: int = 0
    # Of ``ghidra_ok``, how many finished as ``no_functions`` (code present, no function recovered).
    ghidra_no_functions: int = 0


def run_analyze(
    fs_root: Path,
    workspace: Workspace,
    config: Config,
    progress_callback: ProgressCallback | None = None,
    reanalyze: str | None = None,
    force_retry: bool = False,
) -> AnalyzeResult:
    """Orchestrate a full firmware analysis run.

    scan_filesystem always runs.  Ghidra runs only on dirty records.
    After Ghidra, JSON output is ingested into functions/imports/exports/strings.

    ``reanalyze`` (REANALYZE_ALL or a binary name/path) forces re-analysis ignoring the cache.
    ``force_retry`` re-attempts binaries that timed out at a budget this scan would repeat, which
    are otherwise left alone (see ``db_ingest._timeout_skips``); it does not touch the cache.

    Fail-fast: discovers analyzeHeadless before scanning so a missing Ghidra
    installation is reported immediately rather than after a long ELF scan.
    """
    t0 = time.monotonic()

    # Fail-fast: raise GhidraNotFoundError before any disk work
    runner = GhidraRunner(config.ghidra)
    runner.get_headless()

    # Grab the scan stamp at the START, so what is written at the end describes the code this
    # process actually loaded even if the source is edited mid-scan (it is a claim about THIS run).
    scan_stamp = rescan_version.scan_stamp_for(config)

    # Content hash of the extraction pass: a cache-key dimension alongside sha256, so editing
    # ExportFunctions re-extracts every binary automatically (no manual JSON/db deletion).
    pass_version = runner.pass_version()

    # Version of the Ghidra that will actually produce this run's output ('unknown' when it cannot
    # be read). Stamped per analyzed binary next to pass_version, so the recorded version is the one
    # that DID the work — not whatever happens to be installed later when the run is hunted.
    ghidra_version = runner.ghidra_version()

    # The ELF walk already tests every entry for being a symlink; hand it a collector so those
    # links become an inventory instead of being dropped. This walk always runs, so the inventory
    # does not depend on an optional stage.
    symlink_collector = SymlinkCollector(fs_root)
    records = scan_filesystem(
        fs_root, progress_callback=progress_callback, symlink_collector=symlink_collector
    )

    conn = open_db(workspace.db_path)
    # Clear the scan stamp up front: a crash before the end leaves NO stamp (read as "cannot
    # confirm", which re-scans), never a stale one describing a half-built analysis.db.
    conn.execute("DELETE FROM scan_stamp")
    conn.commit()
    dirty_records: list[ElfRecord] = []
    ghidra_ok = 0
    ghidra_failed = 0
    ghidra_no_functions = 0
    incomplete_binaries: list[str] = []
    no_functions_binaries: list[str] = []
    kept_earlier_binaries: list[dict[str, Any]] = []
    reanalyze_pending = 0
    timeout_skipped: list[dict[str, Any]] = []
    ingest_stats = IngestStats()
    symlinks_recorded = 0
    xref_stats = XrefStats()
    nb_stats = NonBinaryStats()
    try:
        # Wipe-and-rebuild the link inventory (the cross-binary exec edge resolves its targets
        # through it). Independent of Ghidra, so it lands even on a fully-cached re-analyze.
        symlinks_recorded = write_symlinks(conn, symlink_collector.records)

        sha_to_id, dirty_shas = ingest_elfs(
            conn,
            records,
            reanalyze=reanalyze,
            pass_version=pass_version,
            timeout_base=config.ghidra.headless_timeout_seconds,
            force_retry=force_retry,
            ghidra_version=ghidra_version,
        )
        dirty_records = [r for r in records if r.sha256 in dirty_shas]

        # What the skip cost, read back from the DECISION rather than re-derived: a timed-out
        # binary in this scan that is not in the dirty set is one nothing will be spent on. Deriving
        # it from dirty_shas means the report cannot drift from the rule — change the rule and this
        # follows, instead of quietly describing the old one.
        scanned_shas = {r.sha256 for r in records}
        timeout_skipped = [
            {
                "binary": row["name"],
                "size_bytes": row["size_bytes"],
                "budget_seconds": row["timeout_budget"],
            }
            for row in conn.execute(
                "SELECT name, sha256, size_bytes, timeout_budget FROM binaries "
                "WHERE ghidra_ok = 0 AND ghidra_status_reason = 'timeout' ORDER BY name"
            ).fetchall()
            if row["sha256"] in scanned_shas and row["sha256"] not in dirty_shas
        ]

        logger.info(
            "pipeline: %d total, %d dirty, %d cached",
            len(records),
            len(dirty_records),
            len(records) - len(dirty_records),
        )

        if dirty_records:
            kept = 0  # binaries whose final result is committed this scan

            def _persist_final(rec: ElfRecord, res: GhidraResult) -> None:
                """Store one binary's FINAL result and commit it, before the next one arrives.

                ★ The SUCCESS stamp (ghidra_ok/status/pass_version) is written inside
                ingest_ghidra_output, in the same transaction as the function rows, so a binary is
                never marked extracted while its functions are missing. A FAILURE has no functions
                to lose, so it is stamped and committed here. Either way the binary is committed
                before the next result is handled, so an interrupt keeps what already finished."""
                nonlocal ghidra_ok, ghidra_failed, ghidra_no_functions, kept
                if res.reason == _INTERRUPTED:
                    return  # cut off, not finished: nothing is recorded and it runs again next time
                if res.success:
                    ghidra_ok += 1
                    if res.analysis_status == "no_functions":
                        ghidra_no_functions += 1
                    one = ingest_ghidra_output(
                        conn,
                        ghidra_output_dir,
                        [rec],
                        sha_to_id,
                        pass_version=pass_version,
                        success_stamp={rec.sha256: (res.analysis_status, ghidra_version)},
                    )
                    for f in dataclasses.fields(IngestStats):
                        setattr(
                            ingest_stats,
                            f.name,
                            getattr(ingest_stats, f.name) + getattr(one, f.name),
                        )
                    if one.binaries_processed == 1:
                        kept += 1
                        # A second transaction: the stamp and rows above are committed inside the
                        # ingest, which cannot take this column with them. An interrupt between the
                        # two commits only means this one binary is re-extracted by a continued
                        # --reanalyze.
                        conn.execute(
                            "UPDATE binaries SET reanalyze_pending = 0 WHERE sha256 = ?",
                            (rec.sha256,),
                        )
                        conn.commit()
                else:
                    # record WHY it failed (timeout/import_failed/no_output/incomplete/
                    # stale_output) so the incomplete surfacing can tell a recoverable timeout
                    # from a structural failure.
                    # ...and record what this attempt RAN UNDER: the budget it was given and
                    # the extraction fingerprint behind it. pass_version stays untouched because it
                    # describes a row's OUTPUT and there is none; these two describe the ATTEMPT,
                    # which is what the next scan compares against to decide whether re-running
                    # would be a different attempt or the same one twice.
                    conn.execute(
                        "UPDATE binaries SET ghidra_ok=?, ghidra_status=?, ghidra_status_reason=?, "
                        "timeout_budget=?, timeout_pass_version=?, reanalyze_pending=0 "
                        "WHERE sha256=?",
                        (
                            0,
                            res.analysis_status,
                            res.reason,
                            res.timeout_budget,
                            pass_version,
                            rec.sha256,
                        ),
                    )
                    conn.commit()
                    ghidra_failed += 1
                    kept += 1
                finalized.add(rec.sha256)

            finalized: set[str] = set()
            ghidra_output_dir = workspace.path / "ghidra_output"
            ghidra_output_dir.mkdir(parents=True, exist_ok=True)
            try:
                results = runner.run_all(
                    dirty_records, ghidra_output_dir, progress_callback, on_final=_persist_final
                )
            except KeyboardInterrupt:
                logger.warning(
                    "interrupted: %d binaries kept this run, %d left for the next run; "
                    "binaries cut off mid-decompile start over",
                    kept,
                    len(dirty_records) - kept,
                )
                raise

            if len(results) != len(dirty_records):
                logger.warning(
                    "ghidra: run_all returned %d results for %d dirty records",
                    len(results),
                    len(dirty_records),
                )
            # Whatever the runner returned without handing it over is stored now, once.
            for rec, res in zip(dirty_records, results, strict=False):
                if rec.sha256 not in finalized:
                    _persist_final(rec, res)
            logger.info(
                "pipeline: %d of %d dirty binaries stored (%d ok, %d failed)",
                kept,
                len(dirty_records),
                ghidra_ok,
                ghidra_failed,
            )
        else:
            logger.info("ghidra: all binaries up-to-date (0 dirty)")

        # build cross-binary xrefs + classify strings (wipe-and-rebuild)
        xref_stats = build_xrefs(conn, fold_edge_threshold=config.xref_fold_edge_threshold)

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
        no_functions_binaries = [
            row["name"]
            for row in conn.execute(
                "SELECT name FROM current_binaries WHERE ghidra_status = 'no_functions' "
                "ORDER BY name"
            ).fetchall()
        ]
        # The same "this scan" as above. A failed binary whose pass_version still names another pass
        # holds that pass's rows, which the hunt reads as not from this extraction.
        kept_earlier_binaries = [
            {
                "binary": row["name"],
                "reason": row["ghidra_status_reason"],
                "earlier_pass": row["pass_version"],
            }
            for row in conn.execute(
                "SELECT name, ghidra_status_reason, pass_version FROM current_binaries "
                "WHERE ghidra_ok = 0 AND pass_version IS NOT NULL AND pass_version != ? "
                "ORDER BY name",
                (pass_version,),
            ).fetchall()
        ]
        reanalyze_pending = conn.execute(
            "SELECT COUNT(*) FROM current_binaries WHERE reanalyze_pending = 1"
        ).fetchone()[0]

        # non-binary ingester framework (wipe-and-rebuild)
        nb_stats = run_all_ingesters(conn, fs_root, progress_callback=progress_callback)

        # The scan finished. Record what built this analysis.db — the stamp grabbed at the start,
        # so it names the code this process ran. Last, inside the try, so it is written only on a
        # clean finish; any exception above leaves the table empty (cleared after open_db).
        conn.execute("INSERT INTO scan_stamp (id, stamp) VALUES (1, ?)", (scan_stamp,))
        conn.commit()
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
        timeout_skipped=timeout_skipped,
        symlinks_recorded=symlinks_recorded,
        no_functions_binaries=no_functions_binaries,
        kept_earlier_binaries=kept_earlier_binaries,
        reanalyze_pending=reanalyze_pending,
        ghidra_no_functions=ghidra_no_functions,
    )
