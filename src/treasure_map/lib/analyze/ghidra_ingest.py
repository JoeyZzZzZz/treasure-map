# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Ghidra JSON ingest: parses ghidra_output/*.json and populates
functions / imports / exports / strings tables.

Designed to align with Round 2 partial invalidation:
- Only ingests JSON files for the `dirty_records` set
- Per-binary DELETE-then-INSERT (destructive, idempotent within a run)
- Skips gracefully when JSON file missing (binary failed Ghidra) or malformed
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from treasure_map.lib.analyze.elf_inventory import ElfRecord

logger = logging.getLogger(__name__)


@dataclass
class IngestStats:
    """Returned by ingest_ghidra_output, surfaced to AnalyzeResult."""

    functions_ingested: int = 0
    imports_ingested: int = 0
    exports_ingested: int = 0
    strings_ingested: int = 0
    binaries_processed: int = 0
    binaries_missing_json: int = 0
    binaries_malformed_json: int = 0


def ingest_ghidra_output(
    conn: sqlite3.Connection,
    ghidra_output_dir: Path,
    dirty_records: list[ElfRecord],
    sha_to_id: dict[str, int],
) -> IngestStats:
    """For each dirty binary, locate its <name>_<sha8>_ghidra.json,
    parse, and write to functions/imports/exports/strings tables.

    Per-binary semantics: DELETE existing rows for this binary_id before
    INSERT. This means re-ingesting the same binary in a single run is safe
    (idempotent), and Round 2 partial invalidation cleanly refreshes only
    the changed binary's data while leaving unchanged binaries' data intact.

    Args:
        conn: open SQLite connection to the workspace's analysis.db
        ghidra_output_dir: workspace ghidra_output directory
        dirty_records: binaries that need re-ingest (from ingest_elfs return)
        sha_to_id: sha256 → binaries.id mapping (from ingest_elfs return)

    Returns:
        IngestStats summarizing what was written
    """
    stats = IngestStats()

    if not dirty_records:
        logger.info("ghidra_ingest: 0 dirty records, nothing to ingest")
        return stats

    for rec in dirty_records:
        sha8 = rec.sha256[:8]
        json_path = ghidra_output_dir / f"{rec.name}_{sha8}_ghidra.json"

        # EC1: JSON missing (Ghidra failed for this binary)
        if not json_path.exists():
            logger.warning(
                "ghidra_ingest: JSON missing for %s (sha8=%s) at %s",
                rec.name,
                sha8,
                json_path,
            )
            stats.binaries_missing_json += 1
            continue

        # EC2: JSON malformed
        try:
            with json_path.open("r", encoding="utf-8") as f:
                data: dict[str, Any] = json.load(f)
        except json.JSONDecodeError as exc:
            logger.warning(
                "ghidra_ingest: malformed JSON for %s: %s",
                rec.name,
                exc,
            )
            stats.binaries_malformed_json += 1
            continue

        binary_id = sha_to_id[rec.sha256]
        _ingest_one_binary(conn, binary_id, data, stats)
        stats.binaries_processed += 1

    conn.commit()

    logger.info(
        "ghidra_ingest: %d binaries processed (%d missing, %d malformed), "
        "%d functions, %d imports, %d exports, %d strings",
        stats.binaries_processed,
        stats.binaries_missing_json,
        stats.binaries_malformed_json,
        stats.functions_ingested,
        stats.imports_ingested,
        stats.exports_ingested,
        stats.strings_ingested,
    )
    return stats


def _ingest_one_binary(
    conn: sqlite3.Connection,
    binary_id: int,
    data: dict[str, Any],
    stats: IngestStats,
) -> None:
    """Replace this binary's rows in functions/imports/exports/strings."""

    # DELETE existing rows for this binary_id (idempotent re-ingest)
    for table in ("functions", "imports", "exports", "strings"):
        conn.execute(f"DELETE FROM {table} WHERE binary_id = ?", (binary_id,))

    # functions
    func_rows = []
    for func in data.get("functions", []):
        pseudocode = func.get("pseudocode") or ""
        ph = hashlib.md5(pseudocode.encode("utf-8")).hexdigest() if pseudocode else None
        func_rows.append(
            (
                binary_id,
                func.get("name"),
                func.get("address"),
                func.get("size", 0),
                pseudocode,
                ph,
                json.dumps(func.get("callees", []), ensure_ascii=False),
                int(func.get("is_exported", 0)),
                # sink_arg_provenance transport: the Ghidra-computed def-use fact for this
                # function's command/format sinks, carried verbatim to be merged into the atlas
                # instance's flow_evidence at hunt time. Missing/old exports -> '[]' (never null).
                json.dumps(func.get("sink_provenance", []), ensure_ascii=False),
                # gap② nvram_ops transport: per-function nvram read/write ops (key + written
                # value source), carried verbatim for the phase-2 key graph. Old exports -> '[]'.
                json.dumps(func.get("nvram_ops", []), ensure_ascii=False),
            )
        )
    if func_rows:
        conn.executemany(
            """INSERT INTO functions
               (binary_id, name, address, size_bytes, pseudocode,
                pseudocode_hash, callees, is_exported, sink_provenance, nvram_ops)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            func_rows,
        )
        stats.functions_ingested += len(func_rows)

    # imports (JSON's lib_name maps to DB's lib_soname)
    imp_rows = [
        (binary_id, imp.get("func_name"), imp.get("lib_name") or "")
        for imp in data.get("imports", [])
    ]
    if imp_rows:
        conn.executemany(
            "INSERT INTO imports (binary_id, func_name, lib_soname) VALUES (?, ?, ?)",
            imp_rows,
        )
        stats.imports_ingested += len(imp_rows)

    # exports
    exp_rows = [
        (binary_id, exp.get("func_name"), exp.get("address")) for exp in data.get("exports", [])
    ]
    if exp_rows:
        conn.executemany(
            "INSERT INTO exports (binary_id, func_name, address) VALUES (?, ?, ?)",
            exp_rows,
        )
        stats.exports_ingested += len(exp_rows)

    # strings (category=NULL — Round B fills it)
    str_rows = [(binary_id, s.get("value"), s.get("address")) for s in data.get("strings", [])]
    if str_rows:
        conn.executemany(
            "INSERT INTO strings (binary_id, value, address) VALUES (?, ?, ?)",
            str_rows,
        )
        stats.strings_ingested += len(str_rows)
