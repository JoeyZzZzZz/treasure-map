# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Ghidra JSON ingest: parses ghidra_output/*.json and populates
functions / imports / exports / strings tables.

Designed to align with Round 2 partial invalidation:
- Only ingests JSON files for the `dirty_records` set
- Per-binary DELETE-then-INSERT (destructive, idempotent within a run)
- Skips gracefully when JSON file missing (binary failed Ghidra) or malformed. Such a binary is
  NOT lost by this skip: the pipeline already recorded it as ``ghidra_status='failed'`` with a
  ``ghidra_status_reason``, and it surfaces via ``facts.list_incomplete_binaries`` (MCP
  ``incomplete_binaries``). This skip is a tolerant fallback, not the only signal.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from treasure_map.lib.analyze.elf_inventory import ElfRecord
from treasure_map.lib.analyze.stub_resolve import StubResolution, relabel_callees, resolve_stubs

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
        # Resolve this binary's lazy-binding stubs to their import names from ELF structure, so a
        # caller left calling FUN_<stub-addr> is seen calling `system` — recovering a real sink the
        # decompiler dropped. Ghidra-independent; None for a non-MIPS or unreadable ELF (no change).
        resolution = resolve_stubs(rec.path)
        _ingest_one_binary(conn, binary_id, data, stats, resolution)
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
    resolution: StubResolution | None = None,
) -> None:
    """Replace this binary's rows in functions/imports/exports/strings."""

    # DELETE existing rows for this binary_id (idempotent re-ingest)
    for table in (
        "functions",
        "imports",
        "exports",
        "strings",
        "nvram_defaults",
        "string_tables",
        "string_refs",
        "data_blocks",
        "detector_scan_status",
    ):
        conn.execute(f"DELETE FROM {table} WHERE binary_id = ?", (binary_id,))

    # functions
    func_rows = []
    for func in data.get("functions", []):
        pseudocode = func.get("pseudocode") or ""
        ph = hashlib.md5(pseudocode.encode("utf-8")).hexdigest() if pseudocode else None
        # ★ Relabel stub calls to their import names, HERE at the callee source — so the name the
        # rest of the pipeline reads is `system`, not FUN_<addr>, and no downstream layer needs a
        # second address-to-name step. A call in a stub region the resolver could not name is
        # carried through unchanged AND recorded as an unclassified external call (the hole stays
        # visible). No resolution (non-MIPS / unreadable) leaves callees exactly as exported.
        raw_callees = func.get("callees", [])
        if resolution is not None and isinstance(raw_callees, list):
            relabelled = relabel_callees([str(c) for c in raw_callees], resolution)
            callees_json = json.dumps(relabelled.callees, ensure_ascii=False)
            unresolved_json = json.dumps(relabelled.unresolved_stub_addrs, ensure_ascii=False)
        else:
            callees_json = json.dumps(raw_callees, ensure_ascii=False)
            unresolved_json = "[]"
        func_rows.append(
            (
                binary_id,
                func.get("name"),
                func.get("address"),
                func.get("size", 0),
                pseudocode,
                ph,
                callees_json,
                # honest callee-graph truncation flag: 1 = the callee list is a prefix (cap hit), so
                # consumers never read a clipped dispatcher's callees/callers as the complete graph.
                1 if func.get("callees_truncated") else 0,
                int(func.get("is_exported", 0)),
                # sink_arg_provenance transport: the Ghidra-computed def-use fact for this
                # function's command/format sinks, carried verbatim to be merged into the atlas
                # instance's flow_evidence at hunt time. Missing/old exports -> '[]' (never null).
                json.dumps(func.get("sink_provenance", []), ensure_ascii=False),
                # gap② nvram_ops transport: per-function nvram read/write ops (key + written
                # value source), carried verbatim for the phase-2 key graph. Old exports -> '[]'.
                json.dumps(func.get("nvram_ops", []), ensure_ascii=False),
                # gap② A2 transport: thin-nvram-wrapper flag (JSON obj or NULL) + this function's
                # calls that pass a constant literal to a local function (resolved at hunt time into
                # wrapper-indirect key edges). Old exports -> NULL / '[]'.
                json.dumps(func["nvram_wrapper"], ensure_ascii=False)
                if func.get("nvram_wrapper")
                else None,
                json.dumps(func.get("wrapper_call_args", []), ensure_ascii=False),
                # string-keyed-edge transport (detector B): the strcmp-ladder {key -> callees} edges
                # recovered in this function, carried verbatim to be flattened into the atlas
                # string_keyed_edge table at hunt time. Old exports -> '{}' (never null).
                json.dumps(func.get("string_keyed_edges", {}), ensure_ascii=False),
                # address-taken transport: who references THIS function's entry as a data/pointer
                # ref (a .data table slot or a .text literal-pool take), carried verbatim and read
                # by get_xrefs(direction=address_taken). Old exports -> '{}' (never null).
                json.dumps(func.get("address_taken", {}), ensure_ascii=False),
                unresolved_json,
            )
        )
    if func_rows:
        conn.executemany(
            """INSERT INTO functions
               (binary_id, name, address, size_bytes, pseudocode,
                pseudocode_hash, callees, callees_truncated, is_exported,
                sink_provenance, nvram_ops, nvram_wrapper, wrapper_call_args,
                string_keyed_edges, address_taken, unresolved_external_calls)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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

    # Honest truncation flags: the extractor reports the true match count and whether the stored
    # list is only a prefix (cap/cancel hit). Carry both onto the binaries row so get_strings can
    # tell a consumer "this binary's strings are incomplete" instead of implying a clean, full list.
    # Absent (old exports) -> total = stored, truncated = 0 (a complete list, the pre-cap default).
    strings_total = data.get("strings_total")
    if strings_total is None:
        strings_total = len(str_rows)
    strings_truncated = 1 if data.get("strings_truncated") else 0
    conn.execute(
        "UPDATE binaries SET strings_total = ?, strings_truncated = ? WHERE id = ?",
        (int(strings_total), strings_truncated, binary_id),
    )

    # naming-bridge phase 1: the router_defaults web-settable-key table. Only a binary where the
    # symbol was LOCATED contributes rows (a resolved member -> key=name; a member whose name ptr
    # was unreadable -> key=NULL, so a located-but-incomplete table stays honest). A binary without
    # the symbol (located=false) contributes NO rows — absence reads as "not located" (unknown),
    # never as "no web-settable keys".
    defaults = data.get("nvram_defaults")
    if isinstance(defaults, dict) and defaults.get("located"):
        def_rows: list[tuple[Any, ...]] = [
            (
                binary_id,
                m.get("key"),
                m.get("default_value"),
                m.get("flags"),
                m.get("index"),
            )
            for m in defaults.get("members", [])
            if isinstance(m, dict)
        ]
        # unresolved members: name ptr non-null but unreadable — recorded (key NULL), never silent
        def_rows += [
            (binary_id, None, None, None, u.get("index"))
            for u in defaults.get("unresolved_members", [])
            if isinstance(u, dict)
        ]
        if def_rows:
            conn.executemany(
                "INSERT INTO nvram_defaults "
                "(binary_id, key, default_value, flags, member_index) VALUES (?, ?, ?, ?, ?)",
                def_rows,
            )

    # detector A: static {string -> funcptr} dispatch tables. One row per entry; the detector-level
    # completeness (incomplete by construction — MVP absolute-2-field only) is denormalized onto
    # each row so the hunt flatten carries it without re-reading a table-level object. An empty or
    # absent list contributes NO rows — "none of THIS form found", never "no dispatch tables exist".
    string_tables = data.get("string_tables")
    if isinstance(string_tables, dict):
        comp = string_tables.get("completeness")
        comp = comp if isinstance(comp, dict) else {}
        c_status = comp.get("status")
        c_reason = comp.get("reason")
        c_scope = comp.get("scope")
        st_rows: list[tuple[Any, ...]] = []
        for t in string_tables.get("tables", []):
            if not isinstance(t, dict):
                continue
            table_addr = t.get("table_addr")
            stride = t.get("stride")
            for i, e in enumerate(t.get("entries", [])):
                if not isinstance(e, dict):
                    continue
                st_rows.append(
                    (
                        binary_id,
                        table_addr,
                        stride,
                        i,
                        e.get("key"),
                        e.get("func_name"),
                        e.get("func_addr"),
                        e.get("func_kind"),
                        c_status,
                        c_reason,
                        c_scope,
                    )
                )
        if st_rows:
            conn.executemany(
                "INSERT INTO string_tables "
                "(binary_id, table_addr, stride, entry_index, key, func_name, func_addr, "
                "func_kind, completeness_status, completeness_reason, completeness_scope) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                st_rows,
            )
        # ★ honest 0-row status: write ONE detector_scan_status row EVERY ingest (NOT gated by
        # st_rows). At zero tables an empty result would otherwise read as "confirmed none"; this
        # row records scanned=1 + scope + cap_hit so a consumer tells genuine-none from
        # unsupported-form or capped. found_count is the number of TABLES (not entries).
        found_tables = sum(1 for t in string_tables.get("tables", []) if isinstance(t, dict))
        conn.execute(
            "INSERT INTO detector_scan_status "
            "(binary_id, detector, scanned, supported_scope, unsupported_note, cap_hit, "
            "found_count) VALUES (?, 'string_tables', 1, ?, ?, ?, ?)",
            (binary_id, c_scope, c_reason, 1 if comp.get("cap_hit") else 0, found_tables),
        )
    else:
        # No detector object in the payload (an export predating detector A). Do NOT claim a scan
        # that did not happen: record scanned=0 so the consumer sees "no status recorded", never a
        # confident negative.
        conn.execute(
            "INSERT INTO detector_scan_status (binary_id, detector, scanned) "
            "VALUES (?, 'string_tables', 0)",
            (binary_id,),
        )

    # Resolved string-reference anchors: one row per (string, referencing instruction). A RESOLVED
    # Ghidra data/pointer reference — unlike the pseudocode TEXT search it cannot hit a comment or
    # an unrelated literal, and unlike a reachability edge it says nothing about what the
    # referencing code then does. A string with no resolved reference contributes NO rows, and an
    # absent payload key contributes none either; the query tells those apart from the scan-status
    # row written below.
    string_refs = data.get("string_refs")
    if isinstance(string_refs, dict):
        sref_rows: list[tuple[Any, ...]] = []
        strings_with_refs = 0
        for entry in string_refs.get("strings", []):
            if not isinstance(entry, dict):
                continue
            refs = [r for r in entry.get("refs", []) if isinstance(r, dict)]
            if not refs:
                continue
            strings_with_refs += 1
            truncated = 1 if entry.get("truncated") else 0
            for r in refs:
                sref_rows.append(
                    (
                        binary_id,
                        entry.get("string_addr"),
                        entry.get("value"),
                        r.get("ref_at"),
                        r.get("ref_in_func"),
                        r.get("ref_in_func_addr"),
                        r.get("segment"),
                        truncated,
                    )
                )
        if sref_rows:
            conn.executemany(
                "INSERT INTO string_refs "
                "(binary_id, string_addr, string_value, ref_at, ref_in_func, ref_in_func_addr, "
                "segment, truncated) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                sref_rows,
            )
        # ★ honest 0-row status, written EVERY ingest and NOT gated on row count: at zero rows an
        # empty string_refs would otherwise read as "this binary references no strings". found_count
        # is the number of STRINGS that had at least one resolved reference (not the row count).
        conn.execute(
            "INSERT INTO detector_scan_status "
            "(binary_id, detector, scanned, supported_scope, unsupported_note, cap_hit, "
            "found_count) VALUES (?, 'string_refs', 1, ?, ?, ?, ?)",
            (
                binary_id,
                "defined_strings_with_resolved_data_refs",
                "indirect_or_computed_references_are_not_resolved",
                1 if string_refs.get("cap_hit") else 0,
                strings_with_refs,
            ),
        )
    else:
        # No string_refs object in the payload (an export predating it). Record scanned=0 so a
        # consumer sees "no status recorded", never a confident "no references".
        conn.execute(
            "INSERT INTO detector_scan_status (binary_id, detector, scanned) "
            "VALUES (?, 'string_refs', 0)",
            (binary_id,),
        )

    # A1: raw segment bytes. One row per exported memory block. RAW BYTES ONLY — nothing here reads
    # them. An initialized block carries its (possibly cap-truncated) bytes; a .bss block carries
    # bytes=NULL with initialized=0, so a later lookup answers "uninitialized, runtime-only" instead
    # of a fabricated zero. `executable` marks a block whose bytes came out of an RX segment, where
    # .rodata and .text are indistinguishable without section headers — the read side turns it into
    # a standing warning, so it must survive the round trip. An absent/empty block list contributes
    # NO rows — the query then reports "not exported" (unknown), never "no data".
    data_blocks = data.get("data_blocks")
    if isinstance(data_blocks, dict):
        blk_rows: list[tuple[Any, ...]] = []
        for b in data_blocks.get("blocks", []):
            if not isinstance(b, dict):
                continue
            initialized = 1 if b.get("initialized") else 0
            executable = 1 if b.get("executable") else 0
            truncated = 1 if b.get("truncated") else 0
            raw: bytes | None = None
            if initialized:
                try:
                    raw = base64.b64decode(b.get("bytes") or "", validate=True)
                except ValueError:
                    # Undecodable transport for a block the exporter said IS initialized. Store zero
                    # bytes and FORCE truncated=1 so the gap reads as "we hold less than size",
                    # never as an authoritative short block.
                    raw, truncated = b"", 1
            blk_rows.append(
                (
                    binary_id,
                    b.get("name"),
                    b.get("start"),
                    b.get("size"),
                    raw,
                    initialized,
                    executable,
                    truncated,
                )
            )
        if blk_rows:
            conn.executemany(
                "INSERT INTO data_blocks "
                "(binary_id, block_name, start_addr, size, bytes, initialized, executable, "
                "truncated) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                blk_rows,
            )
        # ★ honest 0-row status, same shape as the string_tables one: written EVERY ingest, NOT
        # gated on row count. At zero blocks an empty data_blocks table would otherwise read as
        # "this binary has no data segments"; this row records that the export DID run and whether
        # a cap cut it. found_count is the number of BLOCKS exported.
        conn.execute(
            "INSERT INTO detector_scan_status "
            "(binary_id, detector, scanned, supported_scope, unsupported_note, cap_hit, "
            "found_count) VALUES (?, 'data_blocks', 1, ?, ?, ?, ?)",
            (
                binary_id,
                "initialized_non_executable_blocks",
                "uninitialized_bss_blocks_carry_no_bytes",
                1 if data_blocks.get("cap_hit") else 0,
                len([b for b in data_blocks.get("blocks", []) if isinstance(b, dict)]),
            ),
        )
    else:
        # No data_blocks object in the payload (an export predating A1). Do NOT claim an export that
        # did not happen: scanned=0, so a consumer sees "no status recorded", never a clean zero.
        conn.execute(
            "INSERT INTO detector_scan_status (binary_id, detector, scanned) "
            "VALUES (?, 'data_blocks', 0)",
            (binary_id,),
        )
