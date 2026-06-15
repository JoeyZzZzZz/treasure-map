# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Analyzer-2 — the pattern-driven analyzer (R-pattern -> R2 -> atlas).

Composes two hermetic primitives and persists the result: R-pattern locates call-sequence
shape candidates in one analysis.db (OSS excluded at scan time); R2 grades each candidate's
reachability; A2 upserts the RICH "callseq-v1" pattern and writes a graded instance into the
atlas. This is the first time R-pattern's output reaches the persistent store — the pattern
table was designed for exactly this.

Fully hermetic: neither R-pattern nor R2 uses an LLM, so A2 needs no router.

Discipline (same as A1, enforced here and by the schema):
- L0/L1 only (confirmed/blocked -> L1, unknown -> L0); never L2/L3, never an external_anchor.
- Evidence neutralization: R-pattern's raw, firmware-derived evidence (a matched format
  literal may carry a device path) is NEVER persisted. Traceability rides pseudocode_hash;
  evidence_ref holds only a neutral per-instance locator (a run-scoped function id).
- Everything written is a graded lead, never a confirmed bug or a publishable result.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import InstanceRow
from treasure_map.lib.atlas.writer import add_instance, delete_run_instances, upsert_pattern
from treasure_map.lib.diff.loader import FuncRow, load_functions
from treasure_map.lib.pattern import scan
from treasure_map.lib.pattern.classes import CMD, COPY, FORMAT
from treasure_map.lib.reachability import grade_candidate

logger = logging.getLogger(__name__)

_SINK_CLASS_MEMBERS: dict[str, frozenset[str]] = {"cmd": CMD, "copy": COPY, "format": FORMAT}


@dataclass(frozen=True)
class Analyzer2Stats:
    scanned: int  # function rows R-pattern considered
    matches: int  # call-sequence shape matches found
    instances_written: int  # graded instances persisted into the atlas
    by_status: dict[str, int]  # reachability_status -> count, over written instances
    oss_excluded: int  # distinct OSS/third-party binaries R-pattern excluded


def _sink_name_for(callees: list[str], sink_class: str) -> str | None:
    """Return the concrete sink callee for a sink_class (deterministic), or None."""
    members = _SINK_CLASS_MEMBERS.get(sink_class)
    if not members:
        return None
    hits = sorted(name for name in callees if name in members)
    return hits[0] if hits else None


def _parse_callees(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return []
    return [str(x) for x in data] if isinstance(data, list) else []


def run_analyzer2(
    db_path: Path | str,
    atlas_path: Path | str,
    *,
    source_run_id: str,
) -> Analyzer2Stats:
    """Scan one analysis.db for shape candidates, grade them, and write atlas instances.

    source_run_id is the neutral per-run id (the device_spread unit). The analysis DB is
    read-only. Writing is REPLACE-BY-RUN: this run's old instances are deleted first and the
    fresh result is written in ONE transaction (re-running a run refreshes it, never doubles
    it). Other runs' append-and-corroborate evidence and all pattern rows are untouched. Raw
    evidence is never persisted.
    """
    result = scan(db_path)
    funcs: dict[int, FuncRow] = {f.func_id: f for f in load_functions(db_path)}

    by_status = {"confirmed": 0, "blocked": 0, "unknown": 0}
    instances_written = 0

    atlas = open_atlas(Path(atlas_path))
    try:
        # One transaction: drop this run's old rows + write the fresh result, or roll back to
        # the prior result on any error (never leave a half-written run). Only this run_id's
        # instances are deleted; pattern rows (shared accumulation layer) are not.
        with atlas:
            delete_run_instances(atlas, source_run_id, commit=False)
            for match in result.matches:
                row = funcs.get(match.func_ref.func_id)
                if row is None or not (row.pseudocode and row.pseudocode.strip()):
                    logger.info("skipping match with no loadable function body (data gap)")
                    continue

                callees = _parse_callees(row.callees)
                sink_name = _sink_name_for(callees, match.sink_class)
                if sink_name is None:
                    status, blocking = "unknown", None
                else:
                    verdict = grade_candidate(row.pseudocode, callees, sink_name)
                    status, blocking = verdict.status, verdict.blocking_mechanism

                provenance = "L1" if status in {"confirmed", "blocked"} else "L0"
                pattern_id = upsert_pattern(
                    atlas,
                    source_class=match.source_class,
                    sink_class=match.sink_class,
                    call_sequence_shape=match.call_sequence_shape,
                    structural_fingerprint=match.structural_fingerprint,
                    fingerprint_algo_version=match.fingerprint_algo_version,
                    commit=False,
                )
                add_instance(
                    atlas,
                    InstanceRow(
                        pattern_id=pattern_id,
                        pseudocode_hash=row.pseudocode_hash,
                        source_anchor=match.func_ref.func_name,
                        sink_anchor=sink_name,
                        source_run_id=source_run_id,
                        reachability_status=status,
                        blocking_mechanism=blocking,
                        provenance_level=provenance,
                        # Neutral per-instance locator = run + function + sink-class hit. One
                        # function can match multiple sinks (e.g. cmd and copy); each is a
                        # distinct instance, so the sink-class suffix keeps the ref unique
                        # (it is the single anchor used by --explain and manual jump-back).
                        evidence_ref=(
                            f"{source_run_id}#fn{match.func_ref.func_id}@{match.sink_class}"
                        ),
                        scope_origin="intra",
                    ),
                    commit=False,
                )
                instances_written += 1
                by_status[status] += 1
    finally:
        atlas.close()

    return Analyzer2Stats(
        scanned=result.stats.functions_scanned,
        matches=len(result.matches),
        instances_written=instances_written,
        by_status=by_status,
        oss_excluded=result.stats.oss_binaries_excluded,
    )
