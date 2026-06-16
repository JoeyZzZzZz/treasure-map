# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Analyzer-1 — the diff-driven analyzer (patch-diff scenario), the first atlas writer.

Composes two primitives end-to-end and persists the result: R-diff locates the functions
that changed between two analysis databases; R2 grades the reachability of the changed
function in the baseline (where an unfixed flaw would live); A1 writes a neutral, graded
instance into the atlas at provenance L0/L1.

Honesty and discipline (enforced here and at the schema level):
- A1 writes L0/L1 only. L2/L3 need an external patch/CVE anchor and are out of reach
  here; A1 never passes an external_anchor.
- Nothing written is a confirmed defect or a publishable result. The only countable
  surface is the public_finding view (confirmed AND >= L2), which A1 cannot populate — it
  stays empty by construction, and that is the discipline working.
- The pattern A1 upserts is COARSE and versioned "diff-coarse-v0", deliberately distinct
  from R-pattern's rich call-sequence patterns so the two never masquerade as each other.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import InstanceRow, PatternRow
from treasure_map.lib.atlas.writer import add_instance, upsert_pattern
from treasure_map.lib.diff import Axis, run_diff
from treasure_map.lib.diff.differ import DEFAULT_MAX_ASSIST
from treasure_map.lib.diff.loader import FuncRow, load_functions
from treasure_map.lib.diff.matcher import _DiffRouter
from treasure_map.lib.pattern.classes import CMD, COPY, FORMAT
from treasure_map.lib.reachability import grade_candidate
from treasure_map.lib.reachability.taint import locate_sink_arg, origin_of

logger = logging.getLogger(__name__)

# Coarse-pattern algorithm tag — distinct from R-pattern's "callseq-v1" on purpose.
_COARSE_ALGO_VERSION = "diff-coarse-v0"

# Sink-class search order: most-consequential class first, deterministic within a class.
_SINK_CLASSES: tuple[tuple[str, frozenset[str]], ...] = (
    ("cmd", CMD),
    ("copy", COPY),
    ("format", FORMAT),
)

_SOURCE_CLASS_BY_ORIGIN = {
    "strong_source": "external_input",
    "weak_source": "local_input",
    "parameter": "parameter",
}


@dataclass(frozen=True)
class AnalyzerStats:
    leads: int  # change leads R-diff produced (changed / added / removed)
    instances_written: int  # instances persisted into the atlas
    by_status: dict[str, int]  # reachability_status -> count, over written instances
    public_findings: int  # COUNT(*) FROM public_finding — expected 0 in M2


def _find_sink(callees: list[str]) -> tuple[str, str] | None:
    """Return (sink_name, sink_class) for the first sink callee, or None.

    Minimal sink check using the shared call-class constants — NOT a full R-pattern scan.
    Class order is consequence-ranked; ties within a class break alphabetically.
    """
    for sink_class, members in _SINK_CLASSES:
        hits = sorted(name for name in callees if name in members)
        if hits:
            return hits[0], sink_class
    return None


def _fingerprint(source_class: str, sink_class: str, shape: str) -> str:
    basis = "|".join((source_class, sink_class, shape))
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def _coarse_pattern(sink_class: str, source_class: str) -> PatternRow:
    """Build the coarse diff pattern row (A1 does not run R-pattern)."""
    shape = f"changed-fn:{sink_class}"
    return PatternRow(
        source_class=source_class,
        sink_class=sink_class,
        call_sequence_shape=shape,
        structural_fingerprint=_fingerprint(source_class, sink_class, shape),
        fingerprint_algo_version=_COARSE_ALGO_VERSION,
    )


def _parse_callees(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return []
    return [str(x) for x in data] if isinstance(data, list) else []


def _unified_diff(before: str, after: str) -> str:
    return "\n".join(
        difflib.unified_diff(
            before.splitlines(), after.splitlines(), fromfile="a", tofile="b", lineterm="", n=3
        )
    )


def run_analyzer1(
    db_a: Path | str,
    db_b: Path | str,
    axis: Axis,
    atlas_path: Path | str,
    router: _DiffRouter,
    *,
    run_id_a: str,
    run_id_b: str,
    max_assist: int = DEFAULT_MAX_ASSIST,
) -> AnalyzerStats:
    """Diff db_a vs db_b, grade each changed function, and write neutral atlas instances.

    db_a is the baseline (where an unfixed flaw would live); run_id_a is the baseline's
    neutral run id (the device_spread unit). Both analysis DBs are read-only; the
    atlas is append-only. Never raises on a single bad lead — gaps are counted and logged.
    """
    result = run_diff(db_a, db_b, axis, router, max_assist=max_assist)
    funcs_a: dict[int, FuncRow] = {f.func_id: f for f in load_functions(db_a)}
    funcs_b: dict[int, FuncRow] = {f.func_id: f for f in load_functions(db_b)}

    by_status = {"confirmed": 0, "blocked": 0, "unknown": 0}
    instances_written = 0
    gaps = 0

    atlas = open_atlas(Path(atlas_path))
    try:
        for lead in result.leads:
            if lead.change_kind != "changed" or lead.func_ref_a is None:
                continue  # M2 A1 grades changed functions; added/removed counted as leads only
            baseline = funcs_a.get(lead.func_ref_a.func_id)
            if baseline is None or not (baseline.pseudocode and baseline.pseudocode.strip()):
                gaps += 1
                logger.info("skipping changed lead with no baseline pseudocode (data gap)")
                continue

            callees = _parse_callees(baseline.callees)
            comparison = (
                funcs_b.get(lead.func_ref_b.func_id) if lead.func_ref_b is not None else None
            )
            fix_diff = _unified_diff(
                baseline.pseudocode, comparison.pseudocode or "" if comparison else ""
            )

            sink = _find_sink(callees)
            if sink is None:
                # No sink located: a change, but not a reachability candidate. Record it
                # neutrally as unknown rather than inventing a sink.
                status, blocking, sink_name = "unknown", None, None
                sink_class, source_class = "unknown", "unknown"
            else:
                sink_name, sink_class = sink
                verdict = grade_candidate(baseline.pseudocode, callees, sink_name)
                status, blocking = verdict.status, verdict.blocking_mechanism
                sink_arg = locate_sink_arg(baseline.pseudocode, sink_name)
                origin = origin_of(baseline.pseudocode, sink_arg) if sink_arg else "unknown"
                source_class = _SOURCE_CLASS_BY_ORIGIN.get(origin, "unknown")

            provenance = "L1" if status in {"confirmed", "blocked"} else "L0"
            pattern = _coarse_pattern(sink_class, source_class)
            pattern_id = upsert_pattern(
                atlas,
                source_class=pattern.source_class,
                sink_class=pattern.sink_class,
                call_sequence_shape=pattern.call_sequence_shape,
                structural_fingerprint=pattern.structural_fingerprint,
                fingerprint_algo_version=pattern.fingerprint_algo_version,
            )
            add_instance(
                atlas,
                InstanceRow(
                    pattern_id=pattern_id,
                    pseudocode_hash=baseline.pseudocode_hash,
                    source_anchor=lead.func_ref_a.func_name,
                    sink_anchor=sink_name,
                    source_run_id=run_id_a,
                    reachability_status=status,
                    blocking_mechanism=blocking,
                    provenance_level=provenance,
                    fix_diff=fix_diff,
                    scope_origin=axis,
                    # Neutral per-instance locator = run + function + sink-class hit; the
                    # sink-class suffix keeps it unique when a function matches multiple sinks
                    # (the single anchor used by --explain and manual jump-back). Same format
                    # as analyzer2.
                    evidence_ref=f"{run_id_a}#fn{lead.func_ref_a.func_id}@{sink_class}",
                    # Candidate locatability: which binary (baseline build) to open in the
                    # decompiler; carried from the source so the lead stays locatable when
                    # analysis.db is gone. Content hash stored only (no consumer yet).
                    binary_path=baseline.binary_path or baseline.binary_name,
                    binary_content_hash=baseline.binary_sha256,
                ),
            )
            instances_written += 1
            by_status[status] += 1

        public_findings = atlas.execute("SELECT COUNT(*) FROM public_finding").fetchone()[0]
    finally:
        atlas.close()

    if gaps:
        logger.info("analyzer1: %d changed lead(s) skipped for missing baseline pseudocode", gaps)
    return AnalyzerStats(
        leads=len(result.leads),
        instances_written=instances_written,
        by_status=by_status,
        public_findings=int(public_findings),
    )
