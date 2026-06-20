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

import hashlib
import json
import logging
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import InstanceRow
from treasure_map.lib.atlas.writer import add_instance, delete_run_instances, upsert_pattern
from treasure_map.lib.diff.loader import FuncRow, load_functions
from treasure_map.lib.hunt.downweight import (
    detect_form_signal,
    library_origin,
    wrapper_propagation_form_note,
)
from treasure_map.lib.hunt.evidence import EntryIndex, build_flow_evidence, load_entry_index
from treasure_map.lib.hunt.facts import is_thin_cmd_wrapper
from treasure_map.lib.hunt.wrapper_propagation import (
    find_wrapper_propagated_candidates,
)
from treasure_map.lib.pattern import scan
from treasure_map.lib.pattern.classes import CMD, COPY, FORMAT
from treasure_map.lib.reachability import grade_candidate
from treasure_map.lib.reachability.taint import locate_sink_arg

logger = logging.getLogger(__name__)


def _load_caller_ids(db_path: Path | str) -> dict[int, list[int]]:
    """Map callee_func_id -> [caller_func_id, …] from the analysis.db xrefs (read-only).

    One-hop only: the direct function-level callers recorded for each function. Used by the
    caller-constant downweight; absent/empty xrefs simply yield no callers (no downweight)."""
    uri = f"file:{Path(db_path)}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    callers: dict[int, list[int]] = {}
    try:
        rows = conn.execute(
            "SELECT callee_func_id, caller_func_id FROM xrefs "
            "WHERE callee_func_id IS NOT NULL AND caller_func_id IS NOT NULL"
        ).fetchall()
    except sqlite3.OperationalError:
        return callers  # no xrefs table / shape mismatch -> no caller data
    finally:
        conn.close()
    for callee_id, caller_id in rows:
        callers.setdefault(int(callee_id), []).append(int(caller_id))
    return callers


def _load_entry_index(db_path: Path | str) -> EntryIndex:
    """Load the rootfs entry-evidence index (L0.5 script_calls / web_endpoints) once, read-only."""
    uri = f"file:{Path(db_path)}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    try:
        return load_entry_index(conn)
    finally:
        conn.close()


_SINK_CLASS_MEMBERS: dict[str, frozenset[str]] = {"cmd": CMD, "copy": COPY, "format": FORMAT}

# Shell-running command sinks. When a function calls several command sinks, anchor to one of
# these over an exec-family sink (Bug1): system/popen/doSystem run a shell, so anchoring to the
# alphabetically-first execX would let the no_shell_exec form note hide the real shell sink.
_SHELL_CMD_SINKS: frozenset[str] = frozenset({"system", "popen", "doSystem"})


@dataclass(frozen=True)
class Analyzer2Stats:
    scanned: int  # function rows R-pattern considered
    matches: int  # call-sequence shape matches found
    instances_written: int  # graded instances persisted into the atlas
    by_status: dict[str, int]  # reachability_status -> count, over written instances
    oss_excluded: int  # distinct OSS/third-party binaries R-pattern excluded
    wrapper_propagated: int = 0  # cmd candidates recovered via one-hop thin-wrapper propagation


def _load_known_components(db_path: Path | str) -> set[str]:
    """The OSS-binary name set (components-table membership) the shape scan also excludes."""
    uri = f"file:{Path(db_path)}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        rows = conn.execute(
            "SELECT DISTINCT b.name FROM components c JOIN binaries b ON b.id = c.binary_id"
        ).fetchall()
    except sqlite3.OperationalError:
        return set()
    finally:
        conn.close()
    return {r[0] for r in rows}


def _wrapper_fingerprint(source_class: str, wrapped_sink: str) -> str:
    """Deterministic coarse fingerprint for the wrapper-propagated cmd shape (one per
    source_class + wrapped sink), distinct from the rich call-sequence fingerprints."""
    basis = f"wrapper-cmd|{source_class}|{wrapped_sink}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def _sink_name_for(callees: list[str], sink_class: str) -> str | None:
    """Return the concrete sink callee for a sink_class, anchoring to the most dangerous one.

    Deterministic: a shell-running command sink (system/popen/doSystem) is preferred over an
    exec-family sink so a coexisting shell sink is never masked (Bug1); ties break alphabetically.
    """
    members = _SINK_CLASS_MEMBERS.get(sink_class)
    if not members:
        return None
    hits = sorted(name for name in callees if name in members)
    if not hits:
        return None
    return min(hits, key=lambda name: (name not in _SHELL_CMD_SINKS, name))


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
    all_funcs = load_functions(db_path)
    funcs: dict[int, FuncRow] = {f.func_id: f for f in all_funcs}
    callers_of = _load_caller_ids(db_path)
    entry_index = _load_entry_index(db_path)
    # Factor ① (recall): functions whose only command sink is reached one hop through a thin
    # wrapper — invisible to the shape scan (no command sink among their own callees).
    wrapper_candidates = find_wrapper_propagated_candidates(
        all_funcs, _load_known_components(db_path)
    )

    by_status = {"confirmed": 0, "blocked": 0, "unknown": 0}
    instances_written = 0
    wrapper_propagated = 0

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
                sink_arg = (
                    locate_sink_arg(row.pseudocode, sink_name) if sink_name is not None else None
                )
                if sink_name is None:
                    status, blocking = "unknown", None
                else:
                    verdict = grade_candidate(row.pseudocode, callees, sink_name)
                    status, blocking = verdict.status, verdict.blocking_mechanism

                # FP-suppression labels written into existing neutral fields (read-side ordering
                # downweights them; nothing is removed or graded blocked). origin recognizes
                # statically-linked third-party library code (function-symbol granularity, beyond
                # the binary-level OSS exclusion); a form note marks a known low-yield shape. Only
                # attach a form note when the grader left blocking_mechanism open.
                origin = library_origin(match.func_ref.func_name) or "unknown"
                if blocking is None:
                    callers_pc = [
                        funcs[cid].pseudocode or ""
                        for cid in callers_of.get(match.func_ref.func_id, ())
                        if cid in funcs
                    ]
                    blocking = detect_form_signal(
                        sink_name=sink_name,
                        pseudocode=row.pseudocode,
                        callees=callees,
                        sink_arg=sink_arg,
                        func_name=match.func_ref.func_name,
                        callers_pseudocode=callers_pc,
                    )
                # Recall fallback: a bare sink with no recognized in-function source (and no
                # constructed shell command — cmd_injection_shape is exempt; its shell-ish literal
                # is signal enough that the value may be caller-supplied) is listed but ranked low.
                if (
                    blocking is None
                    and match.source_class == "unknown"
                    and match.pattern_kind != "cmd_injection_shape"
                ):
                    blocking = "bare_sink"

                # Neutral STRUCTURAL fact about the function this candidate lives in: is it a thin
                # wrapper that forwards a parameter straight to a shell command sink, and to which
                # sink. Recorded for a later analysis layer to consume; it is NOT read here, by the
                # form-note downweight, or by the read-side score — recording it changes neither
                # this candidate's recall nor its review-ordering rank.
                thin_wrapper, wrapped_sink = is_thin_cmd_wrapper(row.pseudocode, callees)

                # Structured flow EVIDENCE for command-sink candidates (the partition L3 is about):
                # source classification, one-hop value flow, sanitizer presence (coverage=unjudged),
                # rootfs entry sites, and the honest trace boundary. Material for a later agent —
                # NOT a verdict; nothing here reads it back into recall, the score, or the grade.
                flow_evidence: str | None = None
                if match.sink_class == "cmd":
                    sites = entry_index.sites_for(row.binary_name, row.binary_path)
                    flow_evidence = json.dumps(
                        build_flow_evidence(
                            pseudocode=row.pseudocode,
                            callees=callees,
                            sink_arg=sink_arg,
                            entry_sites=sites,
                        ),
                        sort_keys=True,
                    )

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
                        # Candidate locatability: which binary to open in the decompiler. Carried
                        # from the source build so the candidate stays locatable once analysis.db
                        # is gone (atlas is the persistent store). Falls back to the bare name when
                        # the source has no path. Content hash is stored only (no consumer yet).
                        binary_path=row.binary_path or row.binary_name,
                        binary_content_hash=row.binary_sha256,
                        scope_origin="intra",
                        origin=origin,
                        is_thin_cmd_wrapper=thin_wrapper,
                        wrapped_sink=wrapped_sink,
                        flow_evidence=flow_evidence,
                    ),
                    commit=False,
                )
                instances_written += 1
                by_status[status] += 1

            # ── Factor ① recall pass: one-hop thin-wrapper propagation ──────────────────
            # A function whose command sink hides inside a thin wrapper it calls becomes a cmd
            # candidate here (the shape scan could not see the sink among its own callees). The
            # candidate is graded "unknown"/L0 — the real sink is across a call boundary, so an
            # intra-procedural confirmation does not hold; the wrapper hop is stated in evidence.
            # New candidates run through the SAME FP-suppression (a constant / charset-constrained
            # argument forwarded to the wrapper is downweighted) so a safe fanout stays low.
            for wc in wrapper_candidates:
                f = wc.func
                f_pseudocode = f.pseudocode or ""
                f_callees = _parse_callees(f.callees)
                sink_arg = locate_sink_arg(f_pseudocode, wc.wrapper_name)
                blocking = wrapper_propagation_form_note(f_pseudocode, wc.wrapper_name, sink_arg)
                evidence = build_flow_evidence(
                    pseudocode=f_pseudocode,
                    callees=f_callees,
                    sink_arg=sink_arg,
                    entry_sites=entry_index.sites_for(f.binary_name, f.binary_path),
                    wrapper={"name": wc.wrapper_name, "wrapped_sink": wc.wrapped_sink},
                )
                source_class = (
                    "external_input" if evidence["source_kind"] == "free_string" else ("unknown")
                )
                pattern_id = upsert_pattern(
                    atlas,
                    source_class=source_class,
                    sink_class="cmd",
                    call_sequence_shape=f"wrapper-cmd:{wc.wrapped_sink}",
                    structural_fingerprint=_wrapper_fingerprint(source_class, wc.wrapped_sink),
                    fingerprint_algo_version="callseq-v1",
                    commit=False,
                )
                add_instance(
                    atlas,
                    InstanceRow(
                        pattern_id=pattern_id,
                        pseudocode_hash=f.pseudocode_hash,
                        source_anchor=f.name,
                        sink_anchor=wc.wrapped_sink,  # the real sink, one hop via the wrapper
                        source_run_id=source_run_id,
                        reachability_status="unknown",
                        blocking_mechanism=blocking,
                        provenance_level="L0",
                        # Distinct suffix so a function that is ALSO a direct candidate (it is not,
                        # by construction) never collides; this is the wrapper-recovered instance.
                        evidence_ref=f"{source_run_id}#fn{f.func_id}@cmd_via_wrapper",
                        binary_path=f.binary_path or f.binary_name,
                        binary_content_hash=f.binary_sha256,
                        scope_origin="intra",
                        origin=library_origin(f.name) or "unknown",
                        flow_evidence=json.dumps(evidence, sort_keys=True),
                    ),
                    commit=False,
                )
                instances_written += 1
                wrapper_propagated += 1
                by_status["unknown"] += 1
    finally:
        atlas.close()

    return Analyzer2Stats(
        scanned=result.stats.functions_scanned,
        matches=len(result.matches),
        instances_written=instances_written,
        by_status=by_status,
        oss_excluded=result.stats.oss_binaries_excluded,
        wrapper_propagated=wrapper_propagated,
    )
