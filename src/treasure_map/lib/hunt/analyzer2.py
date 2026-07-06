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
from typing import Any

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import InstanceRow, NvramDefaultRow, NvramFlowRow
from treasure_map.lib.atlas.writer import (
    add_instance,
    add_nvram_default_rows,
    add_nvram_flow_rows,
    delete_run_instances,
    delete_run_nvram_defaults,
    delete_run_nvram_flow,
    upsert_pattern,
)
from treasure_map.lib.diff.loader import FuncRow, load_functions
from treasure_map.lib.hunt.downweight import (
    CONST_SINK_ARG,
    detect_form_signal,
    library_origin,
    wrapper_propagation_form_note,
)
from treasure_map.lib.hunt.evidence import (
    EntryIndex,
    build_flow_evidence,
    build_fmtstr_evidence,
    build_size_evidence,
    load_entry_index,
)
from treasure_map.lib.hunt.facts import is_thin_cmd_wrapper
from treasure_map.lib.hunt.wrapper_propagation import (
    find_wrapper_propagated_candidates,
)
from treasure_map.lib.pattern import scan
from treasure_map.lib.pattern.classes import CMD, COPY, FMT_STRING, FORMAT
from treasure_map.lib.query.nvram import template_has_anchor
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


_SINK_CLASS_MEMBERS: dict[str, frozenset[str]] = {
    "cmd": CMD,
    "copy": COPY,
    "format": FORMAT,
    "fmt_string": FMT_STRING,
}

# Shell-running command sinks. When a function calls several command sinks, anchor to one of
# these over an exec-family sink (Bug1): system/popen/doSystem run a shell, so anchoring to the
# alphabetically-first execX would let the no_shell_exec form note hide the real shell sink.
_SHELL_CMD_SINKS: frozenset[str] = frozenset({"system", "popen", "doSystem"})


def _form_note_contradicts_source(blocking_mechanism: str | None, source_kind: str | None) -> bool:
    """True when a form-downweight note contradicts the candidate's OWN evidence source_kind.

    ★ Red-line invariant (Gate A), enforced at the WRITE path as defense-in-depth: a const_sink_arg
    note must never sit on a candidate whose sink argument is a free_string source — exactly the
    whole-function-regex bug (a constant elsewhere in the function wrongly downweighting a tainted
    callsite). The parameter-specific downweight already prevents this; dropping any note this flags
    guarantees a contradiction can never be persisted even if a future path reintroduces one
    (fail-safe: keep the candidate at its normal score rather than silently bury a real lead). This
    lives on the write side, not in the form-note module, so that module never consumes evidence."""
    return blocking_mechanism == CONST_SINK_ARG and source_kind == "free_string"


@dataclass(frozen=True)
class Analyzer2Stats:
    scanned: int  # function rows R-pattern considered
    matches: int  # call-sequence shape matches found
    instances_written: int  # graded instances persisted into the atlas
    by_status: dict[str, int]  # reachability_status -> count, over written instances
    oss_excluded: int  # distinct OSS/third-party binaries R-pattern excluded
    wrapper_propagated: int = 0  # cmd/fmt candidates recovered via one-hop thin-wrapper propagation
    data_gap_skipped: int = 0  # shape matches dropped with no decompilable body (Ghidra gap)
    nvram_flows_written: int = 0  # gap② per-op nvram read/write rows flattened into the atlas
    nvram_wrapper_edges: int = 0  # gap② A2 indirect key edges recovered through thin nvram wrappers
    nvram_defaults_written: int = 0  # naming-bridge phase 1: router_defaults members flattened
    # fmt-wrapper candidates dropped by the precision gate (uncontrollable/unknown forwarded value).
    # A deliberate recall trim — but COUNTED, not silent, so the summary shows the fmt axis was
    # narrowed (parity with data_gap_skipped; never let a drop imply the candidate set is complete).
    fmt_wrapper_unknown_source_skipped: int = 0


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


# Per-axis labels for a wrapper-propagated candidate: (call_sequence_shape prefix, evidence_ref
# suffix). Keyed by the candidate's sink_class. "cmd" keeps its historical strings byte-for-byte.
_WRAPPER_AXIS: dict[str, tuple[str, str]] = {
    "cmd": ("wrapper-cmd", "cmd_via_wrapper"),
    "fmt_string": ("wrapper-fmt", "fmt_via_wrapper"),
}


def _wrapper_fingerprint(sink_class: str, source_class: str, wrapped_sink: str) -> str:
    """Deterministic coarse fingerprint for a wrapper-propagated shape (one per sink axis +
    source_class + wrapped sink), distinct from the rich call-sequence fingerprints. The "cmd"
    axis reproduces the historical `wrapper-cmd|…` basis exactly (no fingerprint churn)."""
    basis = f"{_WRAPPER_AXIS[sink_class][0]}|{source_class}|{wrapped_sink}"
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


def _load_sink_provenance(db_path: Path | str) -> dict[int, list[dict[str, Any]]]:
    """Map func_id -> parsed sink_arg_provenance list (Ghidra def-use fact) from analysis.db.

    Transport read: ExportFunctions computed the provenance and ghidra_ingest stored it
    it on functions.sink_provenance; here it is loaded so the hunt merges it into the atlas
    instance's flow_evidence (the persistent home). A missing column (older analysis.db) or an
    unparsable cell yields no entry — provenance is additive; its absence never blocks a candidate.
    """
    uri = f"file:{Path(db_path)}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    out: dict[int, list[dict[str, Any]]] = {}
    try:
        rows = conn.execute("SELECT id, sink_provenance FROM functions").fetchall()
    except sqlite3.OperationalError:
        return out  # no column (pre-provenance analysis.db) -> no data
    finally:
        conn.close()
    for func_id, raw in rows:
        if not raw:
            continue
        try:
            data = json.loads(raw)
        except (ValueError, TypeError):
            continue
        if isinstance(data, list) and data:
            out[func_id] = data
    return out


def _load_nvram_ops(db_path: Path | str) -> dict[int, list[dict[str, Any]]]:
    """Map func_id -> parsed nvram_ops list (Ghidra def-use fact) from analysis.db.

    Transport read (mirrors _load_sink_provenance): ExportFunctions.buildNvramOps computed the
    per-function nvram read/write ops and ghidra_ingest stored them on functions.nvram_ops; here
    they are loaded so the hunt flattens them into the atlas nvram_key_flow table. A missing column
    (older analysis.db) or an unparsable cell yields no entry — the key graph is additive.
    """
    uri = f"file:{Path(db_path)}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    out: dict[int, list[dict[str, Any]]] = {}
    try:
        rows = conn.execute("SELECT id, nvram_ops FROM functions").fetchall()
    except sqlite3.OperationalError:
        return out  # no column (pre-gap② analysis.db) -> no data
    finally:
        conn.close()
    for func_id, raw in rows:
        if not raw:
            continue
        try:
            data = json.loads(raw)
        except (ValueError, TypeError):
            continue
        if isinstance(data, list) and data:
            out[func_id] = data
    return out


def _flatten_nvram_ops(
    all_funcs: list[FuncRow],
    ops_by_func: dict[int, list[dict[str, Any]]],
    source_run_id: str,
) -> list[NvramFlowRow]:
    """Flatten every function's nvram read/write ops into per-op nvram_key_flow rows.

    Only key-bearing ops (op read/write) become rows; commit/getall carry no key and are not part
    of a key graph. key_kind is preserved verbatim as the honesty three-state — an op with no or an
    unexpected key_kind is treated as 'unresolved' (never silently dropped). A concrete/template key
    rides in `key`; an unresolved key stores key=None. The write-side value source (a
    controllability signal) is carried as JSON on writes; reads carry none.
    """
    rows: list[NvramFlowRow] = []
    for f in all_funcs:
        ops = ops_by_func.get(f.func_id)
        if not ops:
            continue
        for op in ops:
            if not isinstance(op, dict):
                continue
            opkind = op.get("op")
            if opkind not in ("read", "write"):
                continue  # commit / getall carry no key -> not a key-flow fact
            key_kind = op.get("key_kind")
            if key_kind not in ("constant", "parametric", "unresolved"):
                key_kind = "unresolved"  # honesty: an odd/absent kind is unknown, never dropped
            key = op.get("key")
            key = key if isinstance(key, str) else None
            if key_kind == "parametric" and not template_has_anchor(key or ""):
                # A 'template' with no fixed-literal anchor (%s, %s%s, <built:*>) regex-matches ANY
                # key -> it carries no information about the key, so it is really key-unknown.
                # Store as unresolved: it then drives completeness (never masquerading as a possible
                # match for an arbitrary concrete key). wl%d_ssid keeps its anchor and stays a real
                # parametric template.
                key_kind = "unresolved"
            if key_kind == "unresolved":
                key = None
            value_source = None
            if opkind == "write" and op.get("value_source") is not None:
                value_source = json.dumps(op.get("value_source"), sort_keys=True)
            rows.append(
                NvramFlowRow(
                    source_run_id=source_run_id,
                    key=key,
                    key_kind=key_kind,
                    binary=f.binary_name,
                    func=f.name,
                    op=opkind,
                    value_source=value_source,
                    api=op.get("api") if isinstance(op.get("api"), str) else None,
                )
            )
    return rows


def _load_wrapper_data(
    db_path: Path | str,
) -> tuple[dict[int, dict[str, Any]], dict[int, list[dict[str, Any]]]]:
    """Load the A2 transport columns: func_id -> nvram_wrapper {op,api}, and func_id -> the calls
    that pass a constant literal to a local function. A missing column (older analysis.db) or an
    unparsable cell yields no entry — wrapper-indirect recovery is additive."""
    uri = f"file:{Path(db_path)}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    wrappers: dict[int, dict[str, Any]] = {}
    call_args: dict[int, list[dict[str, Any]]] = {}
    try:
        rows = conn.execute("SELECT id, nvram_wrapper, wrapper_call_args FROM functions").fetchall()
    except sqlite3.OperationalError:
        return wrappers, call_args  # pre-A2 analysis.db -> no data
    finally:
        conn.close()
    for func_id, w_raw, ca_raw in rows:
        if w_raw:
            try:
                w = json.loads(w_raw)
            except (ValueError, TypeError):
                w = None
            if isinstance(w, dict) and w.get("op") in ("read", "write"):
                wrappers[func_id] = w
        if ca_raw:
            try:
                ca = json.loads(ca_raw)
            except (ValueError, TypeError):
                ca = None
            if isinstance(ca, list) and ca:
                call_args[func_id] = ca
    return wrappers, call_args


def _flatten_wrapper_edges(
    all_funcs: list[FuncRow],
    wrappers_by_func_id: dict[int, dict[str, Any]],
    call_args_by_func_id: dict[int, list[dict[str, Any]]],
    source_run_id: str,
) -> list[NvramFlowRow]:
    """A2: resolve each caller's constant-literal wrapper call into an INDIRECT nvram key edge.

    A recognized thin nvram wrapper forwards a caller-supplied key into one nvram accessor, so
    direct extraction records that key as key_from_caller (unresolved). Here, the caller passed a
    resolved constant literal at the CALL SITE (wrapper_call_args), so the caller reads/writes THAT
    key through the wrapper — a real edge the direct graph missed. Marked ``via_wrapper`` so a
    consumer tells a one-hop indirect edge from a direct call. ONE hop only: only a literal at the
    immediate call site is resolved; a forwarded caller-param stays uncaptured (honesty > coverage,
    never a fabricated edge). Wrapper identity is (binary, name) — a caller binds to its own binary.
    """
    by_id = {f.func_id: f for f in all_funcs}
    wrapper_by_bin_name: dict[tuple[str | None, str], dict[str, Any]] = {}
    for fid, w in wrappers_by_func_id.items():
        f = by_id.get(fid)
        if f is not None and f.name:
            wrapper_by_bin_name[(f.binary_name, f.name)] = w
    rows: list[NvramFlowRow] = []
    for f in all_funcs:
        cas = call_args_by_func_id.get(f.func_id)
        if not cas:
            continue
        for ca in cas:
            if not isinstance(ca, dict):
                continue
            callee = ca.get("callee")
            if not isinstance(callee, str):
                continue
            wrap = wrapper_by_bin_name.get((f.binary_name, callee))
            if wrap is None:
                continue  # callee is not a recognized nvram wrapper -> not an indirect edge
            key = ca.get("key")
            key = key if isinstance(key, str) else None
            key_kind = ca.get("key_kind")
            if key_kind not in ("constant", "parametric", "unresolved"):
                key_kind = "unresolved"
            if key_kind == "parametric" and not template_has_anchor(key or ""):
                key_kind = "unresolved"
            if key_kind == "unresolved" or not key:
                continue  # no resolved key -> nothing concrete to connect (never fabricate an edge)
            op = wrap.get("op")
            if op not in ("read", "write"):
                continue
            api = wrap.get("api")
            rows.append(
                NvramFlowRow(
                    source_run_id=source_run_id,
                    key=key,
                    key_kind=key_kind,
                    binary=f.binary_name,
                    func=f.name,
                    op=op,
                    value_source=None,  # written value lives inside the wrapper, unresolved here
                    api=api if isinstance(api, str) else None,
                    via_wrapper=callee,
                )
            )
    return rows


def _load_nvram_defaults(db_path: Path | str, source_run_id: str) -> list[NvramDefaultRow]:
    """Load the router_defaults members from analysis.db into atlas rows (naming-bridge phase 1).

    A resolved member carries key=name (+ default/flags); an unresolved member carries key=None
    (recorded, not dropped, so a located-but-incomplete table stays honest). A missing table (older
    analysis.db) yields no rows — web_settable then reads as 'uncertain', never 'not web-settable'.
    """
    uri = f"file:{Path(db_path)}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        rows = conn.execute(
            "SELECT d.key, d.default_value, d.flags, d.member_index, b.name AS binary "
            "FROM nvram_defaults d LEFT JOIN binaries b ON b.id = d.binary_id"
        ).fetchall()
    except sqlite3.OperationalError:
        return []  # pre-naming-bridge analysis.db -> no data
    finally:
        conn.close()
    return [
        NvramDefaultRow(
            source_run_id=source_run_id,
            key=r[0] if isinstance(r[0], str) else None,
            default_value=r[1] if isinstance(r[1], str) else None,
            flags=r[2] if isinstance(r[2], int) else None,
            member_index=r[3] if isinstance(r[3], int) else None,
            binary=r[4],
        )
        for r in rows
    ]


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
    # Ghidra def-use provenance per function (merged into cmd/fmt flow_evidence below). Function-
    # level fact; keyed by func_id. Empty when the analysis.db predates the provenance column.
    sink_prov_by_func = _load_sink_provenance(db_path)
    # gap② phase 2: per-function nvram read/write ops, flattened into the atlas nvram_key_flow
    # table below so an agent can trace a key's writers/readers across binaries. Empty when the
    # analysis.db predates the nvram_ops column.
    nvram_flow_rows = _flatten_nvram_ops(all_funcs, _load_nvram_ops(db_path), source_run_id)
    # gap② A2: resolve each caller's constant-literal call into a recognized thin nvram wrapper into
    # an INDIRECT key edge (via_wrapper) — the wrapper-indirect reads/writes the direct graph
    # misses. Empty when the analysis.db predates the A2 columns. Appended to the run's flow rows.
    _wrappers, _call_args = _load_wrapper_data(db_path)
    wrapper_edge_rows = _flatten_wrapper_edges(all_funcs, _wrappers, _call_args, source_run_id)
    nvram_flow_rows = nvram_flow_rows + wrapper_edge_rows
    # naming-bridge phase 1: the router_defaults web-settable-key table, flattened into the atlas so
    # get_nvram_key_flow answers "is this source key web-settable?". Empty when analysis.db predates
    # the nvram_defaults table (web_settable then reads 'uncertain', never 'not web-settable').
    nvram_default_rows = _load_nvram_defaults(db_path, source_run_id)

    by_status = {"confirmed": 0, "blocked": 0, "unknown": 0}
    instances_written = 0
    wrapper_propagated = 0
    data_gap_skipped = 0
    fmt_wrapper_unknown_source_skipped = 0

    atlas = open_atlas(Path(atlas_path))
    try:
        # One transaction: drop this run's old rows + write the fresh result, or roll back to
        # the prior result on any error (never leave a half-written run). Only this run_id's
        # instances are deleted; pattern rows (shared accumulation layer) are not.
        with atlas:
            delete_run_instances(atlas, source_run_id, commit=False)
            # gap② phase 2: refresh this run's nvram key-flow rows in the SAME transaction as its
            # instances (replace-by-run: delete own rows, then insert the fresh flatten).
            delete_run_nvram_flow(atlas, source_run_id, commit=False)
            add_nvram_flow_rows(atlas, nvram_flow_rows, commit=False)
            # naming-bridge phase 1: refresh this run's router_defaults rows in the same txn.
            delete_run_nvram_defaults(atlas, source_run_id, commit=False)
            add_nvram_default_rows(atlas, nvram_default_rows, commit=False)
            for match in result.matches:
                row = funcs.get(match.func_ref.func_id)
                # A data gap = no loadable body OR a decompile-error comment (non-empty
                # text, no analyzable code). Both are dropped but COUNTED, so the candidate
                # set is honestly marked incomplete (shown in the hunt summary) — a real sink
                # can hide in exactly such an un-decompilable function, so the agent must know
                # it went unanalyzed. (The `row.pseudocode and` chain narrows the type below,
                # so the error-comment test rides the same guard.)
                if (
                    row is None
                    or not (row.pseudocode and row.pseudocode.strip())
                    or row.pseudocode.strip().startswith("/* decompile_error")
                ):
                    data_gap_skipped += 1
                    logger.info("skipping match with no loadable function body (data gap)")
                    continue

                callees = _parse_callees(row.callees)
                # For a format-string candidate the risky (non-literal) sink was already chosen by
                # the recall detector and carried in evidence; anchor to it so a literal-exempt
                # sibling sink (e.g. a printf("lit") alongside a syslog(buf)) is never anchored.
                sink_name: str | None
                if match.sink_class == "fmt_string":
                    sink_name = match.evidence
                else:
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
                # detect_form_signal reads the cmd danger axis (arg0). Copy sinks are graded on the
                # write length, and format-string sinks on their per-sink format argument, by the
                # grader — so the cmd-axis form notes must not run for either (they would read the
                # wrong argument). Their FP-suppression lives elsewhere: copy in the size grade, the
                # format-string literal exemption in the recall detector.
                if blocking is None and match.sink_class not in ("copy", "fmt_string"):
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
                    ev = build_flow_evidence(
                        pseudocode=row.pseudocode,
                        callees=callees,
                        sink_arg=sink_arg,
                        entry_sites=sites,
                    )
                    # ★ Red-line write-side reconciliation (Gate A): never persist a const_sink_arg
                    # note on a candidate whose sink argument is a free_string source. Drop the
                    # contradicting note (fail-safe: keep the candidate at its normal score). The
                    # parameter-specific downweight already prevents this; this is defense-in-depth.
                    if _form_note_contradicts_source(blocking, ev.get("source_kind")):
                        blocking = None
                    # Merge the Ghidra def-use provenance: the function's per-sink
                    # value-origin facts ride alongside the text-level source_kind/flow_path. A
                    # value-origin facts. A surfaced fact only, never read into recall/score/grade.
                    ev["sink_arg_provenance"] = sink_prov_by_func.get(match.func_ref.func_id, [])
                    flow_evidence = json.dumps(ev, sort_keys=True)
                elif match.sink_class == "copy" and sink_name is not None:
                    # Copy candidates carry SIZE evidence (the danger axis): the length source
                    # classification, the one-hop size flow, any clamp/guard seen (coverage
                    # unjudged), the rootfs entry sites (so copy ranks evenly with cmd/fmt on
                    # entry-reach), and the honest trace boundary. Material for a later agent —
                    # never a verdict; nothing reads it back into recall or the grade.
                    sites = entry_index.sites_for(row.binary_name, row.binary_path)
                    flow_evidence = json.dumps(
                        build_size_evidence(
                            pseudocode=row.pseudocode, sink_name=sink_name, entry_sites=sites
                        ),
                        sort_keys=True,
                    )
                elif match.sink_class == "fmt_string" and sink_name is not None:
                    # Format-string candidates carry flow evidence on the FORMAT argument plus the
                    # format-position facts (which arg is the format; literal-only or not).
                    sites = entry_index.sites_for(row.binary_name, row.binary_path)
                    fmt_ev = build_fmtstr_evidence(
                        pseudocode=row.pseudocode,
                        callees=callees,
                        sink_name=sink_name,
                        entry_sites=sites,
                    )
                    # Same def-use provenance merge as the cmd axis (format-string sinks are in the
                    # provenance lexicon too; key arg = the format position).
                    fmt_ev["sink_arg_provenance"] = sink_prov_by_func.get(
                        match.func_ref.func_id, []
                    )
                    flow_evidence = json.dumps(fmt_ev, sort_keys=True)

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
            # A function whose sink hides inside a thin wrapper it calls becomes a candidate here
            # (the shape scan could not see the sink among its own callees), on either the command
            # or the format-string axis (wc.sink_class). The candidate is graded "unknown"/L0 — the
            # real sink is across a call boundary, so an intra-procedural confirmation cannot hold;
            # the wrapper hop is stated in evidence. New candidates run through the SAME
            # FP-suppression (a constant / charset-constrained argument forwarded to the wrapper is
            # downweighted) so a safe fanout stays low. The forwarded-value flow evidence is
            # axis-agnostic: it classifies the value f hands to the wrapper (the danger axis lives
            # inside the wrapper, named by wrapped_sink), so both axes share build_flow_evidence.
            for wc in wrapper_candidates:
                f = wc.func
                f_pseudocode = f.pseudocode or ""
                f_callees = _parse_callees(f.callees)
                shape_prefix, ref_suffix = _WRAPPER_AXIS[wc.sink_class]
                sink_arg = locate_sink_arg(f_pseudocode, wc.wrapper_name)
                blocking = wrapper_propagation_form_note(f_pseudocode, wc.wrapper_name, sink_arg)
                evidence = build_flow_evidence(
                    pseudocode=f_pseudocode,
                    callees=f_callees,
                    sink_arg=sink_arg,
                    entry_sites=entry_index.sites_for(f.binary_name, f.binary_path),
                    wrapper={"name": wc.wrapper_name, "wrapped_sink": wc.wrapped_sink},
                )
                # ★ Red-line write-side reconciliation (Gate A): a wrapper-forwarded free_string
                # must never carry a const_sink_arg note (drop it; keep its normal rank).
                if _form_note_contradicts_source(blocking, evidence.get("source_kind")):
                    blocking = None
                source_class = (
                    "external_input" if evidence["source_kind"] == "free_string" else ("unknown")
                )
                # 缺口① precision gate (format-string axis only): wrapper propagation is
                # L3's sole recall-amplifying step, so on the fmt axis it must rest on a
                # controllable source. A fmt candidate whose forwarded value is not a free
                # (externally-influenced) string is dropped: variadic loggers (vsyslog /
                # vfprintf) are ubiquitous, so without this the amplification floods the set
                # with calls into legitimate logging wrappers whose input is unconfirmed
                # (measured ~90% of fmt wrapper candidates), diluting the real controllable-
                # input deep chains. Dropping an unknown-source candidate creates NO false-
                # negative — an uncontrollable source is not a real format-string-injection
                # path. The command axis is deliberately unchanged: a constant / charset-
                # constrained argument forwarded to a shell wrapper stays a downweighted lead.
                if wc.sink_class == "fmt_string" and source_class == "unknown":
                    # Counted, not silent: the fmt axis was intentionally narrowed here, and the
                    # summary must show it rather than let the candidate set read as complete.
                    fmt_wrapper_unknown_source_skipped += 1
                    continue
                # Def-use provenance for the wrapper function's own sinks. The real
                # sink is one hop away, but the forwarding function's provenance still tells the
                # agent where the forwarded value comes from. A surfaced fact, never scored.
                evidence["sink_arg_provenance"] = sink_prov_by_func.get(f.func_id, [])
                pattern_id = upsert_pattern(
                    atlas,
                    source_class=source_class,
                    sink_class=wc.sink_class,
                    call_sequence_shape=f"{shape_prefix}:{wc.wrapped_sink}",
                    structural_fingerprint=_wrapper_fingerprint(
                        wc.sink_class, source_class, wc.wrapped_sink
                    ),
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
                        # The axis suffix also keeps a cmd- and a fmt-via-wrapper recovery of the
                        # same function from colliding.
                        evidence_ref=f"{source_run_id}#fn{f.func_id}@{ref_suffix}",
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
        data_gap_skipped=data_gap_skipped,
        nvram_flows_written=len(nvram_flow_rows),
        nvram_wrapper_edges=len(wrapper_edge_rows),
        nvram_defaults_written=len(nvram_default_rows),
        fmt_wrapper_unknown_source_skipped=fmt_wrapper_unknown_source_skipped,
    )
