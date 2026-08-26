# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
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
  evidence_ref holds only a neutral per-instance locator (run + binary/function anchor).
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

from treasure_map.lib import facts
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import (
    DetectorScanStatusRow,
    ExecEdgeRow,
    InstanceRow,
    NvramDefaultRow,
    NvramFlowRow,
    RunCapabilityRow,
    StringKeyedEdgeRow,
    WebFormFieldRow,
)
from treasure_map.lib.atlas.writer import (
    add_detector_status,
    add_exec_edges,
    add_instance,
    add_nvram_default_rows,
    add_nvram_flow_rows,
    add_run_capabilities,
    add_string_keyed_edges,
    add_web_form_field_rows,
    begin_run,
    delete_run_capabilities,
    delete_run_detector_status,
    delete_run_exec_edges,
    delete_run_instances,
    delete_run_nvram_defaults,
    delete_run_nvram_flow,
    delete_run_string_keyed_edges,
    delete_run_web_form_fields,
    finish_run,
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
from treasure_map.lib.hunt.exec_edges import (
    UNSUPPORTED_NOTE,
    ExecEdgeInventory,
    build_exec_edges,
    build_symlink_index,
    exec_entry_sites,
)
from treasure_map.lib.hunt.facts import is_thin_cmd_wrapper
from treasure_map.lib.hunt.fmt_provenance import constant_format_record, format_argument
from treasure_map.lib.hunt.refs import _WRAPPER_AXIS, build_evidence_ref
from treasure_map.lib.hunt.wrapper_propagation import (
    find_wrapper_propagated_candidates,
)
from treasure_map.lib.pattern import scan
from treasure_map.lib.pattern.classes import (
    CMD,
    COPY,
    FMT_STRING,
    FORMAT,
    PATH_SINK,
    all_path_calls_literal,
    path_arg_ident,
)
from treasure_map.lib.query.nvram import template_has_anchor
from treasure_map.lib.reachability import grade_candidate
from treasure_map.lib.reachability.taint import _IDENT_RE, locate_sink_arg
from treasure_map.version import __version__

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


def _load_entry_index(
    db_path: Path | str, exec_sites: dict[str, list[dict[str, Any]]] | None = None
) -> EntryIndex:
    """Load the rootfs entry-evidence index (L0.5 script_calls / web_endpoints) once, read-only.

    ``exec_sites`` adds the cross-binary launch sites computed earlier in this hunt — a different
    source from the two rootfs tables, so it arrives as an argument instead of a query."""
    uri = f"file:{Path(db_path)}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    try:
        return load_entry_index(conn, exec_sites=exec_sites)
    finally:
        conn.close()


_SINK_CLASS_MEMBERS: dict[str, frozenset[str]] = {
    "cmd": CMD,
    "copy": COPY,
    "format": FORMAT,
    "fmt_string": FMT_STRING,
    "path_sink": PATH_SINK,
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
    web_form_fields_written: int = 0  # M1 SaTC front-end: editable web form fields flattened
    # fmt-wrapper candidates DEMOTED (not dropped) because the forwarded value's controllability is
    # unknown. They stay in the corpus and stay queryable; the read-side ladder ranks them below a
    # controllable source. Counted so the summary shows how much of the fmt axis rests on a '?'.
    fmt_wrapper_unknown_source_demoted: int = 0


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


# The sink_class string the format axis carries (the key _WRAPPER_AXIS uses for it).
FMT_STRING_CLASS = "fmt_string"


def _wrapper_sink_arg(pseudocode: str, wrapper_name: str, fmt_index: int | None) -> str | None:
    """The identifier feeding the wrapper's dangerous argument — at the FORMAT position when one is
    known, otherwise the first argument.

    ``fmt_index`` is set only for a format-axis candidate whose wrapper signature pinned its format
    position; the command axis, and a format wrapper whose position could not be established, keep
    the historical first-argument reading unchanged.

    A literal at the format position yields None, not an identifier: there is no VARIABLE feeding
    the sink, and manufacturing one out of the literal's first word would send the taint reader
    chasing a name that does not exist. The constant is carried by the provenance record instead."""
    if fmt_index is None:
        return locate_sink_arg(pseudocode, wrapper_name)
    arg = format_argument(pseudocode, wrapper_name, fmt_index)
    if arg is None:
        return locate_sink_arg(pseudocode, wrapper_name)
    ident = _IDENT_RE.search(arg)
    if ident is None or arg.lstrip().startswith('"'):
        return None
    return ident.group(0)


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


def _load_string_keyed_edges(db_path: Path | str) -> dict[int, dict[str, Any]]:
    """Map func_id -> parsed string_keyed_edges object (detector B strcmp-ladder edges), with the
    function's address injected as ``_from_func_addr``.

    Transport read (mirrors _load_nvram_ops): ExportFunctions.buildStringKeyedEdges computed the
    per-function {edges, completeness} and ghidra_ingest stored it on functions.string_keyed_edges;
    here it is loaded so the hunt flattens it into the atlas string_keyed_edge table. A missing
    column (older analysis.db) or an unparsable cell yields no entry — the edge layer is additive.
    """
    uri = f"file:{Path(db_path)}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    out: dict[int, dict[str, Any]] = {}
    try:
        rows = conn.execute("SELECT id, address, string_keyed_edges FROM functions").fetchall()
    except sqlite3.OperationalError:
        return out  # no column (pre-detector-B analysis.db) -> no data
    finally:
        conn.close()
    for func_id, addr, raw in rows:
        if not raw:
            continue
        try:
            data = json.loads(raw)
        except (ValueError, TypeError):
            continue
        if isinstance(data, dict) and data.get("edges"):
            data["_from_func_addr"] = addr
            out[func_id] = data
    return out


def _flatten_string_keyed_edges(
    all_funcs: list[FuncRow],
    edges_by_func: dict[int, dict[str, Any]],
    source_run_id: str,
) -> list[StringKeyedEdgeRow]:
    """Flatten each function's strcmp-ladder edges into per-(key, callee) string_keyed_edge rows.

    ★ IRON LAW: an enumerated edge is a FACT, never a reachability verdict — the reachability layer
    reads these as a lead (key X gates callee Y), the candidate stays reachability=unknown. Each row
    carries the callee anchor (name + addr + kind, BinDiff-alignable) and a fine-grained status
    the diff matches by region: the per-edge gate-resolution issue (partial) takes precedence, else
    the function-region completeness (an unparsed switch marks the region incomplete, so a
    cross-version edge delta in it reads as undetermined, not a real add/remove). A key whose gate
    did not resolve to a callee set is NOT dropped — it emits a callee-less row, keeping the lead.
    """
    rows: list[StringKeyedEdgeRow] = []
    for f in all_funcs:
        data = edges_by_func.get(f.func_id)
        if not data:
            continue
        func_addr = data.get("_from_func_addr")
        _fc = data.get("completeness")
        func_comp: dict[str, Any] = _fc if isinstance(_fc, dict) else {}
        scope = func_comp.get("scope") or (f"{f.name}@{func_addr}" if f.name else func_addr)
        edges = data.get("edges")
        if not isinstance(edges, list):
            continue
        for edge in edges:
            if not isinstance(edge, dict):
                continue
            key = edge.get("key")
            key = key if isinstance(key, str) else None
            mechanism = edge.get("mechanism")
            if mechanism not in ("strcmp_gate", "static_string_table"):
                mechanism = "strcmp_gate"
            ladder_size = edge.get("ladder_size")
            ladder_size = ladder_size if isinstance(ladder_size, int) else None
            _ta = edge.get("table_addr")
            table_addr = _ta if isinstance(_ta, str) else None
            _ec = edge.get("completeness")
            edge_comp: dict[str, Any] = _ec if isinstance(_ec, dict) else {}
            # The per-edge gate issue is the most specific signal; else the function-region status.
            if edge_comp.get("status") in ("partial", "incomplete"):
                c_status = edge_comp["status"]
                c_reason = edge_comp.get("reason")
            else:
                c_status = func_comp.get("status", "complete")
                c_reason = func_comp.get("reason")
            if c_status not in ("complete", "incomplete", "partial"):
                c_status = "complete"
            common: dict[str, Any] = {
                "source_run_id": source_run_id,
                "binary": f.binary_name,
                "from_function": f.name,
                "from_func_addr": func_addr if isinstance(func_addr, str) else None,
                "key": key,
                "mechanism": mechanism,
                "ladder_size": ladder_size,
                "table_addr": table_addr,
                "completeness_status": c_status,
                "completeness_reason": c_reason if isinstance(c_reason, str) else None,
                "completeness_scope": scope if isinstance(scope, str) else None,
            }
            callees = edge.get("callees")
            valid = [c for c in callees if isinstance(c, dict)] if isinstance(callees, list) else []
            if not valid:
                # Gate resolved no callee set: keep the key as a lead (callee-less row), never drop.
                rows.append(StringKeyedEdgeRow(**common))
                continue
            for callee in valid:
                rows.append(
                    StringKeyedEdgeRow(
                        callee_name=callee.get("name"),
                        callee_addr=callee.get("addr"),
                        callee_kind=callee.get("kind"),
                        **common,
                    )
                )
    return rows


def _flatten_string_tables(db_path: Path | str, source_run_id: str) -> list[StringKeyedEdgeRow]:
    """Flatten detector A's static {string -> funcptr} dispatch-table entries into the SAME atlas
    string_keyed_edge table (mechanism='static_string_table'), one row per entry.

    ★ IRON LAW: a table entry is an ENUMERATED edge (key -> handler), never a reachability verdict.
    The reachability layer reads it as a key lead, the candidate stays unknown. A static table has
    no source function (it lives in .rodata), so from_function/from_func_addr are None and the
    table_addr is set; the callee anchor is the handler's {name, addr, kind}. The detector-level
    completeness rides on every row (incomplete by construction — MVP absolute-2-field only), so a
    cross-version delta in an unhandled table form reads as undetermined, not a real add/remove. A
    missing table (older analysis.db) yields no rows — the capability is still registered anyway.
    """
    uri = f"file:{Path(db_path)}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        rows = conn.execute(
            "SELECT s.table_addr, s.key, s.func_name, s.func_addr, s.func_kind, "
            "s.completeness_status, s.completeness_reason, s.completeness_scope, b.name AS binary "
            "FROM string_tables s LEFT JOIN binaries b ON b.id = s.binary_id"
        ).fetchall()
    except sqlite3.OperationalError:
        return []  # pre-detector-A analysis.db -> no data (capability still registered)
    finally:
        conn.close()
    out: list[StringKeyedEdgeRow] = []
    for r in rows:
        c_status = r[5] if r[5] in ("complete", "incomplete", "partial") else "incomplete"
        out.append(
            StringKeyedEdgeRow(
                source_run_id=source_run_id,
                binary=r[8],
                from_function=None,  # a static table has no source function (it lives in .rodata)
                from_func_addr=None,
                key=r[1] if isinstance(r[1], str) else None,
                mechanism="static_string_table",
                callee_name=r[2] if isinstance(r[2], str) else None,
                callee_addr=r[3] if isinstance(r[3], str) else None,
                callee_kind=r[4] if isinstance(r[4], str) else None,
                ladder_size=None,  # ladder_size is a strcmp-ladder concept; N/A for a static table
                table_addr=r[0] if isinstance(r[0], str) else None,
                completeness_status=c_status,
                completeness_reason=r[6] if isinstance(r[6], str) else None,
                completeness_scope=r[7] if isinstance(r[7], str) else None,
            )
        )
    return out


def _load_exec_inventory(db_path: Path | str) -> ExecEdgeInventory:
    """Everything a launch token is matched against: the link inventory, the binary names, and the
    script names.

    Each table is read independently and an absent one degrades to empty rather than failing: an
    analysis.db predating the link inventory still produces edges, they simply resolve fewer
    tokens (reported unmatched, never invented). The binary set is the run's own inventory — the
    same set a reader can open — so "resolved" always means "you can go and read this", and the
    script map carries paths for the same reason: a resolved script edge names a file the reader
    can open, not a bare word."""
    uri = f"file:{Path(db_path)}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        try:
            link_rows = conn.execute(
                "SELECT link_path, link_name, target_name, corrupt_reason FROM fs_symlinks"
            ).fetchall()
        except sqlite3.OperationalError:
            link_rows = []  # pre-inventory analysis.db -> no link resolution, never a hard failure
        try:
            bins = {r[0] for r in conn.execute("SELECT name FROM binaries") if r[0]}
        except sqlite3.OperationalError:
            bins = set()
        try:
            # name -> path(s). The query selects shell scripts ONLY, which is what makes it safe
            # for the resolver to trust inventory membership on its own: a web asset or a config
            # file cannot reach it. Several paths under one basename are kept, not collapsed —
            # they are genuinely different scripts, and choosing between them is not tmap's call.
            scripts: dict[str, list[str]] = {}
            for name, path in conn.execute(
                "SELECT name, path FROM non_binary_files WHERE kind = 'shell_script'"
            ):
                if name and path and path not in scripts.setdefault(name, []):
                    scripts[name].append(path)
        except sqlite3.OperationalError:
            scripts = {}
    finally:
        conn.close()
    return ExecEdgeInventory(
        symlinks=build_symlink_index([(r[0], r[1], r[2], r[3]) for r in link_rows]),
        bin_names=frozenset(bins),
        scripts={k: tuple(sorted(v)) for k, v in scripts.items()},
    )


def _flatten_exec_edges(
    db_path: Path | str,
    all_funcs: list[FuncRow],
    sink_prov_by_func: dict[int, list[dict[str, Any]]],
    source_run_id: str,
) -> list[ExecEdgeRow]:
    """Flatten this run's cross-binary launch edges out of the sink argument provenance.

    Reads only what the extractor already recorded — it does not re-enumerate callsites, which is
    the boundary that keeps this a projection of existing facts rather than a second detector. An
    analysis.db with no provenance yields no edges, and the scan status says so."""
    return build_exec_edges(
        all_funcs, sink_prov_by_func, _load_exec_inventory(db_path), source_run_id
    )


def _exec_scan_status(
    edge_rows: list[ExecEdgeRow], all_funcs: list[FuncRow], source_run_id: str
) -> list[DetectorScanStatusRow]:
    """One honesty row per binary for the launch-edge pass, written EVEN AT zero edges.

    Without it an empty result reads as a confident "this binary launches nothing", which would be
    wrong in every one of the ways ``unsupported_note`` lists — most sharply for a binary whose
    command sinks all sit behind a thin wrapper, where the pass genuinely cannot see the callsite.
    A binary with no functions at all still gets a row: it was in scope, and the scan ran."""
    found: dict[str | None, int] = {}
    for row in edge_rows:
        found[row.launcher_binary] = found.get(row.launcher_binary, 0) + 1
    binaries = {f.binary_name for f in all_funcs} | set(found)
    return [
        DetectorScanStatusRow(
            source_run_id=source_run_id,
            binary=binary,
            detector="exec_argv",
            scanned=1,
            supported_scope="system/popen/doSystem command strings + execl*/execv* arg0",
            unsupported_note=UNSUPPORTED_NOTE,
            cap_hit=0,
            found_count=found.get(binary, 0),
        )
        for binary in sorted(binaries, key=lambda b: (b is None, b or ""))
    ]


def _flatten_detector_status(
    db_path: Path | str, source_run_id: str
) -> list[DetectorScanStatusRow]:
    """Flatten analysis.db detector_scan_status into per-(run, binary, detector) atlas rows.

    Crosses the analysis.db -> atlas boundary alongside the edge facts, so the consumer query (which
    reads ATLAS) can attach a detector's honesty status to an EMPTY string_keyed_edge result. A
    missing table (older analysis.db, not re-scanned) yields no rows -- the query then reports 'no
    status recorded', never a confident negative."""
    uri = f"file:{Path(db_path)}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        rows = conn.execute(
            "SELECT d.detector, d.scanned, d.supported_scope, d.unsupported_note, d.cap_hit, "
            "d.found_count, b.name AS binary "
            "FROM detector_scan_status d LEFT JOIN binaries b ON b.id = d.binary_id"
        ).fetchall()
    except sqlite3.OperationalError:
        return []  # pre-feature analysis.db -> no status (query reports 'no status recorded')
    finally:
        conn.close()
    return [
        DetectorScanStatusRow(
            source_run_id=source_run_id,
            binary=r[6],
            detector=r[0] if isinstance(r[0], str) else "string_tables",
            scanned=int(r[1]) if r[1] is not None else 0,
            supported_scope=r[2] if isinstance(r[2], str) else None,
            unsupported_note=r[3] if isinstance(r[3], str) else None,
            cap_hit=int(r[4]) if r[4] is not None else 0,
            found_count=int(r[5]) if r[5] is not None else 0,
        )
        for r in rows
    ]


def _one_hop_edge_leads(
    all_funcs: list[FuncRow],
    edge_rows: list[StringKeyedEdgeRow],
) -> dict[tuple[str | None, str], list[dict[str, Any]]]:
    """Map (binary, function) -> the string-key leads that structurally reach it in ONE hop.

    DOWNWARD traversal — the same direction wrapper propagation reads: start at each edge's CALLEE
    and read ITS direct callees. One pass over the edge-callee set, so a fan-out handler naturally
    hands its key to every function below it. Zero-hop (the edge callee itself) is NOT produced
    here: the reachability layer already answers that straight from the atlas edge table.

    ★ IRON LAW: a lead is a FACT (a key's dispatch structurally selects this code path), never a
    reachability verdict — the reader keeps reachability=unknown.

    ★ And one hop is STRUCTURAL ONLY. "E calls C" does NOT mean the key's data reaches C: an edge
    callee is often a fat handler that calls plenty of things unrelated to the key it matched. The
    lead says where to look; the note that carries it must say the data arrival is unproven.

    Deliberately NO thinness gate. Wrapper propagation needs one because it CREATES candidates, and
    it must pass through a THIN forwarder. This only ANNOTATES an existing candidate, and the edge
    callees worth following are exactly the FAT handlers — a thinness filter would drop them.
    """
    by_bin_name: dict[tuple[str | None, str], FuncRow] = {
        (f.binary_name, f.name): f for f in all_funcs if f.name
    }
    out: dict[tuple[str | None, str], list[dict[str, Any]]] = {}
    seen: set[tuple[str | None, str, str, str]] = set()
    for e in edge_rows:
        if not e.callee_name or not e.key:
            continue
        callee_row = by_bin_name.get((e.binary, e.callee_name))
        if callee_row is None:
            continue  # the edge callee is not a known function here -> nothing to walk down into
        for callee in _parse_callees(callee_row.callees):
            if not callee or callee == e.callee_name:
                continue
            sig = (e.binary, callee, e.key, e.callee_name)
            if sig in seen:
                continue  # one function may be called several times / by several ladder arms
            seen.add(sig)
            out.setdefault((e.binary, callee), []).append(
                {
                    "via": "string_keyed_edge",
                    "key": e.key,
                    "hops": 1,
                    "through": e.callee_name,
                    "mechanism": e.mechanism,
                }
            )
    return out


def _attach_edge_leads(
    ev: dict[str, Any],
    edge_leads: dict[tuple[str | None, str], list[dict[str, Any]]],
    binary: str | None,
    func_name: str | None,
) -> None:
    """Ride this function's one-hop string-key leads along on its flow evidence.

    A surfaced FACT only: nothing reads it back into recall, the grade, or the rank — it is an
    annotation the reachability layer renders, and the candidate's reachability stays unknown.
    Absent when there are none (never an empty key), so old evidence reads identically.
    """
    if not func_name:
        return
    leads = edge_leads.get((binary, func_name))
    if leads:
        ev["reachability_leads"] = leads


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


def _load_web_form_fields(db_path: Path | str, source_run_id: str) -> list[WebFormFieldRow]:
    """Load editable web form field names from analysis.db into atlas rows (M1 SaTC front-end).

    Each row is a USER-EDITABLE field name + the asset it came from. A missing table (an analysis.db
    built before M1, or one with no web assets) yields no rows — web_settable then reads
    'uncertain', NEVER 'not settable' (the false-negative red line)."""
    uri = f"file:{Path(db_path)}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        rows = conn.execute(
            "SELECT w.field_keyword, f.path, w.source_rule "
            "FROM web_form_fields w LEFT JOIN non_binary_files f ON f.id = w.file_id"
        ).fetchall()
    except sqlite3.OperationalError:
        return []  # pre-M1 analysis.db -> no data (web_settable reads 'uncertain', never 'not')
    finally:
        conn.close()
    return [
        WebFormFieldRow(
            source_run_id=source_run_id,
            field_keyword=r[0] if isinstance(r[0], str) else None,
            source_asset=r[1] if isinstance(r[1], str) else None,
            source_rule=r[2] if isinstance(r[2], str) else None,
        )
        for r in rows
        if isinstance(r[0], str) and r[0]
    ]


def run_analyzer2(
    db_path: Path | str,
    atlas_path: Path | str,
    *,
    source_run_id: str,
    firmware_path: str | None = None,
) -> Analyzer2Stats:
    """Scan one analysis.db for shape candidates, grade them, and write atlas instances.

    source_run_id is the neutral per-run id (the device_spread unit). The analysis DB is
    read-only. Writing is REPLACE-BY-RUN: this run's old instances are deleted first and the
    fresh result is written in ONE transaction (re-running a run refreshes it, never doubles
    it). Other runs' append-and-corroborate evidence and all pattern rows are untouched. Raw
    evidence is never persisted.

    Also records this run's lineage in the atlas ``run`` table — the run_id -> analysis.db
    RESOLVER a run-aware fact tool routes on. ``begin_run`` marks it 'in_progress' BEFORE the
    instance write, ``finish_run`` marks it 'complete' AFTER: a crash between leaves 'in_progress'
    (the honest "did not finish" signal), never a run silently missing behind half-written rows.
    ``firmware_path`` is the scanned firmware root when the caller knows it (else NULL).
    """
    result = scan(db_path)
    all_funcs = load_functions(db_path)
    # ★ phase-scale progress: on a large firmware (~218k functions) the hunt is a multi-second pass;
    # log its magnitude so it is visibly running, not hung (does NOT change the hunt algorithm).
    logger.info("hunt: analyzing %d functions", len(all_funcs))
    funcs: dict[int, FuncRow] = {f.func_id: f for f in all_funcs}
    callers_of = _load_caller_ids(db_path)
    # Factor ① (recall): functions whose only command sink is reached one hop through a thin
    # wrapper — invisible to the shape scan (no command sink among their own callees).
    wrapper_candidates = find_wrapper_propagated_candidates(
        all_funcs, _load_known_components(db_path)
    )
    # Ghidra def-use provenance per function (merged into cmd/fmt flow_evidence below). Function-
    # level fact; keyed by func_id. Empty when the analysis.db predates the provenance column.
    # Loaded BEFORE the entry index because the cross-binary launch edges are read out of it and
    # feed that index as a third entry source.
    sink_prov_by_func = _load_sink_provenance(db_path)
    # Cross-binary launch edges ("A's code execs B"), flattened into the atlas exec_edge table and
    # ALSO offered to the entry index: a binary nothing in the rootfs mentions may still be started
    # by another binary, which used to read as a plain coverage gap. ★ Only edges whose target
    # resolved to a real binary become entry sites, and a site never produces a 'blocked' status.
    exec_edge_rows = _flatten_exec_edges(db_path, all_funcs, sink_prov_by_func, source_run_id)
    entry_index = _load_entry_index(db_path, exec_sites=exec_entry_sites(exec_edge_rows))
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
    # M1 SaTC front-end surface: editable web form fields, flattened into the atlas so web_settable
    # can cross them against the back-end nvram_key_flow constant keys. Empty when the analysis.db
    # predates M1 (web_settable then reads 'uncertain', never 'not settable').
    web_form_field_rows = _load_web_form_fields(db_path, source_run_id)
    # detector B: strcmp-ladder string-keyed edges, flattened into the atlas string_keyed_edge table
    # so the reachability layer can annotate a candidate that is an edge callee (a key lead, still
    # unknown). Empty when the analysis.db predates the detector (no re-scan yet).
    string_keyed_edge_rows = _flatten_string_keyed_edges(
        all_funcs, _load_string_keyed_edges(db_path), source_run_id
    )
    # detector A: static {string -> funcptr} dispatch tables land in the SAME atlas edge table
    # (mechanism='static_string_table'), so both detectors share one query + MCP surface + cap key.
    string_keyed_edge_rows += _flatten_string_tables(db_path, source_run_id)
    # detector A honesty status (per binary): flattened into atlas alongside the edges so an EMPTY
    # result carries "scanned / scope / cap_hit" instead of reading as a confident "none".
    detector_status_rows = _flatten_detector_status(db_path, source_run_id)
    # Launch-edge honesty status (per binary), written even at zero edges — an empty result must
    # not read as "this binary launches nothing" when the pass has known structural gaps.
    detector_status_rows += _exec_scan_status(exec_edge_rows, all_funcs, source_run_id)
    # ONE-HOP string-key leads: which candidates sit one direct call below an edge callee. Computed
    # here because the call graph lives in the analysis DB (the atlas holds no callgraph), and rides
    # to the reachability layer on flow_evidence — the same compute-at-hunt/read-at-triage path as
    # entry_reach. Zero-hop needs no precompute: it is a direct atlas edge lookup at read time.
    edge_leads = _one_hop_edge_leads(all_funcs, string_keyed_edge_rows)
    # Capability registry: register that this run produced string-keyed-edge facts. UNCONDITIONAL —
    # the detector code ran in this tmap version, so the capability is present even if it found zero
    # edges (absence-of-findings is not absence-of-capability). A cross-version diff iterates these.
    capability_rows = [
        RunCapabilityRow(
            run_id=source_run_id, capability="reachability.string_keyed_edge", present=1
        ),
        # Registered UNCONDITIONALLY, exactly like the one above: this tmap version ran the
        # launch-edge pass, so the capability is present even on a firmware with zero edges.
        RunCapabilityRow(run_id=source_run_id, capability="reachability.exec_argv_edge", present=1),
    ]

    by_status = {"confirmed": 0, "blocked": 0, "unknown": 0}
    instances_written = 0
    wrapper_propagated = 0
    data_gap_skipped = 0
    fmt_wrapper_unknown_source_demoted = 0

    # Scan-lineage facts (binary/function counts + extraction build hash) for the run row. Read
    # from the analysis.db (best-effort; degrades to None on an older schema, never a hard failure).
    lineage_conn = facts.open_analysis_ro(db_path)
    try:
        lineage = facts.analysis_run_counts(lineage_conn)
    finally:
        lineage_conn.close()

    atlas = open_atlas(Path(atlas_path))
    try:
        # Record the run STARTED (scan_status='in_progress') + its analysis.db path BEFORE writing
        # any instance. A crash mid-write then leaves 'in_progress' (the honest "did not finish"
        # signal), and the run_id -> analysis.db resolver is already recorded. Committed on its own.
        begin_run(
            atlas,
            source_run_id,
            analysis_db_path=str(Path(db_path).resolve()),
            firmware_path=firmware_path,
            build_hash=lineage["build_hash"],
            tool_version=__version__,
            # The decompiler version the SCAN recorded (always a string, 'unknown' when the scan
            # could not confirm one) -- never re-detected here, which would record whatever Ghidra
            # is installed at hunt time instead of the one that produced this analysis.db.
            ghidra_version=lineage["ghidra_version"],
        )
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
            # M1: refresh this run's editable-web-form-field rows in the same txn (replace-by-run).
            delete_run_web_form_fields(atlas, source_run_id, commit=False)
            add_web_form_field_rows(atlas, web_form_field_rows, commit=False)
            # detector B: refresh this run's string-keyed-edge rows + capability registration in the
            # same txn (replace-by-run). The capability is registered even with zero edges.
            delete_run_string_keyed_edges(atlas, source_run_id, commit=False)
            add_string_keyed_edges(atlas, string_keyed_edge_rows, commit=False)
            # Cross-binary launch edges: same replace-by-run refresh, same transaction.
            delete_run_exec_edges(atlas, source_run_id, commit=False)
            add_exec_edges(atlas, exec_edge_rows, commit=False)
            # detector A honesty status: refresh in the SAME txn (replace-by-run). Written even at
            # zero tables so an empty edge result can attach it — the whole reason this exists.
            delete_run_detector_status(atlas, source_run_id, commit=False)
            add_detector_status(atlas, detector_status_rows, commit=False)
            delete_run_capabilities(atlas, source_run_id, commit=False)
            add_run_capabilities(atlas, capability_rows, commit=False)
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
                # The danger axis differs by sink: a path/file sink is graded on its per-sink PATH
                # argument (fopen arg0, openat/unlinkat arg1, …), NOT arg0. Every other sink keeps
                # the historical arg0 command-string axis, byte-for-byte.
                if sink_name is None:
                    sink_arg = None
                elif match.sink_class == "path_sink":
                    sink_arg = path_arg_ident(row.pseudocode, sink_name)
                else:
                    sink_arg = locate_sink_arg(row.pseudocode, sink_name)
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
                # Path/file sinks: a string-literal PATH argument is a compile-time constant
                # (proven-safe). _sink_arg_is_literal (the cmd axis) is shell-gated and reads arg0,
                # so it misses a path literal; mark it on the path axis here. The demotion iron law
                # then sinks a hard-coded path (fopen("/etc/x")) out of the first screen.
                if (
                    blocking is None
                    and match.sink_class == "path_sink"
                    and sink_name is not None
                    and all_path_calls_literal(row.pseudocode, sink_name)
                ):
                    blocking = CONST_SINK_ARG
                # Recall fallback: a bare sink with no recognized in-function source (and no
                # constructed shell command — cmd_injection_shape is exempt; its shell-ish literal
                # is signal enough that the value may be caller-supplied) is listed but ranked low.
                # bare_sink is an exposure SHAPE (a danger signal), NOT a blocking mechanism — it
                # goes in exposure_shape, not blocking_mechanism, so a consumer never reads a danger
                # shape as a mitigation. blocking stays None, so controllability still reads '?'.
                exposure_shape: str | None = None
                if (
                    blocking is None
                    and match.source_class == "unknown"
                    and match.pattern_kind != "cmd_injection_shape"
                ):
                    exposure_shape = "bare_sink"

                # Neutral STRUCTURAL fact about the function this candidate lives in: is it a thin
                # wrapper that forwards a parameter straight to a shell command sink, and to which
                # sink. Recorded for a later analysis layer to consume; it is NOT read here, by the
                # form-note downweight, or by the read-side score — recording it changes neither
                # this candidate's recall nor its review-ordering rank.
                thin_wrapper, wrapped_sink = is_thin_cmd_wrapper(row.pseudocode, callees)

                # Structured flow EVIDENCE for command-sink candidates (the partition L3 is about):
                # source classification, one-hop value flow, sanitizer presence (coverage=unjudged),
                # rootfs entry sites, and the honest trace boundary. NOT a verdict —
                # nothing here reads it back into recall, the score, or the grade.
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
                    _attach_edge_leads(ev, edge_leads, row.binary_name, match.func_ref.func_name)
                    flow_evidence = json.dumps(ev, sort_keys=True)
                elif match.sink_class == "copy" and sink_name is not None:
                    # Copy candidates carry SIZE evidence (the danger axis): the length source
                    # classification, the one-hop size flow, any clamp/guard seen (coverage
                    # unjudged), the rootfs entry sites (so copy ranks evenly with cmd/fmt on
                    # entry-reach), and the honest trace boundary. Never a verdict —
                    # nothing reads it back into recall or the grade.
                    sites = entry_index.sites_for(row.binary_name, row.binary_path)
                    size_ev = build_size_evidence(
                        pseudocode=row.pseudocode, sink_name=sink_name, entry_sites=sites
                    )
                    _attach_edge_leads(
                        size_ev, edge_leads, row.binary_name, match.func_ref.func_name
                    )
                    flow_evidence = json.dumps(size_ev, sort_keys=True)
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
                    _attach_edge_leads(
                        fmt_ev, edge_leads, row.binary_name, match.func_ref.func_name
                    )
                    flow_evidence = json.dumps(fmt_ev, sort_keys=True)
                elif match.sink_class == "path_sink" and sink_name is not None:
                    # Path/file candidates carry flow evidence on the PATH argument (the danger
                    # axis): its source_kind, the one-hop value flow, any sanitizer seen (coverage
                    # unjudged), the rootfs entry sites, and the honest trace boundary. Never a
                    # verdict — nothing reads it back into recall/grade.
                    sites = entry_index.sites_for(row.binary_name, row.binary_path)
                    path_ev = build_flow_evidence(
                        pseudocode=row.pseudocode,
                        callees=callees,
                        sink_arg=sink_arg,
                        entry_sites=sites,
                    )
                    # Gate A (same as the cmd axis): never persist a const_sink_arg note on a path
                    # whose argument is a free_string source.
                    if _form_note_contradicts_source(blocking, path_ev.get("source_kind")):
                        blocking = None
                    # No Ghidra def-use provenance for path sinks this phase — the writer layer
                    # stays not_traced (an honest '?', never sunk). Controllability comes from the
                    # text-level source_kind above.
                    _attach_edge_leads(
                        path_ev, edge_leads, row.binary_name, match.func_ref.func_name
                    )
                    flow_evidence = json.dumps(path_ev, sort_keys=True)

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
                        exposure_shape=exposure_shape,
                        provenance_level=provenance,
                        # Neutral, RE-SCAN-STABLE per-instance locator = run + binary/function
                        # anchor + sink-class hit. One function can match multiple sinks (e.g. cmd
                        # and copy); each is a distinct instance, so the sink-class suffix keeps the
                        # ref unique (it is the single anchor used by --explain, manual jump-back,
                        # and any durable per-ref judgement store — which is why it must not drift
                        # across a re-scan; see build_evidence_ref).
                        evidence_ref=build_evidence_ref(
                            source_run_id,
                            suffix=match.sink_class,
                            binary_sha256=row.binary_sha256,
                            binary_name=row.binary_name,
                            address=row.address,
                            func_name=match.func_ref.func_name,
                            func_id=match.func_ref.func_id,
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
                # ★ POSITION-AWARE on the format axis. The command axis's dangerous value is the
                # wrapper's FIRST argument, so locate_sink_arg is right there. On the format axis it
                # is wrong, and wrong in the direction that hides bugs: argument 0 is the stream,
                # level or program name, while the format — the only argument that carries
                # format-string injection — sits at whatever position the wrapper's signature puts
                # it. Reading argument 0 therefore judged the wrong value, and when that wrong value
                # happened to be a literal the candidate was read as constant while its actual
                # format was a variable. Measured on real firmware: `W(2, pcVar2, uVar1)` — argument
                # 0 is the constant `2`, the format is the variable `pcVar2` at index 1.
                fmt_index = wc.format_param_index if wc.sink_class == FMT_STRING_CLASS else None
                sink_arg = _wrapper_sink_arg(f_pseudocode, wc.wrapper_name, fmt_index)
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
                # Precision on the format-string axis is a RANKING job, not a corpus job.
                #
                # This gate used to DROP a recovered fmt candidate whose forwarded value was not a
                # free (externally-influenced) string, reasoning that "an uncontrollable source is
                # not a real format-string path". But source_kind here is only ever free_string or
                # unknown — there is no proven-uncontrollable reading to drop. So the gate was
                # discarding candidates whose controllability is UNKNOWN, i.e. 100% '?', breaking
                # the rule that a '?' is never silently removed: the same function found DIRECTLY
                # keeps its unknown candidate, so dropping it when it is found through a wrapper is
                # a pure false negative that also makes the set read as complete when it is not.
                #
                # The real motivation — variadic loggers are ubiquitous, so amplifying recall on
                # them would flood the high band (measured ~90% of fmt wrapper candidates) — is a
                # ranking concern, and the read-side ladder already serves it: an unknown
                # controllability ranks below 'free'/'constrained' and far below a proven cross,
                # while the demotion iron law keeps it OFF the floor (only a proven-safe fact sinks
                # a candidate). So the candidate stays in the corpus, demoted and still queryable.
                if wc.sink_class == "fmt_string" and source_class == "unknown":
                    fmt_wrapper_unknown_source_demoted += 1
                # Def-use provenance for the wrapper function's own sinks. The real
                # sink is one hop away, but the forwarding function's provenance still tells the
                # agent where the forwarded value comes from. A surfaced fact, never scored.
                # Def-use provenance for the wrapper function's own sinks, PLUS — on the format
                # axis — the format argument recovered from this call site. The extractor's def-use
                # pass stops at the function boundary, so a forwarded sink leaves nothing behind and
                # the candidate can only be read as "never traced". Reading the format literal out
                # of the call site one hop up recovers the common case as an ordinary constant
                # record, which the existing classifier judges with no new verdict logic. Every
                # uncertain shape yields no record and keeps the untraced reading (see
                # fmt_provenance). ★ The record carries the format ONLY — never its varargs, which
                # on this axis are harmless data and which a stack_buf-shaped record would get
                # judged as an injection surface.
                recovered = (
                    constant_format_record(
                        pseudocode=f_pseudocode,
                        wrapper_name=wc.wrapper_name,
                        wrapped_sink=wc.wrapped_sink,
                        index=fmt_index,
                    )
                    if wc.sink_class == FMT_STRING_CLASS
                    else []
                )
                evidence["sink_arg_provenance"] = sink_prov_by_func.get(f.func_id, []) + recovered
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
                        # same function from colliding. Same re-scan-stable anchor as above.
                        evidence_ref=build_evidence_ref(
                            source_run_id,
                            suffix=ref_suffix,
                            binary_sha256=f.binary_sha256,
                            binary_name=f.binary_name,
                            address=f.address,
                            func_name=f.name,
                            func_id=f.func_id,
                        ),
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
        # The instance write committed cleanly: mark the run 'complete' + record its analysis
        # counts. Reached only if the transaction above did NOT raise (an exception skips this and
        # leaves scan_status='in_progress' — the honest half-finished signal).
        finish_run(
            atlas,
            source_run_id,
            scan_status="complete",
            binaries=lineage["binaries"],
            functions=lineage["functions"],
            functions_empty=lineage["functions_empty"],
        )
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
        web_form_fields_written=len(web_form_field_rows),
        fmt_wrapper_unknown_source_demoted=fmt_wrapper_unknown_source_demoted,
    )
