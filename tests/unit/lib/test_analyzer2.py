# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for Analyzer-2 (A2) — the pattern-driven atlas writer.

Synthetic, vendor-neutral analysis.db (incl. one OSS binary) + temp atlas; hermetic (no
LLM). Proves the R-pattern -> R2 -> atlas write, OSS exclusion, the L0/L1 mapping, the
empty-public_finding gate, evidence neutralization (raw literal never persisted), and the
boundary.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path

import pytest

import treasure_map.lib.hunt.analyzer2 as analyzer2_mod
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.hunt import run_analyzer2
from treasure_map.lib.query import explain_candidate, get_run
from treasure_map.lib.query.triage import _CONTROLLABILITY_RANK, _controllability_rank
from treasure_map.lib.storage.connection import open_db

_SRC = Path(__file__).resolve().parents[3] / "src" / "treasure_map"
_HUNT_A2 = _SRC / "lib" / "hunt" / "analyzer2.py"
_QUERY_PKG = _SRC / "lib" / "query"
_ATLAS_SCHEMA = _SRC / "lib" / "storage" / "atlas_schema.sql"

# A shell-ish format literal carrying a (neutral) path — the kind of raw evidence that must
# never be persisted to the atlas verbatim.
RAW_EVIDENCE = "/usr/bin/tool %s"


def _sha(name: str) -> str:
    """A content-shaped sha256 for a fixture binary. Derived from the name so distinct binaries get
    distinct hashes IN THEIR FIRST 8 CHARS — evidence_ref anchors the binary by that prefix, so a
    fixture whose hashes shared a prefix (the old str(bid).zfill(64)) would collide refs."""
    return hashlib.sha256(name.encode()).hexdigest()


def _insert_func(
    conn: sqlite3.Connection, bid: int, func: dict[str, object], *, fid: int | None = None
) -> None:
    """Insert one fixture function. ``fid=None`` omits the id so SQLite's AUTOINCREMENT assigns it —
    exactly what ghidra_ingest does, which is what makes func_id climb on every re-ingest."""
    nvram_wrapper = func.get("nvram_wrapper")
    cols = "binary_id, name, address, pseudocode, pseudocode_hash, callees, nvram_ops, "
    cols += "nvram_wrapper, wrapper_call_args, string_keyed_edges"
    vals: tuple[object, ...] = (
        bid,
        func["name"],
        func.get("address"),
        func["pseudocode"],
        func.get("hash"),
        json.dumps(func["callees"]),
        json.dumps(func.get("nvram_ops", [])),
        json.dumps(nvram_wrapper) if nvram_wrapper else None,
        json.dumps(func.get("wrapper_call_args", [])),
        json.dumps(func.get("string_keyed_edges", {})),
    )
    if fid is not None:
        cols = "id, " + cols
        vals = (fid, *vals)
    conn.execute(f"INSERT INTO functions ({cols}) VALUES ({','.join('?' * len(vals))})", vals)


def _rescan_funcs(
    db_path: Path, binaries: list[dict[str, object]], *, reverse: bool = False
) -> None:
    """Re-ingest the same firmware's functions into the SAME analysis.db — what a re-scan does.

    Mirrors ghidra_ingest: DELETE this binary's function rows, then re-INSERT them WITHOUT an
    explicit id. Because the id is AUTOINCREMENT (never reused after a delete), every func_id lands
    past the old high-water mark — the drift that made a func_id-derived evidence_ref useless.
    ``reverse`` additionally flips the enumeration order (what changing the extractor can do), the
    second, smaller drift mechanism.
    """
    conn = open_db(db_path)
    for bid, spec in enumerate(binaries, start=1):
        conn.execute("DELETE FROM functions WHERE binary_id = ?", (bid,))
        funcs = list(spec.get("funcs", []))  # type: ignore[arg-type]
        if reverse:
            funcs.reverse()
        for func in funcs:
            _insert_func(conn, bid, func)  # no explicit id -> AUTOINCREMENT assigns
    conn.commit()
    conn.close()


def _make_db(
    tmp_path: Path,
    binaries: list[dict[str, object]],
    *,
    xrefs: list[tuple[int, int]] | None = None,
    web_form_fields: list[dict[str, object]] | None = None,
) -> Path:
    db_path = tmp_path / "analysis.db"
    conn = open_db(db_path)
    fid = 0
    for caller_fid, callee_fid in xrefs or []:
        conn.execute(
            "INSERT INTO xrefs (caller_func_id, callee_func_id, xref_type) "
            "VALUES (?, ?, 'import_export')",
            (caller_fid, callee_fid),
        )
    for bid, spec in enumerate(binaries, start=1):
        conn.execute(
            "INSERT INTO binaries (id, name, path, sha256) VALUES (?, ?, ?, ?)",
            (bid, spec["name"], spec.get("path"), _sha(str(spec["name"]))),
        )
        if spec.get("oss"):
            conn.execute(
                "INSERT INTO components (binary_id, product, version) VALUES (?, 'tp', '1')",
                (bid,),
            )
        for func in spec.get("funcs", []):  # type: ignore[union-attr]
            fid += 1
            _insert_func(conn, bid, func, fid=fid)
        for m in spec.get("nvram_defaults", []):  # type: ignore[union-attr]
            conn.execute(
                "INSERT INTO nvram_defaults "
                "(binary_id, key, default_value, flags, member_index) VALUES (?, ?, ?, ?, ?)",
                (bid, m.get("key"), m.get("default_value"), m.get("flags"), m.get("index")),
            )
        for i, e in enumerate(spec.get("string_tables", [])):  # type: ignore[arg-type]
            conn.execute(
                "INSERT INTO string_tables "
                "(binary_id, table_addr, stride, entry_index, key, func_name, func_addr, "
                "func_kind, completeness_status, completeness_reason, completeness_scope) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    bid,
                    e.get("table_addr", "0x74920"),
                    e.get("stride", 8),
                    e.get("index", i),
                    e.get("key"),
                    e.get("func_name"),
                    e.get("func_addr"),
                    e.get("func_kind", "direct"),
                    e.get("status", "incomplete"),
                    e.get("reason", "got_relative_and_three_field_and_mips_not_detected"),
                    e.get("scope", "absolute_2field_only"),
                ),
            )
    for ff in web_form_fields or []:
        cur = conn.execute(
            "INSERT INTO non_binary_files (kind, name, path) VALUES ('web_asset', ?, ?)",
            (ff.get("asset", "Form.asp"), ff.get("asset", "Form.asp")),
        )
        conn.execute(
            "INSERT INTO web_form_fields (file_id, field_keyword, source_rule) VALUES (?, ?, ?)",
            (cur.lastrowid, ff.get("key"), ff.get("rule", "input")),
        )
    conn.commit()
    conn.close()
    return db_path


def _cmd_injection_fn(name: str, *, param_sourced: bool = True) -> dict[str, object]:
    # A SOURCE callee (recv) is always present so R-pattern flags the command-injection
    # shape; the snprintf argument decides R2's grade: param_1 -> unknown, buf -> confirmed.
    arg = "param_1" if param_sourced else "buf"
    body = (
        f"void {name}(char* param_1){{ char buf[64]; recv(fd,buf,64); char cmd[128]; "
        f'snprintf(cmd,128,"{RAW_EVIDENCE}",{arg}); system(cmd); }}'
    )
    return {
        "name": name,
        "pseudocode": body,
        "hash": f"h_{name}",
        "callees": ["recv", "snprintf", "system"],
    }


def _data_gap_cmd_fn(name: str) -> dict[str, object]:
    """A function whose call graph shows a command sink but whose body Ghidra could not
    decompile (whitespace-only pseudocode). It forms a bare_cmd shape match on its callees, so
    analyzer2 must SKIP it (no decompilable body) yet COUNT it — never a silent drop. The
    whitespace is non-NULL so it passes the scan's `pseudocode IS NOT NULL` filter, then strips
    to empty at the analyzer2 data-gap guard."""
    return {
        "name": name,
        "pseudocode": "   ",
        "hash": None,
        "callees": ["system"],
    }


def _decompile_error_cmd_fn(name: str) -> dict[str, object]:
    """A command-sink function whose body is a decompile-error COMMENT (non-empty text, but no
    analyzable code). It must still count as a data gap — the error comment must not slip past the
    guard as an 'analyzed' body (Ghidra emits exactly this on a decompile exception)."""
    return {
        "name": name,
        "pseudocode": "/* decompile_error: timed out */",
        "hash": None,
        "callees": ["system"],
    }


def _nvram_fn(name: str, ops: list[dict[str, object]]) -> dict[str, object]:
    """A function carrying nvram_ops but no shape-relevant callees — it is flattened into
    nvram_key_flow independent of the shape scan (the flatten runs over ALL functions)."""
    return {
        "name": name,
        "pseudocode": f"void {name}(){{}}",
        "hash": f"h_{name}",
        "callees": [],
        "nvram_ops": ops,
    }


def _nvram_rows(atlas_path: Path) -> list[sqlite3.Row]:
    conn = open_atlas(atlas_path)
    try:
        return conn.execute(
            "SELECT key, key_kind, binary, func, op, value_source, api, via_wrapper "
            "FROM nvram_key_flow ORDER BY binary, func, op"
        ).fetchall()
    finally:
        conn.close()


def _instances(atlas_path: Path) -> list[sqlite3.Row]:
    conn = open_atlas(atlas_path)
    try:
        return conn.execute("SELECT * FROM instance ORDER BY instance_id").fetchall()
    finally:
        conn.close()


def _count(atlas_path: Path, view: str) -> int:
    conn = open_atlas(atlas_path)
    try:
        return int(conn.execute(f"SELECT COUNT(*) FROM {view}").fetchone()[0])
    finally:
        conn.close()


# ── writer: rich patterns + instances, OSS excluded, L0/L1, empty public_finding ────


def test_writer_populates_atlas_oss_excluded(tmp_path: Path) -> None:
    db = _make_db(
        tmp_path,
        [
            {"name": "webd", "funcs": [_cmd_injection_fn("handle")]},
            {"name": "busybox", "oss": True, "funcs": [_cmd_injection_fn("applet")]},
        ],
    )
    atlas = tmp_path / "atlas.db"
    stats = run_analyzer2(db, atlas, source_run_id="run_dcs")

    assert stats.oss_excluded == 1
    assert stats.matches == 1  # only the custom binary's match
    assert stats.instances_written == 1
    assert _count(atlas, "public_finding") == 0

    conn = open_atlas(atlas)
    try:
        algo = conn.execute("SELECT fingerprint_algo_version FROM pattern").fetchall()
        levels = [r[0] for r in conn.execute("SELECT DISTINCT provenance_level FROM instance")]
        anchors = [r[0] for r in conn.execute("SELECT external_anchor FROM instance")]
    finally:
        conn.close()
    assert all(r[0] == "callseq-v1" for r in algo)  # the RICH pattern, not diff-coarse
    assert all(lvl in ("L0", "L1") for lvl in levels)
    assert all(anchor is None for anchor in anchors)


# ── run lineage: the run_id -> analysis.db resolver + scan_status lifecycle ──────────


def test_run_analyzer2_records_run_lineage(tmp_path: Path) -> None:
    # A clean scan records its lineage row: scan_status='complete', the analysis.db resolver path,
    # the caller's firmware_path, the build hash (pass_version), and the analysis counts — this is
    # what a run-aware fact tool routes on and what list_runs / `tmap runs` shows.
    db = _make_db(tmp_path, [{"name": "webd", "funcs": [_cmd_injection_fn("handle")]}])
    # current_binaries = the most-recent-scan rows (last_seen_at = MAX); stamp last_seen_at + a
    # uniform pass_version so the lineage counts + build hash exercise the real scan-scoped path.
    stamp = sqlite3.connect(db)
    stamp.execute("UPDATE binaries SET last_seen_at = '2026-01-01 00:00:00', pass_version = 'pv_x'")
    stamp.commit()
    stamp.close()
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_lin", firmware_path="/fw/router")

    conn = open_atlas(atlas)
    try:
        run = get_run(conn, "run_lin")
    finally:
        conn.close()
    assert run is not None
    assert run.scan_status == "complete"  # finished cleanly
    assert run.resolved is True
    assert run.analysis_db_path == str(db.resolve())  # the run_id -> analysis.db resolver
    assert run.firmware_path == "/fw/router"
    assert run.binaries == 1 and run.functions == 1
    assert run.build_hash == "pv_x"  # DISTINCT pass_version = the stale-scan signal
    assert run.tool_version is not None


def _boom(*_a: object, **_k: object) -> None:
    raise RuntimeError("boom")


def test_run_analyzer2_crash_leaves_run_in_progress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A crash DURING the instance write must leave scan_status='in_progress' (the honest "did not
    # finish" signal) with the instance transaction rolled back — never a run silently reading
    # complete, and never half-written candidates behind a missing run row.
    db = _make_db(tmp_path, [{"name": "webd", "funcs": [_cmd_injection_fn("handle")]}])
    atlas = tmp_path / "atlas.db"
    monkeypatch.setattr(analyzer2_mod, "add_instance", _boom)
    with pytest.raises(RuntimeError):
        run_analyzer2(db, atlas, source_run_id="run_crash")

    conn = open_atlas(atlas)
    try:
        run = get_run(conn, "run_crash")
        n_inst = conn.execute("SELECT COUNT(*) FROM instance").fetchone()[0]
    finally:
        conn.close()
    assert run is not None and run.scan_status == "in_progress"  # honest half-finished signal
    assert n_inst == 0  # the instance transaction rolled back


# ── honesty: data-gap matches are counted, never silently dropped ───────────────────


def test_data_gap_matches_are_counted_not_silent(tmp_path: Path) -> None:
    # A shape-matched sink candidate whose function body Ghidra could not decompile is dropped
    # (no body to grade), but it must be COUNTED so the candidate set is honestly marked
    # incomplete — a real sink can hide in exactly such an un-decompilable function.
    db = _make_db(tmp_path, [{"name": "webd", "funcs": [_data_gap_cmd_fn("handle")]}])
    atlas = tmp_path / "atlas.db"
    stats = run_analyzer2(db, atlas, source_run_id="run_gap")

    assert stats.matches == 1  # the shape scan saw the candidate
    assert stats.instances_written == 0  # but its body was un-decompilable -> not written
    assert stats.data_gap_skipped == 1  # and it is COUNTED, never silently dropped
    assert _count(atlas, "instance") == 0


def test_decompile_error_body_is_a_counted_data_gap(tmp_path: Path) -> None:
    # A "/* decompile_error ... */" body is non-empty text but carries no analyzable code — it must
    # be caught as a data gap (counted), not slip past the guard and read as an analyzed function.
    db = _make_db(tmp_path, [{"name": "webd", "funcs": [_decompile_error_cmd_fn("handle")]}])
    atlas = tmp_path / "atlas.db"
    stats = run_analyzer2(db, atlas, source_run_id="run_err")

    assert stats.matches == 1
    assert stats.instances_written == 0
    assert stats.data_gap_skipped == 1
    assert _count(atlas, "instance") == 0


# ── gap② phase 2: nvram_ops flattened into the cross-binary nvram_key_flow table ────


def test_nvram_ops_flattened_cross_binary(tmp_path: Path) -> None:
    # rc writes sw_mode; httpd reads it — a real cross-process config flow. A parametric and an
    # unresolved op ride along; the keyless commit op is NOT flattened (no key -> not a key fact).
    db = _make_db(
        tmp_path,
        [
            {
                "name": "rc",
                "funcs": [
                    _nvram_fn(
                        "set_mode",
                        [
                            {
                                "api": "nvram_set",
                                "op": "write",
                                "key": "sw_mode",
                                "key_kind": "constant",
                                "value_source": {"kind": "param", "name": "param_2"},
                            },
                            {
                                "api": "nvram_set",
                                "op": "write",
                                "key": "wl%d_ssid",
                                "key_kind": "parametric",
                                "template": "wl%d_ssid",
                                "value_source": {"kind": "constant", "value": "x"},
                            },
                            {
                                "api": "nvram_set",
                                "op": "write",
                                "key_kind": "unresolved",
                                "reason": "key_from_caller",
                                "value_source": {"kind": "param", "name": "param_1"},
                            },
                            {"api": "nvram_commit", "op": "commit"},  # keyless -> not flattened
                        ],
                    )
                ],
            },
            {
                "name": "httpd",
                "funcs": [
                    _nvram_fn(
                        "read_mode",
                        [
                            {
                                "api": "nvram_get",
                                "op": "read",
                                "key": "sw_mode",
                                "key_kind": "constant",
                            }
                        ],
                    )
                ],
            },
        ],
    )
    atlas = tmp_path / "atlas.db"
    stats = run_analyzer2(db, atlas, source_run_id="run_nv")

    assert stats.nvram_flows_written == 4  # 3 writes + 1 read; the commit op is dropped
    rows = _nvram_rows(atlas)
    as_tuples = [(r["key"], r["key_kind"], r["binary"], r["func"], r["op"]) for r in rows]
    # cross-binary: rc writes sw_mode (constant), httpd reads sw_mode (constant)
    assert ("sw_mode", "constant", "rc", "set_mode", "write") in as_tuples
    assert ("sw_mode", "constant", "httpd", "read_mode", "read") in as_tuples
    assert {r["key_kind"] for r in rows} == {"constant", "parametric", "unresolved"}
    # unresolved key is stored with NULL key — never masquerading as a concrete key
    unresolved = [r for r in rows if r["key_kind"] == "unresolved"]
    assert len(unresolved) == 1 and unresolved[0]["key"] is None
    # write-side value source rides along as JSON (controllability signal); reads carry none
    w = next(r for r in rows if r["key"] == "sw_mode" and r["op"] == "write")
    assert json.loads(w["value_source"]) == {"kind": "param", "name": "param_2"}
    rd = next(r for r in rows if r["key"] == "sw_mode" and r["op"] == "read")
    assert rd["value_source"] is None


def test_anchorless_parametric_reclassified_unresolved(tmp_path: Path) -> None:
    # An over-broad "template" with no fixed-literal anchor (%s%s, <built:*>) is really key-unknown;
    # it must be STORED as unresolved (so it drives completeness) rather than a parametric that
    # regex-matches any key. A real template (wl%d_ssid) keeps its anchor and stays parametric.
    db = _make_db(
        tmp_path,
        [
            {
                "name": "httpd",
                "funcs": [
                    _nvram_fn(
                        "f",
                        [
                            {
                                "api": "nvram_set",
                                "op": "write",
                                "key": "%s%s",
                                "key_kind": "parametric",
                            },
                            {
                                "api": "nvram_set",
                                "op": "write",
                                "key": "<built:strcpy>",
                                "key_kind": "parametric",
                            },
                            {
                                "api": "nvram_set",
                                "op": "write",
                                "key": "wl%d_ssid",
                                "key_kind": "parametric",
                            },
                        ],
                    )
                ],
            }
        ],
    )
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_anchor")
    rows = _nvram_rows(atlas)
    by_kind = {r["key_kind"] for r in rows}
    # the two anchorless templates -> unresolved (key NULL); only wl%d_ssid stays parametric
    assert sorted(r["key"] for r in rows if r["key_kind"] == "parametric") == ["wl%d_ssid"]
    unresolved = [r for r in rows if r["key_kind"] == "unresolved"]
    assert len(unresolved) == 2 and all(r["key"] is None for r in unresolved)
    assert by_kind == {"parametric", "unresolved"}


def test_nvram_flow_replace_by_run_is_idempotent(tmp_path: Path) -> None:
    # Re-running the same run refreshes its nvram rows (delete-own-then-insert), never doubles them.
    spec = [
        {
            "name": "rc",
            "funcs": [
                _nvram_fn(
                    "f",
                    [{"api": "nvram_set", "op": "write", "key": "k", "key_kind": "constant"}],
                )
            ],
        }
    ]
    db = _make_db(tmp_path, spec)
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_x")
    run_analyzer2(db, atlas, source_run_id="run_x")
    assert len(_nvram_rows(atlas)) == 1  # not 2


# ── gap② A2: wrapper-indirect key edges recovered from constant call-site literals ──


def _wrapper_reader_fn(name: str) -> dict[str, object]:
    """A thin nvram wrapper: a caller-supplied key read (key_from_caller) + the nvram_wrapper flag
    the extractor emits. Its own direct op is unresolved; the edge is resolved at its call sites."""
    return {
        "name": name,
        "pseudocode": f"char* {name}(void){{ return nvram_get(); }}",
        "hash": f"h_{name}",
        "callees": ["nvram_get"],
        "nvram_ops": [{"api": "nvram_get", "op": "read", "key_kind": "unresolved"}],
        "nvram_wrapper": {"op": "read", "api": "nvram_get"},
    }


def _wrapper_caller_fn(name: str, callee: str, key: str) -> dict[str, object]:
    """A business caller that passes a constant literal key to the wrapper (the resolvable edge)."""
    return {
        "name": name,
        "pseudocode": f'void {name}(void){{ {callee}("{key}"); }}',
        "hash": f"h_{name}",
        "callees": [callee],
        "wrapper_call_args": [{"callee": callee, "key": key, "key_kind": "constant"}],
    }


def test_wrapper_indirect_edge_recovered_with_via_wrapper(tmp_path: Path) -> None:
    # A2 headline: the caller's constant-literal call into a recognized nvram wrapper becomes an
    # indirect read edge for that key, flagged via_wrapper — the readers:[] blind spot, resolved.
    db = _make_db(
        tmp_path,
        [
            {
                "name": "rc",
                "funcs": [
                    _wrapper_reader_fn("wget"),
                    _wrapper_caller_fn("biz", "wget", "oauth_auth_code"),
                ],
            }
        ],
    )
    atlas = tmp_path / "atlas.db"
    stats = run_analyzer2(db, atlas, source_run_id="run_a2")
    assert stats.nvram_wrapper_edges == 1
    edge = next(r for r in _nvram_rows(atlas) if r["via_wrapper"] is not None)
    assert edge["key"] == "oauth_auth_code"
    assert edge["func"] == "biz" and edge["op"] == "read"
    assert edge["via_wrapper"] == "wget" and edge["key_kind"] == "constant"


def test_call_to_non_wrapper_makes_no_edge(tmp_path: Path) -> None:
    # ★ zero false-connection: a constant-literal call whose callee is NOT a recognized wrapper
    # produces NO edge — A2 never fabricates a key connection from an ordinary call.
    db = _make_db(
        tmp_path,
        [
            {
                "name": "rc",
                "funcs": [
                    # 'helper' has no nvram_wrapper flag -> not a wrapper
                    {
                        "name": "helper",
                        "pseudocode": "void helper(char* k){}",
                        "hash": "h_helper",
                        "callees": [],
                    },
                    _wrapper_caller_fn("biz", "helper", "some_key"),
                ],
            }
        ],
    )
    atlas = tmp_path / "atlas.db"
    stats = run_analyzer2(db, atlas, source_run_id="run_a2b")
    assert stats.nvram_wrapper_edges == 0
    assert all(r["via_wrapper"] is None for r in _nvram_rows(atlas))


def test_wrapper_edge_does_not_cross_binaries(tmp_path: Path) -> None:
    # A wrapper binds by (binary, name): a caller only resolves against a wrapper in its OWN binary,
    # so a same-named function in another binary never mints a spurious cross-binary edge.
    db = _make_db(
        tmp_path,
        [
            {"name": "rc", "funcs": [_wrapper_reader_fn("wget")]},
            {"name": "httpd", "funcs": [_wrapper_caller_fn("biz", "wget", "k")]},
        ],
    )
    atlas = tmp_path / "atlas.db"
    stats = run_analyzer2(db, atlas, source_run_id="run_a2c")
    assert stats.nvram_wrapper_edges == 0  # rc's wrapper is not httpd's


# ── naming-bridge phase 1: router_defaults flattened analysis.db -> atlas ────────────


def _nvram_defaults_rows(atlas_path: Path) -> list[sqlite3.Row]:
    conn = open_atlas(atlas_path)
    try:
        return conn.execute(
            "SELECT key, default_value, flags, member_index, binary FROM nvram_defaults "
            "ORDER BY member_index"
        ).fetchall()
    finally:
        conn.close()


def test_router_defaults_flattened_to_atlas(tmp_path: Path) -> None:
    db = _make_db(
        tmp_path,
        [
            {
                "name": "libshared.so",
                "funcs": [_nvram_fn("noop", [])],
                "nvram_defaults": [
                    {"key": "sw_mode", "default_value": "0", "flags": 0, "index": 0},
                    {"key": "oauth_auth_code", "default_value": "", "flags": 128, "index": 894},
                    {"key": None, "default_value": None, "flags": None, "index": 900},  # unresolved
                ],
            }
        ],
    )
    atlas = tmp_path / "atlas.db"
    stats = run_analyzer2(db, atlas, source_run_id="run_rd")
    assert stats.nvram_defaults_written == 3  # resolved members + the unresolved one (not dropped)
    rows = _nvram_defaults_rows(atlas)
    hit = next(r for r in rows if r["key"] == "oauth_auth_code")
    assert hit["default_value"] == "" and hit["flags"] == 128 and hit["binary"] == "libshared.so"
    # the unresolved member is preserved as a key=NULL row (keeps the table honestly incomplete)
    assert any(r["key"] is None for r in rows)


def test_router_defaults_replace_by_run_is_idempotent(tmp_path: Path) -> None:
    spec = [
        {
            "name": "libshared.so",
            "funcs": [_nvram_fn("noop", [])],
            "nvram_defaults": [{"key": "sw_mode", "default_value": "0", "flags": 0, "index": 0}],
        }
    ]
    db = _make_db(tmp_path, spec)
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_rd2")
    run_analyzer2(db, atlas, source_run_id="run_rd2")
    assert len(_nvram_defaults_rows(atlas)) == 1  # not 2


# ── M1: editable web form fields flattened to the atlas ──────────────────────────────


def test_web_form_fields_flattened_to_atlas(tmp_path: Path) -> None:
    db = _make_db(
        tmp_path,
        [{"name": "webd", "funcs": [_nvram_fn("noop", [])]}],
        web_form_fields=[
            {"key": "fb_comment", "rule": "textarea", "asset": "Feedback.asp"},
            {"key": "wl_ssid", "rule": "input", "asset": "Wireless.asp"},
        ],
    )
    atlas = tmp_path / "atlas.db"
    stats = run_analyzer2(db, atlas, source_run_id="run_wff")
    assert stats.web_form_fields_written == 2
    conn = open_atlas(atlas)
    try:
        rows = {
            r["field_keyword"]: r["source_asset"]
            for r in conn.execute(
                "SELECT field_keyword, source_asset FROM web_form_fields "
                "WHERE source_run_id='run_wff'"
            )
        }
    finally:
        conn.close()
    assert rows == {"fb_comment": "Feedback.asp", "wl_ssid": "Wireless.asp"}


def test_web_form_fields_replace_by_run_is_idempotent(tmp_path: Path) -> None:
    db = _make_db(
        tmp_path,
        [{"name": "webd", "funcs": [_nvram_fn("noop", [])]}],
        web_form_fields=[{"key": "fb_comment", "rule": "textarea"}],
    )
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_wff2")
    run_analyzer2(db, atlas, source_run_id="run_wff2")
    conn = open_atlas(atlas)
    try:
        n = conn.execute(
            "SELECT COUNT(*) FROM web_form_fields WHERE source_run_id='run_wff2'"
        ).fetchone()[0]
    finally:
        conn.close()
    assert n == 1  # not 2


# ── detector B: string-keyed edges (strcmp-ladder dispatch enumeration) ──────────────
# ★ IRON LAW: these tests assert the atlas rows are ENUMERATED FACTS (key gates callee) with a
# BinDiff-alignable callee anchor + fine-grained completeness — NEVER a reachability verdict. The
# reachability-stays-unknown invariant is proven directly on _dim_reachability (test_triage_*).


def _ske_fn(
    name: str,
    edges: list[dict[str, object]],
    *,
    address: str = "0x00010000",
    completeness: dict[str, object] | None = None,
) -> dict[str, object]:
    """A function carrying a detector-B string_keyed_edges object (no shape-relevant callees —
    the flatten runs over ALL functions, independent of the sink scan)."""
    obj: dict[str, object] = {"edges": edges}
    if completeness is not None:
        obj["completeness"] = completeness
    return {
        "name": name,
        "address": address,
        "pseudocode": f"void {name}(){{}}",
        "hash": f"h_{name}",
        "callees": [],
        "string_keyed_edges": obj,
    }


def _ske_rows(atlas_path: Path) -> list[sqlite3.Row]:
    conn = open_atlas(atlas_path)
    try:
        return conn.execute(
            "SELECT binary, from_function, from_func_addr, key, mechanism, callee_name, "
            "callee_addr, callee_kind, ladder_size, completeness_status, completeness_reason, "
            "completeness_scope FROM string_keyed_edge ORDER BY key, callee_name"
        ).fetchall()
    finally:
        conn.close()


def test_string_keyed_edges_flattened_per_key_callee(tmp_path: Path) -> None:
    # A 2-key strcmp ladder on one dispatch variable; each key gates one direct callee. The flatten
    # emits one row per (key, callee), each carrying the BinDiff-alignable callee anchor and the
    # ladder_size (2 = a real dispatch ladder, not a lone compare). Neutral keys only.
    db = _make_db(
        tmp_path,
        [
            {
                "name": "rc",
                "funcs": [
                    _ske_fn(
                        "handle_dispatch",
                        [
                            {
                                "key": "oauth_auth_code",
                                "mechanism": "strcmp_gate",
                                "gate_api": "strcmp",
                                "gate_addr": "0x00010040",
                                "var_id": "sp+0x20",
                                "ladder_size": 2,
                                "callees": [
                                    {
                                        "name": "process_token",
                                        "addr": "0x000b643c",
                                        "kind": "direct",
                                    }
                                ],
                                "completeness": {"status": "complete"},
                            },
                            {
                                "key": "reboot",
                                "mechanism": "strcmp_gate",
                                "gate_api": "strcmp",
                                "gate_addr": "0x00010080",
                                "var_id": "sp+0x20",
                                "ladder_size": 2,
                                "callees": [
                                    {"name": "do_reboot", "addr": "0x00011000", "kind": "direct"}
                                ],
                                "completeness": {"status": "complete"},
                            },
                        ],
                        completeness={"status": "complete", "scope": "handle_dispatch@0x00010000"},
                    )
                ],
            }
        ],
    )
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_ske")
    rows = _ske_rows(atlas)
    assert len(rows) == 2
    by_key = {r["key"]: r for r in rows}
    tok = by_key["oauth_auth_code"]
    assert tok["mechanism"] == "strcmp_gate"
    assert tok["binary"] == "rc"
    assert tok["from_function"] == "handle_dispatch"
    assert tok["from_func_addr"] == "0x00010000"  # source anchor rides from functions.address
    # the callee anchor is the BinDiff-alignable {name, addr, kind}, not a bare address
    assert tok["callee_name"] == "process_token"
    assert tok["callee_addr"] == "0x000b643c"
    assert tok["callee_kind"] == "direct"
    assert tok["ladder_size"] == 2
    assert tok["completeness_status"] == "complete"
    assert by_key["reboot"]["callee_name"] == "do_reboot"


def test_string_keyed_edge_partial_gate_keeps_key_as_callee_less_row(tmp_path: Path) -> None:
    # A key whose gate branch could not be resolved to a callee set is NEVER dropped — it emits a
    # callee-less row (the key stays a lead) with the per-edge partial status taking precedence.
    db = _make_db(
        tmp_path,
        [
            {
                "name": "rc",
                "funcs": [
                    _ske_fn(
                        "opaque",
                        [
                            {
                                "key": "cfg_mode",
                                "mechanism": "strcmp_gate",
                                "ladder_size": 1,
                                "callees": [],
                                "completeness": {
                                    "status": "partial",
                                    "reason": "gate_branch_unresolved",
                                },
                            }
                        ],
                        completeness={"status": "complete", "scope": "opaque@0x00010000"},
                    )
                ],
            }
        ],
    )
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_partial")
    rows = _ske_rows(atlas)
    assert len(rows) == 1
    r = rows[0]
    assert r["key"] == "cfg_mode"
    assert (
        r["callee_name"] is None
    )  # callee-less: the key is kept as a lead, never silently dropped
    assert r["completeness_status"] == "partial"  # per-edge issue wins over the complete region
    assert r["completeness_reason"] == "gate_branch_unresolved"


def test_string_keyed_edge_switch_region_marked_incomplete(tmp_path: Path) -> None:
    # A function with an unrecognized indirect-branch (switch) dispatch marks its REGION incomplete;
    # an edge without its own per-edge status inherits it, so a cross-version edge delta in this
    # region reads as undetermined (not a real add/remove).
    db = _make_db(
        tmp_path,
        [
            {
                "name": "httpd",
                "funcs": [
                    _ske_fn(
                        "router",
                        [
                            {
                                "key": "status",
                                "mechanism": "strcmp_gate",
                                "ladder_size": 1,
                                "callees": [
                                    {"name": "show_status", "addr": "0x00022000", "kind": "direct"}
                                ],
                            }
                        ],
                        completeness={
                            "status": "incomplete",
                            "reason": "switch_form_unrecognized",
                            "scope": "router@0x00020000",
                        },
                    )
                ],
            }
        ],
    )
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_switch")
    rows = _ske_rows(atlas)
    assert len(rows) == 1
    r = rows[0]
    assert r["completeness_status"] == "incomplete"
    assert r["completeness_reason"] == "switch_form_unrecognized"
    assert r["completeness_scope"] == "router@0x00020000"


def test_string_keyed_edges_replace_by_run_is_idempotent(tmp_path: Path) -> None:
    db = _make_db(
        tmp_path,
        [
            {
                "name": "rc",
                "funcs": [
                    _ske_fn(
                        "d",
                        [
                            {
                                "key": "k",
                                "mechanism": "strcmp_gate",
                                "ladder_size": 1,
                                "callees": [{"name": "h", "addr": "0x1", "kind": "direct"}],
                                "completeness": {"status": "complete"},
                            }
                        ],
                    )
                ],
            }
        ],
    )
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_idem")
    run_analyzer2(db, atlas, source_run_id="run_idem")
    conn = open_atlas(atlas)
    try:
        n = conn.execute(
            "SELECT COUNT(*) FROM string_keyed_edge WHERE source_run_id='run_idem'"
        ).fetchone()[0]
    finally:
        conn.close()
    assert n == 1  # replace-by-run: not 2


def test_run_capability_registered_even_with_zero_edges(tmp_path: Path) -> None:
    # ★ absence-of-findings is NOT absence-of-capability: the detector code ran in this tmap
    # version, so the capability is registered present=1 even for a run that found ZERO edges. A
    # cross-version diff reads this to tell "no edges" apart from "this build cannot see edges".
    db = _make_db(tmp_path, [{"name": "rc", "funcs": [_nvram_fn("noop", [])]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_cap")
    conn = open_atlas(atlas)
    try:
        assert _ske_rows(atlas) == []  # no edges at all
        cap = conn.execute(
            "SELECT present FROM run_capability WHERE run_id='run_cap' AND "
            "capability='reachability.string_keyed_edge'"
        ).fetchone()
    finally:
        conn.close()
    assert cap is not None and cap["present"] == 1


def test_string_keyed_edges_query_by_callee_and_by_run(tmp_path: Path) -> None:
    # The two read faces over the produced atlas: edges_reaching_callee (the reachability layer's
    # "is this function a dispatch callee?" lookup) and get_string_keyed_edges (the agent/diff
    # enumeration by run + key). Both return enumerated FACTS, never a reachability verdict.
    from treasure_map.lib.query import edges_reaching_callee, get_string_keyed_edges

    db = _make_db(
        tmp_path,
        [
            {
                "name": "rc",
                "funcs": [
                    _ske_fn(
                        "handle_dispatch",
                        [
                            {
                                "key": "oauth_auth_code",
                                "mechanism": "strcmp_gate",
                                "ladder_size": 1,
                                "callees": [
                                    {
                                        "name": "process_token",
                                        "addr": "0x000b643c",
                                        "kind": "direct",
                                    }
                                ],
                                "completeness": {"status": "complete"},
                            }
                        ],
                    )
                ],
            }
        ],
    )
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_q")
    conn = open_atlas(atlas)
    try:
        # by callee (reachability lookup): the callee's function is reached via a keyed edge
        hits = edges_reaching_callee(conn, "rc", "process_token")
        assert len(hits) == 1
        assert hits[0]["key"] == "oauth_auth_code"
        assert hits[0]["callee"] == {
            "name": "process_token",
            "addr": "0x000b643c",
            "kind": "direct",
        }
        # a function that is NOT any edge's callee returns [] (NOT a proof of unreachability)
        assert edges_reaching_callee(conn, "rc", "handle_dispatch") == []
        # by run + key (agent / diff enumeration)
        out = get_string_keyed_edges(conn, run_id="run_q", key="oauth_auth_code")
        assert out["count"] == 1
        assert out["edges"][0]["from_function"] == "handle_dispatch"
        assert out["edges"][0]["mechanism"] == "strcmp_gate"
    finally:
        conn.close()


# ── one-hop string-key leads: downward from the edge callee, annotation only ─────────


def _fat_handler_fw() -> list[dict[str, object]]:
    """The flagship shape: a strcmp ladder dispatches key -> handler; the handler is FAT (it builds
    a command and calls TWO sinks). Each sink is one hop below the edge callee."""
    return [
        {
            "name": "rc",
            "funcs": [
                _ske_fn(
                    "handle_notifications",
                    [
                        {
                            "key": "oauth_auth_code",
                            "mechanism": "strcmp_gate",
                            "ladder_size": 3,
                            "callees": [
                                {"name": "gen_token_email", "addr": "0x000b643c", "kind": "direct"}
                            ],
                            "completeness": {"status": "complete"},
                        }
                    ],
                    address="000b6000",
                ),
                {  # the FAT edge callee: calls two sinks, plus unrelated work
                    "name": "gen_token_email",
                    "address": "000b643c",
                    "pseudocode": "void gen_token_email(void){}",
                    "hash": "h_gen",
                    "callees": ["run_cmd", "log_status", "strlen"],
                },
                {**_cmd_injection_fn("run_cmd"), "address": "000b32a0"},
                {**_cmd_injection_fn("log_status"), "address": "000b2ec0"},
            ],
        }
    ]


def _leads_of(atlas: Path, source_anchor: str) -> list[dict[str, object]]:
    conn = open_atlas(atlas)
    try:
        row = conn.execute(
            "SELECT flow_evidence FROM instance WHERE source_anchor = ? LIMIT 1", (source_anchor,)
        ).fetchone()
    finally:
        conn.close()
    if row is None or not row["flow_evidence"]:
        return []
    leads = json.loads(row["flow_evidence"]).get("reachability_leads", [])
    return list(leads)


def test_one_hop_lead_reaches_the_sink_below_a_fat_edge_callee(tmp_path: Path) -> None:
    # ★ The capability: the sink one call below the edge callee gets the key lead. The edge callee
    # here is deliberately FAT — a thinness gate (right for wrapper propagation, which CREATES
    # candidates) would kill exactly this lead, so this layer must not have one.
    db = _make_db(tmp_path, _fat_handler_fw())
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_lead")
    leads = _leads_of(atlas, "run_cmd")
    assert len(leads) == 1
    assert leads[0] == {
        "via": "string_keyed_edge",
        "key": "oauth_auth_code",
        "hops": 1,
        "through": "gen_token_email",
        "mechanism": "strcmp_gate",
    }


def test_fanout_edge_callee_hands_the_key_to_both_sinks_below(tmp_path: Path) -> None:
    # One pass over the edge-callee set: a fan-out handler hands its key to EVERY candidate below.
    db = _make_db(tmp_path, _fat_handler_fw())
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_fan")
    for sink in ("run_cmd", "log_status"):
        leads = _leads_of(atlas, sink)
        assert [x["key"] for x in leads] == ["oauth_auth_code"], sink
        assert leads[0]["through"] == "gen_token_email"


def test_one_hop_leads_are_pure_annotation(tmp_path: Path) -> None:
    # No new candidates, no reachability upgrade, no rank change — the leads only ANNOTATE.
    fw = _fat_handler_fw()
    db = _make_db(tmp_path, fw)
    atlas = tmp_path / "atlas.db"
    stats = run_analyzer2(db, atlas, source_run_id="run_ann")

    # same firmware with the edge stripped out -> the candidate corpus must be identical
    bare = [{**fw[0], "funcs": [{**f} for f in fw[0]["funcs"]]}]  # type: ignore[index,dict-item]
    bare[0]["funcs"][0]["string_keyed_edges"] = {}  # type: ignore[index]
    db2 = _make_db(tmp_path / "b", bare)
    (tmp_path / "b").mkdir(exist_ok=True)
    atlas2 = tmp_path / "atlas2.db"
    stats2 = run_analyzer2(db2, atlas2, source_run_id="run_ann")

    assert stats.instances_written == stats2.instances_written  # corpus unchanged by the leads
    conn = open_atlas(atlas)
    try:
        # every candidate that got a lead still reads reachability_status unknown (never upgraded)
        statuses = {
            r["source_anchor"]: r["reachability_status"]
            for r in conn.execute("SELECT source_anchor, reachability_status FROM instance")
        }
    finally:
        conn.close()
    assert statuses["run_cmd"] == "unknown"


# ── detector A: static {string -> funcptr} dispatch tables (same atlas edge table) ───


def test_static_string_table_flattened_to_edges(tmp_path: Path) -> None:
    # A static {string -> handler} dispatch table (detector A) lands in the SAME string_keyed_edge
    # table with mechanism='static_string_table', table_addr set, no source function, ladder_size
    # NULL, and the detector-level completeness (incomplete — absolute-2-field only) on each row.
    db = _make_db(
        tmp_path,
        [
            {
                "name": "httpd",
                "funcs": [_nvram_fn("noop", [])],
                "string_tables": [
                    {
                        "key": "nvram_dump",
                        "func_name": "FUN_000561e4",
                        "func_addr": "0x000561e4",
                        "table_addr": "0x74920",
                    },
                    {
                        "key": "sys_reboot",
                        "func_name": "do_reboot",
                        "func_addr": "0x00011000",
                        "table_addr": "0x74920",
                    },
                ],
            }
        ],
    )
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_a")
    rows = _ske_rows(atlas)
    assert len(rows) == 2
    by_key = {r["key"]: r for r in rows}
    dump = by_key["nvram_dump"]
    assert dump["mechanism"] == "static_string_table"
    assert dump["binary"] == "httpd"
    assert dump["from_function"] is None  # a static table has no source function
    assert dump["callee_name"] == "FUN_000561e4"
    assert dump["callee_addr"] == "0x000561e4"
    assert dump["ladder_size"] is None  # N/A for a static table
    assert dump["completeness_status"] == "incomplete"
    assert dump["completeness_scope"] == "absolute_2field_only"


def test_static_table_undefined_text_handler_survives_to_the_edge(tmp_path: Path) -> None:
    # A handler the dispatch table is the ONLY reference to gets no Ghidra Function object, so the
    # detector anchors it by address and marks kind='undefined_text'. Real firmware measurement: 15
    # of one 32-entry handler table's targets were undefined, and requiring a defined function there
    # shattered the table (13 fragments / 80 entries -> 1 table / 203 entries once relaxed). The
    # honest kind must reach the agent rather than be dropped or silently recoloured as 'direct'.
    db = _make_db(
        tmp_path,
        [
            {
                "name": "httpd",
                "funcs": [_nvram_fn("noop", [])],
                "string_tables": [
                    {
                        "key": "nvram_dump",
                        "func_name": "FUN_000561e4",
                        "func_addr": "0x561e4",
                        "func_kind": "direct",
                    },
                    {
                        "key": "select_channel",
                        "func_name": "FUN_0002a774",
                        "func_addr": "0x2a774",
                        "func_kind": "undefined_text",
                    },
                ],
            }
        ],
    )
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_ut")
    by_key = {r["key"]: r for r in _ske_rows(atlas)}
    assert by_key["nvram_dump"]["callee_kind"] == "direct"
    # the undefined-but-real handler is an edge like any other, honestly kinded
    ut = by_key["select_channel"]
    assert ut["callee_kind"] == "undefined_text"
    assert ut["callee_addr"] == "0x2a774"  # the address is the anchor, defined or not
    assert ut["mechanism"] == "static_string_table"


def test_static_table_and_strcmp_gate_share_query_and_capability(tmp_path: Path) -> None:
    # Both detectors write the SAME table, so one query + one capability key serve both. The
    # mechanism field distinguishes them; edges_reaching_callee finds a static-table handler too.
    from treasure_map.lib.query import edges_reaching_callee, get_string_keyed_edges

    db = _make_db(
        tmp_path,
        [
            {
                "name": "httpd",
                "funcs": [
                    _ske_fn(
                        "dispatch",
                        [
                            {
                                "key": "status",
                                "mechanism": "strcmp_gate",
                                "ladder_size": 1,
                                "callees": [
                                    {"name": "show_status", "addr": "0x2000", "kind": "direct"}
                                ],
                                "completeness": {"status": "complete"},
                            }
                        ],
                    )
                ],
                "string_tables": [
                    {"key": "nvram_dump", "func_name": "FUN_000561e4", "func_addr": "0x000561e4"}
                ],
            }
        ],
    )
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_ab")
    conn = open_atlas(atlas)
    try:
        # the static-table handler is reachable-via-key like a strcmp callee (same lookup)
        a_hit = edges_reaching_callee(conn, "httpd", "FUN_000561e4")
        assert len(a_hit) == 1 and a_hit[0]["mechanism"] == "static_string_table"
        # both mechanisms live under one enumeration surface
        allq = get_string_keyed_edges(conn, run_id="run_ab")
        mechs = {e["mechanism"] for e in allq["edges"]}
        assert mechs == {"strcmp_gate", "static_string_table"}
        # one capability key covers both detectors
        cap = conn.execute(
            "SELECT COUNT(*) FROM run_capability WHERE run_id='run_ab' AND "
            "capability='reachability.string_keyed_edge'"
        ).fetchone()[0]
        assert cap == 1
    finally:
        conn.close()


# ── evidence_ref is RE-SCAN STABLE (a durable per-ref judgement store depends on it) ──
# Real-firmware root cause these guard: func_id is an AUTOINCREMENT rowid and the analysis DB is
# delete-and-reingest per binary, so a re-scanned DB held 88,178 functions numbered 266,156..354,333
# — every id shifted by the function count on EVERY re-scan, with zero code change. A ref built on
# it drifts, and every judgement stored against the old ref silently loses its anchor.


def _rc_dispatch_fw() -> list[dict[str, object]]:
    """Two command-sink candidates in one binary, each at a fixed entry address."""
    return [
        {
            "name": "rc",
            "funcs": [
                {**_cmd_injection_fn("FUN_000b32a0"), "address": "000b32a0"},
                {**_cmd_injection_fn("FUN_000b643c"), "address": "000b643c"},
            ],
        }
    ]


def _ref_of(atlas: Path, source_anchor: str) -> str:
    conn = open_atlas(atlas)
    try:
        row = conn.execute(
            "SELECT evidence_ref FROM instance WHERE source_anchor = ? LIMIT 1", (source_anchor,)
        ).fetchone()
    finally:
        conn.close()
    assert row is not None, f"no instance anchored at {source_anchor}"
    return str(row["evidence_ref"])


def _func_id_of(db: Path, name: str) -> int:
    conn = open_db(db)
    try:
        return int(conn.execute("SELECT id FROM functions WHERE name = ?", (name,)).fetchone()[0])
    finally:
        conn.close()


def test_evidence_ref_survives_a_rescan(tmp_path: Path) -> None:
    # ★ THE property: re-scan the same firmware, get the SAME ref for the same function. The old
    # func_id-derived ref failed exactly here (fn109348 -> fn199770 on real firmware, one function).
    fw = _rc_dispatch_fw()
    db = _make_db(tmp_path, fw)
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_1")
    ref_before = _ref_of(atlas, "FUN_000b32a0")
    id_before = _func_id_of(db, "FUN_000b32a0")

    _rescan_funcs(db, fw)  # same firmware, same order — only the ingest bookkeeping moves
    run_analyzer2(db, atlas, source_run_id="run_1")
    ref_after = _ref_of(atlas, "FUN_000b32a0")
    id_after = _func_id_of(db, "FUN_000b32a0")

    # The drift mechanism really fired (else this test would pass vacuously on any scheme):
    assert id_after != id_before, "fixture did not reproduce func_id drift — test is vacuous"
    # ...and the ref did NOT move with it.
    assert ref_after == ref_before
    assert "000b32a0" in ref_before  # anchored on the entry address, not on ingest bookkeeping
    assert f"fn{id_before}" not in ref_before  # never the rowid


def test_evidence_ref_survives_enumeration_order_change(tmp_path: Path) -> None:
    # Adding/removing a detector can reorder the extractor's function enumeration. That reorders the
    # AUTOINCREMENT ids; the ref must not care (spec acceptance 2).
    fw = _rc_dispatch_fw()
    db = _make_db(tmp_path, fw)
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_1")
    ref_before = _ref_of(atlas, "FUN_000b32a0")

    _rescan_funcs(db, fw, reverse=True)  # enumeration order flipped
    run_analyzer2(db, atlas, source_run_id="run_1")

    assert _ref_of(atlas, "FUN_000b32a0") == ref_before


def test_stored_judgement_keeps_its_anchor_across_a_rescan(tmp_path: Path) -> None:
    # The reason the property matters: the durable judgement store keys its records by evidence_ref.
    # Record one against a candidate, re-scan, and it must still resolve to that same live candidate
    # (spec acceptance 3). Under the old func_id ref this silently went dangling on every re-scan.
    from treasure_map.lib.atlas.writer import add_private_exploit
    from treasure_map.lib.query.exploit_ledger import list_moat

    fw = _rc_dispatch_fw()
    db = _make_db(tmp_path, fw)
    atlas_p = tmp_path / "atlas.db"
    run_analyzer2(db, atlas_p, source_run_id="run_1")
    ref = _ref_of(atlas_p, "FUN_000b32a0")

    conn = open_atlas(atlas_p)
    add_private_exploit(conn, evidence_ref=ref, pattern="p", exploit_note="verified by hand")
    conn.close()

    _rescan_funcs(db, fw, reverse=True)  # re-scan: func_ids climb AND the order flips
    run_analyzer2(db, atlas_p, source_run_id="run_1")

    conn = open_atlas(atlas_p)
    try:
        moat = list_moat(conn)
        # the record still anchors a LIVE candidate — it did not go dangling
        still_anchored = conn.execute(
            "SELECT COUNT(*) FROM instance WHERE evidence_ref = ?", (ref,)
        ).fetchone()[0]
    finally:
        conn.close()
    assert moat["holes"] == 1, "the stored judgement lost its anchor after a re-scan"
    assert still_anchored == 1
    assert _ref_of(atlas_p, "FUN_000b32a0") == ref  # the candidate still carries the same ref


def test_evidence_ref_distinguishes_same_named_binaries(tmp_path: Path) -> None:
    # Real firmware ships DISTINCT binaries under one name (measured: 479 binaries, 475 names —
    # libstdc++.so.6/mtdinfo/nanddump/ubinfo each twice). Anchoring the binary by NAME would collide
    # 4,460 functions' refs; the content-hash prefix keeps them apart even at the same address.
    fw: list[dict[str, object]] = [
        {
            "name": "mtdinfo",
            "path": "bin/mtdinfo",
            "funcs": [{**_cmd_injection_fn("handler"), "address": "00400100"}],
        },
        {
            "name": "mtdinfo",
            "path": "usr/sbin/mtdinfo",
            "funcs": [{**_cmd_injection_fn("handler"), "address": "00400100"}],
        },
    ]
    # distinct content -> distinct sha; _make_db derives sha from the name, so vary it by path here
    db = tmp_path / "analysis.db"
    conn = open_db(db)
    for bid, spec in enumerate(fw, start=1):
        conn.execute(
            "INSERT INTO binaries (id, name, path, sha256) VALUES (?, ?, ?, ?)",
            (bid, spec["name"], spec["path"], _sha(str(spec["path"]))),
        )
        for func in spec["funcs"]:  # type: ignore[union-attr]
            _insert_func(conn, bid, func)  # type: ignore[arg-type]
    conn.commit()
    conn.close()
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_1")

    conn = open_atlas(atlas)
    try:
        refs = [r["evidence_ref"] for r in conn.execute("SELECT evidence_ref FROM instance")]
    finally:
        conn.close()
    assert len(refs) == 2
    assert len(set(refs)) == 2, f"same-named binaries collided at the same address: {refs}"


# ── evidence neutralization: raw literal never persisted ────────────────────────────


def test_raw_evidence_is_not_persisted(tmp_path: Path) -> None:
    db = _make_db(tmp_path, [{"name": "webd", "funcs": [_cmd_injection_fn("handle")]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_dcs")

    (row,) = _instances(atlas)
    # evidence_ref holds a neutral per-instance locator (run-scoped function id), not the
    # raw firmware literal.
    assert row["evidence_ref"] != RAW_EVIDENCE
    # The raw firmware-derived literal appears in NO column of the stored row.
    assert all(RAW_EVIDENCE not in str(row[k]) for k in row.keys())


def test_evidence_ref_unique_per_instance(tmp_path: Path) -> None:
    # Two functions of the SAME shape share one structural_fingerprint (one pattern) but are
    # distinct instances. evidence_ref must locate each instance uniquely — it must NOT be the
    # shared fingerprint (that collided across all same-shape instances and lost traceability).
    db = _make_db(
        tmp_path,
        [{"name": "webd", "funcs": [_cmd_injection_fn("h1"), _cmd_injection_fn("h2")]}],
    )
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_x")

    rows = _instances(atlas)
    assert len(rows) == 2
    refs = [r["evidence_ref"] for r in rows]
    assert len(set(refs)) == 2, f"evidence_ref collided across instances: {refs}"
    # One shared pattern fingerprint underneath; the per-instance refs are never that value.
    conn = open_atlas(atlas)
    try:
        fps = {r[0] for r in conn.execute("SELECT structural_fingerprint FROM pattern")}
    finally:
        conn.close()
    assert len(fps) == 1  # same shape -> one pattern
    assert all(fp not in refs for fp in fps)  # the instance ref is never the shared fingerprint


# ── candidate locatability: binary_path + content hash auto-filled from the source ──


def test_instance_carries_binary_location(tmp_path: Path) -> None:
    # The instance records WHERE the evidence function lives (full path) + the binary's content
    # hash, both auto-filled from the source build — so a candidate is locatable from the atlas.
    db = _make_db(
        tmp_path,
        [{"name": "webd", "path": "usr/sbin/webd", "funcs": [_cmd_injection_fn("handle")]}],
    )
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_loc")

    (row,) = _instances(atlas)
    assert row["binary_path"] == "usr/sbin/webd"  # full path, not the bare name
    assert row["binary_content_hash"] == _sha("webd")  # the source binary's sha256


def test_binary_path_falls_back_to_name_when_source_has_no_path(tmp_path: Path) -> None:
    # A degraded source with no path still yields a locator (the bare name) rather than NULL.
    db = _make_db(tmp_path, [{"name": "webd", "funcs": [_cmd_injection_fn("handle")]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_np")

    (row,) = _instances(atlas)
    assert row["binary_path"] == "webd"


def test_location_survives_source_db_removal(tmp_path: Path) -> None:
    # Locatability must come from the atlas, NOT a read-time join back to analysis.db: delete the
    # source build, then triage still shows the location.
    from treasure_map.lib.query import triage

    db = _make_db(
        tmp_path,
        [{"name": "webd", "path": "usr/sbin/webd", "funcs": [_cmd_injection_fn("handle")]}],
    )
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_gone")
    db.unlink()  # the source build is gone

    conn = open_atlas(atlas)
    try:
        cands = triage(conn, run_id="run_gone")
    finally:
        conn.close()
    assert len(cands) == 1
    assert cands[0].binary_path == "usr/sbin/webd"  # served from the atlas alone


# ── parameter-sourced -> unknown -> L0 (R2's hard invariant carried through) ─────────


def test_parameter_sourced_match_is_unknown_l0(tmp_path: Path) -> None:
    fn = _cmd_injection_fn("handle", param_sourced=True)
    db = _make_db(tmp_path, [{"name": "webd", "funcs": [fn]}])
    atlas = tmp_path / "atlas.db"
    stats = run_analyzer2(db, atlas, source_run_id="r")
    assert stats.by_status["unknown"] == 1
    (row,) = _instances(atlas)
    assert row["reachability_status"] == "unknown"
    assert row["provenance_level"] == "L0"


# ── append-only: second run accumulates, device_spread recomputed ──────────────────


def test_second_run_appends_and_recomputes_breadth(tmp_path: Path) -> None:
    db = _make_db(tmp_path, [{"name": "webd", "funcs": [_cmd_injection_fn("handle")]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_1")
    run_analyzer2(db, atlas, source_run_id="run_2")

    assert len(_instances(atlas)) == 2
    conn = open_atlas(atlas)
    try:
        breadth = conn.execute("SELECT MAX(device_spread) FROM pattern").fetchone()[0]
    finally:
        conn.close()
    assert breadth == 2  # two distinct source_run_id over the same fingerprint


def _multi_sink_fn(name: str = "ma_utils_exec") -> dict[str, object]:
    # One function that matches BOTH a cmd shape (recv->snprintf+%s literal->popen) and a copy
    # shape (recv->strcpy) -> two distinct instances over the same function.
    body = (
        f"void {name}(char* param_1){{ char buf[64]; recv(fd,buf,64); char cmd[128]; "
        f'snprintf(cmd,128,"{RAW_EVIDENCE}",param_1); popen(cmd,"r"); '
        f"char dst[64]; strcpy(dst,param_1); }}"
    )
    return {
        "name": name,
        "pseudocode": body,
        "hash": f"h_{name}",
        "callees": ["recv", "snprintf", "popen", "strcpy"],
    }


# ── replace-by-run: re-running one run-id refreshes (never doubles) ──────────────────


def test_same_run_rerun_is_idempotent(tmp_path: Path) -> None:
    db = _make_db(tmp_path, [{"name": "webd", "funcs": [_cmd_injection_fn("handle")]}])
    atlas = tmp_path / "atlas.db"
    s1 = run_analyzer2(db, atlas, source_run_id="run_rb")
    after_one = len(_instances(atlas))
    s2 = run_analyzer2(db, atlas, source_run_id="run_rb")  # same run-id again

    assert s2.instances_written == s1.instances_written
    assert len(_instances(atlas)) == after_one  # refreshed, NOT doubled
    refs = [r["evidence_ref"] for r in _instances(atlas)]
    assert len(set(refs)) == len(refs)  # every ref unique within the run


def test_rerun_does_not_touch_other_runs(tmp_path: Path) -> None:
    db = _make_db(tmp_path, [{"name": "webd", "funcs": [_cmd_injection_fn("handle")]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_A")
    a_rows_before = [tuple(r) for r in _instances(atlas) if r["source_run_id"] == "run_A"]
    run_analyzer2(db, atlas, source_run_id="run_B")
    run_analyzer2(db, atlas, source_run_id="run_B")  # refresh B twice
    a_rows_after = [tuple(r) for r in _instances(atlas) if r["source_run_id"] == "run_A"]

    assert a_rows_before == a_rows_after  # run A untouched by B's replace-by-run


def test_rerun_failure_rolls_back_to_old_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = _make_db(tmp_path, [{"name": "webd", "funcs": [_cmd_injection_fn("handle")]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_rb")
    before = [tuple(r) for r in _instances(atlas)]
    assert before  # there is an old result to protect

    real_add = analyzer2_mod.add_instance
    calls = {"n": 0}

    def _boom(*args: object, **kwargs: object) -> int:
        calls["n"] += 1
        if calls["n"] >= 1:  # fail during the re-run write
            raise RuntimeError("write blew up mid-run")
        return real_add(*args, **kwargs)  # type: ignore[no-any-return]

    monkeypatch.setattr(analyzer2_mod, "add_instance", _boom)
    with pytest.raises(RuntimeError):
        run_analyzer2(db, atlas, source_run_id="run_rb")

    after = [tuple(r) for r in _instances(atlas)]
    assert after == before  # rolled back to the old result — never a half-written run


def test_replace_by_run_keeps_pattern_rows(tmp_path: Path) -> None:
    db = _make_db(tmp_path, [{"name": "webd", "funcs": [_cmd_injection_fn("handle")]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_rb")
    conn = open_atlas(atlas)
    try:
        patterns_before = conn.execute("SELECT COUNT(*) FROM pattern").fetchone()[0]
    finally:
        conn.close()
    run_analyzer2(db, atlas, source_run_id="run_rb")  # replace-by-run
    conn = open_atlas(atlas)
    try:
        patterns_after = conn.execute("SELECT COUNT(*) FROM pattern").fetchone()[0]
    finally:
        conn.close()
    assert patterns_after == patterns_before  # pattern (accumulation layer) never deleted


# ── evidence_ref uniqueness: func + sink hit ─────────────────────────────────────────


def test_multi_sink_function_has_unique_evidence_refs(tmp_path: Path) -> None:
    db = _make_db(tmp_path, [{"name": "webd", "funcs": [_multi_sink_fn()]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_ms")

    rows = _instances(atlas)
    assert len(rows) >= 2  # one function, multiple sink hits -> multiple instances
    refs = [r["evidence_ref"] for r in rows]
    assert len(set(refs)) == len(refs), f"evidence_ref collided across sink hits: {refs}"
    sink_classes = {r["evidence_ref"].split("@", 1)[1] for r in rows}
    assert {"cmd", "copy"} <= sink_classes  # the ref carries the distinguishing sink class


def test_explain_anchors_the_right_sink_hit(tmp_path: Path) -> None:
    db = _make_db(tmp_path, [{"name": "webd", "funcs": [_multi_sink_fn()]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_ms")

    conn = open_atlas(atlas)
    try:
        cmd_ref = next(
            r["evidence_ref"] for r in _instances(atlas) if r["evidence_ref"].endswith("@cmd")
        )
        ex = explain_candidate(conn, cmd_ref)
    finally:
        conn.close()
    assert ex is not None
    assert ex.candidate.evidence_ref == cmd_ref
    assert ex.candidate.sink_class == "cmd"  # the cmd ref resolves to the cmd hit, not the copy


# ── work item A: FP-suppression form notes + library origin (downweight, never remove) ──


def _exec_no_shell_fn(name: str = "run_exec") -> dict[str, object]:
    # source + shellish %s + an exec sink that does NOT go through a shell.
    body = (
        f"void {name}(char* p){{ char b[64]; recv(fd,b,64); char c[128]; "
        f'snprintf(c,128,"/usr/sbin/tool %s",b); execl(c,c,0); }}'
    )
    return {
        "name": name,
        "pseudocode": body,
        "hash": f"h_{name}",
        "callees": ["recv", "snprintf", "execl"],
    }


def _numeric_fn(name: str = "run_num") -> dict[str, object]:
    body = (
        f"void {name}(char* p){{ char b[64]; recv(fd,b,64); long n=strtol(b,0,10); char c[128]; "
        f'snprintf(c,128,"/bin/tool %s",n); system(c); }}'
    )
    return {
        "name": name,
        "pseudocode": body,
        "hash": f"h_{name}",
        "callees": ["recv", "strtol", "snprintf", "system"],
    }


def _by_anchor(atlas_path: Path) -> dict[str, sqlite3.Row]:
    return {r["source_anchor"]: r for r in _instances(atlas_path)}


def _cand_of(atlas_path: Path, fn: str):  # type: ignore[no-untyped-def]
    """The TriageCandidate for function ``fn`` under the default lens."""
    from treasure_map.lib.query import triage as run_triage

    conn = open_atlas(atlas_path)
    try:
        return next(c for c in run_triage(conn) if c.function == fn)
    finally:
        conn.close()


def _rank_of(atlas_path: Path, fn: str) -> int:
    """Position of ``fn`` in the default-lens order (lower = ranks earlier / more prominent)."""
    from treasure_map.lib.query import triage as run_triage

    conn = open_atlas(atlas_path)
    try:
        cands = run_triage(conn)
        return next(i for i, c in enumerate(cands) if c.function == fn)
    finally:
        conn.close()


def _is_safe(atlas_path: Path, fn: str) -> bool:
    """True when ``fn``'s only-proven-safe demotion fires (it sinks out of the first screen)."""
    from treasure_map.lib.query.triage import _is_proven_safe

    return _is_proven_safe(_cand_of(atlas_path, fn))


def _ctrl_of(atlas_path: Path, fn: str) -> str:
    """The controllability dimension value for ``fn`` (free / constrained / constant / unknown)."""
    return _cand_of(atlas_path, fn).dim("controllability").value


def test_no_shell_exec_is_labelled_and_downweighted(tmp_path: Path) -> None:
    # Compare within the same reachability tier: both candidates grade confirmed (buf-sourced),
    # so the gap is purely the form downweight, not the status weight.
    db = _make_db(
        tmp_path,
        [
            {
                "name": "webd",
                "funcs": [
                    _cmd_injection_fn("shell_sys", param_sourced=False),
                    _exec_no_shell_fn("noshell"),
                ],
            }
        ],
    )
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_a")

    rows = _by_anchor(atlas)
    assert rows["noshell"]["blocking_mechanism"] == "no_shell_exec"
    assert rows["noshell"]["reachability_status"] != "blocked"  # labelled, never blocked
    # no_shell_exec is a labelled form, but it is NOT provably-constant — so it is NOT sunk out of
    # the first screen. Only a proven-safe fact demotes now; a form heuristic never buries a lead.
    assert not _is_safe(atlas, "noshell")


def test_mixed_system_and_execl_anchors_system_not_no_shell(tmp_path: Path) -> None:
    # Bug1: a function that calls BOTH system and execl must anchor to the shell-running sink
    # (system), and no_shell_exec must NOT fire (cmd capability is not all exec-no-shell) — the
    # alphabetically-first execl must not mask the real shell sink.
    mixed = {
        "name": "mixed_exec",
        "pseudocode": (
            "void mixed_exec(char* p){ char b[64]; recv(fd,b,64); char c[128]; "
            'snprintf(c,128,"/usr/sbin/tool %s",b); if (b[0]) execl(c,c,0); else system(c); }'
        ),
        "hash": "h_mixed",
        "callees": ["recv", "snprintf", "execl", "system"],
    }
    db = _make_db(tmp_path, [{"name": "webd", "funcs": [mixed]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_a")

    row = _by_anchor(atlas)["mixed_exec"]
    assert row["sink_anchor"] == "system"  # danger-anchored, not the alphabetically-first execl
    assert row["blocking_mechanism"] != "no_shell_exec"  # shell-capable -> not downweighted


def test_numeric_sanitized_is_labelled_and_downweighted(tmp_path: Path) -> None:
    db = _make_db(
        tmp_path,
        [
            {
                "name": "webd",
                "funcs": [
                    _cmd_injection_fn("raw_sys", param_sourced=False),
                    _numeric_fn("num_sys"),
                ],
            }
        ],
    )
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_a")

    rows = _by_anchor(atlas)
    assert rows["num_sys"]["blocking_mechanism"] == "numeric_sanitized"
    # a numeric validator is an UNPROVEN filter this phase (convergence-transform subtraction is
    # deferred), so it neither downgrades the free source nor sinks the candidate — it stays active.
    assert not _is_safe(atlas, "num_sys")


def test_library_symbol_routes_to_stock_origin(tmp_path: Path) -> None:
    # A statically-linked library function (custom-named binary, library symbol) -> stock_oss_known,
    # which the binary-level OSS exclusion misses. It is routed off pattern_breadth (origin no
    # longer affects the map order; the routing is what still matters for cross-firmware breadth).
    lib_fn = _cmd_injection_fn("handle")
    lib_fn["name"] = "SSL_read"
    db = _make_db(
        tmp_path,
        [{"name": "customd", "funcs": [_cmd_injection_fn("real_handle"), lib_fn]}],
    )
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_a")

    rows = _by_anchor(atlas)
    assert rows["SSL_read"]["origin"] == "stock_oss_known"
    assert rows["real_handle"]["origin"] == "unknown"  # never defaulted to custom
    # origin is no longer a ranking dimension (the map layers are controllability / reachability /
    # sink_impact / ..., not code provenance); stock routing still drives pattern_breadth below
    # (it counts only custom/unknown).
    conn = open_atlas(atlas)
    try:
        breadth = conn.execute(
            "SELECT pattern_breadth FROM pattern_ledger ORDER BY pattern_id"
        ).fetchall()
    finally:
        conn.close()
    assert all(r[0] >= 0 for r in breadth)  # ledger still computes; stock excluded by definition


def test_plain_shell_candidate_is_not_downweighted(tmp_path: Path) -> None:
    # The "do not over-downweight" guard: a real shell system() with an external source, custom
    # symbol, non-numeric, no constant caller keeps blocking_mechanism NULL (full score).
    db = _make_db(tmp_path, [{"name": "webd", "funcs": [_cmd_injection_fn("clean_handle")]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_a")
    assert _by_anchor(atlas)["clean_handle"]["blocking_mechanism"] is None


# ── work item B: bare-sink recall + cross-function source (#8 reverse example) ──────


def test_bare_sink_no_source_is_listed_not_sunk(tmp_path: Path) -> None:
    # A command sink with no in-function source is LISTED (recall) and labelled bare_sink — but it
    # is NOT sunk. The old score buried bare_sink (structurally demoting a real lead); the map only
    # sinks provably-constant, so bare_sink stays in the active region (its controllability is '?').
    bare = {
        "name": "do_exec",
        "pseudocode": "system(param_1);",
        "hash": "h_bare",
        "callees": ["system"],
    }
    db = _make_db(
        tmp_path,
        [{"name": "svcd", "funcs": [_cmd_injection_fn("real", param_sourced=False), bare]}],
    )
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_b")

    rows = _by_anchor(atlas)
    assert "do_exec" in rows  # not silently dropped
    # bare_sink is a danger SHAPE, carried in exposure_shape — NOT in blocking_mechanism (a shape is
    # not a mitigation). blocking_mechanism stays NULL so controllability still reads a live '?'.
    assert rows["do_exec"]["exposure_shape"] == "bare_sink"
    assert rows["do_exec"]["blocking_mechanism"] is None
    assert rows["do_exec"]["reachability_status"] != "blocked"  # listed, never graded blocked
    # the fix: a bare_sink is NOT provably-safe, so it is NOT sunk out of the first screen. Here the
    # bare argument is itself a caller-supplied param (a free source), so it stays fully active.
    assert not _is_safe(atlas, "do_exec")
    assert _ctrl_of(atlas, "do_exec") == "free"


def test_cross_function_source_system_enters_candidates(tmp_path: Path) -> None:
    # The #8 reverse example: a real system("…%s…") built from an optarg/argv value that crosses a
    # function boundary (source is in the caller). It MUST enter the candidate list, and — because
    # it builds a shell command (cmd_injection_shape) — must NOT be downweighted to the bottom.
    apply_mac = {
        "name": "apply_mac",
        "pseudocode": "void apply_mac(char* param_1){ char cmd[128]; "
        'snprintf(cmd,128,"kickmac %s; reboot",param_1); system(cmd); }',
        "hash": "h_apply",
        "callees": ["snprintf", "system"],
    }
    parse_args = {
        "name": "parse_args",
        "pseudocode": "void parse_args(int argc,char** argv){ "
        'getopt_long(argc,argv,"m:",0,0); apply_mac(optarg); }',
        "hash": "h_parse",
        "callees": ["getopt_long", "apply_mac"],
    }
    # caller_func_id=2 (parse_args) -> callee_func_id=1 (apply_mac)
    db = _make_db(
        tmp_path,
        [{"name": "iotd", "funcs": [apply_mac, parse_args]}],
        xrefs=[(2, 1)],
    )
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_8")

    rows = _by_anchor(atlas)
    assert "apply_mac" in rows  # the cross-function shell sink is a candidate (recall win)
    # caller passes a VARIABLE (optarg), not a constant -> NOT caller_constant; and a constructed
    # shell command is exempt from bare_sink -> it is NOT downweighted to the bottom.
    assert rows["apply_mac"]["blocking_mechanism"] is None
    # a constructed shell command from a variable caller-arg -> not provably-constant, so it stays
    # in the active region (never sunk to the bottom).
    assert not _is_safe(atlas, "apply_mac")


def test_caller_constant_downweights_constant_supplied_sink(tmp_path: Path) -> None:
    # caller_constant (A) activates on B's bare-sink candidates: a sink fed only a constant by its
    # sole one-hop caller ranks at the very bottom.
    run_cmd = {
        "name": "run_cmd",
        "pseudocode": "void run_cmd(char* param_1){ system(param_1); }",
        "hash": "h_run",
        "callees": ["system"],
    }
    boot = {
        "name": "boot",
        "pseudocode": 'void boot(void){ run_cmd("/etc/init.d/rcS"); }',
        "hash": "h_boot",
        "callees": ["run_cmd"],
    }
    db = _make_db(tmp_path, [{"name": "initd", "funcs": [run_cmd, boot]}], xrefs=[(2, 1)])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_cc")

    rows = _by_anchor(atlas)
    assert rows["run_cmd"]["blocking_mechanism"] == "caller_constant"


# ── inline charset on the cmd path + the thin-command-wrapper fact (R-L3·prep) ───────


def _charset_inline_cmd_fn(name: str = "arp_set") -> dict[str, object]:
    # A cmd_injection_shape whose command string is built inline from a charset-safe converter
    # (ether_ntoa -> MAC text). The recv buffer never reaches the command -> the command's
    # dynamic part is charset-constrained, so the cmd candidate must be downweighted.
    body = (
        f"void {name}(struct ether_addr* mac){{ char buf[64]; recv(fd,buf,64); char cmd[128]; "
        f'snprintf(cmd,128,"arp -s %s",ether_ntoa(mac)); system(cmd); }}'
    )
    return {
        "name": name,
        "pseudocode": body,
        "hash": f"h_{name}",
        "callees": ["recv", "ether_ntoa", "snprintf", "system"],
    }


def _thin_wrapper_fn(name: str = "exec_sh") -> dict[str, object]:
    # A bare_cmd_shape candidate that is also a thin forwarding wrapper: body ≈ system(param).
    return {
        "name": name,
        "pseudocode": f"void {name}(char* param_1){{ system(param_1); }}",
        "hash": f"h_{name}",
        "callees": ["system"],
    }


def test_inline_charset_cmd_candidate_is_downweighted_end_to_end(tmp_path: Path) -> None:
    # The cmd-path inline charset downweight reaches the persisted instance: the system()
    # candidate built from ether_ntoa is labelled charset_constrained (not bare_sink / None).
    db = _make_db(tmp_path, [{"name": "netd", "funcs": [_charset_inline_cmd_fn()]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_cs")
    row = _by_anchor(atlas)["arp_set"]
    assert row["blocking_mechanism"] == "charset_constrained"
    assert row["is_thin_cmd_wrapper"] == 0  # builds a command; not a verbatim forwarder


def test_thin_wrapper_fact_is_recorded_without_changing_score(tmp_path: Path) -> None:
    # The wrapper fact is stored on the candidate; its review-ordering label is untouched
    # (still bare_sink) — recording the fact does not change recall or rank.
    db = _make_db(tmp_path, [{"name": "initd", "funcs": [_thin_wrapper_fn()]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_w")
    row = _by_anchor(atlas)["exec_sh"]
    assert row["is_thin_cmd_wrapper"] == 1
    assert row["wrapped_sink"] == "system"
    assert row["exposure_shape"] == "bare_sink"  # unchanged by the fact (a shape, not a filter)
    assert row["blocking_mechanism"] is None


def test_wrapper_fact_does_not_add_candidates(tmp_path: Path) -> None:
    # ★ recall/count neutrality: the fact is a label on existing candidates, never a new one.
    # The wrapper function yields exactly one instance (its bare_cmd_shape match), no extra row.
    db = _make_db(tmp_path, [{"name": "initd", "funcs": [_thin_wrapper_fn()]}])
    atlas = tmp_path / "atlas.db"
    stats = run_analyzer2(db, atlas, source_run_id="run_w1")
    assert stats.instances_written == len(_instances(atlas)) == stats.matches == 1


# ── flow evidence (R-L3·B): structured evidence on cmd candidates ─────────────────────


def _charset_buffer_cmd_fn(name: str = "arp_run") -> dict[str, object]:
    # cmd_injection_shape whose command is built from a charset-safe converter laundered through
    # one intermediate buffer. The copy uses strlcpy (not in the global COPY set) so the function
    # matches ONLY the command shape, not an overflow/copy shape — so it is a single cmd candidate.
    body = (
        f"void {name}(struct ether_addr* mac){{ char b[32]; char* p=ether_ntoa(mac); "
        f'strlcpy(b,p,32); char cmd[128]; snprintf(cmd,128,"arp -s %s",b); system(cmd); }}'
    )
    return {
        "name": name,
        "pseudocode": body,
        "hash": f"h_{name}",
        "callees": ["ether_ntoa", "strlcpy", "snprintf", "system"],
    }


def _add_script_call(
    db_path: Path, script_path: str, command: str, line: int, args_pattern: str
) -> None:
    # Raw connect (NOT open_db): the analysis schema DROPs script_calls on every apply, so opening
    # via open_db between inserts would wipe earlier rows. The tables already exist from _make_db.
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "INSERT INTO non_binary_files (kind, name, path) VALUES ('shell_script', ?, ?)",
            (Path(script_path).name, script_path),
        )
        fid = conn.execute("SELECT id FROM non_binary_files ORDER BY id DESC LIMIT 1").fetchone()[0]
        conn.execute(
            "INSERT INTO script_calls (file_id, command, raw_line, line_number, args_pattern) "
            "VALUES (?, ?, ?, ?, ?)",
            (fid, command, f"{command} $X", line, args_pattern),
        )
        conn.commit()
    finally:
        conn.close()


def _evidence_of(atlas_path: Path, fn: str) -> dict:
    row = _by_anchor(atlas_path)[fn]
    return json.loads(row["flow_evidence"])


def _copy_fn(name: str, copy_call: str, callees: list[str]) -> dict[str, object]:
    # A copy candidate with a recognized source (recv) so R-pattern source-classifies it
    # external_input; the copy_call decides the size-source grade.
    body = f"void {name}(void){{ char d[64]; char s[256]; recv(fd,s,256); {copy_call} }}"
    return {"name": name, "pseudocode": body, "hash": f"h_{name}", "callees": callees}


def test_copy_size_bands_const_drops_variable_and_cmd_stay_high(tmp_path: Path) -> None:
    # The copy-size danger axis in action. Four candidates in one run:
    #   cc  — memcpy with a CONSTANT length      -> const_size, demoted out of the high band
    #   cv  — memcpy with a VARIABLE length       -> no note, kept high (recall-neutral)
    #   csl — strncpy(dst, src, strlen(src))      -> source_len suspect, kept high (#13: not safe)
    #   cmd — an external->command candidate       -> floats ABOVE the de-confirmed copies
    db = _make_db(
        tmp_path,
        [
            {
                "name": "svcd",
                "funcs": [
                    _copy_fn("cc", "memcpy(d,s,0x20);", ["recv", "memcpy"]),
                    _copy_fn("cv", "n = recv(fd,s,256); memcpy(d,s,n);", ["recv", "memcpy"]),
                    _copy_fn("csl", "strncpy(d,s,strlen(s));", ["recv", "strncpy", "strlen"]),
                    _cmd_injection_fn("cmd", param_sourced=True),
                ],
            }
        ],
    )
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_band")

    rows = _by_anchor(atlas)
    # Copy sinks never confirm; the constant length is downweighted, the unproven lengths are not.
    assert rows["cc"]["reachability_status"] == "unknown"
    assert rows["cc"]["blocking_mechanism"] == "const_size"
    assert rows["cv"]["blocking_mechanism"] is None
    assert rows["csl"]["blocking_mechanism"] is None

    # The constant-size copy is provably-constant -> sunk out of the first screen; the unbounded /
    # source-length copies are NOT (a true overflow is never silently demoted); the command
    # candidate (higher impact tier) floats above the copies.
    assert _ctrl_of(atlas, "cc") == "constant" and _is_safe(atlas, "cc")
    assert not _is_safe(atlas, "cv")
    assert not _is_safe(atlas, "csl")
    assert _rank_of(atlas, "cc") > _rank_of(atlas, "cv")  # constant copy sunk below unproven one
    assert _rank_of(atlas, "cc") > _rank_of(atlas, "csl")
    assert _rank_of(atlas, "cmd") < _rank_of(atlas, "cv")  # cmd (impact tier) above the copies


def test_fmtstr_cve_recalled_and_literal_not_flooded(tmp_path: Path) -> None:
    # Dual acceptance of the recall round: (1) the public format-string-injection shape
    # syslog(level, buf) with a non-literal format is RECALLED as an fmt_string candidate;
    # (2) the common literal-format logger produces NO candidate (the FP gate; band not flooded).
    db = _make_db(
        tmp_path,
        [
            {
                "name": "logd",
                "funcs": [
                    {
                        "name": "risky_log",  # synthetic name; the shape is syslog(level, buf)
                        "pseudocode": "void risky_log(char* param_1){ syslog(0, param_1); }",
                        "hash": "h_vl",
                        "callees": ["syslog"],
                    },
                    {
                        "name": "safe_log",
                        "pseudocode": 'void safe_log(char* x){ syslog(3, "event %s", x); }',
                        "hash": "h_sl",
                        "callees": ["syslog"],
                    },
                ],
            }
        ],
    )
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_fmt")
    rows = _by_anchor(atlas)
    # (1) recalled, as an fmt_string candidate anchored to syslog, with format evidence.
    assert "risky_log" in rows
    ev = json.loads(rows["risky_log"]["flow_evidence"])
    assert ev["fmt_arg_pos"] == 1 and ev["fmt_arg_literal"] is False
    assert rows["risky_log"]["sink_anchor"] == "syslog"
    # (2) the literal-format logger is exempt -> not a candidate at all.
    assert "safe_log" not in rows


def test_fmtstr_class_outranks_copy_when_same_status(tmp_path: Path) -> None:
    # A format-string sink (RCE-class) sits at the same impact tier as cmd, above copy/format.
    from treasure_map.lib.query import impact_tier

    assert impact_tier("fmt_string") > impact_tier("copy")
    assert impact_tier("fmt_string") == impact_tier("cmd")
    assert impact_tier("cmd") > impact_tier("format")


def test_cmd_candidate_carries_flow_evidence(tmp_path: Path) -> None:
    db = _make_db(tmp_path, [{"name": "netd", "funcs": [_charset_buffer_cmd_fn()]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_fe")
    ev = _evidence_of(atlas, "arp_run")
    assert set(ev) == {
        "source_kind",
        "flow_path",
        "sanitizer_seen",
        "entry_reach",
        "trace_boundary",
        # Ghidra def-use provenance merged in. Empty [] here: the synthetic function
        # has no exported sink_provenance, so it is present-but-empty, never absent.
        "sink_arg_provenance",
    }
    assert ev["sink_arg_provenance"] == []
    # The converter is laundered through an intermediate buffer -> charset_maybe (a lead for the
    # agent), with an honest trace boundary -- and NOT downweighted (charset is inline-only).
    assert ev["source_kind"] == "charset_maybe"
    assert ev["trace_boundary"] == "charset_via_intermediate_untraced"
    assert _by_anchor(atlas)["arp_run"]["blocking_mechanism"] != "charset_constrained"


def test_copy_candidate_has_size_evidence(tmp_path: Path) -> None:
    # A copy candidate carries SIZE evidence (the danger axis), not cmd flow evidence: strcpy's
    # write length is the source string's length -> size_kind source_len (a suspect, not safe).
    fn = {
        "name": "cp_fn",
        "pseudocode": (
            "void cp_fn(char* param_1){ char d[64]; recv(fd,param_1,64); strcpy(d,param_1); }"
        ),
        "hash": "h_cp",
        "callees": ["recv", "strcpy"],
    }
    db = _make_db(tmp_path, [{"name": "webd", "funcs": [fn]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_cp")
    ev = json.loads(_by_anchor(atlas)["cp_fn"]["flow_evidence"])
    assert ev["size_kind"] == "source_len"
    assert "size_flow" in ev and "clamp_seen" in ev and "trace_boundary" in ev


def test_flow_evidence_records_entry_sites_from_script_calls(tmp_path: Path) -> None:
    db = _make_db(tmp_path, [{"name": "netd", "funcs": [_charset_buffer_cmd_fn()]}])
    _add_script_call(db, "/etc/init.d/netd.sh", "/sbin/netd", 7, "var_expansion")
    _add_script_call(db, "/etc/init.d/netd.sh", "netd", 19, "literal")
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_er")
    er = _evidence_of(atlas, "arp_run")["entry_reach"]
    assert er["status"] == "found"
    # both call sites (path form + bare-name form) are listed with their arg source.
    assert {(s["line"], s["arg_source"]) for s in er["sites"]} == {
        (7, "var_expansion"),
        (19, "literal"),
    }


def test_flow_evidence_entry_unknown_when_no_script_calls(tmp_path: Path) -> None:
    # No invocation found is reported as unknown, NOT unreachable; the candidate is not dropped.
    db = _make_db(tmp_path, [{"name": "netd", "funcs": [_charset_buffer_cmd_fn()]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_noer")
    assert _evidence_of(atlas, "arp_run")["entry_reach"]["status"] == "unknown"


def test_flow_evidence_survives_source_db_removal(tmp_path: Path) -> None:
    db = _make_db(tmp_path, [{"name": "netd", "funcs": [_charset_buffer_cmd_fn()]}])
    _add_script_call(db, "/etc/init.d/netd.sh", "netd", 5, "var_expansion")
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_rm")
    db.unlink()  # source analysis.db gone — atlas is the persistent store
    ev = _evidence_of(atlas, "arp_run")
    assert ev["source_kind"] == "charset_maybe"
    assert ev["entry_reach"]["sites"][0]["line"] == 5


def test_flow_evidence_does_not_add_candidates(tmp_path: Path) -> None:
    # ★ count neutrality: evidence is a field on existing cmd candidates, never a new candidate.
    db = _make_db(tmp_path, [{"name": "netd", "funcs": [_charset_buffer_cmd_fn()]}])
    _add_script_call(db, "/etc/init.d/netd.sh", "netd", 5, "literal")
    atlas = tmp_path / "atlas.db"
    s1 = run_analyzer2(db, atlas, source_run_id="run_n1")
    assert s1.instances_written == len(_instances(atlas)) == s1.matches == 1


# ── factor ① one-hop wrapper propagation (R-L3·A): recover the D-2 blind spot ─────────


def _thin_cmd_wrapper_fn(name: str = "do_cmd") -> dict[str, object]:
    return {
        "name": name,
        "pseudocode": f"void {name}(char* param_1){{ system(param_1); }}",
        "hash": f"h_{name}",
        "callees": ["system"],
    }


def _free_via_wrapper_fn(name: str = "set_route") -> dict[str, object]:
    # The D-2 / 0x6b90 shape: builds a free string and forwards it to the thin wrapper — NO direct
    # command sink among its callees, so the shape scan never surfaces it.
    body = (
        f"void {name}(void){{ char* v=nvram_get(0); char cmd[128]; "
        f'snprintf(cmd,128,"route add %s",v); do_cmd(cmd); }}'
    )
    return {
        "name": name,
        "pseudocode": body,
        "hash": f"h_{name}",
        "callees": ["nvram_get", "snprintf", "do_cmd"],
    }


def _const_via_wrapper_fn(name: str = "reboot_now") -> dict[str, object]:
    return {
        "name": name,
        "pseudocode": f'void {name}(void){{ do_cmd("/sbin/reboot"); }}',
        "hash": f"h_{name}",
        "callees": ["do_cmd"],
    }


def _charset_via_wrapper_fn(name: str = "arp_set") -> dict[str, object]:
    body = (
        f"void {name}(struct ether_addr* m){{ char c[64]; "
        f'snprintf(c,64,"arp -s %s",ether_ntoa(m)); do_cmd(c); }}'
    )
    return {
        "name": name,
        "pseudocode": body,
        "hash": f"h_{name}",
        "callees": ["snprintf", "ether_ntoa", "do_cmd"],
    }


def test_free_string_via_wrapper_becomes_high_band_candidate(tmp_path: Path) -> None:
    # ★ D-2 target: a function whose sink hides in a thin wrapper becomes a cmd candidate, with
    # evidence noting the one-hop wrapper, and floats to the high band (free string, no downweight).
    db = _make_db(
        tmp_path,
        [{"name": "netd", "funcs": [_thin_cmd_wrapper_fn(), _free_via_wrapper_fn()]}],
    )
    atlas = tmp_path / "atlas.db"
    stats = run_analyzer2(db, atlas, source_run_id="run_a")
    assert stats.wrapper_propagated == 1

    row = _by_anchor(atlas)["set_route"]
    assert row["sink_anchor"] == "system"  # the real sink, reached via the wrapper
    assert row["provenance_level"] == "L0"  # cross-function: not graded, honest
    assert row["blocking_mechanism"] is None  # free string -> not downweighted
    ev = json.loads(row["flow_evidence"])
    assert ev["source_kind"] == "free_string"
    assert ev["flow_path"]["sink_via_wrapper"] is True
    assert ev["flow_path"]["wrapper"]["name"] == "do_cmd"
    assert ev["trace_boundary"] == "reached_sink_via_one_hop_wrapper"
    assert row["evidence_ref"].endswith("@cmd_via_wrapper")


def _json_free_via_wrapper_fn(name: str = "set_wifi") -> dict[str, object]:
    # The exact 0x6b90 shape: a json string getter -> intermediate var -> snprintf -> wrapper.
    body = (
        f"void {name}(void){{ char* s=json_object_get_string(o); char cmd[256]; "
        f'snprintf(cmd,256,"netctl set %s",s); do_cmd(cmd); }}'
    )
    return {
        "name": name,
        "pseudocode": body,
        "hash": f"h_{name}",
        "callees": ["json_object_get_string", "snprintf", "do_cmd"],
    }


def test_json_free_string_via_wrapper_floats_high(tmp_path: Path) -> None:
    # ★ D-2 anchor: json external input -> intermediate var -> wrapper -> system. Recovered as a
    # cmd candidate, classified free_string (json is a source), high band, not downweighted.
    db = _make_db(
        tmp_path,
        [{"name": "netd", "funcs": [_thin_cmd_wrapper_fn(), _json_free_via_wrapper_fn()]}],
    )
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_json")
    row = _by_anchor(atlas)["set_wifi"]
    assert row["blocking_mechanism"] is None  # free string -> not downweighted
    ev = json.loads(row["flow_evidence"])
    assert ev["source_kind"] == "free_string"
    assert ev["flow_path"]["sink_via_wrapper"] is True
    # free string -> controllability=free (top of the impact band), never sunk
    assert _ctrl_of(atlas, "set_wifi") == "free"
    assert not _is_safe(atlas, "set_wifi")


def test_safe_fanout_to_wrapper_is_suppressed_below_real_concat(tmp_path: Path) -> None:
    # ★ the real free-string-via-wrapper outranks the safe fanout (constant / charset
    # argument forwarded to the wrapper), which the existing FP-suppression downweights.
    db = _make_db(
        tmp_path,
        [
            {
                "name": "netd",
                "funcs": [
                    _thin_cmd_wrapper_fn(),
                    _free_via_wrapper_fn(),
                    _const_via_wrapper_fn(),
                    _charset_via_wrapper_fn(),
                ],
            }
        ],
    )
    atlas = tmp_path / "atlas.db"
    stats = run_analyzer2(db, atlas, source_run_id="run_b")
    assert stats.wrapper_propagated == 3  # the three callers; the wrapper itself is a direct match

    rows = _by_anchor(atlas)
    assert rows["reboot_now"]["blocking_mechanism"] == "const_sink_arg"
    assert rows["arp_set"]["blocking_mechanism"] == "charset_constrained"
    # the real free concat (controllability=free) outranks both safe fanouts: const_sink_arg is
    # provably-constant -> sunk; arp_set's charset_safe source -> constrained (below free).
    assert _ctrl_of(atlas, "set_route") == "free"
    assert _ctrl_of(atlas, "reboot_now") == "constant" and _is_safe(atlas, "reboot_now")
    assert _ctrl_of(atlas, "arp_set") == "constrained"
    assert _rank_of(atlas, "set_route") < _rank_of(atlas, "reboot_now")
    assert _rank_of(atlas, "set_route") < _rank_of(atlas, "arp_set")


def test_wrapper_itself_kept_as_distinct_bare_sink_candidate(tmp_path: Path) -> None:
    # No double counting: the wrapper is its own bare_sink candidate (@cmd); the caller is the
    # wrapper-recovered candidate (@cmd_via_wrapper). Two distinct instances.
    db = _make_db(
        tmp_path,
        [{"name": "netd", "funcs": [_thin_cmd_wrapper_fn(), _free_via_wrapper_fn()]}],
    )
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_c")
    rows = _by_anchor(atlas)
    assert rows["do_cmd"]["exposure_shape"] == "bare_sink"
    assert rows["do_cmd"]["blocking_mechanism"] is None
    assert rows["do_cmd"]["evidence_ref"].endswith("@cmd")
    assert rows["set_route"]["evidence_ref"].endswith("@cmd_via_wrapper")
    refs = [r["evidence_ref"] for r in _instances(atlas)]
    assert len(set(refs)) == len(refs)  # unique


def test_wrapper_propagation_is_deterministic(tmp_path: Path) -> None:
    funcs = [_thin_cmd_wrapper_fn(), _free_via_wrapper_fn(), _charset_via_wrapper_fn()]
    db = _make_db(tmp_path, [{"name": "netd", "funcs": funcs}])
    a1 = tmp_path / "a1.db"
    a2 = tmp_path / "a2.db"
    run_analyzer2(db, a1, source_run_id="r")
    run_analyzer2(db, a2, source_run_id="r")

    def _ev_by_fn(atlas: Path) -> dict[str, str]:
        return {r["source_anchor"]: (r["flow_evidence"] or "") for r in _instances(atlas)}

    assert _ev_by_fn(a1) == _ev_by_fn(a2)


# ── factor ① on the format-string axis (缺口①): symmetric fmt-wrapper propagation ──────


def _thin_fmt_wrapper_fn(name: str = "log_msg") -> dict[str, object]:
    # A thin format wrapper: forwards a parameter into printf's format position (arg0).
    return {
        "name": name,
        "pseudocode": f"void {name}(char* param_1){{ printf(param_1); }}",
        "hash": f"h_{name}",
        "callees": ["printf"],
    }


def _free_via_fmt_wrapper_fn(name: str = "handle_req") -> dict[str, object]:
    # Builds a free string and forwards it to the thin format wrapper — NO direct format-string
    # sink among its callees, so the shape scan never surfaces it (the D-2 blind spot, fmt axis).
    body = (
        f"void {name}(void){{ char* v=nvram_get(0); char m[128]; "
        f'snprintf(m,128,"got %s",v); log_msg(m); }}'
    )
    return {
        "name": name,
        "pseudocode": body,
        "hash": f"h_{name}",
        "callees": ["nvram_get", "snprintf", "log_msg"],
    }


def test_free_string_via_fmt_wrapper_becomes_fmt_candidate(tmp_path: Path) -> None:
    # ★ 缺口① target: a function whose format-string sink hides in a thin format wrapper becomes a
    # fmt_string candidate (NOT a cmd one), with evidence noting the one-hop wrapper.
    db = _make_db(
        tmp_path,
        [{"name": "netd", "funcs": [_thin_fmt_wrapper_fn(), _free_via_fmt_wrapper_fn()]}],
    )
    atlas = tmp_path / "atlas.db"
    stats = run_analyzer2(db, atlas, source_run_id="run_fmt")
    assert stats.wrapper_propagated == 1

    row = _by_anchor(atlas)["handle_req"]
    assert row["sink_anchor"] == "printf"  # the real format-string sink, reached via the wrapper
    assert row["provenance_level"] == "L0"  # cross-function: not graded, honest
    assert row["blocking_mechanism"] is None  # free string -> not downweighted
    ev = json.loads(row["flow_evidence"])
    assert ev["source_kind"] == "free_string"
    assert ev["flow_path"]["sink_via_wrapper"] is True
    assert ev["flow_path"]["wrapper"]["name"] == "log_msg"
    assert ev["flow_path"]["wrapper"]["wrapped_sink"] == "printf"
    assert ev["trace_boundary"] == "reached_sink_via_one_hop_wrapper"
    assert row["evidence_ref"].endswith("@fmt_via_wrapper")

    # The candidate is on the fmt_string axis (its pattern), never mislabeled as cmd.
    conn = open_atlas(atlas)
    try:
        sink_class = conn.execute(
            "SELECT p.sink_class FROM instance i JOIN pattern p ON p.pattern_id = i.pattern_id "
            "WHERE i.source_anchor = 'handle_req'"
        ).fetchone()[0]
    finally:
        conn.close()
    assert sink_class == "fmt_string"


def _unknown_via_fmt_wrapper_fn(name: str = "log_status") -> dict[str, object]:
    # Forwards a value with NO recognized free source (built from a constant) into the thin fmt
    # wrapper. It has no direct fmt sink, so it is a fmt-wrapper candidate — but its source is
    # 'unknown', so the fmt precision gate DROPS it. The drop must be COUNTED, not silent.
    body = f'void {name}(void){{ char m[64]; snprintf(m,64,"status ok"); log_msg(m); }}'
    return {
        "name": name,
        "pseudocode": body,
        "hash": f"h_{name}",
        "callees": ["snprintf", "log_msg"],
    }


def test_fmt_wrapper_unknown_source_is_demoted_and_counted_not_dropped(tmp_path: Path) -> None:
    # ★ A '?' is never silently removed. An unknown forwarded controllability is DEMOTED, not
    # dropped: it stays in the corpus (and stays queryable), and the count reports the demotion so
    # a reader knows how much of the fmt axis rests on an unknown.
    db = _make_db(
        tmp_path,
        [{"name": "netd", "funcs": [_thin_fmt_wrapper_fn(), _unknown_via_fmt_wrapper_fn()]}],
    )
    atlas = tmp_path / "atlas.db"
    stats = run_analyzer2(db, atlas, source_run_id="run_fmt_unk")
    assert stats.fmt_wrapper_unknown_source_demoted == 1  # counted as demoted
    assert "emit_state" in _by_anchor(atlas)  # SURVIVES — the corpus did not shrink


def test_fmt_wrapper_itself_kept_as_distinct_candidate(tmp_path: Path) -> None:
    # No double counting: the wrapper is its own direct fmt candidate (@fmt_string); the caller is
    # the wrapper-recovered candidate (@fmt_via_wrapper). Two distinct, uniquely-referenced rows.
    db = _make_db(
        tmp_path,
        [{"name": "netd", "funcs": [_thin_fmt_wrapper_fn(), _free_via_fmt_wrapper_fn()]}],
    )
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_fmt2")
    rows = _by_anchor(atlas)
    assert rows["log_msg"]["evidence_ref"].endswith("@fmt_string")
    assert rows["handle_req"]["evidence_ref"].endswith("@fmt_via_wrapper")
    refs = [r["evidence_ref"] for r in _instances(atlas)]
    assert len(set(refs)) == len(refs)  # unique


def _unknown_via_fmt_wrapper_fn(name: str = "emit_state") -> dict[str, object]:
    # Forwards a non-free value (a global-ish name — no source call, not a parameter) into the thin
    # fmt wrapper, so the source stays "unknown". This is the field-dominant fmt wrapper shape (a
    # caller of a variadic logger with an unconfirmed source) that the precision gate drops.
    return {
        "name": name,
        "pseudocode": f"void {name}(void){{ log_msg(g_state); }}",
        "hash": f"h_{name}",
        "callees": ["log_msg"],
    }


def test_unknown_source_fmt_wrapper_candidate_survives_in_corpus(tmp_path: Path) -> None:
    # ★ The precision gate is a RANKING job, not a corpus job. source_kind here is only ever
    # free_string or unknown — there is no proven-uncontrollable reading — so dropping on "not
    # controllable" discarded 100% '?'. The same function found DIRECTLY keeps its unknown
    # candidate, so removing it when found through a wrapper was a pure false negative.
    db = _make_db(
        tmp_path,
        [{"name": "netd", "funcs": [_thin_fmt_wrapper_fn(), _unknown_via_fmt_wrapper_fn()]}],
    )
    atlas = tmp_path / "atlas.db"
    stats = run_analyzer2(db, atlas, source_run_id="run_fmt_drop")
    assert stats.wrapper_propagated == 1  # recovered, not discarded
    anchors = set(_by_anchor(atlas))
    assert "emit_state" in anchors  # queryable: it has its own @fmt_via_wrapper instance
    assert "log_msg" in anchors  # the wrapper stays its own direct fmt candidate (printf param)


def test_fmt_wrapper_keeps_controllable_and_demotes_unknown(tmp_path: Path) -> None:
    # Source-selectivity is preserved, but expressed as RANK rather than removal: both callers are
    # recovered; the read-side ladder puts the free-string one above the unknown one. That serves
    # the original motive (variadic loggers must not flood the high band) without deleting a '?'.
    db = _make_db(
        tmp_path,
        [
            {
                "name": "netd",
                "funcs": [
                    _thin_fmt_wrapper_fn(),
                    _free_via_fmt_wrapper_fn(),
                    _unknown_via_fmt_wrapper_fn(),
                ],
            }
        ],
    )
    atlas = tmp_path / "atlas.db"
    stats = run_analyzer2(db, atlas, source_run_id="run_fmt_gate")
    assert stats.wrapper_propagated == 2  # BOTH recovered; the difference is rank, not presence
    assert stats.fmt_wrapper_unknown_source_demoted == 1
    anchors = set(_by_anchor(atlas))
    assert "handle_req" in anchors  # external_input -> kept, ranks high
    assert "emit_state" in anchors  # unknown -> kept, ranks low (never removed)
    # the ladder, not the gate, separates them: free outranks unknown, and neither is sunk
    free_rank = _controllability_rank(_cand_of(atlas, "handle_req").dim("controllability"))
    unk_rank = _controllability_rank(_cand_of(atlas, "emit_state").dim("controllability"))
    assert free_rank > unk_rank  # a controllable source still ranks above an unknown one
    assert unk_rank > _CONTROLLABILITY_RANK["constant"]  # ...but a '?' never hits the floor


def test_cmd_axis_unknown_source_wrapper_is_still_kept(tmp_path: Path) -> None:
    # Regression guard: the precision gate is fmt-axis only. A constant forwarded to a shell wrapper
    # (source_class "unknown" on the cmd axis) stays a graded, downweighted lead — NOT dropped.
    db = _make_db(
        tmp_path,
        [{"name": "netd", "funcs": [_thin_cmd_wrapper_fn(), _const_via_wrapper_fn()]}],
    )
    atlas = tmp_path / "atlas.db"
    stats = run_analyzer2(db, atlas, source_run_id="run_cmd_unknown")
    assert stats.wrapper_propagated == 1  # the const-forwarding cmd caller is still recovered
    row = _by_anchor(atlas)["reboot_now"]
    assert row["evidence_ref"].endswith("@cmd_via_wrapper")
    assert row["blocking_mechanism"] == "const_sink_arg"  # downweighted, not dropped


# ── path/file sinks (recall extension: fopen/open/unlink/… — a controllable path) ──


def _path_sink_fn(
    name: str, *, sink: str = "fopen", path: str = "const", mode: str = '"r"'
) -> dict[str, object]:
    """A function calling a path/file ``sink``. ``path`` picks the PATH-argument form:
    const (a string literal), free (a recv-sourced buffer), or unknown (an untraceable local)."""
    if path == "const":
        params, pre, arg, callees = "", "", '"/tmp/nc/nc.conf"', [sink]
    elif path == "free":
        params, pre, arg, callees = "", "char buf[64]; recv(fd,buf,64); ", "buf", ["recv", sink]
    else:  # unknown: a local with no recognized source, not a parameter, not a literal
        params, pre, arg, callees = "", "char *p = lookup_path(); ", "p", ["lookup_path", sink]
    body = f"void {name}({params}){{ {pre}{sink}({arg},{mode}); }}"
    return {"name": name, "pseudocode": body, "hash": f"h_{name}", "callees": callees}


def test_path_sink_class_generates_candidates(tmp_path: Path) -> None:
    # The whole path-sink class went from zero coverage to a candidate: a fopen with a controllable
    # (recv-sourced) path is now recalled as sink_class=path_sink, anchored to the concrete callee.
    db = _make_db(tmp_path, [{"name": "httpd", "funcs": [_path_sink_fn("open_free", path="free")]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="r")
    cand = _cand_of(atlas, "open_free")
    assert cand.sink_class == "path_sink"
    assert cand.sink_anchor == "fopen"


def test_path_sink_controllability_three_state(tmp_path: Path) -> None:
    # The path argument's controllability is honest three-state, exactly like cmd/fmt reuse the same
    # def-use: a constant literal path -> constant (proven-safe, sunk); a free source -> free
    # (active); an untraceable local -> unknown (a '?', never sunk).
    db = _make_db(
        tmp_path,
        [
            {
                "name": "httpd",
                "funcs": [
                    _path_sink_fn("p_const", path="const"),
                    _path_sink_fn("p_free", path="free"),
                    _path_sink_fn("p_unknown", path="unknown"),
                ],
            }
        ],
    )
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="r")
    assert _ctrl_of(atlas, "p_const") == "constant" and _is_safe(atlas, "p_const")
    assert _ctrl_of(atlas, "p_free") == "free" and not _is_safe(atlas, "p_free")
    assert _ctrl_of(atlas, "p_unknown") == "unknown" and not _is_safe(atlas, "p_unknown")


def test_path_sink_reads_per_sink_arg_position(tmp_path: Path) -> None:
    # openat's path is arg1 (arg0 is the dirfd). A literal path at arg1 must be read as the constant
    # (proving PATH_SINK_ARG is honoured) — blindly reading arg0 (the dirfd) would miss it and the
    # candidate would wrongly stay in the active region instead of sinking.
    fn = {
        "name": "oa",
        "pseudocode": 'void oa(){ openat(0xffffff9c, "/etc/passwd", 0); }',
        "hash": "h_oa",
        "callees": ["openat"],
    }
    db = _make_db(tmp_path, [{"name": "svcd", "funcs": [fn]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="r")
    assert _by_anchor(atlas)["oa"]["blocking_mechanism"] == "const_sink_arg"
    assert _ctrl_of(atlas, "oa") == "constant" and _is_safe(atlas, "oa")


def test_path_sink_writer_is_honestly_not_traced(tmp_path: Path) -> None:
    # This phase there is no Ghidra def-use provenance for path sinks, so the writer layer is an
    # honest 'not_traced' ('?') — never faked 'located', and a '?' never sinks the candidate.
    db = _make_db(tmp_path, [{"name": "httpd", "funcs": [_path_sink_fn("p_free", path="free")]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="r")
    writer = _cand_of(atlas, "p_free").dim("writer")
    assert writer.value == "not_traced" and writer.state == "unknown"


def test_path_sink_impact_is_high_and_filterable(tmp_path: Path) -> None:
    # path_sink enters the map at a high impact tier (above copy) and is filterable via the
    # sink_impact dimension — the triage SORT code did not change (extensibility: one config row).
    from treasure_map.lib.query import filter_by_dimension, impact_tier
    from treasure_map.lib.query import triage as run_triage

    assert impact_tier("path_sink") == impact_tier("cmd")  # high tier
    assert impact_tier("path_sink") > impact_tier("copy")
    db = _make_db(tmp_path, [{"name": "httpd", "funcs": [_path_sink_fn("p_free", path="free")]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="r")
    conn = open_atlas(atlas)
    try:
        only_path = filter_by_dimension(run_triage(conn), "sink_impact", "path_sink")
    finally:
        conn.close()
    assert [c.function for c in only_path] == ["p_free"]


def test_path_sink_is_additive_no_regression(tmp_path: Path) -> None:
    # A function with BOTH a cmd sink and a path sink yields the cmd candidate unchanged PLUS a new
    # path candidate — the path class is additive, never cannibalizing the existing sink classes.
    fn = {
        "name": "both",
        "pseudocode": (
            "void both(){ char buf[64]; recv(fd,buf,64); char cmd[128]; "
            'snprintf(cmd,128,"/bin/x %s",buf); system(cmd); fopen(buf,"r"); }'
        ),
        "hash": "h_both",
        "callees": ["recv", "snprintf", "system", "fopen"],
    }
    db = _make_db(tmp_path, [{"name": "webd", "funcs": [fn]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="r")
    from treasure_map.lib.query import triage as run_triage

    conn = open_atlas(atlas)
    try:
        pairs = {(c.function, c.sink_class) for c in run_triage(conn)}
    finally:
        conn.close()
    assert ("both", "cmd") in pairs  # the pre-existing cmd candidate is untouched
    assert ("both", "path_sink") in pairs  # the new path candidate coexists


# ── BOUNDARY ────────────────────────────────────────────────────────────────────────


def test_a2_sources_are_boundary_clean() -> None:
    # The neutral A2 + aggregation layer carries no offensive/judgement framing and no section /
    # private-doc refs. The private exploited-hole ledger (exploit_ledger.py + its private_exploit /
    # exploit_note storage in the schema) is the ONE sanctioned non-neutral store the
    # exploit-barrier ledger feature adds: the domain term "exploit" is permitted THERE only. Every
    # harder framing word stays banned across the whole layer — including the ledger and the schema
    # — so the carve-out is
    # exactly one word, exactly two surfaces.
    hard = re.compile(
        r"\b(vuln\w*|payload|\bpoc\b|finding|defect|incomplete_patch|fix_quality|"
        r"priority|risk[_ ]?score)\b",
        re.IGNORECASE,
    )
    section_ref = re.compile(r"§|PRD\s")
    # "exploit*" framing is still banned in every NEUTRAL file; the two sanctioned storage
    # identifiers (the exploit_ledger import path, the exploit_note column) are the only exceptions.
    stray_exploit = re.compile(r"\bexploit(?!_ledger\b|_note\b)\w*", re.IGNORECASE)
    exploit_exempt = {"exploit_ledger.py"}  # the private ledger read module (non-neutral by design)
    for path in [_HUNT_A2, *_QUERY_PKG.glob("*.py"), _ATLAS_SCHEMA]:
        text = path.read_text()
        assert not hard.search(text), f"offensive framing in {path.name}"
        assert not section_ref.search(text), f"section/private-doc ref in {path.name}"
        # the schema stores the exploit ledger (its whole barrier DDL block is "exploit" prose), so
        # the exploit-word check applies to the neutral files only, never the two sanctioned
        # surfaces.
        if path.name not in exploit_exempt and path.name != _ATLAS_SCHEMA.name:
            assert not stray_exploit.search(text), f"stray 'exploit' framing in {path.name}"
