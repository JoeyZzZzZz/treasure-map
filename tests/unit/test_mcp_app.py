# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the MCP server (treasure_map.mcp_app) and its contracts.

Hermetic: a synthetic analysis.db + atlas.db; no stdio transport spun up (the tool callables are
exercised directly). Proves tool discovery, the CLI/MCP/lib parity (one shared query), the two
output contracts (no anchor -> no output; no payload), and the recall -> facts milestone chain.
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

from click.testing import CliRunner

from treasure_map import mcp_app
from treasure_map.cli.mcp_cli import fact as fact_group
from treasure_map.lib import facts
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import InstanceRow, NvramFlowRow
from treasure_map.lib.atlas.writer import (
    add_instance,
    add_nvram_flow_rows,
    begin_run,
    finish_run,
    upsert_pattern,
)
from treasure_map.lib.query.triage import Dimension, TriageCandidate
from treasure_map.lib.storage.connection import open_db

_EXPECTED_TOOLS = {
    "list_candidates",
    "list_runs",
    "explain_candidate",
    "get_sink_provenance",
    "get_nvram_key_flow",
    "cross_firmware_patterns",
    "pattern_density",
    "pattern_twins",
    "dormant_candidates",
    "get_pseudocode",
    "get_callees",
    "get_xrefs",
    "get_strings",
    "get_functions_referencing_string",
    "get_imports_exports",
    "get_script_callsites",
    "get_components_cves",
    "get_disassembly",
    "mark_exploited",
    "list_moat",
    "list_cve_patterns",
    "import_cve_patterns",
    "legal_notice",
}


def _mk_analysis(tmp_path: Path) -> Path:
    db = tmp_path / "analysis.db"
    conn = open_db(db)
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256) VALUES (1, 'webd', 'usr/sbin/webd', ?)",
        ("a" * 64,),
    )
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, address, size_bytes, pseudocode, callees) "
        "VALUES (1, 1, 'handle_req', '0x6b90', 64, 'void handle_req(){ do_fwd(buf); }', ?)",
        (json.dumps(["do_fwd"]),),
    )
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, address, pseudocode, callees) "
        "VALUES (2, 1, 'do_fwd', '0x5c34', 'void do_fwd(char* a){ system(a); }', ?)",
        (json.dumps(["system"]),),
    )
    conn.execute(
        "INSERT INTO non_binary_files (id, kind, name, path) "
        "VALUES (1, 'shell_script', 'rc', 'etc/rc')"
    )
    conn.execute(
        "INSERT INTO script_calls (file_id, command, raw_line, line_number, args_pattern) "
        "VALUES (1, 'webd', 'webd &', 3, 'literal')"
    )
    conn.commit()
    conn.close()
    return db


def _mk_atlas(tmp_path: Path) -> Path:
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    pid = upsert_pattern(
        conn,
        source_class="external_input",
        sink_class="cmd",
        call_sequence_shape="source->cmd",
        structural_fingerprint="fp_demo",
        fingerprint_algo_version="callseq-v1",
    )
    add_instance(
        conn,
        InstanceRow(
            pattern_id=pid,
            pseudocode_hash="h1",
            source_anchor="handle_req",
            sink_anchor="do_fwd",
            source_run_id="run_m",
            reachability_status="unknown",
            blocking_mechanism=None,
            provenance_level="L0",
            evidence_ref="run_m#fn1@cmd",
            scope_origin="intra",
            origin="custom",
            binary_path="usr/sbin/webd",
            flow_evidence=json.dumps(
                {
                    "entry_reach": {
                        "status": "found",
                        "sites": [{"kind": "web_endpoint", "method": "POST", "endpoint": "/x.cgi"}],
                    }
                }
            ),
        ),
    )
    # Record the run_id -> analysis.db resolver so the run-aware fact tools can route to run_m's db
    # (the analysis.db _mk_analysis writes in the same tmp_path).
    begin_run(conn, "run_m", analysis_db_path=str((tmp_path / "analysis.db").resolve()))
    finish_run(conn, "run_m", binaries=1, functions=2)
    conn.close()
    return atlas


def _tools(tmp_path: Path):
    _mk_analysis(tmp_path)  # the analysis.db the run_m lineage row resolves to
    return mcp_app.make_tools(_mk_atlas(tmp_path))


# ── discoverability ──────────────────────────────────────────────────────────────────


def test_server_registers_all_tools(tmp_path: Path) -> None:
    _mk_analysis(tmp_path)
    server = mcp_app.build_server(_mk_atlas(tmp_path))
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert names == _EXPECTED_TOOLS


# ── CLI / MCP / lib parity: one shared query, identical result ──────────────────────


_RUN_ENVELOPE_KEYS = {"atlas", "resolved_run", "run_source", "run_lineage", "warning"}


def _fact_payload(result: dict) -> dict:
    """A run-aware fact result minus the run-routing envelope (resolved_run / run_lineage / …), so
    it can be compared against the raw lib/CLI fact it wraps (the shared query is identical)."""
    return {k: v for k, v in result.items() if k not in _RUN_ENVELOPE_KEYS}


def test_cli_mcp_lib_parity_pseudocode(tmp_path: Path) -> None:
    analysis = _mk_analysis(tmp_path)
    tools = mcp_app.make_tools(_mk_atlas(tmp_path))
    # lib directly
    conn = facts.open_analysis_ro(analysis)
    lib_result = facts.get_pseudocode(conn, func="handle_req")
    conn.close()
    # MCP tool (run-aware: routed by run_id, then stamped with the run envelope)
    mcp_result = tools["get_pseudocode"]("handle_req", run_id="run_m")
    assert mcp_result["resolved_run"] == "run_m"  # echoed the run it answered from
    # CLI
    cli = CliRunner().invoke(
        fact_group, ["pseudocode", "handle_req", "--analysis-db", str(analysis)]
    )
    assert cli.exit_code == 0, cli.output
    cli_result = json.loads(cli.output)
    # the underlying fact (minus the MCP run envelope) is identical across lib / MCP / CLI
    assert lib_result == _fact_payload(mcp_result) == cli_result


# ── contract 1: no anchor, no output ────────────────────────────────────────────────


def test_no_anchor_no_output(tmp_path: Path) -> None:
    tools = _tools(tmp_path)
    assert tools["get_pseudocode"]("does_not_exist", run_id="run_m")["found"] is False
    assert tools["explain_candidate"]("run_m#nope")["found"] is False


# ── contract 2: outputs carry no payload / trigger bytes / PoC ──────────────────────


def test_outputs_carry_no_payload(tmp_path: Path) -> None:
    tools = _tools(tmp_path)
    blobs = [
        tools["list_candidates"](),
        tools["explain_candidate"]("run_m#fn1@cmd"),
        tools["get_pseudocode"]("handle_req", run_id="run_m"),
        tools["get_callees"]("handle_req", run_id="run_m"),
        tools["get_script_callsites"]("webd", run_id="run_m"),
        tools["get_disassembly"]("handle_req", run_id="run_m"),
        tools["legal_notice"](),
    ]
    text = json.dumps(blobs).lower()
    # No input-construction vocabulary smuggled into any tool output.
    assert not re.search(r"\b(payload|poc|exploit code|trigger bytes|shellcode)\b", text)


# ── get_nvram_key_flow: cross-binary key graph with three-tier honesty ──────────────


def test_get_nvram_key_flow_tool(tmp_path: Path) -> None:
    atlas = _mk_atlas(tmp_path)
    conn = open_atlas(atlas)
    add_nvram_flow_rows(
        conn,
        [
            NvramFlowRow(
                source_run_id="run_m",
                key="sw_mode",
                key_kind="constant",
                binary="rc",
                func="set_mode",
                op="write",
                value_source='{"kind": "param", "name": "param_2"}',
                api="nvram_set",
            ),
            NvramFlowRow(
                source_run_id="run_m",
                key="sw_mode",
                key_kind="constant",
                binary="httpd",
                func="read_mode",
                op="read",
                api="nvram_get",
            ),
            NvramFlowRow(
                source_run_id="run_m",
                key=None,
                key_kind="unresolved",
                binary="httpd",
                func="fwd",
                op="write",
                api="nvram_set",
            ),
        ],
    )
    conn.close()
    tools = mcp_app.make_tools(atlas)

    res = tools["get_nvram_key_flow"]("sw_mode")
    assert res["found"] is True
    assert [w["binary"] for w in res["writers"]] == ["rc"]
    assert [r["binary"] for r in res["readers"]] == ["httpd"]
    assert res["writers"][0]["value_source"] == {"kind": "param", "name": "param_2"}
    # an unresolved-key op exists -> the tool honestly flags possible incompleteness
    assert res["completeness"] == "may_be_incomplete"
    assert res["unresolved_count"] == 1
    assert "DIRECT nvram_get/set" in res["coverage"]  # standing coverage boundary always present
    # a missing key still returns honestly (no fabrication) AND never reads as "unused": the
    # wrapper blind spot is stated so an empty result is not mistaken for "no consumer".
    miss = tools["get_nvram_key_flow"]("no_such_key")
    assert miss["found"] is False
    assert miss["completeness"] == "may_be_incomplete"
    assert any("wrapper" in n for n in miss["notes"])


# ── list_candidates: anchored, entry-reach carried, derived-not-verdict note ────────


def test_list_candidates_carries_anchor_entry_reach_and_note(tmp_path: Path) -> None:
    tools = _tools(tmp_path)
    out = tools["list_candidates"]()
    assert "DERIVED" in out["note"] and "NOT a verdict" in out["note"]
    # the map carries a switchable lens + honest caveats, no collapsed score
    assert out["lens"]["label"] and out["lens"]["spine"] == "impact"
    assert any("optimistic" in c.lower() for c in out["caveats"])
    (cand,) = out["candidates"]
    assert cand["evidence_ref"] == "run_m#fn1@cmd"  # anchor present
    assert "score" not in cand  # the collapsed score is gone
    # compact row (M1): controllability is a spine state:value label (ALWAYS present); every other
    # axis rides the AXIS-AGNOSTIC carry rule. entry:web is an established mechanistic label, so the
    # row carries reachability=proven:entry:web — the cross-step seam (step-2's Dimension reaches
    # the compact serializer) and sink_impact rides the same rule.
    assert cand["controllability"] == "unknown:unknown"
    assert cand["dimensions"]["reachability"] == "proven:entry:web"
    assert cand["dimensions"]["sink_impact"] == "proven:cmd"
    assert "reachability" not in cand  # the raw entry_reach top-level field is folded into the axis


def test_list_candidates_exposes_view_catalog_with_when_to_use(tmp_path: Path) -> None:
    # Views are DISCOVERABLE from the result: available_views lists every preset with its spine
    # and a when-to-use note, so an agent knows which lens fits its goal (not just how to switch).
    tools = _tools(tmp_path)
    out = tools["list_candidates"]()
    views = {v["view"]: v for v in out["available_views"]}
    assert set(views) == {"default", "by-sink", "nvram-source", "reachable-first"}
    for v in views.values():
        assert v["when_to_use"] and v["spine"]  # each carries a goal note + its spine
    assert "nvram-mediated" in views["nvram-source"]["when_to_use"].lower()
    # reachable-first stays honest: a mechanistic reference, NOT call-graph reachability; it FLOATS
    # (corpus whole), never prunes.
    ro = views["reachable-first"]["when_to_use"].lower()
    assert "not call-graph reachability" in ro and "floats" in ro
    # and the tool docstring points the agent at the catalog + the reachable-only caveat.
    doc = tools["list_candidates"].__doc__.lower()
    assert "available_views" in doc and "not call-graph reachability" in doc


def _mk_multi_atlas(tmp_path: Path) -> Path:
    # 2 cmd + 3 copy candidates over run_m, so corpus/sweep/float counts are observable on the MCP
    # face (the surface the agent actually calls).
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)

    def mk(sink_class: str, fn: str, source_kind: str | None = None) -> None:
        pid = upsert_pattern(
            conn,
            source_class="external_input",
            sink_class=sink_class,
            call_sequence_shape="s",
            structural_fingerprint=f"fp_{sink_class}",
            fingerprint_algo_version="callseq-v1",
        )
        ev = json.dumps({"source_kind": source_kind}) if source_kind else None
        add_instance(
            conn,
            InstanceRow(
                pattern_id=pid,
                pseudocode_hash=fn,
                source_anchor=fn,
                sink_anchor="system" if sink_class == "cmd" else "strcpy",
                source_run_id="run_m",
                reachability_status="unknown",
                blocking_mechanism=None,
                provenance_level="L0",
                evidence_ref=f"run_m#{fn}",
                scope_origin="intra",
                origin="custom",
                flow_evidence=ev,
            ),
        )

    mk("cmd", "c1", source_kind="free_string")
    mk("cmd", "c2")
    mk("copy", "p1")
    mk("copy", "p2")
    mk("copy", "p3")
    begin_run(conn, "run_m", analysis_db_path=str((tmp_path / "analysis.db").resolve()))
    finish_run(conn, "run_m", binaries=1, functions=2)
    conn.close()
    return atlas


def test_list_candidates_filter_floats_corpus_invariant(tmp_path: Path) -> None:
    # ★★ 步骤 2.5 M5-1b (gap #1 — the agent's ACTUAL surface): on MCP a --filter FLOATS, never
    # reduces the corpus. source=nvram (the OAuth-hiding regression) keeps all 5; sink_impact=cmd
    # returns the corpus (5) floated, NOT the 2 matches.
    tools = mcp_app.make_tools(_mk_multi_atlas(tmp_path))
    base = tools["list_candidates"]()
    assert base["corpus"] == 5 and base["total"] == 5
    src = tools["list_candidates"](filters="source=nvram")
    assert src["corpus"] == 5 and src["total"] == 5  # NOT reduced — no candidate hidden
    assert src["lens"]["filter_match"] == 0
    si = tools["list_candidates"](filters="sink_impact=cmd")
    assert si["corpus"] == 5 and si["total"] == 5  # floated, not the 2 reduced
    assert si["lens"]["filter_match"] == 2


def test_list_candidates_only_sweeps_and_refuses_on_mcp(tmp_path: Path) -> None:
    # ★ 步骤 2.5 M2 on MCP: --only sweeps a ground-truth dim (corpus stays whole via `corpus`) and
    # REFUSES an optimistic one with an error, never silently pruning it.
    tools = mcp_app.make_tools(_mk_multi_atlas(tmp_path))
    swept = tools["list_candidates"](only="sink_class=cmd")
    assert swept["corpus"] == 5 and swept["total"] == 2  # corpus whole, view pruned to the sweep
    refused = tools["list_candidates"](only="controllability=free")
    assert "error" in refused and "refused" in refused["error"]
    assert refused["corpus"] == 5  # the refusal still reports the whole corpus


def test_list_candidates_carries_fingerprint_and_incomplete_field(tmp_path: Path) -> None:
    # ★ Work item 6 + red-line honesty: each candidate carries its structural_fingerprint (pivot
    # from cross_firmware_patterns), and the result carries an incomplete_binaries flag.
    tools = _tools(tmp_path)
    # scoped to run_m, the per-scan completeness red-line is computed from its analysis.db
    out = tools["list_candidates"](run_id="run_m")
    assert out["incomplete_binaries"] == []  # the synthetic webd has functions
    # partial-completeness honesty: webd's functions all have pseudocode, so none are flagged
    assert out["partially_incomplete_binaries"] == []
    (cand,) = out["candidates"]
    assert cand["structural_fingerprint"] == "fp_demo"
    # the fingerprint filter round-trips (cross_firmware_patterns -> list_candidates(fingerprint=))
    assert tools["list_candidates"](fingerprint="fp_demo")["total"] == 1
    assert tools["list_candidates"](fingerprint="no_such_fp")["total"] == 0


def test_per_scan_completeness_rides_scoped_list_not_cross_run_views(tmp_path: Path) -> None:
    # The analysis-completeness red-line is a per-SCAN fact — it now rides list_candidates(run_id=…)
    # (which resolves ONE run's analysis.db), NOT the cross-run aggregations (there is no single
    # analysis.db to read across all firmware). The aggregations stay reachable + noted.
    tools = _tools(tmp_path)
    scoped = tools["list_candidates"](run_id="run_m")
    assert "incomplete_binaries" in scoped and "partially_incomplete_binaries" in scoped
    for view in ("cross_firmware_patterns", "pattern_density"):
        out = tools[view]()
        assert "incomplete_binaries" not in out  # moved to the scoped per-run listing
        assert "DERIVED" in out["note"]


def test_list_candidates_sink_class_filter(tmp_path: Path) -> None:
    tools = _tools(tmp_path)
    assert tools["list_candidates"](sink_class="copy")["total"] == 0
    assert tools["list_candidates"](sink_class="cmd")["total"] == 1


def test_list_candidates_sink_and_pagination_metadata(tmp_path: Path) -> None:
    tools = _tools(tmp_path)
    # B2: --sink semantics (concrete callee OR class) align with the CLI.
    assert tools["list_candidates"](sink="do_fwd")["total"] == 1  # by sink_anchor
    assert tools["list_candidates"](sink="cmd")["total"] == 1  # by class
    assert tools["list_candidates"](sink="nope")["total"] == 0
    # B5: pagination metadata + limit clamp.
    out = tools["list_candidates"](limit=1, offset=0)
    assert out["total"] == 1 and out["returned"] == 1 and out["truncated"] is False
    assert out["next_offset"] is None
    page2 = tools["list_candidates"](limit=1, offset=1)
    assert page2["returned"] == 0
    assert tools["list_candidates"](limit=9999)["limit"] <= 200  # clamped


def test_list_candidates_scopes_by_run_and_carries_runs_in_atlas(tmp_path: Path) -> None:
    # M7/M-A1: the listing scopes to an explicit run_id (canonical resolved_run), each row carries
    # its own ``run`` (no ambient current_run_id / is_current_run), and runs_in_atlas is ALWAYS
    # present (even when scoped) so switching firmware is one glance.
    tools = _tools(tmp_path)
    out = tools["list_candidates"](run_id="run_m")
    assert out["resolved_run"] == "run_m"
    assert "current_run_id" not in out and "isolated_to_run" not in out  # ambient binding gone
    assert out["runs_in_atlas"] == ["run_m"]  # bare id list, always present
    assert all(c["run"] == "run_m" for c in out["candidates"])
    assert all("is_current_run" not in c for c in out["candidates"])  # per-row flag gone
    # unscoped spans every run; runs_in_atlas still lists them
    allruns = tools["list_candidates"]()
    assert allruns["resolved_run"] is None and allruns["runs_in_atlas"] == ["run_m"]


def test_fact_tool_requires_run_and_hard_errors_on_the_four_modes(tmp_path: Path) -> None:
    # M2/Q1: a fact tool has NO ambient default and hard-errors (never a silent empty) across the
    # four failure modes, distinguishing "wrong run" from "no such function".
    tools = _tools(tmp_path)
    # (0) no run_id and no evidence_ref -> refuses, names how to supply one
    none = tools["get_pseudocode"]("handle_req")
    assert none["found"] is False and "evidence_ref" in none["error"]
    assert none["runs_in_atlas"] == ["run_m"]
    # (1) misspelled run -> not-in-atlas, lists the available runs (G3)
    bad_run = tools["get_pseudocode"]("handle_req", run_id="run_typo")
    assert "not in this atlas" in bad_run["error"] and "run_m" in bad_run["error"]
    # (3) function in a DIFFERENT run than the one asked -> names the owning run (Q1-a)
    wrong = tools["get_pseudocode"]("handle_req", run_id="run_m")  # handle_req IS in run_m -> found
    assert wrong["found"] is True and wrong["resolved_run"] == "run_m"
    # (4) a function in NO run -> "not in ANY run" (Q1-b), the miss is diagnosed not silent
    absent = tools["get_pseudocode"]("nope_fn", run_id="run_m")
    assert absent["found"] is False and "not in ANY run" in absent["cross_run_note"]


def test_fact_tool_missing_analysis_db_hard_errors(tmp_path: Path) -> None:
    # G4: a run whose analysis.db was never recorded (a pre-existing scan) hard-errors — never a
    # silent empty that reads as "no findings".
    atlas = _mk_multi_atlas(tmp_path)  # writes run_m -> tmp_path/analysis.db, which does NOT exist
    tools = mcp_app.make_tools(atlas)
    r = tools["get_pseudocode"]("c1", run_id="run_m")
    assert r["found"] is False and "not found" in r["error"]
    assert r["resolved_run"] == "run_m"  # still stamped with the run it refers to


def test_fact_tool_routes_by_evidence_ref(tmp_path: Path) -> None:
    # M4: an evidence_ref self-resolves the run (+ binary + function) — no run_id needed. run_source
    # reflects via_ref, and resolved_run is the ref's run.
    tools = _tools(tmp_path)
    r = tools["get_pseudocode"](evidence_ref="run_m#fn1@cmd")
    assert r["resolved_run"] == "run_m" and r["run_source"] == "via_ref"


def test_no_lineage_run_never_revived_by_ws_root_fallback(tmp_path: Path) -> None:
    # ★ honesty red-line: a run in the atlas but with NO lineage row (never trustworthily
    # analyzed) must NOT be revived by a residual old analysis.db in the workspaces root. It
    # short-circuits to re-scan BEFORE any db is opened — so a miss reads as UNKNOWN ("never
    # analyzed"), never NO ("analyzed and absent").
    atlas_p = tmp_path / "atlas.db"
    conn = open_atlas(atlas_p)
    pid = upsert_pattern(
        conn, source_class="external_input", sink_class="cmd", call_sequence_shape="s"
    )
    # 'miwifi' is instance-only -> resolved=False, analysis_db_path=None (a pre-existing scan)
    add_instance(
        conn,
        InstanceRow(
            pattern_id=pid,
            pseudocode_hash="h_m",
            sink_anchor="FUN_m",
            source_run_id="miwifi",
            evidence_ref="miwifi#fn1",
        ),
    )
    # 'rt' carries an instance for FUN_present -> it exists in ANOTHER run (the lethal-probe target)
    add_instance(
        conn,
        InstanceRow(
            pattern_id=pid,
            pseudocode_hash="h_r",
            sink_anchor="FUN_present",
            source_run_id="rt",
            evidence_ref="rt#fn1",
        ),
    )
    conn.close()
    # a residual OLD analysis.db sitting exactly where the ws_root fallback would find it
    ws_root = tmp_path / "workspaces"
    (ws_root / "miwifi").mkdir(parents=True)
    old = open_db(ws_root / "miwifi" / "analysis.db")
    old.execute(
        "INSERT INTO binaries (id, name, path, sha256) VALUES (1, 'mtd', 'sbin/mtd', ?)",
        ("z" * 64,),
    )
    old.commit()
    old.close()
    tools = mcp_app.make_tools(atlas_p, workspaces_root=ws_root)

    # any function on the no-lineage run -> no-DB re-scan, NOT a search-miss; residual db not opened
    r = tools["get_pseudocode"]("main", run_id="miwifi")
    assert r["found"] is False
    assert "no recorded analysis.db" in r["error"] and "re-scan" in r["error"]
    assert "cross_run_note" not in r  # never ran a function search on the residual db
    assert r["run_lineage"]["resolved"] is False

    # ★ lethal probe: a function that exists in ANOTHER run STILL yields no-DB on the no-lineage run
    # (never "wrong run / not in ANY run") — this is what separates UNKNOWN from NO.
    lethal = tools["get_pseudocode"]("FUN_present", run_id="miwifi")
    assert "no recorded analysis.db" in lethal["error"]
    assert "cross_run_note" not in lethal and "found_in_runs" not in lethal


def test_ws_root_fallback_still_recovers_a_moved_lineage_run(tmp_path: Path) -> None:
    # The ws_root fallback keeps its LEGITIMATE purpose: a run WITH a lineage row whose recorded
    # path file has moved is recovered from <ws_root>/<run>/analysis.db (a real migration). Only a
    # NO-lineage run is refused — that asymmetry IS the honesty fix.
    atlas_p = tmp_path / "atlas.db"
    conn = open_atlas(atlas_p)
    begin_run(
        conn, "rt", analysis_db_path=str(tmp_path / "gone" / "analysis.db")
    )  # path now absent
    finish_run(conn, "rt", binaries=1, functions=1)
    conn.close()
    ws_root = tmp_path / "workspaces"
    (ws_root / "rt").mkdir(parents=True)
    db = open_db(ws_root / "rt" / "analysis.db")
    db.execute(
        "INSERT INTO binaries (id, name, path, sha256) VALUES (1, 'webd', 'sbin/webd', ?)",
        ("a" * 64,),
    )
    db.execute(
        "INSERT INTO functions (id, binary_id, name, address, pseudocode, callees) "
        "VALUES (1, 1, 'handle', '0x10', 'void handle(){}', ?)",
        (json.dumps([]),),
    )
    db.commit()
    db.close()
    tools = mcp_app.make_tools(atlas_p, workspaces_root=ws_root)
    r = tools["get_pseudocode"]("handle", run_id="rt")
    assert r["found"] is True and r["resolved_run"] == "rt"


def test_cross_firmware_and_aggregation_tools(tmp_path: Path) -> None:
    # B3: the atlas-view aggregations are reachable as tools and carry the derived note.
    tools = _tools(tmp_path)
    xf = tools["cross_firmware_patterns"]()
    assert "DERIVED" in xf["note"]
    (pat,) = xf["patterns"]
    assert "device_spread" in pat and "pattern_breadth" in pat
    for name in ("pattern_density", "pattern_twins", "dormant_candidates"):
        r = tools[name]()
        assert "note" in r and "count" in r  # may be empty, but always anchored + noted


def test_aggregation_paging_never_silently_drops_the_tail(tmp_path: Path) -> None:
    # Finding 7: a limited aggregation must expose the capped tail as REACHABLE (offset/truncated/
    # next_offset), never count rows it silently omits.
    tools = _tools(tmp_path)
    full = tools["cross_firmware_patterns"](limit=1)
    assert full["count"] == 1 and full["returned"] == 1
    assert full["truncated"] is False and full["next_offset"] is None
    # a cap below the count is honestly truncated with a reachable next_offset
    capped = tools["cross_firmware_patterns"](limit=0)
    assert capped["count"] == 1 and capped["returned"] == 0
    assert capped["truncated"] is True and capped["next_offset"] == 0
    # paging past the end is empty but still states the true total
    past = tools["cross_firmware_patterns"](limit=5, offset=1)
    assert past["returned"] == 0 and past["count"] == 1 and past["truncated"] is False


# ── ★ milestone: recall -> fetch facts -> follow the chain (AI then judges) ─────────


def test_milestone_recall_to_facts_chain(tmp_path: Path) -> None:
    tools = _tools(tmp_path)
    # 1. recall
    cand = tools["list_candidates"]()["candidates"][0]
    assert cand["function"] == "handle_req"
    # 2. fetch the candidate function's facts (by its address anchor) — the ref self-routes the run
    pc = tools["get_pseudocode"](evidence_ref=cand["evidence_ref"])
    assert pc["found"] and "do_fwd" in pc["pseudocode"]
    assert pc["resolved_run"] == "run_m"  # the ref carried the run — no retyping
    # 3. follow callees to the wrapper (run_id explicit this time)
    callees = tools["get_callees"]("handle_req", run_id="run_m")
    assert {c["name"] for c in callees["callees"]} == {"do_fwd"}
    # 4. fetch the wrapper's facts (the one-hop sink lives here)
    wrapper = tools["get_pseudocode"]("do_fwd", run_id="run_m")
    assert wrapper["found"] and "system(a)" in wrapper["pseudocode"]
    # the AI now has the full chain to judge — the tool draws no conclusion for it


def test_disassembly_unavailable_is_honest(tmp_path: Path) -> None:
    tools = _tools(tmp_path)
    r = tools["get_disassembly"]("handle_req", run_id="run_m")
    assert r["available"] is False and r["anchor"]["function"] == "handle_req"


def test_legal_notice_present(tmp_path: Path) -> None:
    tools = _tools(tmp_path)
    assert "defensive" in tools["legal_notice"]()["notice"].lower()


def test_server_instructions_are_workflow_not_just_legalese(tmp_path: Path) -> None:
    # B4: the standing instructions are the agent workflow guide; the legal notice stays reachable
    # via the legal_notice tool.
    atlas = _mk_atlas(tmp_path)
    server = mcp_app.build_server(atlas)
    instr = server.instructions or ""
    assert "evidence_ref" in instr and "cross_firmware_patterns" in instr
    assert "RECALL" in instr  # the loop, not just the banner
    assert "run_id" in instr and "list_runs" in instr  # the run-aware routing guidance
    tools = mcp_app.make_tools(atlas)
    assert "defensive" in tools["legal_notice"]()["notice"].lower()


# ── 缺口③: source_kind (fine-grained controllability) surfaced on explain + list ───────


def test_explain_and_list_surface_source_kind(tmp_path: Path) -> None:
    # The source_kind the evidence layer stored in flow_evidence is surfaced on BOTH the
    # explain_candidate and list_candidates MCP surfaces (a free, controllable string here),
    # alongside the coarse source_class it refines.
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    pid = upsert_pattern(
        conn,
        source_class="external_input",
        sink_class="cmd",
        call_sequence_shape="source->cmd",
        structural_fingerprint="fp_demo",
        fingerprint_algo_version="callseq-v1",
    )
    add_instance(
        conn,
        InstanceRow(
            pattern_id=pid,
            pseudocode_hash="h1",
            source_anchor="handle_req",
            sink_anchor="do_fwd",
            source_run_id="run_m",
            reachability_status="unknown",
            blocking_mechanism=None,
            provenance_level="L0",
            evidence_ref="run_m#fn1@cmd",
            scope_origin="intra",
            origin="custom",
            binary_path="usr/sbin/webd",
            flow_evidence=json.dumps(
                {
                    "source_kind": "free_string",
                    "entry_reach": {
                        "status": "found",
                        "sites": [{"kind": "web_endpoint", "method": "POST", "endpoint": "/x.cgi"}],
                    },
                }
            ),
        ),
    )
    conn.close()
    tools = mcp_app.make_tools(atlas)
    ex = tools["explain_candidate"]("run_m#fn1@cmd")
    assert ex["found"] is True
    # ★ TOP-LEVEL visibility (the shipped bug): an agent reads the explain top level, so BOTH the
    # fine source_kind and the coarse source_class must be directly there — not only in candidate.
    assert ex["source_kind"] == "free_string"
    assert ex["source_class"] == "external_input"
    # still also carried on the nested candidate (unchanged)
    assert ex["candidate"]["source_kind"] == "free_string"
    (cand,) = tools["list_candidates"]()["candidates"]
    # the compact row folds source_kind into the resolved controllability label (free_string with no
    # provenance verdict -> proven:free); the RAW source_kind stays on explain, not the list row.
    assert cand["controllability"] == "proven:free"
    assert "source_kind" not in cand


def test_explain_top_level_exposes_source_kind_and_class(tmp_path: Path) -> None:
    # ★ regression guard for the shipped bug: source_kind was reachable ONLY via the nested
    # candidate object, invisible at the explain TOP LEVEL an agent actually reads. Pin that the
    # top-level dict itself carries both keys (this is the path A-group tests missed).
    tools = _tools(tmp_path)
    ex = tools["explain_candidate"]("run_m#fn1@cmd")
    assert "source_kind" in ex  # top-level key, NOT ex["candidate"]["source_kind"]
    assert "source_class" in ex  # coarse class also top-level — both agent-visible


def test_source_kind_defaults_unknown_and_no_regression(tmp_path: Path) -> None:
    # A candidate whose flow_evidence carries NO source_kind surfaces "unknown" (never fabricated),
    # and every pre-existing field is unchanged — source_kind was ADDED, nothing renamed/removed.
    tools = _tools(tmp_path)  # _mk_atlas evidence has entry_reach but no source_kind
    ex = tools["explain_candidate"]("run_m#fn1@cmd")
    assert ex["source_kind"] == "unknown"  # top-level default when evidence carries none
    assert ex["source_class"] == "external_input"  # coarse class still top-level, not regressed
    assert ex["candidate"]["source_kind"] == "unknown"  # nested value agrees
    assert ex["candidate"]["entry_reach"] == "entry:web"
    assert "score" not in ex["candidate"]  # collapsed score gone; dimension layers replace it
    assert {d["name"] for d in ex["candidate"]["dimensions"]}  # non-empty layer set
    cand = tools["list_candidates"]()["candidates"][0]
    # compact row: source_kind unknown + no verdict -> controllability unknown:unknown (folded, not
    # a raw row field); the raw source_kind now lives on explain only.
    assert cand["controllability"] == "unknown:unknown"
    assert "source_kind" not in cand
    for key in (
        "evidence_ref",
        "controllability",
        "dimensions",
        "sink_class",
        "binary",
        "function",
    ):
        assert key in cand  # the compact spine keys are present
    assert "score" not in cand


# ── 缺口①: pseudocode-text reverse lookup (which functions mention a string) ────────────


def test_get_functions_referencing_string_tool(tmp_path: Path) -> None:
    # Reachable as a tool, matches by pseudocode text (handle_req's body calls do_fwd), and states
    # its honest bound (a TEXT match, not a resolved symbol xref). A missing binary yields no hits.
    tools = _tools(tmp_path)
    r = tools["get_functions_referencing_string"]("do_fwd", run_id="run_m")
    assert r["found"] is True
    assert "handle_req" in {f["function"] for f in r["functions"]}
    assert r["match_kind"] == "pseudocode_text_substring"
    assert "text" in r["note"].lower()
    empty = tools["get_functions_referencing_string"]("do_fwd", "libc.so", run_id="run_m")
    assert empty["functions"] == []


# ── compact-row serializer contract (compact_row_contract.md C1–C8) ────────────────────


def _mk_candidate(dimensions: list[Dimension], **over: object) -> TriageCandidate:
    """A synthetic TriageCandidate for the compact-row serializer contract tests (no DB)."""
    base: dict[str, object] = dict(
        review_status="to-verify",
        reachability_status="unknown",
        function="FUN_1",
        sink_anchor="system",
        source_class="external_input",
        sink_class="cmd",
        blocking_mechanism=None,
        origin="custom",
        source_run_id="run_m",
        evidence_ref="run_m#fn1@cmd",
        binary_path="usr/sbin/webd",
        structural_fingerprint="fp_1",
        nvram_source_key=None,
        dimensions=tuple(dimensions),
    )
    base.update(over)
    return TriageCandidate(**base)  # type: ignore[arg-type]


def test_compact_row_carries_established_dims_and_omits_unknown() -> None:
    # ★ C8-1 general carry: a non-spine dimension with an established state joins the row; an
    # unknown one is omitted (the baseline). controllability is spine — always present, never in the
    # carried dict.
    dims = [
        Dimension("controllability", "unknown", "unknown", "src"),
        Dimension("reachability", "proven", "entry:web", "src"),
        Dimension("filtering", "unknown", "unknown", "src"),
    ]
    row = mcp_app._candidate_row(_mk_candidate(dims), rank=0)
    assert row["dimensions"] == {"reachability": "proven:entry:web"}
    assert "filtering" not in row["dimensions"]  # unknown state omitted
    assert "controllability" not in row["dimensions"]  # promoted to spine, not double-emitted
    assert row["controllability"] == "unknown:unknown"  # spine: present even when unknown


def test_compact_row_carries_a_new_axis_without_a_whitelist() -> None:
    # ★ C8-4 marker-aware (anti-'hidden marker', the recurring root cause): a BRAND-NEW axis that
    # is a Dimension with an established state MUST reach the compact row automatically — the carry
    # loop hardcodes NO dimension whitelist, so a future source=param axis is picked up for free.
    dims = [
        Dimension("controllability", "unknown", "unknown", "src"),
        Dimension("source", "proven", "param", "pattern.source_class=external_input"),
    ]
    row = mcp_app._candidate_row(_mk_candidate(dims), rank=3)
    assert row["dimensions"]["source"] == "proven:param"


def test_compact_row_baseline_is_unknown_state_not_a_modal_value() -> None:
    # ★ C8-3 baseline semantics: carry keys on the UNKNOWN state, never on a per-firmware modal
    # value. A dimension whose VALUE looks like a common reading but whose STATE is unknown is
    # omitted; only an established state is carried.
    dims = [
        Dimension("controllability", "unknown", "unknown", "src"),
        Dimension("reachability", "unknown", "entry:web", "src"),  # value looks 'found', state ?
        Dimension("sink_impact", "proven", "cmd", "src"),
    ]
    row = mcp_app._candidate_row(_mk_candidate(dims), rank=0)
    assert (
        "reachability" not in row["dimensions"]
    )  # unknown state omitted despite a real-looking value
    assert row["dimensions"]["sink_impact"] == "proven:cmd"


def test_compact_row_keeps_excluded_visible() -> None:
    # ★ C8-2 demotion iron law: a proven-safe (excluded) dimension is DEMOTED but stays VISIBLE —
    # hiding it would read as 'not judged' (a re-review waste) or 'still dangerous'.
    dims = [
        Dimension("controllability", "unknown", "unknown", "src"),
        Dimension("filtering", "excluded", "sanitized", "src"),
    ]
    row = mcp_app._candidate_row(_mk_candidate(dims), rank=0)
    assert row["dimensions"]["filtering"] == "excluded:sanitized"


def test_compact_row_axis_prefixes_do_not_mix() -> None:
    # ★ C8-5 axis prefixes: controllability (spine) and reachability (carried) both established —
    # each label reads its own axis, none collapsed into the other.
    dims = [
        Dimension("controllability", "proven", "controllable", "src"),
        Dimension("reachability", "proven", "entry:script", "src"),
    ]
    row = mcp_app._candidate_row(_mk_candidate(dims), rank=0)
    assert row["controllability"] == "proven:controllable"
    assert row["dimensions"]["reachability"] == "proven:entry:script"


def test_compact_list_envelope_carries_legend(tmp_path: Path) -> None:
    # ★ C8-6: the compact list envelope states once that an omitted dimension is unknown, NOT proven
    # safe (unknown ≠ safe), and points at explain for the full note.
    tools = _tools(tmp_path)
    out = tools["list_candidates"]()
    legend = out["legend"].lower()
    assert "unknown" in legend and "not proven safe" in legend
    assert "explain_candidate" in out["legend"]


def test_compact_row_reachability_seam_real_dimension(tmp_path: Path) -> None:
    # ★ cross-step seam (the contract anchor): reachability became a Dimension in step 2, but the
    # compact serializer did not exist then. Verify with the REAL dimension (not a synthetic one):
    # an entry:web candidate carries reachability=proven:entry:web; a no-site candidate OMITS it.
    d_web = tmp_path / "web"
    d_web.mkdir()
    d_no = tmp_path / "nosite"
    d_no.mkdir()
    _mk_analysis(d_web)
    web = mcp_app.make_tools(_mk_atlas(d_web))["list_candidates"]()
    (web_cand,) = web["candidates"]
    assert web_cand["dimensions"]["reachability"] == "proven:entry:web"
    _mk_analysis(d_no)
    nosite = mcp_app.make_tools(_mk_multi_atlas(d_no))["list_candidates"]()
    assert nosite["candidates"]  # the corpus is non-empty
    assert all("reachability" not in c["dimensions"] for c in nosite["candidates"])


def test_note_moves_from_list_to_explain(tmp_path: Path) -> None:
    # ★ M2: the per-dimension note is DROPPED from the compact list row (each dim is one bare
    # state:value label) and preserved IN FULL on explain_candidate — moved, never deleted.
    tools = _tools(tmp_path)
    (cand,) = tools["list_candidates"]()["candidates"]
    assert all(
        isinstance(v, str) for v in cand["dimensions"].values()
    )  # bare labels, no note dicts
    assert "note" not in cand  # the row carries no per-candidate note dump
    ex = tools["explain_candidate"]("run_m#fn1@cmd")
    dims = [d for d in ex["candidate"]["dimensions"]]
    assert any(d["note"] for d in dims)  # explain keeps the full per-dimension note


def test_mcp_get_strings_accepts_offset_and_returns_paging(tmp_path: Path) -> None:
    # ★ M6: the MCP get_strings wrapper threads ``offset`` into the lossless byte-paging envelope.
    tools = _tools(tmp_path)
    r = tools["get_strings"](binary="webd", offset=0, run_id="run_m")
    assert "paging" in r and r["paging"]["offset"] == 0
    assert r["paging"]["next_offset"] is None  # the synthetic webd fits one page


def test_compact_row_carries_param_source_when_controllability_unknown(tmp_path: Path) -> None:
    # ★ step-4 param contract seam (C1/C6, anti-'hidden marker'): a controllability=unknown
    # external_input candidate STILL surfaces source=proven:param on the compact row — the
    # axis-agnostic carry from step 3 picks the new axis up with no serializer edit.
    tools = _tools(tmp_path)  # _mk_atlas uses source_class=external_input
    (cand,) = tools["list_candidates"]()["candidates"]
    assert cand["controllability"] == "unknown:unknown"
    assert cand["dimensions"]["source"] == "proven:param"


def test_explain_carries_param_source_with_unproven_note(tmp_path: Path) -> None:
    # ★ step-4 guardrail 2: the source dimension + its UNPROVEN note ride on explain too (not only
    # the compact list), so a drill-down never loses the "controllability UNPROVEN" caveat.
    tools = _tools(tmp_path)
    ex = tools["explain_candidate"]("run_m#fn1@cmd")
    src = next(d for d in ex["candidate"]["dimensions"] if d["name"] == "source")
    assert src["value"] == "param" and src["state"] == "proven"
    assert "UNPROVEN" in src["note"]


def test_mcp_get_strings_function_scope_flag(tmp_path: Path) -> None:
    # ★ 3.1 on the MCP face (the surface the agent uses): passing `function` yields
    # func_scope_applied:false + the honest "does NOT narrow" note — the echoed function is never a
    # scoping guarantee.
    tools = _tools(tmp_path)
    r = tools["get_strings"](binary="webd", function="handle_req", run_id="run_m")
    assert r["func_scope_applied"] is False
    assert "does NOT narrow" in r["note"]


# ── the two exploit-barrier buckets on the MCP face (mark_exploited + the read tools) ──


def test_mark_exploited_rejects_blank_proof(tmp_path: Path) -> None:
    # ★ verification 2: the admission bar is EXPLOITED. A blank / whitespace proof (or pattern) is
    # rejected at the tool layer — written:False, nothing lands in the ledger.
    tools = _tools(tmp_path)
    for bad in ("", "   ", "\t"):
        r = tools["mark_exploited"](
            evidence_ref="run_m#fn1@cmd", pattern="cmd inj", exploit_note=bad
        )
        assert r["written"] is False and "error" in r
    r = tools["mark_exploited"](
        evidence_ref="run_m#fn1@cmd", pattern="   ", exploit_note="triggered"
    )
    assert r["written"] is False
    assert tools["list_moat"]()["holes"] == 0  # nothing admitted


def test_mark_exploited_resolved_ref_echoes_no_warning(tmp_path: Path) -> None:
    # ★ verification 5 (state 1/3): a ref that anchors a real candidate in a scanned run → written,
    # a `resolved` label, and NO warning (the write is not blind).
    tools = _tools(tmp_path)
    r = tools["mark_exploited"](
        evidence_ref="run_m#fn1@cmd", pattern="cmd inj", exploit_note="POST /x.cgi -> system()"
    )
    assert r["written"] is True and "id" in r
    assert "handle_req" in r["resolved"] and "run_m" in r["resolved"]
    assert "warning" not in r


def test_mark_exploited_ref_not_in_atlas_blind_write_warns(tmp_path: Path) -> None:
    # ★ verification 5 (state 2/3): a ref that anchors NOTHING in the atlas → STILL written
    # (recording before the scan is allowed), but the result carries a BLIND WRITE warning.
    tools = _tools(tmp_path)
    r = tools["mark_exploited"](
        evidence_ref="ghost#nope", pattern="cmd inj", exploit_note="proved by hand"
    )
    assert r["written"] is True
    assert "warning" in r and "BLIND WRITE" in r["warning"]
    assert "resolved" not in r  # nothing to resolve to


def test_mark_exploited_no_lineage_run_blind_write_warns(tmp_path: Path) -> None:
    # ★ verification 5 (state 3/3): the ref DOES anchor a candidate, but its run has no recorded
    # analysis.db (a pre-existing / un-scanned run) → written, with a warning that inherits the
    # no-lineage honesty (a run we cannot re-open must not read as a clean write).
    atlas = _mk_atlas(tmp_path)
    conn = open_atlas(atlas)
    pid = upsert_pattern(
        conn,
        source_class="external_input",
        sink_class="cmd",
        call_sequence_shape="source->cmd",
        structural_fingerprint="fp_ghost",
        fingerprint_algo_version="callseq-v1",
    )
    add_instance(
        conn,
        InstanceRow(
            pattern_id=pid,
            pseudocode_hash="hg",
            source_anchor="ghost_fn",
            sink_anchor="do_x",
            source_run_id="ghost_run",  # an instance whose run row is never begin_run'd
            reachability_status="unknown",
            blocking_mechanism=None,
            provenance_level="L0",
            evidence_ref="ghost_run#fn@cmd",
            scope_origin="intra",
            origin="custom",
            binary_path="usr/sbin/ghostd",
        ),
    )
    conn.close()
    tools = mcp_app.make_tools(atlas)
    r = tools["mark_exploited"](
        evidence_ref="ghost_run#fn@cmd", pattern="cmd inj", exploit_note="proved"
    )
    assert r["written"] is True
    assert "warning" in r and "no recorded" in r["warning"]


def test_list_moat_default_withholds_note_reveal_includes_it(tmp_path: Path) -> None:
    # ★ verification 4: the default read never sprays exploit_note; reveal=True is the one channel.
    tools = _tools(tmp_path)
    tools["mark_exploited"](
        evidence_ref="run_m#fn1@cmd", pattern="cmd", exploit_note="POST x=;reboot; -> reboot"
    )
    default = tools["list_moat"]()
    (entry,) = default["exploits"]
    assert "exploit_note" not in entry and entry["has_exploit_evidence"] is True
    revealed = tools["list_moat"](reveal=True)
    assert revealed["exploits"][0]["exploit_note"] == "POST x=;reboot; -> reboot"


def test_list_moat_depth_is_distinct_ref_via_tool(tmp_path: Path) -> None:
    # ★ verification 3: two rows on the SAME ref → holes stays 1 (COUNT DISTINCT), records is 2.
    tools = _tools(tmp_path)
    tools["mark_exploited"](evidence_ref="run_m#fn1@cmd", pattern="cmd", exploit_note="via web")
    tools["mark_exploited"](evidence_ref="run_m#fn1@cmd", pattern="cmd", exploit_note="via cli too")
    m = tools["list_moat"]()
    assert m["holes"] == 1 and m["records"] == 2


def test_import_cve_patterns_idempotent_via_tool(tmp_path: Path) -> None:
    # ★ verification 8: public import fills the front-stage table and re-running never doubles;
    # public volume never enters barrier depth.
    tools = _tools(tmp_path)
    payload = [
        {"pattern": "nvram->system", "cve_id": "CVE-1", "source": "lan_ip", "sink": "system"},
        {"pattern": "post->popen", "cve_id": "CVE-2", "sink": "popen"},
    ]
    first = tools["import_cve_patterns"](payload)
    assert first["inserted"] == 2 and first["skipped"] == 0
    again = tools["import_cve_patterns"](payload)
    assert again["inserted"] == 0 and again["skipped"] == 2  # idempotent
    assert tools["list_cve_patterns"]()["count"] == 2
    assert tools["list_cve_patterns"](sink="pop")["count"] == 1  # substring filter
    assert tools["list_moat"]()["holes"] == 0  # public volume is off the barrier


# ── public-surface neutrality: the server is a published artifact, stricter discipline ──


def test_public_server_files_are_neutral() -> None:
    # The MCP server + its read layer + CLI are published ("the public-facing surface"); they must
    # carry no strategy vocabulary, no private-doc/section citation, and the defensive legal notice
    # must be wired into the server instructions.
    src = Path(__file__).resolve().parents[2] / "src" / "treasure_map"
    banned = re.compile(r"\b(moat|shield|fix_quality|incomplete_patch)\b|盾|§|PRD\s", re.IGNORECASE)
    privdoc = re.compile(r"private (design )?notes|treasure-map-notes", re.IGNORECASE)
    for rel in ("lib/facts.py", "mcp_app.py", "cli/mcp_cli.py"):
        text = (src / rel).read_text()
        assert not banned.search(text), f"strategy/section vocab in {rel}"
        assert not privdoc.search(text), f"private-doc reference in {rel}"
    # the defensive notice is the server's standing instruction
    assert "LEGAL_NOTICE" in (src / "mcp_app.py").read_text()
