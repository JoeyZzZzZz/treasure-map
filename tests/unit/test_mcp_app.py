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
from treasure_map.lib.atlas.writer import add_instance, add_nvram_flow_rows, upsert_pattern
from treasure_map.lib.query.triage import Dimension, TriageCandidate
from treasure_map.lib.storage.connection import open_db

_EXPECTED_TOOLS = {
    "list_candidates",
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
    conn.close()
    return atlas


def _tools(tmp_path: Path):
    return mcp_app.make_tools(_mk_analysis(tmp_path), _mk_atlas(tmp_path))


# ── discoverability ──────────────────────────────────────────────────────────────────


def test_server_registers_all_tools(tmp_path: Path) -> None:
    server = mcp_app.build_server(_mk_analysis(tmp_path), _mk_atlas(tmp_path))
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert names == _EXPECTED_TOOLS


# ── CLI / MCP / lib parity: one shared query, identical result ──────────────────────


def test_cli_mcp_lib_parity_pseudocode(tmp_path: Path) -> None:
    analysis = _mk_analysis(tmp_path)
    tools = mcp_app.make_tools(analysis, _mk_atlas(tmp_path))
    # lib directly
    conn = facts.open_analysis_ro(analysis)
    lib_result = facts.get_pseudocode(conn, func="handle_req")
    conn.close()
    # MCP tool
    mcp_result = tools["get_pseudocode"]("handle_req")
    # CLI
    cli = CliRunner().invoke(
        fact_group, ["pseudocode", "handle_req", "--analysis-db", str(analysis)]
    )
    assert cli.exit_code == 0, cli.output
    cli_result = json.loads(cli.output)
    assert lib_result == mcp_result == cli_result


# ── contract 1: no anchor, no output ────────────────────────────────────────────────


def test_no_anchor_no_output(tmp_path: Path) -> None:
    tools = _tools(tmp_path)
    assert tools["get_pseudocode"]("does_not_exist")["found"] is False
    assert tools["explain_candidate"]("run_m#nope")["found"] is False


# ── contract 2: outputs carry no payload / trigger bytes / PoC ──────────────────────


def test_outputs_carry_no_payload(tmp_path: Path) -> None:
    tools = _tools(tmp_path)
    blobs = [
        tools["list_candidates"](),
        tools["explain_candidate"]("run_m#fn1@cmd"),
        tools["get_pseudocode"]("handle_req"),
        tools["get_callees"]("handle_req"),
        tools["get_script_callsites"]("webd"),
        tools["get_disassembly"]("handle_req"),
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
    tools = mcp_app.make_tools(_mk_analysis(tmp_path), atlas)

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
    conn.close()
    return atlas


def test_list_candidates_filter_floats_corpus_invariant(tmp_path: Path) -> None:
    # ★★ 步骤 2.5 M5-1b (gap #1 — the agent's ACTUAL surface): on MCP a --filter FLOATS, never
    # reduces the corpus. source=nvram (the OAuth-hiding regression) keeps all 5; sink_impact=cmd
    # returns the corpus (5) floated, NOT the 2 matches.
    tools = mcp_app.make_tools(_mk_analysis(tmp_path), _mk_multi_atlas(tmp_path), run_id="run_m")
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
    tools = mcp_app.make_tools(_mk_analysis(tmp_path), _mk_multi_atlas(tmp_path), run_id="run_m")
    swept = tools["list_candidates"](only="sink_class=cmd")
    assert swept["corpus"] == 5 and swept["total"] == 2  # corpus whole, view pruned to the sweep
    refused = tools["list_candidates"](only="controllability=free")
    assert "error" in refused and "refused" in refused["error"]
    assert refused["corpus"] == 5  # the refusal still reports the whole corpus


def test_list_candidates_carries_fingerprint_and_incomplete_field(tmp_path: Path) -> None:
    # ★ Work item 6 + red-line honesty: each candidate carries its structural_fingerprint (pivot
    # from cross_firmware_patterns), and the result carries an incomplete_binaries flag.
    tools = _tools(tmp_path)
    out = tools["list_candidates"]()
    assert out["incomplete_binaries"] == []  # the synthetic webd has functions
    # partial-completeness honesty: webd's functions all have pseudocode, so none are flagged
    assert out["partially_incomplete_binaries"] == []
    (cand,) = out["candidates"]
    assert cand["structural_fingerprint"] == "fp_demo"
    # the fingerprint filter round-trips (cross_firmware_patterns -> list_candidates(fingerprint=))
    assert tools["list_candidates"](fingerprint="fp_demo")["total"] == 1
    assert tools["list_candidates"](fingerprint="no_such_fp")["total"] == 0


def test_cross_firmware_views_carry_incomplete_flag(tmp_path: Path) -> None:
    tools = _tools(tmp_path)
    for view in ("cross_firmware_patterns", "pattern_density"):
        out = tools[view]()
        assert "incomplete_binaries" in out
        assert "partially_incomplete_binaries" in out


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


def test_list_candidates_run_isolation(tmp_path: Path) -> None:
    # B1: a server bound to run_m only surfaces run_m candidates by default; an explicit run_id
    # for another run isolates to it (here empty), and is_current_run flags the bound run.
    analysis, atlas = _mk_analysis(tmp_path), _mk_atlas(tmp_path)
    tools = mcp_app.make_tools(analysis, atlas, run_id="run_m")
    out = tools["list_candidates"]()
    assert out["current_run_id"] == "run_m"
    assert out["isolated_to_run"] == "run_m"
    assert all(c["is_current_run"] for c in out["candidates"])
    # a bound run that has no candidates falls back to all runs, annotated (not an empty list)
    tools_stale = mcp_app.make_tools(analysis, atlas, run_id="does_not_exist")
    fb = tools_stale["list_candidates"]()
    assert fb["isolated_to_run"] is None and fb["total"] == 1
    assert fb["runs"] is not None  # firmware split shown when not isolated


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
    # 2. fetch the candidate function's facts (by its address anchor)
    pc = tools["get_pseudocode"]("0x6b90")
    assert pc["found"] and "do_fwd" in pc["pseudocode"]
    # 3. follow callees to the wrapper
    callees = tools["get_callees"]("handle_req")
    assert {c["name"] for c in callees["callees"]} == {"do_fwd"}
    # 4. fetch the wrapper's facts (the one-hop sink lives here)
    wrapper = tools["get_pseudocode"]("do_fwd")
    assert wrapper["found"] and "system(a)" in wrapper["pseudocode"]
    # the AI now has the full chain to judge — the tool draws no conclusion for it


def test_disassembly_unavailable_is_honest(tmp_path: Path) -> None:
    tools = _tools(tmp_path)
    r = tools["get_disassembly"]("handle_req")
    assert r["available"] is False and r["anchor"]["function"] == "handle_req"


def test_legal_notice_present(tmp_path: Path) -> None:
    tools = _tools(tmp_path)
    assert "defensive" in tools["legal_notice"]()["notice"].lower()


def test_server_instructions_are_workflow_not_just_legalese(tmp_path: Path) -> None:
    # B4: the standing instructions are the agent workflow guide; the legal notice stays reachable
    # via the legal_notice tool.
    analysis, atlas = _mk_analysis(tmp_path), _mk_atlas(tmp_path)
    server = mcp_app.build_server(analysis, atlas)
    instr = server.instructions or ""
    assert "evidence_ref" in instr and "cross_firmware_patterns" in instr
    assert "RECALL" in instr  # the loop, not just the banner
    tools = mcp_app.make_tools(analysis, atlas)
    assert "defensive" in tools["legal_notice"]()["notice"].lower()


# ── 缺口③: source_kind (fine-grained controllability) surfaced on explain + list ───────


def test_explain_and_list_surface_source_kind(tmp_path: Path) -> None:
    # The source_kind the evidence layer stored in flow_evidence is surfaced on BOTH the
    # explain_candidate and list_candidates MCP surfaces (a free, controllable string here),
    # alongside the coarse source_class it refines.
    analysis = _mk_analysis(tmp_path)
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
    tools = mcp_app.make_tools(analysis, atlas)
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
    r = tools["get_functions_referencing_string"]("do_fwd")
    assert r["found"] is True
    assert "handle_req" in {f["function"] for f in r["functions"]}
    assert r["match_kind"] == "pseudocode_text_substring"
    assert "text" in r["note"].lower()
    assert tools["get_functions_referencing_string"]("do_fwd", "libc.so")["functions"] == []


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
    web = mcp_app.make_tools(_mk_analysis(d_web), _mk_atlas(d_web))["list_candidates"]()
    (web_cand,) = web["candidates"]
    assert web_cand["dimensions"]["reachability"] == "proven:entry:web"
    nosite = mcp_app.make_tools(_mk_analysis(d_no), _mk_multi_atlas(d_no), run_id="run_m")[
        "list_candidates"
    ]()
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
    r = tools["get_strings"](binary="webd", offset=0)
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
    r = tools["get_strings"](binary="webd", function="handle_req")
    assert r["func_scope_applied"] is False
    assert "does NOT narrow" in r["note"]


# ── public-surface neutrality: the server is a published artifact, stricter discipline ──


def test_public_server_files_are_neutral() -> None:
    # The MCP server + its read layer + CLI are published ("the public spear"); they must carry no
    # strategy vocabulary, no private-doc/section citation, and the defensive legal notice must be
    # wired into the server instructions.
    src = Path(__file__).resolve().parents[2] / "src" / "treasure_map"
    banned = re.compile(r"\b(moat|shield|fix_quality|incomplete_patch)\b|盾|§|PRD\s", re.IGNORECASE)
    privdoc = re.compile(r"private (design )?notes|treasure-map-notes", re.IGNORECASE)
    for rel in ("lib/facts.py", "mcp_app.py", "cli/mcp_cli.py"):
        text = (src / rel).read_text()
        assert not banned.search(text), f"strategy/section vocab in {rel}"
        assert not privdoc.search(text), f"private-doc reference in {rel}"
    # the defensive notice is the server's standing instruction
    assert "LEGAL_NOTICE" in (src / "mcp_app.py").read_text()
