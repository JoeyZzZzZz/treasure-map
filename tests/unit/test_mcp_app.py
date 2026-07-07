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
            flow_evidence=json.dumps({"entry_reach": {"status": "found", "sites": []}}),
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
    (cand,) = out["candidates"]
    assert cand["evidence_ref"] == "run_m#fn1@cmd"  # anchor present
    assert cand["entry_reach"] == "found"  # entry-reach surfaced as a derived signal
    assert cand["score"] is not None


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
                {"source_kind": "free_string", "entry_reach": {"status": "found", "sites": []}}
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
    assert cand["source_kind"] == "free_string"


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
    assert ex["candidate"]["entry_reach"] == "found"
    assert ex["candidate"]["score"] is not None
    cand = tools["list_candidates"]()["candidates"][0]
    assert cand["source_kind"] == "unknown"
    for key in ("evidence_ref", "source_class", "score", "entry_reach", "sink_class"):
        assert key in cand  # no prior key dropped


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
