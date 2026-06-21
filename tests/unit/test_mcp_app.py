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
from treasure_map.lib.atlas.models import InstanceRow
from treasure_map.lib.atlas.writer import add_instance, upsert_pattern
from treasure_map.lib.storage.connection import open_db

_EXPECTED_TOOLS = {
    "list_candidates",
    "explain_candidate",
    "get_pseudocode",
    "get_callees",
    "get_xrefs",
    "get_strings",
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


# ── list_candidates: anchored, entry-reach carried, derived-not-verdict note ────────


def test_list_candidates_carries_anchor_entry_reach_and_note(tmp_path: Path) -> None:
    tools = _tools(tmp_path)
    out = tools["list_candidates"]()
    assert "DERIVED" in out["note"] and "NOT a verdict" in out["note"]
    (cand,) = out["candidates"]
    assert cand["evidence_ref"] == "run_m#fn1@cmd"  # anchor present
    assert cand["entry_reach"] == "found"  # entry-reach surfaced as a derived signal
    assert cand["score"] is not None


def test_list_candidates_sink_class_filter(tmp_path: Path) -> None:
    tools = _tools(tmp_path)
    assert tools["list_candidates"](sink_class="copy")["count"] == 0
    assert tools["list_candidates"](sink_class="cmd")["count"] == 1


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
