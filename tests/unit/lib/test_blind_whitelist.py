# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The blind-read whitelist (read_basis.BLIND_SAFE_TOOLS) proven from the answers, not the names.

A shadow judgement is blind only when its session made no call whose answer depends on the
verdicts recorded. Each whitelisted tool is called (through the real server, its log on) in two
worlds that hold the same facts and judgements on the same subjects with DIFFERENT verdicts — diff
verdicts rotated, a scan verdict excluded vs suspicious — and its answer must be the same, byte
for byte, once the server block and the world's own path are taken out. Whether something was
judged at all may show (a judged-or-not count, as get_diff_meta's binary_presence gives); the
verdict's value may not. A word scan would not do: get_tool_reference names every verdict as
vocabulary and carries none of them.

The completeness guard ties the table to the whitelist: a tool added to BLIND_SAFE_TOOLS without a
call here fails it, and once a call is added, the difference proves or refutes it."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from tests.unit.lib.test_diff_review import (  # noqa: F401 — the autouse cache fixture
    DX,
    DY,
    PAIR,
    World,
    _clear_view_caches,
    _pair_anchor,
    a_row,
)
from tests.unit.lib.test_review_units import _build_world, _server_call
from tests.unit.test_mcp_app import _mk_analysis
from treasure_map import mcp_app
from treasure_map.lib import overlay
from treasure_map.lib.atlas.models import InstanceRow, NvramFlowRow
from treasure_map.lib.atlas.writer import (
    add_instance,
    add_nvram_flow_rows,
    add_private_exploit,
    begin_run,
    finish_run,
    upsert_pattern,
)
from treasure_map.lib.query import patch_view as pv
from treasure_map.lib.query import read_basis as rb
from treasure_map.lib.query import review_units as ru

A1 = _pair_anchor(DX, "00001000", "00001000")
A2 = _pair_anchor(DX, "00002000", "00002800")
A3 = _pair_anchor(DX, "00003000", "00003000")
P4 = f"{PAIR}#function_presence#libx::b:00004000"
Y5 = _pair_anchor(DY, "00005000", "00005000")
REF_M = "run_m#fn1@cmd"
REF_A = "runA#0a1b2c3d:00001000@cmd@0x10"

# One call (at least) per whitelisted tool, plus the switches that change an answer's shape.
SAFE_CALLS: list[tuple[str, dict[str, Any]]] = [
    ("get_pseudocode", {"run_id": "run_m", "function": "handle_req"}),
    ("get_pseudocode", {"evidence_ref": REF_M}),
    ("get_disassembly", {"run_id": "run_m", "function": "handle_req"}),
    ("get_callees", {"run_id": "run_m", "function": "handle_req"}),
    ("get_callees", {"evidence_ref": REF_M}),
    ("get_xrefs", {"run_id": "run_m", "function": "do_fwd"}),
    ("get_xrefs", {"run_id": "run_m", "function": "do_fwd", "direction": "callees"}),
    ("get_strings", {"run_id": "run_m", "binary": "webd"}),
    ("get_strings", {"evidence_ref": REF_M}),
    ("get_data_bytes", {"run_id": "run_m", "binary": "webd", "address": "0x6bc0"}),
    ("get_data_table", {"run_id": "run_m", "binary": "webd", "address": "0x6bc0"}),
    ("get_sink_provenance", {"evidence_ref": REF_M}),
    ("get_sink_provenance", {"evidence_ref": REF_M, "dominating_only": True}),
    ("get_imports_exports", {"run_id": "run_m", "binary": "webd"}),
    ("get_function_alignment", {"diff_id": DX, "function": "0x1000"}),
    ("get_function_alignment", {"diff_id": DX, "function": "0x2800", "side": "b"}),
    ("get_function_alignment", {"diff_id": DX, "function": "0x4000", "side": "b"}),
    ("get_functions_referencing_string", {"run_id": "run_m", "text": "x"}),
    ("get_string_reference_anchors", {"run_id": "run_m", "text": "x"}),
    ("get_string_keyed_edges", {"run_id": "run_m"}),
    ("get_nvram_key_flow", {"key": "node_role"}),
    ("get_nvram_key_flow", {"key": "node_role", "run_id": "run_m"}),
    ("get_script_callsites", {"run_id": "run_m", "binary": "webd"}),
    ("launched_by", {"target": "webd"}),
    ("launched_by", {"target": "webd", "run_id": "run_m"}),
    ("pattern_density", {}),
    ("cross_firmware_patterns", {}),
    ("same_shape_siblings", {"diff_id": DX, "evidence_ref": REF_A}),
    ("same_shape_siblings", {"diff_id": DX, "evidence_ref": REF_A, "members_offset": 0}),
    ("get_diff_meta", {"diff_id": DX}),
    ("get_diff_meta", {"diff_id": DY}),
    ("get_diff_deltas", {"diff_id": DX}),
    ("get_diff_deltas", {"diff_id": DX, "verbose": True}),
    ("get_diff_string_delta", {"diff_id": DX}),
    ("list_runs", {}),
    ("legal_notice", {}),
    ("get_tool_reference", {}),
    ("get_tool_reference", {"name": "guide"}),
    ("get_tool_reference", {"name": "parameters"}),
    ("get_tool_reference", {"name": "annotate_diff"}),
]

# The two worlds' verdicts: the same subjects judged, every value different.
VERDICTS = {
    "x": {
        A1: "no_real_change",
        A2: "change_inconclusive",
        A3: "changed_real",
        P4: "changed_real",
        Y5: "change_inconclusive",
        REF_M: "excluded",
    },
    "y": {
        A1: "change_inconclusive",
        A2: "changed_real",
        A3: "no_real_change",
        P4: "change_inconclusive",
        Y5: "changed_real",
        REF_M: "suspicious",
    },
}


def _world(tmp: Path, monkeypatch: pytest.MonkeyPatch, which: str) -> World:
    tmp.mkdir(parents=True, exist_ok=True)
    w = _build_world(tmp, monkeypatch)
    w.rows[DX] = [a_row("00001000")]
    _mk_analysis(tmp)
    conn = w.atlas
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
            evidence_ref=REF_M,
            scope_origin="intra",
            origin="custom",
            binary_path="usr/sbin/webd",
            flow_evidence=json.dumps({"entry_reach": {"status": "found", "sites": []}}),
        ),
    )
    begin_run(conn, "run_m", analysis_db_path=str((tmp / "analysis.db").resolve()))
    finish_run(conn, "run_m", binaries=1, functions=2)
    add_nvram_flow_rows(
        conn,
        [
            NvramFlowRow(
                source_run_id="run_m",
                key="node_role",
                key_kind="constant",
                binary="webd",
                func="handle_req",
                op="read",
                api="nvram_get",
            )
        ],
    )
    conn.commit()
    for anchor, verdict in VERDICTS[which].items():
        if anchor == REF_M:
            overlay.upsert_overlay(
                conn,
                evidence_ref=REF_M,
                verdict=verdict,
                rationale="r",
                attributed_to="agent-via-mcp",
            )
            continue
        basis = (
            {"checked": [anchor], "why_unchanged": "same"} if verdict == "no_real_change" else None
        )
        w.judge(DY if anchor == Y5 else DX, anchor, verdict, verdict_basis=basis)
    if which == "x":
        add_private_exploit(
            conn, evidence_ref=REF_M, pattern="p", exploit_note="n", attributed_to="tester"
        )
    conn.commit()
    return w


# When each world was built: a fact of the fixture, not of the verdicts.
_STAMP = re.compile(r"\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:[+-]\d\d:?\d\d|Z)?")


def _text(got: dict[str, Any], where: Path) -> str:
    got = {k: v for k, v in got.items() if k != "server"}
    text = json.dumps(got, sort_keys=True, default=str)
    text = text.replace(str(where.resolve()), "<w>").replace(str(where), "<w>")
    return _STAMP.sub("<t>", text)


def _answers(tmp: Path, monkeypatch: pytest.MonkeyPatch, which: str) -> list[str]:
    pv._clear_view_caches()
    ru.DIFF_CACHE.clear()
    where = tmp / which
    w = _world(where, monkeypatch, which)
    server = mcp_app.build_server(w.path)
    out = []
    for name, args in SAFE_CALLS:
        got = _server_call(server, name, args)
        if name == "list_runs":  # runs written in the same second sort either way
            got["runs"] = sorted(got.get("runs") or [], key=lambda r: json.dumps(r, sort_keys=True))
        out.append(_text(got, where))
    return out


def test_every_whitelisted_tool_has_a_call_here() -> None:
    """★ C-9 completeness: the table names exactly the whitelist.

    MUTATION (verified RED, 1 failed): add list_overlays to BLIND_SAFE_TOOLS -> RED."""
    assert {name for name, _ in SAFE_CALLS} == rb.BLIND_SAFE_TOOLS


def test_no_whitelisted_answer_changes_with_the_verdicts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ C-9: every call in SAFE_CALLS answers the same, byte for byte, in world x and world y.

    MUTATION (verified RED, 1 failed): have get_diff_meta carry a judged subject's verdict ->
    RED; MUTATION (verified RED, 1 failed): add get_diff_patch_view (which carries review_state)
    to the whitelist and a call of it here -> RED."""
    x = _answers(tmp_path, monkeypatch, "x")
    y = _answers(tmp_path, monkeypatch, "y")
    assert len(x) == len(SAFE_CALLS)
    differ = [SAFE_CALLS[i] for i, (a, b) in enumerate(zip(x, y, strict=True)) if a != b]
    assert differ == []


def test_the_worlds_really_differ_where_a_verdict_shows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The precondition of the difference test: the two worlds' verdicts DO show where a tool
    carries them (get_diff_patch_view's review_state, list_candidates' verdict_shape), so the equal
    answers above are not equal for want of a difference."""
    seen = {}
    for which in ("x", "y"):
        pv._clear_view_caches()
        ru.DIFF_CACHE.clear()
        where = tmp_path / which
        w = _world(where, monkeypatch, which)
        server = mcp_app.build_server(w.path)
        view = _server_call(server, "get_diff_patch_view", {"diff_id": DX})
        cands = _server_call(server, "list_candidates", {"run_id": "run_m"})
        assert "error" not in view and "error" not in cands, (view, cands)
        seen[which] = (_text(view, where), _text(cands, where))
    assert seen["x"][0] != seen["y"][0]
    assert seen["x"][1] != seen["y"][1]
