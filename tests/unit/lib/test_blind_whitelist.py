# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The blind-read whitelist (read_basis.BLIND_SAFE_TOOLS) proven from the answers, not the names.

A shadow judgement is blind only when its session made no call whose answer depends on the
verdicts recorded. Each whitelisted tool is called (through the real server, its log on) in three
worlds that hold the same facts: x and y judge the same subjects with DIFFERENT verdicts — every
subject's value differs, and so does the distribution of values over the pair — and "none" judges
nothing. An answer must be the same, byte for byte, in x and y once the server block and the
world's own path are taken out; against "none" it may differ only in a judged-or-not count (as
get_diff_meta's binary_presence gives), never in a verdict's value. A word scan would not do:
get_tool_reference names every verdict as vocabulary and carries none of them.

Three fixtures, so every call reaches the branch that could carry a verdict: the diff World of
test_diff_review (diffs, a scan candidate, nvram flow), the same-shape World of
test_same_shape_siblings (a group of judged entries), and the binary-presence World of
test_binary_presence (binaries one run holds alone, judged on the run pair). Every call must
answer without an error and with something found; the few that can only reach a not-found answer
here are listed in NOT_FOUND_ONLY with why.

The completeness guard ties the table to the whitelist: a tool added to BLIND_SAFE_TOOLS without a
call here fails it, and once a call is added, the difference proves or refutes it."""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from tests.unit.lib import test_binary_presence as tbp
from tests.unit.lib import test_same_shape_siblings as tss
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
from treasure_map.cli import mcp_cli
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
from treasure_map.lib.query import same_shape_siblings as ss
from treasure_map.version import UNKNOWN_VERSION

A1 = _pair_anchor(DX, "00001000", "00001000")
A2 = _pair_anchor(DX, "00002000", "00002800")
A3 = _pair_anchor(DX, "00003000", "00003000")
P4 = f"{PAIR}#function_presence#libx::b:00004000"
Y5 = _pair_anchor(DY, "00005000", "00005000")
REF_M = "run_m#fn1@cmd"

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

# The same-shape World's calls: a group whose members' entries are judged.
SIB_CALLS: list[tuple[str, dict[str, Any]]] = [
    ("same_shape_siblings", {"diff_id": tss.DIFF, "evidence_ref": tss.LISTED}),
    ("same_shape_siblings", {"diff_id": tss.DIFF, "evidence_ref": tss.LISTED, "members_offset": 0}),
    ("same_shape_siblings", {"diff_id": tss.DIFF, "evidence_ref": tss.WRAPPED[0]}),
]
# The binary-presence World's calls: binaries one run holds alone, judged on the run pair.
PRES_CALLS: list[tuple[str, dict[str, Any]]] = [
    ("get_diff_meta", {"diff_id": tbp.DIFF}),
]

# The diff World's calls again in their paged forms (a later page, a small limit, an offset past
# the end), answered under a response budget of PAGE_BUDGET bytes so the byte cut really runs:
# where a page is cut, and what the paging fields say, must not depend on the verdicts either.
PAGE_BUDGET = 2_000
PAGE_CALLS: list[tuple[str, dict[str, Any]]] = [
    ("get_xrefs", {"run_id": "run_m", "function": "do_fwd", "limit": 2, "offset": 1}),
    ("get_xrefs", {"run_id": "run_m", "function": "do_fwd", "limit": 200}),
    ("get_xrefs", {"run_id": "run_m", "function": "do_fwd", "offset": 50}),
    ("get_sink_provenance", {"evidence_ref": REF_M, "limit": 2, "offset": 1}),
    ("get_sink_provenance", {"evidence_ref": REF_M}),
    ("get_imports_exports", {"run_id": "run_m", "binary": "webd", "limit": 2, "offset": 1}),
    ("get_imports_exports", {"run_id": "run_m", "binary": "webd"}),
    ("get_function_alignment", {"diff_id": DX, "function": "dup", "limit": 1, "offset": 1}),
    ("get_function_alignment", {"diff_id": DX, "function": "dup"}),
    ("get_functions_referencing_string", {"run_id": "run_m", "text": "x", "limit": 2, "offset": 1}),
    ("get_functions_referencing_string", {"run_id": "run_m", "text": "x"}),
    ("get_string_reference_anchors", {"run_id": "run_m", "text": "x", "limit": 2, "offset": 1}),
    ("get_string_reference_anchors", {"run_id": "run_m", "text": "x"}),
    ("get_string_keyed_edges", {"run_id": "run_m", "limit": 2, "offset": 1}),
    ("get_string_keyed_edges", {"run_id": "run_m"}),
    ("get_nvram_key_flow", {"key": "node_role", "limit": 2, "offset": 1}),
    ("get_nvram_key_flow", {"key": "node_role", "run_id": "run_m"}),
    ("get_nvram_key_flow", {"key": "node_role", "offset": 50}),
    ("launched_by", {"target": "webd", "limit": 2, "offset": 1}),
    ("launched_by", {"target": "webd"}),
    ("get_diff_deltas", {"diff_id": DX, "limit": 2, "offset": 1}),
    ("get_diff_deltas", {"diff_id": DX}),
]

NRC, CI, CR = "no_real_change", "change_inconclusive", "changed_real"
# World y's verdict of a subject world x judged ``v``: another value on every subject, and another
# distribution over the pair (x: nrc 1 / ci 2 / cr 2 here; y: ci 2 / cr 3).
_OTHER = {NRC: CR, CI: CR, CR: CI, "excluded": "suspicious"}
X_VERDICTS = {A1: NRC, A2: CI, A3: CR, P4: CR, Y5: CI, REF_M: "excluded"}
WORLDS = ("x", "y", "none")


def _verdict(which: str, x: str) -> str | None:
    """World ``which``'s verdict on a subject world x judged ``x`` (None: not judged)."""
    return {"x": x, "y": _OTHER[x], "none": None}[which]


# The calls that, in these fixtures, can only reach a not-found answer — kept because the
# not-found answer must not carry a verdict either, and because there is no fixture for more.
def _key(name: str, args: dict[str, Any]) -> tuple[str, str]:
    return name, json.dumps(args, sort_keys=True)


NOT_FOUND_ONLY: dict[tuple[str, str], str] = {
    _key("get_data_bytes", {"run_id": "run_m", "binary": "webd", "address": "0x6bc0"}): (
        "the fixture's analysis.db holds no data segment"
    ),
    _key("get_data_table", {"run_id": "run_m", "binary": "webd", "address": "0x6bc0"}): (
        "the fixture's analysis.db holds no data segment"
    ),
    _key("get_function_alignment", {"diff_id": DX, "function": "0x4000", "side": "b"}): (
        "a function in no pair: not found IS the answer for it (the unmatched branch)"
    ),
    _key("get_function_alignment", {"diff_id": DX, "function": "dup", "limit": 1, "offset": 1}): (
        "a name on two functions: the ambiguous answer is found false, its candidates listed"
    ),
    _key("get_function_alignment", {"diff_id": DX, "function": "dup"}): (
        "a name on two functions: the ambiguous answer is found false, its candidates listed"
    ),
}

# Where the "none" world may differ from a judged one: a judged-or-not count, by its key — never a
# verdict's value. Each entry is (call label, key).
JUDGED_OR_NOT: frozenset[tuple[str, str]] = frozenset(
    {('pres:get_diff_meta({"diff_id": "runA::runB::libx"})', "not_looked_at")}
)


# Three sink records on the candidate, so get_sink_provenance has records to page.
_PROV = [
    {
        "sink_idx": i,
        "sink": "system",
        "sink_addr": hex(0x6BA0 + 0x10 * i),
        "arg_idx": 0,
        "provenance": {"kind": "stack_buf", "stack_key": f"frame[{i}]" + "s" * 600, "writers": []},
    }
    for i in range(3)
]


def _page_data(tmp: Path, conn: Any) -> None:
    """A few rows more for each paged tool, so a page of two leaves rows after it and a budget of
    PAGE_BUDGET cuts some pages: callers of do_fwd and functions mentioning "x" in run_m's
    analysis.db, imports, exports and references of "x" there; nvram, launch and string-key edges
    in the atlas; deltas on libx; and a name ("dup") on two of libx's aligned A functions."""
    db = sqlite3.connect(tmp / "analysis.db")
    for i in range(3, 7):
        db.execute(
            "INSERT INTO functions (id, binary_id, name, address, pseudocode, callees) "
            "VALUES (?, 1, ?, ?, ?, ?)",
            (
                i,
                f"fx{i}_" + "n" * 300,
                hex(0x7000 + 0x40 * i),
                f'void fx{i}(){{ do_fwd("x{i}{"m" * 300}"); }}',
                json.dumps(["do_fwd"]),
            ),
        )
    for i in range(3):
        db.execute(
            "INSERT INTO imports (binary_id, func_name, lib_soname, source) "
            "VALUES (1, ?, 'libc.so.0', 'decompiler')",
            (f"imp{i}" + "_" * 200,),
        )
        db.execute(
            "INSERT INTO exports (binary_id, func_name, address) VALUES (1, ?, ?)",
            (f"exp{i}" + "_" * 200, hex(0x8000 + i)),
        )
        db.execute(
            "INSERT INTO string_refs (binary_id, string_addr, string_value, ref_at, ref_in_func, "
            "ref_in_func_addr, segment) VALUES (1, '0x9000', 'x', ?, 'handle_req', '0x6b90', ?)",
            (hex(0x6B94 + 4 * i), ".text" + "-" * 200),
        )
    db.commit()
    db.close()
    pad = "p" * 200
    for i in range(4):
        conn.execute(
            "INSERT INTO nvram_key_flow (source_run_id, key, key_kind, binary, func, op, api) "
            "VALUES ('run_m', 'node_role', 'constant', 'webd', ?, ?, 'nvram_get')",
            (f"f{i}_{pad}", "write" if i % 2 else "read"),
        )
        conn.execute(
            "INSERT INTO exec_edge (source_run_id, launcher_binary, launcher_function, "
            "launcher_addr, exec_api, sink_addr, target_layer, target_token, target_resolution, "
            "target_binary, argv_template) "
            "VALUES ('run_m', 'rcd', ?, ?, 'system', ?, 'shell_command', 'webd', 'resolved', "
            "'webd', ?)",
            (f"start{i}", hex(0x400 + i), hex(0x410 + i), f"webd -{i} {pad}"),
        )
        conn.execute(
            "INSERT INTO string_keyed_edge (source_run_id, binary, from_function, key, "
            "callee_name, callee_addr, callee_kind) "
            "VALUES ('run_m', 'webd', 'dispatch', ?, ?, ?, 'direct')",
            (f"k{i}_{pad}", f"cb{i}", hex(0x500 + i)),
        )
        conn.execute(
            "INSERT INTO dimension_delta (diff_id, dimension, subject_kind, subject_key, binary, "
            "delta_kind) VALUES (?, 'string_edge', 'edge', ?, 'libx', 'layer_changed')",
            (DX, f"libx|strcmp_gate|k{i}|{pad * 3}"),
        )
    conn.execute(
        "UPDATE function_alignment SET name_a = 'dup' WHERE diff_id = ? AND addr_a IN (?, ?)",
        (DX, "00002000", "00003000"),
    )
    conn.commit()


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
            flow_evidence=json.dumps(
                {"entry_reach": {"status": "found", "sites": []}, "sink_arg_provenance": _PROV}
            ),
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
    _page_data(tmp, conn)
    for anchor, x in X_VERDICTS.items():
        verdict = _verdict(which, x)
        if verdict is None:
            continue
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


def _sib_world(tmp: Path, mp: pytest.MonkeyPatch, which: str) -> Path:
    """The same-shape World, its listed pairs judged (none in world "none")."""

    def fresh(atlas: Any, diff_id: str) -> dict[str, Any]:
        return {"source_stale": False, "source_stale_reason": None, "toolchain_checked": True}

    mp.setattr(pv, "diff_source_staleness", fresh)
    mp.setattr(ss, "diff_source_staleness", fresh)
    mp.setattr(mcp_app, "_installed_commit", lambda: UNKNOWN_VERSION)
    mp.setattr(mcp_cli, "installed_commit", lambda: UNKNOWN_VERSION)
    tmp.mkdir(parents=True, exist_ok=True)
    w = tss.World(tmp)
    tss._build(w)
    # Every entry the view lists (pairs and one-sided functions), judged in turn NRC, CI, CR, … in
    # world x.
    page = pv.get_diff_patch_view(w.atlas, tss.DIFF, rows_limit=0, limit=200)
    listed = [e["entry_id"] for e in page["entries"]]
    assert len(listed) == 12, listed
    for i, entry_id in enumerate(listed):
        verdict = _verdict(which, (NRC, CI, CR)[i % 3])
        if verdict is None:
            continue
        kind, rest = entry_id.split(":", 1)
        anchor = (
            _pair_anchor(tss.DIFF, *rest.split(":"))
            if kind == "pair"
            else f"runA::runB#function_presence#libx::{entry_id}"
        )
        overlay.annotate_diff(
            w.atlas,
            diff_id=tss.DIFF,
            anchor_ref=anchor,
            verdict=verdict,
            rationale="r",
            verdict_basis=(
                {"checked": [anchor], "why_unchanged": "same"} if verdict == NRC else None
            ),
        )
    w.commit()
    return w.path


def _pres_world(tmp: Path, mp: pytest.MonkeyPatch, which: str) -> Path:
    """The binary-presence World, its first two A-only binaries judged on the run pair."""
    mp.setattr(mcp_app, "_installed_commit", lambda: UNKNOWN_VERSION)
    mp.setattr(
        pv,
        "diff_source_staleness",
        lambda atlas, diff_id: {
            "source_stale": False,
            "source_stale_reason": None,
            "toolchain_checked": True,
        },
    )
    tmp.mkdir(parents=True, exist_ok=True)
    w = tbp.World(tmp)
    tbp._build(w)
    presence = tbp.bp.find_presence(w.atlas, "runA", "runB")
    a_only = [b for b in presence.items if b.tag == "a_only"][:2]
    assert len(a_only) == 2, presence.items
    for b, x in zip(a_only, (NRC, CI), strict=True):
        verdict = _verdict(which, x)
        if verdict is None:
            continue
        # its first review subject: a function holding a candidate
        anchor = next(s.anchor for s in tbp.bp.review_subjects(presence) if s.binary is b)
        overlay.annotate_diff(
            w.atlas,
            run_pair=tbp.PAIR,
            anchor_ref=anchor,
            verdict=verdict,
            rationale="r",
            verdict_basis=(
                {"checked": [anchor], "why_unchanged": "same"} if verdict == NRC else None
            ),
        )
    w.commit()
    return w.path


def _label(part: str, name: str, args: dict[str, Any]) -> str:
    return f"{part}:{name}({json.dumps(args, sort_keys=True)})"


def _answers(tmp: Path, which: str) -> dict[str, dict[str, Any]]:
    """Every call of the three tables in world ``which``: its answer with the server block, the
    world's own path and the build times taken out, by call label."""
    out: dict[str, dict[str, Any]] = {}
    for part, calls in (("diff", SAFE_CALLS), ("sib", SIB_CALLS), ("pres", PRES_CALLS)):
        pv._clear_view_caches()
        ru.DIFF_CACHE.clear()
        where = tmp / which / part
        with pytest.MonkeyPatch.context() as mp:
            if part == "diff":
                path = _world(where, mp, which).path
            elif part == "sib":
                path = _sib_world(where, mp, which)
            else:
                path = _pres_world(where, mp, which)
            server = mcp_app.build_server(path)
            for name, args in calls:
                got = _server_call(server, name, args)
                if name == "list_runs":  # runs written in the same second sort either way
                    got["runs"] = sorted(
                        got.get("runs") or [], key=lambda r: json.dumps(r, sort_keys=True)
                    )
                out[_label(part, name, args)] = json.loads(_text(got, where))
            if part == "diff":
                # The paged forms, in the same world, under the small budget.
                mp.setattr(mcp_app, "_RESPONSE_BYTE_BUDGET", PAGE_BUDGET)
                for name, args in PAGE_CALLS:
                    got = _server_call(server, name, args)
                    out[_label("page", name, args)] = json.loads(_text(got, where))
        pv._clear_view_caches()
        ru.DIFF_CACHE.clear()
    return out


def _all_calls() -> list[tuple[str, str, dict[str, Any]]]:
    return [
        (part, name, args)
        for part, calls in (
            ("diff", SAFE_CALLS),
            ("sib", SIB_CALLS),
            ("pres", PRES_CALLS),
            ("page", PAGE_CALLS),
        )
        for name, args in calls
    ]


def _masked(label: str, got: Any) -> Any:
    """``got`` without the judged-or-not counts JUDGED_OR_NOT allows for this call."""
    keys = {key for call, key in JUDGED_OR_NOT if call == label}
    if isinstance(got, dict):
        return {k: _masked(label, v) for k, v in got.items() if k not in keys}
    if isinstance(got, list):
        return [_masked(label, v) for v in got]
    return got


def test_every_whitelisted_tool_has_a_call_here() -> None:
    """★ C-9 completeness: the tables name exactly the whitelist.

    MUTATION (verified RED, 1 failed): add list_overlays to BLIND_SAFE_TOOLS -> RED."""
    assert {name for _, name, _ in _all_calls()} == rb.BLIND_SAFE_TOOLS


@pytest.fixture(scope="module")
def answers(tmp_path_factory: pytest.TempPathFactory) -> dict[str, dict[str, dict[str, Any]]]:
    """The three worlds' answers, built once for the tests below."""
    tmp = tmp_path_factory.mktemp("worlds")
    return {which: _answers(tmp, which) for which in WORLDS}


def test_every_call_reaches_an_answer_that_could_carry_a_verdict(
    answers: dict[str, dict[str, dict[str, Any]]],
) -> None:
    """★ FC03: a call that only reaches an error, or a not-found answer, compares two answers
    that cannot differ — so every call answers without an error and finds something, except the
    ones NOT_FOUND_ONLY names (with why); that list is exactly the calls that do not find.

    MUTATION (verified RED, 1 failed): put back the siblings call on a ref that is no candidate
    of the diff World (it answers an error) -> RED."""
    x = answers["x"]
    assert len(x) == len(_all_calls())
    not_found = set()
    for part, name, args in _all_calls():
        got = x[_label(part, name, args)]
        assert "error" not in got, (part, name, args, got.get("error"))
        if got.get("found") is False:
            not_found.add(_key(name, args))
    assert not_found == set(NOT_FOUND_ONLY), not_found


def test_no_whitelisted_answer_changes_with_the_verdicts(
    answers: dict[str, dict[str, dict[str, Any]]],
) -> None:
    """★ C-9 / FC03: every call answers the same, byte for byte, in world x and world y — whose
    verdicts differ on every subject and in their distribution over the pair.

    MUTATION (verified RED, 1 failed): have get_diff_meta carry a judged subject's verdict -> RED;
    MUTATION (verified RED, 1 failed): add get_diff_patch_view (which carries review_state) to the
    whitelist and a call of it here -> RED. FC03 — MUTATION (verified RED, 1 failed): give
    same_shape_siblings' members their entry's verdict (its found path) -> RED; MUTATION (verified
    RED, 1 failed): give get_diff_meta the pair's verdict counts -> RED; MUTATION (verified RED, 1
    failed): give get_diff_meta's binary_presence the A-only binaries' verdicts -> RED.
    T-J5 — MUTATION (verified RED, 1 failed): widen get_nvram_key_flow's answer by the number of
    changed_real verdicts (a field padded before the page is fitted) -> its pages, and the
    unpaged calls, differ -> RED."""
    x, y = answers["x"], answers["y"]
    differ = [label for label in x if json.dumps(x[label]) != json.dumps(y[label])]
    assert differ == []


def test_against_no_judgement_only_a_judged_or_not_count_moves(
    answers: dict[str, dict[str, dict[str, Any]]],
) -> None:
    """★ FC03: world "none" (nothing judged) against world x: an answer may differ only in the
    judged-or-not counts JUDGED_OR_NOT names — and each one named does move (the table is exactly
    what differs, never wider).

    MUTATION (verified RED, 1 failed): carry the judged subjects' anchors (not their verdicts) in
    get_diff_meta's binary_presence -> RED."""
    x, none = answers["x"], answers["none"]
    differ = {label for label in x if json.dumps(x[label]) != json.dumps(none[label])}
    assert differ == {call for call, _ in JUDGED_OR_NOT}, differ
    for label in differ:
        assert json.dumps(_masked(label, x[label])) == json.dumps(_masked(label, none[label]))


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


def test_the_other_two_fixtures_really_hold_different_verdicts(tmp_path: Path) -> None:
    """The same precondition for the same-shape and binary-presence fixtures: their judgements
    show where a tool carries them (list_overlays on the diff / on the run pair) — three ways
    apart, and with a different distribution of verdicts in x and y."""
    from collections import Counter

    for part, build, run_id in (
        ("sib", _sib_world, tbp.PAIR),
        ("pres", _pres_world, tbp.PAIR),
    ):
        got = {}
        for which in WORLDS:
            pv._clear_view_caches()
            ru.DIFF_CACHE.clear()
            with pytest.MonkeyPatch.context() as mp:
                path = build(tmp_path / which / part, mp, which)
                server = mcp_app.build_server(path)
                rows = _server_call(
                    server, "list_overlays", {"anchor_kind": "diff_subject", "run_id": run_id}
                )
            got[which] = Counter(r["verdict"] for r in rows.get("overlays") or [])
        assert got["none"] == Counter(), (part, got)
        assert got["x"] and got["y"] and got["x"] != got["y"], (part, got)
        assert sum(got["x"].values()) == sum(got["y"].values()), (part, got)


# The tools whose paged forms PAGE_CALLS reads: the whitelisted tools that page their rows.
_PAGED_TOOLS = frozenset(
    {
        "get_xrefs",
        "get_sink_provenance",
        "get_imports_exports",
        "get_function_alignment",
        "get_functions_referencing_string",
        "get_string_reference_anchors",
        "get_string_keyed_edges",
        "get_nvram_key_flow",
        "launched_by",
        "get_diff_deltas",
    }
)


def _cut(got: dict[str, Any]) -> bool:
    """Whether a page says the byte budget ended it (top level, or in get_diff_deltas' page)."""
    return (
        got.get("truncated_by_bytes") is True
        or (got.get("page") or {}).get("truncated_by_bytes") is True
    )


def test_the_paged_forms_really_reach_the_byte_cut(
    answers: dict[str, dict[str, dict[str, Any]]],
) -> None:
    """T-J5 precondition: the paged calls compare pages the byte cut actually shaped — every
    paging tool has a call whose page the budget ended, and a call past the end is an empty last
    page that still finds its subject (never a not-found the comparison cannot tell apart).
    Without the budget patch no page here is cut (the rows are few), and the equal answers of
    test_no_whitelisted_answer_changes_with_the_verdicts would compare only whole lists.

    MUTATION (verified RED, 1 failed): drop the PAGE_BUDGET patch in _answers -> RED."""
    x = answers["x"]
    page_calls = [(name, args) for part, name, args in _all_calls() if part == "page"]
    assert {name for name, _ in page_calls} == _PAGED_TOOLS
    cut = {name for name, args in page_calls if _cut(x[_label("page", name, args)])}
    assert cut == _PAGED_TOOLS, sorted(_PAGED_TOOLS - cut)
    for name, args in page_calls:
        if args.get("offset") == 50:
            got = x[_label("page", name, args)]
            assert got.get("found") is True and got["next_offset"] is None, (name, got)
