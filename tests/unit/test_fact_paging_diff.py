# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Paging of the diff-side and overlay listings: list_overlays (both anchor kinds), list_diffs,
get_diff_sink_overlay's rows and get_function_alignment's ambiguous candidates.

A page is never a filter: walking ``offset = next_offset`` until null reads every row exactly
once, every count is over every row, and a row too large for the budget is still given (one per
page) rather than dropped. list_overlays pages by first-write order (the row id), so a judgement
rewritten while a reader is paging does not move under the reader.

Synthetic fixtures only."""

from __future__ import annotations

import json
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
)
from tests.unit.lib.test_review_units import _build_world
from treasure_map import mcp_app
from treasure_map.lib import overlay
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import InstanceRow
from treasure_map.lib.atlas.writer import add_instance, begin_run, finish_run, upsert_pattern
from treasure_map.lib.query import diff_align as da
from treasure_map.lib.query import sink_overlay as so

# ── helpers ───────────────────────────────────────────────────────────────────────────────────


def _walk(call: Any, rows: str, **args: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Every page of ``call`` from offset 0, following next_offset until null: the rows in page
    order and the pages themselves. Bounded, so a next_offset that never ends fails loudly."""
    seen: list[dict[str, Any]] = []
    pages: list[dict[str, Any]] = []
    offset: int | None = 0
    for _ in range(500):
        assert offset is not None
        page = call(offset=offset, **args)
        assert "error" not in page, page.get("error")
        pages.append(page)
        seen += page[rows]
        offset = page["next_offset"]
        if offset is None:
            return seen, pages
        assert offset == len(seen), (offset, len(seen))
    raise AssertionError("next_offset never reached null")


# ── list_overlays, the candidate path ─────────────────────────────────────────────────────────

_RUN = "run_o"


def _refs(n: int) -> list[str]:
    return [f"{_RUN}#deadbeef:{0x1000 + i:08x}@cmd" for i in range(n)]


def _overlay_atlas(tmp_path: Path, n: int) -> tuple[Path, list[str]]:
    """``n`` annotations (blind writes: no candidate needed), one verdict, written at strictly
    increasing times in id order — so the display order (verdict, latest first) is the REVERSE
    of the id order, and a page by the display order moves when a row is rewritten."""
    path = tmp_path / "atlas.db"
    con = open_atlas(path)
    refs = _refs(n)
    for i, ref in enumerate(refs):
        overlay.upsert_overlay(con, evidence_ref=ref, verdict="suspicious", rationale=f"r{i}")
        con.execute(
            "UPDATE overlay SET updated_at = ? WHERE anchor_ref = ?",
            (f"2026-01-01 00:00:{i:02d}", ref),
        )
    con.commit()
    con.close()
    return path, refs


def _rewrite(path: Path, ref: str, at: str) -> None:
    """A real rewrite of one judgement (upsert), its updated_at then set to ``at`` so it is
    certainly the latest — CURRENT_TIMESTAMP has whole-second resolution."""
    con = open_atlas(path)
    try:
        res = overlay.upsert_overlay(con, evidence_ref=ref, verdict="suspicious", rationale="again")
        assert res.action == "updated"
        con.execute("UPDATE overlay SET updated_at = ? WHERE anchor_ref = ?", (at, ref))
        con.commit()
    finally:
        con.close()


def test_a_candidate_overlay_page_does_not_move_when_a_judgement_is_rewritten(
    tmp_path: Path,
) -> None:
    """T-J23 (evidence_ref path): read page one, rewrite a judgement that sits on a LATER page
    (its updated_at becomes the latest), read on: the pages together are every judgement once,
    in id order.

    MUTATION (verified RED, 1 failed): page in the display order (drop the id sort in
    overlay.page_overlay_rows) -> the rewritten row jumps to the front, page two repeats a row
    and the rewritten one is never read -> RED."""
    path, refs = _overlay_atlas(tmp_path, 5)
    tool = mcp_app.make_tools(path)["list_overlays"]
    first = tool(limit=2)
    assert first["next_offset"] == 2 and first["total_overlays"] == 5
    seen = list(first["overlays"])
    # The row rewritten is one the first page did NOT hold, so a display-order page would move.
    late = next(r for r in refs if r not in {o["anchor_ref"] for o in seen})
    _rewrite(path, late, "2026-01-02 00:00:00")
    con = open_atlas(path)
    try:
        latest = con.execute("SELECT anchor_ref FROM overlay ORDER BY updated_at DESC").fetchone()
        assert latest[0] == late  # the precondition: it really is the latest now
    finally:
        con.close()
    offset = first["next_offset"]
    while offset is not None:
        page = tool(limit=2, offset=offset)
        seen += page["overlays"]
        offset = page["next_offset"]
    ids = [o["id"] for o in seen]
    assert ids == sorted(ids) and len(set(ids)) == 5
    assert sorted(o["anchor_ref"] for o in seen) == sorted(refs)


def test_a_candidate_overlay_page_cut_by_bytes_says_what_it_holds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A list_overlays page the response budget ended sooner than ``limit``: returned is the rows
    it holds (fewer than total_overlays), next_offset resumes right after them.

    MUTATION (verified RED, 1 failed): skip the tool's ``returned = len(overlays)`` after
    _fit_page -> returned still counts the uncut page -> RED."""
    path, _refs_ = _overlay_atlas(tmp_path, 6)
    tool = mcp_app.make_tools(path)["list_overlays"]
    whole = tool(limit=200)
    assert whole["returned"] == 6 and whole["truncated_by_bytes"] is False
    monkeypatch.setattr(mcp_app, "_RESPONSE_BYTE_BUDGET", len(json.dumps(whole)) - 300)
    got = tool(limit=200)
    assert got["truncated_by_bytes"] is True and 0 < len(got["overlays"]) < 6
    assert got["returned"] == len(got["overlays"]) < got["total_overlays"] == 6
    assert got["next_offset"] == len(got["overlays"])


def test_a_candidate_overlay_page_counts_over_every_row(tmp_path: Path) -> None:
    """T-J24 (evidence_ref path): on a page of two, count and counts_by_verdict are over all
    five rows, returned is the page's rows and total_overlays all of them.

    MUTATION (verified RED, 1 failed): set count to the page's length in page_overlay_rows ->
    RED."""
    path, refs = _overlay_atlas(tmp_path, 5)
    con = open_atlas(path)
    try:
        overlay.upsert_overlay(con, evidence_ref=refs[4], verdict="excluded", rationale="noise")
    finally:
        con.close()
    tool = mcp_app.make_tools(path)["list_overlays"]
    whole = tool(limit=200)
    assert whole["returned"] == 5 and whole["next_offset"] is None
    for offset in (0, 2, 4):
        page = tool(limit=2, offset=offset)
        assert page["count"] == 5
        assert (
            page["counts_by_verdict"]
            == whole["counts_by_verdict"]
            == {
                "suspicious": 4,
                "excluded": 1,
            }
        )
        assert page["total_overlays"] == 5
        assert page.get("returned") == len(page["overlays"]) == (1 if offset == 4 else 2)


def test_the_library_lists_every_overlay_in_its_display_order_when_given_no_limit(
    tmp_path: Path,
) -> None:
    """Without a limit, lib list_overlays is what it was: every row, by verdict then latest
    first, and no paging keys; the MCP tool (which always pages) gives first-write order.

    MUTATION (verified RED, 1 failed): sort by id in page_overlay_rows even when limit is None ->
    RED."""
    path, refs = _overlay_atlas(tmp_path, 4)
    con = open_atlas(path)
    try:
        overlay.upsert_overlay(con, evidence_ref=refs[0], verdict="excluded", rationale="noise")
        out = overlay.list_overlays(con)
    finally:
        con.close()
    assert "returned" not in out and "total_overlays" not in out
    rows = out["overlays"]
    assert [r["verdict"] for r in rows] == ["excluded", "suspicious", "suspicious", "suspicious"]
    sus = [r["updated_at"] for r in rows if r["verdict"] == "suspicious"]
    assert sus == sorted(sus, reverse=True)
    mcp = mcp_app.make_tools(path)["list_overlays"]()["overlays"]
    ids = [r["id"] for r in mcp]
    assert ids == sorted(ids) and ids != [r["id"] for r in rows]


# ── list_overlays, the diff_subject path ──────────────────────────────────────────────────────

_A1 = _pair_anchor(DX, "00001000", "00001000")
_A2 = _pair_anchor(DX, "00002000", "00002800")
_A3 = _pair_anchor(DX, "00003000", "00003000")
_P4 = f"{PAIR}#function_presence#libx::b:00004000"
_Y5 = _pair_anchor(DY, "00005000", "00005000")
_JUDGED = {
    _A1: "no_real_change",
    _A2: "change_inconclusive",
    _A3: "changed_real",
    _P4: "changed_real",
    _Y5: "change_inconclusive",
}


def _judged_world(tmp_path: Path, mp: pytest.MonkeyPatch) -> World:
    """The review-units World with its five subjects judged, at increasing times in id order."""
    w = _build_world(tmp_path, mp)
    for i, (anchor, verdict) in enumerate(_JUDGED.items()):
        basis = (
            {"checked": [anchor], "why_unchanged": "same"} if verdict == "no_real_change" else None
        )
        w.judge(DY if anchor == _Y5 else DX, anchor, verdict, verdict_basis=basis)
        w.atlas.execute(
            "UPDATE overlay SET updated_at = ? WHERE anchor_ref = ?",
            (f"2026-01-01 00:00:{i:02d}", anchor),
        )
    w.atlas.commit()
    return w


def test_a_diff_judgement_page_does_not_move_when_a_judgement_is_rewritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-J23 (diff_subject path, run pair given): page one read, a judgement on a later page
    rewritten (now the latest), the pages together are every judgement once, in id order.

    MUTATION (verified RED, 1 failed): page in the display order (drop the id sort in
    overlay.page_overlay_rows) -> RED."""
    w = _judged_world(tmp_path, monkeypatch)
    tool = mcp_app.make_tools(w.path)["list_overlays"]
    args = {"anchor_kind": "diff_subject", "run_id": PAIR, "limit": 2}
    first = tool(**args)
    assert first["total_overlays"] == 5 and first["next_offset"] == 2
    seen = list(first["overlays"])
    late = next(a for a in _JUDGED if a not in {o["anchor_ref"] for o in seen})
    verdict = "changed_real" if _JUDGED[late] != "changed_real" else "change_inconclusive"
    w.judge(DY if late == _Y5 else DX, late, verdict)
    w.atlas.execute(
        "UPDATE overlay SET updated_at = '2026-01-02 00:00:00' WHERE anchor_ref = ?", (late,)
    )
    w.atlas.commit()
    latest = w.atlas.execute("SELECT anchor_ref FROM overlay ORDER BY updated_at DESC").fetchone()
    assert latest[0] == late
    offset = first["next_offset"]
    while offset is not None:
        page = tool(**args, offset=offset)
        seen += page["overlays"]
        offset = page["next_offset"]
    ids = [o["id"] for o in seen]
    assert ids == sorted(ids) and len(set(ids)) == 5
    assert {o["anchor_ref"] for o in seen} == set(_JUDGED)


def test_a_diff_judgement_page_counts_and_progress_over_every_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-J24 (diff_subject path): every page carries count, counts_by_verdict,
    counts_by_review_state and review_progress of the whole pair; returned is the page's rows.

    MUTATION (verified RED, 1 failed): recount counts_by_verdict from the page in
    page_overlay_rows -> RED. MUTATION (verified RED, 1 failed): set count to the page's
    length -> RED."""
    w = _judged_world(tmp_path, monkeypatch)
    tool = mcp_app.make_tools(w.path)["list_overlays"]
    args = {"anchor_kind": "diff_subject", "run_id": PAIR}
    whole = tool(**args, limit=200)
    assert whole["returned"] == 5 and whole["next_offset"] is None
    assert whole["counts_by_verdict"] == {
        "no_real_change": 1,
        "change_inconclusive": 2,
        "changed_real": 2,
    }
    assert "review_progress" in whole
    for offset in (0, 2, 4):
        page = tool(**args, limit=2, offset=offset)
        assert page["count"] == 5 and page["total_overlays"] == 5
        assert page["counts_by_verdict"] == whole["counts_by_verdict"]
        assert page["counts_by_review_state"] == whole["counts_by_review_state"]
        assert json.dumps(page["review_progress"], sort_keys=True) == json.dumps(
            whole["review_progress"], sort_keys=True
        )
        assert page.get("returned") == len(page["overlays"]) == (1 if offset == 4 else 2)


# ── list_candidates(overlay=true) reads every judgement, not one page of them ────────────────

_CAND_RUN = "run_v"
_LOW = f"{_CAND_RUN}#deadbeef:00002000@log"
_HIGH = f"{_CAND_RUN}#deadbeef:00005000@cmd"


def _candidate_atlas(tmp_path: Path) -> Path:
    path = tmp_path / "atlas.db"
    con = open_atlas(path)
    for name, ref, sink_class in (("cmd", _HIGH, "cmd"), ("log", _LOW, "log")):
        pid = upsert_pattern(
            con,
            source_class="external_input",
            sink_class=sink_class,
            call_sequence_shape=f"source->{name}",
        )
        add_instance(
            con,
            InstanceRow(
                pattern_id=pid,
                source_run_id=_CAND_RUN,
                evidence_ref=ref,
                pseudocode_hash=f"hash-{name}",
                sink_anchor="system",
                reachability_status="unknown",
                binary_path="usr/sbin/webd",
                flow_evidence=json.dumps({"source_kind": "free_string"}),
            ),
        )
    begin_run(con, _CAND_RUN, analysis_db_path=str(tmp_path / "analysis.db"))
    finish_run(con, _CAND_RUN, binaries=1, functions=2)
    con.close()
    return path


def test_the_overlay_view_reads_judgements_past_the_first_hundred(tmp_path: Path) -> None:
    """T-J25: 150 judgements on other refs are written first, then the one that floats the
    low-impact candidate (id 151, past any default page): list_candidates(overlay=true) floats
    it and carries its marker — the view reads every judgement, not one page of them.

    MUTATION (verified RED, 1 failed): give lib list_overlays a default limit of 100 -> the
    floating judgement is not read, the base order stays -> RED."""
    path = _candidate_atlas(tmp_path)
    tools = mcp_app.make_tools(path)
    base = [c["evidence_ref"] for c in tools["list_candidates"](run_id=_CAND_RUN)["candidates"]]
    assert base == [_HIGH, _LOW]  # the precondition: the low candidate starts last
    con = open_atlas(path)
    try:
        for i in range(150):
            overlay.upsert_overlay(
                con,
                evidence_ref=f"elsewhere#deadbeef:{i:08x}@cmd",
                verdict="inconclusive",
                rationale="other",
            )
        res = overlay.upsert_overlay(con, evidence_ref=_LOW, verdict="suspicious", rationale="dig")
        assert res.id > 100
    finally:
        con.close()
    listed = tools["list_candidates"](run_id=_CAND_RUN, overlay=True)["candidates"]
    assert [c["evidence_ref"] for c in listed] == [_LOW, _HIGH]
    marker = next(c for c in listed if c["evidence_ref"] == _LOW).get("overlay") or {}
    assert marker.get("verdict") == "suspicious"


# ── list_diffs ────────────────────────────────────────────────────────────────────────────────

# Same-named diffs of one pair (one binary name, three contents), written so the insertion order
# runs AGAINST the diff_id order: only an order ending on diff_id puts them in diff_id order.
_SAME = ("runA::runB::libz@3", "runA::runB::libz@2", "runA::runB::libz@1")


def _diffs_world(tmp_path: Path, mp: pytest.MonkeyPatch) -> World:
    w = _build_world(tmp_path, mp)
    for i, diff_id in enumerate(_SAME):
        w.atlas.execute(
            "INSERT INTO diff_meta (diff_id, run_a_id, run_b_id, binary_a, binary_b, "
            "sha256_a, sha256_b, diff_ok, version_skew) "
            "VALUES (?, 'runA', 'runB', 'libz', 'libz', ?, ?, 1, 0)",
            (diff_id, f"{i}" * 64, f"{i + 5}" * 64),
        )
    w.atlas.commit()
    return w


def test_list_diffs_pages_every_row_once_in_a_total_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-J15 / T-J18: the pair's five diffs (three of them named libz) walked two at a time are
    every row once, the libz rows in diff_id order; next_offset is null only on the last page.

    MUTATION (verified RED, 1 failed): drop dm.diff_id from list_diffs' ORDER BY -> the libz
    rows come in insertion order -> RED."""
    w = _diffs_world(tmp_path, monkeypatch)
    tool = mcp_app.make_tools(w.path)["list_diffs"]
    whole = tool(run_a_id="runA", run_b_id="runB", limit=200)
    assert whole["total_diffs"] == 5 and whole["next_offset"] is None
    seen, pages = _walk(tool, "diffs", run_a_id="runA", run_b_id="runB", limit=2)
    assert [p["next_offset"] for p in pages] == [2, 4, None]
    ids = [d["diff_id"] for d in seen]
    assert ids == [d["diff_id"] for d in whole["diffs"]] and len(set(ids)) == 5
    libz = [i for i in ids if "libz" in i]
    assert libz == sorted(_SAME)


def test_list_diffs_reads_its_pair_wide_fields_from_every_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """review_pairs, count and coverage are the whole pair's on every page; the library
    answer (what tmap's CLI reads coverage from) is unpaged.

    MUTATION (verified RED, 1 failed): build review_pairs from the page's rows -> RED."""
    w = _diffs_world(tmp_path, monkeypatch)
    tool = mcp_app.make_tools(w.path)["list_diffs"]
    whole = tool(run_a_id="runA", run_b_id="runB", limit=200)
    page2 = tool(run_a_id="runA", run_b_id="runB", limit=2, offset=2)
    assert len(page2["diffs"]) == 2
    assert (
        page2["review_pairs"]
        == whole["review_pairs"]
        == [{"run_pair": PAIR, "diffs": 5, "call": f"start_diff_review(run_pair='{PAIR}')"}]
    )
    assert page2["count"] == whole["count"] == 5
    assert json.dumps(page2["coverage"], sort_keys=True) == json.dumps(
        whole["coverage"], sort_keys=True
    )
    lib = da.list_diffs(w.atlas, "runA", "runB")
    assert len(lib["diffs"]) == lib["count"] == 5
    assert "next_offset" not in lib and "total_diffs" not in lib and "coverage" in lib


def test_list_diffs_refuses_a_limit_or_offset_out_of_range(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-J14: a limit outside 1..200, an offset below 0, and a bool for either are refused.

    MUTATION (verified RED, 1 failed): drop the isinstance(limit, bool) test from
    _page_args_error -> limit=True is read as 1 -> RED."""
    w = _diffs_world(tmp_path, monkeypatch)
    tool = mcp_app.make_tools(w.path)["list_diffs"]
    for bad in ({"limit": 0}, {"limit": 201}, {"limit": True}, {"offset": -1}, {"offset": True}):
        assert "error" in tool(**bad), bad


# ── get_diff_sink_overlay rows ────────────────────────────────────────────────────────────────


def _overlay_rows(n: int) -> list[so.SinkOverlayRow]:
    return [
        so.SinkOverlayRow(
            diff_id=DX,
            binary="libx",
            sink_class="cmd",
            a_ref=f"runA#deadbeef:{0x1000 + i:08x}@cmd@0x10",
            b_ref=None,
            key_granularity="callsite",
            presence="presence_undetermined",
            presence_reason="present_different_callee",
            match_basis="instruction",
            counterpart_call="present_different_callee",
            alignment_confidence=0.97,
            counterpart_callee={
                "matched_addr": "00000010",
                "callees": [{"name": "popen_" + "w" * 300}],
                "same_callee_candidate_elsewhere": False,
            },
        )
        for i in range(n)
    ]


def _sink_tool(tmp_path: Path, mp: pytest.MonkeyPatch, n: int) -> Any:
    w = _build_world(tmp_path, mp)
    rows = _overlay_rows(n)
    cov = so.SinkOverlayCoverage(n, n, 0, 0, 0, False)
    mp.setattr(mcp_app, "_compute_sink_overlay", lambda *a, **k: so.SinkOverlayResult(rows, cov))
    return mcp_app.make_tools(w.path)["get_diff_sink_overlay"]


def test_sink_overlay_rows_are_cut_to_the_budget_and_resume_after_the_last_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-J21 / T-J6 / T-J14b: 200 wide rows at the default limit do not fit one response: the
    page ends sooner with truncated_by_bytes, within the budget, and walking next_offset reads
    every row once in the one-page order.

    MUTATION (verified RED, 1 failed): return the rows page without _fit_page -> the page holds
    all 200 rows, over the budget -> RED."""
    tool = _sink_tool(tmp_path, monkeypatch, 200)
    first = tool(diff_id=DX, detail="rows")
    assert first["total_rows"] == 200
    assert first.get("truncated_by_bytes") is True and 0 < len(first["rows"]) < 200
    assert first.get("next_offset") == len(first["rows"])
    assert len(json.dumps(first)) <= mcp_app._RESPONSE_BYTE_BUDGET and "over_budget" not in first
    seen, pages = _walk(tool, "rows", diff_id=DX, detail="rows")
    whole = tool(diff_id=DX, detail="rows", limit=2000, offset=0)
    assert "error" not in whole  # the documented 1..2000 range still holds
    order = [r.a_ref for r in so.page_overlay(_overlay_rows(200), limit=200, offset=0)["rows"]]
    assert [r["a_ref"] for r in seen] == order and len(set(order)) == 200
    assert all(len(json.dumps(p)) <= mcp_app._RESPONSE_BYTE_BUDGET for p in pages)
    assert pages[-1]["truncated_by_bytes"] is False


# ── get_function_alignment, ambiguous ─────────────────────────────────────────────────────────


def _ambiguous_world(tmp_path: Path, mp: pytest.MonkeyPatch, n: int) -> World:
    """``n`` side-a functions named ``dup``, each aligned to three side-b functions."""
    w = _build_world(tmp_path, mp)
    for i in range(n):
        for j in range(3):
            w.atlas.execute(
                "INSERT INTO function_alignment (diff_id, addr_a, addr_b, name_a, name_b, "
                "alignment_confidence, similarity, alignment_state, instructions, basicblocks) "
                "VALUES (?, ?, ?, 'dup', ?, 0.5, 0.5, 'alignment_undetermined', 4, 1)",
                (DX, f"{0x9000 + 0x10 * i:08x}", f"{0xA000 + 0x100 * i + j:08x}", f"b{j}"),
            )
    w.atlas.commit()
    return w


def test_ambiguous_candidates_page_with_each_candidates_pairs_whole(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-J13: five same-named functions, two candidates a page: each candidate carries all
    three of its pairs, total_candidates is exact and the pages together are the library's
    whole answer.

    MUTATION (verified RED, 1 failed): keep only a candidate's first pair in align_by_function
    -> RED."""
    w = _ambiguous_world(tmp_path, monkeypatch, 5)
    tool = mcp_app.make_tools(w.path)["get_function_alignment"]
    seen, pages = _walk(tool, "candidates", diff_id=DX, function="dup", limit=2)
    assert all(p["reason"] == "ambiguous" and p["total_candidates"] == 5 for p in pages)
    assert [len(p["candidates"]) for p in pages] == [2, 2, 1]
    assert all(len(c["pairs"]) == 3 for c in seen)
    lib = da.align_by_function(w.atlas, DX, "dup", "a")
    assert json.dumps(seen, sort_keys=True) == json.dumps(lib["candidates"], sort_keys=True)


def test_an_ambiguous_page_over_the_budget_keeps_whole_candidates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With a budget the envelope plus one candidate barely passes, the page is cut between
    candidates (truncated_by_bytes), never inside one: every candidate on every page has its
    three pairs, and the walk still reads all five.

    MUTATION (verified RED, 1 failed): keep only a candidate's first pair in align_by_function
    -> RED."""
    w = _ambiguous_world(tmp_path, monkeypatch, 5)
    tool = mcp_app.make_tools(w.path)["get_function_alignment"]
    one = tool(diff_id=DX, function="dup", limit=1)
    budget = len(json.dumps(one)) + 50
    monkeypatch.setattr(mcp_app, "_RESPONSE_BYTE_BUDGET", budget)
    seen, pages = _walk(tool, "candidates", diff_id=DX, function="dup", limit=5)
    assert pages[0]["truncated_by_bytes"] is True and len(pages[0]["candidates"]) < 5
    assert len(seen) == 5 and all(len(c["pairs"]) == 3 for c in seen)


# ── the blind whitelist stays the verdict-free tools ──────────────────────────────────────────


def test_the_paged_verdict_carrying_listings_stay_off_the_blind_whitelist() -> None:
    """T-J17: list_overlays carries verdicts, and the other three are not proven blind; none of
    them may be read as keeping a shadow judgement blind.

    MUTATION (verified RED, 1 failed): add list_diffs to BLIND_SAFE_TOOLS -> RED."""
    from treasure_map.lib.query import read_basis as rb

    for name in ("list_overlays", "list_diffs", "get_diff_sink_overlay", "list_diff_blindspots"):
        assert name not in rb.BLIND_SAFE_TOOLS, name
