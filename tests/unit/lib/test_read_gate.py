# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The read gate and the hand-off gate of a pair's review.

* A no_real_change / change_inconclusive on a must-read subject counts as disposed only when it was
  written after the subject was read whole (lib/query/review_units ``GATED_VERDICTS``): one written
  having read its candidate rows or its code in part reads needs_recheck, at the write
  (mcp_app._write_plan marks it) and at the report (read_audits). A changed_real read in part still
  counts (``basis_incomplete``).
* get_diff_handoff serves the official hand-off only once ``must_read_complete`` is true at the
  default k; the driver's ``--handoff`` holds the same bar; the command line's file is written all
  the same, marked PARTIAL.
* The report counts the disposed subjects and the pair's judgements by verdict; the progress block
  names the batch driver while the must-read set is not done.

Zero real data: the World of test_diff_review (two diffs of one run pair). A session's reads are
recorded through the real tool-call log (lib/tool_call_log ``build_line``) into a log handed to
make_tools, so the real write path reads them."""

from __future__ import annotations

import json
import re
import sqlite3
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
    _ref,
    _row,
)
from tests.unit.lib.test_review_units import _build_world, _diff_of, _review
from treasure_map import mcp_app
from treasure_map.lib import tool_call_log as tcl
from treasure_map.lib.query import coverage
from treasure_map.lib.query import review_report as rr
from treasure_map.lib.query import review_units as ru

# Must-read at every k (attention 0, one candidate row): the entry unit of A1-A4.
A1 = _pair_anchor(DX, "00001000", "00001000")
E1 = "pair:00001000:00001000"
# Must-read only at k >= 1 (top_k alone): second tier at k=0 — A5-A7.
A3 = _pair_anchor(DX, "00003000", "00003000")
E3 = "pair:00003000:00003000"


@pytest.fixture(autouse=True)
def _clear_unit_cache() -> None:
    ru.DIFF_CACHE.clear()
    mcp_app._HANDOFF_CACHE.clear()


def _code(w: World, addr: str) -> None:
    """A short function at ``addr`` in libx on both sides: one page of pseudocode."""
    for side in ("a", "b"):
        conn = sqlite3.connect(w.tmp / f"analysis_{side}.db")
        conn.execute(
            "INSERT INTO functions (binary_id, name, address, pseudocode, callees) "
            "VALUES (1, ?, ?, ?, '[]')",
            (f"fn_{addr}", addr, f"int fn_{addr}(void) {{\n    return {side!r};\n}}\n"),
        )
        conn.commit()
        conn.close()


@pytest.fixture
def gw(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> World:
    w = _build_world(tmp_path, monkeypatch)
    _code(w, "00001000")
    _code(w, "00003000")
    return w


class Sess:
    """One server session: a tool-call log of its own (its reads recorded through the real
    ``build_line``) and the tools bound to it, so a write reads them as the server does."""

    def __init__(self, w: World, name: str) -> None:
        self.w = w
        self.log = tcl.ToolCallLog(w.tmp / "calls.jsonl", tcl.Session(id=name))
        self.tools = mcp_app.make_tools(w.path, call_log=self.log)

    def start(self, k: int) -> None:
        """A start_diff_review(run_pair, k) answered: the k the session's writes are read at."""
        self.log.record("start_diff_review", {"run_pair": PAIR, "k": k}, {"run_pair": PAIR})

    def deliver(self, unit_id: str, *, cut: bool) -> None:
        """The unit handed out with its one-subject material, cut or whole."""
        self.log.record(
            "start_diff_review",
            {"run_pair": PAIR, "unit": unit_id},
            {"unit": {"unit_id": unit_id, "material_cut": cut}, "material": {"entry": {}}},
        )

    def entry_read(self, entry_id: str, *, shown: bool, rows: tuple[int, int, int]) -> None:
        """get_diff_patch_view(entry_id) answered with its hunk shown whole or held back, and
        candidate rows ``rows`` = (offset, how many, total)."""
        off, n, total = rows
        hunk = {"lines": ["- a", "+ b"]} if shown else {"withheld": "over_gate"}
        entry = {
            "entry_id": entry_id,
            "rows": [{}] * n,
            "rows_total": total,
            "rows_offset": off,
            "pseudocode_delta": {"kind": "structural", "inline_hunk": hunk},
        }
        self.log.record(
            "get_diff_patch_view",
            {"diff_id": DX, "entry_id": entry_id, "rows_offset": off},
            {"entries": [entry]},
        )

    def read_code(self, addr: str) -> None:
        """A real get_pseudocode of the B side, whole in one page, recorded."""
        args = {"run_id": "runB", "function": f"0x{addr}"}
        res = self.tools["get_pseudocode"](**args)
        assert res.get("paging", {}).get("truncated") is False, res.get("paging")
        self.log.record("get_pseudocode", args, res)

    def judge(self, anchor: str, verdict: str, unit_id: str | None = None) -> dict[str, Any]:
        args: dict[str, Any] = {
            "anchor_ref": anchor,
            "verdict": verdict,
            "rationale": "r",
            "diff_id": _diff_of(anchor),
        }
        if verdict == "no_real_change":
            args.update(checked=[anchor], why_unchanged="the same call")
        if unit_id is not None:
            args["unit_id"] = unit_id
        got: dict[str, Any] = self.tools["annotate_diff"](**args)
        assert got.get("written") is True, got
        return got


def _unit_of(w: World, anchor: str, k: int) -> str:
    (uid,) = [
        u.unit_id
        for u in _review(w, k=k).units
        if u.must_read and u.kind == ru.ENTRY and any(m.anchor_ref == anchor for m in u.members)
    ]
    return uid


def _basis(got: dict[str, Any]) -> tuple[dict[str, Any], Any]:
    rb = dict(got["read_basis"])
    return rb, rb.pop("unread_before_verdict", None)


def _state(w: World, anchor: str, k: int = ru.DEFAULT_K) -> str | None:
    ru.DIFF_CACHE.clear()
    return _review(w, k=k).progress.states.get(anchor)


# ── M1: the read gate ─────────────────────────────────────────────────────────────────────────


def test_a1_a_held_back_hunk_read_by_entry_alone_holds_back_a_no_real_change(gw: World) -> None:
    """★ A1: an entry unit handed out with its hunk held back, read on by its entry_id
    (code_shown false, every candidate row in the window) and no side's code: a no_real_change
    then reads ``unit_delivered`` + ``material_cut`` + ``read_partial: "pages"`` — marked unread,
    needs_recheck, not disposed. A side's code read whole and judged again: concluded.

    MUTATION (verified RED, 1 failed): leave read_partial out of review_units.read_short -> the
    write is not marked -> RED."""
    s = Sess(gw, "s1")
    s.start(4)
    unit = _unit_of(gw, A1, 4)
    before = _review(gw, k=4).report["must_read"]["members_disposed"]
    s.deliver(unit, cut=True)
    s.entry_read(E1, shown=False, rows=(0, 1, 1))
    got = s.judge(A1, "no_real_change", unit)
    basis, flag = _basis(got)
    assert basis == {"basis": "unit_delivered", "material_cut": True, "read_partial": "pages"}
    assert flag is True
    assert got.get("needs_recheck") == mcp_app._JUDGED_PART_READ
    assert _state(gw, A1) == coverage.NEEDS_RECHECK
    rep = _review(gw, k=4)
    assert rep.report["must_read"]["members_disposed"] == before
    assert A1 in rep.audits.read_in_part
    s.read_code("00001000")
    got = s.judge(A1, "no_real_change", unit)
    basis, flag = _basis(got)
    assert basis == {"basis": "unit_delivered", "material_cut": True} and not flag
    assert _state(gw, A1) == coverage.CONCLUDED


def test_a2_a_changed_real_read_in_part_still_counts(gw: World) -> None:
    """★ A2: the same reading as A1 with a changed_real: not marked, disposed, counted under
    ``basis_incomplete``.

    MUTATION (verified RED, 1 failed): drop the GATED_VERDICTS check from
    review_units.gated_short (every verdict read in part held back) -> RED."""
    s = Sess(gw, "s1")
    s.start(4)
    unit = _unit_of(gw, A1, 4)
    s.deliver(unit, cut=True)
    s.entry_read(E1, shown=False, rows=(0, 1, 1))
    got = s.judge(A1, "changed_real", unit)
    basis, flag = _basis(got)
    assert basis == {"basis": "unit_delivered", "material_cut": True, "read_partial": "pages"}
    assert not flag and "needs_recheck" not in got
    assert _state(gw, A1) == coverage.CONCLUDED
    assert A1 in _review(gw, k=4).audits.basis_incomplete


def test_a3_part_of_the_candidate_rows_holds_back_a_change_inconclusive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ A3: an entry of 25 candidate rows read by its entry_id for its first page only (the real
    view, rows 0-20): ``rows_partial`` and no ``read_partial`` — a change_inconclusive written then
    reads needs_recheck.

    MUTATION (verified RED, 1 failed): leave rows_partial out of review_units.read_short -> RED."""
    w = _build_world(tmp_path, monkeypatch)
    w.rows[DX] = [
        _row(_ref("runA", "00001000", at=f"0x{16 + j:x}"), None, reason="present_different_callee")
        for j in range(25)
    ]
    assert A1 in {m.anchor_ref for u in _review(w, k=4).units if u.must_read for m in u.members}
    s = Sess(w, "s1")
    s.start(4)
    args = {"diff_id": DX, "entry_id": E1}
    page = s.tools["get_diff_patch_view"](**args)
    (one,) = page["entries"]
    assert (one["rows_total"], one["rows_next_offset"]) == (25, 20)  # the precondition
    s.log.record("get_diff_patch_view", args, page)
    got = s.judge(A1, "change_inconclusive")
    basis, flag = _basis(got)
    assert basis.get("rows_partial") is True and "read_partial" not in basis, basis
    assert flag is True
    assert _state(w, A1) == coverage.NEEDS_RECHECK


def test_a4_two_writes_read_in_part_then_one_read_whole(gw: World) -> None:
    """★ A4: a no_real_change read in part, written twice, reads needs_recheck after each; the
    third, written after reading the code whole, reads concluded."""
    s = Sess(gw, "s1")
    s.start(4)
    unit = _unit_of(gw, A1, 4)
    s.deliver(unit, cut=True)
    s.entry_read(E1, shown=False, rows=(0, 1, 1))
    for _ in range(2):
        s.judge(A1, "no_real_change", unit)
        assert _state(gw, A1) == coverage.NEEDS_RECHECK
    s.read_code("00001000")
    s.judge(A1, "no_real_change", unit)
    assert _state(gw, A1) == coverage.CONCLUDED


def _part_read_session(w: World, name: str, k: int) -> Sess:
    s = Sess(w, name)
    s.start(k)
    s.entry_read(E3, shown=False, rows=(0, 0, 0))
    return s


def test_a5_an_unmarked_write_read_in_part_does_not_clear_a_marked_one(gw: World) -> None:
    """★ A5 (R2): a no_real_change read in part, marked (written at k=4, where it is must-read),
    then another session's — at k=0, where it is not, so unmarked — read in part too: the first
    still holds it. Read at k=0 (where the latest write alone would not set it): needs_recheck.

    MUTATION (verified RED, 1 failed): clear on any write whose basis is not ``none`` (drop
    ``not gated_short`` in read_audits) -> disposed at k=0 -> RED."""
    first = _part_read_session(gw, "s4", 4).judge(A3, "no_real_change")
    assert _basis(first)[1] is True  # the precondition: marked
    second = _part_read_session(gw, "s0", 0).judge(A3, "no_real_change")
    basis, flag = _basis(second)
    assert basis == {"basis": "fetched", "read_partial": "pages"} and not flag  # unmarked
    assert _state(gw, A3, k=0) == coverage.NEEDS_RECHECK


def test_a6_a_write_read_in_part_at_a_smaller_k_is_held_back_at_the_reports_k(gw: World) -> None:
    """★ A6 (R3): a no_real_change read in part written at k=0 (not must-read there, unmarked) is
    disposed at k=0 and reads needs_recheck at k=4, where the subject is must-read.

    MUTATION (verified RED, 1 failed): R3 only for a latest write with basis ``none`` (read_audits
    tests ``basis == "none"`` instead of ``held_unread``) -> concluded at k=4 -> RED."""
    got = _part_read_session(gw, "s0", 0).judge(A3, "no_real_change")
    assert _basis(got)[1] in (None, False)  # the precondition: unmarked
    assert _state(gw, A3, k=0) == coverage.CONCLUDED
    assert _state(gw, A3, k=4) == coverage.NEEDS_RECHECK


def test_a7_a_changed_real_read_in_part_clears_a_marked_write(gw: World) -> None:
    """★ A7: a marked no_real_change read in part, then a changed_real read the same way: disposed
    (a changed_real is not held back), counted under basis_incomplete.

    MUTATION (verified RED, 1 failed): clear only on a write read whole (``not read_short`` for
    every verdict in read_audits) -> needs_recheck -> RED."""
    s = _part_read_session(gw, "s4", 4)
    assert _basis(s.judge(A3, "no_real_change"))[1] is True
    s.judge(A3, "changed_real")
    assert _state(gw, A3) == coverage.CONCLUDED
    assert A3 in _review(gw, k=4).audits.basis_incomplete


def test_a8_the_report_counts_the_two_causes(gw: World) -> None:
    """★ A8: one subject judged having read nothing (any verdict), one a no_real_change read in
    part: ``judged_unread.by_cause`` is {unread 1, read_in_part 1} and the coverage statement says
    "judged unread 2 (read in part 1)".

    MUTATION (verified RED, 1 failed): count every judged-unread subject as read in part (in_part
    = len(needs_recheck) in report) -> RED."""
    s = _part_read_session(gw, "s4", 4)
    s.judge(A1, "changed_real")  # nothing of it read
    s.judge(A3, "no_real_change")
    rep = _review(gw, k=4).report
    assert rep["judged_unread"]["count"] == 2
    assert rep["judged_unread"]["by_cause"] == {"unread": 1, "read_in_part": 1}
    assert "judged unread 2 (read in part 1);" in rep["coverage_statement"]


# ── M3: the dispositions ──────────────────────────────────────────────────────────────────────


def _judge_must(
    w: World, k: int, verdict: str = "changed_real", skip: tuple[str, ...] = ()
) -> None:
    """Every must-read member at ``k`` judged (no read basis: not held back)."""
    ru.DIFF_CACHE.clear()
    for u in _review(w, k=k).units:
        if not u.must_read or u.kind in (ru.AUDIT, ru.REDUCE):
            continue
        for m in u.members:
            if m.anchor_ref in skip:
                continue
            basis = (
                {"checked": [m.anchor_ref], "why_unchanged": "same"}
                if verdict == "no_real_change"
                else None
            )
            w.judge(_diff_of(m.anchor_ref), m.anchor_ref, verdict, verdict_basis=basis)
    ru.DIFF_CACHE.clear()


def _copy_judgements_to(w: World, pair: str) -> int:
    """Every diff_subject judgement of the pair copied, as it is, under another run pair (its
    anchors moved to that pair)."""
    cols = [r[1] for r in w.atlas.execute("PRAGMA table_info(overlay)") if r[1] != "id"]
    moved = {"run_id": "?", "anchor_ref": "replace(anchor_ref, ?, ?)"}
    sel = ", ".join(moved.get(c, c) for c in cols)
    args: list[str] = []
    for c in cols:
        if c == "run_id":
            args.append(pair)
        elif c == "anchor_ref":
            args += [PAIR, pair]
    cur = w.atlas.execute(
        f"INSERT INTO overlay ({', '.join(cols)}) SELECT {sel} FROM overlay "  # noqa: S608
        "WHERE anchor_kind = 'diff_subject' AND run_id = ?",
        (*args, PAIR),
    )
    w.atlas.commit()
    return cur.rowcount


def test_c2_the_dispositions_are_the_pairs_own(gw: World) -> None:
    """★ C2: the verdict counts read this pair's judgements only — another pair's (here copies of
    them under another run pair) count nothing.

    MUTATION (verified RED, 1 failed): read the judgements of every pair (drop ``AND run_id = ?``
    from read_audits' current rows) -> recorded doubles -> RED."""
    gw.judge(DX, A1, "changed_real")
    gw.judge(DX, A3, "no_real_change", verdict_basis={"checked": [A3], "why_unchanged": "s"})
    assert _copy_judgements_to(gw, "runA::runC") == 2  # the other pair's judgements
    rep = _review(gw, k=4).report
    assert rep["verdicts"]["recorded"] == {
        "changed_real": 1,
        "no_real_change": 1,
        "change_inconclusive": 0,
    }
    assert rep["verdicts"]["disposed"] == {
        "changed_real": 1,
        "no_real_change": 1,
        "change_inconclusive": 0,
        "without_verdict": 0,
    }
    assert "verdicts disposed 1/1/0, recorded 1/1/0 (" in rep["coverage_statement"]
    p = mcp_app.make_tools(gw.path)["start_diff_review"](run_pair=PAIR)
    assert p["report"]["verdicts"] == rep["verdicts"]
    assert p["progress"]["dispositions"] == rep["verdicts"]["disposed"]
    assert "dispositions" in p["progress"]["pair_wide"]


def _wide(w: World) -> None:
    """Three more aligned pairs in libx: past the first k=4, so DX has a second tier."""
    for addr in ("00007000", "00008000", "00009000"):
        w.pair(DX, addr, addr, conf=0.97, sim=0.7)


def _second_tier(w: World, k: int = ru.DEFAULT_K) -> str:
    ru.DIFF_CACHE.clear()
    return next(
        m.anchor_ref for u in _review(w, k=k).units if u.kind == ru.SECOND_TIER for m in u.members
    )


def test_c3_the_handoff_header_counts_a_second_tier_judgement(gw: World) -> None:
    """★ C3: with the must-read set done, a judgement on a second-tier member (the findings
    unchanged) moves the disposed count in the header page (offset 0).

    MUTATION (verified RED, 1 failed): cache the header with the blocks again (serve the cached
    header while the findings digest is the same) -> RED."""
    _wide(gw)
    _judge_must(gw, 4)
    tools = mcp_app.make_tools(gw.path)
    first = tools["get_diff_handoff"](PAIR, 0)
    assert "text" in first, first
    n = int(re.search(r"_Of (\d+) disposed subjects", first["text"]).group(1))  # type: ignore[union-attr]
    other = _second_tier(gw)
    gw.judge(DX, other, "no_real_change", verdict_basis={"checked": [other], "why_unchanged": "s"})
    again = tools["get_diff_handoff"](PAIR, 0)
    assert again["findings_digest"] == first["findings_digest"]  # the precondition
    assert f"_Of {n + 1} disposed subjects" in again["text"], again["text"][:400]


# ── M2: the hand-off gate ─────────────────────────────────────────────────────────────────────


def test_b1_an_incomplete_pair_is_refused_with_its_progress(gw: World) -> None:
    """★ B1: get_diff_handoff on a pair whose must-read set is not done: refused
    (``must_read_incomplete``), no block, with the review's progress (still_open, resume_with, the
    driver) and where a partial one is written — on every page, offset 1 too.

    MUTATION (verified RED, 1 failed): invert the gate (refuse when must_read_complete) -> RED."""
    gw.judge(DX, A1, "changed_real")  # a finding, so a served page would carry a block
    tools = mcp_app.make_tools(gw.path)
    for off in (0, 1):
        got = tools["get_diff_handoff"](PAIR, off)
        assert got.get("refused") == "must_read_incomplete", got
        assert "text" not in got and got["must_read_complete"] is False
        p = got["progress"]
        assert {"still_open", "resume_with", "must_read_left"} <= set(p)
        assert "tmap review run runA::runB --agent <preset>" in p["if_this_context_fills"]
        assert f"tmap review report {PAIR} --handoff -o <file>" in got["note"]
        assert p["resume_with"] in got["note"]


def test_b1_a_review_that_cannot_be_read_is_refused(
    gw: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The gate fails closed: a review that raises is refused as ``must_read_unknown``."""

    def boom(*a: Any, **k: Any) -> Any:
        raise RuntimeError("cannot read")

    _judge_must(gw, 4)
    monkeypatch.setattr(ru, "review_pair", boom)
    got = mcp_app.make_tools(gw.path)["get_diff_handoff"](PAIR, 0)
    assert got.get("refused") == "must_read_unknown" and "cannot read" in got["error"]


def test_b2_a_done_pair_is_served(gw: World) -> None:
    """★ B2: every must-read member judged: the hand-off is served, its header counting the
    disposed subjects, with no PARTIAL line."""
    _judge_must(gw, 4)
    got = mcp_app.make_tools(gw.path)["get_diff_handoff"](PAIR, 0)
    assert "refused" not in got and got["text"].startswith("# Findings hand-off for runA::runB")
    assert "_Of 6 disposed subjects: 6 changed_real / 0 no_real_change" in got["text"]
    assert "PARTIAL" not in got["text"]


def _cli_handoff(w: World, out: Path) -> Any:
    from click.testing import CliRunner

    from treasure_map.cli import review_cli

    return CliRunner().invoke(
        review_cli.review, ["report", PAIR, "--handoff", "-o", str(out), "--atlas", str(w.path)]
    )


def _pages(w: World) -> str:
    tools = mcp_app.make_tools(w.path)
    pages, off = [], 0
    while off is not None:
        r = tools["get_diff_handoff"](PAIR, off)
        assert "text" in r, r
        pages.append(r["text"])
        off = r["next_offset"]
    return "".join(pages)


def test_b3_the_command_line_writes_a_partial_file_before_and_the_mcp_text_after(
    gw: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ B3: before the must-read set is done, ``review report --handoff`` still writes the file,
    its header saying PARTIAL; once done, the file is the MCP pages byte for byte.

    MUTATION (verified RED, 1 failed): leave the PARTIAL line out of handoff_header -> RED."""
    from treasure_map import version
    from treasure_map.version import UNKNOWN_VERSION

    monkeypatch.setattr(version, "installed_commit", lambda: UNKNOWN_VERSION)
    gw.judge(DX, A1, "changed_real")
    out = gw.tmp / "h.md"
    res = _cli_handoff(gw, out)
    assert res.exit_code == 0, res.output
    text = out.read_text(encoding="utf-8")
    assert "_must_read_complete false: a PARTIAL hand-off, not the official one — 5 must-read" in (
        text
    )
    assert "PARTIAL" in res.output
    _judge_must(gw, 4, skip=(A1,))
    res = _cli_handoff(gw, out)
    assert res.exit_code == 0 and "PARTIAL" not in res.output, res.output
    assert out.read_text(encoding="utf-8") == _pages(gw)


def _drive_result(w: World, k: int) -> Any:
    """A finished drive at ``k``, its stop read from the review at ``k`` (as rd.drive's)."""
    from treasure_map.lib import review_driver as rd

    ru.DIFF_CACHE.clear()
    review = _review(w, k=k)
    offer = ru.coverage_offer(review, worker=None, workers=None, sweep=False)
    return rd.DriveResult(stopped="no must-read unit left", finished=True, offer=offer)


def _held(w: World, k: int) -> str | None:
    from treasure_map.cli import review_cli

    staleness = {"source_stale": False, "source_stale_reason": None}
    return review_cli._handoff_held(_drive_result(w, k), str(w.path), "runA", "runB", k, staleness)


def test_b4_a_drive_stopped_at_a_limit_writes_no_handoff(gw: World) -> None:
    """★ B4: a drive stopped at --max-units is not finished: the hand-off is held (the command line
    end to end: test_handoff ``test_the_handoff_is_skipped_while_the_review_is_not_done``)."""
    from treasure_map.cli import review_cli
    from treasure_map.lib import review_driver as rd

    stopped = rd.DriveResult(stopped="max_units 5 reached", finished=False)
    held = review_cli._handoff_held(stopped, str(gw.path), "runA", "runB", 4, {})
    assert held is not None and "max_units 5 reached" in held


def test_b5_a_withheld_diff_holds_the_handoff_though_the_drive_finished(
    gw: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ B5: a pair with a withheld diff and every other must-read member disposed: the drive
    finishes (no unit left), yet the hand-off is held — the driver writes none and the MCP tool
    refuses, ``still_open.withheld_diffs`` naming it.

    MUTATION (verified RED, 1 failed): the driver's bar back to finished alone (drop the
    must_read_complete check from _handoff_held) -> RED."""
    from click.testing import CliRunner

    from treasure_map.cli import review_cli
    from treasure_map.lib import review_driver as rd

    _judge_must(gw, 4)
    gw.atlas.execute("UPDATE diff_meta SET version_skew = 1 WHERE diff_id = ?", (DY,))
    gw.atlas.commit()
    ru.DIFF_CACHE.clear()
    result = _drive_result(gw, 4)
    assert result.finished and result.offer["must_read_complete"] is False  # the precondition
    held = _held(gw, 4)
    assert held is not None and "withheld diffs 1" in held, held
    got = mcp_app.make_tools(gw.path)["get_diff_handoff"](PAIR, 0)
    assert got.get("refused") == "must_read_incomplete"
    assert got["progress"]["still_open"]["withheld_diffs"] == 1
    # Through the command line: the drive faked to that stop, the hand-off launch never made.
    launched: list[Any] = []
    monkeypatch.setattr(rd, "probe", lambda *a, **k: rd.ProbeResult(True, True, True, "faked"))
    monkeypatch.setattr(rd, "drive", lambda *a, **k: result)
    monkeypatch.setattr(rd, "run_handoff", lambda *a, **k: launched.append(a) or {"ok": True})
    monkeypatch.setattr(ru, "pair_staleness", lambda *a, **k: {"source_stale": False})
    res = CliRunner().invoke(
        review_cli.review,
        [
            "run",
            PAIR,
            "--agent",
            "claude-code",
            "--handoff",
            str(gw.tmp / "h.md"),
            "--atlas",
            str(gw.path),
        ],
    )
    assert "hand-off skipped: must_read_complete false" in res.output, res.output
    assert launched == []


def test_b6_the_gate_is_read_afresh_not_by_the_findings_digest(gw: World) -> None:
    """★ B6: in one process, refused while one must-read member is unjudged; that member judged
    no_real_change (the findings, so their digest, unchanged): served.

    MUTATION (verified RED, 1 failed): keep must_read_complete per findings digest (answer the
    second call from the first call's reading) -> refused again -> RED."""
    _judge_must(gw, 4, skip=(A3,))
    tools = mcp_app.make_tools(gw.path)
    before = rr.handoff_findings(gw.atlas, PAIR)
    assert tools["get_diff_handoff"](PAIR, 0).get("refused") == "must_read_incomplete"
    gw.judge(DX, A3, "no_real_change", verdict_basis={"checked": [A3], "why_unchanged": "s"})
    assert rr.handoff_findings(gw.atlas, PAIR) == before  # the precondition: same findings
    got = tools["get_diff_handoff"](PAIR, 0)
    assert "refused" not in got and "text" in got, got


def test_b7_the_official_bar_is_the_default_k(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ B7: the must-read set done at k=0 but not at k=4: refused, and a ``--k 0`` drive writes
    no hand-off; done at k=8 (which holds k=4's): served, and a ``--k 8`` drive writes it.

    MUTATION (verified RED, 1 failed): read the drive's own k (no second reading at the default)
    in _handoff_held -> the k=0 drive writes it -> RED."""
    w = _build_world(tmp_path, monkeypatch)
    _wide(w)
    _judge_must(w, 0)
    ru.DIFF_CACHE.clear()
    assert _review(w, k=0).report["must_read_complete"] is True  # the precondition
    assert _review(w, k=4).report["must_read_complete"] is False
    assert mcp_app.make_tools(w.path)["get_diff_handoff"](PAIR, 0).get("refused")
    held = _held(w, 0)
    assert held is not None and f"default k={ru.DEFAULT_K}" in held
    _judge_must(w, 8)
    assert _held(w, 8) is None
    assert "text" in mcp_app.make_tools(w.path)["get_diff_handoff"](PAIR, 0)


# ── M4: the driver named while the must-read set is not done ──────────────────────────────────


def test_d1_the_driver_is_named_only_while_the_must_read_set_is_open(gw: World) -> None:
    """★ D1: start_diff_review's progress carries ``if_this_context_fills`` (the driver's command)
    while the must-read set is not done, and not once it is.

    MUTATION (verified RED, 1 failed): say it whatever must_read_complete reads -> RED."""
    tools = mcp_app.make_tools(gw.path)
    p = tools["start_diff_review"](run_pair=PAIR)["progress"]
    assert p["must_read_complete"] is False
    assert p["if_this_context_fills"].startswith("A must-read set too large for one context")
    assert (
        "tmap review run runA::runB --agent <preset> (preset: claude-code;"
        in (p["if_this_context_fills"])
    )
    _judge_must(gw, 4)
    p = tools["start_diff_review"](run_pair=PAIR)["progress"]
    assert p["must_read_complete"] is True and "if_this_context_fills" not in p


def test_d2_the_drivers_command_keeps_the_sessions_reading(gw: World) -> None:
    """★ D2: at k=8 in shard 1 of 3, the driver's command carries ``--k 8 --worker 1 --workers
    3`` — the reading this session is on (as resume_with does).

    MUTATION (verified RED, 1 failed): leave the shard out of the driver's command -> RED."""
    tools = mcp_app.make_tools(gw.path)
    out = tools["start_diff_review"](run_pair=PAIR, k=8, worker=1, workers=3)
    said = out["progress"]["if_this_context_fills"]
    assert "tmap review run runA::runB --agent <preset> --k 8 --worker 1 --workers 3 (" in said
    assert json.loads(json.dumps(out))  # the answer stays JSON
