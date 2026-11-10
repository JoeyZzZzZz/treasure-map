# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""A pair's review in several sessions: every answer that hands a unit out, or stops, carries
``progress`` (lib/query/review_units ``progress_block``) — what this session was handed, what is
left of the must-read part, the reduce owed, ``must_read_complete`` and the rest of what keeps it
false, the coverage statement, whose counts are the whole pair's, and the call a fresh session
continues with. A fresh session's start_diff_review(run_pair) continues where the last one
stopped.

Zero real data: the worlds of test_review_units / test_must_read_first (two diffs of one run
pair) and of test_callee_groups (a callee group and its reduce)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from tests.unit.lib.test_callee_groups import (
    _fresh,  # noqa: F401 — the autouse cache fixture
    _judge_every_entry,
)
from tests.unit.lib.test_callee_groups import _world as _cg_world
from tests.unit.lib.test_diff_review import (  # noqa: F401 — the autouse cache fixture
    DX,
    DY,
    PAIR,
    World,
    _clear_view_caches,
)
from tests.unit.lib.test_must_read_first import FAILED_DIFF, _mixed
from tests.unit.lib.test_review_units import (
    _assert_page_members,
    _build_world,
    _diff_of,
    _hex_world,
    _judge_args,
    _review,
    _server_call,
)
from treasure_map import mcp_app
from treasure_map.lib import overlay
from treasure_map.lib import tool_call_log as tcl
from treasure_map.lib.query import diff_skill
from treasure_map.lib.query import review_units as ru

PROGRESS_KEYS = {
    "this_session",
    "must_read_left",
    "reduce_owed",
    "must_read_complete",
    "still_open",
    "coverage_statement",
    "scope",
    "pair_wide",
    "resume_with",
}
STILL_OPEN_KEYS = {
    "failed_diffs",
    "withheld_diffs",
    "audits_open",
    "disagreements",
    "judged_unread",
}
PAIR_WIDE = [
    "must_read_left",
    "reduce_owed",
    "must_read_complete",
    "coverage_statement",
    "still_open",
]


@pytest.fixture(autouse=True)
def _clear_unit_cache() -> None:
    ru.DIFF_CACHE.clear()


def _session_lines(w: World, server: Any) -> list[dict[str, Any]]:
    lines = tcl.read_lines(tcl.log_path_for(w.path))
    assert lines is not None
    return [ln for ln in lines if ln.get("session") == server._call_log.session.id]


def _batch(server: Any, nu: dict[str, Any]) -> dict[str, Any]:
    """Judge every member of the unit ``nu`` in one batch write naming it."""
    diffs = {_diff_of(m["anchor_ref"]) for m in nu["members"]}
    assert len(diffs) == 1, diffs  # the precondition: one diff's members
    items = [
        {"anchor_ref": m["anchor_ref"], "verdict": "changed_real", "rationale": "r"}
        for m in nu["members"]
    ]
    out = _server_call(
        server,
        "annotate_diff_batch",
        {"annotations": items, "diff_id": diffs.pop(), "unit_id": nu["unit_id"]},
    )
    assert out.get("written") is True, out
    return out


def _must_read_loop(server: Any, *, k: int = 0, **extra: Any) -> dict[str, Any]:
    """Judge every unit handed out until none is: the last write's answer."""
    answer = _server_call(server, "start_diff_review", {"run_pair": PAIR, "k": k, **extra})
    nu = answer["next_unit"]
    for _ in range(40):
        if nu is None:
            return answer
        answer = _batch(server, nu)
        nu = answer["next_unit"]
    raise AssertionError("the loop did not end")


# ── this session ──────────────────────────────────────────────────────────────────────────────


def test_this_session_counts_what_was_handed_before_this_answer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ T-F1a: an overview, a write, a write, in one session (after another session's calls on
    the same log): ``units_handed`` reads 0, 1, 2 and ``response_bytes`` the sum of this
    session's log lines before each answer — the answer itself not in it.

    MUTATION (verified RED, 1 failed): count every line of the log (the other session's too) ->
    RED. MUTATION (verified RED, 1 failed): count the answer being sent (one more unit) -> 1, 2, 3
    -> RED."""
    w = _build_world(tmp_path, monkeypatch)
    other = mcp_app.build_server(w.path)
    _server_call(other, "start_diff_review", {"run_pair": PAIR, "k": 0})
    server = mcp_app.build_server(w.path)
    seen: list[dict[str, Any]] = []
    expected: list[int] = []
    expected.append(sum(ln["response_bytes"] for ln in _session_lines(w, server)))
    head = _server_call(server, "start_diff_review", {"run_pair": PAIR, "k": 0})
    seen.append(head["progress"]["this_session"])
    nu = head["next_unit"]
    for _ in range(2):
        expected.append(sum(ln["response_bytes"] for ln in _session_lines(w, server)))
        out = _batch(server, nu)
        seen.append(out["progress"]["this_session"])
        nu = out["next_unit"]
        assert nu is not None
    assert [s["units_handed"] for s in seen] == [0, 1, 2], seen
    assert [s["response_bytes"] for s in seen] == expected, (seen, expected)
    assert expected[0] == 0 and expected[1] > 0  # the other session's call is not counted


def test_a_second_session_on_the_same_log_counts_its_own(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ T-F1b: a second server session on the same log file counts only its own lines.

    MUTATION (verified RED, 1 failed): leave out the session filter -> the first session's
    bytes and unit counted -> RED."""
    w = _build_world(tmp_path, monkeypatch)
    first = mcp_app.build_server(w.path)
    _batch(first, _server_call(first, "start_diff_review", {"run_pair": PAIR, "k": 0})["next_unit"])
    assert _session_lines(w, first)  # the precondition: the first session's lines are there
    second = mcp_app.build_server(w.path)
    got = _server_call(second, "start_diff_review", {"run_pair": PAIR, "k": 0})
    assert got["progress"]["this_session"] == {"units_handed": 0, "response_bytes": 0}
    nxt = _batch(second, got["next_unit"])
    mine = _session_lines(w, second)
    assert nxt["progress"]["this_session"] == {
        "units_handed": 1,
        "response_bytes": sum(ln["response_bytes"] for ln in mine[:-1]),
    }


def test_without_a_log_this_session_is_unknown_and_the_rest_is_given(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-F1j: no tool-call log: ``this_session`` is null and says why; every other field is
    there, at the overview and in a write's answer."""
    w = _build_world(tmp_path, monkeypatch)
    tools = mcp_app.make_tools(w.path)  # no call log
    head = tools["start_diff_review"](run_pair=PAIR, k=0)
    nu = head["next_unit"]
    out = tools["annotate_diff"](**_judge_args(nu["members"][0], nu["unit_id"]))
    for p in (head["progress"], out["progress"]):
        assert p["this_session"] is None
        assert p["this_session_unavailable"] == "no tool-call log for this session"
        assert set(p) == PROGRESS_KEYS | {"this_session_unavailable"}


# ── what is left ──────────────────────────────────────────────────────────────────────────────


def test_what_is_left_is_the_must_read_part(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ T-F1c: judging one must-read member takes one off ``must_read_left.members``, which is
    the report's must-read members less those disposed — not every listed subject's (the world
    has a second tier).

    MUTATION (verified RED, 1 failed): count from all_listed -> RED."""
    w = _mixed(tmp_path, monkeypatch)
    server = mcp_app.build_server(w.path)
    head = _server_call(server, "start_diff_review", {"run_pair": PAIR, "k": 0})
    before = head["progress"]["must_read_left"]
    mr = head["report"]["must_read"]
    assert head["report"]["all_listed"]["members"] > mr["members"]  # the precondition
    assert before == {
        "units": mr["units"] - mr["units_disposed"],
        "members": mr["members"] - mr["members_disposed"],
    }
    nu = head["next_unit"]
    out = _server_call(server, "annotate_diff", _judge_args(nu["members"][0], nu["unit_id"]))
    assert out["progress"]["must_read_left"]["members"] == before["members"] - 1
    rep = _review(w, k=0).report["must_read"]
    assert out["progress"]["must_read_left"]["members"] == rep["members"] - rep["members_disposed"]


def _reduce_owed_world(tmp_path: Path) -> Any:
    """Every subject judged without its group_ref: only the reduce is owed."""
    w = _cg_world(tmp_path)
    _judge_every_entry(w)
    return w


def test_only_the_reduce_left(tmp_path: Path) -> None:
    """★ T-F1d / T-F1e: every must-read subject judged and the reduce still owed: no must-read
    unit left, ``reduce_owed`` the report's own count (an integer, read as it is), and
    ``must_read_complete`` false — none of the three stands for "done" alone.

    MUTATION (verified RED, 1 failed): leave reduce_owed out -> RED. MUTATION (verified RED, 1
    failed): give must_read_complete as "no must-read unit left" -> true -> RED. MUTATION
    (verified RED, 1 failed, TypeError): read reduce_owed as len(report["reduce"]["owed"])."""
    w = _reduce_owed_world(tmp_path)
    tools = mcp_app.make_tools(w.path)
    head = tools["start_diff_review"](run_pair=PAIR)
    p = head["progress"]
    assert head["next_unit"]["kind"] == ru.REDUCE  # the precondition
    owed = _review(w).report["reduce"]["owed"]
    assert isinstance(owed, int) and owed > 0
    assert p.get("reduce_owed") == owed
    assert p["must_read_left"] == {"units": 0, "members": 0}
    assert p["must_read_complete"] is False


@pytest.mark.parametrize(
    "cause",
    ["must_read_left", "withheld_diffs", "failed_diffs", "disagreements", "judged_unread"],
)
def test_every_cause_of_an_incomplete_must_read_part_is_shown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cause: str
) -> None:
    """★ T-F1f / T-F1g: each condition that keeps ``must_read_complete`` false shows in a field
    of its own — a must-read member not disposed (``must_read_left``), a withheld diff, a failed
    diff, a disagreement, a subject judged unread (``still_open``); the reduce is
    test_only_the_reduce_left. With every must-read member disposed and nothing owed, a withheld
    diff is the only field that says why it is false (T-F1f). The seventh condition, an open blind
    audit, cannot be made: blind auditing is sealed (``BLIND_AUDIT_ENABLED`` False), so
    ``audits.open`` is always null and so is ``still_open.audits_open`` — asserted, not turned on.

    MUTATION (verified RED, 1 of 5 failed each): give any one of still_open's withheld_diffs /
    failed_diffs / disagreements / judged_unread as 0 -> that case RED. MUTATION (verified RED, 5
    of 5 failed): leave still_open out -> RED."""
    assert ru.BLIND_AUDIT_ENABLED is False
    w = _build_world(tmp_path, monkeypatch)
    if cause == "withheld_diffs":
        w.atlas.execute("UPDATE diff_meta SET version_skew = 1 WHERE diff_id = ?", (DY,))
    elif cause == "failed_diffs":
        w.atlas.execute(FAILED_DIFF)
    w.atlas.commit()
    server = mcp_app.build_server(w.path)
    if cause != "must_read_left":
        _must_read_loop(server)
    anchor = next(m.anchor_ref for u in _review(w, k=0).units if u.must_read for m in u.members)
    if cause == "disagreements":
        other = overlay.WriteContext(channel="mcp", session="another session")
        w.judge(_diff_of(anchor), anchor, "change_inconclusive", ctx=other)
    elif cause == "judged_unread":
        unread = overlay.WriteContext(
            channel="mcp", session="w", read_basis={"basis": "none", "unread_before_verdict": True}
        )
        w.judge(_diff_of(anchor), anchor, "changed_real", ctx=unread)
    head = _server_call(server, "start_diff_review", {"run_pair": PAIR, "k": 0})
    p = head["progress"]
    assert p["must_read_complete"] is False and p["reduce_owed"] == 0
    assert set(p.get("still_open", {})) == STILL_OPEN_KEYS
    assert p["still_open"]["audits_open"] is None
    if cause == "must_read_left":
        assert p["must_read_left"]["members"] > 0
        assert not any(v for k, v in p["still_open"].items() if k != "audits_open")
    else:
        assert p["still_open"].get(cause, 0) >= 1, p["still_open"]
    if cause in ("withheld_diffs", "failed_diffs"):
        # T-F1f: nothing left to hand out, nothing owed; only still_open says why
        assert head["next_unit"] is None
        assert p["must_read_left"] == {"units": 0, "members": 0}
        assert p["still_open"][cause] == 1


# ── the stop and the budget ───────────────────────────────────────────────────────────────────


def test_every_stop_carries_progress(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """★ T-F1i: the stop of both hand-out points — the write that judges the last must-read
    member, and start_diff_review(run_pair) with nothing left — carries the whole ``progress``.

    MUTATION (verified RED, 1 failed): put start_diff_review's block after its ``if nxt is None``
    return (still before the room is measured) -> RED. MUTATION (verified RED, 1 failed): put
    _after_unit_write's after its ``if nxt is None`` return -> RED."""
    w = _mixed(tmp_path, monkeypatch)
    server = mcp_app.build_server(w.path)
    last = _must_read_loop(server)
    head = _server_call(server, "start_diff_review", {"run_pair": PAIR, "k": 0})
    for answer in (last, head):
        assert answer["next_unit"] is None
        assert set(answer.get("progress", {})) == PROGRESS_KEYS, answer.get("progress")
        assert answer["progress"]["must_read_left"] == {"units": 0, "members": 0}
    assert last["progress"]["coverage_statement"] == last["coverage_statement"]
    assert head["progress"]["coverage_statement"] == head["report"]["coverage_statement"]


# Page budgets at which a 60-member batch's material is cut to fit.
_PAGES = tuple(range(9_000, 21_001, 500))


@pytest.mark.parametrize("page", _PAGES)
def test_the_material_is_fitted_beside_progress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, page: int
) -> None:
    """★ T-F1h: at the overview, a single write and a batch write, a unit's material cut to fill
    the page is fitted beside ``progress``: every answer keeps to the byte budget; the two stops
    (no unit) carry it within the budget too.

    MUTATION (verified RED, 17 of 25 failed): set _after_unit_write's block after ``used`` is
    counted -> RED. MUTATION (verified RED, 12 of 25 failed): set start_diff_review's block after
    the material is fitted -> RED. (Set after the room is measured but before the material is
    fitted, start_diff_review stays within the budget, 0 of 25 failed: the fit measures the
    answer as sent and cuts again.)"""
    w = _hex_world(tmp_path, monkeypatch, 60)
    monkeypatch.setattr(mcp_app, "_RESPONSE_BYTE_BUDGET", page)
    server = mcp_app.build_server(w.path)
    first = _server_call(server, "start_diff_review", {"run_pair": PAIR, "sweep": True, "k": 1})
    e1 = first["next_unit"]  # one entry; the 59 others are one second-tier batch
    one = _server_call(server, "annotate_diff", _judge_args(e1["members"][0], e1["unit_id"]))
    start = _server_call(server, "start_diff_review", {"run_pair": PAIR, "sweep": True, "k": 1})
    nu = start["next_unit"]
    item = {
        "anchor_ref": nu["members"][0]["anchor_ref"],
        "verdict": "changed_real",
        "rationale": "r",
    }
    batch = _server_call(
        server,
        "annotate_diff_batch",
        {"annotations": [item], "diff_id": DX, "unit_id": nu["unit_id"]},
    )
    for answer in (one, start, batch):
        held = answer["next_unit"]
        assert held["kind"] == ru.SECOND_TIER and held["material_cut"] is True  # a full page
        assert "progress" in answer
        _assert_page_members(held)
        assert len(json.dumps(answer)) <= page, (len(json.dumps(answer)), page)


def test_a_unit_read_alone_carries_no_progress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-F1k: start_diff_review(run_pair, unit=…) — one unit alone, the blind read's only way in
    — carries no ``progress`` and nothing else new (its keys as before; its bytes were compared
    with d3eb840's by hand when this landed).

    MUTATION (verified RED, 1 failed): add the block to the unit= read -> RED."""
    w = _build_world(tmp_path, monkeypatch)
    server = mcp_app.build_server(w.path)
    uid = _review(w, k=0).units[0].unit_id
    alone = _server_call(server, "start_diff_review", {"run_pair": PAIR, "unit": uid, "k": 0})
    assert "unit" in alone and "material" in alone
    assert set(alone) <= {"run_pair", "server", "unit", "members", "material", "material_cut"}


# ── shards ────────────────────────────────────────────────────────────────────────────────────


def _shard_done_elsewhere_owed(w: World, workers: int) -> int:
    """A worker of ``workers`` holding some must-read units while another holds more: its own
    units' members judged."""
    units = [u for u in _review(w, k=0).units if u.must_read]
    holders = {i: [u for u in units if ru.in_shard(u.unit_id, i, workers)] for i in range(workers)}
    worker = next(i for i, us in holders.items() if us and len(us) < len(units))
    for u in holders[worker]:
        for m in u.members:
            w.judge(m.stream, m.anchor_ref, "changed_real")
    return worker


def test_in_a_shard_progress_says_its_counts_are_the_pairs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ T-F1m / T-F1n: a shard whose own must-read units are all disposed reads
    ``scope`` "shard", the pair's must-read units still left, ``pair_wide`` naming the counts
    that are the pair's and ``must_read_complete`` false — at start_diff_review (worker / workers
    passed) and at a write's answer (the shard inferred from the session) alike; unsharded,
    ``scope`` is "pair".

    MUTATION (verified RED, 1 failed): leave scope out -> RED. MUTATION (verified RED,
    1 failed): give scope as "shard" only while the shard has units left -> RED. MUTATION
    (verified RED, 1 failed): pass sharded=False from _after_unit_write -> RED."""
    workers = 3
    w = _mixed(tmp_path, monkeypatch)
    worker = _shard_done_elsewhere_owed(w, workers)
    server = mcp_app.build_server(w.path)
    args = {"run_pair": PAIR, "k": 0, "worker": worker, "workers": workers}
    head = _server_call(server, "start_diff_review", args)
    assert head["next_unit"] is None  # the precondition: this shard's must-read part is done
    p = head["progress"]
    assert p.get("scope") == "shard" and p.get("pair_wide") == PAIR_WIDE
    assert p["must_read_left"]["units"] > 0 and p["must_read_complete"] is False
    assert f"worker={worker}, workers={workers}" in p["resume_with"]
    # a write in this session (the shard inferred from it) says the same
    swept = _server_call(server, "start_diff_review", {**args, "sweep": True})
    nu = swept["next_unit"]
    assert nu is not None and nu["kind"] == ru.SECOND_TIER
    out = _server_call(server, "annotate_diff", _judge_args(nu["members"][0], nu["unit_id"]))
    assert out.get("shard", {}).get("inferred") is True  # the precondition
    assert (out["progress"].get("scope"), out["progress"].get("pair_wide")) == ("shard", PAIR_WIDE)
    whole = _server_call(
        mcp_app.build_server(w.path), "start_diff_review", {"run_pair": PAIR, "k": 0}
    )
    assert whole["progress"]["scope"] == "pair"


def test_the_reduce_another_shard_holds_is_named_the_pairs(tmp_path: Path) -> None:
    """★ T-F1o: the reduce is held by one shard; another shard's ``progress`` still counts it
    (``reduce_owed`` > 0, as its coverage offer does not) and ``pair_wide`` says that count is
    the pair's.

    MUTATION (verified RED, 1 failed): leave reduce_owed out of pair_wide -> RED."""
    workers = 3
    w = _reduce_owed_world(tmp_path)
    r = _review(w)
    red = next(u for u in r.units if u.kind == ru.REDUCE)
    worker = next(i for i in range(workers) if not ru.in_shard(red.unit_id, i, workers))
    tools = mcp_app.make_tools(w.path)
    head = tools["start_diff_review"](run_pair=PAIR, worker=worker, workers=workers)
    assert head["coverage_offer"]["reduce_owed_in_this_shard"] is None  # held elsewhere
    p = head["progress"]
    assert p["reduce_owed"] > 0 and "reduce_owed" in p["pair_wide"] and p["scope"] == "shard"


# ── words ─────────────────────────────────────────────────────────────────────────────────────

# The words a dispatch group's authored text must never carry (test_dispatch_groups'
# _FORBIDDEN_WORDS, the same list).
_FORBIDDEN_WORDS = (
    "reachable",
    "reachability",
    "unreachable",
    "routed",
    "reaches",
    "dispatched to",
    "vulnerable",
    "exploitable",
    "malicious",
    "benign",
    "safe",
    "blocked",
    "patched",
)


def _words(x: Any, out: list[str]) -> list[str]:
    """Every key (cut at ``_`` into its words) and every string value of ``x``, lower case."""
    if isinstance(x, dict):
        for k, v in x.items():
            out.extend(str(k).lower().split("_"))
            _words(v, out)
    elif isinstance(x, list):
        for v in x:
            _words(v, out)
    elif isinstance(x, str):
        out.append(x.lower().replace("_", " "))
    return out


def test_progress_carries_no_reachability_or_verdict_word(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ T-F1l: no key of ``progress`` (cut at ``_`` — ``\\bblocked\\b`` does not match inside
    ``blocked_by``, ``_`` being a word character) and no string in it carries a reachability or
    verdict word; read on a block with every field set, a stop with a withheld diff.

    MUTATION (verified RED, 1 failed): rename still_open to blocked_by -> RED."""
    w = _build_world(tmp_path, monkeypatch)
    w.atlas.execute("UPDATE diff_meta SET version_skew = 1 WHERE diff_id = ?", (DY,))
    w.atlas.commit()
    server = mcp_app.build_server(w.path)
    blocks = [_server_call(server, "start_diff_review", {"run_pair": PAIR, "k": 0})["progress"]]
    blocks.append(_must_read_loop(server)["progress"])
    blocks.append(mcp_app.make_tools(w.path)["start_diff_review"](run_pair=PAIR, k=0)["progress"])
    words = [t for b in blocks for t in _words(b, [])]
    assert "still" in words and "pair" in words  # the scan read the block
    hits = [(word, t) for t in words for word in _FORBIDDEN_WORDS if re.search(rf"\b{word}\b", t)]
    assert hits == []


# ── what the skill and the workflow say ───────────────────────────────────────────────────────


def test_every_progress_field_the_skill_names_is_in_the_answer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ T-F2c: every ``progress.<field>`` the skill names is a field of the block that
    start_diff_review(run_pair) hands back — at a unit and at the stop.

    MUTATION (verified RED, 1 failed): rename any one field of the block (resume_with) -> RED."""
    named = set(re.findall(r"progress\.([a-z_]+)", diff_skill.skill_text()))
    assert named == PROGRESS_KEYS  # every field of it is named
    w = _mixed(tmp_path, monkeypatch)
    server = mcp_app.build_server(w.path)
    head = _server_call(server, "start_diff_review", {"run_pair": PAIR, "k": 0})
    assert head["next_unit"] is not None
    stop = _must_read_loop(server)
    for answer in (head, stop):
        assert named <= set(answer["progress"]), sorted(named - set(answer["progress"]))


def test_a_fresh_session_continues_with_the_next_unit_not_disposed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ T-F2g (the behaviour the hand-off rests on): session A takes the first unit, judges it
    and stops; session B, on the same log, calls start_diff_review(run_pair) as ``resume_with``
    names it and gets the first unit in the hand-out order not yet disposed — not A's — with its
    material."""
    w = _mixed(tmp_path, monkeypatch)
    a = mcp_app.build_server(w.path)
    head = _server_call(a, "start_diff_review", {"run_pair": PAIR, "k": 0})
    u1 = head["next_unit"]
    stopped = _batch(a, u1)
    assert stopped["progress"]["resume_with"] == f'start_diff_review(run_pair="{PAIR}", k=0)'
    b = mcp_app.build_server(w.path)
    got = _server_call(b, "start_diff_review", {"run_pair": PAIR, "k": 0})
    nu = got["next_unit"]
    r = _review(w, k=0)
    want = next(
        u
        for u in ru.dispatch_order(r.units, sweep=False)
        if not ru.unit_disposed(u, r.progress.states)
    )
    assert nu["unit_id"] == want.unit_id != u1["unit_id"]
    assert isinstance(nu.get("material"), dict) and "error" not in nu["material"]
    assert got["progress"]["this_session"] == {"units_handed": 0, "response_bytes": 0}


def test_resume_with_names_the_reading_this_session_is_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``resume_with`` names the call a fresh session continues with on the same reading: the
    default k left out, another k named, and a shard's worker / workers and sweep when given.

    MUTATION (verified RED, 1 failed): leave worker / workers out of resume_with -> RED."""
    w = _build_world(tmp_path, monkeypatch)
    tools = mcp_app.make_tools(w.path)
    pair = json.dumps(PAIR)
    assert tools["start_diff_review"](run_pair=PAIR)["progress"]["resume_with"] == (
        f"start_diff_review(run_pair={pair})"
    )
    got = tools["start_diff_review"](run_pair=PAIR, k=0, worker=1, workers=2, sweep=True)
    assert got["progress"]["resume_with"] == (
        f"start_diff_review(run_pair={pair}, k=0, worker=1, workers=2, sweep=true)"
    )
