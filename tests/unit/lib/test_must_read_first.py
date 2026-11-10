# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""A pair's review hands out the must-read units only by default, and stops there with its
coverage (lib/query/review_units ``dispatch_order`` / ``coverage_offer``): through the module, the
MCP server's two hand-out points and the batch driver. The second tier is handed out on request
(``sweep`` / ``--until complete``), after every must-read unit.

Zero real data: the worlds of test_review_units (two diffs of one run pair) and of
test_callee_groups (a callee group and its reduce)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from tests.unit.lib.test_callee_groups import P1, P2, P4, X_A, X_B, _fresh  # noqa: F401
from tests.unit.lib.test_callee_groups import _anchor as _cg_anchor
from tests.unit.lib.test_callee_groups import _world as _cg_world
from tests.unit.lib.test_diff_review import (  # noqa: F401 — the autouse cache fixture
    DX,
    PAIR,
    World,
    _clear_view_caches,
)
from tests.unit.lib.test_review_units import _build_world, _judge_args, _review, _server_call
from treasure_map import mcp_app
from treasure_map.cli import review_cli
from treasure_map.lib import overlay
from treasure_map.lib import review_driver as rd
from treasure_map.lib.query import callee_groups as cg
from treasure_map.lib.query import review_units as ru

# What coverage_offer holds — facts only: no prediction of what reading on would find.
OFFER_KEYS = {
    "scope",
    "disposed",
    "unseen",
    "second_tier",
    "not_reachable",
    "basis_incomplete",
    "reduce_owed_in_this_shard",
    "reduce_note",
    "must_read_complete",
    "complete",
    "continue_with",
    "pair_wide",
}
FAILED_DIFF = (
    "INSERT INTO diff_meta (diff_id, run_a_id, run_b_id, binary_a, binary_b, sha256_a, sha256_b, "
    "diff_ok, version_skew, diff_status_reason) VALUES ('runA::runB::libz', 'runA', 'runB', "
    "'libz', 'libz', '0a1b', '0a1c', 0, 0, 'bindiff_failed')"
)


@pytest.fixture(autouse=True)
def _clear_unit_cache() -> None:
    ru.DIFF_CACHE.clear()


def _mixed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, failed: bool = False) -> World:
    """At k=0: must-read units and second-tier batches interleaved in the hand-out order (a batch
    before a must-read unit), over two diffs; optionally a diff that failed."""
    w = _build_world(tmp_path, monkeypatch)
    for i in range(1, 6):
        w.pair(DX, f"0001{i}000", f"0001{i}000", conf=0.97, sim=0.7)
    if failed:
        w.atlas.execute(FAILED_DIFF)
        w.atlas.commit()
    return w


def _judge_unit(w: World, u: ru.Unit) -> None:
    for m in u.members:
        w.judge(m.stream, m.anchor_ref, "changed_real")


def _loop(w: World, *, sweep: bool, k: int = 0) -> list[ru.Unit]:
    """Hand units out with ``sweep`` and judge each, until none is left: the units handed out."""
    seen: list[ru.Unit] = []
    for _ in range(100):
        u = _review(w, k=k).next_unit(sweep=sweep)
        if u is None:
            return seen
        seen.append(u)
        _judge_unit(w, u)
    raise AssertionError("the loop did not end")


def test_by_default_the_second_tier_is_never_handed_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ T-G7a: the hand-out order puts second-tier batches before must-read units; by default the
    units handed out are every must-read unit and no second-tier batch, and then none — while the
    second tier is still unjudged (the stop does not wait for anything more).

    MUTATION (verified RED, 1 failed): drop the must-read filter (hand out every unit) -> a
    second_tier_batch is handed out -> RED. MUTATION (verified RED, 1 failed): stop only once
    must_read_complete is true (hand out the second tier while it is not) -> RED (the world has
    a failed diff, so must_read_complete never holds)."""
    w = _mixed(tmp_path, monkeypatch, failed=True)
    units = _review(w, k=0).units
    kinds = [u.kind for u in units]
    first_second = kinds.index(ru.SECOND_TIER)
    last_must = max(i for i, u in enumerate(units) if u.must_read)
    assert first_second < last_must  # the precondition: interleaved, as on a real pair
    handed = _loop(w, sweep=False)
    assert ru.SECOND_TIER not in [u.kind for u in handed]
    assert {u.unit_id for u in handed} == {u.unit_id for u in units if u.must_read}
    r = _review(w, k=0)
    assert r.report["must_read"]["members_disposed"] == r.report["must_read"]["members"]
    assert r.report["all_listed"]["unjudged"] > 0  # the second tier, not handed out
    assert r.next_unit(sweep=False) is None


def test_with_sweep_the_second_tier_comes_after_every_must_read_unit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ T-G7e: asked for, the second tier is handed out — every unit in the end — and only after
    every must-read unit; asking for it moves no unit, id or must-read flag.

    MUTATION (verified RED, 1 failed): with sweep, hand out in Unit.order alone (interleaved, as
    before) -> a batch comes before a must-read unit -> RED."""
    w = _mixed(tmp_path, monkeypatch)
    before = [(u.unit_id, u.kind, u.must_read) for u in _review(w, k=0).units]
    handed = _loop(w, sweep=True)
    flags = [u.must_read for u in handed]
    assert flags == sorted(flags, reverse=True), flags  # every must-read unit first
    assert {u.unit_id for u in handed} == {uid for uid, _k, _m in before}
    # the units themselves are the same whichever way they were handed out
    w2 = _mixed(tmp_path / "again", monkeypatch)
    assert [(u.unit_id, u.kind, u.must_read) for u in _review(w2, k=0).units] == before


def test_the_reduce_is_handed_out_once_the_must_read_part_is_judged(tmp_path: Path) -> None:
    """★ T-G7h: a callee group (must-read) whose members were judged without its group_ref owes
    the reduce; with the second tier unjudged, the reduce is handed out by default once the
    must-read units are judged, and judging it makes must_read_complete true while ``complete``
    stays false.

    MUTATION (verified RED, 1 failed): keep the reduce gate on every subject unit (the second
    tier too) -> no reduce is ever handed out by default -> RED."""
    w = _cg_world(tmp_path)
    for a in ("00030000", "00031000"):
        w.pair(a, a, 0.97, 0.6)
        w.fn("a", a, ["system"], name=f"z_{a}")
        w.fn("b", a, ["system"], name=f"z_{a}")
    w.commit()

    def review() -> ru.PairReview:
        return ru.review_pair(
            w.atlas, "runA", "runB", k=4, pair_staleness={"source_stale": False}, server_commit="c"
        )

    r = review()
    kinds = {u.kind for u in r.units}
    assert {ru.GROUP, ru.SECOND_TIER} <= kinds  # the precondition
    for _ in range(10):
        u = review().next_unit(sweep=False)
        assert u is not None and u.kind != ru.SECOND_TIER, u
        if u.kind == ru.REDUCE:
            break
        for m in u.members:
            overlay.annotate_diff(
                w.atlas,
                anchor_ref=m.anchor_ref,
                verdict="changed_real",
                rationale="r",
                diff_id=m.stream,
            )
    else:
        raise AssertionError("no reduce was handed out")
    ref = cg.group_ref(m.stream, X_B)
    for p in (P1, P2, P4, (X_A, X_B)):
        overlay.annotate_diff(
            w.atlas,
            anchor_ref=_cg_anchor(p),
            verdict="changed_real",
            rationale="r",
            diff_id=m.stream,
            group_ref=ref,
        )
    r = review()
    assert r.next_unit(sweep=False) is None
    assert r.report["must_read_complete"] is True
    assert r.report["complete"] is False
    offer = ru.coverage_offer(r, worker=None, workers=None, sweep=False)
    assert offer["second_tier"]["members"] == 2


def test_the_coverage_offer_is_facts_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """★ T-G7b / T-G7d: at the stop, coverage_offer holds the second tier still to read (units,
    members, by bucket, why), the scope, what no unit can reach, the incomplete-basis count, the
    reduce of this shard and the two completeness flags — exactly these keys: nothing that
    predicts what reading on would yield (no low_yield), no verdict, nothing ``blocked``, no
    order of entries.

    MUTATION (verified RED, 1 failed): add ``low_yield`` to the offer -> RED. MUTATION (verified
    RED, 1 failed): count the second tier's members from the disposed ones -> RED."""
    w = _mixed(tmp_path, monkeypatch)
    _loop(w, sweep=False)
    r = _review(w, k=0)
    offer = ru.coverage_offer(r, worker=None, workers=None, sweep=False)
    assert set(offer) == OFFER_KEYS
    second = [u for u in r.units if u.kind == ru.SECOND_TIER]
    st = offer["second_tier"]
    assert st["units"] == len(second) == 3
    assert st["members"] == sum(len(u.members) for u in second) == 8
    assert sum(st["by_bucket"].values()) == 8 and st["why"] and st["handed_out"] is False
    assert offer["scope"] == "pair" and offer["continue_with"]
    text = json.dumps(offer)
    for word in ("low_yield", "yield", "verdict", "blocked", "likely", "probab"):
        assert word not in text, word


def test_a_failed_diff_does_not_keep_the_review_from_stopping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ T-G7c: with a diff that failed, must_read_complete and complete never hold — the stop is
    "no must-read unit is left", not either flag — and the offer names the failed diff apart.

    MUTATION (verified RED, 1 failed): stop only when must_read_complete holds -> the loop never
    ends -> RED."""
    w = _mixed(tmp_path, monkeypatch, failed=True)
    server = mcp_app.build_server(w.path)
    start = _server_call(server, "start_diff_review", {"run_pair": PAIR, "k": 0})
    nu = start["next_unit"]
    answer: dict[str, Any] = start
    for _ in range(40):
        if nu is None:
            break
        assert nu["kind"] != ru.SECOND_TIER, nu
        for m in nu["members"]:
            answer = _server_call(server, "annotate_diff", _judge_args(m, nu["unit_id"]))
            assert answer.get("written") is True, answer
        nu = answer.get("next_unit")
    assert nu is None and "coverage_offer" in answer, answer
    offer = answer["coverage_offer"]
    assert offer["not_reachable"]["failed_diffs"] == 1
    assert offer["must_read_complete"] is False and offer["complete"] is False
    again = _server_call(server, "start_diff_review", {"run_pair": PAIR, "k": 0})
    assert again["next_unit"] is None and again["coverage_offer"]["second_tier"]["members"] == 8


def test_every_hand_out_point_stops_and_sweep_carries_on_through_a_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ T-G7f: the three hand-out points all stop at the must-read part — start_diff_review and
    a write's answer (null next_unit with the offer), and the batch driver (no second-tier launch,
    stopped "no must-read unit left") — and after start_diff_review(sweep=true), a write naming
    its unit hands on another second-tier unit (the session's sweep carries on).

    MUTATION (verified RED, 1 failed): leave the driver's own selection unfiltered -> it launches
    a second-tier batch -> RED. MUTATION (verified RED, 1 failed): pass sweep=False in
    _after_unit_write whatever the session asked -> the write after a sweep hands on nothing ->
    RED. MUTATION (verified RED, 1 failed): pass sweep=True in _start_pair_review -> RED."""
    w = _mixed(tmp_path, monkeypatch)
    server = mcp_app.build_server(w.path)
    nu = _server_call(server, "start_diff_review", {"run_pair": PAIR, "k": 0})["next_unit"]
    answer: dict[str, Any] = {}
    while nu is not None:
        assert nu["kind"] != ru.SECOND_TIER and nu["must_read"] is True, nu
        for m in nu["members"]:
            answer = _server_call(server, "annotate_diff", _judge_args(m, nu["unit_id"]))
        nu = answer.get("next_unit")
    assert answer["next_unit"] is None
    # exactly these keys: no separate "other direction unread" count (that is basis_incomplete)
    assert set(answer["coverage_offer"]) == OFFER_KEYS | {"evidence_reads_cut"}
    start = _server_call(server, "start_diff_review", {"run_pair": PAIR, "k": 0})
    assert start["next_unit"] is None and "coverage_offer" in start
    swept = _server_call(server, "start_diff_review", {"run_pair": PAIR, "k": 0, "sweep": True})
    nu = swept["next_unit"]
    assert nu is not None and nu["kind"] == ru.SECOND_TIER, swept
    first = nu["unit_id"]
    for m in nu["members"]:
        answer = _server_call(server, "annotate_diff", _judge_args(m, first))
    nxt = answer.get("next_unit")
    assert nxt is not None and nxt["kind"] == ru.SECOND_TIER and nxt["unit_id"] != first, answer
    assert answer.get("sweep") == {"on": True, "inferred": True}

    # the driver, on a fresh world: by default it launches no second-tier batch
    w2 = _mixed(tmp_path / "driver", monkeypatch)
    launched: list[str] = []

    def agent(argv: list[str], *, cwd: Path, timeout: float) -> rd.Launch:
        uid = re.search(r'unit="([0-9a-f]{16})"', argv[-1])
        assert uid is not None
        u = _review(w2, k=0).unit(uid.group(1))
        assert u is not None
        launched.append(u.kind)
        for m in u.members:
            overlay.annotate_diff(
                w2.atlas,
                anchor_ref=m.anchor_ref,
                verdict="changed_real",
                rationale="r",
                diff_id=m.stream,
                ctx=overlay.WriteContext(channel="mcp", unit_id=u.unit_id, session="agent"),
            )
        return rd.Launch(0, 0.01, False)

    preset = rd.Preset(name="t", argv=("agent", "{prompt}"))
    result = rd.drive(
        w2.path, "runA", "runB", preset, workdir=tmp_path, k=0, runner=agent, echo=lambda s: None
    )
    assert launched and ru.SECOND_TIER not in launched, launched
    assert result.stopped == "no must-read unit left" and result.finished is True, result
    assert result.offer is not None and result.offer["second_tier"]["members"] == 8


def test_without_a_log_a_write_hands_on_the_default_and_says_why(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-G7f: a write naming its unit, in a session with no tool-call log to read the
    sweep from, hands on the must-read units only, and says why."""
    w = _mixed(tmp_path, monkeypatch)
    tools = mcp_app.make_tools(w.path)  # no call log
    nu = tools["start_diff_review"](run_pair=PAIR, k=0, sweep=True)["next_unit"]
    assert nu["kind"] == ru.ENTRY or nu["must_read"] is True
    got = tools["annotate_diff"](**_judge_args(nu["members"][0], nu["unit_id"]))
    assert got.get("sweep", {}).get("on") is False and "no tool-call log" in got["sweep"]["why"]


def test_sweep_is_recorded_in_the_log_and_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``sweep`` is a recorded parameter (a later write reads it back), a boolean, and the pair's
    only: with diff_id it is refused, as worker / workers / unit / k are."""
    from treasure_map.lib import tool_call_log as tcl

    assert "sweep" in tcl.KEY_PARAMS
    w = _mixed(tmp_path, monkeypatch)
    tools = mcp_app.make_tools(w.path)
    bad = tools["start_diff_review"](run_pair=PAIR, sweep="yes")
    assert "sweep must be true or false" in bad["error"]
    one = tools["start_diff_review"](diff_id=DX, sweep=True)
    assert "apply to run_pair only" in one["error"]


def test_the_command_line_stops_at_the_must_read_part_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ T-G7g: ``tmap review run`` drives ``--until must_read`` unless told ``--until
    complete``.

    MUTATION (verified RED, 1 failed): default --until to complete -> RED."""
    seen: list[str] = []

    class _Conn:
        def close(self) -> None:
            pass

    monkeypatch.setattr(review_cli, "_open", lambda atlas, pair: (_Conn(), "runA", "runB", "a.db"))
    monkeypatch.setattr(ru, "pair_staleness", lambda *a, **k: {"source_stale": False})
    monkeypatch.setattr(rd, "probe", lambda *a, **k: rd.ProbeResult(True, True, True, "faked"))

    def drive(*a: Any, **k: Any) -> rd.DriveResult:
        seen.append(k["until"])
        return rd.DriveResult(stopped="no must-read unit left", finished=True)

    monkeypatch.setattr(rd, "drive", drive)
    for extra, want in (([], "must_read"), (["--until", "complete"], "complete")):
        res = CliRunner().invoke(review_cli.review, ["run", PAIR, "--agent", "claude-code", *extra])
        assert res.exit_code == 0, res.output
        assert seen[-1] == want


def test_in_shards_each_stops_on_its_own_and_one_holds_the_reduce(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ T-G7g: sharded, a shard's stop is its own (``scope`` "shard", the second tier of its own
    units) and ``reduce_owed_in_this_shard`` is a count in the one shard holding the reduce, null
    in every other.

    MUTATION (verified RED, 1 failed): give every shard the pair's reduce count -> RED.
    MUTATION (verified RED, 1 failed): count the pair's second tier in every shard -> RED."""
    w = _mixed(tmp_path, monkeypatch)
    r = _review(w, k=0)
    workers = 3
    offers = [ru.coverage_offer(r, worker=i, workers=workers, sweep=False) for i in range(workers)]
    assert all(o["scope"] == "shard" for o in offers)
    held = [o["reduce_owed_in_this_shard"] for o in offers]
    assert sum(1 for h in held if h is not None) == 1, held
    assert sum(o["second_tier"]["members"] for o in offers) == 8
    whole = ru.coverage_offer(r, worker=None, workers=None, sweep=False)
    assert whole["scope"] == "pair" and whole["reduce_owed_in_this_shard"] == 0


def test_the_evidence_reads_left_cut_are_counted_per_reading() -> None:
    """``evidence_reads_cut``: a fact tool's reading (its calls but for the page's place) is left
    cut when every page of it came back cut; one read to an uncut page is not; a read of the
    subject itself (pseudocode) is the read basis's, not counted here; no log is unknown (None).

    MUTATION (verified RED, 1 failed): key a reading by its offset too -> each page its own
    reading -> RED."""
    from treasure_map.lib.query import read_basis as rb

    def line(tool: str, truncated: bool, **params: Any) -> dict[str, Any]:
        return {"tool": tool, "params": params, "truncated": truncated}

    lines = [
        line("get_xrefs", True, run_id="r", function="f"),
        line("get_xrefs", True, run_id="r", function="f", offset=20),
        line("get_strings", True, run_id="r", binary="b"),
        line("get_strings", False, run_id="r", binary="b", offset=40),
        line("get_pseudocode", True, run_id="r", function="f"),
    ]
    got = rb.evidence_reads_cut(lines)
    assert got is not None and (got["count"], got["readings"]) == (1, 2), got
    assert "per session" in got["scope"]
    assert rb.evidence_reads_cut(None) is None


def test_a_sweep_stop_offers_no_continuation_and_says_where_the_unreachable_are(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MINOR-7: at a sweep's stop there is nothing more to hand out — ``continue_with`` is null
    (the default stop names the sweep) — and the unreachable counts say which call lists them
    (``see``), on every stop: start_diff_review's and a write's answer alike.

    MUTATION (verified RED, 1 failed): give ``continue_with`` whatever the mode -> the sweep stop
    names a sweep -> RED. MUTATION (verified RED, 1 failed): drop ``see`` from the offer -> RED."""
    w = _mixed(tmp_path, monkeypatch, failed=True)
    _loop(w, sweep=True)
    r = _review(w, k=0)
    assert r.next_unit(sweep=True) is None
    swept = ru.coverage_offer(r, worker=None, workers=None, sweep=True)
    assert swept["continue_with"] is None
    assert swept["second_tier"]["members"] == 0  # the precondition: the sweep read it all
    w2 = _mixed(tmp_path / "default", monkeypatch, failed=True)
    _loop(w2, sweep=False)
    default = ru.coverage_offer(_review(w2, k=0), worker=None, workers=None, sweep=False)
    assert default["continue_with"] and "sweep=true" in default["continue_with"]
    for offer in (swept, default):
        assert offer["not_reachable"]["failed_diffs"] == 1
        assert str(offer["not_reachable"].get("see")).startswith("list_diff_blindspots(")


def test_a_shards_offer_says_which_counts_are_the_pairs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MINOR 13: a shard's offer is scoped "shard" (its second tier, its reduce) while
    ``disposed`` / ``unseen`` / ``not_reachable`` / ``basis_incomplete`` / ``must_read_complete``
    / ``complete`` are the whole pair's — every shard gives the same values there, and
    ``pair_wide`` names them.

    MUTATION (verified RED, 1 failed): drop ``pair_wide`` -> RED. MUTATION (verified RED, 1
    failed): name only the three counts (the old list) -> RED."""
    w = _mixed(tmp_path, monkeypatch)
    r = _review(w, k=0)
    offers = [ru.coverage_offer(r, worker=i, workers=3, sweep=False) for i in range(3)]
    wide = list(ru.PAIR_WIDE_OFFER_KEYS)
    assert set(wide) == {
        "disposed",
        "unseen",
        "not_reachable",
        "basis_incomplete",
        "must_read_complete",
        "complete",
    }
    for key in wide:
        assert len({json.dumps(o[key]) for o in offers}) == 1, key
    assert all(o.get("pair_wide") == wide for o in offers)
    assert {o["scope"] for o in offers} == {"shard"}


def test_a_shard_read_through_says_the_pair_is_not_yet_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MINOR (G-5/1): one shard of two judged through — its next unit None — while the other
    shard's must-read units are open: its offer says ``must_read_complete`` false, and
    ``pair_wide`` says that is the pair's, not the shard's.

    MUTATION (verified RED, 1 failed): leave must_read_complete out of pair_wide -> RED."""
    w = _mixed(tmp_path, monkeypatch)
    for _ in range(100):
        u = _review(w, k=0).next_unit(0, 2, sweep=False)
        if u is None:
            break
        _judge_unit(w, u)
    r = _review(w, k=0)
    assert r.next_unit(0, 2, sweep=False) is None  # the precondition: shard 0 read through
    assert r.next_unit(1, 2, sweep=False) is not None  # and shard 1 not
    offer = ru.coverage_offer(r, worker=0, workers=2, sweep=False)
    assert offer["scope"] == "shard" and offer["must_read_complete"] is False
    assert "must_read_complete" in offer["pair_wide"] and "complete" in offer["pair_wide"]


def test_by_default_an_open_audit_is_still_handed_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MINOR-8: the default hand-out (no sweep) hands out an open audit as it does a must-read
    unit — the audits are in the default dispatch order, not only the sweep's. (Blind auditing is
    sealed by default; this turns it on.)

    MUTATION (verified RED, 1 failed): leave the audits out of the default dispatch order ->
    the change_inconclusive's audit is never handed out -> RED."""
    monkeypatch.setattr(ru, "BLIND_AUDIT_ENABLED", True)
    w = _mixed(tmp_path, monkeypatch)
    first = _review(w, k=0).next_unit(sweep=False)
    assert first is not None and first.must_read
    writer = overlay.WriteContext(channel="mcp", session="writer")
    for m in first.members:
        w.judge(m.stream, m.anchor_ref, "change_inconclusive", ctx=writer)
    r = _review(w, k=0)
    assert any(u.kind == ru.AUDIT for u in r.units)  # the precondition: an audit is open
    audit = r.next_unit(sweep=False)
    assert audit is not None and audit.kind == ru.AUDIT, audit


def test_the_report_lists_the_units_as_they_are_handed_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MINOR-5: the Markdown and HTML reports list every must-read unit before the first
    second-tier one (the hand-out order, where ``Unit.order`` interleaves them) and say the second
    tier is handed out only on request; the terminal's next units are the default hand-out's (no
    second tier).

    MUTATION (verified RED, 1 failed): list the units in ``Unit.order`` (Markdown and HTML) -> a
    second-tier unit before a must-read one -> RED. MUTATION (verified RED, 1 failed):
    list the terminal's pending units with the second tier -> RED."""
    from treasure_map.lib.query import review_report as rr

    w = _mixed(tmp_path, monkeypatch)
    r = _review(w, k=0)
    kinds = [u.must_read for u in r.units]
    assert kinds.index(False) < len(kinds) - 1 - kinds[::-1].index(True)  # interleaved
    second = {u.unit_id for u in r.units if u.kind == ru.SECOND_TIER}
    must = {u.unit_id for u in r.units if u.must_read}
    for text in (rr.markdown(r), rr.html_page(r)):
        assert "handed out only with sweep=true" in text
        order = [uid for uid in re.findall(r"\b[0-9a-f]{16}\b", text) if uid in second | must]
        firsts = list(dict.fromkeys(order))
        assert set(firsts) == second | must, (len(firsts), len(second | must))
        last_must = max(i for i, uid in enumerate(firsts) if uid in must)
        first_second = min(i for i, uid in enumerate(firsts) if uid in second)
        assert last_must < first_second, firsts
    terminal = rr.terminal(r)
    shown = set(re.findall(r"\b[0-9a-f]{16}\b", terminal.split("next units", 1)[1]))
    assert shown and not shown & second, shown
