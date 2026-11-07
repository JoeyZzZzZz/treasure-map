# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Callee groups (lib/query/callee_groups) and what rides on them: the group units of the pair
review, a judgement leaning on a callee group (group freshness), and the reduce.

Zero real data: the World of test_patch_view (one diff of libx)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests.unit.lib.test_patch_view import DIFF, World, _pair_id
from treasure_map.lib import overlay
from treasure_map.lib.errors import ConfigError
from treasure_map.lib.query import callee_groups as cg
from treasure_map.lib.query import diff_review as dr
from treasure_map.lib.query import patch_view as pv
from treasure_map.lib.query import review_units as ru

X_B, X_A = "00009000", "00008000"
P1, P2, P3, P4 = (
    ("00001000", "00002000"),
    ("00003000", "00004000"),
    ("00005000", "00006000"),
    ("00007000", "0000a000"),
)


@pytest.fixture(autouse=True)
def _fresh(monkeypatch: pytest.MonkeyPatch) -> None:
    pv._clear_view_caches()
    ru.DIFF_CACHE.clear()
    monkeypatch.setattr(
        pv,
        "diff_source_staleness",
        lambda atlas, diff_id: {
            "source_stale": False,
            "source_stale_reason": None,
            "toolchain_checked": True,
        },
    )


def _world(tmp: Path, *, p2_a_readable: bool = True) -> World:
    """X (new_helper at B 00009000) is paired with A's old_helper (00008000). P1 and P2 call X on
    B and nothing like it on A; P3's A side calls old_helper (X's counterpart) — not new; P4's A
    side has no function in that analysis.db (its call list cannot be read); every B side also
    calls ``system``, an import, never a key. ``p2_a_readable=False`` leaves P2's A side out
    too, so P1 is the one member whose "newly calls X" is confirmed."""
    w = World(tmp)
    w.pair(X_A, X_B, 0.97, 0.9)
    w.fn("a", X_A, [], name="old_helper")
    w.fn("b", X_B, [], name="new_helper")
    for a, b in (P1, P2, P3, P4):
        w.pair(a, b, 0.97, 0.6)
        w.fn("b", b, ["system", "new_helper"], name=f"fn_{b}")
    w.fn("a", P1[0], ["system"], name=f"fn_{P1[1]}")
    if p2_a_readable:
        w.fn("a", P2[0], ["system"], name=f"fn_{P2[1]}")
    w.fn("a", P3[0], ["system", "old_helper"], name=f"fn_{P3[1]}")
    w.commit()
    return w


def _groups(w: World) -> dict[str, cg.CalleeGroup]:
    built = pv.build_diff_view(w.atlas, DIFF)
    assert built is not None
    return cg.callee_groups(w.atlas, built, pv.listed_view(w.atlas, built).entries)


def test_the_members_are_the_pairs_that_newly_call_a_defined_function(tmp_path: Path) -> None:
    """★ The group of X holds P1, P2 (B calls X, A calls no counterpart of it) and P4 (its A call
    list cannot be read: kept, counted apart); P3 is out (its A side calls X's counterpart); an
    import (system) keys no group.

    MUTATION (verified RED): drop the counterpart check -> P3 joins -> RED; drop an unreadable A
    side instead of keeping it -> P4 missing -> RED; key groups on any callee name -> a system
    group appears -> RED."""
    groups = _groups(_world(tmp_path))
    assert set(groups) == {X_B}
    g = groups[X_B]
    assert set(g.members) == {_pair_id(*P1), _pair_id(*P2), _pair_id(*P4)}
    assert (g.callee_a, g.callee_name) == (X_A, "new_helper")
    # the unread-A member (P4) is recorded by its entry id, not merely counted
    assert g.members_a_side_unread == [_pair_id(*P4)]
    assert g.ref == f"{DIFF}#callee:{X_B}@{cg.CALLEE_GROUP_VERSION}"


def test_a_callee_that_may_only_be_unpaired_keys_no_group(tmp_path: Path) -> None:
    """X in no pair, its counterpart suspected on the other side: no group (what looks new may be
    only unpaired); established absent, it keys one.

    MUTATION (verified RED): ignore counterpart_suspected -> RED."""
    w = World(tmp_path)
    w.unpaired("b", X_B, "counterpart_suspected")
    w.fn("b", X_B, [], name="new_helper")
    for a, b in (P1, P2):
        w.pair(a, b, 0.97, 0.6)
        w.fn("a", a, [], name=f"fn_{b}")
        w.fn("b", b, ["new_helper"], name=f"fn_{b}")
    w.commit()
    assert _groups(w) == {}
    w.atlas.execute("UPDATE function_presence SET presence_state = 'unmatched_analysis_complete'")
    w.commit()
    pv._clear_view_caches()
    assert set(_groups(w)) == {X_B}


def _review(w: World, k: int = 50) -> ru.PairReview:
    return ru.review_pair(
        w.atlas,
        "runA",
        "runB",
        k=k,
        pair_staleness={"source_stale": False, "source_stale_reason": None},
        server_commit=None,
    )


def test_a_group_unit_hands_its_must_read_members_out_together(tmp_path: Path) -> None:
    """★ With its members must-read (k covers them), the group is one unit, ahead of the singles at
    its place, carrying the group; its members are in no other unit.

    MUTATION (verified RED): never cut group units -> RED."""
    r = _review(_world(tmp_path))
    units = [u for u in r.units if u.kind == ru.GROUP]
    assert len(units) == 1
    unit = units[0]
    assert unit.group is not None and unit.group["ref"].endswith(f"#callee:{X_B}@callee-v1")
    ids = {m.entry_id for m in unit.members}
    assert ids == {_pair_id(*P1), _pair_id(*P2), _pair_id(*P4)}
    others = [m.entry_id for u in r.units if u is not unit for m in u.members]
    assert not ids & set(others)
    assert r.report["groups"]["units"] == 1


def _anchor(pair: tuple[str, str]) -> str:
    return dr.pair_anchor("runA", "runB", "libx", *pair)


def _judge(w: World, pair: tuple[str, str], group_ref: str | None = None) -> Any:
    return overlay.annotate_diff(
        w.atlas,
        anchor_ref=_anchor(pair),
        verdict="changed_real",
        rationale="r",
        diff_id=DIFF,
        group_ref=group_ref,
    )


def test_a_judgement_leans_on_a_callee_group_and_re_checks_when_it_moves(tmp_path: Path) -> None:
    """★ A member and X's own entry may lean on the group (is_member / is_callee); an entry outside
    it is refused. A new caller joining the group re-checks the judgement that leaned on it.

    MUTATION (verified RED): accept any entry -> P3 is taken -> RED; let a callee group never move
    -> the joined member reads concluded -> RED."""
    w = _world(tmp_path)
    ref = cg.group_ref(DIFF, X_B)
    _judge(w, P1, ref)
    _judge(w, (X_A, X_B), ref)
    with pytest.raises(ConfigError, match="not about this entry"):
        _judge(w, P3, ref)
    group = json_of(w, P1)["group"]
    assert group["relation"] == "is_member" and group["kind"] == "callee"
    assert json_of(w, (X_A, X_B))["group"]["relation"] == "is_callee"
    pv._clear_view_caches()
    assert _state(w, P1) == "concluded"
    w.pair("0000b000", "0000c000", 0.97, 0.6)
    w.fn("a", "0000b000", [], name="fn_c")
    w.fn("b", "0000c000", ["new_helper"], name="fn_c")
    w.commit()
    pv._clear_view_caches()
    assert _state(w, P1) == "needs_recheck"


def json_of(w: World, pair: tuple[str, str]) -> dict[str, Any]:
    import json

    raw = w.atlas.execute(
        "SELECT basis_state FROM overlay WHERE anchor_ref = ?", (_anchor(pair),)
    ).fetchone()
    return dict(json.loads(raw[0]))


def _state(w: World, pair: tuple[str, str]) -> str:
    built = pv.build_diff_view(w.atlas, DIFF)
    assert built is not None
    return pv.ViewReview(w.atlas, built).judged[_anchor(pair)].state


def test_the_reduce_is_owed_until_the_group_is_read_as_one(tmp_path: Path) -> None:
    """★ Every member a group unit handed out, and X's own entry, owe a judgement leaning on the
    group: until then the reduce is owed and must_read_complete is false; judged without the
    group_ref they still owe it; with it, the reduce is done. The reduce unit is handed out only
    once every other unit is disposed.

    MUTATION (verified RED): leave the callee's own entry out of the reduce -> done too early ->
    RED; drop the reduce from must_read_complete -> RED."""
    w = _world(tmp_path)
    ref = cg.group_ref(DIFF, X_B)
    r = _review(w)
    owed = {m.anchor_ref for m in ru.read_reduce(w.atlas, r.facts, r.units)}
    assert owed == {_anchor(p) for p in (P1, P2, P4, (X_A, X_B))}
    assert not any(u.kind == ru.REDUCE for u in r.units)  # the rest is not disposed yet
    for u in r.units:
        for m in u.members:
            if m.kind == "entry":
                overlay.annotate_diff(
                    w.atlas,
                    anchor_ref=m.anchor_ref,
                    verdict="changed_real",
                    rationale="r",
                    diff_id=DIFF,
                )
    r = _review(w)
    reduce_units = [u for u in r.units if u.kind == ru.REDUCE]
    assert len(reduce_units) == 1 and r.report["must_read_complete"] is False
    assert r.report["reduce"]["owed"] == 4
    for p in (P1, P2, P4, (X_A, X_B)):
        _judge(w, p, ref)
    r = _review(w)
    assert r.report["reduce"]["owed"] == 0
    assert not any(u.kind == ru.REDUCE for u in r.units)
    assert "reduce done" in r.report["coverage_statement"]


def test_the_markdown_draws_a_small_group_and_lists_a_large_one(tmp_path: Path) -> None:
    """MUTATION (verified RED): draw every group whatever its size -> RED."""
    from treasure_map.lib.query import review_report as rr

    r = _review(_world(tmp_path))
    text = rr.markdown(r)
    assert "```mermaid" in text and "new_helper" in text
    unit = next(u for u in r.units if u.kind == ru.GROUP)
    many = ru.Unit(**{**unit.__dict__, "members": unit.members * (rr.MERMAID_MAX_MEMBERS + 1)})
    assert "too many to draw" in "\n".join(rr._mermaid_group(many))


def test_the_report_names_a_members_unreadable_a_side(tmp_path: Path) -> None:
    """★ The group kept P4, whose A-side call list was unreadable, so "newly calls X" is
    UNCONFIRMED for it: the report NAMES P4 rather than letting "N members newly call X" read as
    settled for every member (the reader surfacing of members_a_side_unread).

    MUTATION (verified RED): drop the unread caveat in _mermaid_group -> P4's id is absent -> RED.
    """
    from treasure_map.lib.query import review_report as rr

    text = rr.markdown(_review(_world(tmp_path)))
    assert "UNCONFIRMED" in text
    assert _pair_id(*P4) in text


def test_the_material_pack_names_the_unreadable_a_side_member(tmp_path: Path) -> None:
    """★ The MCP material pack an agent reads lists members_a_side_unread (P4's id) and warns in
    `how` that "newly calls" is unconfirmed for it; premise_relies_on_unread is False here because
    P1 and P2 are confirmed (two readable A sides).

    MUTATION (verified RED): drop members_a_side_unread from _group_material -> P4 absent -> RED.
    """
    from treasure_map import mcp_app

    w = _world(tmp_path)
    group = next(u for u in _review(w).units if u.kind == ru.GROUP)
    out = mcp_app.make_tools(w.path)["start_diff_review"](run_pair="runA::runB", unit=group.unit_id)
    mat = out["material"]
    assert _pair_id(*P4) in mat["members_a_side_unread"]
    assert "CAVEAT" in mat["how"]
    assert mat["premise_relies_on_unread"] is False


def test_the_material_pack_says_when_the_groups_premise_rests_on_unread_members(
    tmp_path: Path,
) -> None:
    """★ With P2's A side unreadable as well, P1 is the only member that is known to newly call X:
    the group's ">= 2 members newly call X" holds only by counting P2 and P4, and the material
    pack says so (premise_relies_on_unread true), naming both.

    MUTATION (verified RED): premise_relies_on_unread always False -> RED."""
    from treasure_map import mcp_app

    w = _world(tmp_path, p2_a_readable=False)
    group = next(u for u in _review(w).units if u.kind == ru.GROUP)
    out = mcp_app.make_tools(w.path)["start_diff_review"](run_pair="runA::runB", unit=group.unit_id)
    mat = out["material"]
    assert sorted(mat["members_a_side_unread"]) == sorted([_pair_id(*P2), _pair_id(*P4)])
    assert mat["premise_relies_on_unread"] is True


def test_the_material_pack_never_hands_an_empty_pseudocode_as_a_reading(tmp_path: Path) -> None:
    """★ The callee's B side has no text (its decompile timed out): the pack says it is unavailable,
    with the status and the recorded decompile outcome — not ``{"pseudocode": ""}``, which reads as
    an empty function.

    MUTATION (verified RED, 1 failed): let an empty string through as pseudocode in _side_code."""
    from treasure_map import mcp_app

    w = _world(tmp_path)
    w.adb["b"].execute(
        "UPDATE functions SET pseudocode = '', decompile_status = 'timeout', size_bytes = 400 "
        "WHERE name = 'new_helper'"
    )
    w.commit()
    group = next(u for u in _review(w).units if u.kind == ru.GROUP)
    out = mcp_app.make_tools(w.path)["start_diff_review"](run_pair="runA::runB", unit=group.unit_id)
    b_side = out["material"]["callee"]["b_side"]
    assert "pseudocode" not in b_side
    assert b_side.get("unavailable") == "decompile_failed"
    assert b_side.get("decompile_status") == "timeout"


def test_a_group_whose_view_fails_hands_out_no_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ R-11: when the diff's view cannot be read, the group's material is that error — not a
    group with no entries, which the log would record as handed out whole.

    MUTATION (verified RED, 1 failed): swallow the view's error into ``entries: []`` -> the log
    records the unit as handed out -> RED."""
    from treasure_map import mcp_app
    from treasure_map.lib import tool_call_log as tcl

    w = _world(tmp_path)
    group = next(u for u in _review(w, k=ru.DEFAULT_K).units if u.kind == ru.GROUP)
    real = mcp_app._get_diff_patch_view

    def failing(atlas: Any, diff_id: str, **kw: Any) -> dict[str, Any]:
        if kw.get("entry_id") is None:
            return {"error": "the view could not be built"}
        return dict(real(atlas, diff_id, **kw))

    monkeypatch.setattr(mcp_app, "_get_diff_patch_view", failing)
    out = mcp_app.make_tools(w.path)["start_diff_review"](run_pair="runA::runB", unit=group.unit_id)
    assert out["material"] == {"error": "the view could not be built"}, out["material"]
    assert "unit" not in tcl.build_line(tcl.Session(), "start_diff_review", {}, out)


def test_the_reduce_keeps_its_id_while_its_owed_judgements_are_written(tmp_path: Path) -> None:
    """★ The reduce is one unit while it is owed: written one owed judgement at a time with the
    unit_id it was handed out with, every write is taken (none refused as naming no unit), each
    answer hands the same reduce on until the last, and the reduce is then done.

    MUTATION (verified RED, 1 failed): take the reduce's id from its owed members (as before) ->
    the first answer hands on a reduce of another id (the next write naming the id it was handed
    out with is refused) -> RED."""
    from tests.unit.test_tool_surface import _call
    from treasure_map import mcp_app

    w = _world(tmp_path)
    for u in _review(w, k=ru.DEFAULT_K).units:
        for m in u.members:
            if m.kind == "entry":
                overlay.annotate_diff(
                    w.atlas,
                    anchor_ref=m.anchor_ref,
                    verdict="changed_real",
                    rationale="r",
                    diff_id=DIFF,
                )
    server = mcp_app.build_server(w.path)
    head = _call(server, "start_diff_review", {"run_pair": "runA::runB"})["next_unit"]
    assert head is not None and head["kind"] == ru.REDUCE, head
    uid = head["unit_id"]
    owed = head["material"]["owed"]
    assert len(owed) == 4  # the precondition: several judgements owed
    for n, item in enumerate(owed, 1):
        got = _call(
            server,
            "annotate_diff",
            {
                "anchor_ref": item["anchor_ref"],
                "verdict": "changed_real",
                "rationale": "r",
                "diff_id": DIFF,
                "group_ref": item["group_ref"],
                "unit_id": uid,
            },
        )
        assert got.get("written") is True, (n, got)
        nxt = got.get("next_unit")
        assert (nxt or {}).get("unit_id") == (uid if n < len(owed) else None), (n, nxt)
    assert _review(w, k=ru.DEFAULT_K).report["reduce"]["owed"] == 0


def test_a_reduce_whose_owed_list_was_cut_says_its_material_was_cut(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ R-11: the reduce's owed list cut to fit (``owed_truncated``) is a cut material, so a
    write of an owed judgement it did not list is not read as handed out whole.

    MUTATION (verified RED, 1 failed): leave ``owed_truncated`` out of _material_cut -> RED."""
    from treasure_map import mcp_app

    w = _world(tmp_path)
    for u in _review(w, k=ru.DEFAULT_K).units:
        for m in u.members:
            if m.kind == "entry":
                overlay.annotate_diff(
                    w.atlas,
                    anchor_ref=m.anchor_ref,
                    verdict="changed_real",
                    rationale="r",
                    diff_id=DIFF,
                )
    red = next(u for u in _review(w, k=ru.DEFAULT_K).units if u.kind == ru.REDUCE)
    tools = mcp_app.make_tools(w.path)
    whole = tools["start_diff_review"](run_pair="runA::runB", unit=red.unit_id)
    assert whole["material_cut"] is False and "owed_truncated" not in whole["material"]
    # a budget that leaves the owed list less room than it takes
    rest = len(json.dumps(whole)) - len(json.dumps(whole["material"]))
    monkeypatch.setattr(
        mcp_app, "_RESPONSE_BYTE_BUDGET", rest + len(json.dumps(whole["material"])) - 40
    )
    cut = mcp_app.make_tools(w.path)["start_diff_review"](run_pair="runA::runB", unit=red.unit_id)
    assert cut["material"].get("owed_truncated") is True, cut["material"]
    assert cut["material_cut"] is True


# ── a group and the reduce are handed out by their page ───────────────────────────────────────


def _judge_every_entry(w: World) -> None:
    """Judge every entry member of every unit, without a group_ref: the reduce comes due."""
    for u in _review(w, k=ru.DEFAULT_K).units:
        for m in u.members:
            if m.kind == "entry":
                overlay.annotate_diff(
                    w.atlas,
                    anchor_ref=m.anchor_ref,
                    verdict="changed_real",
                    rationale="r",
                    diff_id=DIFF,
                )


def _assert_handed_by_page(out: dict[str, Any], page: list[str], key: str, total: int) -> None:
    """A paged hand-out names exactly the members its material lists (same order) and counts
    the unit's members."""
    assert "members" in out, sorted(out)
    got = [m.get(key) for m in out["members"]]
    assert got == page, (got, page)
    assert "members_total" in out and "members_after_this_page" in out, sorted(out)
    assert out["members_total"] == total, out["members_total"]


def test_a_callee_group_is_handed_out_by_its_page(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ At a page budget where the group's material lists fewer members than the group holds,
    the unit= read (and the overview's next unit, when that is the group) names exactly the
    members the material lists — none it does not show — and counts the rest owed in
    members_after_this_page. The budgets are scanned, not hard-coded: some budget must cut the
    page part-way (the precondition), or the test says so.

    MUTATION (verified RED, 1 failed, AssertionError): drop GROUP from mcp_app._PAGED_KINDS (hand
    out every member of the group) -> RED."""
    from treasure_map import mcp_app

    w = _world(tmp_path)
    group = next(u for u in _review(w).units if u.kind == ru.GROUP)
    total = len(group.members)
    assert total == 3
    cut_seen: set[str] = set()
    for budget in range(3_000, 20_001, 1_000):
        monkeypatch.setattr(mcp_app, "_RESPONSE_BYTE_BUDGET", budget)
        tools = mcp_app.make_tools(w.path)
        alone = tools["start_diff_review"](run_pair="runA::runB", unit=group.unit_id, k=50)
        head = tools["start_diff_review"](run_pair="runA::runB", k=50).get("next_unit") or {}
        holders = {"unit": alone}
        if head.get("unit_id") == group.unit_id:
            holders["overview"] = head
        for path, out in holders.items():
            mat = out.get("material") or {}
            if "entries" not in mat:
                continue
            page = [e["entry_id"] for e in mat["entries"]]
            _assert_handed_by_page(out, page, "entry_id", total)
            # nothing of the group is judged yet: every member the page leaves out is owed
            assert out["members_after_this_page"] == total - len(page), (path, budget, page)
            if 0 < len(page) < total:
                cut_seen.add(path)
    # the precondition: some budget cut the page part-way, on the unit= read at least
    assert "unit" in cut_seen, "no budget cut the group's page part-way on the unit= read"


def test_a_group_whose_first_entry_is_larger_than_the_page_hands_out_that_one_cut(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ Every member's entry is larger than the whole page (an inflated inline hunk): the group
    is handed out with its first listed member alone, that entry cut to fit (its hunk withheld),
    and the material says it was cut — never an empty page that names no member.

    MUTATION (verified RED, 1 failed, AssertionError): in _group_material drop the "first entry
    alone over the page is handed out cut" branch (``if not kept and entries: kept = [...]``) ->
    the page lists no member -> RED."""
    from treasure_map import mcp_app

    w = _world(tmp_path)
    group = next(u for u in _review(w).units if u.kind == ru.GROUP)
    ids = {m.entry_id for m in group.members}
    real = mcp_app._get_diff_patch_view

    def inflated(*a: Any, **kw: Any) -> Any:
        page = real(*a, **kw)
        if isinstance(page, dict) and page.get("entries"):
            hunk = {"lines": [f"+ line {i} " + "x" * 200 for i in range(300)]}
            page = {
                **page,
                "entries": [
                    {
                        **e,
                        "pseudocode_delta": {
                            **(e.get("pseudocode_delta") or {}),
                            "inline_hunk": hunk,
                        },
                    }
                    if e.get("entry_id") in ids
                    else e
                    for e in page["entries"]
                ],
            }
        return page

    monkeypatch.setattr(mcp_app, "_get_diff_patch_view", inflated)
    out = mcp_app.make_tools(w.path)["start_diff_review"](
        run_pair="runA::runB", unit=group.unit_id, k=50
    )
    assert len(json.dumps(out)) <= mcp_app._RESPONSE_BYTE_BUDGET
    mat = out.get("material") or {}
    assert "entries" in mat, mat
    page = [e["entry_id"] for e in mat["entries"]]
    assert len(page) == 1 and page[0] in ids, page
    _assert_handed_by_page(out, page, "entry_id", len(group.members))
    assert out["members_after_this_page"] == len(group.members) - 1
    assert out.get("material_cut") is True


def test_the_reduce_is_handed_out_by_its_page(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ At a page budget where the reduce's owed list is cut (``owed_truncated``), the unit=
    read names exactly the owed judgements the material lists, in its order, with how many the
    reduce holds and how many it owes beyond the page — never a member it does not show. The
    budgets are scanned; some budget must cut the owed list part-way (the precondition).

    MUTATION (verified RED, 1 failed, AssertionError): drop REDUCE from mcp_app._PAGED_KINDS
    (hand out every owed member) -> RED; count a reduce's members by their judgements' state
    (``_owed`` without its reduce case, as before) -> members_after_this_page 0 -> RED; count the
    unit head's members_disposed by state (``_ru.disposed``) -> head says 4 -> RED."""
    from treasure_map import mcp_app

    w = _world(tmp_path)
    _judge_every_entry(w)
    red = next(u for u in _review(w, k=ru.DEFAULT_K).units if u.kind == ru.REDUCE)
    total = len(red.members)
    assert total == 4
    cut_seen = 0
    for budget in range(1_500, 3_501, 100):
        monkeypatch.setattr(mcp_app, "_RESPONSE_BYTE_BUDGET", budget)
        out = mcp_app.make_tools(w.path)["start_diff_review"](
            run_pair="runA::runB", unit=red.unit_id
        )
        mat = out.get("material") or {}
        if "owed" not in mat:
            continue
        page = [o["anchor_ref"] for o in mat["owed"]]
        _assert_handed_by_page(out, page, "anchor_ref", total)
        # Every member of a reduce is owed (its judgement reads concluded, yet owes the
        # group_ref): the ones the page leaves out are all counted, none as disposed.
        assert out["members_after_this_page"] == total - len(page), (budget, page)
        assert out["members_disposed"] == 0, budget
        # The unit head says the same (it is built apart from the paged top-level count).
        assert (out.get("unit") or {}).get("members_disposed") == 0, (budget, out.get("unit"))
        if 0 < len(page) < total:
            cut_seen += 1
    assert cut_seen, "no budget cut the reduce's owed list part-way: the precondition did not hold"


def test_a_compacted_batch_answer_keeps_each_results_group_ref(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ A batch answer whose per-item echo comes near the page is compacted to index and action
    per result — and each result written with a group_ref keeps it, so the compact answer still
    says which judgements leaned on the group.

    MUTATION (verified RED, 1 failed, AssertionError): drop "group_ref" from the compacted keys
    in annotate_diff_batch -> RED."""
    from treasure_map import mcp_app

    w = _world(tmp_path)
    ref = cg.group_ref(DIFF, X_B)
    items = [
        {"anchor_ref": _anchor(p), "verdict": "changed_real", "rationale": "r", "group_ref": ref}
        for p in (P1, P2, P4, (X_A, X_B))
    ]
    monkeypatch.setattr(mcp_app, "_RESPONSE_BYTE_BUDGET", 10**7)
    whole = mcp_app.make_tools(w.path)["annotate_diff_batch"](items, diff_id=DIFF)
    assert whole.get("written") is True, whole
    assert all("anchor_ref" in r for r in whole["results"]), whole["results"]
    size = len(json.dumps(whole["results"]))
    monkeypatch.setattr(mcp_app, "_RESPONSE_BYTE_BUDGET", size + 4_000)
    cut = mcp_app.make_tools(w.path)["annotate_diff_batch"](items, diff_id=DIFF)
    assert cut.get("written") is True, cut
    results = cut.get("results") or []
    assert len(results) == len(items), results
    # the precondition: the echo was compacted (no anchor_ref; who was overwritten said once)
    assert all("anchor_ref" not in r for r in results), results
    assert "overwrote_by" in cut, sorted(cut)
    assert [r.get("group_ref") for r in results] == [ref] * len(items), results


def test_a_group_material_names_the_call_that_reads_on_a_members_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ A callee group whose member P1 has 35 candidate rows: the group's material carries the
    first page of them (``rows_next_offset`` 20) and names the call that reads the rest
    (``read_rows``), and that member is not logged as shown whole (``unit_whole``) — its judgement
    is not read as every row read.

    MUTATION (verified RED, 1 failed): in _group_material leave read_rows out of the material ->
    RED."""
    from tests.unit.lib.test_diff_review import _row
    from tests.unit.lib.test_patch_view import _ref
    from treasure_map import mcp_app
    from treasure_map.lib import tool_call_log as tcl
    from treasure_map.lib.query import sink_overlay as so

    w = _world(tmp_path)
    rows = [
        _row(_ref("runA", P1[0], "cmd", f"0x{16 + j:x}"), None, reason="present_different_callee")
        for j in range(35)
    ]
    monkeypatch.setattr(
        pv,
        "compute_sink_overlay",
        lambda atlas, diff_id: so.SinkOverlayResult(
            list(rows), so.SinkOverlayCoverage(0, 0, 0, 0, 0, False)
        ),
    )
    group = next(u for u in _review(w).units if u.kind == ru.GROUP)
    member = _pair_id(*P1)
    assert member in {m.entry_id for m in group.members}  # the precondition
    out = mcp_app.make_tools(w.path)["start_diff_review"](
        run_pair="runA::runB", unit=group.unit_id, k=50
    )
    mat = out.get("material") or {}
    by_id = {e.get("entry_id"): e for e in mat.get("entries") or []}
    assert member in by_id, sorted(by_id)
    assert (by_id[member].get("rows_total"), by_id[member].get("rows_next_offset")) == (35, 20)
    assert "rows_offset=<rows_next_offset>" in (mat.get("read_rows") or ""), sorted(mat)
    line = tcl.build_line(tcl.Session(id="s"), "start_diff_review", {"unit": group.unit_id}, out)
    assert member not in (line.get("unit_whole") or []), line.get("unit_whole")
    assert (line.get("unit_rows") or {}).get(member) == [0, 20, 35], line.get("unit_rows")
