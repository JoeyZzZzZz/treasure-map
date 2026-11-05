# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Callee groups (lib/query/callee_groups) and what rides on them: the group units of the pair
review, a judgement leaning on a callee group (group freshness), and the reduce.

Zero real data: the World of test_patch_view (one diff of libx)."""

from __future__ import annotations

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


def _world(tmp: Path) -> World:
    """X (new_helper at B 00009000) is paired with A's old_helper (00008000). P1 and P2 call X on
    B and nothing like it on A; P3's A side calls old_helper (X's counterpart) — not new; P4's A
    side has no function in that analysis.db (its call list cannot be read); every B side also
    calls ``system``, an import, never a key."""
    w = World(tmp)
    w.pair(X_A, X_B, 0.97, 0.9)
    w.fn("a", X_A, [], name="old_helper")
    w.fn("b", X_B, [], name="new_helper")
    for a, b in (P1, P2, P3, P4):
        w.pair(a, b, 0.97, 0.6)
        w.fn("b", b, ["system", "new_helper"], name=f"fn_{b}")
    w.fn("a", P1[0], ["system"], name=f"fn_{P1[1]}")
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
