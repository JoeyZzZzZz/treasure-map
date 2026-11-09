# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""What a diff judgement's answer points to when it is written (lib/query/write_hints): the
entry's candidate rows by side, on every diff verdict (``other_direction``), and — on a
changed_real that names a sink removed or replaced — the same-shape groups of its calls
(``same_shape``). Read-only: nothing of it is stored, and no bucket, attention, order or review
state moves.

Zero real data: the one-diff world of test_same_shape_siblings, plus one aligned pair whose only
candidate row is on the B side."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from tests.unit.lib.test_same_shape_siblings import (  # noqa: F401 — the autouse fixture
    DIFF,
    GROUP_A,
    LISTED,
    SRC,
    World,
    _build,
    _ref,
    _servable,
)
from treasure_map import mcp_app
from treasure_map.lib.query import diff_review as dr
from treasure_map.lib.query import diff_workflow as dw
from treasure_map.lib.query import patch_view as pv
from treasure_map.lib.query import review_report as rr
from treasure_map.lib.query import same_shape_siblings as ss
from treasure_map.lib.query import write_hints as wh
from treasure_map.lib.rescan_version import CodeStamp
from treasure_map.version import UNKNOWN_VERSION

PAIR = "runA::runB"
BOTH = "pair:00001000:00002000"  # its one row has a ref on both sides (LISTED's)
A_ONLY = "pair:0000c000:0000d000"  # its one row: A side only (CTX_MEMBER)
B_ONLY = "pair:00028000:00029000"  # its one row: B side only (added here)
FN_LEVEL = "pair:0001c000:0001d000"  # its one row: a function-level A ref
VERDICTS = ("changed_real", "no_real_change", "change_inconclusive")


@pytest.fixture
def current(monkeypatch: pytest.MonkeyPatch) -> None:
    def fresh(atlas: Any, diff_id: str) -> dict[str, Any]:
        return {"source_stale": False, "source_stale_reason": None, "toolchain_checked": True}

    monkeypatch.setattr(pv, "diff_source_staleness", fresh)
    monkeypatch.setattr(ss, "diff_source_staleness", fresh)
    monkeypatch.setattr(mcp_app, "_diff_source_staleness", fresh)


@pytest.fixture
def world(tmp_path: Path, current: None) -> World:
    w = World(tmp_path)
    _build(w)
    w.pair("00028000", "00029000", 0.97, 0.6)
    w.inst("runB", _ref("runB", "00029000", "copy", "0x10"), "copy", "strcpy", SRC)
    w.fn("a", "00028000", [])
    w.fn("b", "00029000", ["strcpy"])
    w.commit()
    return w


def _entries(w: World) -> dict[str, dict[str, Any]]:
    view = pv.get_diff_patch_view(w.atlas, DIFF, limit=200)
    return {e["entry_id"]: e for e in view["entries"]}


def _anchor(w: World, entry_id: str) -> str:
    entries = _entries(w)
    assert entry_id in entries, sorted(entries)
    return str(entries[entry_id]["anchor_ref"])


def _args(anchor: str, verdict: str, **kw: Any) -> dict[str, Any]:
    args: dict[str, Any] = {"anchor_ref": anchor, "verdict": verdict, "diff_id": DIFF}
    if verdict == "no_real_change":
        args.update(checked=[anchor], why_unchanged="the same call on both sides")
    else:
        args["rationale"] = "read both sides"
    return {**args, **kw}


def _rows_by_side(entry: dict[str, Any]) -> tuple[int, int]:
    """The entry's rows with a ref on the A side only and on the B side only, read off the view
    as get_diff_patch_view renders it — an independent count of what other_direction gives."""
    rows = entry.get("rows") or []
    assert len(rows) == entry["rows_total"]  # every row on the page
    a = sum(1 for r in rows if r.get("a_ref") and not r.get("b_ref"))
    b = sum(1 for r in rows if r.get("b_ref") and not r.get("a_ref"))
    return a, b


# ── other_direction: on every verdict, both sides ───────────────────────────────────────────


@pytest.mark.parametrize("verdict", VERDICTS)
@pytest.mark.parametrize("entry_id", [A_ONLY, B_ONLY])
def test_every_verdict_is_told_the_rows_on_one_side_only(
    world: World, verdict: str, entry_id: str
) -> None:
    """★ T-G9a / T-G9a′: whichever diff verdict is written — no_real_change, the one that sinks an
    entry, included — on an entry holding a row with a ref on one side only, the answer carries
    ``other_direction``: both counts (an A-only entry still says 0 on B, and the other way
    round), equal to the rows the view renders, and the call that reads them by the entry's own
    id (never get_diff_sink_overlay, which has no entry filter).

    MUTATION (verified RED, 4 failed): give other_direction only when verdict == "changed_real"
    -> the no_real_change and change_inconclusive cases RED (the r0 shape). MUTATION (verified
    RED, 3 failed): give only the B count -> the A_ONLY cases RED. MUTATION (verified RED, 6
    failed): point read_with at get_diff_sink_overlay(side=...) -> RED."""
    entry = _entries(world)[entry_id]
    tools = mcp_app.make_tools(world.path)
    got = tools["annotate_diff"](**_args(str(entry["anchor_ref"]), verdict))
    assert got.get("written") is True, got
    od = got.get("other_direction")
    assert od is not None, got
    assert (od.get("a_side_only_rows"), od.get("b_side_only_rows")) == _rows_by_side(entry)
    assert od["read_with"] == (
        f'get_diff_patch_view(diff_id="{DIFF}", entry_id="{entry_id}", rows_offset=0)'
    )
    assert "get_diff_sink_overlay" not in json.dumps(got)


def test_a_no_real_change_on_a_b_side_only_entry_is_told_its_b_rows(world: World) -> None:
    """★★ T-G9a′ — the one that matters most: a no_real_change (which sinks the entry) written on
    an entry whose only candidate row is on the B side gets ``other_direction`` with that row.

    MUTATION (verified RED, 1 failed): give other_direction on changed_real only -> RED."""
    entry = _entries(world)[B_ONLY]
    assert _rows_by_side(entry) == (0, 1)  # the precondition: one row, B side only
    tools = mcp_app.make_tools(world.path)
    got = tools["annotate_diff"](**_args(str(entry["anchor_ref"]), "no_real_change"))
    assert got.get("written") is True, got
    assert got.get("other_direction", {}).get("b_side_only_rows") == 1, got


def test_a_feature_kind_changed_real_is_told_both_sides(world: World) -> None:
    """T-G9a: a changed_real naming feature_added or feature_removed (what a change brings in or
    takes out) always carries other_direction when the entry has one-sided rows."""
    tools = mcp_app.make_tools(world.path)
    for kind, entry_id in (("feature_added", B_ONLY), ("feature_removed", A_ONLY)):
        got = tools["annotate_diff"](
            **_args(_anchor(world, entry_id), "changed_real", change_kind=[kind])
        )
        assert got.get("written") is True, got
        assert "other_direction" in got, got


def test_an_entry_with_no_one_sided_row_says_why_never_nothing(world: World) -> None:
    """★ T-G9b: an entry whose every row has a ref on both sides gets
    ``other_direction_unavailable`` with why — not an absent key; so does an anchor that is no
    entry (lib level), and an entry with no row.

    MUTATION (verified RED, 1 failed): return {} for an entry with no one-sided row -> RED."""
    tools = mcp_app.make_tools(world.path)
    got = tools["annotate_diff"](**_args(_anchor(world, BOTH), "change_inconclusive"))
    assert got.get("written") is True, got
    assert "other_direction" not in got
    assert "both sides" in str(got.get("other_direction_unavailable")), got
    none = wh.other_direction(DIFF, None, "the anchor names a file")
    assert none == {"other_direction_unavailable": "the anchor names a file"}
    bare = dr.Subject("function_pair", {}, pv._Entry(pair=None, unpaired=None))
    assert wh.other_direction(DIFF, bare, "x") == {
        "other_direction_unavailable": "the entry has no candidate row"
    }


def test_a_batch_tells_each_item_its_rows_by_side(world: World) -> None:
    """T-G9a in a batch: each item's echo carries its own other_direction (or why not)."""
    tools = mcp_app.make_tools(world.path)
    items = [
        _args(_anchor(world, e), v)
        for e, v in ((A_ONLY, "no_real_change"), (B_ONLY, "changed_real"), (BOTH, "changed_real"))
    ]
    out = tools["annotate_diff_batch"](
        [{k: v for k, v in i.items() if k != "diff_id"} for i in items], diff_id=DIFF
    )
    assert out.get("written") is True, out
    by = {r["index"]: r for r in out["results"]}
    assert by[0]["other_direction"]["a_side_only_rows"] == 1
    assert by[1]["other_direction"]["b_side_only_rows"] == 1
    assert "other_direction_unavailable" in by[2]


def test_a_batch_near_the_page_says_the_rows_call_once(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A batch whose echo nears the page keeps each item's two counts and says once the call that
    reads them and why an item has none (with its indexes).

    MUTATION (verified RED, 1 failed): leave other_direction out of the cut echo -> RED.
    MUTATION (verified RED, 1 failed): drop the reasons said once -> RED."""
    monkeypatch.setattr(mcp_app, "_ECHO_RESERVE", 10**9)
    tools = mcp_app.make_tools(world.path)
    items = [
        {"anchor_ref": _anchor(world, e), "verdict": "change_inconclusive", "rationale": "r"}
        for e in (A_ONLY, B_ONLY, BOTH)
    ]
    out = tools["annotate_diff_batch"](items, diff_id=DIFF)
    assert out.get("written") is True, out
    by = {r["index"]: r for r in out["results"]}
    assert by[0].get("other_direction") == {"a_side_only_rows": 1, "b_side_only_rows": 0}
    assert by[1].get("other_direction") == {"a_side_only_rows": 0, "b_side_only_rows": 1}
    assert "other_direction_unavailable" not in by[2]
    assert "other_direction_unavailable_indexes" in out, out
    (why,) = out["other_direction_unavailable_indexes"]
    assert out["other_direction_unavailable_indexes"][why] == [2]
    assert out["other_direction_read_with"].startswith(f'get_diff_patch_view(diff_id="{DIFF}"')


# ── same_shape: on a changed_real that names a sink removed or replaced ─────────────────────


def _one_diff_group(w: World, ref: str) -> dict[str, Any]:
    out = ss.same_shape_siblings(
        w.atlas,
        DIFF,
        evidence_ref=ref,
        build_hash=w.build,
        current=CodeStamp(hunt="src-a1a1a1a1a1a1a1a1", scan="{}"),
        commit=UNKNOWN_VERSION,
    )
    assert "group_ref" in out, out
    return out


def test_a_removed_sink_is_told_its_calls_same_shape_groups(world: World) -> None:
    """★ T-K9a: changed_real + sink_removed, no group_ref: ``same_shape.groups`` — one per group of
    the entry's A-side calls — with the group's ref, member count and by_landing exactly as
    same_shape_siblings gives them for this diff, the run pair's members outside this diff, and
    both calls that read it.

    MUTATION (verified RED, 1 failed): drop the same_shape hint from annotate_diff -> RED.
    MUTATION (verified RED, 1 failed): give the by_landing of the run-pair call (none) -> RED."""
    want = _one_diff_group(world, LISTED)
    tools = mcp_app.make_tools(world.path)
    got = tools["annotate_diff"](
        **_args(_anchor(world, BOTH), "changed_real", change_kind=["sink_removed"])
    )
    assert got.get("written") is True, got
    block = got.get("same_shape")
    assert block is not None, got
    (g,) = block["groups"]
    assert g["group_ref"] == want["group_ref"]
    assert g["member_count"] == want["member_count"] == len(GROUP_A)
    assert g["by_landing"] == want["by_landing"] and g["by_landing"]
    assert isinstance(g.get("members_outside_input_diff"), int), g
    assert g["read_with"] == {
        "one_diff": f'same_shape_siblings(diff_id="{DIFF}", evidence_ref="{LISTED}")',
        "run_pair": f'same_shape_siblings(diff_id="{PAIR}", evidence_ref="{LISTED}")',
    }


def test_a_judgement_that_leaned_on_the_same_shape_group_is_not_told_it_again(
    world: World,
) -> None:
    """★ T-K9b1: a changed_real + sink_removed that passed the same-shape group it leaned on
    (``…#f2:…``) carries no same_shape block.

    MUTATION (verified RED, 1 failed): ignore group_ref in wants_same_shape -> RED."""
    gref = _one_diff_group(world, LISTED)["group_ref"]
    tools = mcp_app.make_tools(world.path)
    got = tools["annotate_diff"](
        **_args(_anchor(world, BOTH), "changed_real", change_kind=["sink_removed"], group_ref=gref)
    )
    assert got.get("written") is True, got
    assert "same_shape" not in got and "same_shape_unavailable" not in got


@pytest.mark.parametrize(
    ("group_ref", "told"),
    [
        (None, True),
        ("runA::runB::libx#callee:system@callee-v1", True),
        ("runA::runB::libx#f2:abc:a@fpv/f2-v1", False),
    ],
    ids=["no_group", "callee_group", "same_shape_group"],
)
def test_only_a_same_shape_group_ref_skips_the_block(group_ref: str | None, told: bool) -> None:
    """★ T-K9b2: a callee group's group_ref (the ref a callee group unit's members are judged
    with) still gets the same-shape groups — only a same-shape group's ref skips them.

    MUTATION (verified RED, 1 failed): skip whenever a group_ref is passed -> callee_group RED."""
    basis = {"change_kind": ["sink_replaced"]}
    assert wh.wants_same_shape("changed_real", basis, group_ref) is told


@pytest.mark.parametrize(
    ("verdict", "kinds", "told"),
    [
        ("changed_real", ["sink_removed"], True),
        ("changed_real", ["sink_replaced", "guard_added"], True),
        ("changed_real", "sink_replaced", True),
        ("changed_real", ["guard_added"], False),
        ("changed_real", ["feature_removed"], False),
        ("changed_real", None, False),
        ("change_inconclusive", None, False),
    ],
)
def test_only_a_sink_removed_or_replaced_changed_real_is_told(
    verdict: str, kinds: Any, told: bool
) -> None:
    """★ T-K9c (lib): only those two change kinds ask for the groups."""
    basis = None if kinds is None else {"change_kind": kinds}
    assert wh.wants_same_shape(verdict, basis, None) is told


def test_a_guard_added_changed_real_carries_no_same_shape(world: World) -> None:
    """★ T-K9c: a changed_real naming only guard_added gets no same-shape block of any kind.

    MUTATION (verified RED, 1 failed): give the block on every changed_real -> RED."""
    tools = mcp_app.make_tools(world.path)
    got = tools["annotate_diff"](
        **_args(_anchor(world, BOTH), "changed_real", change_kind=["guard_added"])
    )
    assert got.get("written") is True, got
    assert not {k for k in got if k.startswith("same_shape")}, got


def test_an_entry_whose_rows_are_no_groups_members_says_why(world: World) -> None:
    """★ T-K9d: an entry whose only A-side row is a function-level ref (no group's member) gets
    ``same_shape_unavailable``, not nothing; so does an entry with no A-side row, and an entry
    with no row (lib level).

    MUTATION (verified RED, 1 failed): return {} when no group is found -> RED."""
    tools = mcp_app.make_tools(world.path)
    got = tools["annotate_diff"](
        **_args(_anchor(world, FN_LEVEL), "changed_real", change_kind=["sink_removed"])
    )
    assert got.get("written") is True, got
    assert "same_shape" not in got
    assert "not_a_member" in str(got.get("same_shape_unavailable")), got
    b_only = tools["annotate_diff"](
        **_args(_anchor(world, B_ONLY), "changed_real", change_kind=["sink_replaced"])
    )
    assert "A-side ref" in str(b_only.get("same_shape_unavailable")), b_only
    bare = dr.Subject("function_pair", {}, pv._Entry(pair=None, unpaired=None))
    ss_pass = wh.SameShapePass(build_hash=None, current=None, commit="c")
    assert wh.same_shape(world.atlas, DIFF, bare, ss_pass) == {
        "same_shape_unavailable": "the entry has no candidate row"
    }


def test_a_batch_computes_a_group_once_and_its_items_share_it(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ T-K9e: three items of one batch whose calls are members of the same group: the group is
    computed once (one one-diff same_shape_siblings call), and every item carries it.

    MUTATION (verified RED, 1 failed): never read ss.groups (compute per item) -> 3 calls -> RED."""
    calls: list[str] = []
    real = ss.same_shape_siblings

    def counted(atlas: Any, diff_id: str, **kw: Any) -> dict[str, Any]:
        if diff_id == DIFF:
            calls.append(diff_id)
        return real(atlas, diff_id, **kw)

    monkeypatch.setattr(ss, "same_shape_siblings", counted)
    tools = mcp_app.make_tools(world.path)
    shared = [BOTH, A_ONLY, "pair:00009000:0000a000"]
    items = [
        {
            "anchor_ref": _anchor(world, e),
            "verdict": "changed_real",
            "rationale": "r",
            "change_kind": ["sink_removed"],
        }
        for e in shared
    ]
    out = tools["annotate_diff_batch"](items, diff_id=DIFF)
    assert out.get("written") is True, out
    refs = {r["same_shape"]["groups"][0]["group_ref"] for r in out["results"]}
    assert len(refs) == 1 and len(out["results"]) == 3
    assert calls == [DIFF]


def test_past_its_time_a_group_is_deferred_and_the_write_stands(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ T-K9e: with no time left for same-shape groups the write is made all the same, and the
    group is ``same_shape_deferred`` with the calls that read it — never computed in the write's
    time.

    MUTATION (verified RED, 1 failed): ignore the deadline -> same_shape computed -> RED."""
    monkeypatch.setattr(wh, "SAME_SHAPE_SECONDS", 0.0)
    tools = mcp_app.make_tools(world.path)
    anchor = _anchor(world, BOTH)
    got = tools["annotate_diff"](**_args(anchor, "changed_real", change_kind=["sink_removed"]))
    assert got.get("written") is True, got
    assert "same_shape" not in got
    (deferred,) = got["same_shape_deferred"]["groups"]
    assert deferred["read_with"]["one_diff"].startswith("same_shape_siblings(")
    stored = world.atlas.execute(
        "SELECT verdict FROM overlay WHERE anchor_ref = ?", (anchor,)
    ).fetchone()
    assert stored is not None and stored[0] == "changed_real"


def test_near_the_page_a_group_keeps_its_ref_count_and_calls_only(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ T-K9e: an answer past the hints' room keeps each group's ref, member count and calls, and
    says ``by_landing_withheld``.

    MUTATION (verified RED, 1 failed): never withhold -> by_landing still there -> RED."""
    monkeypatch.setattr(mcp_app, "_ECHO_RESERVE", 10**9)
    tools = mcp_app.make_tools(world.path)
    got = tools["annotate_diff"](
        **_args(_anchor(world, BOTH), "changed_real", change_kind=["sink_removed"])
    )
    block = got.get("same_shape")
    assert block is not None and block.get("by_landing_withheld") is True, got
    (g,) = block["groups"]
    assert set(g) == {"group_ref", "member_count", "read_with"}


def _unit_of(tools: dict[str, Any], entry_id: str) -> tuple[str, str]:
    """A unit handed out holding ``entry_id`` — its id and the member's anchor."""
    for _ in range(40):
        start = tools["start_diff_review"](run_pair=PAIR, k=200)
        nu = start.get("next_unit")
        assert nu is not None, start
        for m in nu.get("members") or nu["material"].get("entries", []):
            if m.get("entry_id") == entry_id:
                return nu["unit_id"], str(m["anchor_ref"])
        for m in nu.get("members") or []:
            tools["annotate_diff"](
                anchor_ref=m["anchor_ref"],
                verdict="change_inconclusive",
                rationale="r",
                diff_id=DIFF,
                unit_id=nu["unit_id"],
            )
    raise AssertionError(f"no unit handed out {entry_id}")


def test_the_hints_are_in_the_answer_before_the_next_unit_is_fit(world: World) -> None:
    """★ T-K9e: the hints join the answer BEFORE its size is taken for the next unit's material —
    so they come before ``next_unit`` in the answer, and the answer stays within the page.

    MUTATION (verified RED, 1 failed): merge the hints after _after_unit_write -> they come after
    next_unit -> RED."""
    tools = mcp_app.make_tools(world.path)
    uid, anchor = _unit_of(tools, BOTH)
    got = tools["annotate_diff"](
        **_args(anchor, "changed_real", change_kind=["sink_removed"], unit_id=uid)
    )
    keys = list(got)
    assert "next_unit" in keys, got
    assert keys.index("same_shape") < keys.index("next_unit")
    assert keys.index("other_direction_unavailable") < keys.index("next_unit")
    assert len(json.dumps(got)) <= mcp_app._RESPONSE_BYTE_BUDGET


# ── nothing is stored, nothing moves; the wording stays the view's own ──────────────────────


def test_the_hints_are_never_stored_and_move_no_entry(world: World) -> None:
    """★ T-G9e: the stored judgement carries no hint (its basis is what was written), and every
    entry's bucket, attention, significance and place in the view, and the must-read set, read the
    same before and after hint-carrying writes.

    MUTATION (verified RED, 1 failed): put other_direction into the stored verdict_basis -> RED."""
    from treasure_map.lib.query import review_units as ru

    def shape() -> tuple[list[Any], list[str]]:
        view = pv.get_diff_patch_view(world.atlas, DIFF, limit=200)
        order = [
            (e["entry_id"], e.get("bucket"), e.get("attention"), e.get("significance"))
            for e in view["entries"]
        ]
        ru.DIFF_CACHE.clear()
        rev = ru.review_pair(
            world.atlas,
            "runA",
            "runB",
            k=4,
            pair_staleness={"source_stale": False},
            server_commit="c",
        )
        must = sorted(m.anchor_ref for u in rev.units if u.must_read for m in u.members)
        return order, must

    before = shape()
    tools = mcp_app.make_tools(world.path)
    for entry_id in (A_ONLY, B_ONLY):
        got = tools["annotate_diff"](
            **_args(_anchor(world, entry_id), "changed_real", change_kind=["sink_removed"])
        )
        assert got.get("written") is True, got
    for (basis,) in world.atlas.execute("SELECT verdict_basis FROM overlay"):
        text = basis or ""
        assert "other_direction" not in text and "same_shape" not in text, text
    assert shape() == before


# The words G-9's own fields and sentences never use: a direction judgement or a risk judgement.
_JUDGEMENT_WORDS = re.compile(
    r"\b(added|new|deleted|gone|missing|removed|introduced|attack_surface|attack surface|"
    r"new_risk|risk|vulnerab\w*|exploit\w*|unsafe|safe)\b",
    re.IGNORECASE,
)


def test_the_two_direction_wording_is_tmaps_own_and_judges_nothing(world: World) -> None:
    """★ T-G9d: the field names and texts G-9 itself produces — other_direction and its keys, the
    reasons other_direction_unavailable gives, the sentence PAIR_WORKFLOW and the hand-off header
    carry — use the view's side wording (A side / B side, '-' / '+'), never a direction judgement
    (added / new / deleted / gone / missing) or a risk word. The scan is limited to what tmap
    writes here: a change kind an agent records (feature_added) is its value, printed as given.

    MUTATION (verified RED, 1 failed): word PAIR_SIDES "the new B-side lines" -> RED."""
    tools = mcp_app.make_tools(world.path)
    texts = [dw.PAIR_SIDES]
    for entry_id in (A_ONLY, BOTH):
        got = tools["annotate_diff"](**_args(_anchor(world, entry_id), "change_inconclusive"))
        for key in ("other_direction", "other_direction_unavailable"):
            if key in got:
                texts += [key, json.dumps(got[key])]
    texts.append(wh.other_direction(DIFF, None, "x")["other_direction_unavailable"])
    header = rr.handoff_header(PAIR, 1)
    assert dw.PAIR_SIDES in header and dw.PAIR_SIDES in dw.PAIR_WORKFLOW
    texts += [header.replace(rr.HANDOFF_BOUNDARY, "")]
    hits = [m.group(0) for t in texts for m in _JUDGEMENT_WORDS.finditer(t.replace("_", " "))]
    assert hits == [], hits
    assert any("other_direction" in t for t in texts)  # the scan read the fields
