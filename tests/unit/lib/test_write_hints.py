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
    """★ T-K9e: an answer past the hints' room keeps each group's ref, member counts (this diff's,
    and outside it across the run pair, once read) and calls, and says ``by_landing_withheld``.

    MUTATION (verified RED, 1 failed): never withhold -> by_landing still there -> RED.
    MUTATION (verified RED, 1 failed): leave members_outside_input_diff out of the kept keys (the
    run pair's count read, then dropped) -> RED."""
    monkeypatch.setattr(mcp_app, "_ECHO_RESERVE", 10**9)
    tools = mcp_app.make_tools(world.path)
    got = tools["annotate_diff"](
        **_args(_anchor(world, BOTH), "changed_real", change_kind=["sink_removed"])
    )
    block = got.get("same_shape")
    assert block is not None and block.get("by_landing_withheld") is True, got
    (g,) = block["groups"]
    assert set(g) == {"group_ref", "member_count", "members_outside_input_diff", "read_with"}
    assert isinstance(g["members_outside_input_diff"], int), g


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


# ── the time: one-diff facts first, the run pair's part in the time left ────────────────────

WRAPPED_ENTRY = "pair:00018000:00019000"  # its call is a member of the wrapper group (4 members)


def test_past_its_time_only_the_run_pair_part_is_deferred(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ MAJOR-4: two groups in one batch (GROUP_A, 7 members; the wrapper group, 4); the call's
    time runs out during the first run-pair read. Both groups still carry their one-diff facts
    (ref, member count, by_landing); the run-pair part was read for the smaller group first, and
    the other says ``members_outside_input_diff`` null with ``members_outside_deferred`` — its
    ``read_with.run_pair`` call reads it.

    MUTATION (verified RED, 1 failed): read each group's run pair as it is computed (one part, as
    before) -> the time runs out on GROUP_A's run pair, the wrapper group is deferred whole (no
    member count) -> RED. MUTATION (verified RED, 1 failed): read the run pairs largest group
    first -> GROUP_A's read, the wrapper group's deferred -> RED."""
    late = {"now": False}
    real = ss.same_shape_siblings

    def pair_read(atlas: Any, diff_id: str, **kw: Any) -> dict[str, Any]:
        out = real(atlas, diff_id, **kw)
        if diff_id == PAIR:
            late["now"] = True  # this read took the call past its time
        return out

    monkeypatch.setattr(ss, "same_shape_siblings", pair_read)
    monkeypatch.setattr(wh.SameShapePass, "over", lambda self: late["now"])
    tools = mcp_app.make_tools(world.path)
    items = [
        {
            "anchor_ref": _anchor(world, e),
            "verdict": "changed_real",
            "rationale": "r",
            "change_kind": ["sink_removed"],
        }
        for e in (BOTH, WRAPPED_ENTRY)
    ]
    out = tools["annotate_diff_batch"](items, diff_id=DIFF)
    assert out.get("written") is True, out
    by = {r["index"]: r for r in out["results"]}
    assert "same_shape_deferred" not in by[0] and "same_shape_deferred" not in by[1], out
    (big,) = by[0]["same_shape"]["groups"]
    (small,) = by[1]["same_shape"]["groups"]
    assert (big.get("member_count"), small.get("member_count")) == (7, 4), (big, small)
    assert big.get("by_landing") and small.get("by_landing")
    assert isinstance(small.get("members_outside_input_diff"), int), small
    assert small.get("members_outside_deferred") is None
    assert big.get("members_outside_input_diff", "absent") is None, big
    assert big.get("members_outside_deferred") is True
    assert big["read_with"]["run_pair"].startswith(f'same_shape_siblings(diff_id="{PAIR}"')


def test_a_single_write_reads_its_groups_run_pair_part_too(world: World) -> None:
    """The one-judgement path calls the second part as well: its group's run-pair count is read,
    never left at the null placeholder.

    MUTATION (verified RED, 1 failed): leave ``_wh.finish`` out of annotate_diff -> null -> RED."""
    tools = mcp_app.make_tools(world.path)
    got = tools["annotate_diff"](
        **_args(_anchor(world, BOTH), "changed_real", change_kind=["sink_removed"])
    )
    (g,) = got["same_shape"]["groups"]
    assert isinstance(g.get("members_outside_input_diff"), int), g
    assert "members_outside_deferred" not in g


# ── a batch's echo near the page: each group said once, then counts ─────────────────────────


def _synthetic_groups(n: int, prefix: str) -> list[dict[str, Any]]:
    pad = "x" * 300
    return [
        {
            "group_ref": f"{prefix}#f2:{i:04d}",
            "read_with": {"one_diff": f"same_shape_siblings({pad}{i})", "run_pair": pad},
        }
        for i in range(n)
    ]


def _all_items(world: World) -> list[dict[str, Any]]:
    return [
        {
            "anchor_ref": e["anchor_ref"],
            "verdict": "changed_real",
            "rationale": "r",
            "change_kind": ["sink_removed"],
        }
        for e in _entries(world).values()
    ]


def test_a_cut_batch_says_each_deferred_group_once(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ MAJOR-5: every item of a batch with the same ten groups deferred, each with its calls: the
    cut echo lists each group once for the batch (``same_shape_deferred_groups``, by group_ref)
    and each item only their indexes there — the answer within the page, every group_ref named.

    MUTATION (verified RED, 1 failed): keep each item's same_shape_deferred as it is (the old cut
    echo) -> the answer over the page -> RED."""
    shared = _synthetic_groups(10, "G")

    def deferred(atlas: Any, diff_id: str, subject: Any, ss_pass: Any) -> dict[str, Any]:
        return {"same_shape_deferred": {"groups": shared, "why": "ran out"}}

    monkeypatch.setattr(wh, "same_shape", deferred)
    tools = mcp_app.make_tools(world.path)
    items = _all_items(world)
    full = len(json.dumps(shared)) * len(items)
    assert full > mcp_app._RESPONSE_BYTE_BUDGET  # the precondition: said per item, over the page
    out = tools["annotate_diff_batch"](items, diff_id=DIFF)
    assert out.get("written") is True, out
    text = json.dumps(out)
    assert len(text) <= mcp_app._RESPONSE_BYTE_BUDGET, len(text)
    listed = out["same_shape_deferred_groups"]
    assert [g["group_ref"] for g in listed] == [g["group_ref"] for g in shared]
    assert out["same_shape_deferred_why"] == "ran out"
    for r in out["results"]:
        assert [listed[i]["group_ref"] for i in r["same_shape_deferred"]] == [
            g["group_ref"] for g in shared
        ], r


def test_a_cut_batch_still_near_the_page_gives_its_groups_by_count(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ MAJOR-5: groups so many that even said once they near the page: each item's groups and the
    batch's listings become counts, and ``same_shape_withheld`` says why — the answer within the
    page.

    MUTATION (verified RED, 1 failed): skip the second measure (no count cut) -> over -> RED."""
    calls = {"n": 0}

    def own_groups(atlas: Any, diff_id: str, subject: Any, ss_pass: Any) -> dict[str, Any]:
        calls["n"] += 1
        groups = _synthetic_groups(30, f"I{calls['n']}")
        return {"same_shape": {"groups": [{**g, "member_count": 2} for g in groups]}}

    monkeypatch.setattr(wh, "same_shape", own_groups)
    tools = mcp_app.make_tools(world.path)
    out = tools["annotate_diff_batch"](_all_items(world), diff_id=DIFF)
    assert out.get("written") is True, out
    assert len(json.dumps(out)) <= mcp_app._RESPONSE_BYTE_BUDGET
    assert "page_budget" in out.get("same_shape_withheld", ""), sorted(out)
    assert out["same_shape_groups"] == 30 * calls["n"]
    assert all(r["same_shape"] == 30 for r in out["results"]), out["results"][:2]


def _evidence_ref(i: int) -> str:
    return f"runA::usr/sbin/httpd::{0x40000 + 16 * i:08x}::callsite::strcpy::{'k' * 120}"


def test_a_cut_batch_lists_every_group_once_with_one_call_template(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ G-4: sixty-one groups, each with its two calls (one diff, the run pair) and long refs,
    spread over the batch's items: said per group, the calls alone near the page. The cut echo
    says the two calls once (``same_shape_read_with``, the ref a slot), lists each group once
    (``same_shape_groups``: its group_ref, counts and the ``evidence_ref`` that fills the slot) and
    each item the indexes of its groups — the answer within the page, every group listed, each
    item's groups read back by index, nothing given by count.

    MUTATION (verified RED, 1 failed): keep each group's read_with in the listing (no template)
    -> the listings near the page, the items by count -> RED."""
    n = 61
    items = _all_items(world)
    held = {
        i: [g for g in range(n) if g % len(items) == i % len(items) or g < 8]
        for i in range(len(items))
    }
    calls = {"n": 0}
    refs = {g: f"{DIFF}#f2:{'s' * 60}:{g:04d}:a@3/2" for g in range(n)}

    def spread(atlas: Any, diff_id: str, subject: Any, ss_pass: Any) -> dict[str, Any]:
        i = calls["n"]
        calls["n"] += 1
        groups = []
        for g in held[i]:
            ss_pass.refs.setdefault(refs[g], _evidence_ref(g))
            groups.append(
                {
                    "group_ref": refs[g],
                    "member_count": 3,
                    "by_landing": {"A": {"-": 3}},
                    "members_outside_input_diff": 5,
                    "read_with": wh._read_with(diff_id, PAIR, _evidence_ref(g)),
                }
            )
        return {"same_shape": {"groups": groups}}

    monkeypatch.setattr(wh, "same_shape", spread)
    per_group = sum(len(json.dumps(wh._read_with(DIFF, PAIR, _evidence_ref(g)))) for g in range(n))
    assert per_group > 30_000  # the precondition: said per group, the calls alone near the page
    tools = mcp_app.make_tools(world.path)
    out = tools["annotate_diff_batch"](items, diff_id=DIFF)
    assert out.get("written") is True, out
    assert len(json.dumps(out)) <= mcp_app._RESPONSE_BYTE_BUDGET, len(json.dumps(out))
    assert "same_shape_withheld" not in out, out.get("same_shape_withheld")
    listed = out["same_shape_groups"]
    assert sorted(g["group_ref"] for g in listed) == sorted(refs.values())
    assert all(g["members_outside_input_diff"] == 5 and "read_with" not in g for g in listed)
    template = out["same_shape_read_with"]
    assert set(template) == {"one_diff", "run_pair"} and wh._REF_SLOT in template["one_diff"]
    for r in out["results"]:
        i = r["index"]
        assert [listed[k]["group_ref"] for k in r["same_shape"]] == [refs[g] for g in held[i]], r
        for k in r["same_shape"]:
            filled = template["one_diff"].replace(
                wh._REF_SLOT, json.dumps(listed[k]["evidence_ref"])
            )
            assert filled == wh._read_with(DIFF, PAIR, listed[k]["evidence_ref"])["one_diff"]


def test_a_batch_listing_keeps_the_run_pairs_count(world: World) -> None:
    """★ MINOR (G-5/8): a cut batch's group listing keeps the members outside the input diff that
    the second part read (and why a run pair could not be read), beside the group's ref, count
    and the evidence_ref its calls take.

    MUTATION (verified RED, 1 failed): leave members_outside_input_diff out of the kept keys ->
    RED."""
    ss_pass = wh.SameShapePass(build_hash=None, current=None, commit="c")
    ss_pass.refs["G#f2:1"] = "ref-1"
    ss_pass.refs["G#f2:2"] = "ref-2"
    group = {
        "group_ref": "G#f2:1",
        "member_count": 4,
        "by_landing": {"A": {"-": 4}},
        "members_outside_input_diff": 7,
        "read_with": {"one_diff": "x", "run_pair": "y"},
    }
    other = {"group_ref": "G#f2:2", "member_count": 2, "run_pair_unavailable": "e", "read_with": {}}
    results = [{"same_shape": {"groups": [group, other]}}, {"same_shape": {"groups": [group]}}]
    items, batch = wh.batch_same_shape(results, ss_pass, DIFF)
    assert items == [{"same_shape": [0, 1]}, {"same_shape": [0]}]
    first, second = batch["same_shape_groups"]
    assert first == {
        "group_ref": "G#f2:1",
        "member_count": 4,
        "members_outside_input_diff": 7,
        "evidence_ref": "ref-1",
    }
    assert second["run_pair_unavailable"] == "e" and second["evidence_ref"] == "ref-2"


def test_a_deferred_group_still_says_its_member_count(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ MINOR (G-5/6): with the write call's time gone before any group is begun, each deferred
    group still says its member count — the one same_shape_siblings gives for it — read from the
    side's calls already in hand.

    MUTATION (verified RED, 1 failed): leave member_count out of a deferred group -> RED."""
    monkeypatch.setattr(wh.SameShapePass, "over", lambda self: True)
    tools = mcp_app.make_tools(world.path)
    got = tools["annotate_diff"](
        **_args(_anchor(world, BOTH), "changed_real", change_kind=["sink_removed"])
    )
    late = got.get("same_shape_deferred")
    assert late is not None and "same_shape" not in got, sorted(got)
    want = _one_diff_group(world, LISTED)
    (g,) = late["groups"]
    assert g["group_ref"] == want["group_ref"]
    assert g.get("member_count") == want["member_count"], (g, want["member_count"])


@pytest.mark.parametrize("level", ["relation_and_count", "count"])
def test_a_batch_whose_groups_echo_nears_the_page_cuts_it(
    world: World, monkeypatch: pytest.MonkeyPatch, level: str
) -> None:
    """★ G-3: the echo of the groups the items leaned on is measured with the rest: an echo near
    the page by itself keeps each group's relation and member count — still near it, their count —
    and ``groups_withheld`` says so; the answer within the page, each item naming its group_ref.

    MUTATION (verified RED, 2 failed): measure the items' echo only (the old check) -> the groups
    echo kept whole -> over the page -> RED."""
    gref = _one_diff_group(world, LISTED)["group_ref"]
    pad = "s" * 45_000
    real = mcp_app._diff_group_echo

    def big(atlas: Any, row_id: int) -> dict[str, Any] | None:
        echo = real(atlas, row_id)
        assert echo is not None
        if level == "count":
            return {**echo, "relation": pad}
        return {**echo, "summary": pad}

    monkeypatch.setattr(mcp_app, "_diff_group_echo", big)
    tools = mcp_app.make_tools(world.path)
    item = {
        "anchor_ref": _anchor(world, BOTH),
        "verdict": "changed_real",
        "rationale": "r",
        "change_kind": ["sink_removed"],
        "group_ref": gref,
    }
    out = tools["annotate_diff_batch"]([item], diff_id=DIFF)
    assert out.get("written") is True, out
    assert len(json.dumps(out)) <= mcp_app._RESPONSE_BYTE_BUDGET, len(json.dumps(out))
    assert "page_budget" in out.get("groups_withheld", ""), sorted(out)
    assert [r.get("group_ref") for r in out["results"]] == [gref]
    if level == "count":
        assert out["groups"] == 1
    else:
        assert set(out["groups"][gref]) <= {"group_ref", "relation", "member_count"}
        assert out["groups"][gref]["member_count"] == _one_diff_group(world, LISTED)["member_count"]


def test_a_batch_builds_its_subjects_once(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    """MINOR 10: a batch's hints read every item's subject from one build of the diff's subjects,
    never one build per item.

    MUTATION (verified RED, 1 failed): leave the batch's subjects out of _write_hints (each item
    builds its own) -> entry_subject once per item -> RED."""
    whole: list[str] = []
    one: list[str] = []
    real_all, real_one = wh.entry_subjects, wh.entry_subject

    def all_counted(*a: Any, **kw: Any) -> Any:
        whole.append("x")
        return real_all(*a, **kw)

    def one_counted(*a: Any, **kw: Any) -> Any:
        one.append("x")
        return real_one(*a, **kw)

    monkeypatch.setattr(wh, "entry_subjects", all_counted)
    monkeypatch.setattr(wh, "entry_subject", one_counted)
    items = _all_items(world)
    assert len(items) > 2
    tools = mcp_app.make_tools(world.path)
    out = tools["annotate_diff_batch"](items, diff_id=DIFF)
    assert out.get("written") is True, out
    assert (len(whole), len(one)) == (1, 0), (whole, one)


def test_a_candidate_anchor_is_told_its_whole_entrys_rows_by_side(world: World) -> None:
    """MINOR 11: on a candidate anchor (one row of an entry), ``other_direction`` counts the whole
    entry's rows — here the anchor's own row has refs on both sides and another row of the entry
    a B ref only: b_side_only_rows 1 — while ``same_shape`` reads the anchor's row alone.

    MUTATION (verified RED, 1 failed): count the anchor's own row only -> 0 -> RED."""
    world.inst("runB", _ref("runB", "00002000", "copy", "0x30"), "copy", "strcpy", SRC)
    world.commit()
    entry = _entries(world)[BOTH]
    assert _rows_by_side(entry) == (0, 1)  # the precondition: the other row is B only
    row = next(r for r in entry["rows"] if r.get("a_ref") == LISTED)
    anchor = (
        f"{PAIR}#candidate#{row['key_granularity']}|{row['sink_class']}|{LISTED}|{row['b_ref']}"
    )
    tools = mcp_app.make_tools(world.path)
    got = tools["annotate_diff"](**_args(anchor, "changed_real", change_kind=["sink_removed"]))
    assert got.get("written") is True, got
    od = got.get("other_direction")
    assert od is not None, got
    assert (od["a_side_only_rows"], od["b_side_only_rows"]) == (0, 1)
    (g,) = got["same_shape"]["groups"]
    assert g["member_count"] == len(GROUP_A)


def test_a_presence_and_a_file_anchor_say_their_own_why() -> None:
    """MINOR 12: the reason a binary one run holds alone has no rows by side is that every
    candidate is on that side; a file's is that it has no candidate rows; anything else names no
    entry.

    MUTATION (verified RED, 1 failed): one reason for all three (the old text) -> RED."""
    presence = f"{PAIR}#binary_presence#a_only:usr/sbin/x::00001000"
    assert dr.is_binary_presence_anchor(presence)  # the precondition: read as a presence anchor
    assert "any candidate of it is on that side" in wh.no_entry_why(presence)
    assert "has no candidate rows" in wh.no_entry_why(f"{PAIR}#non_binary#etc/rc")
    assert "every candidate" not in wh.no_entry_why(f"{PAIR}#non_binary#etc/rc")
    assert "no entry of a binary diff" in wh.no_entry_why(f"{PAIR}#function_pair#x::1::2")


def test_a_large_hint_leaves_less_room_for_the_next_units_material(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ T-K9e (MINOR-9): a ~20 KB same-shape block, and a next unit whose material fills every
    byte it is given: the answer stays within the page only if the hints were counted in the size
    the material was fit beside.

    MUTATION (verified RED, 1 failed): measure the answer without its hints for the next unit's
    room -> over the page by about the block -> RED."""
    block = {"groups": [{"group_ref": "G#f2:1", "member_count": 2, "read_with": "y" * 20_000}]}

    def big(atlas: Any, diff_id: str, subject: Any, ss_pass: Any) -> dict[str, Any]:
        return {"same_shape": block}

    real_fit = mcp_app._entry_within_budget

    def fill(entry: dict[str, Any], base: int, budget: int | None = None) -> dict[str, Any]:
        out = real_fit(entry, base, budget)
        if budget is None:
            return out
        return {**out, "pad": "z" * max(0, budget - len(json.dumps(out)) - 16)}

    tools = mcp_app.make_tools(world.path)
    uid, anchor = _unit_of(tools, BOTH)
    monkeypatch.setattr(wh, "same_shape", big)
    monkeypatch.setattr(mcp_app, "_entry_within_budget", fill)
    got = tools["annotate_diff"](
        **_args(anchor, "changed_real", change_kind=["sink_removed"], unit_id=uid)
    )
    nu = got.get("next_unit")
    assert nu is not None and "pad" in json.dumps(nu.get("material")), sorted(got)
    assert len(json.dumps(got["same_shape"])) > 20_000  # the precondition: the block was kept
    assert len(json.dumps(got)) <= mcp_app._RESPONSE_BYTE_BUDGET, len(json.dumps(got))


def test_a_large_hint_in_a_batch_leaves_less_room_for_the_next_units_material(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ MINOR (G-5/5): as for one judgement, a batch's ~20 KB same-shape block is counted in the
    size the next unit's material is fit beside — the answer within the page.

    MUTATION (verified RED, 1 failed): measure the batch's answer without its results for the
    next unit's room -> over the page -> RED."""
    block = {"groups": [{"group_ref": "G#f2:1", "member_count": 2, "read_with": "y" * 20_000}]}

    def big(atlas: Any, diff_id: str, subject: Any, ss_pass: Any) -> dict[str, Any]:
        return {"same_shape": block}

    real_fit = mcp_app._entry_within_budget

    def fill(entry: dict[str, Any], base: int, budget: int | None = None) -> dict[str, Any]:
        out = real_fit(entry, base, budget)
        if budget is None:
            return out
        return {**out, "pad": "z" * max(0, budget - len(json.dumps(out)) - 16)}

    tools = mcp_app.make_tools(world.path)
    uid, anchor = _unit_of(tools, BOTH)
    monkeypatch.setattr(wh, "same_shape", big)
    monkeypatch.setattr(mcp_app, "_entry_within_budget", fill)
    item = {
        "anchor_ref": anchor,
        "verdict": "changed_real",
        "rationale": "r",
        "change_kind": ["sink_removed"],
    }
    got = tools["annotate_diff_batch"]([item], diff_id=DIFF, unit_id=uid)
    assert got.get("written") is True, got
    nu = got.get("next_unit")
    assert nu is not None and "pad" in json.dumps(nu.get("material")), sorted(got)
    assert len(json.dumps(got["results"])) > 20_000  # the precondition: the block was kept
    assert len(json.dumps(got)) <= mcp_app._RESPONSE_BYTE_BUDGET, len(json.dumps(got))
