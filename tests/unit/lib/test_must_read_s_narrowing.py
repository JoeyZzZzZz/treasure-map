# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The must-read predicate v3 on bucket S: an S entry is must-read when it carries a candidate row
(``bucket_s_candidate``) or is in one of its diff's callee groups (``bucket_s_callee_group``), or
by any other reason; the rest of bucket S is second tier — still listed, counted, offered (ask
the person first) and handed out by ``sweep``. The P predicate is unchanged.

Zero real data: the Worlds of test_diff_review / test_review_units (one diff of libx, S pairs)
and of test_patch_view / test_callee_groups (a callee group)."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tests.unit.lib.test_diff_review import (  # noqa: F401 — the autouse cache fixture
    DX,
    PAIR,
    World,
    _clear_view_caches,
    _ref,
    _row,
)
from tests.unit.lib.test_review_units import _diff, _facts, _m, _review
from tests.unit.test_tool_surface import _call
from treasure_map import mcp_app, mcp_cards
from treasure_map.lib import overlay
from treasure_map.lib.query import diff_skill
from treasure_map.lib.query import patch_view as pv
from treasure_map.lib.query import review_units as ru
from treasure_map.lib.setup import skills as sk

_SRC = Path(__file__).parents[3] / "src" / "treasure_map"
_FIXTURES = Path(__file__).parents[2] / "fixtures"


@pytest.fixture(autouse=True)
def _clear_unit_cache() -> None:
    ru.DIFF_CACHE.clear()


def _s_pairs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rows: list[int]
) -> tuple[World, list[str]]:
    """One aligned similarity-1 pair in DX per item of ``rows``, all read as differing (bucket S),
    each with that many persisted candidate rows (a row placed A / R / P / B would move it out of
    S). Returns the world and the entry ids in order."""
    w = World(tmp_path, monkeypatch)
    pairs, ids = [], []
    for i, n in enumerate(rows, start=1):
        a = f"{i:08x}"
        w.pair(DX, a, a, sim=1.0)
        for j in range(n):
            w.rows.setdefault(DX, []).append(
                _row(
                    _ref("runA", a, f"0x{16 + j:x}"),
                    _ref("runB", a, f"0x{16 + j:x}"),
                    presence="persisted",
                    call="present_same_callee",
                )
            )
        pairs.append((a, a))
        ids.append(f"pair:{a}:{a}")
    monkeypatch.setattr(pv, "_differs_of", lambda readings, built: frozenset(pairs))
    return w, ids


def _unit_of(r: ru.PairReview, entry_id: str) -> ru.Unit:
    (u,) = [u for u in r.units if any(m.entry_id == entry_id for m in u.members)]
    return u


def _member(r: ru.PairReview, entry_id: str) -> ru.Member:
    return next(m for m in _unit_of(r, entry_id).members if m.entry_id == entry_id)


# ── X-1 / X-2: a candidate row keeps an S entry must-read; none moves it to the second tier ──


def test_an_s_entry_with_one_candidate_row_stays_must_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-X1a: one persisted candidate row is enough — ``bucket_s_candidate``, in an S batch.

    MUTATION (verified RED): the gate as ``>= 2`` -> no reason -> second tier -> RED; the
    ``bucket_s_candidate`` branch dropped -> RED."""
    w, (one,) = _s_pairs(tmp_path, monkeypatch, [1])
    r = _review(w, k=0)
    m = _member(r, one)
    assert (m.bucket, m.rows) == ("S", 1)  # the precondition
    assert m.reasons == ("bucket_s_candidate",)
    assert m.must_read
    assert _unit_of(r, one).kind == ru.S_BATCH


def test_an_s_entry_with_no_candidate_row_and_no_other_reason_is_second_tier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ T-X1b: 0 rows, attention > 0, past k, in no group -> second tier, in no S batch.

    MUTATION (verified RED): X-1 alone, cut_units still routing every S entry to the S batch
    (``if m.bucket == "S":``) -> RED."""
    w, (none, one) = _s_pairs(tmp_path, monkeypatch, [0, 1])
    r = _review(w, k=0)
    m = _member(r, none)
    assert (m.bucket, m.rows, m.reasons) == ("S", 0, ())
    assert m.attention is not None and m.attention > 0  # the precondition
    assert _unit_of(r, none).kind == ru.SECOND_TIER
    s_batched = {x.entry_id for u in r.units if u.kind == ru.S_BATCH for x in u.members}
    assert none not in s_batched and one in s_batched


def test_another_reason_still_keeps_an_s_entry_without_rows_must_read() -> None:
    """T-X1c: 0 rows but attention 0 -> must-read (``attention_0``); 0 rows, no reason, but among
    the first k -> ``top_k`` puts it in the S batch.

    MUTATION (verified RED): S without rows always second tier (``and m.rows`` in cut_units) ->
    RED; the must-read test taken before top_k is added (``raw.must_read``) -> the top_k case
    -> RED."""
    e = SimpleNamespace(
        shown_bucket="S",
        shown_subclass=None,
        row_views=[],
        sink_candidate_counts=None,
        sink_callsite_counts=None,
        pair=None,
    )
    assert ru.entry_reasons(e, 9, 0, None, 0) == ("attention_0",)
    assert ru.entry_reasons(e, 9, 1, None, 0) == ()
    first = _m("pair:1", "p::d", 0, "S")
    later = _m("pair:2", "p::d", 1, "S")
    kept = _m("pair:3", "p::d", 2, "S", ("attention_0",))
    units = ru.cut_units(_facts(diffs=[_diff("p::d", [first, later, kept])]), k=1)
    kind = {m.entry_id: u.kind for u in units for m in u.members}
    assert kind == {"pair:1": ru.S_BATCH, "pair:2": ru.SECOND_TIER, "pair:3": ru.S_BATCH}


def test_the_candidate_count_the_predicate_reads_is_the_members_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-X1d: ``bucket_s_candidate`` holds exactly for the S members whose ``rows`` (the count
    the member carries, ``len(row_views)``) is at least one.

    MUTATION (verified RED): the predicate reads another count (``len(e.rows)``-style: the
    entry's raw rows, or ``e.candidate_count``) -> the 0/1/3 split moves -> RED."""
    w, ids = _s_pairs(tmp_path, monkeypatch, [0, 1, 3, 0])
    facts = ru.diff_facts(w.atlas, DX)
    assert facts is not None
    got = {m.entry_id: (m.rows, "bucket_s_candidate" in m.reasons) for m in facts.entries}
    assert got == {
        ids[0]: (0, False),
        ids[1]: (1, True),
        ids[2]: (3, True),
        ids[3]: (0, False),
    }
    listing = pv.significance_listing(w.atlas, DX)
    assert listing is not None
    assert {o.entry.entry_id: len(o.entry.row_views) for o in listing.entries} == {
        k: v[0] for k, v in got.items()
    }


def test_the_rename_touches_the_must_read_reason_only() -> None:
    """T-X1e: no whole-word ``bucket_s`` is left in review_units and none is a reason; the
    not_listed category of the same name (patch_view's fixture) is unchanged.

    MUTATION (verified RED): a blanket rename of ``bucket_s`` -> the fixture's category gone ->
    RED (and test_patch_view's not_listed test with it)."""
    src = (_SRC / "lib" / "query" / "review_units.py").read_text(encoding="utf-8")
    assert re.findall(r"\bbucket_s\b", src) == []
    assert "bucket_s" not in ru.REASONS
    assert {"bucket_s_candidate", "bucket_s_callee_group"} <= set(ru.REASONS)
    assert ru.REASONS.index("bucket_s_callee_group") == ru.REASONS.index("bucket_s_candidate") + 1
    full = (_FIXTURES / "patch_view_full_entries.json").read_text(encoding="utf-8")
    assert '"bucket_s":' in full


@pytest.mark.parametrize(
    "subclass",
    [
        "unmatched_analysis_complete",
        "unmatched_analysis_incomplete",
        "counterpart_suspected",
        "absent",
    ],
)
def test_every_p_entry_stays_must_read_without_a_candidate_row(subclass: str) -> None:
    """T-X1f: the P predicate is unchanged — every P subclass, 0 rows, attention > 0, past k.

    MUTATION (verified RED): ``p_entry`` gated on a subclass or a candidate row -> RED."""
    e = SimpleNamespace(
        shown_bucket="P",
        shown_subclass=subclass,
        row_views=[],
        sink_candidate_counts=None,
        sink_callsite_counts=None,
        pair=None,
    )
    assert ru.entry_reasons(e, 9, 2, None, 0) == ("p_entry",)


# ── the second tier still holds them ─────────────────────────────────────────────────────────


def test_the_moved_s_entries_are_offered_counted_and_handed_out_by_sweep(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-X2a / T-X2b / T-X2c: with the one must-read entry judged, the stop says must_read_complete
    and not complete, its offer counts the moved S entries under S (ask the person first, with
    sweep=true), the report still lists and counts them unjudged, and ``sweep=true`` hands out
    the second-tier unit they are in.

    MUTATION (verified RED): ``complete`` no longer counting the second tier -> RED; the moved
    entries dropped from all_listed -> RED; second tier not cut for them (neither tier) -> RED;
    continue_with without "ask the person" -> RED."""
    w, ids = _s_pairs(tmp_path, monkeypatch, [1, 0, 0])
    moved = set(ids[1:])
    server = mcp_app.build_server(w.path)
    head = _call(server, "start_diff_review", {"run_pair": PAIR, "k": 0})
    nu = head["next_unit"]
    assert nu is not None and nu["kind"] == ru.S_BATCH
    assert {m["entry_id"] for m in nu["members"]} == {ids[0]}
    wrote = _call(
        server,
        "annotate_diff",
        {
            "anchor_ref": nu["members"][0]["anchor_ref"],
            "verdict": "changed_real",
            "rationale": "r",
            "diff_id": DX,
            "unit_id": nu["unit_id"],
        },
    )
    assert wrote.get("next_unit") is None
    stop = _call(server, "start_diff_review", {"run_pair": PAIR, "k": 0})
    assert stop["next_unit"] is None
    offer = stop["coverage_offer"]
    assert offer["second_tier"]["by_bucket"] == {"S": len(moved)}
    assert offer["must_read_complete"] is True and offer["complete"] is False
    assert "ask the person" in offer["continue_with"] and "sweep=true" in offer["continue_with"]
    rep = _review(w, k=0).report
    assert rep["all_listed"]["members"] == 3 and rep["all_listed"]["unjudged"] == 2
    swept = _call(server, "start_diff_review", {"run_pair": PAIR, "k": 0, "sweep": True})
    su = swept["next_unit"]
    assert su is not None and su["kind"] == ru.SECOND_TIER
    assert {m["entry_id"] for m in su["members"]} == moved


# ── X-2b: the S members of a callee group are must-read with it ──────────────────────────────


def _group_world(tmp: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    """test_callee_groups's X (new_helper on B, paired with A's old_helper): P1 and P2, aligned
    similarity-1 pairs read as differing with no candidate row (bucket S), newly call X on B; P3
    is bucket S too but its A side calls X's counterpart (in no group)."""
    from tests.unit.lib.test_callee_groups import P1, P2, P3, X_A, X_B
    from tests.unit.lib.test_patch_view import World as PvWorld

    monkeypatch.setattr(
        pv,
        "diff_source_staleness",
        lambda atlas, diff_id: {
            "source_stale": False,
            "source_stale_reason": None,
            "toolchain_checked": True,
        },
    )
    w = PvWorld(tmp)
    w.pair(X_A, X_B, 0.97, 0.9)
    w.fn("a", X_A, [], name="old_helper")
    w.fn("b", X_B, [], name="new_helper")
    for a, b in (P1, P2, P3):
        w.pair(a, b, 0.97, 1.0)
        w.fn("b", b, ["system", "new_helper"], name=f"fn_{b}")
    w.fn("a", P1[0], ["system"], name=f"fn_{P1[1]}")
    w.fn("a", P2[0], ["system"], name=f"fn_{P2[1]}")
    w.fn("a", P3[0], ["system", "old_helper"], name=f"fn_{P3[1]}")
    w.commit()
    monkeypatch.setattr(pv, "_differs_of", lambda readings, built: frozenset({P1, P2, P3}))
    pv._clear_view_caches()
    return w, [f"pair:{a}:{b}" for a, b in (P1, P2, P3)]


def _cg_review(w: Any) -> ru.PairReview:
    return ru.review_pair(
        w.atlas,
        "runA",
        "runB",
        k=0,
        pair_staleness={"source_stale": False, "source_stale_reason": None},
        server_commit=None,
    )


def test_the_s_members_of_a_callee_group_are_must_read_in_its_unit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-X2d / T-X2e / T-X2f: the two grouped S entries (0 rows) are must-read by
    ``bucket_s_callee_group``, handed out together in one callee group unit, owed in the reduce;
    the third S entry (0 rows, in no group) is second tier; the report counts the reason.

    MUTATION (verified RED): the reason dropped -> the group has no must-read member, no group
    unit, the two in the second tier, reduce owed 0 -> RED. MUTATION (verified RED): the reason
    given to every S entry -> P3 must-read -> RED. MUTATION (verified RED): the reason not in
    REASONS -> report() KeyError -> RED."""
    w, (p1, p2, p3) = _group_world(tmp_path, monkeypatch)
    r = _cg_review(w)
    for e in (p1, p2):
        m = _member(r, e)
        assert (m.bucket, m.rows) == ("S", 0)  # the precondition
        assert m.reasons == ("bucket_s_callee_group",)
    assert _unit_of(r, p1) is _unit_of(r, p2)
    assert _unit_of(r, p1).kind == ru.GROUP
    m3 = _member(r, p3)
    assert (m3.bucket, m3.rows, m3.reasons) == ("S", 0, ())
    assert _unit_of(r, p3).kind == ru.SECOND_TIER
    assert r.report["groups"]["members"] == 2
    assert r.report["reduce"]["owed"] == 3  # the two members and the group's own callee entry
    assert r.report["must_read"]["by_reason"]["bucket_s_callee_group"] == 2


def test_an_added_reason_keeps_the_reasons_order() -> None:
    """The group reason is placed in REASONS order among the member's reasons."""
    assert ru._with_reason(_m("pair:2", "p::d", 0, "S", ("top_k",)), "bucket_s_callee_group") == (
        _m("pair:2", "p::d", 0, "S", ("bucket_s_callee_group", "top_k"))
    )


# ── X-3: the predicate version ───────────────────────────────────────────────────────────────


def test_the_predicate_version_moved_and_with_it_every_unit_id() -> None:
    """T-X3a / T-J7 (v4: the units read the facts' order, spec Y). MUTATION (verified RED):
    PREDICATE_VERSION left at v3 -> RED."""
    assert ru.PREDICATE_VERSION == "v4"
    anchors = ["a", "b"]
    for earlier in ("v2", "v3"):
        assert ru.unit_id(ru.S_BATCH, anchors, earlier) != ru.unit_id(ru.S_BATCH, anchors)


def test_a_judgement_written_under_v2_is_kept_under_v3(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-X3b: a judgement written naming a v2 unit is read under the current version by its
    anchor: the member's
    review state is the same, under a new unit id.

    MUTATION (verified RED): the review state read by unit id (the judgement's unit) -> RED."""
    w, (one,) = _s_pairs(tmp_path, monkeypatch, [1])
    real = ru.unit_id
    with monkeypatch.context() as mp:
        mp.setattr(ru, "PREDICATE_VERSION", "v2")
        mp.setattr(ru, "unit_id", lambda kind, anchors, pv_="v2": real(kind, anchors, pv_))
        server = mcp_app.build_server(w.path)
        nu = _call(server, "start_diff_review", {"run_pair": PAIR, "k": 0})["next_unit"]
        old_id = nu["unit_id"]
        assert old_id == real(ru.S_BATCH, [nu["members"][0]["anchor_ref"]], "v2")
        wrote = _call(
            server,
            "annotate_diff",
            {
                "anchor_ref": nu["members"][0]["anchor_ref"],
                "verdict": "changed_real",
                "rationale": "r",
                "diff_id": DX,
                "unit_id": old_id,
            },
        )
        assert wrote.get("written", True) is not False, wrote
        before = _review(w, k=0)
        state_v2 = before.progress.states[_member(before, one).anchor_ref]
    ru.DIFF_CACHE.clear()
    after = _review(w, k=0)
    assert _unit_of(after, one).unit_id != old_id
    assert after.progress.states[_member(after, one).anchor_ref] == state_v2
    assert ru.disposed(state_v2)


# ── X-4 / X-5: the texts ─────────────────────────────────────────────────────────────────────


def _texts() -> dict[str, str]:
    tools = mcp_app.make_tools(Path("/nonexistent/atlas.db"))
    out = {
        "guide": mcp_app._AGENT_GUIDE,
        "instructions": mcp_app._AGENT_INSTRUCTIONS,
        "card": mcp_cards.TOOL_CARDS["start_diff_review"].summary,
    }
    for name in ("start_diff_review", "get_diff_patch_view"):
        out[name] = tools[name].__doc__ or ""
    return {k: " ".join(v.split()) for k, v in out.items()}


def test_the_instructions_point_to_the_units_the_server_hands_out() -> None:
    """T-X4a: no bucket name in the instructions; the must-read units, each entry with a
    lift_basis; within 3,800.

    MUTATION (verified RED): the old "bucket S entry," list put back -> RED."""
    t = _texts()["instructions"]
    assert "bucket S" not in t
    assert "read every must-read unit" in t
    assert re.search(r"entry with a `{0,2}lift_basis", t)
    assert len(mcp_app._AGENT_INSTRUCTIONS) <= 3_800


def test_the_read_first_texts_name_the_s_entries_the_predicate_keeps() -> None:
    """T-X4b, by place: the old wording is gone from each, the new list is in each; the unrelated
    ``A bucket S entry carries drift`` sentence stays.

    MUTATION (verified RED): the guide's old "every bucket S entry and" put back -> RED; a
    blanket replace of "bucket S entry" -> the drift sentence gone -> RED."""
    t = _texts()
    assert "every bucket S entry and" not in t["guide"]
    assert "every bucket S entry and" not in t["start_diff_review"]
    assert "every bucket S entry," not in t["get_diff_patch_view"]
    assert "bucket S and" not in t["card"]
    for name in ("guide", "card", "start_diff_review", "get_diff_patch_view"):
        assert "candidate row" in t[name], name
    for name in ("guide", "start_diff_review", "get_diff_patch_view"):
        assert "bucket S entry that carries a candidate row or is in a callee group" in t[name]
        assert "ask the person first" in t[name], name
    assert "callee group" in t["card"]
    for name, text in t.items():
        assert re.search(r"entr(y|ies) with a `{0,2}lift_basis", text), name
    assert "A bucket S entry carries" in (_SRC / "mcp_app.py").read_text(encoding="utf-8")
    card = mcp_cards.TOOL_CARDS["start_diff_review"]
    assert len(mcp_cards.render_description("start_diff_review", card)) <= 1_200


def test_sweep_is_said_to_need_the_person_first() -> None:
    """T-X5b (texts): the start_diff_review description's sweep=true sentence asks the person
    first. MUTATION (verified RED): the sentence left as it was -> RED."""
    t = _texts()["start_diff_review"]
    assert "``sweep=true`` (ask the person first) hands out the second tier" in t


def test_the_skill_asks_the_person_before_the_second_tier() -> None:
    """T-X5a. MUTATION (verified RED): the old "to read the second tier too, call" kept -> RED."""
    text = " ".join(diff_skill.skill_text().split())
    assert "to read the second tier too, call" not in text
    i = text.index("ask the person whether to read the second tier")
    j = text.index("only on their yes")
    assert i < j < text.index("sweep=true", j)


def test_the_text_shipped_before_is_an_earlier_version() -> None:
    """T-X6: the 4,658-byte text (spec V's) is LEGACY, its fixture holds it, and the 3,741-byte
    hash is listed once.

    MUTATION (verified RED): the skill changed without adding its old hash -> RED."""
    old = (_FIXTURES / "skills" / "legacy_diff_review_4658.md").read_bytes()
    assert len(old) == 4_658
    assert hashlib.sha256(old).hexdigest() in sk.LEGACY_SHA256
    src = (_SRC / "lib" / "setup" / "skills.py").read_text(encoding="utf-8")
    assert src.count("81cb1c8a3f38f56e1db267cd05eefd0e4dc01fa90ff0b51d624555ff3b2c7055") == 1


# ── spec Y J-2: the second tier's judgements due a re-check ─────────────────────────────────


_UNREAD = overlay.WriteContext(
    channel="mcp", session="w", read_basis={"basis": "none", "unread_before_verdict": True}
)
_READ = overlay.WriteContext(channel="mcp", session="w", read_basis={"basis": "fetched"})


def _due_world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[World, list[str]]:
    """Six S entries at k=0: the first two (a candidate row each) in the must-read S batch, the
    last four (none) in one second-tier unit. Judged: the first must-read one written unread
    (needs_recheck); in the second tier two written unread (needs_recheck), one read and judged
    changed_real (concluded), one judged and then given a verdict no longer in use
    (needs_relabel). Returns the world and the six anchors."""
    w, ids = _s_pairs(tmp_path, monkeypatch, [1, 1, 0, 0, 0, 0])
    r = _review(w, k=0)
    anchors = [_member(r, e).anchor_ref for e in ids]
    for a in (anchors[0], anchors[2], anchors[3]):
        w.judge(DX, a, "changed_real", ctx=_UNREAD)
    w.judge(DX, anchors[4], "changed_real", ctx=_READ)
    w.judge(DX, anchors[5], "changed_real", ctx=_READ)
    w.atlas.execute(
        "UPDATE overlay SET verdict = 'a_retired_word' WHERE anchor_ref = ?", (anchors[5],)
    )
    w.atlas.commit()
    ru.DIFF_CACHE.clear()
    return w, anchors


def test_the_stop_counts_the_second_tier_judgements_due_a_recheck(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ T-J6: ``second_tier.due_recheck`` counts the second-tier members due a re-check or a
    relabel (3), not the concluded one, nor the must-read member due a re-check (it is handed out
    again). The relabel one is what neither completion flag sees: it is in no audit's
    needs_recheck, and due_recheck counts it.

    MUTATION (verified RED): no due_recheck -> RED; NEEDS_RELABEL left out -> 2 -> RED; the
    must-read members counted too -> 4 -> RED; only the audits' needs_recheck counted -> the
    relabel one missed -> RED."""
    w, anchors = _due_world(tmp_path, monkeypatch)
    r = _review(w, k=0)
    states = r.progress.states
    assert [states[a] for a in anchors[2:]] == [
        ru.NEEDS_RECHECK,
        ru.NEEDS_RECHECK,
        ru.CONCLUDED,
        ru.NEEDS_RELABEL,
    ]  # the premise
    assert states[anchors[0]] == ru.NEEDS_RECHECK
    assert _unit_of(r, _member_id(r, anchors[0])).must_read
    assert not _unit_of(r, _member_id(r, anchors[5])).must_read
    offer = ru.coverage_offer(r, worker=None, workers=None, sweep=False)
    assert offer["second_tier"].get("due_recheck") == 3
    assert anchors[5] not in r.audits.needs_recheck


def test_due_recheck_is_the_scope_s_in_a_shard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-J6b: with three shards, the shards' due_recheck add up to the pair's and at least one is
    below it; due_recheck is not among the pair-wide keys.

    MUTATION (verified RED): due_recheck read off the whole pair (as basis_incomplete is) -> every
    shard reads the total -> RED."""
    w, _anchors = _due_world(tmp_path, monkeypatch)
    r = _review(w, k=0)
    whole = ru.coverage_offer(r, worker=None, workers=None, sweep=False)["second_tier"]
    shards = [
        ru.coverage_offer(r, worker=i, workers=3, sweep=False)["second_tier"]["due_recheck"]
        for i in range(3)
    ]
    assert sum(shards) == whole["due_recheck"] == 3
    assert min(shards) < whole["due_recheck"]
    assert "due_recheck" not in ru.PAIR_WIDE_OFFER_KEYS
    assert "second_tier" not in ru.PAIR_WIDE_OFFER_KEYS


def _member_id(r: ru.PairReview, anchor: str) -> str:
    return next(m.entry_id for u in r.units for m in u.members if m.anchor_ref == anchor) or ""
