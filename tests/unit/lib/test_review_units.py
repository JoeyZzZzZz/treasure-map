# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The review of a run pair cut into work units (lib/query/review_units) and its MCP face
(start_diff_review(run_pair=...)): the must-read predicate, the round-robin hand-out order, unit
ids and shards, disposal, the report, and the cache.

Zero real data: the World of test_diff_review (one run pair, diffs of libx and liby), plus
hand-built entries and pair facts where a signal is easier to state than to build."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
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
    _unlist_and_repair,
    a_row,
)
from treasure_map import mcp_app
from treasure_map.lib import overlay
from treasure_map.lib.query import patch_view as pv
from treasure_map.lib.query import read_basis as rb
from treasure_map.lib.query import review_units as ru


@pytest.fixture(autouse=True)
def _clear_unit_cache() -> None:
    ru.DIFF_CACHE.clear()


@pytest.fixture
def world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> World:
    return _build_world(tmp_path, monkeypatch)


def _build_world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> World:
    w = World(tmp_path, monkeypatch)
    # libx: an A entry (attention 0), an undetermined pair (R), a changed aligned pair with no
    # candidate (C, attention 2), a function in no pair (P). liby: an R entry and a P entry.
    w.pair(DX, "00001000", "00001000")
    w.rows[DX] = [a_row("00001000")]
    w.pair(DX, "00002000", "00002800", conf=0.5, sim=0.4)
    w.pair(DX, "00003000", "00003000", conf=0.97, sim=0.7)
    w.unpaired(DX, "b", "00004000", "unmatched_analysis_complete")
    w.pair(DY, "00005000", "00005000", conf=0.5, sim=0.6)
    w.unpaired(DY, "a", "00006000", "unmatched_analysis_complete")
    return w


def _review(w: World, k: int = ru.DEFAULT_K, **kw: Any) -> ru.PairReview:
    return ru.review_pair(
        w.atlas,
        "runA",
        "runB",
        k=k,
        pair_staleness={"source_stale": False},
        server_commit="c0",
        **kw,
    )


def _members(r: ru.PairReview) -> dict[str, ru.Member]:
    return {m.entry_id or m.anchor_ref: m for u in r.units for m in u.members}


# ── the order every reader shares ────────────────────────────────────────────────────────────


@pytest.mark.parametrize("diff_id", [DX, DY])
def test_the_listing_is_the_default_page_order_with_its_attention_and_lift(
    world: World, diff_id: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ significance_listing gives the entries in the order, attention and lift_basis of the
    default get_diff_patch_view page — one computation, so the two never part. (libx's C entry is
    read at attention 0 here, through the one significance both read, so the significance order
    and the candidate_tier order differ.)

    MUTATION (verified RED): order the listing by candidate_tier -> the C entry is not first ->
    RED."""
    real = pv.significance

    def floated(e: Any, *a: Any) -> tuple[int, str]:
        if e.entry_id == "pair:00003000:00003000":
            return (0, "test_float")
        return real(e, *a)

    monkeypatch.setattr(pv, "significance", floated)
    listing = pv.significance_listing(world.atlas, diff_id)
    assert listing is not None and not listing.withheld
    page = pv.get_diff_patch_view(world.atlas, diff_id, limit=200)
    got = [(o.entry.entry_id, o.attention, o.lift_basis) for o in listing.entries]
    want = [
        (e["entry_id"], e["significance"]["attention"], e.get("lift_basis"))
        for e in page["entries"]
    ]
    assert got == want
    if diff_id == DX:
        assert got[0][0] == "pair:00003000:00003000"


# ── the predicate ────────────────────────────────────────────────────────────────────────────


def test_each_reason_marks_its_entries_and_the_rest_are_second_tier(world: World) -> None:
    """★ P entries, attention-0 entries and the first k of each diff are must-read; the rest of
    the listed entries are second tier, in a batch per diff and bucket.

    MUTATION (verified RED): drop the P reason -> b:00004000 second tier -> RED; drop the
    attention-0 reason (k=0) -> the A entry second tier -> RED."""
    r = _review(world, k=0)
    m = _members(r)
    assert m["b:00004000"].reasons == ("p_entry",)
    assert m["a:00006000"].reasons == ("p_entry",)
    assert m["pair:00001000:00001000"].reasons == ("attention_0",)
    assert m["pair:00002000:00002800"].reasons == ()
    assert m["pair:00003000:00003000"].reasons == ()
    by_kind = {u.kind for u in r.units if not u.must_read}
    assert by_kind == {ru.SECOND_TIER}
    second = [u for u in r.units if u.kind == ru.SECOND_TIER]
    assert {(u.stream, u.members[0].bucket) for u in second} == {(DX, "R"), (DX, "C"), (DY, "R")}


def test_the_first_k_entries_of_each_diff_are_must_read(world: World) -> None:
    """★ k=2: the first two entries of each diff by its own default order are must-read
    (``top_k``), whatever their bucket; k changes the set, not the order.

    MUTATION (verified RED): never add top_k -> the R entries stay second tier -> RED."""
    r = _review(world, k=2)
    m = _members(r)
    assert "top_k" in m["pair:00002000:00002800"].reasons  # libx's second
    assert "top_k" in m["pair:00005000:00005000"].reasons  # liby's first
    assert "top_k" not in m["pair:00003000:00003000"].reasons  # libx's third
    assert r.report["must_read"]["by_reason"]["top_k"] == 4


def test_an_attention_1_b_sink_entry_past_k_is_must_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ A bucket B entry at attention 1 whose candidates line up with no visible delta
    (``sink_present_no_visible_delta``), or whose sink instruction found no match
    (``instruction_unmatched``), is must-read (``aligned_b_sink``) though it is past the first k:
    a fix to a sink call can read either way. Another B subclass at attention 1 stays second tier.

    MUTATION (verified RED, 1 failed): drop the ``aligned_b_sink`` clause from ``entry_reasons``
    -> both entries second tier -> RED."""
    w = World(tmp_path, monkeypatch)
    w.pair(DX, "00001000", "00001000")
    w.pair(DX, "00002000", "00002000", sim=0.5)
    w.pair(DX, "00003000", "00003000", sim=0.6)
    w.pair(DX, "00004000", "00004000", sim=0.7)
    persisted = _row(
        _ref("runA", "00002000"),
        _ref("runB", "00002000"),
        presence="persisted",
        call="present_same_callee",
    )
    w.rows[DX] = [
        a_row("00001000"),
        persisted,
        _row(_ref("runA", "00003000"), None, reason="instruction_unmatched"),
        a_row("00004000", elsewhere=True),
    ]
    listing = pv.significance_listing(w.atlas, DX)
    assert listing is not None
    seen = {o.entry.entry_id: (o.entry.shown_subclass, o.attention) for o in listing.entries}
    assert seen["pair:00002000:00002000"] == ("sink_present_no_visible_delta", 1)
    assert seen["pair:00003000:00003000"] == ("instruction_unmatched", 1)
    assert seen["pair:00004000:00004000"] == ("rematch_suspected", 1)
    r = _review(w, k=1)
    m = _members(r)
    assert m["pair:00002000:00002000"].reasons == ("aligned_b_sink",)
    assert m["pair:00003000:00003000"].reasons == ("aligned_b_sink",)
    assert m["pair:00004000:00004000"].reasons == ()
    assert r.report["must_read"]["by_reason"]["aligned_b_sink"] == 2
    assert r.report["predicate_version"] == ru.PREDICATE_VERSION
    unit_of = {mm.entry_id: u for u in r.units for mm in u.members}
    assert unit_of["pair:00004000:00004000"].kind == ru.SECOND_TIER
    assert unit_of["pair:00002000:00002000"].kind == ru.ENTRY


def _entry(**kw: Any) -> SimpleNamespace:
    base: dict[str, Any] = {
        "shown_bucket": "B",
        "pair": SimpleNamespace(aligned=True),
        "sink_candidate_counts": None,
        "sink_callsite_counts": None,
        "shown_subclass": "",
    }
    return SimpleNamespace(**{**base, **kw})


@pytest.mark.parametrize(
    ("entry", "want"),
    [
        # one side not in its scan's inventory, the other naming a sink candidate: an R entry
        (
            _entry(
                shown_bucket="R",
                pair=SimpleNamespace(aligned=False),
                sink_candidate_counts={
                    "delta": [],
                    "unknown": [
                        {"sink": "system", "side": "a", "reason": "function_not_in_scan_inventory"}
                    ],
                },
            ),
            ("side_not_in_inventory",),
        ),
        # the same on a B entry: not the transition clause
        (
            _entry(
                sink_candidate_counts={
                    "delta": [],
                    "unknown": [
                        {"sink": "system", "side": "a", "reason": "function_not_in_scan_inventory"}
                    ],
                }
            ),
            (),
        ),
        # unknown with no sink named: nothing on the other side
        (
            _entry(
                shown_bucket="R",
                pair=SimpleNamespace(aligned=False),
                sink_candidate_counts={
                    "delta": [],
                    "unknown": [
                        {"sink": None, "side": "a", "reason": "function_not_in_scan_inventory"}
                    ],
                },
            ),
            (),
        ),
        # fewer command calls on B
        (
            _entry(sink_callsite_counts={"delta": [{"sink": "system", "a": 2, "b": 1}]}),
            ("command_calls_fewer",),
        ),
        (
            _entry(sink_callsite_counts={"delta": [{"sink": "_eval", "a": 1, "b": 0}]}),
            ("command_calls_fewer",),
        ),
        # equal, more calls, a copy-family sink, a wide-char sink: not
        (_entry(sink_callsite_counts={"delta": [{"sink": "system", "a": 2, "b": 2}]}), ()),
        (_entry(sink_callsite_counts={"delta": [{"sink": "system", "a": 1, "b": 2}]}), ()),
        (_entry(sink_callsite_counts={"delta": [{"sink": "strcpy", "a": 2, "b": 1}]}), ()),
        (_entry(sink_callsite_counts={"delta": [{"sink": "wcscpy", "a": 2, "b": 1}]}), ()),
        # an unknown side is never fewer
        (
            _entry(
                sink_callsite_counts={
                    "delta": [],
                    "unknown": [{"sink": "system", "side": "b", "reason": "text_unavailable"}],
                }
            ),
            (),
        ),
        # an undetermined pairing: not an aligned pair
        (
            _entry(
                pair=SimpleNamespace(aligned=False),
                sink_callsite_counts={"delta": [{"sink": "system", "a": 2, "b": 1}]},
            ),
            (),
        ),
        # a B sink entry at attention 2 (the attention passed below): not aligned_b_sink
        (_entry(shown_subclass="sink_present_no_visible_delta"), ()),
    ],
    ids=[
        "transition_r",
        "transition_not_r",
        "transition_no_sink",
        "fewer_system",
        "fewer_eval",
        "equal",
        "more",
        "copy_sink",
        "wide_char",
        "unknown_side",
        "not_aligned",
        "b_sink_attention_2",
    ],
)
def test_the_two_count_clauses(entry: SimpleNamespace, want: tuple[str, ...]) -> None:
    """★ The transition clause (an R entry, one side outside its scan's inventory, a sink named)
    and the command-call clause (an aligned pair, fewer calls on B of the command class, _eval or
    execvpe; never a copy or wide-char sink, never an unknown side).

    MUTATION (verified RED): accept any bucket for the transition clause -> transition_not_r;
    count the wide-char family -> wide_char; drop the aligned check -> not_aligned; read b <= a ->
    equal (each -> RED in its case); accept attention 2 for the B sink clause -> b_sink_attention_2
    (verified RED, 1 failed)."""
    assert ru.entry_reasons(entry, 99, 2, None, 4) == want


# ── units, order, shards ────────────────────────────────────────────────────────────────────


def _facts(**kw: Any) -> ru.PairFacts:
    base: dict[str, Any] = {
        "run_a": "runA",
        "run_b": "runB",
        "diffs": [],
        "presence": None,
        "presence_members": [],
        "pair_files": None,
        "file_members": [],
        "files_unavailable": None,
        "failed_diffs": [],
        "not_diffed_binaries": {},
        "identical_not_diffed": {},
    }
    return ru.PairFacts(**{**base, **kw})


def _m(anchor: str, stream: str, pos: int, bucket: str = "R", reasons: tuple[str, ...] = ()) -> Any:
    kind = {"binary_presence": "binary_presence", "non_binary_file": "non_binary_file"}.get(
        bucket, "entry"
    )
    return ru.Member(
        anchor_ref=anchor,
        kind=kind,
        stream=stream,
        position=pos,
        entry_id=anchor if kind == "entry" else None,
        bucket=bucket,
        reasons=reasons,
    )


def _diff(diff_id: str, members: list[Any]) -> ru.DiffFacts:
    return ru.DiffFacts(diff_id, diff_id, True, False, [], members, {}, "runA", "runB")


def test_units_are_handed_out_round_robin_by_position() -> None:
    """★ Round r hands out the r-th entry of every diff (each in its own order), of the
    binary_presence binaries and of the changed files, before any (r+1)-th: a diff's head is never
    queued behind another diff's long tail.

    MUTATION (verified RED): order units by stream first (diff by diff) -> RED."""
    d1 = _diff("p::d1", [_m(f"d1e{i}", "p::d1", i, reasons=("p_entry",)) for i in range(3)])
    d2 = _diff("p::d2", [_m(f"d2e{i}", "p::d2", i, reasons=("p_entry",)) for i in range(2)])
    facts = _facts(
        diffs=[d2, d1],
        presence_members=[
            _m("bp0", ru.PRESENCE_STREAM, 0, "binary_presence", ("binary_presence",))
        ],
        file_members=[
            _m(f"f{i}", ru.FILE_STREAM, i, "non_binary_file", ("non_binary_file",))
            for i in range(2)
        ],
    )
    order = [u.members[0].anchor_ref for u in ru.cut_units(facts, k=0)]
    assert order == ["d1e0", "d2e0", "bp0", "f0", "d1e1", "d2e1", "f1", "d1e2"]


def test_s_entries_and_the_second_tier_are_batched_and_capped() -> None:
    """Bucket S entries are batched per diff (must-read), the second tier per diff and bucket; a
    batch holds at most BATCH_UNIT_MAX (16) members — about what one page's material shows, so a
    unit is read and judged from the page it is handed out on.

    MUTATION (verified RED): drop the cap -> one S batch of 250 -> RED. MUTATION (verified RED,
    1 failed): cut batches at BATCH_MAX (200) again -> RED."""
    s = [_m(f"s{i}", "p::d", i, "S", ("bucket_s",)) for i in range(250)]
    c = [_m(f"c{i}", "p::d", 250 + i, "C") for i in range(3)]
    units = ru.cut_units(_facts(diffs=[_diff("p::d", s + c)]), k=0)
    sizes = sorted((u.kind, len(u.members)) for u in units)
    assert ru.BATCH_UNIT_MAX == 16
    assert sizes == sorted([(ru.S_BATCH, 16)] * 15 + [(ru.S_BATCH, 10), (ru.SECOND_TIER, 3)])
    assert all(u.must_read for u in units if u.kind == ru.S_BATCH)


def test_a_unit_id_is_its_kind_members_and_predicate_and_shards_partition_the_units() -> None:
    """★ The id is a hash of the kind, the sorted member anchors and the predicate version (not of
    the order they came in); the shards of n partition the units, read from the id's first 8 hex
    digits — never Python's per-process hash().

    MUTATION (verified RED): leave the predicate version out of the id -> RED; read the shard from
    hash(uid) -> not a partition across processes (and the fixed expectations here) -> RED."""
    assert ru.unit_id("entry", ["b", "a"]) == ru.unit_id("entry", ["a", "b"])
    assert ru.unit_id("entry", ["a"]) != ru.unit_id("s_batch", ["a"])
    other = "v0" if ru.PREDICATE_VERSION != "v0" else "v1"
    assert ru.unit_id("entry", ["a"]) != ru.unit_id("entry", ["a"], predicate_version=other)
    ids = [ru.unit_id("entry", [str(i)]) for i in range(40)]
    shards = [{u for u in ids if ru.in_shard(u, w, 3)} for w in range(3)]
    assert set().union(*shards) == set(ids)
    assert sum(len(s) for s in shards) == len(ids)
    assert all(ru.in_shard(u, None, None) for u in ids)
    assert ru.in_shard("00000005ffffffff", 2, 3) and not ru.in_shard("00000005ffffffff", 0, 3)


# ── disposal, next unit, the report ─────────────────────────────────────────────────────────


def test_a_judged_member_is_disposed_and_the_next_unit_moves_on(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ The next unit is the first in the hand-out order with a member not disposed; a judgement
    (concluded or change_inconclusive) disposes it. must_read_complete needs the must-read units
    only — the second tier keeps ``complete`` false, not it. (Blind auditing is sealed by default;
    this test turns it on — see test_blind_audit_is_sealed_off_by_default for the gate itself.)

    MUTATION (verified RED): count change_inconclusive as not disposed -> RED; let the second tier
    hold must_read_complete -> RED; hand a session the audit of its own judgement -> RED; let an
    open audit leave must_read_complete true -> RED."""
    monkeypatch.setattr(ru, "BLIND_AUDIT_ENABLED", True)
    r = _review(world, k=0)
    first = r.next_unit()
    assert first is not None and first.members[0].entry_id == "pair:00001000:00001000"
    assert r.report["must_read_complete"] is False
    writer = overlay.WriteContext(channel="mcp", session="writer")
    world.judge(DX, _pair_anchor(DX, "00001000", "00001000"), "change_inconclusive", ctx=writer)
    world.judge(DX, _pair_anchor(DX, "00002000", "00002800"), "changed_real")  # second tier
    r = _review(world, k=0)
    # Its audit follows it at once — but not for the session that wrote it (it cannot read it
    # blind): that session moves on.
    audit = r.next_unit()
    assert audit is not None and audit.kind == ru.AUDIT
    nxt = r.next_unit(session="writer")
    assert nxt is not None and nxt.members[0].entry_id != first.members[0].entry_id
    must = [m for u in r.units if u.must_read and u.kind != ru.AUDIT for m in u.members]
    for m in must:
        if m.entry_id and m.entry_id.startswith(("a:", "b:")):
            world.judge(m.stream, m.anchor_ref, "changed_real")
    # The change_inconclusive opened an audit: a blind second reading that agrees closes it.
    assert _review(world, k=0).report["must_read_complete"] is False
    world.judge(
        DX,
        _pair_anchor(DX, "00001000", "00001000"),
        "change_inconclusive",
        shadow=True,
        ctx=overlay.WriteContext(channel="mcp", session="auditor"),
    )
    r = _review(world, k=0)
    assert r.report["must_read_complete"] is True
    assert r.report["complete"] is False  # second tier unjudged
    assert r.report["must_read"]["members_disposed"] == r.report["must_read"]["members"]


def test_a_member_whose_facts_moved_is_not_disposed(world: World) -> None:
    """A judgement whose facts moved reads needs_recheck: not disposed, so its unit comes back.

    MUTATION (verified RED): count needs_recheck as disposed -> RED."""
    anchor = _pair_anchor(DX, "00001000", "00001000")
    world.judge(DX, anchor, "changed_real")
    assert ru.disposed(_review(world, k=0).progress.states[anchor])
    world.rows[DX] = []  # a re-hunt: the A row is gone, the entry's facts moved
    states = _review(world, k=0).progress.states
    assert not ru.disposed(states.get(anchor))


def test_the_coverage_statement_states_the_numbers(world: World) -> None:
    r = _review(world, k=1)
    rep = r.report
    line = rep["coverage_statement"]
    assert line.startswith(
        f"must-read {rep['must_read']['members']} / disposed {rep['must_read']['members_disposed']}"
    )
    assert f"predicate {ru.PREDICATE_VERSION} (k=1)" in line and line.endswith("server c0")


def test_the_report_counts_judgements_whose_subject_is_no_longer_listed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ The report (and its markdown) counts a judgement whose subject still resolves but is no
    longer listed under ``judged_not_listed``, apart from the dangling one whose subject is gone.

    MUTATION (verified RED, 1 failed): ``unlisted_judgements`` returns nothing -> the report counts
    0 and the markdown has no section -> RED; ``read_progress`` does not collect them -> RED; let
    an anchor_unresolved one in -> the count reads 2 -> RED."""
    from treasure_map.lib.query import review_report as rr

    w = World(tmp_path, monkeypatch)
    unlisted, gone = _unlist_and_repair(w)
    r = _review(w, k=0)
    assert r.report["dangling_judgements"] == [gone]
    jnl = r.report["judged_not_listed"]
    assert (jnl["count"], jnl["by_verdict"], jnl["anchors"]) == (1, {"changed_real": 1}, [unlisted])
    assert jnl["changed_real"] == {"count": 1, "anchors": [unlisted]}
    assert unlisted not in r.progress.states and gone not in r.progress.states
    md = rr.markdown(r)
    assert "## Judgements whose subject is no longer listed" in md
    assert f"  - changed_real: `{unlisted}`" in md
    head, _, tail = md.partition("## Judgements whose subject is no longer listed")
    assert f"- `{gone}`" in head and gone not in tail.split("## Units")[0]


def test_the_markdown_counts_the_unlisted_judgements_it_does_not_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ The markdown's "… N more" under the judgements no longer listed is the count less the
    anchors its lines name: a changed_real anchor sorted past the first shown ones is named on its
    own line, so it is not counted among the more.

    MUTATION (verified RED, 1 failed): "more" = count - the first shown anchors (the changed_real
    line left out of the sum) -> "… 10 more" -> RED."""
    from treasure_map.lib.query import diff_review as dr
    from treasure_map.lib.query import review_report as rr

    w = World(tmp_path, monkeypatch)
    _unlist_and_repair(w)
    r = _review(w, k=0)

    def judged(anchor: str, verdict: str) -> dr.DiffAnnotation:
        return dr.DiffAnnotation(anchor, verdict, dr.CHANGED, {}, False, None)

    rows = [judged(f"a{i:02d}", "no_real_change") for i in range(29)] + [
        judged("z99", "changed_real")
    ]
    r.report["judged_not_listed"] = dr.judged_not_listed(rows)
    shown = dr.JUDGED_NOT_LISTED_SHOWN
    assert len(rows) > shown + 1 and "z99" not in r.report["judged_not_listed"]["anchors"]
    md = rr.markdown(r)
    section = md.partition("## Judgements whose subject is no longer listed")[2].split("## ")[0]
    named = [ln for ln in section.splitlines() if ln.startswith("  - ") and "`" in ln]
    assert len(named) == shown + 1 and "  - changed_real: `z99`" in named
    assert f"  - … {len(rows) - len(named)} more" in section, section


# ── the cache ────────────────────────────────────────────────────────────────────────────────


def test_the_structure_is_cached_by_the_facts_and_a_rehunt_reads_anew(world: World) -> None:
    """★ A second reading serves each diff from the cache; a re-hunt (the runs' stamps move) reads
    every diff anew. A judgement never invalidates it.

    MUTATION (verified RED): key the cache by diff_id alone -> the re-hunt is served the old
    units -> RED."""
    _review(world)
    misses = ru.DIFF_CACHE.misses
    world.judge(DX, _pair_anchor(DX, "00001000", "00001000"), "changed_real")
    _review(world)
    assert ru.DIFF_CACHE.misses == misses
    world.rows[DX] = []  # re-hunt: no candidate row, the pair is no longer an A entry
    r = _review(world)
    assert ru.DIFF_CACHE.misses == misses + 2
    assert _members(r)["pair:00001000:00001000"].bucket != "A"


# ── the MCP face ────────────────────────────────────────────────────────────────────────────


def _tool(w: World) -> Any:
    return mcp_app.make_tools(w.path)["start_diff_review"]


@pytest.mark.parametrize(
    ("kw", "word"),
    [
        ({}, "exactly one"),
        ({"diff_id": DX, "run_pair": PAIR}, "exactly one"),
        ({"diff_id": DX, "unit": "abc"}, "run_pair only"),
        ({"diff_id": DX, "k": 3}, "run_pair only"),
        ({"run_pair": PAIR, "worker": 0}, "together"),
        ({"run_pair": PAIR, "worker": 3, "workers": 3}, "worker must be"),
        ({"run_pair": PAIR, "k": -1}, "k must be"),
        ({"run_pair": PAIR, "limit": 5}, "limit"),
    ],
)
def test_the_two_forms_and_their_arguments_are_checked(
    world: World, kw: dict[str, Any], word: str
) -> None:
    """MUTATION (verified RED): drop the exactly-one check -> {} reaches the diff form -> RED."""
    out = _tool(world)(**kw)
    assert word in str(out.get("error") or ""), out


def test_the_pair_form_reports_and_hands_out_the_next_unit(world: World) -> None:
    """★ run_pair returns the bounded report (coverage_statement, must-read counts) and the next
    unit with its id and material; unit=<id> returns that unit alone; an unknown id says so. Every
    response stays within the byte budget and never lists every unit.

    MUTATION (verified RED): leave next_unit's material out -> RED."""
    tool = _tool(world)
    out = tool(run_pair=PAIR)
    assert "error" not in out, out
    rep = out["report"]
    assert rep["coverage_statement"].startswith("must-read ")
    assert rep["predicate_version"] == ru.PREDICATE_VERSION
    nxt = out["next_unit"]
    assert nxt["kind"] == ru.ENTRY and nxt["members"][0]["entry_id"] == "pair:00001000:00001000"
    assert nxt.get("material", {}).get("entry", {}).get("entry_id") == "pair:00001000:00001000"
    assert len(json.dumps(out)) <= mcp_app._RESPONSE_BYTE_BUDGET
    assert "units" not in out
    one = tool(run_pair=PAIR, unit=nxt["unit_id"])
    assert one["unit"]["unit_id"] == nxt["unit_id"] and one.get("material")
    assert "no unit" in tool(run_pair=PAIR, unit="0" * 16).get("error", "")
    shard = tool(run_pair=PAIR, worker=0, workers=2)
    assert {k: shard["shard"][k] for k in ("worker", "workers")} == {"worker": 0, "workers": 2}
    if shard["next_unit"] is not None:
        assert ru.in_shard(shard["next_unit"]["unit_id"], 0, 2)


def test_the_diff_form_is_unchanged(world: World) -> None:
    """The diff_id form answers as it did: no report, no unit."""
    out = _tool(world)(diff_id=DX)
    assert out["diff_id"] == DX and "headline" in out and "report" not in out


# ── the command line ─────────────────────────────────────────────────────────────────────────


def _cli(w: World, *args: str) -> Any:
    from click.testing import CliRunner

    from treasure_map.cli.review_cli import review

    return CliRunner().invoke(
        review, [*args, "--atlas", str(w.path)] if args[0] == "report" else list(args)
    )


def test_the_terminal_summary_leads_with_the_coverage_statement(world: World) -> None:
    """★ The first line printed is the report's coverage_statement, as the MCP report gives it.

    MUTATION (verified RED): print the header first -> RED."""
    res = _cli(world, "report", PAIR)
    assert res.exit_code == 0, res.output
    want = _review(world).report["coverage_statement"].replace("server c0", "")
    assert res.output.splitlines()[0].startswith(want)
    assert "next units" in res.output


def test_markdown_and_html_write_every_unit_and_html_escapes(
    world: World, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ --md / --html write every unit with its members; the HTML page carries no script and
    escapes what the firmware named.

    MUTATION (verified RED): drop html.escape on a member -> the injected tag survives -> RED."""
    md = tmp_path / "r.md"
    res = _cli(world, "report", PAIR, "--md", "-o", str(md))
    assert res.exit_code == 0, res.output
    text = md.read_text()
    units = _review(world).units
    assert all(u.unit_id in text for u in units)
    real = ru.cut_units

    def tagged(facts: ru.PairFacts, k: int = ru.DEFAULT_K) -> list[ru.Unit]:
        out = real(facts, k)
        m = out[0].members[0]
        bad = ru.Member(**{**m.__dict__, "entry_id": "<script>x</script>"})
        return [ru.Unit(**{**out[0].__dict__, "members": (bad,)}), *out[1:]]

    monkeypatch.setattr(ru, "cut_units", tagged)
    page = tmp_path / "r.html"
    res = _cli(world, "report", PAIR, "--html", "-o", str(page))
    assert res.exit_code == 0, res.output
    body = page.read_text()
    assert "<script" not in body and "&lt;script&gt;" in body
    assert "Content-Security-Policy" in body


@pytest.mark.parametrize(
    "args",
    [("--md",), ("-o", "x.md"), ("--md", "--html", "-o", "x")],
    ids=["md_without_o", "o_without_format", "both_formats"],
)
def test_the_output_options_are_checked(world: World, args: tuple[str, ...]) -> None:
    res = _cli(world, "report", PAIR, *args)
    assert res.exit_code != 0


def test_the_skill_prints_and_installs(tmp_path: Path) -> None:
    """The shipped skill prints as it is and installs as <dir>/tmap-diff-review/SKILL.md."""
    from click.testing import CliRunner

    from treasure_map.cli.review_cli import review

    out = CliRunner().invoke(review, ["skill"])
    assert out.exit_code == 0 and out.output.startswith("---\nname: tmap-diff-review")
    res = CliRunner().invoke(review, ["skill", "--install", str(tmp_path / "skills")])
    assert res.exit_code == 0
    assert (tmp_path / "skills" / "tmap-diff-review" / "SKILL.md").read_text() == out.output


# ── audits and disagreements ─────────────────────────────────────────────────────────────────

A1 = _pair_anchor(DX, "00001000", "00001000")


def _ctx(session: str) -> Any:
    return overlay.WriteContext(channel="mcp", session=session)


def _nrc(anchor: str) -> dict[str, Any]:
    return {"checked": [anchor], "why_unchanged": "same call"}


def test_a_no_real_change_is_audited_blind_and_an_agreeing_reading_closes_it(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ A no_real_change opens an audit unit (its member read without its state); a shadow from
    the session that wrote it is not blind and closes nothing; a blind shadow that agrees closes
    it, and must_read_complete is no longer held by it. (Blind auditing is sealed by default; this
    test turns it on.)

    MUTATION (verified RED): open no audit on no_real_change -> RED; count a non-blind shadow ->
    the writer's own shadow closes it -> RED."""
    monkeypatch.setattr(ru, "BLIND_AUDIT_ENABLED", True)
    world.judge(DX, A1, "no_real_change", verdict_basis=_nrc(A1), ctx=_ctx("writer"))
    r = _review(world, k=0)
    assert len(r.audits.open) == 1
    audit = r.audits.open[0]
    assert audit.sources == ("no_real_change",) and audit.write_session == "writer"
    assert r.report["audits"]["open"] == 1
    own = overlay.WriteContext(
        channel="mcp", session="writer", read_basis={"basis": "fetched", "non_blind": True}
    )
    world.judge(DX, A1, "no_real_change", verdict_basis=_nrc(A1), shadow=True, ctx=own)
    assert len(_review(world, k=0).audits.open) == 1
    world.judge(DX, A1, "no_real_change", verdict_basis=_nrc(A1), shadow=True, ctx=_ctx("auditor"))
    r = _review(world, k=0)
    assert r.audits.open == [] and r.audits.disagreements == []


def test_a_reading_otherwise_is_a_disagreement_that_a_person_settles(world: World) -> None:
    """★ A blind shadow with another verdict is a disagreement (must_read_complete false); a
    person's judgement settles it — and is not itself audited.

    MUTATION (verified RED): let a human write be audited -> an audit remains -> RED; ignore a
    disagreeing shadow -> RED."""
    world.judge(DX, A1, "no_real_change", verdict_basis=_nrc(A1), ctx=_ctx("writer"))
    world.judge(DX, A1, "changed_real", shadow=True, ctx=_ctx("auditor"))
    r = _review(world, k=0)
    assert len(r.audits.disagreements) == 1
    d = r.audits.disagreements[0]
    assert d["why"] == "audit_reads_otherwise" and d["shadow"] == ["changed_real"]
    assert r.report["must_read_complete"] is False
    world.judge(DX, A1, "changed_real", attributed_to="human", ctx=_ctx("person"))
    r = _review(world, k=0)
    assert r.audits.disagreements == [] and r.audits.open == []
    # The person's judgement is the current one; the agent's and the audit's stay in the history.
    row = world.atlas.execute(
        "SELECT verdict, attributed_to FROM overlay WHERE anchor_ref = ?", (A1,)
    ).fetchone()
    assert tuple(row) == ("changed_real", "human")
    events = [
        tuple(e)
        for e in world.atlas.execute(
            "SELECT event, attributed_to FROM overlay_history WHERE anchor_ref = ? ORDER BY id",
            (A1,),
        )
    ]
    assert events == [
        ("insert", "agent-via-mcp"),
        ("shadow", "agent-via-mcp"),
        ("update", "human"),
    ]


def test_an_overwrite_by_another_session_is_a_disagreement(world: World) -> None:
    """★ Two sessions write the same anchor with different verdicts: the later stands and the pair
    is a disagreement; the same session changing its mind is not.

    MUTATION (verified RED): flag only the audit kind -> RED."""
    world.judge(DX, A1, "changed_real", ctx=_ctx("s1"))
    world.judge(DX, A1, "changed_real", ctx=_ctx("s1"))
    assert _review(world, k=0).audits.disagreements == []
    world.judge(DX, A1, "change_inconclusive", ctx=_ctx("s2"))
    found = [x for x in _review(world, k=0).audits.disagreements if x["anchor_ref"] == A1]
    assert len(found) == 1
    assert found[0]["why"] == "overwritten_by_another_session"
    assert found[0]["before"] == "changed_real"


def test_judged_unread_is_needs_recheck(world: World) -> None:
    """★ A-2(2), always on while blind auditing is sealed: a subject whose LATEST write was made
    unread (read_basis ``unread_before_verdict``) reads NEEDS_RECHECK and holds must_read_complete,
    and opens no blind audit. (a) unread -> NEEDS_RECHECK; (b) a later read-first write clears it;
    (c) a later unread write keeps it; (d) re-reading the pair without a new write keeps it.

    MUTATION (verified RED): skip the needs_recheck append -> (a) RED; read the flag off any write
    rather than the latest -> (b) RED; drop needs_recheck from must_read_complete -> RED."""
    unread = overlay.WriteContext(
        channel="mcp", session="w", read_basis={"basis": "none", "unread_before_verdict": True}
    )
    read_first = overlay.WriteContext(channel="mcp", session="w", read_basis={"basis": "fetched"})
    # (a) judged unread -> needs recheck, no blind audit
    world.judge(DX, A1, "changed_real", ctx=unread)
    r = _review(world, k=0)
    assert A1 in r.audits.needs_recheck and r.audits.open == []
    assert r.progress.states[A1] == ru.NEEDS_RECHECK
    assert r.report["must_read_complete"] is False
    assert r.report["needs_recheck"]["count"] == 1 and A1 in r.report["needs_recheck"]["subjects"]
    # (d) reading the pair again (no new write) keeps it
    assert A1 in _review(world, k=0).audits.needs_recheck
    # (b) a later read-first write clears it (the latest write is no longer unread)
    world.judge(DX, A1, "changed_real", ctx=read_first)
    assert A1 not in _review(world, k=0).audits.needs_recheck
    # (c) a later unread write brings it back
    world.judge(DX, A1, "changed_real", ctx=unread)
    assert A1 in _review(world, k=0).audits.needs_recheck


def test_the_report_says_audits_off_while_blind_auditing_is_sealed(world: World) -> None:
    """★ A-3: with blind auditing sealed (the default), audits.open is null with status
    'audits off' (not 0, which would read as 'audited, none open'); the coverage statement says
    'open audits off' and carries the real count of subjects judged unread.

    MUTATION (verified RED): report len(audits.open) while sealed -> open is 0 not null -> RED;
    leave the statement saying 'open audits 0' -> RED."""
    r = _review(world, k=0)
    assert r.report["audits"]["open"] is None
    assert r.report["audits"]["status"] == "audits off"
    assert "open audits off" in r.report["coverage_statement"]
    assert "judged unread 0" in r.report["coverage_statement"]


def test_the_blind_read_whitelist_excludes_views_that_carry_a_verdict(world: World) -> None:
    """★ G, soundness: the blind-read whitelist is grounded in real responses. get_diff_patch_view's
    answer on a judged entry really carries review_state and the verdict, so it is NOT blind-read
    safe; the fact tool it is nearest (get_diff_meta) carries neither and is.

    MUTATION (verified RED): add get_diff_patch_view to BLIND_SAFE_TOOLS -> it is called blind-safe
    though its response leaks the verdict -> RED."""
    world.judge(DX, A1, "no_real_change", verdict_basis=_nrc(A1), ctx=_ctx("writer"))
    view = json.dumps(world.view(DX))
    assert "review_state" in view and "no_real_change" in view  # it really leaks a verdict
    assert rb._blind_safe({"tool": "get_diff_patch_view", "params": {}}, "au1") is False
    assert "get_diff_patch_view" not in rb.BLIND_SAFE_TOOLS
    assert rb._blind_safe({"tool": "get_diff_meta", "params": {}}, "au1") is True


def test_blind_audit_is_sealed_off_by_default(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ A-1 / acceptance 4: a no_real_change opens NO blind audit unit while the gate is sealed
    (the default); flipping BLIND_AUDIT_ENABLED on produces one. The sealing never silences the
    needs_recheck or disagreement signals.

    MUTATION (verified RED): produce audit units regardless of the gate -> the sealed assertion
    RED; honour the gate for the report count only -> the sealed `open is None` RED."""
    world.judge(DX, A1, "no_real_change", verdict_basis=_nrc(A1), ctx=_ctx("writer"))
    sealed = _review(world, k=0)
    assert sealed.audits.open == []
    assert sealed.report["audits"]["open"] is None
    monkeypatch.setattr(ru, "BLIND_AUDIT_ENABLED", True)
    opened = _review(world, k=0)
    assert len(opened.audits.open) == 1 and opened.audits.open[0].sources == ("no_real_change",)
    assert opened.report["audits"]["open"] == 1 and opened.report["audits"]["status"] == "on"


# ── the MCP writes: unit, shadow, read basis ─────────────────────────────────────────────────


def _server_call(server: Any, name: str, args: dict[str, Any]) -> dict[str, Any]:
    from tests.unit.test_tool_surface import _call

    return _call(server, name, args)


def test_a_write_naming_its_unit_records_what_was_read_and_hands_on_the_next(
    world: World,
) -> None:
    """★ Through the server: the unit handed out by start_diff_review, judged with its unit_id,
    records read_basis unit_delivered and answers with the next unit; a write on a must-read
    member that read nothing first records unread_before_verdict — which marks the subject
    NEEDS_RECHECK (always on, no blind audit). See test_judged_unread_is_needs_recheck for the
    clear/stay cases.

    MUTATION (verified RED): leave read_basis out of the write's context -> RED; never mark
    unread_before_verdict -> no needs_recheck -> RED."""
    server = mcp_app.build_server(world.path)
    head = _server_call(server, "start_diff_review", {"run_pair": PAIR, "k": 0})
    nxt = head["next_unit"]
    anchor = nxt["members"][0]["anchor_ref"]
    out = _server_call(
        server,
        "annotate_diff",
        {
            "anchor_ref": anchor,
            "verdict": "changed_real",
            "rationale": "r",
            "diff_id": DX,
            "unit_id": nxt["unit_id"],
        },
    )
    assert out.get("written") is True, out
    assert (out.get("read_basis") or {}).get("basis") == "unit_delivered"
    assert out["next_unit"]["unit_id"] != nxt["unit_id"]
    hist = world.atlas.execute(
        "SELECT unit_id, read_basis, channel FROM overlay_history WHERE anchor_ref = ?", (anchor,)
    ).fetchone()
    assert hist[0] == nxt["unit_id"] and hist[2] == "mcp"
    assert json.loads(hist[1] or "{}").get("basis") == "unit_delivered"
    p_entry = f"{PAIR}#function_presence#libx::b:00004000"
    blind = _server_call(
        server,
        "annotate_diff",
        {"anchor_ref": p_entry, "verdict": "changed_real", "rationale": "r", "diff_id": DX},
    )
    assert blind.get("written") is True, blind
    assert blind["read_basis"] == {"basis": "none", "unread_before_verdict": True}
    # Judged unread -> NEEDS_RECHECK (never a blind audit), with the gate off as it is here.
    r = _review(world, k=0)
    assert r.audits.open == [] and p_entry in r.audits.needs_recheck
    assert r.progress.states[p_entry] == ru.NEEDS_RECHECK
    assert r.report["needs_recheck"]["count"] >= 1 and r.report["must_read_complete"] is False


def _wide_world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, n: int) -> World:
    """A world with ``n`` aligned pairs in DX (addresses 0x1000, 0x2000, …): at k < n some are
    second tier, at k >= n all are must-read — so the session's k changes the must-read set."""
    w = World(tmp_path, monkeypatch)
    for i in range(1, n + 1):
        w.pair(DX, f"0000{i}000", f"0000{i}000")
    return w


def test_a_write_naming_a_non_default_k_unit_gets_its_next_unit_at_that_k(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ A-7 / acceptance 10: start_diff_review at k=8 hands k=8 units; a write naming one gets its
    next unit read at k=8 (``_after_unit_write`` uses the session's k, not the default). With eight
    must-read entries at k=8, after the first four writes the next unit is still an ``entry``; at
    the default k=4 it would be the second-tier batch instead.

    MUTATION (verified RED): _after_unit_write reads at DEFAULT_K -> after four writes the next unit
    is ``second_tier_batch`` -> RED."""
    w = _wide_world(tmp_path, monkeypatch, 8)
    server = mcp_app.build_server(w.path)
    head = _server_call(server, "start_diff_review", {"run_pair": PAIR, "k": 8})
    nxt = head["next_unit"]
    for _ in range(4):
        assert nxt is not None and nxt["kind"] == "entry"
        out = _server_call(
            server,
            "annotate_diff",
            {
                "anchor_ref": nxt["members"][0]["anchor_ref"],
                "verdict": "changed_real",
                "rationale": "r",
                "diff_id": DX,
                "unit_id": nxt["unit_id"],
            },
        )
        assert out.get("written") is True, out
        nxt = out["next_unit"]
    assert nxt is not None and nxt["kind"] == "entry"


def test_judged_unread_uses_the_sessions_k_for_the_must_read_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ A-7 / acceptance 11: a subject that is must-read only at the session's larger k, judged
    unread, records unread_before_verdict and reads NEEDS_RECHECK — the must-read set is read at
    the session's k (the largest start_diff_review asked for), not the default.

    MUTATION (verified RED): read the must-read set at DEFAULT_K -> the k=8-only subject is not
    must-read -> no unread_before_verdict -> not needs_recheck -> RED."""
    w = _wide_world(tmp_path, monkeypatch, 8)
    must_k = lambda k: {  # noqa: E731
        m.anchor_ref
        for u in _review(w, k=k).units
        if u.must_read and u.kind != ru.AUDIT
        for m in u.members
    }
    target = sorted(must_k(8) - must_k(4))[0]  # must-read at k=8, not at the default k=4
    server = mcp_app.build_server(w.path)
    _server_call(server, "start_diff_review", {"run_pair": PAIR, "k": 8})
    out = _server_call(
        server,
        "annotate_diff",
        {"anchor_ref": target, "verdict": "changed_real", "rationale": "r", "diff_id": DX},
    )
    assert out.get("written") is True, out
    assert out["read_basis"] == {"basis": "none", "unread_before_verdict": True}
    assert target in _review(w, k=8).audits.needs_recheck


def test_an_audit_unit_write_is_a_shadow_and_a_person_cannot_be_claimed_over_mcp(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ A write naming an audit unit is a shadow (the current judgement unchanged); a write
    naming a unit it is not a member of is refused; attributed_to='human' is refused over MCP,
    'human-via-agent' is recorded. (Blind auditing is sealed by default; this test turns it on so
    an audit unit exists to name.)

    MUTATION (verified RED): write an audit unit's judgement as a normal write -> the current
    verdict changes -> RED; accept 'human' over MCP -> RED."""
    monkeypatch.setattr(ru, "BLIND_AUDIT_ENABLED", True)
    tool = mcp_app.make_tools(world.path)["annotate_diff"]
    world.judge(DX, A1, "no_real_change", verdict_basis=_nrc(A1), ctx=_ctx("writer"))
    opened = _review(world, k=0).audits.open
    assert len(opened) == 1
    uid = opened[0].unit.unit_id
    out = tool(A1, "changed_real", "r", diff_id=DX, unit_id=uid)
    assert out.get("written") is True and "SHADOW" in out["note"]
    row = world.atlas.execute("SELECT verdict FROM overlay WHERE anchor_ref = ?", (A1,)).fetchone()
    assert row[0] == "no_real_change"
    other = _pair_anchor(DX, "00003000", "00003000")
    stray = tool(other, "changed_real", "r", diff_id=DX, unit_id=uid)
    assert stray.get("written") is False and "does not hold" in stray["error"]
    refused = tool(other, "changed_real", "r", diff_id=DX, attributed_to="human")
    assert refused.get("written") is False and "human-via-agent" in refused["error"]
    relayed = tool(other, "changed_real", "r", diff_id=DX, attributed_to="human-via-agent")
    assert relayed.get("written") is True
    who = world.atlas.execute(
        "SELECT attributed_to FROM overlay WHERE anchor_ref = ?", (other,)
    ).fetchone()
    assert who[0] == "human-via-agent"


# ── a person's channels: judge and the worksheet ─────────────────────────────────────────────


def test_judge_takes_a_person_only_on_an_interactive_terminal(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ --by human from a pipe is refused (nothing written); human-via-agent is written so; on a
    terminal with an agent marker set it drops to human-via-agent; on a plain terminal with the
    confirmation typed it is human.

    MUTATION (verified RED): skip the terminal check -> the pipe writes 'human' -> RED; ignore the
    marker -> RED."""
    from click.testing import CliRunner

    from treasure_map.cli import review_cli

    unit = next(u for u in _review(world, k=0).units if len(u.members) == 1)
    anchor = unit.members[0].anchor_ref
    base = [unit.unit_id, PAIR, "--verdict", "changed_real", "--rationale", "r", "--k", "0"]
    base += ["--atlas", str(world.path)]
    run = CliRunner().invoke
    for var in review_cli.AGENT_ENV_MARKERS:
        monkeypatch.delenv(var, raising=False)

    def who() -> str | None:
        row = world.atlas.execute(
            "SELECT attributed_to FROM overlay WHERE anchor_ref = ?", (anchor,)
        ).fetchone()
        return row[0] if row else None

    res = run(review_cli.review, ["judge", *base])
    assert res.exit_code != 0 and "interactive terminal" in res.output and who() is None
    assert run(review_cli.review, ["judge", *base, "--by", "human-via-agent"]).exit_code == 0
    assert who() == "human-via-agent"
    monkeypatch.setattr(review_cli, "_interactive", lambda: True)
    monkeypatch.setenv(review_cli.AGENT_ENV_MARKERS[0], "1")
    res = run(review_cli.review, ["judge", *base])
    assert res.exit_code == 0 and "human-via-agent" in res.output
    monkeypatch.delenv(review_cli.AGENT_ENV_MARKERS[0])
    res = run(review_cli.review, ["judge", *base], input="human\n")
    assert res.exit_code == 0, res.output
    assert who() == "human"


def test_the_worksheet_goes_out_and_comes_back_through_the_same_gates(
    world: World, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ --emit lists the open audits; --apply writes each filled item through annotate_diff (a
    person's attribution, the worksheet channel) and refuses one whose checked names nothing in the
    view — that one is not written.

    MUTATION (verified RED): write the items straight to the overlay (no annotate_diff) -> the bad
    item is taken -> RED."""
    from click.testing import CliRunner

    from treasure_map.cli import review_cli

    monkeypatch.setattr(ru, "BLIND_AUDIT_ENABLED", True)
    for var in review_cli.AGENT_ENV_MARKERS:
        monkeypatch.delenv(var, raising=False)
    a2 = _pair_anchor(DX, "00003000", "00003000")
    world.judge(DX, A1, "change_inconclusive", ctx=_ctx("w"))
    world.judge(DX, a2, "change_inconclusive", ctx=_ctx("w"))
    sheet = tmp_path / "sheet.json"
    run = CliRunner().invoke
    at = ["--atlas", str(world.path)]
    assert run(review_cli.review, ["audit", PAIR, "--emit", str(sheet), *at]).exit_code == 0
    data = json.loads(sheet.read_text())
    items = {it["anchor_ref"]: it for it in data["items"]}
    assert {A1, a2} <= set(items)
    items[A1].update(verdict="changed_real", rationale="the guard is gone")
    items[a2].update(
        verdict="no_real_change",
        why_unchanged="w",
        checked=["runA::runB#function_pair#libx::0dead::0beef"],
    )
    sheet.write_text(json.dumps(data))
    res = run(
        review_cli.review,
        ["audit", PAIR, "--apply", str(sheet), "--by", "human-via-agent", *at],
    )
    assert res.exit_code == 0, res.output
    assert "written 1, refused 1" in res.output
    rows = dict(
        world.atlas.execute(
            "SELECT anchor_ref, verdict FROM overlay WHERE anchor_ref IN (?, ?)", (A1, a2)
        ).fetchall()
    )
    assert rows == {A1: "changed_real", a2: "change_inconclusive"}
    ch = world.atlas.execute(
        "SELECT channel, attributed_to FROM overlay_history WHERE anchor_ref = ? "
        "ORDER BY id DESC LIMIT 1",
        (A1,),
    ).fetchone()
    assert tuple(ch) == ("worksheet", "human-via-agent")


def test_the_worksheet_hides_the_audit_verdict_but_keeps_a_disagreement(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ spec six.7: a worksheet AUDIT item must NOT carry the verdict under audit — seeing it
    anchors the auditor, whose write then becomes current and closes the audit. A DISAGREEMENT
    item, settled by seeing the clash, still carries current. (Blind auditing is sealed by default;
    this test turns it on for the AUDIT item.)

    MUTATION (verified RED): put `current` back on audit items -> it appears on the audit item."""
    from treasure_map.cli import review_cli

    monkeypatch.setattr(ru, "BLIND_AUDIT_ENABLED", True)
    a_dis = _pair_anchor(DX, "00003000", "00003000")
    world.judge(DX, A1, "no_real_change", verdict_basis=_nrc(A1), ctx=_ctx("writer"))
    world.judge(DX, a_dis, "no_real_change", verdict_basis=_nrc(a_dis), ctx=_ctx("writer"))
    # a blind shadow that DISAGREES turns a_dis into a disagreement (not an open audit)
    world.judge(DX, a_dis, "changed_real", shadow=True, ctx=_ctx("auditor"))
    reading = _review(world, k=0)
    sheet = review_cli.worksheet(world.atlas, reading, "runA::runB")
    items = {it["anchor_ref"]: it for it in sheet["items"]}
    assert items[A1]["why"][0] == "audit"
    assert "current" not in items[A1]  # blind: the verdict under audit is hidden
    assert items[a_dis]["why"][0] == "disagreement"
    assert items[a_dis]["current"] is not None  # a disagreement is settled by seeing both


def _auditor_view(w: World, verdict: str) -> dict[str, Any]:
    """Everything an auditor of A1 is shown once A1 is judged ``verdict``: the MCP unit material,
    the worksheet item, and every markdown / HTML report row that names A1."""
    from treasure_map.cli import review_cli
    from treasure_map.lib.query import review_report as rr

    basis = _nrc(A1) if verdict == "no_real_change" else None
    w.judge(DX, A1, verdict, verdict_basis=basis, ctx=_ctx("writer"))
    r = _review(w, k=0)
    [audit] = r.audits.open
    uid = audit.unit.unit_id
    mcp = mcp_app.make_tools(w.path)["start_diff_review"](run_pair=PAIR, k=0, unit=uid)
    assert mcp.get("unit", {}).get("kind") == ru.AUDIT, mcp
    sheet = review_cli.worksheet(w.atlas, r, PAIR)
    entry = audit.member.entry_id
    assert entry is not None
    md = [ln for ln in rr.markdown(r).splitlines() if entry in ln]
    page = [ln for ln in rr.html_page(r).splitlines() if entry in ln]
    assert len(md) >= 2 and len(page) >= 2  # its own unit's row and the audit unit's row
    return {
        "mcp": {k: v for k, v in mcp.items() if k != "server"},
        "sheet": [it for it in sheet["items"] if it["anchor_ref"] == A1],
        "markdown": md,
        "html": page,
    }


def test_an_auditor_is_shown_nothing_that_depends_on_the_verdict_under_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ spec six.7, read blind: the same subject audited once over a no_real_change and once over
    a change_inconclusive — what the auditor is shown (the MCP material of the audit unit, the
    worksheet item, each report row naming the subject) is IDENTICAL, so no field of it can carry
    the verdict, nor its why_unchanged, nor the review state that names it. The sources are still
    counted, in the report's audits.by_source only.

    MUTATION (verified RED): the audit member's reasons = its sources -> the MCP members and the
    report's reasons column differ -> RED; the worksheet's why carries the sources -> RED; the
    markdown (and, apart, the HTML) member table shows the real state -> RED."""
    monkeypatch.setattr(ru, "BLIND_AUDIT_ENABLED", True)
    a = _auditor_view(_build_world(tmp_path / "a", monkeypatch), "no_real_change")
    b = _auditor_view(_build_world(tmp_path / "b", monkeypatch), "change_inconclusive")
    for face in ("mcp", "sheet", "markdown", "html"):
        assert a[face] == b[face], face
    assert [m["reasons"] for m in a["mcp"]["members"]] == [[ru.AUDIT]]
    assert a["sheet"][0]["why"] == ["audit"]


def test_a_batch_naming_its_unit_records_it_and_hands_on_the_next(world: World) -> None:
    """annotate_diff_batch with unit_id writes every item with the unit in its history and answers
    with the next unit; an item outside the unit refuses the batch, nothing written.

    MUTATION (verified RED): drop the context in the batch's write -> no unit_id in the history ->
    RED."""
    tool = mcp_app.make_tools(world.path)["annotate_diff_batch"]
    unit = next(u for u in _review(world).units if u.kind == ru.ENTRY)
    item = {"anchor_ref": unit.members[0].anchor_ref, "verdict": "changed_real", "rationale": "r"}
    out = tool([item], diff_id=unit.stream, unit_id=unit.unit_id)
    assert out.get("written") is True, out
    assert "next_unit" in out
    got = world.atlas.execute(
        "SELECT unit_id FROM overlay_history WHERE anchor_ref = ?", (item["anchor_ref"],)
    ).fetchone()
    assert got is not None and got[0] == unit.unit_id
    other = next(
        m
        for u in _review(world).units
        for m in u.members
        if m.stream == unit.stream and m.anchor_ref != item["anchor_ref"]
    )
    stray = dict(item, anchor_ref=other.anchor_ref)
    bad = tool([stray], diff_id=unit.stream, unit_id=unit.unit_id)
    assert bad.get("written") is False


# ── the whole-pair loop as the server's own words teach it ───────────────────────────────────


def _diff_of(anchor: str) -> str:
    """The diff of a World entry anchor (``…#function_pair#libx::…`` is DX)."""
    return DY if "#liby::" in anchor else DX


def _judge_args(member: dict[str, Any], unit_id: str | None) -> dict[str, Any]:
    args: dict[str, Any] = {
        "anchor_ref": member["anchor_ref"],
        "verdict": "changed_real",
        "rationale": "r",
        "diff_id": _diff_of(member["anchor_ref"]),
    }
    if unit_id is not None:
        args["unit_id"] = unit_id
    return args


def _history_basis(w: World, anchor: str) -> dict[str, Any]:
    row = w.atlas.execute(
        "SELECT read_basis FROM overlay_history WHERE anchor_ref = ? ORDER BY id DESC LIMIT 1",
        (anchor,),
    ).fetchone()
    assert row is not None, anchor
    got: dict[str, Any] = json.loads(row[0] or "{}")
    return got


@pytest.mark.parametrize("name_unit", [True, False], ids=["with_unit_id", "without_unit_id"])
def test_the_pair_loop_as_the_workflow_says_it_completes(world: World, name_unit: bool) -> None:
    """★ C-1 / F-1 / F-2: follow PAIR_WORKFLOW literally — judge each member of next_unit, call
    start_diff_review(run_pair) again — and the review completes within 30 rounds: next_unit
    null, must_read_complete true, every write read as ``unit_delivered``. Naming the unit
    (``unit_id``, as the text now says) is the way taught; a write that leaves it out is still
    read against the unit this session was handed (``unit_inferred``), so it is not dead-ended.

    MUTATION (verified RED, 1 failed): drop the server's inference (``handed`` always empty) ->
    without_unit_id: every write basis none, disposed 0 -> RED. MUTATION (verified RED, 1
    failed): drop ``unit_id=...`` from PAIR_WORKFLOW -> the text test in test_diff_workflow RED
    (this loop passes it explicitly). R-9 — MUTATION (verified RED, 1 failed): record the inferred
    unit's id with the write -> without_unit_id RED; MUTATION (verified RED, 1 failed): hand the
    next unit on after an inferred write -> without_unit_id RED."""
    server = mcp_app.build_server(world.path)
    out = _server_call(server, "start_diff_review", {"run_pair": PAIR})
    bases: list[dict[str, Any]] = []
    judged: list[str] = []
    for _ in range(30):
        nu = out.get("next_unit")
        if not nu:
            break
        for m in nu["members"]:
            r = _server_call(
                server, "annotate_diff", _judge_args(m, nu["unit_id"] if name_unit else None)
            )
            assert r.get("written") is True, r
            bases.append(r["read_basis"])
            if not name_unit:
                # R-9: an inferred unit is for the read basis only — no next unit handed on
                assert "next_unit" not in r and "coverage_statement" not in r, sorted(r)
            judged.append(m["anchor_ref"])
        out = _server_call(server, "start_diff_review", {"run_pair": PAIR})
    assert bases, "the loop judged nothing"
    assert out.get("next_unit") is None, out.get("next_unit")
    assert out["report"]["must_read_complete"] is True, out["report"]["coverage_statement"]
    want = {"basis": "unit_delivered", "material_cut": False}
    if not name_unit:
        want["unit_inferred"] = True
    assert bases == [want] * len(bases)
    units = {
        a: world.atlas.execute(
            "SELECT unit_id FROM overlay_history WHERE anchor_ref = ? ORDER BY id DESC LIMIT 1",
            (a,),
        ).fetchone()[0]
        for a in judged
    }
    # R-9: and none is recorded as the unit the write judged
    assert all((u is None) is (not name_unit) for u in units.values()), units


def test_a_batch_naming_no_unit_is_read_against_the_unit_it_was_handed(world: World) -> None:
    """★ F-2 (batch): the same loop with annotate_diff_batch and no unit_id — every item's history
    records ``unit_delivered`` with ``unit_inferred``, and the review completes.

    MUTATION (verified RED, 1 failed): drop the inference -> basis none -> RED. An inferred unit
    is for the read basis only: the batch answer hands no next unit on and the history records no
    unit. MUTATION (verified RED, 1 failed): hand the next unit on after a batch naming no unit
    -> RED."""
    server = mcp_app.build_server(world.path)
    out = _server_call(server, "start_diff_review", {"run_pair": PAIR})
    judged: list[str] = []
    for _ in range(30):
        nu = out.get("next_unit")
        if not nu:
            break
        by_diff: dict[str, list[dict[str, Any]]] = {}
        for m in nu["members"]:
            item = {"anchor_ref": m["anchor_ref"], "verdict": "changed_real", "rationale": "r"}
            by_diff.setdefault(_diff_of(m["anchor_ref"]), []).append(item)
        for diff_id, items in by_diff.items():
            r = _server_call(
                server, "annotate_diff_batch", {"annotations": items, "diff_id": diff_id}
            )
            assert r.get("written") is True, r
            assert "next_unit" not in r and "coverage_statement" not in r, sorted(r)
            judged += [i["anchor_ref"] for i in items]
        out = _server_call(server, "start_diff_review", {"run_pair": PAIR})
    assert judged and out.get("next_unit") is None
    assert out["report"]["must_read_complete"] is True, out["report"]["coverage_statement"]
    for anchor in judged:
        got = _history_basis(world, anchor)
        assert got.get("basis") == "unit_delivered" and got.get("unit_inferred") is True, anchor
        unit = world.atlas.execute(
            "SELECT unit_id FROM overlay_history WHERE anchor_ref = ? ORDER BY id DESC LIMIT 1",
            (anchor,),
        ).fetchone()[0]
        assert unit is None, (anchor, unit)


def test_a_write_naming_no_unit_is_not_read_against_a_unit_that_does_not_hold_it(
    world: World,
) -> None:
    """★ F-2 honesty: the inference only stands in a handed unit that HOLDS the written subject. A
    must-read subject outside every unit handed out, judged before anything of it was read, stays
    ``none`` + unread_before_verdict and reads NEEDS_RECHECK.

    MUTATION (verified RED, 1 failed): infer from any handed unit, holding the anchor or not ->
    the write reads unit_delivered -> RED."""
    server = mcp_app.build_server(world.path)
    head = _server_call(server, "start_diff_review", {"run_pair": PAIR, "k": 0})
    handed = {m["anchor_ref"] for m in head["next_unit"]["members"]}
    p_entry = f"{PAIR}#function_presence#libx::b:00004000"
    assert p_entry not in handed  # the precondition: no handed unit holds it
    must = {m.anchor_ref for u in _review(world, k=0).units if u.must_read for m in u.members}
    assert p_entry in must
    out = _server_call(
        server,
        "annotate_diff",
        {"anchor_ref": p_entry, "verdict": "changed_real", "rationale": "r", "diff_id": DX},
    )
    assert out["read_basis"] == {"basis": "none", "unread_before_verdict": True}
    assert p_entry in _review(world, k=0).audits.needs_recheck


def test_an_inferred_unit_whose_material_was_cut_counts_only_once_something_is_fetched(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ F-2: a handed unit whose material was cut stands in for an unnamed write only once
    something of the unit was fetched after it (as for a named one): straight after the cut
    delivery the write reads ``none``; after get_diff_patch_view of the entry it counts.

    MUTATION (verified RED, 1 failed): read a cut delivery as whole (``always_cut`` False) -> the
    first write reads unit_delivered -> RED."""
    monkeypatch.setattr(mcp_app, "_RESPONSE_BYTE_BUDGET", 2_500)
    server = mcp_app.build_server(world.path)
    head = _server_call(server, "start_diff_review", {"run_pair": PAIR, "k": 0})
    nu = head["next_unit"]
    assert nu["material_cut"] is True  # the precondition: the delivery was cut
    member = nu["members"][0]
    first = _server_call(server, "annotate_diff", _judge_args(member, None))
    assert first["read_basis"].get("basis") == "none", first["read_basis"]
    entry_id = member["entry_id"]
    seen = _server_call(
        server,
        "get_diff_patch_view",
        {"diff_id": _diff_of(member["anchor_ref"]), "entry_id": entry_id},
    )
    assert "error" not in seen, seen
    again = _server_call(server, "annotate_diff", _judge_args(member, None))
    assert again["read_basis"].get("basis") in ("unit_delivered", "fetched"), again["read_basis"]


def test_the_next_unit_a_write_hands_back_carries_its_material(world: World) -> None:
    """★ C-2: the next unit in a write's answer comes WITH its material, within the response
    budget, so judging its members at once with its unit_id is a read (``unit_delivered``) — the
    log records a unit as handed out only with its material (see test_tool_call_log).

    MUTATION (verified RED, 1 failed): leave the material out of _after_unit_write's next unit ->
    no material, nothing recorded as handed out -> the next write reads none -> RED."""
    server = mcp_app.build_server(world.path)
    head = _server_call(server, "start_diff_review", {"run_pair": PAIR, "k": 0})
    u1 = head["next_unit"]
    out: dict[str, Any] = {}
    for m in u1["members"]:
        out = _server_call(server, "annotate_diff", _judge_args(m, u1["unit_id"]))
    u2 = out["next_unit"]
    assert isinstance(u2.get("material"), dict) and "error" not in u2["material"], u2
    assert len(json.dumps(out)) <= mcp_app._RESPONSE_BYTE_BUDGET
    o2 = _server_call(server, "annotate_diff", _judge_args(u2["members"][0], u2["unit_id"]))
    assert o2["read_basis"].get("basis") == "unit_delivered", o2["read_basis"]
    assert "unit_inferred" not in o2["read_basis"]


# ── needs_recheck: what sets it and what clears it ───────────────────────────────────────────

UNREAD = overlay.WriteContext(
    channel="mcp", session="w", read_basis={"basis": "none", "unread_before_verdict": True}
)
NONE_NOFLAG = overlay.WriteContext(
    channel="mcp", session="w2", read_basis={"basis": "none", "unread_before_verdict": False}
)


def _read(session: str) -> Any:
    return overlay.WriteContext(channel="mcp", session=session, read_basis={"basis": "fetched"})


def _must_at(w: World, k: int) -> set[str]:
    return {
        m.anchor_ref
        for u in _review(w, k=k).units
        if u.must_read and u.kind not in (ru.AUDIT, ru.REDUCE)
        for m in u.members
    }


def _read_unit(server: Any, unit_id: str, k: int | None) -> dict[str, Any]:
    """Read a unit's material (start_diff_review(run_pair, unit=...)) before judging it."""
    args: dict[str, Any] = {"run_pair": PAIR, "unit": unit_id}
    if k is not None:
        args["k"] = k
    got = _server_call(server, "start_diff_review", args)
    assert "error" not in got, got
    return got


def test_a_newer_unread_write_without_the_flag_does_not_clear_it(world: World) -> None:
    """★ C-3 (X1): only a newer write whose read basis is not ``none`` clears needs_recheck; a
    basis-none write carrying no flag (not must-read at its writer's k) changes nothing.

    NOTE: A1 is must-read at k=0, so the report-k layer flags it whatever the walk of its history
    says — reading the flag off the latest write only stays GREEN here. The walk itself is pinned
    by test_the_walk_of_the_history_holds_off_the_report_k."""
    world.judge(DX, A1, "changed_real", ctx=UNREAD)
    assert A1 in _review(world, k=0).audits.needs_recheck
    world.judge(DX, A1, "changed_real", ctx=NONE_NOFLAG)
    assert A1 in _review(world, k=0).audits.needs_recheck


def test_a_second_session_at_the_default_k_does_not_clear_a_k8_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ C-3 (X1m): a k=8 session judges a k=8-only subject unread; a second session that never
    asked k=8 rewrites it, still unread -> the k=8 report keeps it needs_recheck (its own k makes it
    must-read and the latest write read nothing).

    MUTATION (verified RED, 1 failed): go back to reading the flag off the latest write alone (no
    walk of the history, no report-k layer) -> RED."""
    w = _wide_world(tmp_path, monkeypatch, 8)
    target = sorted(_must_at(w, 8) - _must_at(w, 4))[0]
    s1 = mcp_app.build_server(w.path)
    _server_call(s1, "start_diff_review", {"run_pair": PAIR, "k": 8})
    o1 = _server_call(
        s1,
        "annotate_diff",
        {"anchor_ref": target, "verdict": "changed_real", "rationale": "r", "diff_id": DX},
    )
    assert o1["read_basis"] == {"basis": "none", "unread_before_verdict": True}
    s2 = mcp_app.build_server(w.path)
    _server_call(s2, "list_runs", {})  # a log for this session, so its basis is none, not unknown
    o2 = _server_call(
        s2,
        "annotate_diff",
        {"anchor_ref": target, "verdict": "changed_real", "rationale": "r2", "diff_id": DX},
    )
    assert o2.get("written") is True and o2["read_basis"]["basis"] == "none", o2
    assert target in _review(w, k=8).audits.needs_recheck


def test_a_subject_judged_unread_at_a_smaller_k_reads_needs_recheck_at_a_larger_k(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ C-3, the report-k layer: a k=4 session judges unread a subject must-read only at k=8 —
    no flag (not must-read at its writer's k) — yet the k=8 report reads it needs_recheck: its
    latest write read nothing and this report's k makes it must-read.

    MUTATION (verified RED, 1 failed): drop the report-k layer -> RED."""
    w = _wide_world(tmp_path, monkeypatch, 8)
    target = sorted(_must_at(w, 8) - _must_at(w, 4))[0]
    w.judge(DX, target, "changed_real", ctx=NONE_NOFLAG)
    assert target not in _review(w, k=4).audits.needs_recheck
    assert target in _review(w, k=8).audits.needs_recheck


def test_a_subject_judged_unread_at_a_larger_k_holds_the_smaller_k_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ A-m1 (fail-closed, owner's decision): a k=8 session judges unread a subject that is
    must-read only at k=8; the k=4 report — every one of ITS must-read subjects then read and
    judged — still says must_read_complete false: a subject judged unread holds it whether or not
    it is in this report's must-read set.

    MUTATION (verified RED, 1 failed): drop ``not audits.needs_recheck`` from must_read_complete
    -> RED."""
    w = _wide_world(tmp_path, monkeypatch, 8)
    target = sorted(_must_at(w, 8) - _must_at(w, 4))[0]
    w.judge(DX, target, "changed_real", ctx=UNREAD)
    for anchor in _must_at(w, 4):
        w.judge(DX, anchor, "changed_real", ctx=_read("s4"))
    r = _review(w, k=4)
    assert target not in _must_at(w, 4) and target in r.audits.needs_recheck
    assert r.report["must_read"]["members_disposed"] == r.report["must_read"]["members"]
    assert r.report["must_read_complete"] is False


def test_reading_after_an_unread_write_without_judging_again_keeps_it(world: World) -> None:
    """★ C-5 (X4): reading the subject after an unread write is not enough — no new write, still
    needs_recheck.

    MUTATION (verified RED, 1 failed): clear the flag on any fetch of the subject in the log
    after the write -> RED."""
    server = mcp_app.build_server(world.path)
    p_entry = f"{PAIR}#function_presence#libx::b:00004000"
    _server_call(server, "list_runs", {})  # the session's log exists (else basis is unknown)
    o = _server_call(
        server,
        "annotate_diff",
        {"anchor_ref": p_entry, "verdict": "changed_real", "rationale": "r", "diff_id": DX},
    )
    assert o["read_basis"] == {"basis": "none", "unread_before_verdict": True}
    v = _server_call(server, "get_diff_patch_view", {"diff_id": DX, "entry_id": "b:00004000"})
    assert "error" not in v, v
    assert p_entry in _review(world, k=0).audits.needs_recheck


def test_an_overwrite_by_another_session_alone_holds_must_read_complete(world: World) -> None:
    """★ C-5 (X5): every must-read member disposed, the only thing left a cross-session overwrite
    with another verdict -> must_read_complete false, with blind auditing sealed.

    MUTATION (verified RED, 1 failed): drop disagreements from must_read_complete -> RED."""
    for anchor in sorted(_must_at(world, 0)):
        world.judge(_diff_of(anchor), anchor, "changed_real", ctx=_read("s1"))
    assert _review(world, k=0).report["must_read_complete"] is True
    world.judge(DX, A1, "change_inconclusive", ctx=_read("s2"))
    r = _review(world, k=0)
    assert [d["why"] for d in r.audits.disagreements] == ["overwritten_by_another_session"]
    assert r.report["must_read_complete"] is False


def test_the_coverage_statement_counts_the_subjects_judged_unread(world: World) -> None:
    """★ C-5 (X6) / owner's decision: the coverage statement's ``judged unread N`` is the real
    count of subjects judged before they were read.

    MUTATION (verified RED, 1 failed): print len(audits.open) there instead -> RED."""
    world.judge(DX, A1, "changed_real", ctx=UNREAD)
    st = _review(world, k=0).report["coverage_statement"]
    assert "judged unread 1;" in st, st


def _walk_pair(server: Any, k: int | None, batch: bool = False) -> dict[str, Any]:
    """Read each unit then judge it with its unit_id, until no unit is left; the last answer."""
    args: dict[str, Any] = {"run_pair": PAIR}
    if k is not None:
        args["k"] = k
    nxt = _server_call(server, "start_diff_review", args)["next_unit"]
    out: dict[str, Any] = {}
    for _ in range(60):
        if nxt is None:
            return out
        _read_unit(server, nxt["unit_id"], k)
        if batch:
            items = [
                {"anchor_ref": m["anchor_ref"], "verdict": "changed_real", "rationale": "r"}
                for m in nxt["members"]
            ]
            out = _server_call(
                server,
                "annotate_diff_batch",
                {"annotations": items, "diff_id": DX, "unit_id": nxt["unit_id"]},
            )
        else:
            for m in nxt["members"]:
                out = _server_call(server, "annotate_diff", _judge_args(m, nxt["unit_id"]))
        assert out.get("written") is True, out
        nxt = out.get("next_unit")
    raise AssertionError("the pair did not finish in 60 units")


def test_a_k8_session_ends_with_coverage_at_k8(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ C-5 (X7): the last write of a k=8 session answers the coverage statement at (k=8).

    MUTATION (verified RED, 1 failed): read the coverage at DEFAULT_K in _after_unit_write ->
    RED."""
    w = _wide_world(tmp_path, monkeypatch, 8)
    out = _walk_pair(mcp_app.build_server(w.path), 8)
    assert out.get("next_unit", "absent") is None
    assert "(k=8)" in out["coverage_statement"], out["coverage_statement"]


def test_a_k0_session_ends_with_coverage_at_k0(world: World) -> None:
    """★ C-4 (X2): the session's k is the k its start_diff_review calls asked for, not always at
    least the default: a k=0 session's coverage comes back at (k=0).

    MUTATION (verified RED, 1 failed): keep DEFAULT_K always in the session's ks -> (k=4) -> RED."""
    out = _walk_pair(mcp_app.build_server(world.path), 0)
    assert "(k=0)" in out["coverage_statement"], out["coverage_statement"]


def test_a_refused_k_is_not_the_sessions_k(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """★ C-4 (X3): a start_diff_review the server refused (k=201, out of range) sets nothing: the
    session works at the default k, so after its four must-read entries the next unit is the
    second tier.

    MUTATION (verified RED, 1 failed): take k from refused calls too -> read at k=201 -> the next
    unit is still an entry -> RED."""
    w = _wide_world(tmp_path, monkeypatch, 8)
    server = mcp_app.build_server(w.path)
    bad = _server_call(server, "start_diff_review", {"run_pair": PAIR, "k": 201})
    assert "error" in bad, bad
    nxt = _server_call(server, "start_diff_review", {"run_pair": PAIR})["next_unit"]
    for _ in range(4):
        assert nxt is not None and nxt["kind"] == "entry"
        _read_unit(server, nxt["unit_id"], None)
        out = _server_call(server, "annotate_diff", _judge_args(nxt["members"][0], nxt["unit_id"]))
        assert out.get("written") is True, out
        nxt = out["next_unit"]
    assert nxt is not None and nxt["kind"] == "second_tier_batch"


def test_the_read_with_of_a_k8_next_unit_reads_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ C-4 (X10): the next unit a k=8 write hands back exists only at k=8; its ``read_with``
    names k=8, so calling it as written reads the unit.

    MUTATION (verified RED, 1 failed): leave k out of read_with -> 'no unit … k=4' -> RED."""
    import ast

    w = _wide_world(tmp_path, monkeypatch, 8)
    server = mcp_app.build_server(w.path)
    nxt = _server_call(server, "start_diff_review", {"run_pair": PAIR, "k": 8})["next_unit"]
    seen: list[str] = []
    for _ in range(4):
        _read_unit(server, nxt["unit_id"], 8)
        seen.append(nxt["unit_id"])
        out = _server_call(server, "annotate_diff", _judge_args(nxt["members"][0], nxt["unit_id"]))
        nxt = out["next_unit"]
    assert nxt["unit_id"] not in seen and nxt["unit_id"] not in {
        u.unit_id for u in _review(w).units
    }
    call = ast.parse(nxt["read_with"], mode="eval").body
    assert isinstance(call, ast.Call)
    kwargs = {kw.arg: ast.literal_eval(kw.value) for kw in call.keywords}
    got = _server_call(server, "start_diff_review", kwargs)
    assert "error" not in got, got


def test_a_batch_write_hands_back_the_next_unit_at_the_sessions_k(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ C-6 (X8): annotate_diff_batch reads the next unit at the session's k too (k=8: after four
    entries, still an entry, none repeated).

    MUTATION (verified RED, 1 failed): pass DEFAULT_K to _after_unit_write from the batch ->
    RED."""
    w = _wide_world(tmp_path, monkeypatch, 8)
    server = mcp_app.build_server(w.path)
    nxt = _server_call(server, "start_diff_review", {"run_pair": PAIR, "k": 8})["next_unit"]
    seen: list[str] = []
    for _ in range(4):
        assert nxt is not None and nxt["kind"] == "entry"
        _read_unit(server, nxt["unit_id"], 8)
        seen.append(nxt["unit_id"])
        item = {
            "anchor_ref": nxt["members"][0]["anchor_ref"],
            "verdict": "changed_real",
            "rationale": "r",
        }
        out = _server_call(
            server,
            "annotate_diff_batch",
            {"annotations": [item], "diff_id": DX, "unit_id": nxt["unit_id"]},
        )
        assert out.get("written") is True, out
        nxt = out["next_unit"]
    assert len(set(seen)) == 4
    assert nxt is not None and nxt["kind"] == "entry"


def test_the_probe_fails_when_only_the_blind_launch_misses_tmap(tmp_path: Path) -> None:
    """★ C-6 (X9): a preset with blind_argv is probed twice; when the blind launch does not reach
    tmap (its argv swallowed the prompt), the probe fails — the plain launch reaching it is not
    enough.

    MUTATION (verified RED, 1 failed): ignore the blind launch's result -> ok -> RED."""
    from treasure_map.lib import review_driver as rd
    from treasure_map.lib import tool_call_log as tcl

    atlas = tmp_path / "atlas.db"
    preset = rd.Preset("test", ("agent", "{unit_id}", "{prompt}"), blind_argv=("--deny", "list"))

    def agent(argv: list[str], *, cwd: Path, timeout: float) -> rd.Launch:
        if "--deny" not in argv:
            tcl.ToolCallLog(tcl.log_path_for(atlas)).record("list_runs", {}, {"runs": []})
        return rd.Launch(0, 0.0, False)

    got = rd.probe(preset, atlas_path=atlas, workdir=tmp_path, timeout=5, runner=agent)
    assert got.ok is False and got.tmap_reached is False


# ── write answers: where to go next, and judged-unread said on the answer ────────────────────


def test_a_write_naming_no_unit_points_at_the_whole_pair(world: World) -> None:
    """★ F-6: annotate_diff / annotate_diff_batch without unit_id answer with the whole pair's
    calls, filled in (not list_overlays); a write made before anything was read says so on the
    answer (``needs_recheck``) — per result in a batch, the note only counting them.

    MUTATION (verified RED, 1 failed): keep the list_overlays note -> RED; MUTATION (verified
    RED, 1 failed): leave needs_recheck off the single answer -> RED; MUTATION (verified RED, 1
    failed): leave it off the batch results -> RED."""
    server = mcp_app.build_server(world.path)
    _server_call(server, "list_runs", {})
    p_entry = f"{PAIR}#function_presence#libx::b:00004000"
    one = _server_call(
        server,
        "annotate_diff",
        {"anchor_ref": p_entry, "verdict": "changed_real", "rationale": "r", "diff_id": DX},
    )
    assert one.get("written") is True, one
    for out in (one,):
        assert "start_diff_review(run_pair='runA::runB')" in out["note"]
        assert "get_diff_handoff(run_pair='runA::runB')" in out["note"]
        assert "list_overlays" not in out["note"]
    assert "needs_recheck" in one.get("needs_recheck", ""), one
    items = [
        {"anchor_ref": A1, "verdict": "changed_real", "rationale": "r"},
        {"anchor_ref": p_entry, "verdict": "changed_real", "rationale": "r"},
    ]
    many = _server_call(server, "annotate_diff_batch", {"annotations": items, "diff_id": DX})
    assert many.get("written") is True, many
    assert "start_diff_review(run_pair='runA::runB')" in many["note"]
    assert "list_overlays" not in many["note"]
    flagged = {r["anchor_ref"] for r in many["results"] if "needs_recheck" in r}
    assert flagged == {A1, p_entry}
    assert "2 of them written before their subject was read" in many["note"]


def test_a_write_naming_its_unit_keeps_its_answer_and_needs_no_pair_pointer(world: World) -> None:
    """F-6: with unit_id the answer already carries the next unit: no whole-pair pointer."""
    server = mcp_app.build_server(world.path)
    nu = _server_call(server, "start_diff_review", {"run_pair": PAIR, "k": 0})["next_unit"]
    out = _server_call(server, "annotate_diff", _judge_args(nu["members"][0], nu["unit_id"]))
    assert out.get("written") is True and "whole pair:" not in out["note"]
    assert "needs_recheck" not in out


def test_list_diffs_leads_with_one_review_call_per_run_pair(world: World) -> None:
    """★ F-5: list_diffs' first key is ``review_pairs``: one row per run pair of the answer —
    a pair with a single diff too — with its diff count and its start_diff_review call.

    MUTATION (verified RED, 1 failed): put review_pairs after the rest -> RED; MUTATION (verified
    RED, 1 failed): list only pairs with more than one diff -> RED."""
    world.atlas.execute(
        "INSERT INTO diff_meta (diff_id, run_a_id, run_b_id, binary_a, binary_b, sha256_a, "
        "sha256_b, diff_ok, version_skew) VALUES ('runA::runC::libz', 'runA', 'runC', 'libz', "
        "'libz', '0a1b', '0a1c', 1, 0)"
    )
    world.atlas.commit()
    out = mcp_app.make_tools(world.path)["list_diffs"]()
    assert next(iter(out)) == "review_pairs"
    assert out["review_pairs"] == [
        {"run_pair": "runA::runB", "diffs": 2, "call": "start_diff_review(run_pair='runA::runB')"},
        {"run_pair": "runA::runC", "diffs": 1, "call": "start_diff_review(run_pair='runA::runC')"},
    ]
    pairs = {f"{d['run_a_id']}::{d['run_b_id']}" for d in out["diffs"]}
    assert len(out["review_pairs"]) == len(pairs)


# ── the blind read (gated): what a shadow judgement counts as having read ────────────────────


def _audit_world(world: World, monkeypatch: pytest.MonkeyPatch) -> str:
    """Blind auditing on, A1 judged no_real_change by another session: its audit unit's id."""
    monkeypatch.setattr(ru, "BLIND_AUDIT_ENABLED", True)
    world.judge(DX, A1, "no_real_change", verdict_basis=_nrc(A1), ctx=_ctx("writer"))
    opened = _review(world, k=0).audits.open
    assert len(opened) == 1
    return opened[0].unit.unit_id


def _shadow(server: Any, uid: str) -> dict[str, Any]:
    out = _server_call(
        server,
        "annotate_diff",
        {
            "anchor_ref": A1,
            "verdict": "no_real_change",
            "checked": [A1],
            "why_unchanged": "same",
            "diff_id": DX,
            "unit_id": uid,
        },
    )
    assert out.get("written") is True and "SHADOW" in out["note"], out
    return out


def test_a_shadow_after_reading_only_its_audit_unit_is_blind_and_closes_it(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ C-8 (E0): a session that read only the audit unit writes a blind shadow; the audit
    closes. Through the real server and its real log."""
    uid = _audit_world(world, monkeypatch)
    server = mcp_app.build_server(world.path)
    _read_unit(server, uid, 0)
    out = _shadow(server, uid)
    assert out["read_basis"].get("non_blind") is False
    assert _review(world, k=0).audits.open == []


def test_a_shadow_after_reading_another_unit_is_not_blind(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ C-8 (E1): reading the ordinary unit that holds the audited subject (its material carries
    review_state, the verdict under audit) before the audit unit makes the shadow NOT blind; the
    audit stays open.

    MUTATION (verified RED, 1 failed): treat start_diff_review as safe for any unit
    (``params.get("unit") is not None``) -> blind -> RED."""
    uid = _audit_world(world, monkeypatch)
    plain = next(
        u.unit_id
        for u in _review(world, k=0).units
        if u.kind == ru.ENTRY and any(m.anchor_ref == A1 for m in u.members)
    )
    server = mcp_app.build_server(world.path)
    _read_unit(server, plain, 0)
    _read_unit(server, uid, 0)
    out = _shadow(server, uid)
    assert out["read_basis"].get("non_blind") is True
    assert len(_review(world, k=0).audits.open) == 1


@pytest.mark.parametrize("overlay_arg", [None, True], ids=["overlay_off", "overlay_on"])
def test_list_candidates_before_a_shadow_makes_it_not_blind(
    world: World, monkeypatch: pytest.MonkeyPatch, overlay_arg: bool | None
) -> None:
    """★ C-7: list_candidates carries judgements even with overlay off (coverage,
    in_exploit_ledger, verdict_shape), so calling it before a shadow — either way — makes the
    shadow not blind; the call's ``overlay`` is in the log.

    MUTATION (verified RED, 1 failed): put back the overlay-off exemption -> overlay_off blind ->
    RED; MUTATION (verified RED, 1 failed): drop "overlay" from KEY_PARAMS with the exemption back
    -> overlay_on blind -> RED."""
    from treasure_map.lib import tool_call_log as tcl

    uid = _audit_world(world, monkeypatch)
    server = mcp_app.build_server(world.path)
    args: dict[str, Any] = {"run_id": "runB"}
    if overlay_arg is not None:
        args["overlay"] = overlay_arg
    _server_call(server, "list_candidates", args)
    _read_unit(server, uid, 0)
    out = _shadow(server, uid)
    assert out["read_basis"].get("non_blind") is True
    assert len(_review(world, k=0).audits.open) == 1
    lines = tcl.read_lines(tcl.log_path_for(world.path)) or []
    logged = [ln["params"] for ln in lines if ln.get("tool") == "list_candidates"]
    assert logged and logged[0].get("overlay") is bool(overlay_arg)


# ── what a cut material reads, and the answer's byte budget ─────────────────────────────────


def _hex_world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, n: int) -> World:
    """``n`` aligned pairs in DX at addresses 1, 2, …, n (eight hex digits each): at k=0 or k=1
    the rest of them is ONE second-tier batch, whose material is cut once n is large."""
    w = World(tmp_path, monkeypatch)
    for i in range(1, n + 1):
        w.pair(DX, f"{i:08x}", f"{i:08x}")
    return w


def test_a_cut_batch_reads_only_the_members_its_material_showed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ FC01: a second-tier batch whose page showed some of its members (a small page budget,
    so a 16-member batch does not fit). A member it showed reads ``unit_delivered`` at once, named
    or not; one that NO delivery listed reads ``none`` even after another member's entry was
    fetched — and ``unit_delivered`` (``material_cut``) once its own entry was. The hand-out names
    exactly the members its page shows. (A named write's answer hands the unit out again, possibly
    listing other members: what counts is what some delivery listed.)

    MUTATION (verified RED, 1 failed): the former rule — after a cut delivery a fetch of ANY member
    counts for the whole unit (``infer`` over every member of the unit) -> an unlisted member reads
    unit_delivered -> RED."""
    w = _hex_world(tmp_path, monkeypatch, 60)
    monkeypatch.setattr(mcp_app, "_RESPONSE_BYTE_BUDGET", 12_000)
    server = mcp_app.build_server(w.path)
    nu = _server_call(server, "start_diff_review", {"run_pair": PAIR, "k": 0})["next_unit"]
    listed = {e["entry_id"] for e in nu["material"]["entries"]}
    unit = _review(w, k=0).unit(nu["unit_id"])
    assert unit is not None
    members = [{"anchor_ref": m.anchor_ref, "entry_id": m.entry_id} for m in unit.members]
    # the preconditions: one cut batch that lists some members and not others
    assert nu["kind"] == "second_tier_batch" and nu["material_cut"] is True
    assert {m["entry_id"] for m in nu["members"]} == listed
    assert 3 <= len(listed) <= len(members) - 4, (len(listed), len(members))

    def write(m: dict[str, Any], named: bool) -> dict[str, Any]:
        got = _server_call(
            server, "annotate_diff", _judge_args(m, nu["unit_id"] if named else None)
        )
        assert got.get("written") is True, got
        again = got.get("next_unit") or {}
        if again.get("unit_id") == nu["unit_id"]:  # handed out again: what it listed counts too
            listed.update(e["entry_id"] for e in again["material"].get("entries") or [])
        return got

    def unlisted() -> dict[str, Any]:
        return next(m for m in members if m["entry_id"] not in listed and m not in used)

    shown = [m for m in members if m["entry_id"] in listed]
    used: list[dict[str, Any]] = []
    assert write(shown[1], False)["read_basis"] == {
        "basis": "unit_delivered",
        "material_cut": False,
        "unit_inferred": True,
    }
    seen = _server_call(
        server, "get_diff_patch_view", {"diff_id": DX, "entry_id": shown[2]["entry_id"]}
    )
    assert "error" not in seen, seen
    not_read = {"basis": "none", "unread_before_verdict": False}  # second tier: not must-read
    used.append(unlisted())
    assert write(used[-1], False)["read_basis"] == not_read
    used.append(unlisted())
    assert write(used[-1], True)["read_basis"] == not_read
    used.append(unlisted())
    own = _server_call(
        server, "get_diff_patch_view", {"diff_id": DX, "entry_id": used[-1]["entry_id"]}
    )
    assert "error" not in own, own
    assert write(used[-1], True)["read_basis"] == {"basis": "unit_delivered", "material_cut": True}
    assert write(shown[0], True)["read_basis"] == {"basis": "unit_delivered", "material_cut": False}


# Page budgets at which a single fit of the material (measured without its wrapping, or without
# the member list the page then hands out) sends an answer over the budget.
_OVER_AT = tuple(range(9_000, 24_001, 1_500))


@pytest.mark.parametrize("page", _OVER_AT)
def test_every_answer_carrying_a_units_material_keeps_to_the_byte_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, page: int
) -> None:
    """★ FC02: the material's own budget counts its entries but not its wrapping, so the answer
    is measured as it is sent and the material cut again by what it is over. At each of these
    page budgets a single fit sends some kind of answer over the budget; every answer keeps to it
    now, and each hands out exactly the members its page's material lists.

    MUTATION (verified RED, 11 failed): drop the measure-and-cut-again pass (one fit to the
    entries' budget, as before) -> RED at every budget. MUTATION (verified RED, 9 failed): the
    unit= read not measured as sent (its ``sent_size`` always 0) -> RED."""
    w = _hex_world(tmp_path, monkeypatch, 60)
    monkeypatch.setattr(mcp_app, "_RESPONSE_BYTE_BUDGET", page)
    server = mcp_app.build_server(w.path)
    budget = mcp_app._RESPONSE_BYTE_BUDGET
    nu = _server_call(server, "start_diff_review", {"run_pair": PAIR, "k": 1})["next_unit"]
    args = {**_judge_args(nu["members"][0], nu["unit_id"])}
    sizes: dict[str, int] = {}
    for kind in ("write", "overwrite"):
        out = _server_call(server, "annotate_diff", args)
        assert out.get("written") is True, out
        _assert_page_members(out["next_unit"])
        sizes[kind] = len(json.dumps(out))
    item = {k: args[k] for k in ("anchor_ref", "verdict", "rationale")}
    batch = _server_call(
        server,
        "annotate_diff_batch",
        {"annotations": [item], "diff_id": DX, "unit_id": nu["unit_id"]},
    )
    assert batch.get("written") is True, batch
    _assert_page_members(batch["next_unit"])
    sizes["batch"] = len(json.dumps(batch))
    alone = _server_call(
        server,
        "start_diff_review",
        {"run_pair": PAIR, "unit": batch["next_unit"]["unit_id"], "k": 1},
    )
    assert "material" in alone, alone
    _assert_page_members(alone)
    sizes["unit"] = len(json.dumps(alone))
    sizes["start"] = len(
        json.dumps(_server_call(server, "start_diff_review", {"run_pair": PAIR, "k": 1}))
    )
    assert all(size <= budget for size in sizes.values()), sizes


def _assert_page_members(holder: dict[str, Any]) -> None:
    """A batch / group / reduce hand-out lists exactly the members its material shows (at least
    one); a one-subject unit lists its one member."""
    mat = holder["material"]
    if "entries" in mat:
        page = [e["entry_id"] for e in mat["entries"]]
        got = [m["entry_id"] for m in holder["members"]]
    elif "owed" in mat:
        page = [o["anchor_ref"] for o in mat["owed"]]
        got = [m["anchor_ref"] for m in holder["members"]]
    else:
        assert len(holder["members"]) == 1, holder["members"]
        return
    assert got and got == page, (got, page)
    assert holder["members_total"] >= len(got)


def test_the_walk_of_the_history_holds_off_the_report_k(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ FC04 (X1, the walk itself): the subject is must-read at k=8 only, so the k=4 report's own
    layer cannot flag it — only the walk of its history can. A k=8 session judged it unread
    (flagged); a k=4 session rewrote it, still unread, unflagged: the k=4 report keeps it
    needs_recheck.

    MUTATION (verified RED, 1 failed): read the flag off the latest write only -> RED. MUTATION
    (verified RED, 1 failed): let any unflagged write clear it (basis none included) -> RED."""
    w = _wide_world(tmp_path, monkeypatch, 8)
    target = sorted(_must_at(w, 8) - _must_at(w, 4))[0]
    w.judge(DX, target, "changed_real", ctx=UNREAD)
    w.judge(DX, target, "changed_real", ctx=NONE_NOFLAG)
    assert target not in _must_at(w, 4)  # the precondition: the report-k layer is out of play
    assert target in _review(w, k=4).audits.needs_recheck


def test_a_one_diff_start_call_is_not_a_pair_call_at_the_default_k(world: World) -> None:
    """★ R-7: the session's k is read off its whole-pair start_diff_review calls only; a k=0
    session that also opened one diff (start_diff_review(diff_id), which has no k) keeps k=0.

    MUTATION (verified RED, 1 failed): count every start_diff_review line (the diff form as the
    default k) -> the next unit's read_with loses its ``k=0`` -> RED."""
    server = mcp_app.build_server(world.path)
    nu = _server_call(server, "start_diff_review", {"run_pair": PAIR, "k": 0})["next_unit"]
    one = _server_call(server, "start_diff_review", {"diff_id": DX})
    assert "error" not in one, one
    out = _server_call(server, "annotate_diff", _judge_args(nu["members"][0], nu["unit_id"]))
    assert out.get("written") is True, out
    assert out["next_unit"] is not None
    assert out["next_unit"]["read_with"].endswith(", k=0)"), out["next_unit"]["read_with"]


def test_a_refused_call_asking_an_in_range_k_sets_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ R-8 (the error filter alone): a start_diff_review refused for its unit but asking k=8 —
    in range — sets nothing: the session works at the default k, so after its four must-read
    entries the next unit is the second tier.

    MUTATION (verified RED, 1 failed): take k from refused calls too (the range check kept) ->
    read at k=8 -> the fifth unit is still an entry -> RED."""
    w = _wide_world(tmp_path, monkeypatch, 8)
    server = mcp_app.build_server(w.path)
    bad = _server_call(server, "start_diff_review", {"run_pair": PAIR, "unit": "nope", "k": 8})
    assert "error" in bad, bad
    nxt = _server_call(server, "start_diff_review", {"run_pair": PAIR})["next_unit"]
    for _ in range(4):
        assert nxt is not None and nxt["kind"] == "entry"
        _read_unit(server, nxt["unit_id"], None)
        out = _server_call(server, "annotate_diff", _judge_args(nxt["members"][0], nxt["unit_id"]))
        assert out.get("written") is True, out
        nxt = out["next_unit"]
    assert nxt is not None and nxt["kind"] == "second_tier_batch"


def test_a_call_without_k_counts_as_the_default_k(world: World) -> None:
    """★ R-8 (a call without k): a session that asked k=0 and then called without k works at the
    larger, the default — its last write's coverage reads (k=4).

    MUTATION (verified RED, 1 failed): skip calls without k -> the session reads k=0 -> RED."""
    server = mcp_app.build_server(world.path)
    _server_call(server, "start_diff_review", {"run_pair": PAIR, "k": 0})
    out = _walk_pair(server, None)
    assert "(k=4)" in out["coverage_statement"], out["coverage_statement"]


def test_a_range_check_alone_keeps_an_out_of_range_k_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ R-8 (the range check alone): a logged start_diff_review line asking an out-of-range k
    with NO error recorded (a log line the error filter does not catch) still sets nothing.

    MUTATION (verified RED, 1 failed): drop the 0..MAX_K check (the error filter kept) -> the
    session reads k=201 -> refused write -> RED."""
    from treasure_map.lib import tool_call_log as tcl

    w = _wide_world(tmp_path, monkeypatch, 8)
    server = mcp_app.build_server(w.path)
    nxt = _server_call(server, "start_diff_review", {"run_pair": PAIR})["next_unit"]
    log = tcl.log_path_for(w.path)
    session = next(iter(tcl.read_lines(log) or []))["session"]
    forged = tcl.build_line(
        tcl.Session(id=session), "start_diff_review", {"run_pair": PAIR, "k": 201}
    )
    tcl.append(log, forged)
    out = _server_call(server, "annotate_diff", _judge_args(nxt["members"][0], nxt["unit_id"]))
    assert out.get("written") is True, out
    assert out["next_unit"] is not None and ", k=" not in out["next_unit"]["read_with"]


def test_the_reports_judged_unread_is_the_coverage_statements_number(world: World) -> None:
    """★ R-13: the structured report's ``judged_unread`` is the coverage statement's "judged
    unread N" — one count, one name; the former key ``needs_recheck`` carries the same value,
    marked deprecated.

    MUTATION (verified RED, 1 failed): count the open audits under ``judged_unread`` -> RED."""
    import re

    world.judge(DX, A1, "changed_real", ctx=UNREAD)
    rep = _review(world, k=0).report
    said = re.search(r"judged unread (\d+);", rep["coverage_statement"])
    assert said is not None, rep["coverage_statement"]
    assert rep["judged_unread"]["count"] == int(said.group(1)) == 1
    assert A1 in rep["judged_unread"]["subjects"]
    old = dict(rep["needs_recheck"])
    assert old.pop("deprecated") == "renamed judged_unread"
    assert old == rep["judged_unread"]


# ── a file unit's material: cut and withheld inside its entry ────────────────────────────────


def _file_world(tmp_path: Path, rows: bool) -> Any:
    """One changed script on both sides of the pair (the FW fixture of test_file_diff): a long
    hunk whose text continues on another page, or (``rows``) 600 recorded lines whose structured
    lists and hunk both page."""
    from tests.unit.lib.test_file_diff import FW

    fw = FW(tmp_path)
    if rows:
        a_lines = [f"/usr/sbin/tool --set opt_{i} {'v' * 60} &" for i in range(600)]
        b_lines = [f"/usr/sbin/tool --set opt_{i} {'w' * 60} &" for i in range(600)]
        a = fw.file("a", "etc/init.sh", "shell_script", "\n".join(a_lines) + "\n")
        b = fw.file("b", "etc/init.sh", "shell_script", "\n".join(b_lines) + "\n")
        for side, fid, lines in (("a", a, a_lines), ("b", b, b_lines)):
            for n, line in enumerate(lines, start=1):
                fw.row(
                    side,
                    "script_calls",
                    fid,
                    command="/usr/sbin/tool",
                    raw_line=line,
                    line_number=n,
                )
    else:
        big = "".join(f"echo {i} {'x' * 200}\n" for i in range(400))
        fw.file("a", "etc/long.sh", "shell_script", "start\n")
        fw.file("b", "etc/long.sh", "shell_script", "start\n" + big)
    return fw


@pytest.mark.parametrize("rows", [False, True], ids=["long_hunk", "recorded_lines"])
def test_a_file_whose_difference_continues_reads_as_a_cut_material(
    tmp_path: Path, rows: bool
) -> None:
    """A file unit's line difference and structured lists live inside its ``entry``: when they
    continue on another page the material is cut, so a named write before anything else is read
    is judged unread, and one after the file was read on its own reads ``unit_delivered``
    (``material_cut``) — with ``read_partial`` while only the first page of its line difference
    was read, without it once every page was (lib/query/read_basis: a paged read counts whole by
    the windows its pages held).

    MUTATION (verified RED, 2 failed): read the continuation off the material's top level, as
    before -> material_cut False, the first write unit_delivered -> RED."""
    fw = _file_world(tmp_path, rows)
    server = mcp_app.build_server(fw.path)
    nu = _server_call(server, "start_diff_review", {"run_pair": PAIR})["next_unit"]
    assert nu["kind"] == ru.FILE and nu["must_read"] is True, nu["kind"]
    entry = nu["material"]["entry"]
    assert entry["hunk"]["next_hunk_offset"] is not None  # the precondition: the hunk continues
    assert nu["material_cut"] is True
    m = nu["members"][0]
    args = {
        "anchor_ref": m["anchor_ref"],
        "verdict": "changed_real",
        "rationale": "r",
        "run_pair": PAIR,
        "unit_id": nu["unit_id"],
    }
    first = _server_call(server, "annotate_diff", args)
    assert first["read_basis"] == {"basis": "none", "unread_before_verdict": True}
    path = m["anchor_ref"].split("#non_binary#", 1)[1]
    read = _server_call(server, "get_file_diff", {"run_pair": PAIR, "path": path})
    assert "error" not in read, read
    again = _server_call(server, "annotate_diff", args)
    assert again["read_basis"] == {
        "basis": "unit_delivered",
        "material_cut": True,
        "read_partial": "pages",
    }
    offset = read["entry"]["hunk"]["next_hunk_offset"]
    while offset is not None:
        more = _server_call(
            server, "get_file_diff", {"run_pair": PAIR, "path": path, "hunk_offset": offset}
        )
        offset = more["entry"]["hunk"]["next_hunk_offset"]
    whole = _server_call(server, "annotate_diff", args)
    assert whole["read_basis"] == {"basis": "unit_delivered", "material_cut": True}


def test_a_file_material_over_its_room_withholds_inside_its_entry_and_is_built_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With little room, a file unit's material withholds its hunk inside the entry (where it
    is) and keeps to the budget, its difference read once.

    MUTATION (verified RED, 1 failed): withhold at the material's top level, as before -> the
    answer stays over the budget and the difference is rebuilt on every refit -> RED."""
    from treasure_map.lib.query import file_diff as fd

    fw = _file_world(tmp_path, rows=False)
    calls = {"n": 0}
    real = fd.file_diff

    def counted(*a: Any, **kw: Any) -> Any:
        if kw.get("path"):
            calls["n"] += 1
        return real(*a, **kw)

    monkeypatch.setattr(mcp_app._fd, "file_diff", counted)
    monkeypatch.setattr(mcp_app, "_RESPONSE_BYTE_BUDGET", 30_000)
    server = mcp_app.build_server(fw.path)
    head = _server_call(server, "start_diff_review", {"run_pair": PAIR})
    nu = head["next_unit"]
    assert len(json.dumps(head)) <= 30_000, len(json.dumps(head))
    assert calls["n"] == 1, calls
    assert nu["material"]["entry"]["hunk"]["withheld"] == "page_budget"
    assert nu["material_cut"] is True


# ── a full batch: its member list, its write answer, its members still owed ──────────────────


def _s_world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, n: int) -> World:
    """``n`` aligned similarity-1 pairs in DX that all read as differing: bucket S, must-read,
    batched (at most 200 a batch)."""
    w = World(tmp_path, monkeypatch)
    pairs = []
    for i in range(1, n + 1):
        a = f"{i:08x}"
        w.pair(DX, a, a, sim=1.0)
        pairs.append((a, a))
    monkeypatch.setattr(pv, "_differs_of", lambda readings, built: frozenset(pairs))
    return w


@pytest.mark.parametrize("budget", [48_000, 12_000], ids=["page", "small_page"])
def test_every_hand_out_of_a_batch_names_the_members_its_page_shows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, budget: int
) -> None:
    """A batch is handed out by its page: the overview's next unit, the unit= read and a write
    answer's next unit each list exactly the members the material on that page shows — never more
    (a member listed but not shown would be "handed out" and never read) — within the budget; what
    is owed beyond the page is counted (``members_after_this_page``) and comes on the next.

    MUTATION (verified RED, 2 failed): hand out every member of the unit, as before -> RED."""
    w = _hex_world(tmp_path, monkeypatch, 200)
    monkeypatch.setattr(mcp_app, "_RESPONSE_BYTE_BUDGET", budget)
    server = mcp_app.build_server(w.path)
    head = _server_call(server, "start_diff_review", {"run_pair": PAIR, "k": 0})
    nu = head["next_unit"]
    assert nu["kind"] == ru.SECOND_TIER and nu["members_total"] == ru.BATCH_UNIT_MAX
    alone = _server_call(
        server, "start_diff_review", {"run_pair": PAIR, "unit": nu["unit_id"], "k": 0}
    )
    wrote = _server_call(server, "annotate_diff", _judge_args(nu["members"][0], nu["unit_id"]))
    for answer, holder in ((head, nu), (alone, alone), (wrote, wrote["next_unit"])):
        assert len(json.dumps(answer)) <= budget, len(json.dumps(answer))
        _assert_page_members(holder)
        shown = len(holder["members"])
        owed = holder["members_total"] - holder["members_disposed"]
        assert holder["members_after_this_page"] == owed - sum(
            1 for m in holder["members"] if not ru.disposed(m.get("review_state"))
        )
        if budget < 48_000:
            assert shown < ru.BATCH_UNIT_MAX and holder["members_after_this_page"] > 0


def test_a_full_batch_write_answer_keeps_to_the_budget_and_names_the_unread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """annotate_diff_batch over 200 must-read members of one diff, twice (no unit named: read
    against the unit this session was handed): each answer keeps to the byte budget — the
    per-item echo shrinks to index and action, and what repeats is said once:
    ``needs_recheck_indexes`` are exactly the items no delivery had listed, with what that means
    (``needs_recheck_means``), and the second write's ``overwrote_by`` counts the 200 it replaced.

    MUTATION (verified RED, 1 failed): keep the full per-item echo -> over the budget -> RED."""
    w = _s_world(tmp_path, monkeypatch, 200)
    server = mcp_app.build_server(w.path)
    nu = _server_call(server, "start_diff_review", {"run_pair": PAIR, "k": 0})["next_unit"]
    listed = {e["entry_id"] for e in nu["material"].get("entries") or []}
    members = [m for u in _review(w, k=0).units if u.kind == ru.S_BATCH for m in u.members]
    assert len(members) == 200 and 0 < len(listed) < 200  # the precondition
    items = [
        {"anchor_ref": m.anchor_ref, "verdict": "changed_real", "rationale": "r"} for m in members
    ]
    unread = [i for i, m in enumerate(members) if m.entry_id not in listed]
    for label in ("first", "overwrite"):
        b = _server_call(server, "annotate_diff_batch", {"annotations": items, "diff_id": DX})
        assert b.get("written") is True, b
        assert len(json.dumps(b)) <= mcp_app._RESPONSE_BYTE_BUDGET, (label, len(json.dumps(b)))
        assert b["needs_recheck_indexes"] == unread, label
        assert b["needs_recheck_means"] == mcp_app._JUDGED_UNREAD
        assert "needs_recheck_indexes" in b["note"]
        if label == "overwrite":
            assert b["overwrote_by"] == {"agent-via-mcp": 200}


def test_a_batch_echo_within_the_reserve_below_the_budget_is_compacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The per-item echo is compacted once it comes within 8,000 bytes of the budget, so the rest
    of the answer (note, groups, the next unit) still has room: an echo of S bytes is kept whole
    under a budget far above it and compacted under a budget of S + 4,000.

    MUTATION (verified RED, 1 failed): compact only once the echo alone is over the budget (no
    reserve) -> RED."""
    w = _s_world(tmp_path, monkeypatch, 40)
    server = mcp_app.build_server(w.path)
    _server_call(server, "start_diff_review", {"run_pair": PAIR, "k": 0})
    members = [m for u in _review(w, k=0).units if u.kind == ru.S_BATCH for m in u.members]
    items = [
        {"anchor_ref": m.anchor_ref, "verdict": "changed_real", "rationale": "r"} for m in members
    ]
    args = {"annotations": items, "diff_id": DX}
    monkeypatch.setattr(mcp_app, "_RESPONSE_BYTE_BUDGET", 10**7)
    _server_call(server, "annotate_diff_batch", args)
    whole = _server_call(server, "annotate_diff_batch", args)  # an overwrite, kept whole
    assert "needs_recheck_indexes" not in whole and "anchor_ref" in whole["results"][0]
    size = len(json.dumps(whole["results"]))
    monkeypatch.setattr(mcp_app, "_RESPONSE_BYTE_BUDGET", size + 4_000)
    cut = _server_call(server, "annotate_diff_batch", args)
    # what a write points to stays, cut (lib/query/write_hints): the counts by side only
    kept = {"index", "action", "group_ref", "other_direction", "same_shape", "same_shape_deferred"}
    assert set(cut["results"][0]) <= kept, cut["results"][0]
    assert "anchor_ref" not in cut["results"][0]
    assert cut["overwrote_by"] == {"agent-via-mcp": len(items)}


def test_the_pair_loop_as_written_completes_a_cut_must_read_batch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Must-read batches whose page shows only some members (a small page budget), followed as
    the workflow says — judge each member next_unit lists, naming the unit, call
    start_diff_review again, never fetch an entry: a unit handed out again lists the members still
    owed a reading first, so the review completes.

    MUTATION (verified RED, 1 failed): list the members in view order whatever was judged -> the
    page shows the members already judged every round and the rest are never handed out -> RED."""
    w = _s_world(tmp_path, monkeypatch, 60)
    monkeypatch.setattr(mcp_app, "_RESPONSE_BYTE_BUDGET", 12_000)
    server = mcp_app.build_server(w.path)
    out = _server_call(server, "start_diff_review", {"run_pair": PAIR})
    cut = False
    for _ in range(40):
        nu = out.get("next_unit")
        if not nu:
            break
        cut = cut or nu["members_after_this_page"] > 0
        for m in nu["members"]:
            r = _server_call(server, "annotate_diff", _judge_args(m, nu["unit_id"]))
            assert r.get("written") is True, r
        out = _server_call(server, "start_diff_review", {"run_pair": PAIR})
    assert cut  # the precondition: some page did not show its whole unit
    assert out.get("next_unit") is None, out["report"]["coverage_statement"]
    assert out["report"]["must_read_complete"] is True, out["report"]["coverage_statement"]


def test_a_batch_past_the_views_first_2000_entries_is_read_by_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A batch whose members sit past the view's first 2,000 entries: its material reads them
    from the view by entry id (no paging from the top), counts the unit's members, and shows them.

    MUTATION (verified RED, 1 failed): read the view's first 2,000 entries only -> no entry
    found -> RED."""
    w = _hex_world(tmp_path, monkeypatch, 2050)
    batches = [u for u in _review(w, k=0).units if u.kind == ru.SECOND_TIER]
    last = batches[-1]
    assert min(m.position for m in last.members) >= 2000, [m.position for m in last.members]
    server = mcp_app.build_server(w.path)
    one = _server_call(
        server, "start_diff_review", {"run_pair": PAIR, "unit": last.unit_id, "k": 0}
    )
    mat = one["material"]
    assert mat["entries_total"] == len(last.members)
    assert [e["entry_id"] for e in mat["entries"]] == [m.entry_id for m in last.members]
    assert "members_not_in_view" not in mat and one["material_cut"] is False


def test_a_member_the_view_does_not_list_is_named_and_cuts_the_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A unit member the view does not list (the facts and the view out of step) is named under
    ``members_not_in_view``, is not handed out, and makes the material cut.

    MUTATION (verified RED, 1 failed): drop the members the view did not list -> RED."""
    w = _hex_world(tmp_path, monkeypatch, 30)
    unit = next(u for u in _review(w, k=0).units if u.kind == ru.SECOND_TIER)
    gone = unit.members[0].entry_id
    real = mcp_app._get_diff_patch_view

    def hide(*a: Any, **kw: Any) -> Any:
        page = real(*a, **kw)
        if isinstance(page, dict) and page.get("entries") and kw.get("entry_ids"):
            page = {**page, "entries": [e for e in page["entries"] if e.get("entry_id") != gone]}
        return page

    monkeypatch.setattr(mcp_app, "_get_diff_patch_view", hide)
    server = mcp_app.build_server(w.path)
    one = _server_call(
        server, "start_diff_review", {"run_pair": PAIR, "unit": unit.unit_id, "k": 0}
    )
    assert one["material"].get("members_not_in_view") == [gone]
    assert one["material_cut"] is True
    assert gone not in {m["entry_id"] for m in one["members"]}


def test_the_on_disk_stamp_is_rehashed_only_when_a_package_file_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, world: World
) -> None:
    """Every start_diff_review says whether the code on disk moved; hashing the code is done
    once and again only after a file of the package changed.

    MUTATION (verified RED, 1 failed): hash on every call, as before -> RED."""
    import shutil

    from treasure_map.lib import rescan_version as rv

    pkg = tmp_path / "pkg"
    shutil.copytree(rv._PACKAGE, pkg, ignore=shutil.ignore_patterns("__pycache__"))
    monkeypatch.setattr(rv, "_PACKAGE", pkg)
    calls = {"n": 0}
    real = rv.code_version_of

    def counted(package_dir: Path, root: str) -> str:
        calls["n"] += 1
        return real(package_dir, root)

    monkeypatch.setattr(rv, "code_version_of", counted)
    server = mcp_app.build_server(world.path)
    first = _server_call(server, "start_diff_review", {"run_pair": PAIR})
    hashed = calls["n"]
    second = _server_call(server, "start_diff_review", {"run_pair": PAIR})
    assert first["server"]["code_moved_on_disk"] is False
    assert second["server"]["code_moved_on_disk"] is False
    assert hashed >= 1 and calls["n"] == hashed, (hashed, calls["n"])
    target = pkg / "lib" / "hunt" / "analyzer2.py"
    target.write_text(target.read_text() + "\n_MOVED_ON_DISK = 1\n")
    moved = _server_call(server, "start_diff_review", {"run_pair": PAIR})
    assert moved["server"]["code_moved_on_disk"] is True
    assert calls["n"] > hashed


@pytest.mark.parametrize("part", ["structured", "hunk_shape"])
def test_a_file_whose_lists_or_hunk_shape_continue_reads_as_a_cut_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, part: str
) -> None:
    """A file unit whose hunk text ends on its page but whose structured lists (or, for a
    suppressed hunk, its hunk shape) continue on another page: the material is cut, and a named
    write before anything else is read is judged unread.

    MUTATION (verified RED, 1 failed each): leave the structured lists' paging out of the cut
    -> structured RED; leave the hunk shape out -> hunk_shape RED."""
    fw = _file_world(tmp_path, rows=False)
    real = mcp_app._fd.file_diff

    def shaped(*a: Any, **kw: Any) -> Any:
        got = real(*a, **kw)
        if kw.get("path") and isinstance(got.get("entry"), dict):
            entry = dict(got["entry"])
            hunk = dict(entry.pop("hunk", {}) or {})
            hunk["next_hunk_offset"] = None
            if part == "structured":
                entry["hunk"] = hunk
                entry["structured"] = {"commands": ["x"], "lists_paging": {"next_offset": 1}}
            else:
                entry["hunk_shape"] = {"segments": [], "next_hunk_offset": 3}
            got = {**got, "entry": entry}
        return got

    monkeypatch.setattr(mcp_app._fd, "file_diff", shaped)
    server = mcp_app.build_server(fw.path)
    nu = _server_call(server, "start_diff_review", {"run_pair": PAIR})["next_unit"]
    assert nu["kind"] == ru.FILE
    assert nu["material_cut"] is True
    m = nu["members"][0]
    first = _server_call(
        server,
        "annotate_diff",
        {
            "anchor_ref": m["anchor_ref"],
            "verdict": "changed_real",
            "rationale": "r",
            "run_pair": PAIR,
            "unit_id": nu["unit_id"],
        },
    )
    assert first["read_basis"] == {"basis": "none", "unread_before_verdict": True}


# ── what was read: a part held back counts as cut ─────────────────────────────────────────────


def _withhold_hunk(monkeypatch: pytest.MonkeyPatch, entry_id: str) -> None:
    """Every view page renders ``entry_id``'s inline hunk withheld over its gate (as an entry with
    too many structural lines reads)."""
    real = mcp_app._get_diff_patch_view

    def gated(*a: Any, **kw: Any) -> Any:
        page = real(*a, **kw)
        if isinstance(page, dict) and page.get("entries"):
            page = {
                **page,
                "entries": [
                    {
                        **e,
                        "pseudocode_delta": {
                            **(e.get("pseudocode_delta") or {}),
                            "inline_hunk": {"withheld": "over_gate", "read_with": "get_pseudocode"},
                        },
                    }
                    if e.get("entry_id") == entry_id
                    else e
                    for e in page["entries"]
                ],
            }
        return page

    monkeypatch.setattr(mcp_app, "_get_diff_patch_view", gated)


def test_an_entry_whose_hunk_is_withheld_over_its_gate_reads_as_a_cut_material(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An entry unit whose inline hunk is withheld (over its gate) is a cut material: a write
    before the entry is read on is judged unread, not read.

    MUTATION (verified RED, 1 failed): count only the page budget's withholding as cut, as
    before -> material_cut False, the write unit_delivered -> RED."""
    _withhold_hunk(monkeypatch, "pair:00001000:00001000")
    server = mcp_app.build_server(world.path)
    nu = _server_call(server, "start_diff_review", {"run_pair": PAIR})["next_unit"]
    assert nu["kind"] == ru.ENTRY and nu["members"][0]["entry_id"] == "pair:00001000:00001000"
    assert nu["material_cut"] is True
    got = _server_call(server, "annotate_diff", _judge_args(nu["members"][0], nu["unit_id"]))
    assert got["read_basis"] == {"basis": "none", "unread_before_verdict": True}


def test_a_batch_member_whose_hunk_was_withheld_is_not_read_whole_and_counts_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A batch lists a member whose own inline hunk it withholds: the member was not shown whole,
    so a write on it before it is read on reads ``none``. Second tier (not must-read), it is
    disposed — and counted apart in the coverage statement as ``basis incomplete``.

    MUTATION (verified RED, 1 failed): count every listed member as shown whole -> the write reads
    unit_delivered -> RED. MUTATION (verified RED, 1 failed): leave such judgements out of the
    count -> RED."""
    w = _hex_world(tmp_path, monkeypatch, 30)
    unit = next(u for u in _review(w, k=0).units if u.kind == ru.SECOND_TIER)
    target = unit.members[0]
    _withhold_hunk(monkeypatch, str(target.entry_id))
    server = mcp_app.build_server(w.path)
    nu = _server_call(server, "start_diff_review", {"run_pair": PAIR, "k": 0})["next_unit"]
    assert nu["unit_id"] == unit.unit_id
    assert target.entry_id in {m["entry_id"] for m in nu["members"]}  # listed
    m = {"anchor_ref": target.anchor_ref}
    got = _server_call(server, "annotate_diff", _judge_args(m, nu["unit_id"]))
    assert got["read_basis"] == {"basis": "none", "unread_before_verdict": False}
    rep = _server_call(server, "start_diff_review", {"run_pair": PAIR, "k": 0})["report"]
    assert rep["basis_incomplete"]["count"] == 1
    assert rep["basis_incomplete"]["subjects"] == [target.anchor_ref]
    assert "basis incomplete 1;" in rep["coverage_statement"]


# ── judgements no unit hands out: dangling, and no longer listed ────────────────────────────


@pytest.mark.parametrize("verdict", ["change_inconclusive", "changed_real"])
def test_the_entry_point_counts_the_dangling_judgements_by_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, verdict: str
) -> None:
    """start_diff_review's report carries the judgements whose subject no longer resolves
    (``dangling``, by verdict, changed_real apart) beside the ones no longer listed, and the
    coverage statement names both counts — no unit hands either out, so the entry point is
    where they are seen.

    MUTATION (verified RED, 2 failed): leave ``dangling`` off the report keys start_diff_review
    forwards -> RED; MUTATION (verified RED, 2 failed): ``read_progress`` does not collect the
    dangling judgements -> RED; MUTATION (verified RED, 1 failed): no changed_real apart ->
    changed_real RED."""
    from tests.unit.lib.test_diff_review import _unlist_and_repair

    w = World(tmp_path, monkeypatch)
    unlisted, gone = _unlist_and_repair(w)
    if verdict == "changed_real":
        # the same judgement as a change found (a write is refused now that the subject is gone)
        w.atlas.execute("UPDATE overlay SET verdict = 'changed_real' WHERE anchor_ref = ?", (gone,))
        w.atlas.commit()
    server = mcp_app.build_server(w.path)
    rep = _server_call(server, "start_diff_review", {"run_pair": PAIR})["report"]
    assert "dangling" in rep, sorted(rep)
    dangling = rep["dangling"]
    assert dangling["count"] == 1 and dangling["by_verdict"] == {verdict: 1}
    assert dangling["anchors"] == [gone]
    want = 1 if verdict == "changed_real" else 0
    assert dangling["changed_real"]["count"] == want
    assert rep["judged_not_listed"]["count"] == 1
    assert f"dangling 1 (changed_real {want}); not listed 1;" in rep["coverage_statement"]


# ── shards: what a write hands on, and what each shard holds ──────────────────────────────────


def test_a_write_naming_no_shard_hands_on_the_shard_its_session_asked_for(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A session that asked start_diff_review for shard 1 of 3 and then writes naming its unit
    but no shard is handed the next unit of that shard, and the answer says so (``shard``,
    ``inferred``), as a write reads the session's k.

    MUTATION (verified RED, 1 failed): no shard from the session -> the answer names none and
    the next unit may fall outside the shard -> RED."""
    w = _hex_world(tmp_path, monkeypatch, 200)
    server = mcp_app.build_server(w.path)
    start = {"run_pair": PAIR, "k": 0, "worker": 1, "workers": 3}
    nu = _server_call(server, "start_diff_review", start)["next_unit"]
    assert ru.in_shard(nu["unit_id"], 1, 3)
    got = _server_call(server, "annotate_diff", _judge_args(nu["members"][0], nu["unit_id"]))
    assert got.get("shard") == {"worker": 1, "workers": 3, "inferred": True}
    assert got["next_unit"] is None or ru.in_shard(got["next_unit"]["unit_id"], 1, 3)


def test_a_unit_read_between_the_sharded_overview_and_the_write_keeps_the_shard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The session asked the overview for shard 1 of 3, then read one unit alone with
    start_diff_review(run_pair, unit=...) naming no shard, then wrote naming only the unit: the
    unit= read is not the session's last overview (it asks for no shard), so the write still
    hands on the next unit of shard 1 and says the shard was inferred.

    MUTATION (verified RED, 1 failed, AssertionError): let a unit= call count as the session's
    last overview in _session_shard (drop ``or params.get("unit") is not None``) -> no shard ->
    RED."""
    w = _hex_world(tmp_path, monkeypatch, 200)
    server = mcp_app.build_server(w.path)
    start = {"run_pair": PAIR, "k": 0, "worker": 1, "workers": 3}
    nu = _server_call(server, "start_diff_review", start)["next_unit"]
    assert nu is not None and ru.in_shard(nu["unit_id"], 1, 3)
    alone = _server_call(
        server, "start_diff_review", {"run_pair": PAIR, "unit": nu["unit_id"], "k": 0}
    )
    assert "material" in alone and alone.get("members"), sorted(alone)
    got = _server_call(server, "annotate_diff", _judge_args(alone["members"][0], nu["unit_id"]))
    assert got.get("written") is True, got
    assert got.get("shard") == {"worker": 1, "workers": 3, "inferred": True}, got.get("shard")
    nxt = got.get("next_unit")
    assert nxt is not None, sorted(got)  # the precondition: a next unit is handed on
    assert ru.in_shard(nxt["unit_id"], 1, 3), nxt["unit_id"]
    assert int(nxt["unit_id"][:8], 16) % 3 == 1


def test_the_overview_says_what_each_shard_holds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With workers=3 the overview's shard block counts each shard's units, members, must-read
    members and their candidate rows; summed over the shards they are the pair's own counts.

    MUTATION (verified RED, 1 failed): no per-shard counts -> RED."""
    w = _s_world(tmp_path, monkeypatch, 100)
    server = mcp_app.build_server(w.path)
    out = _server_call(server, "start_diff_review", {"run_pair": PAIR, "worker": 0, "workers": 3})
    slices = out["shard"].get("slices")
    assert slices is not None, out["shard"]
    assert [s["worker"] for s in slices] == [0, 1, 2]
    rep = out["report"]
    units = sum(
        r["units"] for k, r in rep["units_by_kind"].items() if k not in (ru.AUDIT, ru.REDUCE)
    )
    assert sum(s["units"] for s in slices) == units
    assert sum(s["members"] for s in slices) == rep["all_listed"]["members"]
    assert sum(s["must_read_members"] for s in slices) == rep["must_read"]["members"]
    assert sum(s["candidate_rows"] for s in slices) == rep["must_read"]["candidate_rows"]


def test_a_batch_whose_first_owed_entry_is_larger_than_the_page_hands_out_that_one_cut(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The first member still owed has an entry larger than the whole page: the batch is handed
    out with that one member alone, its entry cut to fit (its hunk withheld, with where to read
    it), and the material says it was cut — never an empty page that names no member.

    MUTATION (verified RED, 1 failed): hand out no entry when the first does not fit -> the page
    lists no member -> RED."""
    w = _hex_world(tmp_path, monkeypatch, 30)
    unit = next(u for u in _review(w, k=0).units if u.kind == ru.SECOND_TIER)
    big = str(unit.members[0].entry_id)
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
                    if e.get("entry_id") == big
                    else e
                    for e in page["entries"]
                ],
            }
        return page

    monkeypatch.setattr(mcp_app, "_get_diff_patch_view", inflated)
    server = mcp_app.build_server(w.path)
    one = _server_call(
        server, "start_diff_review", {"run_pair": PAIR, "unit": unit.unit_id, "k": 0}
    )
    assert len(json.dumps(one)) <= mcp_app._RESPONSE_BYTE_BUDGET
    assert [m["entry_id"] for m in one["members"]] == [big]
    assert one["material"]["entries"][0]["entry_id"] == big
    assert one["material_cut"] is True
    assert one["members_after_this_page"] == len(unit.members) - 1
