# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Signals the diff view had computed but buried, brought forward (lib/query/patch_view): a sink
name in an aligned pair's callee-set difference floats its entry, each function's sink candidate
counts, bucket S (an aligned similarity-1 pair whose pseudocode differs), the first counts a reader
sees, and the recomputed overlay kept per process while its baseline is not current.

Zero real data: the world is test_patch_view's (one diff of ``libx``, each run with its own
analysis.db); every address and name is synthetic.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from tests.unit.lib.test_patch_view import (
    DIFF,
    World,
    _overlay_row,
    _pair_id,
    _ref,
    _view,
)
from treasure_map import mcp_app
from treasure_map.lib import overlay
from treasure_map.lib.errors import ConfigError
from treasure_map.lib.query import diff_annotations as dann
from treasure_map.lib.query import diff_review as dr
from treasure_map.lib.query import patch_view as pv
from treasure_map.lib.query import sink_overlay as so
from treasure_map.version import UNKNOWN_VERSION


@pytest.fixture(autouse=True)
def _fresh(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every world reuses one diff id: drop the process-wide caches, and read the diff as current
    (its stamps are not under test here)."""
    monkeypatch.setattr(mcp_app, "_installed_commit", lambda: UNKNOWN_VERSION)
    monkeypatch.setattr(
        pv,
        "diff_source_staleness",
        lambda atlas, diff_id: {
            "source_stale": False,
            "source_stale_reason": None,
            "toolchain_checked": True,
        },
    )
    pv._clear_view_caches()


def _rows(monkeypatch: pytest.MonkeyPatch, rows: list[so.SinkOverlayRow]) -> None:
    """The diff's overlay rows, as computed (no stored baseline)."""
    monkeypatch.setattr(
        pv,
        "compute_sink_overlay",
        lambda atlas, diff_id: so.SinkOverlayResult(
            list(rows), so.SinkOverlayCoverage(0, 0, 0, 0, 0, False)
        ),
    )


def _cmd(side: str, func: str, at: str) -> str:
    return _ref("runA" if side == "a" else "runB", func, "cmd", at)


# ── a sink in an aligned pair's callee-set difference floats its entry ────────────────────────


def _b_swap_world(tmp_path: Path) -> World:
    """Two B pairs whose candidates line up (sink_present_no_visible_delta) and whose callee lists
    differ by a sink and three other names — wide, not narrow — one with the sink on side A, one on
    side B; and a third such pair with no sink in the difference."""
    w = World(tmp_path)
    for a, b, ca, cb in (
        ("00001000", "00002000", ["system", "popen", "l1", "l2"], ["system"]),
        ("00003000", "00004000", ["system"], ["system", "popen", "l1", "l2"]),
        ("00005000", "00006000", ["system", "l1"], ["system", "l2"]),
    ):
        w.pair(a, b, 0.97, 0.7)
        w.inst("a", _cmd("a", a, "0x10"), "cmd", "system")
        w.inst("b", _cmd("b", b, "0x10"), "cmd", "system")
        w.im(a[:-2] + "10", b[:-2] + "10", a)
        w.fn("a", a, ca)
        w.fn("b", b, cb)
    w.commit()
    return w


def test_an_aligned_wide_swap_floats_a_b_entry_whichever_side_holds_the_sink(
    tmp_path: Path,
) -> None:
    """★ A B entry whose aligned callee-set difference holds a sink floats to attention 0, basis
    sink_callee_swap — not narrow (three names on a side), and alike whether the sink is only in A
    or only in B. With no sink in the difference it stays at attention 1. In the candidate_tier
    order such a B entry sorts with sink_presence_signal (subclass_rank 0).

    MUTATION (verified RED, 1 failed each): drop the aligned-swap branch of ``significance`` ->
    RED; float only a swap whose sink is on side A -> RED; float only a narrow swap -> RED; drop the
    aligned swap from the B rank in ``_rank`` -> RED."""
    w = _b_swap_world(tmp_path)
    v = _view(w, sort_by="significance")["by_id"]
    a_side, b_side = _pair_id("00001000", "00002000"), _pair_id("00003000", "00004000")
    plain = _pair_id("00005000", "00006000")
    assert v[a_side]["sink_callee_swap"]["sinks_only_in_a"] == ["popen"]
    assert v[b_side]["sink_callee_swap"]["sinks_only_in_b"] == ["popen"]
    for eid in (a_side, b_side):
        e = v[eid]
        assert (e["bucket"], e["subclass"]) == ("B", "sink_present_no_visible_delta"), eid
        assert e["sink_callee_swap"]["narrow"] is False, eid
        assert e["significance"] == {"attention": 0, "basis": "sink_callee_swap"}, eid
        assert e["lift_basis"] is None and e["rank_key"]["sink_callee_swap"] == 0, eid
    assert "sink_callee_swap" not in v[plain]
    assert v[plain]["significance"] == {"attention": 1, "basis": "recheckable_no_visible_delta"}
    tier = _view(w, sort_by="candidate_tier")["by_id"]
    assert tier[a_side]["rank_key"]["subclass_rank"] == 0
    assert tier[b_side]["rank_key"]["subclass_rank"] == 0
    assert tier[plain]["rank_key"]["subclass_rank"] == 2


def test_an_aligned_pair_in_bucket_r_is_lifted_never_floated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ A pair can be aligned and still sit in R (one of its rows lands there). Its swap reads
    pairing aligned, yet R is never floated: it stays at attention 1, lifted (swap_lift 1,
    lift_basis sink_callee_swap) — never 0, never 2.

    MUTATION (verified RED, 1 failed): drop the ``bucket != "R"`` guard in ``significance`` ->
    the entry reaches attention 0 -> RED."""
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.97, 0.8)
    w.fn("a", "00001000", ["memcpy"])
    w.fn("b", "00002000", ["strcpy"])
    w.commit()
    row = _overlay_row(_cmd("a", "00001000", "0x10"), None, "callsite", "cmd")
    row = so.SinkOverlayRow(
        **{
            **row.__dict__,
            "presence": "presence_undetermined",
            "presence_reason": "callsite_not_exported",
        }
    )
    _rows(monkeypatch, [row])
    e = _view(w, sort_by="significance")["by_id"][_pair_id("00001000", "00002000")]
    assert (e["bucket"], e["alignment_state"]) == ("R", "aligned")
    assert e["sink_callee_swap"]["pairing"] == "aligned"
    assert e["significance"]["attention"] == 1
    assert (e["rank_key"]["sink_callee_swap"], e["lift_basis"]) == (1, "sink_callee_swap")


# ── sink_candidate_counts ──────────────────────────────────────────────────────────────────────


def _counts_world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> World:
    """Aligned pairs (similarity 0.8), each a shape of what the counts read:
    delta    A 3 system + 1 strcpy, B 1 system + 1 strcpy (strcpy equal: not listed)
    noinv    A 2 system; B's function is not in that scan's inventory (and holds no candidate)
    coarse   A 2 system; B one system at function-fallback granularity
    ambig    A 1 system; B one candidate whose sink name cannot be read (no instance record)
    equal    A 2 system, B 2 system
    elsewhere A no candidate; B 2 system, one carried by a row placed in another entry (its A ref
             is in ``other``) — counted for the function it names, not for the entry
    other    A 1 system (the row above), B none
    and an undetermined pair (confidence 0.5): A 2 system, B 1."""
    w = World(tmp_path)
    shapes = {
        "delta": ("00001000", "00002000"),
        "noinv": ("00003000", "00004000"),
        "coarse": ("00005000", "00006000"),
        "ambig": ("00007000", "00008000"),
        "equal": ("00009000", "0000a000"),
        "elsewhere": ("0000b000", "0000c000"),
        "other": ("0000d000", "0000e000"),
        "proposed": ("0000f000", "00010000"),
    }
    for key, (a, b) in shapes.items():
        w.pair(a, b, 0.5 if key == "proposed" else 0.97, 0.8)
        w.fn("a", a, ["system", "strcpy"])
        if key != "noinv":
            w.fn("b", b, ["system", "strcpy"])
    rows: list[so.SinkOverlayRow] = []

    def cand(side: str, func: str, at: str, sink: str = "system", gran: str = "callsite") -> str:
        ref = _ref("runA" if side == "a" else "runB", func, "cmd", at)
        if sink:
            w.inst(side, ref, "cmd", sink)
        rows.append(
            _overlay_row(ref, None, gran, "cmd")
            if side == "a"
            else _overlay_row(None, ref, gran, "cmd")
        )
        return ref

    for i in range(3):
        cand("a", "00001000", f"0x{0x10 + i * 4:x}")
    cand("a", "00001000", "0x40", "strcpy")
    cand("b", "00002000", "0x10")
    cand("b", "00002000", "0x40", "strcpy")
    cand("a", "00003000", "0x10")
    cand("a", "00003000", "0x14")
    cand("a", "00005000", "0x10")
    cand("a", "00005000", "0x14")
    cand("b", "00006000", "0x10", gran="function_fallback")
    cand("a", "00007000", "0x10")
    cand("b", "00008000", "0x10", sink="")
    for f, side in (("00009000", "a"), ("0000a000", "b")):
        cand(side, f, "0x10")
        cand(side, f, "0x14")
    cand("b", "0000c000", "0x10")
    # one row whose A ref is in ``other`` and whose B ref is in ``elsewhere``: placed in ``other``
    a_ref, b_ref = _cmd("a", "0000d000", "0x10"), _cmd("b", "0000c000", "0x14")
    w.inst("a", a_ref, "cmd", "system")
    w.inst("b", b_ref, "cmd", "system")
    rows.append(_overlay_row(a_ref, b_ref, "callsite", "cmd"))
    cand("a", "0000f000", "0x10")
    cand("a", "0000f000", "0x14")
    cand("b", "00010000", "0x10")
    w.commit()
    _rows(monkeypatch, rows)
    return w


def _counts(v: dict[str, Any], a: str, b: str) -> dict[str, Any] | None:
    e = v["by_id"][_pair_id(a, b)]
    return e.get("sink_candidate_counts")


def test_the_counts_name_each_sink_that_counts_differently(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ Per sink, each function's hunt candidates (callsite keys, by distinct ref): a sink both
    sides count differently is a delta, one they count alike is not listed, a pair counting every
    sink alike carries no field. Rows are counted by the function they name, not by the entry they
    sit in.

    MUTATION (verified RED, 1 failed each): list equal counts in delta -> RED; read a row's B ref
    only when the row has no A ref (count by where the row was placed) -> ``elsewhere`` reads B 1
    -> RED."""
    w = _counts_world(tmp_path, monkeypatch)
    v = _view(w)
    sc = _counts(v, "00001000", "00002000")
    assert sc is not None
    assert sc["unit"] == pv.SINK_COUNTS_UNIT
    assert sc["pairing"] == "aligned"
    assert sc["delta"] == [{"sink": "system", "a": 3, "b": 1}]
    assert sc["unknown"] == []
    assert _counts(v, "00009000", "0000a000") is None
    assert _counts(v, "0000b000", "0000c000") == {
        "unit": pv.SINK_COUNTS_UNIT,
        "pairing": "aligned",
        "delta": [{"sink": "system", "a": 0, "b": 2}],
        "unknown": [],
    }


def test_what_cannot_be_counted_is_unknown_with_why_never_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ A side that cannot be counted is unknown, with its reason, and never a number: a function
    the B scan does not hold (function_not_in_scan_inventory — not 0), a sink with a
    function-level key there (granularity_not_per_call), a candidate whose sink name cannot be read
    (sink_ambiguous on every sink of that side, and ``sink: null`` when that side names none).

    MUTATION (verified RED, 1 failed each): drop the inventory check -> noinv reads b 0 in delta
    -> RED; drop the function-level check -> coarse reads b 0 -> RED; drop the null-sink line ->
    RED."""
    w = _counts_world(tmp_path, monkeypatch)
    v = _view(w)
    noinv = _counts(v, "00003000", "00004000")
    assert noinv is not None and noinv["delta"] == []
    assert noinv["unknown"] == [
        {"sink": "system", "side": "b", "reason": "function_not_in_scan_inventory"}
    ]
    coarse = _counts(v, "00005000", "00006000")
    assert coarse is not None and coarse["delta"] == []
    assert coarse["unknown"] == [
        {"sink": "system", "side": "b", "reason": "granularity_not_per_call"}
    ]
    ambig = _counts(v, "00007000", "00008000")
    assert ambig is not None and ambig["delta"] == []
    assert ambig["unknown"] == [
        {"sink": "system", "side": "b", "reason": "sink_ambiguous"},
        {"sink": None, "side": "b", "reason": "sink_ambiguous"},
    ]


def test_an_unread_side_is_side_unreadable_never_out_of_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An analysis.db that cannot be read answers 'not held' for every function; the counts say
    side_unreadable for that whole side, before (and instead of) function_not_in_scan_inventory.

    MUTATION (verified RED, 1 failed): test the inventory before the read error -> RED."""
    w = _counts_world(tmp_path, monkeypatch)
    w.atlas.execute("UPDATE run SET analysis_db_path = ? WHERE run_id = 'runB'", ("/nowhere.db",))
    w.commit()
    v = _view(w)
    reasons = {
        u["reason"]
        for e in v["entries"]
        for u in (e.get("sink_candidate_counts") or {}).get("unknown", [])
        if u["side"] == "b"
    }
    assert reasons == {"side_unreadable"}
    sc = _counts(v, "00001000", "00002000")
    assert sc is not None and sc["delta"] == []
    assert {"sink": "system", "side": "b", "reason": "side_unreadable"} in sc["unknown"]


def test_an_aligned_count_delta_floats_and_a_proposed_one_lifts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ An aligned pair whose counts differ floats to attention 0 (basis sink_candidate_counts);
    an undetermined pair's (pairing proposed) lifts it inside attention 1 (lift_basis
    sink_candidate_counts); an unknown alone moves nothing.

    MUTATION (verified RED, 1 failed each): drop the counts branch of ``significance`` -> RED;
    leave the counts out of ``_lift_basis`` -> RED. (Floating a proposed delta too is held back
    by the R guard, which an undetermined pair always meets: an equivalent mutation.)"""
    w = _counts_world(tmp_path, monkeypatch)
    v = _view(w, sort_by="significance")
    delta = v["by_id"][_pair_id("00001000", "00002000")]
    assert delta["significance"] == {"attention": 0, "basis": "sink_candidate_counts"}
    proposed = v["by_id"][_pair_id("0000f000", "00010000")]
    assert proposed["sink_candidate_counts"]["pairing"] == "proposed"
    assert proposed["sink_candidate_counts"]["delta"] == [{"sink": "system", "a": 2, "b": 1}]
    assert proposed["significance"]["attention"] == 1
    assert (proposed["rank_key"]["sink_callee_swap"], proposed["lift_basis"]) == (
        1,
        "sink_candidate_counts",
    )
    noinv = v["by_id"][_pair_id("00003000", "00004000")]
    assert noinv["significance"]["attention"] == 1 and noinv["lift_basis"] is None


def test_a_swap_names_the_basis_before_a_count_delta(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When an entry has both a sink swap and a count delta, the swap is read first: an aligned
    pair floats with basis sink_callee_swap, and an undetermined pair is lifted with lift_basis
    sink_callee_swap.

    MUTATION (verified RED, 1 failed each): test the counts before the swap in ``significance``
    -> basis sink_candidate_counts -> RED; the same in ``_lift_basis`` -> RED."""
    w = World(tmp_path)
    rows: list[so.SinkOverlayRow] = []
    for a, b, conf in (("00001000", "00002000", 0.97), ("00003000", "00004000", 0.5)):
        w.pair(a, b, conf, 0.8)
        w.fn("a", a, ["system", "popen"])
        w.fn("b", b, ["system"])
        for side, func, n in (("a", a, 2), ("b", b, 1)):
            for i in range(n):
                ref = _cmd(side, func, f"0x{0x10 + i * 4:x}")
                w.inst(side, ref, "cmd", "system")
                rows.append(
                    _overlay_row(ref, None, "callsite", "cmd")
                    if side == "a"
                    else _overlay_row(None, ref, "callsite", "cmd")
                )
    w.commit()
    _rows(monkeypatch, rows)
    v = _view(w, sort_by="significance")["by_id"]
    aligned, proposed = v[_pair_id("00001000", "00002000")], v[_pair_id("00003000", "00004000")]
    for e, pairing in ((aligned, "aligned"), (proposed, "proposed")):
        assert e["sink_callee_swap"]["pairing"] == pairing
        assert e["sink_candidate_counts"]["pairing"] == pairing
        assert e["sink_candidate_counts"]["delta"] == [{"sink": "system", "a": 2, "b": 1}]
    assert aligned["significance"] == {"attention": 0, "basis": "sink_callee_swap"}
    assert proposed["significance"]["attention"] == 1
    assert proposed["lift_basis"] == "sink_callee_swap"


def test_a_summary_carries_the_counts_lift_and_note_as_counts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A summary entry keeps lift_basis and swap_pairing_note, and sink_candidate_counts as its
    pairing, its whole delta and only how many unknowns and why.

    MUTATION (verified RED, 1 failed each): leave sink_candidate_counts out of the summary -> RED;
    copy its unknown list whole -> RED; leave lift_basis out of the copied keys -> RED."""
    w = _counts_world(tmp_path, monkeypatch)
    w.fn("a", "00011000", ["memcpy"])
    w.fn("b", "00012000", ["strcpy"])
    w.pair("00011000", "00012000", 0.5, 0.4)  # a proposed swap: its note rides the entry
    w.commit()
    pages = [pv.get_diff_patch_view(w.atlas, DIFF, detail="summary", limit=200)]
    by_id = {e["entry_id"]: e for e in pages[0]["entries"]}
    noinv = by_id[_pair_id("00003000", "00004000")]
    assert noinv.get("sink_candidate_counts") == {
        "pairing": "aligned",
        "delta": [],
        "unknown": {"n": 1, "reasons": ["function_not_in_scan_inventory"]},
    }
    proposed = by_id[_pair_id("0000f000", "00010000")]
    assert proposed.get("lift_basis") == "sink_candidate_counts"
    swap = by_id[_pair_id("00011000", "00012000")]
    assert swap.get("swap_pairing_note") == pv.SWAP_PAIRING_NOTE
    assert swap.get("lift_basis") == "sink_callee_swap"


# ── bucket S ───────────────────────────────────────────────────────────────────────────────────


def _s_world(tmp_path: Path) -> World:
    """Aligned similarity-1 pairs: one whose text differs (S), one identical (not listed), one whose
    text differs and whose candidate lines up (S, with a persisted row), and an E-shaped pair kept
    out by its own bucket."""
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.97, 1.0)
    w.fn("a", "00001000", ["foo"], pseudocode="x = foo(1);")
    w.fn("b", "00002000", ["foo"], pseudocode="x = foo(2);")
    w.pair("00003000", "00004000", 0.97, 1.0)
    w.fn("a", "00003000", ["foo"], pseudocode="x = foo(3);")
    w.fn("b", "00004000", ["foo"], pseudocode="x = foo(3);")
    w.pair("00005000", "00006000", 0.97, 1.0)
    w.inst("a", _cmd("a", "00005000", "0x10"), "cmd", "system")
    w.inst("b", _cmd("b", "00006000", "0x10"), "cmd", "system")
    w.im("00005010", "00006010", "00005000")
    w.fn("a", "00005000", ["system"], pseudocode="system(a);")
    w.fn("b", "00006000", ["system"], pseudocode="system(b);")
    w.commit()
    return w


S1, IDENT, S_ROW = (
    _pair_id("00001000", "00002000"),
    _pair_id("00003000", "00004000"),
    _pair_id("00005000", "00006000"),
)


def test_an_aligned_similarity_one_pair_whose_text_differs_is_listed_as_s(tmp_path: Path) -> None:
    """★ An aligned similarity-1 pair that places no bucket and reads differs is listed as bucket
    S (subclass aligned_pseudocode_differs), an identical one is not, and the not-listed
    'differs' category keeps its key at 0 with listed_as. S is never written to the build: the
    entry's own bucket is empty and its judgement basis reads bucket null.

    MUTATION (verified RED, 1 failed each): list every unbucketed aligned pair as S (drop the
    differs test) -> the identical pair is listed -> RED; write "S" to ``e.bucket`` -> the basis
    reads S -> RED; sink S to attention 2 -> RED."""
    w = _s_world(tmp_path)
    v = _view(w)
    assert S1 in v["by_id"] and S_ROW in v["by_id"] and IDENT not in v["by_id"]
    for eid in (S1, S_ROW):
        assert (v["by_id"][eid]["bucket"], v["by_id"][eid]["subclass"]) == (
            "S",
            "aligned_pseudocode_differs",
        )
        assert v["by_id"][eid]["significance"] == {
            "attention": 1,
            "basis": "aligned_pseudocode_differs",
        }
    assert v["counts"]["by_bucket"] == {"S": 2}
    assert v["not_listed"]["aligned_pseudocode_differs"] == {
        "count": 0,
        "listed_as": "bucket S",
        "page_with": 'bucket="S"',
    }
    assert v["not_listed"]["aligned_pseudocode_identical"]["count"] == 1
    built = pv.build_diff_view(w.atlas, DIFF)
    assert built is not None
    listed = pv.listed_view(w.atlas, built)
    assert listed.s_ids == {S1, S_ROW}
    by_id = {e.entry_id: e for e in listed.entries}
    assert by_id[S1].bucket == "" and by_id[S1].listed_as == "S"
    assert dr.entry_facts(by_id[S1])["bucket"] is None
    assert {e.entry_id for e in built.entries} == set()  # the build itself lists nothing


def test_s_entries_order_after_r_b_and_e_in_their_segment() -> None:
    """In the candidate_tier order an S entry with a candidate is in segment 2 after R, B and E
    (lane 3), one with none in segment 3 after B, R, C and E (lane 4).

    MUTATION (verified RED, 1 failed): give S lane 0 in segment 2 -> it leads R -> RED."""

    def entry(bucket: str, tier: int | str, listed_as: str = "", addr: str = "x") -> pv._Entry:
        pair = pv._Pair(addr, addr, None, None, 0.95, 0.5, "aligned", None, None)
        e = pv._Entry(pair=pair, unpaired=None, bucket=bucket, listed_as=listed_as)
        e.tier = tier
        e.rank = pv._rank(e)
        return e

    seg2 = [
        entry("", 3, "S", "00000001"),
        entry("E", 3, addr="00000002"),
        entry("B", 3, addr="00000003"),
        entry("R", 3, addr="00000004"),
    ]
    seg3 = [
        entry("", pv.NO_SINK, "S", "00000005"),
        entry("E", pv.NO_SINK, addr="00000006"),
        entry("C", pv.NO_SINK, addr="00000007"),
        entry("R", pv.NO_SINK, addr="00000008"),
        entry("B", pv.NO_SINK, addr="00000009"),
    ]
    order = [e.address for e in pv._sort(seg2 + seg3, None)]
    assert order == [
        "00000004",
        "00000003",
        "00000002",
        "00000001",
        "00000009",
        "00000008",
        "00000007",
        "00000006",
        "00000005",
    ]
    assert seg2[0].rank["lane"] == 3 and seg3[0].rank["lane"] == 4


def test_a_judged_s_entry_reads_current_in_both_read_paths(tmp_path: Path) -> None:
    """★ A judgement written on an S entry reads current — concluded, basis unchanged — on the view
    and on list_overlays, and the progress counts it as looked at.

    MUTATION (verified RED, 1 failed): build ViewReview's items from ``built.entries`` -> the
    run pair's progress counts no S entry -> RED."""
    w = _s_world(tmp_path)
    anchor = dr.pair_anchor("runA", "runB", "libx", "00001000", "00002000")
    w.judge(DIFF, anchor, "changed_real")
    w.commit()
    rows = overlay.list_overlays(w.atlas, anchor_kind="diff_subject", run_id="runA::runB")
    (row,) = [r for r in rows["overlays"] if r["anchor_ref"] == anchor]
    assert (row["basis_state"], row["source_stale"]) == ("unchanged", False)
    assert row["review_state"] == "concluded"
    assert rows["review_progress"]["by_bucket"]["S"]["concluded"] == 1
    again = _view(w)
    assert again["by_id"][S1]["review_state"] == "concluded"
    assert again["review_progress"]["by_bucket"]["S"]["concluded"] == 1


def test_an_s_entry_resolves_by_entry_id_and_anchor_and_can_be_promoted(tmp_path: Path) -> None:
    """★ An S entry is named like any listed entry — by entry_id and by anchor_ref, in the view and
    in promote alike — and its persisted row carries a promotion under the existing rules.

    MUTATION (verified RED, 1 failed each): resolve the view's entry in ``built.entries`` -> the S
    entry reads 'placed but not listed' -> RED; read promote's entry from ``built.entries`` ->
    RED."""
    w = _s_world(tmp_path)
    e = _view(w)["by_id"][S_ROW]
    for name in (S_ROW, e["anchor_ref"]):
        one = pv.get_diff_patch_view(w.atlas, DIFF, entry_id=name)
        assert "error" not in one, one
        assert [x["entry_id"] for x in one["entries"]] == [S_ROW]
    (row,) = e["rows"]
    assert row["landing"] == "persisted"
    try:
        res = overlay.promote(
            w.atlas,
            diff_id=DIFF,
            entry_id=e["anchor_ref"],
            row_ref=row["a_ref"],
            verdict="inconclusive",
            rationale="the pair's change does not reach the call",
        )
    except ConfigError as exc:
        pytest.fail(f"the S entry's persisted row was refused: {exc}")
    assert res.promoted_from["anchor_ref"] == e["anchor_ref"]
    assert res.promoted_from["landing"] == "persisted"


def test_an_s_anchor_counts_as_checked_evidence(tmp_path: Path) -> None:
    """A no_real_change on another entry may cite an S entry's anchor in ``checked``: it resolves
    in the current view.

    MUTATION (verified RED, 1 failed): resolve checked anchors in ``built.entries`` -> refused ->
    RED."""
    w = _s_world(tmp_path)
    v = _view(w)
    target, cited = v["by_id"][S1], v["by_id"][S_ROW]
    try:
        res = w.judge(
            DIFF,
            target["anchor_ref"],
            "no_real_change",
            verdict_basis={"why_unchanged": "a renamed constant", "checked": [cited["anchor_ref"]]},
        )
    except ConfigError as exc:
        pytest.fail(f"the S anchor did not resolve: {exc}")
    assert res.action == "inserted"
    with pytest.raises(ConfigError, match="names nothing"):
        w.judge(
            DIFF,
            target["anchor_ref"],
            "no_real_change",
            verdict_basis={
                "why_unchanged": "x",
                "checked": [cited["anchor_ref"].replace("00006000", "00007000")],
            },
        )


def test_an_s_anchor_counts_as_checked_for_a_file_judgement(tmp_path: Path) -> None:
    """A no_real_change on a non-binary file of the pair, written through the diff's id, may cite
    an S entry's anchor in ``checked``: it resolves in that diff's current view.

    MUTATION (verified RED, 1 failed): resolve such an anchor in ``built.entries`` (is_diff_anchor
    with no precomputed lookups) -> refused as naming nothing -> RED."""
    from tests.unit.lib.test_file_diff import _add_files

    w = _s_world(tmp_path)
    _add_files(w)
    cited = _view(w)["by_id"][S1]["anchor_ref"]
    try:
        res = overlay.annotate_diff(
            w.atlas,
            anchor_ref="runA::runB#non_binary#etc/rc",
            verdict="no_real_change",
            rationale="r",
            verdict_basis={"why_unchanged": "a comment", "checked": [cited]},
            diff_id=DIFF,
        )
    except ConfigError as exc:
        pytest.fail(f"the S anchor did not resolve for a file judgement: {exc}")
    assert res.action == "inserted"


def test_the_differs_set_is_kept_per_staleness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The differs set a reader with no readings of its own takes from the cache is kept apart per
    the diff's source_stale: a pair whose text is the same and whose callee set differs reads
    differs (S) while the diff is current, and not once it is stale (its callee set is
    undetermined) — the stale reader is never served the current answer.

    MUTATION (verified RED, 1 failed): leave source_stale out of the differs cache key -> the
    stale read is served the current set -> RED."""
    stale = {"v": False}
    monkeypatch.setattr(
        pv,
        "diff_source_staleness",
        lambda atlas, diff_id: {
            "source_stale": stale["v"],
            "source_stale_reason": "diff_logic_changed" if stale["v"] else None,
            "toolchain_checked": True,
        },
    )
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.97, 1.0)
    w.fn("a", "00001000", ["foo"], pseudocode="x = foo(1);")
    w.fn("b", "00002000", ["bar"], pseudocode="x = foo(1);")
    w.pair("00003000", "00004000", 0.97, 1.0)
    w.fn("a", "00003000", ["foo"], pseudocode="x = foo(1);")
    w.fn("b", "00004000", ["foo"], pseudocode="x = foo(2);")
    w.commit()
    callees, text = _pair_id("00001000", "00002000"), _pair_id("00003000", "00004000")

    def s_ids() -> frozenset[str]:
        built = pv.build_diff_view(w.atlas, DIFF)
        assert built is not None
        return pv.listed_view(w.atlas, built).s_ids

    assert s_ids() == {callees, text}
    stale["v"] = True
    assert s_ids() == {text}


def test_a_rehunt_moves_pairs_between_s_and_b_and_every_pair_is_counted_once(
    tmp_path: Path,
) -> None:
    """★ In one process: a re-hunt that gives one similarity-1 pair a changed length constant (B)
    and takes it from another moves the first out of S and the second into it — the bucket test is
    read from each build, never cached — and every aligned pair stays counted exactly once, listed
    or not.

    MUTATION (verified RED, 1 failed): cache the S entry ids instead of the differs pairs -> the
    first view's S set is served after the re-hunt -> RED."""
    w = World(tmp_path)
    for a, b, n in (("00001000", "00002000", 1), ("00003000", "00004000", 3)):
        w.pair(a, b, 0.97, 1.0)
        w.fn("a", a, ["snprintf"], pseudocode=f"snprintf(d,0x{n}0,f);")
        w.fn("b", b, ["snprintf"], pseudocode=f"snprintf(d,0x{n}1,f);")
        w.im(a[:-2] + "10", b[:-2] + "10", a)
    w.pair("00005000", "00006000", 0.97, 1.0)  # identical, counted under not_listed throughout
    w.fn("a", "00005000", ["foo"], pseudocode="foo();")
    w.fn("b", "00006000", ["foo"], pseudocode="foo();")

    def sized(a: str, b: str) -> None:
        size_a = '{"size_kind": "cap_const", "size_flow": {"size_arg": "0x10"}}'
        size_b = '{"size_kind": "cap_const", "size_flow": {"size_arg": "0x11"}}'
        w.inst("a", _ref("runA", a, "copy", "0x10"), "copy", "snprintf", size_a)
        w.inst("b", _ref("runB", b, "copy", "0x10"), "copy", "snprintf", size_b)

    sized("00001000", "00002000")
    w.commit()

    def read() -> tuple[dict[str, str], int]:
        v = pv.get_diff_patch_view(w.atlas, DIFF, limit=200)
        not_listed = sum(c["count"] for c in v["not_listed"].values())
        return {e["entry_id"]: e["bucket"] for e in v["entries"]}, not_listed

    first, nl_first = read()
    x, y = _pair_id("00001000", "00002000"), _pair_id("00003000", "00004000")
    assert (first[x], first[y]) == ("B", "S")
    assert len(first) + nl_first == 3

    def s_by_cache() -> frozenset[str]:
        built = pv.build_diff_view(w.atlas, DIFF)
        assert built is not None
        return pv.listed_view(w.atlas, built).s_ids  # no readings: the differs cache

    assert s_by_cache() == {y}
    w.atlas.execute("DELETE FROM instance WHERE evidence_ref LIKE '%:00001000@%'")
    w.atlas.execute("DELETE FROM instance WHERE evidence_ref LIKE '%:00002000@%'")
    sized("00003000", "00004000")
    w.atlas.execute("UPDATE run SET updated_at = 'rehunt-1'")  # a hunt stamps the run row
    w.commit()
    assert s_by_cache() == {x}  # the cached differs pairs, the bucket test read anew
    second, nl_second = read()
    assert (second[x], second[y]) == ("S", "B")
    assert len(second) + nl_second == 3


def test_a_rerun_diff_lists_its_new_differs_pair_as_s(tmp_path: Path) -> None:
    """★ In one process: a diff re-run (a new created_at) that pairs a new aligned similarity-1
    pair whose text differs lists it as S — through the view's own readings and through the
    differs cache a judgement write reads alike.

    MUTATION (verified RED, 1 failed): drop created_at from the readings key -> the new pair is
    read from the old readings (no reading) and is not S -> RED."""
    w = _s_world(tmp_path)
    assert S1 in _view(w)["by_id"]
    built = pv.build_diff_view(w.atlas, DIFF)
    assert built is not None
    pv.listed_view(w.atlas, built)  # fills the differs cache too
    w.pair("00007000", "00008000", 0.97, 1.0)
    w.fn("a", "00007000", ["foo"], pseudocode="x = foo(7);")
    w.fn("b", "00008000", ["foo"], pseudocode="x = foo(8);")
    w.atlas.execute("UPDATE diff_meta SET created_at = '2099-01-01 00:00:00'")
    w.commit()
    new = _pair_id("00007000", "00008000")
    assert (_view(w)["by_id"].get(new) or {}).get("bucket") == "S"
    rebuilt = pv.build_diff_view(w.atlas, DIFF)
    assert rebuilt is not None
    assert new in pv.listed_view(w.atlas, rebuilt).s_ids


def test_a_view_with_its_own_readings_never_reads_the_differs_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """get_diff_patch_view (and function_states) decide S from the readings they hold — one reading
    per view — and never look the differs set up in the cache (nor write it); a reader without
    readings does.

    MUTATION (verified RED, 1 failed each): let ``listed_view`` consult the cache when readings
    are given -> RED; let it write the cache from them -> RED."""
    w = _s_world(tmp_path)

    class _NoGet(pv._BoundedCache[tuple[str, ...], frozenset[tuple[str, str]]]):
        def get(self, key: tuple[str, ...]) -> frozenset[tuple[str, str]] | None:
            raise AssertionError("the differs cache was read")

        def __setitem__(self, key: tuple[str, ...], value: frozenset[tuple[str, str]]) -> None:
            raise AssertionError("the differs cache was written")

    monkeypatch.setattr(pv, "_DIFFERS_CACHE", _NoGet(8))
    assert S1 in _view(w)["by_id"]
    states = pv.function_states(w.atlas, DIFF)
    assert states is not None and states["changed"]["listed_as_s"] == 2
    built = pv.build_diff_view(w.atlas, DIFF)
    assert built is not None
    with pytest.raises(AssertionError, match="differs cache was read"):
        pv.listed_view(w.atlas, built)


def test_every_reader_of_the_view_lists_s_the_same_way(tmp_path: Path) -> None:
    """The cheap readers — ViewReview (list_overlays' progress), capture_diff_basis, the checked-
    anchor rule, promote's entry lookup — all see the S entries get_diff_patch_view lists.

    MUTATION (verified RED, 1 failed): read ``built.entries`` in capture_diff_basis_on -> a
    judgement on S is refused -> RED."""
    w = _s_world(tmp_path)
    anchor = _view(w)["by_id"][S1]["anchor_ref"]
    meta = dann._binary_diff(w.atlas, DIFF)
    built = pv.build_diff_view(w.atlas, DIFF)
    assert built is not None
    try:
        snap = dann.capture_diff_basis_on(w.atlas, built, meta, DIFF, anchor)
    except ConfigError as exc:
        pytest.fail(f"a judgement on the S entry was refused: {exc}")
    assert snap["facts"]["bucket"] is None
    review = pv.ViewReview(w.atlas, pv.build_diff_view(w.atlas, DIFF))  # type: ignore[arg-type]
    assert {i.bucket for i in review.items.values()} == {"S"}
    progress = overlay.list_overlays(w.atlas, anchor_kind="diff_subject", run_id="runA::runB")[
        "review_progress"
    ]
    assert progress["total"] == 2 and progress["complete"] is False


# ── the first counts ───────────────────────────────────────────────────────────────────────────


def test_the_first_counts_name_swaps_count_deltas_and_s(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """function_states' ``changed`` counts the pairs carrying a sink swap (by pairing and side), a
    count delta (by pairing) or an unknown count, and the S entries — beside the counts it had.

    MUTATION (verified RED, 1 failed each): count a proposed swap as aligned -> RED; leave the
    unknown counts out -> RED."""
    w = _counts_world(tmp_path, monkeypatch)
    w.fn("a", "00011000", ["memcpy"])
    w.fn("b", "00012000", ["strcpy"])
    w.pair("00011000", "00012000", 0.5, 0.4)
    w.commit()
    s = pv.function_states(w.atlas, DIFF)
    assert s is not None
    changed = s["changed"]
    assert changed["with_sink_callee_swap"] == {
        "aligned": {"a_only": 0, "b_only": 0, "both": 0},
        "proposed": {"a_only": 0, "b_only": 0, "both": 1},
    }
    # aligned: delta (3 / 1), elsewhere (0 / 2), other (1 / 0); proposed: 2 / 1
    assert changed["with_sink_candidate_counts_delta"] == {"aligned": 3, "proposed": 1}
    assert changed["with_sink_candidate_counts_unknown"] == 3
    assert changed["listed_as_s"] == 0
    assert {"total", "with_scoped_sink_delta", "no_scoped_signal"} <= set(changed)


# ── the recomputed overlay, kept while the baseline is not current ────────────────────────────


def test_a_recomputed_overlay_is_computed_once_per_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ With no current baseline the overlay is computed in memory: paging computes it once, not
    once per page; and any of what it rests on moving — when the diff was written, a side's
    call-site facts, a re-hunt (the run's stamp or its instance rows) — computes it again.

    MUTATION (verified RED, 1 failed each): drop created_at from the key -> RED; drop
    callsite_facts_hash_a -> RED; drop hunt_inputs_hash_b -> RED; drop the diff code version ->
    RED; drop the instance stamp -> RED; drop the cache -> RED."""
    w = _s_world(tmp_path)
    calls: list[str] = []
    real = pv.compute_sink_overlay

    def counted(atlas: sqlite3.Connection, diff_id: str) -> Any:
        calls.append(diff_id)
        return real(atlas, diff_id)

    monkeypatch.setattr(pv, "compute_sink_overlay", counted)
    first = pv.get_diff_patch_view(w.atlas, DIFF, limit=1)
    assert first["baseline_state"] == "recomputed_absent"
    pv.get_diff_patch_view(w.atlas, DIFF, limit=1, offset=1)
    pv.get_diff_patch_view(w.atlas, DIFF, sort_by="candidate_tier", rows_limit=0)
    assert len(calls) == 1
    for change in (
        "UPDATE diff_meta SET created_at = '2099-01-01 00:00:00'",
        "UPDATE diff_meta SET callsite_facts_hash_a = 'moved'",
        "UPDATE diff_meta SET callsite_facts_hash_b = 'moved'",
        "UPDATE diff_meta SET hunt_inputs_hash_a = 'moved'",
        "UPDATE diff_meta SET hunt_inputs_hash_b = 'moved'",
        "UPDATE run SET updated_at = 'rehunt-1' WHERE run_id = 'runB'",
    ):
        before = len(calls)
        w.atlas.execute(change)
        w.commit()
        pv.get_diff_patch_view(w.atlas, DIFF, limit=1)
        pv.get_diff_patch_view(w.atlas, DIFF, limit=1)
        assert len(calls) == before + 1, change
    before = len(calls)
    w.inst("b", _cmd("b", "00002000", "0x40"), "cmd", "system")
    w.commit()
    pv.get_diff_patch_view(w.atlas, DIFF, limit=1)
    assert len(calls) == before + 1
    before = len(calls)
    monkeypatch.setattr(pv, "diff_code_version", lambda: "src-newer")  # newer diff code
    pv.get_diff_patch_view(w.atlas, DIFF, limit=1)
    assert len(calls) == before + 1
