# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Pair evidence on the R entries whose pair BinDiff proposed below the alignment threshold
(lib/query/patch_view): ``pair_evidence`` (supported / negated / none, from the callers and the
anchors) and ``counterpart_hint`` (what a unique string, a dispatch key or an import name points
to). A supported pairing that carries a lift_basis floats to attention 0; nothing else moves, R
stays R and nothing is re-paired.

Zero real data: the world is test_patch_view's (one diff of ``libx``, each run with its own
analysis.db); every address, name and string is synthetic.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from tests.unit.lib.test_diff_read_signals import _rows
from tests.unit.lib.test_patch_view import _WORDS, DIFF, World, _overlay_row, _pair_id, _ref, _view
from treasure_map import mcp_app, mcp_cards
from treasure_map.lib.query import diff_review as dr
from treasure_map.lib.query import patch_view as pv
from treasure_map.version import UNKNOWN_VERSION


def _staleness(stale: bool | None) -> Any:
    return lambda atlas, diff_id: {
        "source_stale": stale,
        "source_stale_reason": None if stale is False else "test",
        "toolchain_checked": True,
    }


@pytest.fixture(autouse=True)
def _fresh(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every world reuses one diff id: drop the process-wide caches, and read the diff as current
    unless a test says otherwise."""
    monkeypatch.setattr(mcp_app, "_installed_commit", lambda: UNKNOWN_VERSION)
    monkeypatch.setattr(pv, "diff_source_staleness", _staleness(False))
    pv._clear_view_caches()


# ── the world ────────────────────────────────────────────────────────────────────────────────


def _string(w: World, side: str, value: str, func: str | None, *, truncated: int = 0) -> None:
    """One reference to ``value`` from inside ``func`` (None: from no function)."""
    w.adb[side].execute(
        "INSERT INTO string_refs (binary_id, string_addr, string_value, ref_at, ref_in_func, "
        "ref_in_func_addr, truncated) VALUES (1, '0x00090000', ?, '0x00000010', NULL, ?, ?)",
        (value, f"0x{func}" if func else None, truncated),
    )


def _key(w: World, side: str, key: str, func: str) -> None:
    """One dispatch-table entry: ``key`` selects the handler at ``func``."""
    w.adb[side].execute(
        "INSERT INTO string_tables (binary_id, table_addr, stride, entry_index, key, func_name, "
        "func_addr, func_kind) VALUES (1, '0x00080000', 8, 0, ?, NULL, ?, 'direct')",
        (key, f"0x{func}"),
    )


def _thunks(w: World, side: str, *addrs: str) -> None:
    spans = [[f"0x{a}", [[f"0x{a}", f"0x{a}"]]] for a in addrs]
    w.adb[side].execute("UPDATE binaries SET thunk_spans = ? WHERE id = 1", (json.dumps(spans),))


def _swap(w: World, a: str, b: str, sim: float = 0.4, **names: str) -> None:
    """An undetermined pair whose callee lists differ by a sink: a proposed sink_callee_swap, so
    its lift_basis is ``sink_callee_swap``."""
    w.pair(a, b, 0.5, sim, **names)
    w.fn("a", a, ["system"], name=names.get("name_a"))
    w.fn("b", b, ["memcpy"], name=names.get("name_b"))


def _caller(w: World, a: str, b: str, ca: str, cb: str, *, calls_b: bool) -> None:
    """``ca`` calls a on A; its aligned counterpart ``cb`` calls b (``calls_b``) or another name."""
    w.pair(ca, cb, 0.97, 0.9)
    w.fn("a", ca, [f"FUN_{a}"])
    w.fn("b", cb, [f"FUN_{b}"] if calls_b else ["log_line"])


SUP_CALLER = ("00001000", "00002000")  # caller corroborated -> supported, floated
NEG = ("00003000", "00004000")  # caller refuted, a string consistent -> negated
CONFLICT = ("00005000", "00006000")  # caller corroborated, a string conflicts -> none
BARE = ("00008000", "00009000")  # the same real symbol name, nothing else -> none
MIXED = ("0000a000", "0000b000")  # one string consistent, one conflicting -> none
SUP_STRING = ("0000d000", "0000e000")  # a string consistent, no caller -> supported, floated
FORMAT = ("0000f000", "00010000")  # only a format-only, a spoiled and a cut string -> none
SUP_KEY = ("00017000", "00018000")  # a dispatch key consistent -> supported, floated
ALIGNED = ("00020000", "00021000")  # an aligned swap at similarity 0.3: attention 0
OTHER_B = "00007000"  # a B function no pair holds (the conflicting string's owner)
OTHER_MIX = "0000c000"


def _evidence_world(tmp_path: Path) -> World:
    w = World(tmp_path)
    _swap(w, *SUP_CALLER)
    _caller(w, *SUP_CALLER, "00011000", "00012000", calls_b=True)
    _swap(w, *NEG)
    _caller(w, *NEG, "00013000", "00014000", calls_b=False)
    _string(w, "a", "neg pairing text", NEG[0])
    _string(w, "b", "neg pairing text", NEG[1])
    _swap(w, *CONFLICT)
    _caller(w, *CONFLICT, "00015000", "00016000", calls_b=True)
    _string(w, "a", "conflict text", CONFLICT[0])
    _string(w, "b", "conflict text", OTHER_B)
    w.fn("b", OTHER_B, [])
    _swap(w, *BARE, name_a="do_work", name_b="do_work")
    _swap(w, *MIXED)
    _string(w, "a", "mixed one", MIXED[0])
    _string(w, "b", "mixed one", MIXED[1])
    _string(w, "a", "mixed two", MIXED[0])
    _string(w, "b", "mixed two", OTHER_MIX)
    w.fn("b", OTHER_MIX, [])
    _swap(w, *SUP_STRING)
    _string(w, "a", "string pairing text", SUP_STRING[0])
    _string(w, "b", "string pairing text", SUP_STRING[1])
    _swap(w, *FORMAT)
    for side, f in (("a", FORMAT[0]), ("b", FORMAT[1])):
        _string(w, side, "%s:%d", f)  # format-only: says nothing of its function
        _string(w, side, "spoiled text", f)
        _string(w, side, "cut text", f, truncated=1 if side == "b" else 0)
    _string(w, "b", "spoiled text", None)  # also referenced from no function on B
    _swap(w, *SUP_KEY)
    _key(w, "a", "do_reboot", SUP_KEY[0])
    _key(w, "b", "do_reboot", SUP_KEY[1])
    w.pair(*ALIGNED, 0.97, 0.3)
    w.fn("a", ALIGNED[0], ["system"])
    w.fn("b", ALIGNED[1], ["memcpy"])
    w.commit()
    return w


def _e(v: dict[str, Any], pair: tuple[str, str]) -> dict[str, Any]:
    entry_id = _pair_id(*pair)
    assert entry_id in v["by_id"], entry_id
    return dict(v["by_id"][entry_id])


# ── the three states ─────────────────────────────────────────────────────────────────────────


def test_the_callers_and_anchors_give_three_states(tmp_path: Path) -> None:
    """A corroborating caller, a consistent string or a consistent dispatch key supports the
    pairing; a refuting caller negates it; a bare same-name pairing, a conflict and a mix support
    nothing. Every undetermined R pair carries pair_evidence; no other entry does.

    MUTATION (verified RED, 1 failed): read no dispatch key -> SUP_KEY none -> RED."""
    w = _evidence_world(tmp_path)
    v = _view(w, sort_by="significance")
    want = {
        SUP_CALLER: ("supported", "corroborated", None),
        NEG: ("negated", "refuted", "consistent"),
        CONFLICT: ("none", "corroborated", "conflict"),
        BARE: ("none", "none", None),
        MIXED: ("none", "none", "mixed"),
        SUP_STRING: ("supported", "none", "consistent"),
        FORMAT: ("none", "none", None),
        SUP_KEY: ("supported", "none", "consistent"),
    }
    for pair, (state, caller, hint) in want.items():
        e = _e(v, pair)
        assert e["bucket"] == "R", pair
        pe = e.get("pair_evidence")
        assert pe is not None, pair
        assert (pe["state"], pe["caller_anchor"]["state"]) == (state, caller), (pair, pe)
        assert (e.get("counterpart_hint") or {}).get("state") == hint, (pair, e)
    for entry_id, e in v["by_id"].items():
        if e.get("alignment_state") != "alignment_undetermined":
            assert "pair_evidence" not in e and "counterpart_hint" not in e, entry_id
    assert _e(v, BARE)["pair_evidence"]["caller_anchor"]["reason"] == "no_caller_a"


def test_a_refuting_caller_wins_over_a_consistent_anchor(tmp_path: Path) -> None:
    """★ Negated first: a pairing whose callers' counterparts all skip b (every list read in full)
    is negated even when a unique string agrees with it.

    MUTATION (verified RED, 1 failed): judge a consistent anchor before the refuting caller ->
    NEG reads supported -> RED."""
    v = _view(_evidence_world(tmp_path), sort_by="significance")
    e = _e(v, NEG)
    assert e["pair_evidence"]["state"] == "negated"
    assert e["pair_evidence"]["caller_anchor"] == {
        "state": "refuted",
        "callers_a": 1,
        "callers_b_aligned": 1,
    }
    assert e["counterpart_hint"]["state"] == "consistent"
    assert e["significance"]["attention"] == 1 and e["lift_basis"] == "sink_callee_swap"


def test_a_conflicting_anchor_overrides_a_corroborating_caller(tmp_path: Path) -> None:
    """★ A unique string that points b's way to another function keeps a caller-corroborated
    pairing off ``supported``, and the hint names that function with its direction, anchor,
    evidence and own pairing state.

    MUTATION (verified RED, 1 failed): let a corroborating caller decide before the conflict ->
    CONFLICT reads supported (and floats) -> RED."""
    v = _view(_evidence_world(tmp_path), sort_by="significance")
    e = _e(v, CONFLICT)
    assert e["pair_evidence"]["state"] == "none"
    assert e["pair_evidence"]["caller_anchor"]["state"] == "corroborated"
    assert e["counterpart_hint"] == {
        "state": "conflict",
        "anchors": ["string"],
        "hints": [
            {
                "direction": "to_b",
                "addr": OTHER_B,
                "pairing_state": "unpaired",
                "anchor": "string",
                "evidence": ["conflict text"],
                "evidence_count": 1,
            }
        ],
    }
    assert _e(v, MIXED)["counterpart_hint"]["hints"][0]["addr"] == OTHER_MIX


def test_a_conflict_keeps_the_lift_basis_and_the_must_read(tmp_path: Path) -> None:
    """★ A counterpart_hint conflict (or mix) only keeps a pairing from floating: the entry keeps
    its lift_basis, leads attention 1 (rank_key.sink_callee_swap 1) and so stays in what must be
    read — it is never stripped of the swap lift.

    MUTATION (verified RED, 1 failed): fold the conflict into ``_lift_basis`` (return None, as
    pairing_name_conflict does) -> RED; MUTATION (verified RED, 1 failed): clear the lift_basis
    of an entry with a counterpart_hint -> RED."""
    v = _view(_evidence_world(tmp_path), sort_by="significance")
    for pair in (CONFLICT, MIXED, NEG, BARE, FORMAT):
        e = _e(v, pair)
        assert e["significance"]["attention"] == 1, pair
        assert e["lift_basis"] == "sink_callee_swap", pair
        assert e["rank_key"]["sink_callee_swap"] == 1, pair


def test_the_string_anchor_reads_only_unique_function_strings(tmp_path: Path) -> None:
    """A format-only string, a string also referenced from no function, and a string whose
    reference list was cut tie no function to another: FORMAT reads no hint and no support.

    MUTATION (verified RED, 1 failed): drop the format-only filter -> FORMAT supported -> RED;
    MUTATION (verified RED, 1 failed): keep a value referenced from no function -> RED;
    MUTATION (verified RED, 1 failed): keep a value whose list was cut -> RED."""
    v = _view(_evidence_world(tmp_path), sort_by="significance")
    e = _e(v, FORMAT)
    assert e["pair_evidence"]["state"] == "none"
    assert "counterpart_hint" not in e
    assert pv._format_only("%s:%d") and pv._format_only("%02x")
    assert not pv._format_only("at+cmd=%s")


def test_the_dispatch_key_anchor_reads_one_handler_on_each_side(tmp_path: Path) -> None:
    """A key with exactly one handler on each side ties those handlers; a key with two handlers on
    a side ties nothing.

    MUTATION (verified RED, 1 failed): read the key table's handlers as a set of any size (take
    the first) -> the two-handler key reads consistent -> RED."""
    w = _evidence_world(tmp_path)
    _key(w, "b", "do_reboot", OTHER_B)  # the key now has two handlers on B
    w.commit()
    v = _view(w, sort_by="significance")
    e = _e(v, SUP_KEY)
    assert e["pair_evidence"]["state"] == "none"
    assert "counterpart_hint" not in e


# ── the float, and its limits ────────────────────────────────────────────────────────────────


def test_a_supported_pairing_with_a_lift_basis_floats_after_the_aligned_pairs(
    tmp_path: Path,
) -> None:
    """★ Floated: a supported pairing carrying a lift_basis reads attention 0 under basis
    supported_pair_swap, keeps lift_basis sink_callee_swap and is given no swap_lift
    (rank_key.sink_callee_swap 0) — so it does not read ahead of an aligned attention-0 pair of
    lower similarity. A bare same-name pairing is never floated.

    MUTATION (verified RED, 1 failed): give a floated entry swap_lift 1 -> it reads before the
    aligned pair -> RED; MUTATION (verified RED, 1 failed): float a bare same-name (``_anchor``
    name) pairing too -> RED; MUTATION (verified RED, 1 failed): drop the float -> RED."""
    v = _view(_evidence_world(tmp_path), sort_by="significance")
    for pair in (SUP_CALLER, SUP_STRING, SUP_KEY):
        e = _e(v, pair)
        assert e["significance"] == {"attention": 0, "basis": "supported_pair_swap"}, pair
        assert e["lift_basis"] == "sink_callee_swap", pair
        assert e["rank_key"]["sink_callee_swap"] == 0, pair
        assert e["bucket"] == "R" and e["alignment_state"] == "alignment_undetermined"
    aligned = _e(v, ALIGNED)
    assert aligned["significance"] == {"attention": 0, "basis": "sink_callee_swap"}
    assert aligned["lift_basis"] is None
    order = [e["entry_id"] for e in v["entries"]]
    assert order.index(_pair_id(*ALIGNED)) < order.index(_pair_id(*SUP_CALLER))
    assert {e["entry_id"] for e in v["entries"][:4]} == {
        _pair_id(*p) for p in (ALIGNED, SUP_CALLER, SUP_STRING, SUP_KEY)
    }
    assert _e(v, BARE)["significance"]["attention"] == 1


def test_a_supported_pairing_reads_after_every_attention_0_read_signal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ Inside attention 0 the read signals come first and an R entry its pair evidence floated
    follows them — whatever its similarity (0.09 here, against an aligned signal's 0.97) and its
    read-first order (the floated entry's proposed reading orders 2 here; the aligned one has
    none). Nothing else moves: attentions, bases and lift_basis are as before.

    MUTATION (verified RED): drop supported_last from the key -> the 0.09 entry reads first ->
    RED; put it after -read_first -> the read-first order lifts it ahead -> RED."""
    w = World(tmp_path)
    sup, real = ("00001000", "00002000"), ("00020000", "00021000")
    _swap(w, *sup, sim=0.09)
    _caller(w, *sup, "00011000", "00012000", calls_b=True)
    w.pair(*real, 0.97, 0.97)
    w.fn("a", real[0], ["system"])
    w.fn("b", real[1], ["memcpy"])
    w.commit()
    monkeypatch.setattr(pv, "_read_first_order", lambda e, state: 2)
    v = _view(w, sort_by="significance")
    floated, signal = _e(v, sup), _e(v, real)
    assert floated["significance"] == {"attention": 0, "basis": "supported_pair_swap"}
    assert floated["lift_basis"] == "sink_callee_swap"
    assert signal["significance"] == {"attention": 0, "basis": "sink_callee_swap"}
    order = [e["entry_id"] for e in v["entries"]]
    assert order.index(_pair_id(*real)) < order.index(_pair_id(*sup))


def _entry(pair_evidence: dict[str, Any] | None, **kw: Any) -> pv._Entry:
    p = pv._Pair("00001000", "00002000", "f", "f", 0.5, 0.4, "alignment_undetermined", None, None)
    return pv._Entry(pair=p, unpaired=None, bucket="R", pair_evidence=pair_evidence, **kw)


def test_a_supported_count_delta_floats_under_its_own_basis() -> None:
    """A supported pairing whose lift_basis is a sink candidate count delta floats under
    supported_pair_counts; the same pairing unsupported, or with no delta, stays at 1.

    MUTATION (verified RED, 1 failed): map both lift bases to supported_pair_swap -> RED."""
    counts = {"pairing": "proposed", "delta": {"system": {"a": 2, "b": 1}}, "unknown": []}
    sup = {"state": "supported"}
    assert pv.significance(_entry(sup, sink_candidate_counts=counts), None, None) == (
        0,
        "supported_pair_counts",
    )
    for evidence in ({"state": "none"}, {"state": "negated"}, None):
        assert pv.significance(_entry(evidence, sink_candidate_counts=counts), None, None)[0] == 1
    assert pv.significance(_entry(sup), None, None)[0] == 1  # no lift_basis: nothing to float
    named = _entry(
        sup, sink_candidate_counts=counts, pairing_name_conflict={"name_a": "f", "name_b": "g"}
    )
    assert pv.significance(named, None, None)[0] == 1  # pairing_name_conflict: no lift_basis


def test_a_stale_or_unreadable_source_gives_none_and_no_hint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ A diff whose sources are not shown current (source_stale True, or unknown None), or whose
    analysis.db cannot be read, reads every undetermined pairing ``none`` with that reason and no
    counterpart_hint — the pair's addresses are the diff's, a re-extracted analysis.db may hold
    another function there. The entry stays at attention 1 with its lift_basis unchanged.

    The pairing is a count delta (the counts do not read the callee lists, so its lift_basis
    survives a stale source) whose unique string is consistent: current, it floats.

    MUTATION (verified RED, 1 failed): ignore the build's callee_block -> the stale diff floats
    the pairing and gives a hint -> RED."""
    w = World(tmp_path)
    a, b = "00001000", "00002000"
    w.pair(a, b, 0.5, 0.4)
    w.fn("a", a, ["system"])
    w.fn("b", b, ["system"])
    _string(w, "a", "count pairing text", a)
    _string(w, "b", "count pairing text", b)
    rows = []
    for side, f, at in (("a", a, "0x10"), ("a", a, "0x14"), ("b", b, "0x10")):
        ref = _ref("runA" if side == "a" else "runB", f, "cmd", at)
        w.inst(side, ref, "cmd", "system")
        rows.append(
            _overlay_row(ref, None, "callsite", "cmd")
            if side == "a"
            else _overlay_row(None, ref, "callsite", "cmd")
        )
    w.commit()
    _rows(monkeypatch, rows)
    e = _e(_view(w, sort_by="significance"), (a, b))
    assert e["significance"] == {"attention": 0, "basis": "supported_pair_counts"}
    for stale in (True, None):
        monkeypatch.setattr(pv, "diff_source_staleness", _staleness(stale))
        pv._clear_view_caches()
        e = _e(_view(w, sort_by="significance"), (a, b))
        assert e["pair_evidence"] == {"state": "none", "reason": "source_stale"}, stale
        assert "counterpart_hint" not in e, stale
        assert e["significance"]["attention"] == 1, stale
        assert (e["lift_basis"], e["rank_key"]["sink_callee_swap"]) == ("sink_candidate_counts", 1)
    monkeypatch.setattr(pv, "diff_source_staleness", _staleness(False))
    w.atlas.execute(
        "UPDATE run SET analysis_db_path = ? WHERE run_id = 'runB'", (str(tmp_path / "gone.db"),)
    )
    w.commit()
    pv._clear_view_caches()
    e = _e(_view(w, sort_by="significance"), (a, b))
    assert e["pair_evidence"] == {"state": "none", "reason": "analysis_db_unavailable"}
    assert "counterpart_hint" not in e and e["significance"]["attention"] == 1


# ── thunks ───────────────────────────────────────────────────────────────────────────────────

T_SAME = ("00030000", "00031000")  # two thunks, one import name
T_DIFF = ("00032000", "00033000")  # two thunks, memcpy vs memset: B pairs a memcpy thunk elsewhere
T_DIFF2 = ("00034000", "00035000")  # two thunks, free vs memcpy: A pairs a memcpy thunk elsewhere
T_NOHINT = ("00036000", "00037000")  # two thunks, read vs write: neither name elsewhere
T_ONE_SAME = ("00038000", "00039000")  # a real open vs a thunk open; B holds a real open too
B_REAL_OPEN = "0003a000"
T_ONE_OTHER = ("00040000", "00041000")  # a real close vs a thunk close; no real close on B
T_A_THUNK = ("00044000", "00045000")  # a thunk fork vs a real function


def _thunk_world(tmp_path: Path) -> World:
    w = World(tmp_path)
    for (a, b), (na, nb) in (
        (T_SAME, ("strcpy", "strcpy")),
        (T_DIFF, ("memcpy", "memset")),
        (T_DIFF2, ("free", "memcpy")),
        (T_NOHINT, ("read", "write")),
        (T_A_THUNK, ("fork", "spawn_child")),
    ):
        w.pair(a, b, 0.5, 0.4, name_a=na, name_b=nb)
    w.fn("b", T_A_THUNK[1], ["system"], name="spawn_child")
    for (a, b), name in ((T_ONE_SAME, "open"), (T_ONE_OTHER, "close")):
        w.pair(a, b, 0.5, 0.4, name_a=name, name_b=name)
        w.fn("a", a, ["system"], name=name)
    w.fn("b", B_REAL_OPEN, [], name="open")
    # close's caller on A, whose aligned counterpart on B calls the import close: the callee lists
    # hold names only, so this cannot tell the import from a function named close.
    w.pair("00042000", "00043000", 0.97, 0.9)
    w.fn("a", "00042000", ["close"])
    w.fn("b", "00043000", ["close"])
    _thunks(w, "a", T_SAME[0], T_DIFF[0], T_DIFF2[0], T_NOHINT[0], T_A_THUNK[0])
    _thunks(w, "b", T_SAME[1], T_DIFF[1], T_DIFF2[1], T_NOHINT[1], T_ONE_SAME[1], T_ONE_OTHER[1])
    w.commit()
    return w


def test_thunk_pairings_read_their_import_names(tmp_path: Path) -> None:
    """★ Two thunks of one import name: ``same_import_name``, no hint, none (never supported).
    Two of different names: a conflict pointing at the other side's paired thunk of that name, or
    with no such thunk a conflict with reason ``import_names_differ`` and no hint. A real function
    paired to a thunk whose side holds a real function of the thunk's name: a conflict pointing at
    it, with its own pairing state; with none there: ``other_side_thunk``, no hint. A thunk on
    either side reads its caller anchor ``none``. Every one stays listed and in the review's
    count.

    MUTATION (verified RED, 1 failed): read same_import_name as a consistent anchor -> T_SAME
    supported -> RED; MUTATION (verified RED, 1 failed): give a different-name pair with no
    other-side thunk no conflict -> RED; MUTATION (verified RED, 1 failed): leave the one-sided
    pairing with a real same-name function on the thunk side without a conflict -> RED;
    MUTATION (verified RED, 1 failed): drop the thunk pairings from the listed entries -> RED."""
    v = _view(_thunk_world(tmp_path), sort_by="significance")

    def ev(pair: tuple[str, str]) -> tuple[dict[str, Any], dict[str, Any] | None]:
        e = _e(v, pair)
        assert e["bucket"] == "R", pair
        return e["pair_evidence"], e.get("counterpart_hint")

    pe, hint = ev(T_SAME)
    assert pe["state"] == "none" and hint is None
    assert pe["thunk"] == {"sides": ["a", "b"], "fact": "same_import_name"}
    assert pe["caller_anchor"] == {"state": "none", "reason": "b_is_thunk"}
    pe, hint = ev(T_DIFF)
    assert pe["state"] == "none" and pe["thunk"]["fact"] == "import_names_differ"
    assert hint is not None and hint["state"] == "conflict"
    assert [
        (h["direction"], h["addr"], h["anchor"], h["pairing_state"]) for h in hint["hints"]
    ] == [("to_b", T_DIFF2[1], "import_name", "proposed")]
    _pe, hint = ev(T_DIFF2)
    assert hint is not None
    assert [(h["direction"], h["addr"]) for h in hint["hints"]] == [("to_a", T_DIFF[0])]
    pe, hint = ev(T_NOHINT)
    assert pe["state"] == "none"
    assert hint == {"state": "conflict", "anchors": [], "reason": "import_names_differ"}
    pe, hint = ev(T_ONE_SAME)
    assert pe["thunk"] == {"sides": ["b"], "fact": "same_name_function_on_thunk_side"}
    assert hint is not None and hint["state"] == "conflict"
    assert [
        (h["direction"], h["addr"], h["anchor"], h["pairing_state"]) for h in hint["hints"]
    ] == [("to_b", B_REAL_OPEN, "same_name_function", "unpaired")]
    pe, hint = ev(T_ONE_OTHER)
    assert pe["thunk"] == {"sides": ["b"], "fact": "other_side_thunk"} and hint is None
    pe, hint = ev(T_A_THUNK)
    assert pe["caller_anchor"] == {"state": "none", "reason": "a_is_thunk"}
    assert pe["thunk"] == {"sides": ["a"], "fact": "other_side_thunk"} and hint is None
    thunk_ids = {
        _pair_id(*p)
        for p in (T_SAME, T_DIFF, T_DIFF2, T_NOHINT, T_ONE_SAME, T_ONE_OTHER, T_A_THUNK)
    }
    assert thunk_ids <= set(v["by_id"])
    progress = v["review_progress"]
    assert progress["total"] == len(v["by_id"]) and progress["not_looked_at"] == progress["total"]
    for entry_id in thunk_ids:
        assert v["by_id"][entry_id]["significance"]["attention"] == 1, entry_id


def test_a_thunk_b_is_never_read_through_its_import_name(tmp_path: Path) -> None:
    """★ A thunk b reads its caller anchor ``none`` (b_is_thunk), never through BinDiff's name for
    it: a callee list holds names, so a call to the import close cannot be told from a call to a
    function named close. Read that way, T_ONE_OTHER (close's A caller's counterpart calls close)
    would be corroborated and supported.

    MUTATION (verified RED, 1 failed): read a thunk b's callers by its BinDiff name (``name_b``)
    instead of returning b_is_thunk -> T_ONE_OTHER supported -> RED."""
    v = _view(_thunk_world(tmp_path), sort_by="significance")
    e = _e(v, T_ONE_OTHER)
    assert e["pair_evidence"]["state"] == "none"
    assert e["pair_evidence"]["caller_anchor"] == {"state": "none", "reason": "b_is_thunk"}


# ── the counts, the build, the words ─────────────────────────────────────────────────────────


def test_the_first_counts_name_the_floated_and_the_conflicting(tmp_path: Path) -> None:
    """function_states' ``changed`` counts the R entries floated by a supported pairing and those
    whose counterpart_hint conflicts (a mix is not a conflict), over the whole diff.

    MUTATION (verified RED, 1 failed): count every hinted entry as a conflict -> RED."""
    w = _evidence_world(tmp_path)
    s = pv.function_states(w.atlas, DIFF)
    assert s is not None
    assert s["changed"]["with_supported_r_lift"] == 3
    assert s["changed"]["with_counterpart_conflict"] == 1


def test_the_evidence_is_read_in_the_view_never_in_the_build_or_a_judgement(
    tmp_path: Path,
) -> None:
    """The build leaves pair_evidence unset (annotate / promote never pay for it), and a
    judgement's basis (diff_review.entry_facts) is the same with it attached.

    MUTATION (verified RED, 1 failed): attach the evidence in build_diff_view -> RED."""
    w = _evidence_world(tmp_path)
    built = pv.build_diff_view(w.atlas, DIFF)
    assert built is not None
    by_id = {e.entry_id: e for e in built.entries}
    e = by_id[_pair_id(*CONFLICT)]
    assert e.pair_evidence is None and e.counterpart_hint is None
    before = json.dumps(dr.entry_facts(e), sort_keys=True)
    pv._attach_pair_evidence(w.atlas, built)
    assert e.pair_evidence is not None and e.counterpart_hint is not None
    assert json.dumps(dr.entry_facts(e), sort_keys=True) == before


def test_a_re_extraction_is_not_served_stale_anchors(tmp_path: Path) -> None:
    """The anchors are cached per run with the run's stamps in the key: a re-extracted run (its
    build hash moved) is read again.

    MUTATION (verified RED, 1 failed): key the anchor cache by run id and content hash only ->
    RED."""
    w = _evidence_world(tmp_path)
    assert _e(_view(w, sort_by="significance"), SUP_STRING)["pair_evidence"]["state"] == (
        "supported"
    )
    w.adb["b"].execute("DELETE FROM string_refs WHERE string_value = 'string pairing text'")
    w.atlas.execute("UPDATE run SET updated_at = '2099-01-01' WHERE run_id = 'runB'")
    w.commit()
    e = _e(_view(w, sort_by="significance"), SUP_STRING)
    assert e["pair_evidence"]["state"] == "none" and "counterpart_hint" not in e


def test_a_summary_entry_carries_the_evidence_as_states(tmp_path: Path) -> None:
    """A summary entry gives pair_evidence's state, its caller anchor's state and thunk fact, and
    counterpart_hint's state, hint count and reason — no address, no string.

    MUTATION (verified RED, 5 failed — with the four summary projection worlds): leave
    pair_evidence out of the summary -> RED."""
    w = _thunk_world(tmp_path)
    page = pv.get_diff_patch_view(w.atlas, DIFF, detail="summary", limit=200)
    by_id = {e["entry_id"]: e for e in page["entries"]}
    assert _pair_id(*T_ONE_SAME) in by_id and _pair_id(*T_NOHINT) in by_id
    assert by_id[_pair_id(*T_ONE_SAME)].get("pair_evidence") == {
        "state": "none",
        "caller_anchor": "none",
        "thunk": "same_name_function_on_thunk_side",
    }
    assert by_id[_pair_id(*T_ONE_SAME)].get("counterpart_hint") == {"state": "conflict", "hints": 1}
    assert by_id[_pair_id(*T_NOHINT)].get("counterpart_hint") == {
        "state": "conflict",
        "hints": 0,
        "reason": "import_names_differ",
    }


def _labels(value: Any, out: set[str]) -> None:
    """Every key, and every string value but the evidence and the addresses, at any depth."""
    if isinstance(value, dict):
        for k, v in value.items():
            out.add(str(k))
            if k not in ("evidence", "addr"):
                _labels(v, out)
    elif isinstance(value, list):
        for v in value:
            _labels(v, out)
    elif isinstance(value, str):
        out.add(value)


def test_no_evidence_label_says_what_a_change_means(tmp_path: Path) -> None:
    """The evidence's every key and value (states, reasons, anchors, facts, the floated bases)
    is free of words that say what a change means.

    MUTATION (verified RED, 1 failed): name the fact ``other_side_thunk`` ``new_thunk`` -> RED."""
    labels: set[str] = set()
    for make, name in ((_evidence_world, "e"), (_thunk_world, "t")):
        (tmp_path / name).mkdir()
        v = _view(make(tmp_path / name), sort_by="significance")
        for e in v["entries"]:
            _labels({k: e.get(k) for k in ("pair_evidence", "counterpart_hint")}, labels)
            labels.add(e["significance"]["basis"])
    assert {
        "supported_pair_swap",
        "b_is_thunk",
        "a_is_thunk",
        "other_side_thunk",
        "same_import_name",
        "import_names_differ",
        "same_name_function_on_thunk_side",
        "no_caller_a",
        "refuted",
        "corroborated",
        "conflict",
        "mixed",
        "pairing_state",
    } <= labels, sorted(labels)
    for label in labels:
        assert not set(re.split(r"[^a-z0-9]+", label.lower())) & _WORDS, label


def test_every_read_first_text_names_every_entry_with_a_lift_basis() -> None:
    """The texts that say what must be read name every entry with a lift_basis — the floated R
    entries carry one at attention 0 — never only the attention-1 ones.

    MUTATION (verified RED, 1 failed): put back "attention-1 entry with a lift_basis" in the
    guide -> RED."""
    texts = {
        "guide": mcp_app._AGENT_GUIDE,
        "instructions": mcp_app._AGENT_INSTRUCTIONS,
        "card": mcp_cards.TOOL_CARDS["start_diff_review"].summary,
    }
    tools = mcp_app.make_tools(Path("/nonexistent/atlas.db"))
    for name in ("start_diff_review", "get_diff_patch_view"):
        texts[name] = tools[name].__doc__ or ""
    for name, text in texts.items():
        flat = " ".join(text.split())
        assert "attention-1 entr" not in flat, name
        assert "attention-1 entries with a" not in flat, name
    for name in ("guide", "instructions", "card", "start_diff_review", "get_diff_patch_view"):
        flat = " ".join(texts[name].split())
        assert re.search(r"entr(y|ies) with a `{0,2}lift_basis", flat), name
