# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""D29: get_diff_patch_view's per-CALLSITE sink counts (``sink_callsite_counts``), built from a
function's ``call_tokens`` — each SINK_CALLEE_NAMES callee's CALL count in the two sides, NOT
deduplicated. An independent key (unit ``callsite``) that NEVER mixes into sink_candidate_counts
and NEVER moves an entry's bucket or significance.

The one thing that matters most: a side with no readable pseudocode reads 0 call tokens, and that
0 is NOT "the call is gone". Such a side is reported unknown (skipped_micro / text_unavailable by
size), never an N->0 delta. Zero real data: the test world of test_patch_view.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.unit.lib.test_patch_view import World, _entry, _pair_id
from treasure_map.lib.query import patch_view as pv

A, B = "00001000", "00002000"
PID = _pair_id(A, B)


@pytest.fixture
def current(monkeypatch: pytest.MonkeyPatch) -> None:
    """The diff reads as current (its stamps are not under test here)."""
    monkeypatch.setattr(
        pv,
        "diff_source_staleness",
        lambda atlas, diff_id: {
            "source_stale": False,
            "source_stale_reason": None,
            "toolchain_checked": True,
        },
    )


def _pair(
    tmp_path: Path,
    a_calls: list[str],
    b_calls: list[str],
    *,
    a_pc: str | None = "f();",
    b_pc: str | None = "f();",
    a_sz: int = 200,
    b_sz: int = 200,
    sim: float = 0.6,
    a_callees: list[str] | None = None,
    b_callees: list[str] | None = None,
) -> World:
    """One aligned pair of ``libx``, each side's call_tokens driven by ``a_calls`` / ``b_calls``."""
    w = World(tmp_path)
    w.pair(A, B, 0.97, sim, name_a="f", name_b="f")
    w.fn(
        "a",
        A,
        a_callees if a_callees is not None else [],
        pseudocode=a_pc,
        size_bytes=a_sz,
        calls=a_calls,
    )
    w.fn(
        "b",
        B,
        b_callees if b_callees is not None else [],
        pseudocode=b_pc,
        size_bytes=b_sz,
        calls=b_calls,
    )
    w.commit()
    return w


def _scc(w: World, **kw: object) -> dict[str, object]:
    return _entry(w, PID, **kw)["sink_callsite_counts"]


def test_a_repeated_sink_call_counted_not_deduplicated(tmp_path: Path, current: None) -> None:
    """A recall-gap sink (_eval) called 4 times on A, 3 on B: sink_callsite_counts is 4 -> 3 — a
    repeated call disappearing is a delta the callee SET (sink_candidate_counts / callee_set) is
    blind to. The pair is bucket B recall_gap_sink as before; D29 adds only the count field.

    MUTATION (verified RED): count distinct sink names (dedupe the tokens) -> 1 -> 1 -> no delta."""
    w = _pair(tmp_path, ["_eval"] * 4, ["_eval"] * 3, a_callees=["_eval"], b_callees=["_eval"])
    e = _entry(w, PID)
    assert (e["bucket"], e["subclass"]) == ("B", "recall_gap_sink:argv_runner")
    scc = e["sink_callsite_counts"]
    assert scc["unit"] == "callsite"
    assert scc["delta"] == [{"sink": "_eval", "a": 4, "b": 3}]
    assert scc["unknown"] == []
    # no hunt candidate on either side -> no sink_candidate_counts: the two keys never mix
    assert "sink_candidate_counts" not in e


def test_a_micro_stub_side_is_unknown_never_a_zero_delta(tmp_path: Path, current: None) -> None:
    """A side gutted to a design-skipped micro stub (size < _DECOMPILE_MIN_SIZE, empty text) read 0
    call tokens — that 0 is NOT "the call was removed". It is reported skipped_micro, and no N->0
    delta is forged.

    MUTATION (verified RED): read the empty call_tokens as a 0 count -> delta _eval 0 -> 2."""
    w = _pair(
        tmp_path, [], ["_eval"] * 2, a_pc=None, a_sz=6, a_callees=["_eval"], b_callees=["_eval"]
    )
    scc = _scc(w)
    assert {"sink": "_eval", "side": "a", "reason": "skipped_micro"} in scc["unknown"]
    assert scc["delta"] == []


def test_an_empty_text_real_body_side_is_unknown_never_a_zero_delta(
    tmp_path: Path, current: None
) -> None:
    """The cfg_client case: a real-size body (>= _DECOMPILE_MIN_SIZE) whose decompile produced no
    text read 0 call tokens. Reported text_unavailable, never _eval 4 -> 0. Decided by empty text +
    size alone, reading NO decompile_status column (the fixture db has none), so a pre-r6
    analysis.db is judged the same.

    MUTATION (verified RED): treat an empty-text large body as a real 0 -> delta _eval 4 -> 0."""
    w = _pair(
        tmp_path, ["_eval"] * 4, [], b_pc=None, b_sz=30000, a_callees=["_eval"], b_callees=["_eval"]
    )
    scc = _scc(w)
    assert {"sink": "_eval", "side": "b", "reason": "text_unavailable"} in scc["unknown"]
    assert scc["delta"] == []


def test_a_missing_call_tokens_column_is_unknown_not_a_crash(tmp_path: Path, current: None) -> None:
    """An older analysis.db with no call_tokens column: that side is unknown, never 0, and nothing
    raises.

    MUTATION (verified RED): default a missing column to 0 counts -> delta _eval 0 -> 3."""
    w = _pair(tmp_path, ["_eval"] * 4, ["_eval"] * 3, a_callees=["_eval"], b_callees=["_eval"])
    w.adb["a"].execute("ALTER TABLE functions DROP COLUMN call_tokens")
    w.adb["a"].commit()
    scc = _scc(w)
    assert {"sink": "_eval", "side": "a", "reason": "call_tokens_unavailable"} in scc["unknown"]
    assert scc["delta"] == []


def test_a_bucket_s_pair_carries_the_count_and_is_never_floated(
    tmp_path: Path, current: None
) -> None:
    """A similarity-1 aligned pair whose pseudocode differs is bucket S; its snprintf callsite count
    changed 4 -> 1. The count is reported, AND significance stays attention 1 (aligned_pseudocode_
    differs) — a sink_callsite_counts delta NEVER floats an entry to attention 0.

    MUTATION (verified RED): consult sink_callsite_counts in significance() like sink_candidate_
    counts -> attention 0 -> RED."""
    w = _pair(
        tmp_path,
        ["snprintf"] * 4,
        ["snprintf"] * 1,
        a_pc="snprintf(a,0x10,c); snprintf(a,0x20,d); snprintf(a,0x30,e); snprintf(a,0x40,f);",
        b_pc="snprintf(a,0x10,c);",
        sim=1.0,
        a_callees=["snprintf"],
        b_callees=["snprintf"],
    )
    e = _entry(w, PID)
    assert e["bucket"] == "S"
    assert e["sink_callsite_counts"]["delta"] == [{"sink": "snprintf", "a": 4, "b": 1}]
    assert e["significance"]["attention"] == 1  # never 0: the count does not lift it
    assert e["significance"]["basis"] == "aligned_pseudocode_differs"


def test_increase_and_decrease_are_symmetric(tmp_path: Path, current: None) -> None:
    """Direction-neutral: a sink gained reads the same shape as one lost (a and b in place, no
    ordering of one before the other)."""
    up = _pair(
        tmp_path / "up", ["_eval"] * 1, ["_eval"] * 3, a_callees=["_eval"], b_callees=["_eval"]
    )
    down = _pair(
        tmp_path / "down", ["_eval"] * 3, ["_eval"] * 1, a_callees=["_eval"], b_callees=["_eval"]
    )
    assert _scc(up)["delta"] == [{"sink": "_eval", "a": 1, "b": 3}]
    assert _scc(down)["delta"] == [{"sink": "_eval", "a": 3, "b": 1}]


def test_a_non_sink_call_is_not_counted(tmp_path: Path, current: None) -> None:
    """Only SINK_CALLEE_NAMES are counted; an ordinary callee (strlen, a FUN_ stub) is not, so a
    pair whose only call-token change is a non-sink carries no sink_callsite_counts."""
    w = _pair(
        tmp_path,
        ["strlen", "_eval"],
        ["strlen", "strlen", "_eval"],  # strlen changed, _eval steady
        a_callees=["_eval"],
        b_callees=["_eval"],
    )
    # _eval steady (1 == 1), strlen not a sink -> nothing to report -> no field on the entry
    assert "sink_callsite_counts" not in _entry(w, PID)
