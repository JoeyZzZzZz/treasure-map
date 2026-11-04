# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""overlay_history (lib/overlay): every change to the overlay — insert, update, promote, each
clear_overlay scope — is appended with the whole row before and after; a shadow judgement is
recorded there only; changed_real's change_kind.

Zero real data: the World of test_diff_review."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests.unit.lib.test_diff_review import (  # noqa: F401 — the autouse cache fixture
    DX,
    PAIR,
    World,
    _clear_view_caches,
    _pair_anchor,
    _promote,
    _ref,
    a_row,
)
from treasure_map.lib import overlay
from treasure_map.lib.errors import ConfigError


def _history(w: World, anchor: str | None = None) -> list[dict[str, Any]]:
    sql = "SELECT * FROM overlay_history WHERE event <> 'migration'"
    args: tuple[str, ...] = ()
    if anchor is not None:
        sql += " AND anchor_ref = ?"
        args = (anchor,)
    rows = [dict(r) for r in w.atlas.execute(sql + " ORDER BY id", args)]
    for r in rows:
        for k in ("before", "after", "note", "read_basis"):
            r[k] = json.loads(r[k]) if r[k] else None
    return rows


def _overlay_row(w: World, anchor: str) -> dict[str, Any]:
    return dict(w.atlas.execute("SELECT * FROM overlay WHERE anchor_ref = ?", (anchor,)).fetchone())


@pytest.fixture
def world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> World:
    return World(tmp_path, monkeypatch)


@pytest.fixture
def judged(world: World) -> tuple[World, str]:
    world.pair(DX, "00001000", "00001000")
    world.rows[DX] = [a_row("00001000")]
    return world, _pair_anchor(DX, "00001000", "00001000")


def test_a_write_and_an_overwrite_are_both_kept_with_the_whole_row(
    judged: tuple[World, str],
) -> None:
    """★ The first write is an insert (no before), the second an update whose before is the first
    write's whole row; the context (channel, unit) is recorded with each; the overlay keeps the
    last one.

    MUTATION (verified RED): leave the history out of _write_row's update branch -> one row ->
    RED; record the row after as before -> RED."""
    w, anchor = judged
    ctx = overlay.WriteContext(channel="judge", unit_id="u1", session="s1")
    w.judge(DX, anchor, "change_inconclusive")
    first = _overlay_row(w, anchor)
    w.judge(DX, anchor, "changed_real", ctx=ctx)
    rows = _history(w, anchor)
    assert [r["event"] for r in rows] == ["insert", "update"]
    assert rows[0]["before"] is None and rows[0]["after"]["verdict"] == "change_inconclusive"
    assert rows[1]["before"] == first
    assert rows[1]["after"]["verdict"] == "changed_real"
    assert (rows[1]["channel"], rows[1]["unit_id"], rows[1]["session"]) == ("judge", "u1", "s1")
    assert rows[0]["channel"] == "api"
    assert _overlay_row(w, anchor)["verdict"] == "changed_real"


def test_a_promotion_is_recorded_as_one(world: World) -> None:
    """MUTATION (verified RED): record a promoted write as a plain insert -> RED."""
    world.pair(DX, "00001000", "00002000")
    ref = _ref("runA", "00001000")
    world.rows[DX] = [a_row("00001000")]
    world.candidate(ref)
    _promote(world, "pair:00001000:00002000", ref)
    (row,) = _history(world, ref)
    assert row["event"] == "promote" and row["after"]["promoted_from"]


@pytest.mark.parametrize("scope", ["anchor", "run", "kind"])
def test_every_clear_scope_records_each_row_it_deletes(
    judged: tuple[World, str], scope: str
) -> None:
    """★ Each clear_overlay scope — one anchor, one run pair, a whole kind — records every row it
    deletes, whole, so the cleared rows can be rebuilt from the history exactly.

    MUTATION (verified RED): skip the history on the kind-wide delete -> the kind case -> RED."""
    w, anchor = judged
    w.pair(DX, "00002000", "00002000")
    w.judge(DX, anchor, "changed_real")
    other = _pair_anchor(DX, "00002000", "00002000")
    w.judge(DX, other, "change_inconclusive")
    rows = {a: _overlay_row(w, a) for a in (anchor, other)}
    kw: dict[str, Any] = {"anchor_kind": "diff_subject"}
    if scope == "anchor":
        kw["anchor_ref"] = anchor
    elif scope == "run":
        kw["run_id"] = PAIR
    else:
        kw["clear_all"] = True
    gone = overlay.clear_overlay(w.atlas, **kw)
    deletes = [r for r in _history(w) if r["event"] == "delete"]
    assert len(deletes) == gone == (1 if scope == "anchor" else 2)
    assert all(r["note"]["scope"] == scope for r in deletes)
    for r in deletes:
        assert r["before"] == rows[r["anchor_ref"]]
        assert r["after"] is None


def test_a_shadow_judgement_is_kept_beside_the_current_one(judged: tuple[World, str]) -> None:
    """★ A shadow (an audit's judgement) passes the same gates as a write, is recorded in the
    history only, and leaves the current row as it was.

    MUTATION (verified RED): let a shadow fall through to the write -> the row changes -> RED."""
    w, anchor = judged
    w.judge(DX, anchor, "changed_real")
    before = _overlay_row(w, anchor)
    res = w.judge(DX, anchor, "change_inconclusive", shadow=True)
    assert res.action == "shadow"
    assert _overlay_row(w, anchor) == before
    shadow = [r for r in _history(w, anchor) if r["event"] == "shadow"]
    assert len(shadow) == 1 and shadow[0]["after"]["verdict"] == "change_inconclusive"
    with pytest.raises(ConfigError):
        w.judge(DX, "runA::runB#function_pair#libx::0bad::0bad", "changed_real", shadow=True)


@pytest.mark.parametrize(
    ("basis", "ok"),
    [
        ({"change_kind": ["guard_added"]}, True),
        ({"change_kind": ["sink_removed", "constant_changed"]}, True),
        ({"change_kind": "restructured"}, True),
        ({"change_kind": ["guard_added", "guard_added"]}, False),
        ({"change_kind": ["made_up"]}, False),
        ({"change_kind": []}, False),
    ],
)
def test_changed_real_carries_its_change_kind(
    judged: tuple[World, str], basis: dict[str, Any], ok: bool
) -> None:
    """★ changed_real may name one or more change kinds (each once, from the closed set), stored
    with its basis; anything else is refused.

    MUTATION (verified RED): accept any string -> made_up -> RED; drop the duplicate check ->
    RED."""
    w, anchor = judged
    if not ok:
        with pytest.raises(ConfigError, match="change_kind"):
            w.judge(DX, anchor, "changed_real", verdict_basis=basis)
        return
    w.judge(DX, anchor, "changed_real", verdict_basis=basis)
    stored = json.loads(_overlay_row(w, anchor)["verdict_basis"])
    want = (
        basis["change_kind"] if isinstance(basis["change_kind"], list) else [basis["change_kind"]]
    )
    assert stored["change_kind"] == want


def test_change_kind_belongs_to_changed_real_only(judged: tuple[World, str]) -> None:
    w, anchor = judged
    with pytest.raises(ConfigError, match="change_kind applies to changed_real only"):
        w.judge(
            DX,
            anchor,
            "no_real_change",
            verdict_basis={
                "checked": [anchor],
                "why_unchanged": "w",
                "change_kind": ["guard_added"],
            },
        )
