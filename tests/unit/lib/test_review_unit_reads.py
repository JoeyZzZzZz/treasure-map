# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""What a review unit hands out to be read, and what a write then counts as read: a unit handed
out again lists only the members still owed; a batch's material carries its members' candidate
rows; a judgement written having read only part of an entry's candidate rows is disposed but
counted under ``basis_incomplete``.

Zero real data: the World of test_diff_review (one run pair; aligned pairs in libx)."""

from __future__ import annotations

from pathlib import Path
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
from treasure_map import mcp_app
from treasure_map.lib import tool_call_log as tcl
from treasure_map.lib.query import review_units as ru
from treasure_map.lib.query import sink_overlay as so


@pytest.fixture(autouse=True)
def _clear_unit_cache() -> None:
    ru.DIFF_CACHE.clear()


def _call(server: Any, name: str, args: dict[str, Any]) -> dict[str, Any]:
    from tests.unit.test_tool_surface import _call as call

    return call(server, name, args)


def _review(w: World, k: int = 0) -> ru.PairReview:
    return ru.review_pair(
        w.atlas,
        "runA",
        "runB",
        k=k,
        pair_staleness={"source_stale": False},
        server_commit="c0",
    )


def _rows(addr: str, n: int) -> list[so.SinkOverlayRow]:
    """``n`` candidate rows on the A side of the pair at ``addr``, one per call site."""
    return [
        _row(
            _ref("runA", addr, at=f"0x{16 + j:x}"),
            None,
            reason="present_different_callee",
            call="present_different_callee",
        )
        for j in range(n)
    ]


def _world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, n: int, rows: dict[str, int]) -> World:
    """``n`` aligned pairs in DX at addresses 1..n (eight hex digits), the ones in ``rows`` with
    that many candidate rows each."""
    w = World(tmp_path, monkeypatch)
    for i in range(1, n + 1):
        w.pair(DX, f"{i:08x}", f"{i:08x}")
    w.rows[DX] = [r for addr, count in rows.items() for r in _rows(addr, count)]
    return w


def _judge(server: Any, anchor: str, unit_id: str | None) -> dict[str, Any]:
    args: dict[str, Any] = {
        "anchor_ref": anchor,
        "verdict": "changed_real",
        "rationale": "r",
        "diff_id": DX,
    }
    if unit_id is not None:
        args["unit_id"] = unit_id
    got = _call(server, "annotate_diff", args)
    assert got.get("written") is True, got
    return got


def _ids(holder: dict[str, Any]) -> list[str]:
    return [str(m.get("entry_id")) for m in holder.get("members") or []]


def test_a_unit_handed_out_again_lists_only_the_members_still_owed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ A 16-member batch, ten of its members judged: handed out again — by the overview's next
    unit, by unit= and by the last write's answer — its material and ``members`` list the six
    still owed and none judged (a reader told to judge every member listed would judge those
    again), with the ten counted in ``members_disposed``. Once all sixteen are judged, unit= lists
    them all.

    MUTATION (verified RED, 1 failed): fill the page with the disposed members after the owed
    ones (``found.sort`` by disposed, as before) -> sixteen listed -> RED."""
    w = _world(tmp_path, monkeypatch, 20, {})
    server = mcp_app.build_server(w.path)
    nu = _call(server, "start_diff_review", {"run_pair": PAIR, "k": 0})["next_unit"]
    assert nu["kind"] == ru.SECOND_TIER and nu["members_total"] == ru.BATCH_UNIT_MAX
    assert len(nu["members"]) == ru.BATCH_UNIT_MAX  # the precondition: one page holds them all
    uid = nu["unit_id"]
    members = [m["anchor_ref"] for m in nu["members"]]
    by_anchor = {m["anchor_ref"]: m["entry_id"] for m in nu["members"]}
    wrote: dict[str, Any] = {}
    for anchor in members[:10]:
        wrote = _judge(server, anchor, uid)
    owed = [by_anchor[a] for a in members[10:]]
    again = wrote.get("next_unit") or {}
    head = _call(server, "start_diff_review", {"run_pair": PAIR, "k": 0})["next_unit"]
    alone = _call(server, "start_diff_review", {"run_pair": PAIR, "unit": uid, "k": 0})
    for label, holder in (("write", again), ("overview", head), ("unit", alone)):
        assert holder.get("unit_id", uid) == uid, label
        assert _ids(holder) == owed, (label, _ids(holder))
        page = [e["entry_id"] for e in holder["material"]["entries"]]
        assert page == owed, (label, page)
        assert not any(ru.disposed(m.get("review_state")) for m in holder["members"]), label
        assert (holder["members_disposed"], holder["members_after_this_page"]) == (10, 0), label
        assert holder["material"]["entries_truncated"] is False, label
    for anchor in members[10:]:
        _judge(server, anchor, uid)
    done = _call(server, "start_diff_review", {"run_pair": PAIR, "unit": uid, "k": 0})
    assert sorted(_ids(done)) == sorted(by_anchor.values())


def test_a_batch_material_carries_its_members_candidate_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ K6 (a): a batch's members are handed out with up to a page of their candidate rows, so a
    member listed whole is read with every row: the 5-row member carries its five rows and reads
    as shown whole (``unit_delivered``, not cut); the 35-row member carries the first twenty with
    ``rows_next_offset`` and ``read_rows``, is not shown whole (judged at once it read nothing:
    ``basis_incomplete``), and once the rest of its rows are read on by rows_offset its judgement
    reads ``unit_delivered`` (``material_cut``) with every row read — the delivered window and the
    one read on together.

    MUTATION (verified RED, 1 failed each): read the batch's entries with rows_limit=0 (as before)
    -> no rows -> RED; leave ``rows_next_offset`` out of part_cut -> the 35-row member reads shown
    whole -> RED; leave the deliveries' ``unit_rows`` out of _rows_partial -> the rows read on
    alone read partial -> RED."""
    w = _world(tmp_path, monkeypatch, 20, {"00000003": 35, "00000004": 5})
    server = mcp_app.build_server(w.path)
    nu = _call(server, "start_diff_review", {"run_pair": PAIR, "k": 0})["next_unit"]
    big, small = "pair:00000003:00000003", "pair:00000004:00000004"
    assert _ids(nu) == [big, small], _ids(nu)  # the precondition: one batch holds the two
    entries = {e["entry_id"]: e for e in nu["material"]["entries"]}
    assert len(entries[small].get("rows") or []) == 5 and entries[small]["rows_next_offset"] is None
    assert len(entries[big].get("rows") or []) == 20 and entries[big]["rows_next_offset"] == 20
    assert "rows_offset=<rows_next_offset>" in nu["material"].get("read_rows", "")
    assert nu["material_cut"] is True
    anchors = {m["entry_id"]: m["anchor_ref"] for m in nu["members"]}
    got = _judge(server, anchors[small], nu["unit_id"])
    assert got["read_basis"] == {"basis": "unit_delivered", "material_cut": False}
    got = _judge(server, anchors[big], nu["unit_id"])
    assert got["read_basis"].get("basis") == "none", got["read_basis"]
    assert anchors[big] in _review(w).audits.basis_incomplete
    more = _call(server, "get_diff_patch_view", {"diff_id": DX, "entry_id": big, "rows_offset": 20})
    assert "error" not in more, more
    got = _judge(server, anchors[big], nu["unit_id"])
    assert got["read_basis"] == {"basis": "unit_delivered", "material_cut": True}
    assert _review(w).audits.basis_incomplete == []


def test_a_judgement_on_part_of_an_entrys_rows_is_counted_basis_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ K6 (b): an entry of 35 candidate rows read by entry_id only for its first page, then
    judged: its read basis is ``fetched`` with ``rows_partial`` — disposed (not needs_recheck),
    and counted under ``basis_incomplete`` in the report and the coverage statement. Read the
    second page too and judged again: every row read, nothing incomplete.

    MUTATION (verified RED, 1 failed each): leave ``rows_partial`` out of read_audits'
    basis_incomplete -> RED; log no ``rows_read`` window for an entry read -> no rows_partial ->
    RED."""
    w = _world(tmp_path, monkeypatch, 3, {"00000002": 35})
    server = mcp_app.build_server(w.path)
    entry = "pair:00000002:00000002"
    page = _call(server, "get_diff_patch_view", {"diff_id": DX, "entry_id": entry})
    (one,) = page["entries"]
    assert (one["rows_total"], one["rows_next_offset"]) == (35, 20)  # the precondition
    anchor = one["anchor_ref"]
    got = _judge(server, anchor, None)
    assert got["read_basis"] == {"basis": "fetched", "rows_partial": True}
    r = _review(w)
    assert ru.disposed(r.progress.states.get(anchor)), r.progress.states.get(anchor)
    assert r.report["basis_incomplete"]["count"] == 1
    assert r.report["basis_incomplete"]["subjects"] == [anchor]
    assert "basis incomplete 1;" in r.report["coverage_statement"]
    _call(server, "get_diff_patch_view", {"diff_id": DX, "entry_id": entry, "rows_offset": 20})
    got = _judge(server, anchor, None)
    assert got["read_basis"] == {"basis": "fetched"}
    assert _review(w).report["basis_incomplete"]["count"] == 0


def test_the_row_window_of_a_read_is_logged_from_what_it_returned() -> None:
    """``rows_read`` is the window the answer held — from its rows_offset and the rows it carried,
    of rows_total — and a unit material logs ``unit_rows`` only for the entries holding part of
    their rows.

    MUTATION (verified RED, 1 failed): start every window at 0 (ignore the answer's rows_offset)
    -> RED."""
    session = tcl.Session(id="s")
    entry = {"entry_id": "e1", "rows": [{}] * 15, "rows_total": 35, "rows_offset": 20}
    line = tcl.build_line(
        session,
        "get_diff_patch_view",
        {"diff_id": DX, "entry_id": "e1", "rows_offset": 20, "rows_limit": 20},
        {"entries": [entry]},
    )
    assert line.get("rows_read") == [20, 35, 35]
    material = {
        "entries": [
            {"entry_id": "e1", "rows": [{}] * 20, "rows_total": 35, "rows_next_offset": 20},
            {"entry_id": "e2", "rows": [{}] * 5, "rows_total": 5, "rows_next_offset": None},
        ]
    }
    line = tcl.build_line(
        session,
        "start_diff_review",
        {"run_pair": PAIR},
        {"next_unit": {"unit_id": "u1", "material": material}},
    )
    assert line.get("unit_rows") == {"e1": [0, 20, 35]}
    assert line.get("unit_whole") == ["e2"]
