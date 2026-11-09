# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""One class basis for a batch of no_real_change judgements (annotate_diff_batch's
``class_basis``; lib/overlay ``apply_class_basis``): the class's reason and why_unchanged reach
every item, merged with what the item gives, and the anchor threshold of each item is unchanged.

Zero real data: the World of test_diff_review (aligned pairs in libx)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests.unit.lib.test_diff_review import (  # noqa: F401 — the autouse cache fixture
    DX,
    World,
    _clear_view_caches,
    _pair_anchor,
)
from treasure_map import mcp_app
from treasure_map.lib import overlay
from treasure_map.lib.query import diff_annotations as dann

CLASS = {
    "reason": "date_literal",
    "why_unchanged": "only the build date string differs",
    "checked_text": ["the two date literals"],
}


@pytest.fixture
def world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> World:
    w = World(tmp_path, monkeypatch)
    for i in range(1, 14):
        w.pair(DX, f"{i:08x}", f"{i:08x}")
    return w


def _anchor(i: int) -> str:
    return _pair_anchor(DX, f"{i:08x}", f"{i:08x}")


def _stored(w: World, anchor: str) -> dict[str, Any] | None:
    row = w.atlas.execute(
        "SELECT verdict_basis FROM overlay WHERE anchor_ref = ?", (anchor,)
    ).fetchone()
    return None if row is None else json.loads(row[0])


def _written(w: World) -> int:
    return int(w.atlas.execute("SELECT COUNT(*) FROM overlay").fetchone()[0])


def _nrc(i: int, **kw: Any) -> dict[str, Any]:
    return {"anchor_ref": _anchor(i), "verdict": "no_real_change", "checked": [_anchor(i)], **kw}


def test_one_class_reaches_every_item_of_the_batch(world: World) -> None:
    """★ T-D24a: thirteen items, one class basis: each stored judgement's ``checked`` holds its
    own anchor, then ``class:<reason>``, then the class's notes; its why_unchanged is the class's;
    and the stored shape is the ordinary ``{kind, checked, why_unchanged}``.

    MUTATION (verified RED, 1 failed): leave the class out of the items (apply nothing) -> the
    items carry no why_unchanged -> refused -> RED. MUTATION (verified RED, 1 failed): store the
    class under a key of its own beside checked -> the stored shape differs -> RED."""
    tools = mcp_app.make_tools(world.path)
    out = tools["annotate_diff_batch"](
        [_nrc(i) for i in range(1, 14)], diff_id=DX, class_basis=CLASS
    )
    assert out.get("written") is True and out["count"] == 13, out
    for i in range(1, 14):
        assert _stored(world, _anchor(i)) == {
            "kind": "no_real_change",
            "checked": [_anchor(i), "class:date_literal", "the two date literals"],
            "why_unchanged": "only the build date string differs",
        }


def test_an_items_own_why_wins_and_checked_is_merged_not_replaced(world: World) -> None:
    """★ T-D24b: an item's own why_unchanged is kept over the class's; its own checked items stay
    first and are not repeated (an item that already names the class reason keeps one copy).

    MUTATION (verified RED, 1 failed): let the class's why_unchanged win -> RED. MUTATION
    (verified RED, 1 failed): replace the item's checked with the class items -> its anchor gone
    -> refused -> RED."""
    tools = mcp_app.make_tools(world.path)
    items = [
        _nrc(1, why_unchanged="a renamed log string, nothing else"),
        _nrc(2, checked=[_anchor(2), "class:date_literal", "a note of its own"]),
    ]
    out = tools["annotate_diff_batch"](items, diff_id=DX, class_basis=CLASS)
    assert out.get("written") is True, out
    one = _stored(world, _anchor(1))
    assert one is not None and one["why_unchanged"] == "a renamed log string, nothing else"
    two = _stored(world, _anchor(2))
    assert two is not None
    assert two["checked"] == [
        _anchor(2),
        "class:date_literal",
        "a note of its own",
        "the two date literals",
    ]


def test_the_class_notes_never_stand_in_for_an_anchor(world: World) -> None:
    """★ T-D24c: an item that gives no checked of its own has only the class's plain-text items —
    no anchor of this diff resolves — so it is refused (the anchor threshold, unchanged), and with
    it the whole batch: nothing is written.

    MUTATION (verified RED, 1 failed): count a ``class:`` item toward the anchor threshold ->
    the item is accepted -> RED."""
    tools = mcp_app.make_tools(world.path)
    items = [_nrc(1), {"anchor_ref": _anchor(2), "verdict": "no_real_change"}]
    out = tools["annotate_diff_batch"](items, diff_id=DX, class_basis=CLASS)
    assert out.get("written") is False, out
    assert [e["indexes"] for e in out["errors"]] == [[1]], out
    assert _written(world) == 0


@pytest.mark.parametrize(
    ("basis", "message"),
    [
        ({**CLASS, "reason": "vendor_build_banner"}, "reason must be one of"),
        ({**CLASS, "reason": None}, "reason must be one of"),
        ({**CLASS, "why_unchanged": "  "}, "why_unchanged must be non-blank"),
        ({**CLASS, "checked_text": "one note"}, "checked_text must be a list"),
        ({**CLASS, "note": "x"}, "class_basis takes"),
        ("date_literal", "must be an object"),
    ],
    ids=["unknown_reason", "no_reason", "blank_why", "text_not_list", "stray_key", "not_object"],
)
def test_a_class_basis_outside_its_shape_refuses_the_batch(
    world: World, basis: Any, message: str
) -> None:
    """★ T-D24d: a reason outside the closed set (no free text, no vendor list decides it), a
    blank why, a stray key: the whole batch is refused, nothing written.

    MUTATION (verified RED, 2 failed): accept any non-blank reason string -> unknown_reason and
    (with the None check kept) only that case RED."""
    tools = mcp_app.make_tools(world.path)
    out = tools["annotate_diff_batch"]([_nrc(1)], diff_id=DX, class_basis=basis)
    assert out.get("written") is False, out
    assert message in out["errors"][0]["error"], out
    assert _written(world) == 0


def test_each_reason_of_the_set_is_accepted_and_reads_as_plain_text() -> None:
    """T-D24d: every reason of the set is accepted, and its checked item is plain text to the
    anchor rule (never refused as a bad anchor)."""
    for reason in overlay.CLASS_REASONS:
        items, errors = overlay.apply_class_basis(
            [{"verdict": "no_real_change", "checked": ["x"]}],
            {"reason": reason, "why_unchanged": "w"},
        )
        assert errors == [] and items[0]["checked"] == ["x", f"class:{reason}"]
        assert dann._anchor_marker(f"class:{reason}") is None


def test_a_class_shared_with_another_verdict_refuses_the_batch_naming_it(world: World) -> None:
    """★ T-D24e: a changed_real (or change_inconclusive) item in a batch with a class basis
    refuses the whole batch, naming the item — never skipped quietly, never given the class's
    why_unchanged (which a changed_real would refuse anyway).

    MUTATION (verified RED, 1 failed): skip the items of other verdicts quietly -> the batch is
    written -> RED."""
    tools = mcp_app.make_tools(world.path)
    items = [
        _nrc(1),
        {"anchor_ref": _anchor(2), "verdict": "changed_real", "rationale": "r"},
        {"anchor_ref": _anchor(3), "verdict": "change_inconclusive", "rationale": "r"},
    ]
    out = tools["annotate_diff_batch"](items, diff_id=DX, class_basis=CLASS)
    assert out.get("written") is False, out
    named = sorted(i for e in out["errors"] for i in e["indexes"])
    assert named == [1, 2], out
    assert all("no_real_change items only" in e["error"] for e in out["errors"])
    assert _written(world) == 0


def test_a_batch_without_a_class_is_unchanged(world: World) -> None:
    """Without class_basis nothing is added to an item: its checked and why are its own."""
    tools = mcp_app.make_tools(world.path)
    out = tools["annotate_diff_batch"]([_nrc(1, why_unchanged="w")], diff_id=DX)
    assert out.get("written") is True, out
    assert _stored(world, _anchor(1)) == {
        "kind": "no_real_change",
        "checked": [_anchor(1)],
        "why_unchanged": "w",
    }
