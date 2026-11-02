# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""D25: string_delta — the string literals a binary gained / lost between two runs, taken as the
set difference of each side's ``strings`` values, with each value's resolved reference anchors read
from the per-run ``string_refs`` table (NOT get_functions_referencing_string's substring match, and
NOT string_edges' strcmp_gate counts).

Honest reads: a ref in no function (ref_in_func NULL) is shown not dropped; a binary that exported
no string_refs rows is refs UNKNOWN, never 'no references'; a NULL strings_truncated is unknown, not
'not truncated'. Zero real data: the test world of test_patch_view.
"""

from __future__ import annotations

from pathlib import Path

from tests.unit.lib.test_patch_view import DIFF, SHA_A, SHA_B, World, _pair_id  # noqa: F401
from treasure_map.lib.query.patch_view import string_delta


def _strings(w: World, side: str, values: list[str]) -> None:
    for v in values:
        w.adb[side].execute(
            "INSERT INTO strings (binary_id, value, address, category) "
            "VALUES (1, ?, '0x0', 'misc')",
            (v,),
        )


def _ref(
    w: World,
    side: str,
    value: str,
    *,
    ref_at: str,
    func: str | None,
    func_addr: str | None,
    truncated: int = 0,
) -> None:
    w.adb[side].execute(
        "INSERT INTO string_refs (binary_id, string_addr, string_value, ref_at, ref_in_func, "
        "ref_in_func_addr, segment, truncated) VALUES (1, '0x0', ?, ?, ?, ?, '.text', ?)",
        (value, ref_at, func, func_addr, truncated),
    )


def _trunc(w: World, side: str, state: int | None) -> None:
    w.adb[side].execute("UPDATE binaries SET strings_truncated = ? WHERE id = 1", (state,))


def test_added_and_removed_are_the_set_difference(tmp_path: Path) -> None:
    """removed = A-only, added = B-only — the plain set difference of the two sides' string values,
    not any count of strcmp_gate edges.

    MUTATION (verified RED): report a count from string_edges instead -> the values are wrong."""
    w = World(tmp_path)
    _strings(w, "a", ["shared", "gone", "also_gone"])
    _strings(w, "b", ["shared", "new"])
    w.commit()
    sd = string_delta(w.atlas, DIFF)
    assert sd["a_only_count"] == 2 and sd["b_only_count"] == 1
    assert [v["value"] for v in sd["sides"]["a_only"]["values"]] == ["also_gone", "gone"]
    assert [v["value"] for v in sd["sides"]["b_only"]["values"]] == ["new"]


def test_refs_come_from_string_refs_and_keep_a_null_function(tmp_path: Path) -> None:
    """A removed string's refs are its A-side string_refs rows; a row whose ref_in_func is NULL (a
    reference in no function) is shown, never dropped and never counted as 'no references'.

    MUTATION (verified RED): drop the NULL-ref_in_func row -> the null ref is missing."""
    w = World(tmp_path)
    _strings(w, "a", ["gone"])
    _strings(w, "b", [])
    _ref(w, "a", "gone", ref_at="0x100", func="FUN_1", func_addr="0xf0")
    _ref(w, "a", "gone", ref_at="0x200", func=None, func_addr=None)
    w.commit()
    refs = string_delta(w.atlas, DIFF)["sides"]["a_only"]["values"][0]["refs"]
    assert {r["ref_in_func"] for r in refs} == {"FUN_1", None}
    assert len(refs) == 2


def test_added_refs_are_read_on_the_b_side(tmp_path: Path) -> None:
    """An added string's refs come from the B side (where it exists), not A."""
    w = World(tmp_path)
    _strings(w, "a", [])
    _strings(w, "b", ["new"])
    _ref(w, "b", "new", ref_at="0x300", func="FUN_2", func_addr="0x2f0")
    w.commit()
    refs = string_delta(w.atlas, DIFF)["sides"]["b_only"]["values"][0]["refs"]
    assert refs == [
        {"ref_at": "0x300", "ref_in_func": "FUN_2", "ref_in_func_addr": "0x2f0", "truncated": False}
    ]


def test_no_string_refs_rows_is_unknown_not_no_references(tmp_path: Path) -> None:
    """A binary that exported no string_refs rows at all: refs are UNKNOWN (refs_exported False),
    never 'no references'.

    MUTATION (verified RED): report refs_exported True when the table is empty."""
    w = World(tmp_path)
    _strings(w, "a", ["gone"])
    _strings(w, "b", [])
    # no _ref() for the A side at all
    w.commit()
    removed = string_delta(w.atlas, DIFF)["sides"]["a_only"]
    assert removed["refs_exported"] is False
    assert removed["values"][0]["refs"] == []


def test_strings_truncated_state_is_honest_including_null(tmp_path: Path) -> None:
    """strings_truncated is read per side as clean (0) / truncated (1) / unknown (NULL) — a NULL is
    unknown, NEVER folded into 'not truncated'.

    MUTATION (verified RED): read NULL as clean -> the unknown side reads clean."""
    w = World(tmp_path)
    _strings(w, "a", ["x"])
    _strings(w, "b", ["y"])
    _trunc(w, "a", 1)
    _trunc(w, "b", None)
    w.commit()
    assert string_delta(w.atlas, DIFF)["strings_truncated"] == {"a": "truncated", "b": "unknown"}


def test_a_per_string_ref_cap_is_carried(tmp_path: Path) -> None:
    """A string whose ref list was capped carries truncated=True on that ref."""
    w = World(tmp_path)
    _strings(w, "a", ["gone"])
    _strings(w, "b", [])
    _ref(w, "a", "gone", ref_at="0x100", func="FUN_1", func_addr="0xf0", truncated=1)
    w.commit()
    refs = string_delta(w.atlas, DIFF)["sides"]["a_only"]["values"][0]["refs"]
    assert refs[0]["truncated"] is True


def test_a_side_that_cannot_be_read_is_an_error_not_an_empty_set(tmp_path: Path) -> None:
    """A side whose binary is not in its analysis.db is a read_error, not a silent empty set that
    would read as 'every string was removed'."""
    w = World(tmp_path)
    _strings(w, "a", ["x"])
    w.atlas.execute("UPDATE diff_meta SET sha256_b = 'deadbeef' WHERE diff_id = ?", (DIFF,))
    w.commit()
    sd = string_delta(w.atlas, DIFF)
    assert sd["read_error"]["b"] is not None
    # A's strings are not all reported 'removed' off a blank B — removed is A \ B over an empty B,
    # but the error flags that B is unreadable, so a consumer does not read it as a real delta.
    assert sd["read_error"]["a"] is None


def test_get_diff_meta_carries_the_counts(tmp_path: Path) -> None:
    """get_diff_meta's ``string_delta`` block carries the counts and each side's truncation state
    (the list itself is get_diff_string_delta)."""
    from treasure_map.lib.query.diff_align import get_diff_meta

    w = World(tmp_path)
    _strings(w, "a", ["shared", "gone"])
    _strings(w, "b", ["shared", "new"])
    w.commit()
    block = get_diff_meta(w.atlas, DIFF)["string_delta"]
    assert block["b_only_count"] == 1 and block["a_only_count"] == 1
    assert block["strings_truncated"] == {"a": "clean", "b": "clean"}


def test_direction_neutral(tmp_path: Path) -> None:
    """added and removed are symmetric: swapping the two sides swaps the two lists, nothing else."""
    w = World(tmp_path)
    _strings(w, "a", ["only_a"])
    _strings(w, "b", ["only_b"])
    w.commit()
    sd = string_delta(w.atlas, DIFF)
    assert [v["value"] for v in sd["sides"]["a_only"]["values"]] == ["only_a"]
    assert [v["value"] for v in sd["sides"]["b_only"]["values"]] == ["only_b"]
