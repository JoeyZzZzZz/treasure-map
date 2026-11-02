# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""D25: string_delta — the string literals one side of a diff holds and the other does not
(a_only / b_only), taken as the set difference of each side's ``strings`` values, with each value's
resolved reference anchors read from the per-run ``string_refs`` table (NOT
get_functions_referencing_string's substring match, and NOT string_edges' strcmp_gate counts).

Honest reads: a ref in no function (ref_in_func NULL) is shown not dropped; a binary that exported
no string_refs rows is refs UNKNOWN, never 'no references'; a NULL strings_truncated is unknown, not
'not truncated'. Zero real data: the test world of test_patch_view.
"""

from __future__ import annotations

import json
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


def test_a_truncated_or_unknown_side_marks_both_counts_and_lists_unconfirmed(
    tmp_path: Path,
) -> None:
    """A side whose strings list is a prefix (truncated) or unrecorded (NULL -> unknown) may hold,
    past what it stored, a value the other side lists as one-sided: the counts and the lists are
    then ``unconfirmed``, with the sides named — in string_delta AND in get_diff_meta's block. Two
    clean sides are confirmed (``unconfirmed`` False, nothing named).

    MUTATIONS (verified RED): (1) mark only a truncated side, not an unknown one -> b:unknown
    missing; (2) get_diff_meta drops ``unconfirmed`` -> its block lacks it."""
    from treasure_map.lib.query.diff_align import get_diff_meta

    w = World(tmp_path)
    _strings(w, "a", ["shared", "x"])
    _strings(w, "b", ["shared", "y"])
    w.commit()
    clean = string_delta(w.atlas, DIFF)
    assert clean["unconfirmed"] is False and clean["unconfirmed_by"] == []
    _trunc(w, "a", 1)
    _trunc(w, "b", None)
    w.commit()
    sd = string_delta(w.atlas, DIFF)
    assert sd["unconfirmed"] is True
    assert sd["unconfirmed_by"] == ["a:truncated", "b:unknown"]
    block = get_diff_meta(w.atlas, DIFF)["string_delta"]
    assert block.get("unconfirmed") is True
    assert block.get("unconfirmed_by") == ["a:truncated", "b:unknown"]


def _wide_world(tmp_path: Path, n_a: int, n_b: int, refs: int) -> World:
    """``n_a`` A-only and ``n_b`` B-only strings, each with ``refs`` wide reference rows, so a
    default page (limit 200) is far over the response budget."""
    w = World(tmp_path)
    a_vals = [f"a_only_value_{i:04d}_" + "x" * 60 for i in range(n_a)]
    b_vals = [f"b_only_value_{i:04d}_" + "y" * 60 for i in range(n_b)]
    _strings(w, "a", a_vals)
    _strings(w, "b", b_vals)
    for side, vals in (("a", a_vals), ("b", b_vals)):
        for v in vals:
            for r in range(refs):
                _ref(
                    w,
                    side,
                    v,
                    ref_at=f"0x{0x400000 + r:x}",
                    func=f"FUN_{0x410000 + r:08x}",
                    func_addr=f"0x{0x410000 + r:x}",
                )
    w.commit()
    return w


def test_the_tool_fits_the_response_budget_and_pages_to_the_whole_set(tmp_path: Path) -> None:
    """At the default limit the page is over 48,000 bytes before fitting: the tool cuts both lists
    at one index, stays within the budget, and says where to resume (next_offset non-null,
    values_truncated true). Following next_offset returns every value of both sides exactly once,
    in order — a side that runs out first stops (next_offset null) while the other goes on.

    MUTATION (verified RED): return the page unfitted -> the response is over the budget."""
    from treasure_map.mcp_app import _RESPONSE_BYTE_BUDGET, make_tools

    w = _wide_world(tmp_path, 120, 260, refs=4)
    full = string_delta(w.atlas, DIFF)
    tool = make_tools(w.path)["get_diff_string_delta"]
    first = tool(DIFF)
    assert len(json.dumps(first)) <= _RESPONSE_BYTE_BUDGET
    a, b = first["sides"]["a_only"], first["sides"]["b_only"]
    assert a["next_offset"] is not None and a["values_truncated"] is True
    assert a["next_offset"] == b["next_offset"] == a["returned"] == b["returned"]
    seen: dict[str, list[str]] = {"a_only": [], "b_only": []}
    page, pages = first, 0
    while True:
        pages += 1
        assert len(json.dumps(page)) <= _RESPONSE_BYTE_BUDGET
        for name in seen:
            seen[name] += [v["value"] for v in page["sides"][name]["values"]]
        live = [page["sides"][n]["next_offset"] for n in seen]
        live = [o for o in live if o is not None]
        if not live:
            break
        assert len(set(live)) == 1  # one index for both lists
        page = tool(DIFF, offset=live[0])
    assert pages > 2
    assert seen["a_only"] == [v["value"] for v in full["sides"]["a_only"]["values"]]
    assert seen["b_only"] == [v["value"] for v in full["sides"]["b_only"]["values"]]
    assert len(seen["a_only"]) == 120 and len(seen["b_only"]) == 260


def test_the_tool_limit_is_capped_at_the_shared_maximum(tmp_path: Path) -> None:
    """limit above _MAX_LIMIT (200) is refused, as on every other paged tool."""
    from treasure_map.mcp_app import make_tools

    w = World(tmp_path)
    w.commit()
    tool = make_tools(w.path)["get_diff_string_delta"]
    assert "error" in tool(DIFF, limit=201)
    assert "error" not in tool(DIFF, limit=200)


def test_a_fitted_page_is_full_at_every_budget(tmp_path: Path) -> None:
    """Swept one byte at a time over two indexes' width: each page is within the budget, and it
    is FULL — the page measured with its paging fields back at their placeholders, plus the next
    index's values and separators, would be over it. The placeholders are what was measured, so a
    correct page may end a few bytes under; measuring the final width would misread it.

    MUTATIONS (verified RED): (1) stop one index early (``>=`` for ``>``) -> a page one index short
    of full at the budget it exactly fills; (2) measure with a narrower ``values_truncated``
    placeholder (true) -> the page that just holds everything comes out over its budget."""
    import copy

    from treasure_map.mcp_app import _fit_string_delta

    w = _wide_world(tmp_path, 30, 45, refs=2)
    base = string_delta(w.atlas, DIFF)
    base["note"] = "n"
    vals = {n: base["sides"][n]["values"] for n in ("a_only", "b_only")}
    one = sum(len(json.dumps(v[0])) + 2 for v in vals.values())
    # the width of the page that holds every value (cut by nothing, values_truncated false)
    whole = len(json.dumps(_fit_string_delta(copy.deepcopy(base), 0, 10**9)))
    start = 6000
    slack_seen: set[int] = set()
    # a cut page, and the pages around the one that just holds everything (values_truncated false)
    for budget in [*range(start, start + 2 * one), *range(whole - 2 * one, whole + 5)]:
        page = _fit_string_delta(copy.deepcopy(base), 0, budget)
        size = len(json.dumps(page))
        assert size <= budget, budget
        kept = page["sides"]["a_only"]["returned"]
        slack_seen.add(budget - size)
        held = copy.deepcopy(page)
        for name in ("a_only", "b_only"):
            n = held["sides"][name]["count"]  # the wider of null and the total
            held["sides"][name]["next_offset"] = n if len(str(n)) > len("null") else None
            held["sides"][name]["values_truncated"] = False
            held["sides"][name]["returned"] = len(vals[name])
        nxt = sum(len(json.dumps(v[kept])) + 2 for v in vals.values() if kept < len(v))
        if nxt:
            assert len(json.dumps(held)) + nxt > budget, budget
    assert min(slack_seen) <= 10  # the sweep reached pages filled to within bytes of the budget
    assert _fit_string_delta(copy.deepcopy(base), 0, whole)["sides"]["b_only"]["returned"] == 45
