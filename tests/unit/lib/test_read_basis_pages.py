# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""A subject read by a tool that pages it is read whole only when its pages, together, held all of
it (lib/query/read_basis ``read_partial``; the windows logged by lib/tool_call_log ``page_rows``).

Zero real data: synthetic log lines, and the World of test_diff_review with one long function."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from tests.unit.lib.test_diff_review import (  # noqa: F401 — the autouse cache fixture
    DX,
    PAIR,
    World,
    _clear_view_caches,
    _pair_anchor,
    _ref,
    _row,
)
from treasure_map import mcp_app
from treasure_map.lib import tool_call_log as tcl
from treasure_map.lib.query import read_basis as rb
from treasure_map.lib.query import review_units as ru

ANCHOR = "a::b#function_pair#libx::00401000::00402000"
ENTRY = "pair:00401000:00402000"
FILE = "a::b#non_binary#etc/rc"


def _read(tool: str, window: list[int] | None, *, cap: bool = False, **params: Any) -> dict:
    """One logged read of a subject: its params, and the window of it its page held."""
    line: dict[str, Any] = {"tool": tool, "params": {"run_id": "b", **params}}
    if window is not None:
        line["page_rows"] = window
    if cap:
        line["extraction_cap"] = True
    return line


def _pseudo(window: list[int] | None, **params: Any) -> dict[str, Any]:
    return _read("get_pseudocode", window, function="0x00402000", **params)


def _infer(lines: list[dict[str, Any]], **kw: Any) -> dict[str, Any]:
    return rb.infer(lines, anchor_ref=kw.pop("anchor_ref", ANCHOR), entry_id=ENTRY, **kw)


# ── read_basis: coverage, not the last page ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("lines", "partial"),
    [
        ([_pseudo([0, 40, 120])], "pages"),
        ([_pseudo([0, 40, 120]), _pseudo([40, 80, 120], offset=40)], "pages"),
        (
            [_pseudo([0, 40, 120]), _pseudo([40, 80, 120], offset=40), _pseudo([80, 120, 120])],
            None,
        ),
        ([_pseudo([80, 120, 120], offset=80)], "pages"),
        ([_pseudo(None)], "pages"),
        ([_pseudo([0, 120, 120])], None),
        ([_pseudo([0, 0, 0])], None),
        # pages of two streams never add up: half the lines and the other half of the listing
        (
            [
                _pseudo([0, 60, 120]),
                _read("get_disassembly", [60, 120, 120], function="00402000", offset=60),
            ],
            "pages",
        ),
        # nor do the same function's pages in two runs
        ([_pseudo([0, 60, 120]), _pseudo([60, 120, 120], run_id="a")], "pages"),
        # one whole stream is enough, whatever the others held
        ([_pseudo([0, 60, 120]), _read("get_disassembly", [0, 9, 9], function="402000")], None),
    ],
    ids=[
        "first_of_three",
        "two_of_three",
        "all_three",
        "last_page_only",
        "no_window_logged",
        "one_whole_page",
        "empty_text",
        "two_tools_do_not_add_up",
        "two_runs_do_not_add_up",
        "one_whole_stream",
    ],
)
def test_a_paged_read_counts_whole_only_when_its_pages_cover_it(
    lines: list[dict[str, Any]], partial: str | None
) -> None:
    """★ T-G8a / T-G8b: a function read by get_pseudocode only for some of its pages reads
    ``fetched`` with ``read_partial: "pages"``; every page read, it falls back to plain
    ``fetched``. The last page alone is not the whole (its next_offset is null, it still left the
    head unread), and a read that logged no window counts as partial (FAIL-CLOSED).

    MUTATION (verified RED, 6 failed): drop the read_partial check from infer's fetched branch ->
    every "pages" case RED. MUTATION (verified RED, 1 failed): read a stream whole when its last
    window ends at the total (``max(end) >= total``) -> last_page_only RED. MUTATION (verified
    RED, 1 failed): count a stream with no window as whole -> no_window_logged RED. MUTATION
    (verified RED, 2 failed): key the streams by function alone -> the two "do_not_add_up" cases
    RED."""
    got = _infer(lines)
    assert got["basis"] == "fetched"
    assert got.get("read_partial") == partial


def test_a_cut_unit_read_on_for_one_page_is_partial_on_the_delivered_branch() -> None:
    """★ T-G8a: a unit whose material was cut, read on by the subject's pseudocode for one page of
    three: ``unit_delivered`` with ``material_cut`` AND ``read_partial`` — the delivered branch
    reads the same coverage as the fetched one. The pages read BEFORE the delivery do not count
    toward it (only reads after the delivery read the subject on). Read on whole: no flag.

    MUTATION (verified RED, 1 failed): leave the read_partial check out of infer's delivered
    branch -> RED (only the fetched branch flagged)."""
    delivery = {"tool": "start_diff_review", "params": {}, "unit": "u1", "unit_material_cut": True}
    lines = [delivery, _pseudo([0, 40, 120])]
    got = _infer(lines, unit_id="u1")
    assert got == {"basis": "unit_delivered", "material_cut": True, "read_partial": "pages"}
    before = [_pseudo([40, 120, 120], offset=40), delivery, _pseudo([0, 40, 120])]
    assert _infer(before, unit_id="u1").get("read_partial") == "pages"
    whole = [delivery, _pseudo([0, 40, 120]), _pseudo([40, 120, 120], offset=40)]
    assert _infer(whole, unit_id="u1") == {"basis": "unit_delivered", "material_cut": True}


def test_a_material_shown_whole_needs_no_page_of_the_subject() -> None:
    """T-G8d: a delivery that showed the subject whole stays ``unit_delivered`` with
    ``material_cut`` false, whatever pages of it were read after — the material's own reading
    (``_shown_whole``) is untouched."""
    delivery = {"tool": "start_diff_review", "params": {}, "unit": "u1", "unit_material_cut": False}
    got = _infer([delivery, _pseudo([0, 40, 120])], unit_id="u1")
    assert got == {"basis": "unit_delivered", "material_cut": False}


def test_a_file_read_for_one_page_of_its_hunk_is_partial() -> None:
    """★ T-G8a: get_file_diff read for the first page of a file's line difference only:
    ``read_partial``; every page: none.

    MUTATION (verified RED, 1 failed): key a file's stream by function (None for every file) and
    ignore the path -> still partial here, but a whole read of ANOTHER file then covers this one
    (second assert) -> RED."""
    first = _read("get_file_diff", [0, 30, 70], run_pair="a::b", path="etc/rc")
    rest = _read("get_file_diff", [30, 70, 70], run_pair="a::b", path="etc/rc", hunk_offset=30)
    other = _read("get_file_diff", [0, 70, 70], run_pair="a::b", path="etc/other")
    assert _infer([first], anchor_ref=FILE)["read_partial"] == "pages"
    assert _infer([first, other], anchor_ref=FILE)["read_partial"] == "pages"
    assert "read_partial" not in _infer([first, rest], anchor_ref=FILE)


def test_a_callee_list_the_scan_cut_is_an_extraction_cap_not_a_page_to_read_on() -> None:
    """★ T-G8c: a get_callees answer whose list the scan stored cut short (``callees_truncated``)
    is one whole page that still is not all of it: ``read_partial: "extraction_cap"`` — a kind
    apart from "pages", since reading on cannot complete it. A whole pseudocode read beside it
    clears it; a pseudocode read only in part leaves the cap (the only whole stream).

    MUTATION (verified RED, 1 failed): treat a capped stream as whole -> no flag -> RED.
    MUTATION (verified RED, 1 failed): report every partial read as "pages" -> RED."""
    callees = _read("get_callees", [0, 512, 512], cap=True, function="00402000")
    assert _infer([callees]).get("read_partial") == "extraction_cap"
    assert _infer([callees, _pseudo([0, 40, 120])]).get("read_partial") == "extraction_cap"
    assert "read_partial" not in _infer([callees, _pseudo([0, 120, 120])])
    plain = _read("get_callees", [0, 3, 3], function="00402000")
    assert "read_partial" not in _infer([plain])


def test_an_entry_read_is_read_by_its_rows_not_by_pages() -> None:
    """T-G8e: an entry read by entry_id is the rows' reading (``rows_partial``), never
    ``read_partial`` — the two keys stay apart, whatever pages of its function were also read."""
    entry = {
        "tool": "get_diff_patch_view",
        "params": {"entry_id": ENTRY},
        "rows_read": [0, 3, 3],
    }
    got = _infer([entry, _pseudo([0, 40, 120])])
    assert got == {"basis": "fetched"}


# ── tool_call_log: the window a page held ───────────────────────────────────────────────────


def _paging(offset: int, returned: int, total: int, key: str) -> dict[str, Any]:
    return {"offset": offset, "returned": returned, key: total, "next_offset": None}


@pytest.mark.parametrize(
    ("tool", "args", "result", "window"),
    [
        (
            "get_pseudocode",
            {"function": "f"},
            {"pseudocode": "x", "paging": _paging(40, 40, 120, "total_lines")},
            [40, 80, 120],
        ),
        (
            "get_disassembly",
            {"function": "f"},
            {"instructions": [], "paging": _paging(0, 30, 90, "total_matched")},
            [0, 30, 90],
        ),
        ("get_disassembly", {"function": "f"}, {"available": True, "total": 0}, [0, 0, 0]),
        ("get_disassembly", {"function": "f"}, {"available": False}, None),
        ("get_callees", {"function": "f"}, {"callees": [{"name": "a"}, {"name": "b"}]}, [0, 2, 2]),
        (
            "get_file_diff",
            {"path": "etc/rc"},
            {"entry": {"hunk": {"lines": ["a", "b"], "hunk_offset": 4, "total_pieces": 9}}},
            [4, 6, 9],
        ),
        (
            "get_file_diff",
            {"path": "etc/rc"},
            {"entry": {"hunk_shape": {"segments": [{}], "hunk_offset": 0, "total_segments": 1}}},
            [0, 1, 1],
        ),
        ("get_file_diff", {"path": "etc/rc"}, {"entry": {"hunk_unavailable": "binary"}}, [0, 0, 0]),
        ("get_file_diff", {"path": "etc/rc", "offset": 3}, {"entry": {"hunk_on_page": 0}}, None),
        (
            "get_file_diff",
            {"path": "etc/rc", "detail": "summary"},
            {"entry": {"hunk_stats": {"segments": 2}}},
            None,
        ),
        ("get_file_diff", {}, {"entries": []}, None),
    ],
    ids=[
        "pseudocode_lines",
        "disassembly_insns",
        "disassembly_empty",
        "disassembly_unavailable",
        "callees",
        "file_hunk",
        "file_shape",
        "file_no_text",
        "file_text_elsewhere",
        "file_summary",
        "file_list_page",
    ],
)
def test_the_log_records_the_window_a_page_held(
    tool: str, args: dict[str, Any], result: dict[str, Any], window: list[int] | None
) -> None:
    """★ T-G8a: each paged read logs ``page_rows`` = ``[start, end, total]`` in the unit its tool
    pages by; a page that held no part of the subject logs none (and so reads as partial).

    MUTATION (verified RED, 1 failed): read the pseudocode total from ``total_matched`` (the
    byte-paged tools' key) -> pseudocode_lines RED. MUTATION (verified RED, 1 failed): window a
    file page holding no text as the empty whole window -> file_summary / file_text_elsewhere
    RED."""
    line = tcl.build_line(tcl.Session(), tool, args, result)
    assert line.get("page_rows") == window


def test_a_cut_callee_list_is_logged_as_an_extraction_cap() -> None:
    """T-G8c: ``callees_truncated`` on a get_callees answer is logged as ``extraction_cap``."""
    cut = tcl.build_line(
        tcl.Session(), "get_callees", {"function": "f"}, {"callees": [], "callees_truncated": True}
    )
    whole = tcl.build_line(
        tcl.Session(), "get_callees", {"function": "f"}, {"callees": [], "callees_truncated": False}
    )
    assert cut.get("extraction_cap") is True and "extraction_cap" not in whole


def test_the_row_windows_are_logged_as_before() -> None:
    """★ T-G8f: ``page_rows`` is new beside the row windows: an entry read still logs
    ``rows_read`` in its shape and no ``page_rows``; a unit's partial rows still log
    ``unit_rows``."""
    entry = {"entry_id": ENTRY, "rows": [{}, {}], "rows_total": 5, "rows_offset": 2}
    line = tcl.build_line(
        tcl.Session(), "get_diff_patch_view", {"entry_id": ENTRY}, {"entries": [entry]}
    )
    assert line.get("rows_read") == [2, 4, 5] and "page_rows" not in line
    material = {"entries": [{"entry_id": ENTRY, "rows": [{}], "rows_total": 3}]}
    unit = {"unit_id": "u1", "material": material}
    line = tcl.build_line(tcl.Session(), "start_diff_review", {}, {"next_unit": unit})
    assert line.get("unit_rows") == {ENTRY: [0, 1, 3]} and "page_rows" not in line


# ── through the server: a long function's pseudocode read one page at a time ────────────────


def _long_world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[World, str]:
    """One aligned pair in DX at 0x1000, its B side a function of ~3 pages of pseudocode."""
    w = World(tmp_path, monkeypatch)
    w.pair(DX, "00001000", "00001000")
    w.rows[DX] = [_row(_ref("runA", "00001000"), _ref("runB", "00001000"))]
    text = "".join(f"    v{i} = call_{i}(v{i - 1}, 0x{i:04x}); // line {i}\n" for i in range(1500))
    assert len(text) > 2 * 20_000  # the precondition: more than two pages
    conn = sqlite3.connect(tmp_path / "analysis_b.db")
    conn.execute(
        "INSERT INTO functions (binary_id, name, address, pseudocode, callees) "
        "VALUES (1, 'big_fn', '00001000', ?, '[]')",
        (text,),
    )
    conn.commit()
    conn.close()
    return w, _pair_anchor(DX, "00001000", "00001000")


def _call(server: Any, name: str, args: dict[str, Any]) -> dict[str, Any]:
    from tests.unit.test_tool_surface import _call as call

    return call(server, name, args)


def _judge(server: Any, anchor: str) -> dict[str, Any]:
    args = {"anchor_ref": anchor, "verdict": "changed_real", "rationale": "r", "diff_id": DX}
    return _call(server, "annotate_diff", args)


def test_a_judgement_after_one_page_of_a_long_function_counts_basis_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ T-G8a end to end: get_pseudocode's first page of a three-page function, then a judgement:
    ``read_partial: "pages"``, disposed, and counted under ``basis_incomplete`` (+1 in the
    coverage statement). Every page read and judged again: nothing incomplete.

    MUTATION (verified RED, 1 failed): leave read_partial out of read_audits' basis_incomplete
    -> RED. MUTATION (verified RED, 1 failed): log no page_rows for get_pseudocode -> every read
    unlogged, the second judgement still partial -> RED."""
    ru.DIFF_CACHE.clear()
    w, anchor = _long_world(tmp_path, monkeypatch)
    server = mcp_app.build_server(w.path)
    page = _call(server, "get_pseudocode", {"run_id": "runB", "function": "0x1000"})
    assert page["paging"]["truncated"] is True, page.get("paging")
    got = _judge(server, anchor)
    assert got["read_basis"] == {"basis": "fetched", "read_partial": "pages"}
    review = ru.review_pair(
        w.atlas, "runA", "runB", k=4, pair_staleness={"source_stale": False}, server_commit="c"
    )
    assert ru.disposed(review.progress.states.get(anchor))
    assert review.report["basis_incomplete"]["subjects"] == [anchor]
    assert "basis incomplete 1;" in review.report["coverage_statement"]
    offset = page["paging"]["next_offset"]
    while offset is not None:
        nxt = _call(
            server, "get_pseudocode", {"run_id": "runB", "function": "0x1000", "offset": offset}
        )
        offset = nxt["paging"]["next_offset"]
    got = _judge(server, anchor)
    assert got["read_basis"] == {"basis": "fetched"}
    ru.DIFF_CACHE.clear()
    review = ru.review_pair(
        w.atlas, "runA", "runB", k=4, pair_staleness={"source_stale": False}, server_commit="c"
    )
    assert review.report["basis_incomplete"]["count"] == 0
    assert PAIR in review.report["run_pair"]
