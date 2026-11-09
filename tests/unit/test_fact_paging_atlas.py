# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Paging of the atlas-backed fact tools whose answers grow with the firmware.

Each list is put in one total order and cut into pages: every page holds at most ``limit`` rows
and at most the response budget's bytes, ``next_offset`` resumes right after the last row a page
holds (null only once every row is read), and the totals are exact. A page is never a filter:
walking ``offset = next_offset`` reads every row exactly once. The answers' own older fields
(``count`` / ``truncated`` of the edge listings, ``page`` of get_diff_deltas) keep what they
meant. The answers are read through make_tools, the functions the MCP server registers; the
budget is lowered with monkeypatch where a test needs the byte ceiling to cut.

Two kinds of tie-break are guarded differently. The Python-sorted lists (nvram) are ordered by
their content last, so two atlases holding the same rows in opposite insertion order page
identically. The SQL-ordered lists (string-keyed edges, exec edges) end their ORDER BY on the row
id; SQLite in practice returns tied rows in rowid order whether or not the query names it, so
dropping the id cannot be seen in the rows — the guard reads the statement actually executed
(the connection's trace callback) and requires its ORDER BY to end on ``id``."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from tests.unit.lib.test_sink_provenance import _addr_ref, _seed
from treasure_map import mcp_app
from treasure_map.lib import tool_call_log as tcl
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import (
    DimensionDeltaRow,
    ExecEdgeRow,
    NvramFlowRow,
    StringKeyedEdgeRow,
)
from treasure_map.lib.atlas.writer import (
    add_dimension_deltas,
    add_exec_edges,
    add_nvram_flow_rows,
    add_string_keyed_edges,
)
from treasure_map.lib.query import exec_edges, paging, string_edges
from treasure_map.lib.query.nvram import get_nvram_key_flow
from treasure_map.lib.query.triage import get_sink_provenance as lib_provenance

_FUNC = 0x400000
Tools = dict[str, Callable[..., Any]]


def _size(obj: Any) -> int:
    return len(json.dumps(obj))


def _tools(atlas: Path) -> Tools:
    return mcp_app.make_tools(atlas)


def _walk(call: Callable[..., dict[str, Any]], rows: str, **args: Any) -> list[dict[str, Any]]:
    """Every page of ``call`` from offset 0, following next_offset until null; each page within
    the budget and holding at least one row while rows remain."""
    out: list[dict[str, Any]] = []
    offset: int | None = 0
    pages = 0
    while offset is not None:
        page = call(**args, offset=offset)
        assert "error" not in page, page.get("error")
        assert "over_budget" not in page
        assert _size(page) <= mcp_app._RESPONSE_BYTE_BUDGET
        out.extend(page[rows])
        nxt = page["next_offset"]
        assert nxt is None or nxt == offset + len(page[rows])
        assert nxt is None or page[rows], "a page before the end holds a row"
        offset = nxt
        pages += 1
        assert pages < 500
    return out


# ── get_sink_provenance: every-record mode pages ──────────────────────────────────────────────


def _records(n: int, pad: int = 300) -> list[dict[str, Any]]:
    """``n`` sink records of one function, each a few hundred bytes wide."""
    out = []
    for i in range(n):
        writer = f"snprintf@{hex(_FUNC + 0x10 * i - 4)}"
        out.append(
            {
                "sink_idx": i,
                "sink": "system",
                "sink_addr": hex(_FUNC + 0x10 * i),
                "arg_idx": 0,
                "provenance": {
                    "kind": "stack_buf",
                    "stack_key": f"frame[{i}]",
                    "writer_count": 1,
                    "nearest_dominating_writer": writer,
                    "writers": [
                        {
                            "writer": writer,
                            "dominates_sink": True,
                            "fmt": f"/usr/sbin/tool --opt {i} " + "c" * pad,
                            "varargs": [],
                        }
                    ],
                },
            }
        )
    return out


def _provenance_atlas(tmp_path: Path, n: int, pad: int = 300) -> str:
    ref = _addr_ref(_FUNC, _FUNC + 0x10 * 3)
    _seed(tmp_path, ref=ref, provenance=_records(n, pad))
    return ref


def test_the_library_pages_every_record_mode_in_stored_order(tmp_path: Path) -> None:
    """T-J1 (library): limit/offset cut the stored record list; the pages joined are the whole
    list, total_records counts every record, an offset past the end is an empty page.

    MUTATION (verified RED, 1 failed): page_list ignores offset (rows[:limit]) -> RED."""
    ref = _provenance_atlas(tmp_path, 23)
    conn = open_atlas(tmp_path / "atlas.db")
    try:
        whole = lib_provenance(conn, ref)
        assert whole["total_records"] == 23 and len(whole["records"]) == 23
        joined = []
        for off in range(0, 23, 5):
            page = lib_provenance(conn, ref, limit=5, offset=off)
            assert page["total_records"] == 23
            joined += page["records"]
        assert json.dumps(joined) == json.dumps(whole["records"])
        past = lib_provenance(conn, ref, limit=5, offset=40)
        assert past["records"] == [] and past["total_records"] == 23
    finally:
        conn.close()


def test_a_provenance_over_the_budget_comes_in_pages_that_read_every_record(
    tmp_path: Path,
) -> None:
    """T-J1: 150 records (well over the budget whole): the first page is within the budget, cut
    by bytes before limit, with a non-null next_offset; following next_offset reads all 150, once,
    in order.

    MUTATION (verified RED, 1 failed): return get_sink_provenance's result without _fit_page ->
    the first page holds 100 records and is over the budget -> RED."""
    ref = _provenance_atlas(tmp_path, 150)
    tools = _tools(tmp_path / "atlas.db")
    first = tools["get_sink_provenance"](evidence_ref=ref)
    assert _size(first) <= mcp_app._RESPONSE_BYTE_BUDGET
    assert first["total_records"] == 150
    assert 0 < len(first["records"]) < 100 and first["truncated_by_bytes"] is True
    assert first["next_offset"] == len(first["records"])
    got = _walk(tools["get_sink_provenance"], "records", evidence_ref=ref)
    assert [r["sink_idx"] for r in got] == list(range(150))


def test_the_pages_joined_are_the_single_records_read_one_by_one(tmp_path: Path) -> None:
    """T-J1c: the records the pages hold, joined, are byte for byte the records sink_idx reads
    one at a time (the same presentation: dominating-first, the own-callsite flag).

    MUTATION (verified RED, 1 failed): every-record mode returns the stored records without
    _marked (no presentation, no own-callsite flag) -> RED."""
    ref = _provenance_atlas(tmp_path, 60)
    tools = _tools(tmp_path / "atlas.db")
    paged = _walk(tools["get_sink_provenance"], "records", evidence_ref=ref, limit=7)
    one_by_one = [
        tools["get_sink_provenance"](evidence_ref=ref, sink_idx=i)["record"] for i in range(60)
    ]
    assert any(r.get("is_candidate_callsite") is True for r in one_by_one)
    assert json.dumps(paged, sort_keys=True) == json.dumps(one_by_one, sort_keys=True)


# ── get_nvram_key_flow: three lists, one shared index ────────────────────────────────────────

_KEY = "wan_ifname"


def _nvram_rows(order: int = 1) -> list[NvramFlowRow]:
    """30 writers (all of one binary and function: tied on the displayed order, told apart only
    by api), 2 readers, 3 matching templates. ``order`` -1 inserts them reversed."""
    rows = [
        NvramFlowRow(
            source_run_id="run_n",
            key=_KEY,
            key_kind="constant",
            binary="cfgd",
            func="apply",
            op="write",
            api=f"nvram_set_{i:02d}",
        )
        for i in range(30)
    ]
    rows += [
        NvramFlowRow(
            source_run_id="run_n",
            key=_KEY,
            key_kind="constant",
            binary=f"reader{i}",
            func="get",
            op="read",
            api="nvram_get",
        )
        for i in range(2)
    ]
    rows += [
        NvramFlowRow(
            source_run_id="run_n",
            key="wan%s",
            key_kind="parametric",
            binary=f"tmpl{i}",
            func="t",
            op="read",
            api="nvram_get",
        )
        for i in range(3)
    ]
    return rows[::order]


def _nvram_atlas(tmp_path: Path, order: int = 1) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    conn = open_atlas(tmp_path / "atlas.db")
    add_nvram_flow_rows(conn, _nvram_rows(order))
    conn.close()
    return tmp_path / "atlas.db"


def test_the_nvram_lists_page_at_one_index_each_in_its_place(tmp_path: Path) -> None:
    """T-J12: a long writers list beside 2 readers: ONE top-level next_offset (non-null while
    writers remain), exact totals per list, writers / readers / template_matches where they always
    are; following next_offset reads every list to its end, and found / match / completeness are
    the whole graph's on every page.

    MUTATION (verified RED, 1 failed): _fit_lists writes its paging fields into a nested block
    (result["paging"]) instead of the top level -> RED.
    MUTATION (verified RED, 1 failed): page_nvram_key_flow pages writers only (readers whole on
    every page) -> RED."""
    atlas = _nvram_atlas(tmp_path)
    tools = _tools(atlas)
    conn = open_atlas(atlas)
    try:
        whole = get_nvram_key_flow(conn, _KEY)
    finally:
        conn.close()
    assert len(whole["writers"]) == 30 and len(whole["readers"]) == 2
    assert len(whole["template_matches"]) == 3
    first = tools["get_nvram_key_flow"](key=_KEY, limit=4)
    assert first.get("next_offset") == 4
    totals = ("total_writers", "total_readers", "total_template_matches")
    assert tuple(first.get(k) for k in totals) == (
        30,
        2,
        3,
    )
    assert len(first["writers"]) == 4 and len(first["readers"]) == 2
    got: dict[str, list[Any]] = {"writers": [], "readers": [], "template_matches": []}
    offset: int | None = 0
    while offset is not None:
        page = tools["get_nvram_key_flow"](key=_KEY, limit=4, offset=offset)
        assert {"writers", "readers", "template_matches", "next_offset"} <= set(page)
        assert page["found"] is True and page["match"] == "exact"
        assert page["completeness"] == whole["completeness"]
        for name in got:
            got[name] += page[name]
        offset = page.get("next_offset")
    for name, rows in got.items():
        assert sorted(map(json.dumps, rows)) == sorted(map(json.dumps, whole[name])), name
        assert len(rows) == len({json.dumps(r) for r in rows}), name


def test_the_nvram_page_order_is_the_rows_not_their_storage(tmp_path: Path) -> None:
    """T-J15: the writers all tie on (binary, func); two atlases holding the same rows inserted in
    opposite order give the same pages, row for row — the order is total on the rows themselves,
    so no tie depends on how the rows happen to be stored.

    MUTATION (verified RED, 1 failed): drop the content part of page_lists' sort key (order by
    the displayed fields only) -> the ties keep their storage order -> RED."""
    pages = []
    for order, where in ((1, "fwd"), (-1, "rev")):
        tools = _tools(_nvram_atlas(tmp_path / where, order))
        writers = []
        offset: int | None = 0
        while offset is not None:
            page = tools["get_nvram_key_flow"](key=_KEY, limit=6, offset=offset)
            writers += [w["api"] for w in page["writers"]]
            offset = page["next_offset"]
        pages.append(writers)
    assert pages[0] == pages[1]
    assert sorted(pages[0]) == [f"nvram_set_{i:02d}" for i in range(30)]


# ── get_string_keyed_edges: the old row-cap fields beside the new paging fields ──────────────


def _edges_atlas(tmp_path: Path, n: int = 12, pad: int = 0) -> Path:
    """``n`` static-table edges (from_function NULL, one key, one callee name: tied on the whole
    displayed order), told apart by callee_addr."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    conn = open_atlas(tmp_path / "atlas.db")
    add_string_keyed_edges(
        conn,
        [
            StringKeyedEdgeRow(
                source_run_id="run_e",
                binary="webd",
                from_function=None,
                key="k" + "x" * pad,
                mechanism="static_string_table",
                callee_name="handler",
                callee_addr=hex(0x1000 + i),
                table_addr="0x9000",
            )
            for i in range(n)
        ],
    )
    conn.close()
    return tmp_path / "atlas.db"


def _edge_width(atlas: Path) -> int:
    conn = open_atlas(atlas)
    try:
        return _size(string_edges.get_string_keyed_edges(conn, limit=1)["edges"][0])
    finally:
        conn.close()


def test_a_page_cut_by_bytes_keeps_the_row_cap_fields_apart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-J3: a limit above the rows (the row cap not reached) and a budget that holds 3 edges:
    ``truncated`` (the row cap) stays false, ``count`` is the edges on the page, ``total_edges``
    every edge, ``truncated_by_bytes`` says the budget ended it.

    MUTATION (verified RED, 1 failed): pass truncated="truncated" to _fit_page in
    get_string_keyed_edges -> the row-cap field reads the byte cut -> RED. (total_edges =
    len(edges) is the same answer here, every row fetched: the next test catches it.)"""
    atlas = _edges_atlas(tmp_path)
    tools = _tools(atlas)
    whole = tools["get_string_keyed_edges"](limit=200)
    assert whole["total_edges"] == 12 and whole["count"] == 12 and whole["truncated"] is False
    width = _edge_width(atlas)
    # next_offset's placeholder is null here: 12 is narrower than null.
    envelope = {**whole, "edges": [], "next_offset": None, "truncated_by_bytes": False}
    monkeypatch.setattr(mcp_app, "_RESPONSE_BYTE_BUDGET", _size(envelope) + 3 * width + 4 + 1)
    page = tools["get_string_keyed_edges"](limit=20)
    assert len(page["edges"]) == 3 and page["count"] == 3
    assert page["truncated"] is False and page.get("truncated_by_bytes") is True
    assert page.get("total_edges") == 12 and page.get("next_offset") == 3


def test_a_page_at_the_row_cap_says_so_and_the_total_is_exact(tmp_path: Path) -> None:
    """T-J3: limit reached, nothing cut by bytes: ``truncated`` true (the row cap, as before),
    ``count`` 5, ``truncated_by_bytes`` false, ``total_edges`` 12, ``next_offset`` 5.

    MUTATION (verified RED, 1 failed): total_edges = len(edges) -> the 5th row reads as the
    last -> RED."""
    tools = _tools(_edges_atlas(tmp_path))
    page = tools["get_string_keyed_edges"](limit=5)
    assert page["count"] == 5 and page["truncated"] is True
    assert page.get("truncated_by_bytes") is False
    assert page.get("total_edges") == 12 and page.get("next_offset") == 5


def test_tied_static_table_edges_page_once_each(tmp_path: Path) -> None:
    """T-J15 / T-J6: every edge ties on (from_function NULL, key, callee_name); pages of 5 joined
    are the unpaged list, row for row."""
    atlas = _edges_atlas(tmp_path)
    tools = _tools(atlas)
    got = _walk(tools["get_string_keyed_edges"], "edges", limit=5)
    conn = open_atlas(atlas)
    try:
        whole = string_edges.get_string_keyed_edges(conn)["edges"]
    finally:
        conn.close()
    assert json.dumps(got) == json.dumps(whole)
    assert len({e["callee"]["addr"] for e in got}) == 12


def _ordering(sql: str) -> list[str]:
    m = re.search(r"ORDER BY (.+?)(?: LIMIT| OFFSET|$)", sql, re.S)
    assert m is not None, sql
    return [part.strip() for part in m.group(1).split(",")]


def _executed(conn: sqlite3.Connection, run: Callable[[], Any]) -> list[str]:
    seen: list[str] = []
    conn.set_trace_callback(seen.append)
    try:
        run()
    finally:
        conn.set_trace_callback(None)
    return seen


def test_the_edge_listings_order_ends_on_the_row_id(tmp_path: Path) -> None:
    """T-J15: SQLite returns tied rows in rowid order whether or not the query says so, so a
    missing tie-break cannot be seen in the rows; the statement each listing EXECUTES is read
    instead, and its ORDER BY must end on the unique row id.

    MUTATION (verified RED, 1 failed): drop ", id" from get_string_keyed_edges' ORDER BY -> RED.
    MUTATION (verified RED, 1 failed): drop ", id" from launched_by's ORDER BY -> RED."""
    atlas = _edges_atlas(tmp_path)
    conn = open_atlas(atlas)
    try:
        ske = _executed(conn, lambda: string_edges.get_string_keyed_edges(conn, limit=3, offset=3))
        led = _executed(conn, lambda: exec_edges.launched_by(conn, "tgt", limit=3, offset=3))
    finally:
        conn.close()
    sel = [s for s in ske if "FROM string_keyed_edge" in s and "ORDER BY" in s]
    assert len(sel) == 1 and _ordering(sel[0])[-1] == "id", sel
    sel = [s for s in led if "FROM exec_edge" in s and "ORDER BY" in s]
    assert len(sel) == 1 and _ordering(sel[0])[-1] == "id", sel


# ── launched_by: a limit it always took unbounded is cut, said, and paged ────────────────────


def _exec_atlas(tmp_path: Path, n_a: int = 205, n_z: int = 45) -> Path:
    """``n_a`` edges from launchers named ``busybox`` at two paths (tied on launcher, function and
    sink address), then ``n_z`` from ``zz_init`` — which sorts last, so a first page of 200 holds
    none of them."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    conn = open_atlas(tmp_path / "atlas.db")

    def edge(binary: str, path: str, i: int) -> ExecEdgeRow:
        return ExecEdgeRow(
            source_run_id="run_x",
            launcher_binary=binary,
            launcher_function="main",
            exec_api="execv",
            target_token="/usr/sbin/tgt",
            target_resolution="resolved",
            target_binary="tgt",
            sink_addr="0x1000",
            launcher_addr=hex(0x2000 + i),
            launcher_binary_path=path,
            target_layer="exec_image",
        )

    rows = [edge("busybox", f"bin{i % 2}/busybox", i) for i in range(n_a)]
    rows += [edge("zz_init", "sbin/zz_init", n_a + i) for i in range(n_z)]
    add_exec_edges(conn, rows)
    conn.close()
    return tmp_path / "atlas.db"


def test_launched_by_cuts_a_huge_limit_says_so_and_pages_to_the_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-J14 / T-J18: limit=100000 is not an error; it is cut to 200 (``limit_clamped`` names the
    value asked for); total_edges is exact; next_offset is null only on the page that ends the
    list; launcher_binaries is read from every edge, the first page's included.

    MUTATION (verified RED, 1 failed): launched_by uses the limit as given (no clamp) -> RED.
    MUTATION (verified RED, 1 failed): launcher_binaries from the page's edges -> RED.
    MUTATION (verified RED, 1 failed): echo no limit_clamped -> RED."""
    monkeypatch.setattr(mcp_app, "_RESPONSE_BYTE_BUDGET", 10**9)
    tools = _tools(_exec_atlas(tmp_path))
    page = tools["launched_by"](target="tgt", limit=100000)
    assert "error" not in page
    assert page.get("limit_clamped") == 100000
    assert len(page["edges"]) == 200 and page["total_edges"] == 250
    assert page["next_offset"] == 200 and page["truncated"] is True
    assert {e["launcher"]["binary"] for e in page["edges"]} == {"busybox"}
    assert page["launcher_binaries"] == ["busybox", "zz_init"]
    last = tools["launched_by"](target="tgt", limit=100000, offset=200)
    assert len(last["edges"]) == 50 and last["next_offset"] is None
    assert last["launcher_binaries"] == ["busybox", "zz_init"]
    exact = tools["launched_by"](target="tgt", limit=50, offset=200)
    assert exact["next_offset"] is None and "limit_clamped" not in exact


def test_launched_by_pages_tied_launchers_once_each(tmp_path: Path) -> None:
    """T-J15 / T-J6: two binaries named busybox (different paths) tie on launcher, function and
    sink address; walking the pages (the budget cutting them) reads every edge once, in the
    unpaged order.

    MUTATION (verified RED, 1 failed): launched_by slices every[offset:limit] (drops the offset
    from the end index) -> RED."""
    atlas = _exec_atlas(tmp_path, n_a=60, n_z=5)
    tools = _tools(atlas)
    got = _walk(tools["launched_by"], "edges", target="tgt", limit=7)
    conn = open_atlas(atlas)
    try:
        whole = exec_edges.launched_by(conn, "tgt")["edges"]
    finally:
        conn.close()
    assert json.dumps(got) == json.dumps(whole) and len(got) == 65


# ── get_diff_deltas: the byte gate lives in the library's own page block ────────────────────

_DIFF = "run_a::run_b::webd"


def _deltas_atlas(tmp_path: Path, n: int, pad: int = 40) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    conn = open_atlas(tmp_path / "atlas.db")
    add_dimension_deltas(
        conn,
        [
            DimensionDeltaRow(
                diff_id=_DIFF,
                dimension="string_edge",
                subject_kind="edge",
                subject_key=f"key_{i:03d}_" + "s" * pad,
                delta_kind="layer_changed",
                state_a="a",
                state_b="b",
                binary="webd",
            )
            for i in range(n)
        ],
    )
    conn.close()
    return tmp_path / "atlas.db"


def test_a_delta_page_cut_by_bytes_resumes_from_its_own_page_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-J22: the budget cuts a page of 100: ``page`` (the one paging block, no top-level
    next_offset) says what fits — count every delta as before, returned the deltas kept,
    next_offset right after them, truncated whether more follow, truncated_by_bytes; following
    page.next_offset reads every delta once, in id order.

    MUTATION (verified RED, 1 failed): _fit_deltas sets truncated_by_bytes only (page's
    returned / next_offset / truncated left as the library's) -> the cut rows are never read ->
    RED.
    MUTATION (verified RED, 1 failed): _fit_deltas also writes a top-level next_offset -> RED."""
    tools = _tools(_deltas_atlas(tmp_path, 30))
    whole = tools["get_diff_deltas"](diff_id=_DIFF, limit=200)
    assert len(whole["deltas"]) == 30 and whole["page"]["truncated_by_bytes"] is False
    monkeypatch.setattr(mcp_app, "_RESPONSE_BYTE_BUDGET", _size(whole) - 2_000)
    got: list[dict[str, Any]] = []
    offset: int | None = 0
    cut = 0
    while offset is not None:
        res = tools["get_diff_deltas"](diff_id=_DIFF, offset=offset)
        assert "next_offset" not in res and "over_budget" not in res
        assert _size(res) <= mcp_app._RESPONSE_BYTE_BUDGET
        page = res["page"]
        assert page["count"] == 30 and page["returned"] == len(res["deltas"])
        assert page["truncated"] is (page["next_offset"] is not None)
        cut += page["truncated_by_bytes"]
        got += res["deltas"]
        offset = page["next_offset"]
    assert cut >= 1
    assert json.dumps(got) == json.dumps(whole["deltas"])


def test_a_huge_delta_limit_is_cut_to_the_cap_and_said(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-J14: get_diff_deltas has always taken any limit and documents paging with it: 100000
    is not an error, it is cut to 200 and the answer says so.

    MUTATION (verified RED, 1 failed): get_diff_deltas passes the limit as given -> RED."""
    monkeypatch.setattr(mcp_app, "_RESPONSE_BYTE_BUDGET", 10**9)
    tools = _tools(_deltas_atlas(tmp_path, 250, pad=0))
    res = tools["get_diff_deltas"](diff_id=_DIFF, limit=100000)
    assert "error" not in res and res.get("limit_clamped") == 100000
    assert len(res["deltas"]) == 200 and res["page"]["next_offset"] == 200
    plain = tools["get_diff_deltas"](diff_id=_DIFF, limit=10)
    assert "limit_clamped" not in plain


# ── the local fitters: one index, placeholders no narrower than the final values ────────────


def _lists_result(n_a: int, n_b: int, width: int) -> dict[str, Any]:
    return {
        "found": True,
        "a": [{"v": f"a{i:04d}" + "x" * width} for i in range(n_a)],
        "b": [{"v": f"b{i:04d}" + "y" * (width // 2)} for i in range(n_b)],
        "total_a": n_a + 200_000,  # wider than null, so the placeholder is the total
        "total_b": n_b,
    }


def _index_cost(result: dict[str, Any], i: int) -> int:
    return sum(
        _size(rows[i]) + (2 if i else 0) for rows in (result["a"], result["b"]) if i < len(rows)
    )


def test_fit_lists_cuts_every_list_at_one_index_and_each_page_is_full() -> None:
    """_fit_lists, every budget from a little under one index to the whole page, a byte at a
    time: both lists are cut at the same index; a page that is cut is within the budget and FULL
    (with the paging fields at their placeholders, the next index would not have fitted);
    next_offset resumes at offset + kept (non-null while a list has rows past it).

    MUTATION (verified RED, 1 failed): measure the envelope with next_offset null instead of the
    widest placeholder -> a page over the budget -> RED.
    MUTATION (verified RED, 1 failed): cut each list on its own (b keeps its rows past the index
    a stopped at) -> RED."""
    base = _lists_result(12, 5, 40)
    whole = _size({**base, "next_offset": 100_012, "truncated_by_bytes": False})
    seen_cut = set()
    for budget in range(whole - 900, whole + 30):
        res = mcp_app._fit_lists(json.loads(json.dumps(base)), 100_000, ("a", "b"), budget=budget)
        kept = len(res["a"])
        assert res["a"] == base["a"][:kept] and res["b"] == base["b"][: min(kept, 5)]
        assert res["next_offset"] == 100_000 + kept  # total_a has rows past every page
        if res.get("over_budget"):
            assert kept == 1
            continue
        assert _size(res) <= budget
        if kept < 12:
            assert res["truncated_by_bytes"] is True
            placeholder = {**res, "next_offset": 200_012, "truncated_by_bytes": False}
            assert _size(placeholder) + _index_cost(base, kept) > budget
            seen_cut.add(budget)
        else:
            assert res["truncated_by_bytes"] is False
    assert len(seen_cut) > 500


def test_fit_lists_keeps_one_index_when_one_row_is_over_the_budget() -> None:
    """T-J8 (shape): one row wider than the budget: the page holds it (never an empty page that
    reads as 'nothing here') and says over_budget; next_offset still resumes after it."""
    res = mcp_app._fit_lists(_lists_result(3, 3, 5_000), 0, ("a", "b"), budget=1_000)
    assert len(res["a"]) == 1 and len(res["b"]) == 1
    assert res["over_budget"] is True and res["next_offset"] == 1


def test_fit_lists_reads_the_end_and_leaves_an_undetermined_list() -> None:
    """next_offset is null only when EVERY list is read to its end; a list that is None (not
    determined) stays None; an error answer is returned as it is."""
    res = {"x": [1, 2], "y": None, "total_x": 2, "total_y": None}
    out = mcp_app._fit_lists(res, 0, ("x", "y"))
    assert out["x"] == [1, 2] and out["y"] is None and out["next_offset"] is None
    res = {"x": [1, 2], "z": [1], "total_x": 2, "total_z": 9}
    assert mcp_app._fit_lists(res, 0, ("x", "z"))["next_offset"] == 2
    err = {"error": "e"}
    assert mcp_app._fit_lists(err, 0, ("x",)) == {"error": "e"}


def _deltas_result(n: int, total: int, offset: int = 0) -> dict[str, Any]:
    deltas = [{"id": i, "k": "z" * 60} for i in range(offset, offset + n)]
    hi = offset + n
    return {
        "diff_id": "d",
        "deltas": deltas,
        "page": {
            "count": total,
            "returned": n,
            "offset": offset,
            "truncated": hi < total,
            "next_offset": hi if hi < total else None,
        },
    }


def test_fit_deltas_recomputes_its_page_block_for_what_fits() -> None:
    """_fit_deltas over a byte-by-byte budget sweep: within the budget (or one delta and
    over_budget), page.count unchanged, returned / next_offset / truncated for the deltas kept,
    truncated_by_bytes when the budget ended the page, and a cut page is full.

    MUTATION (verified RED, 1 failed): measure the envelope with page.next_offset null instead of
    the count (wider here) -> a page over the budget -> RED."""
    whole = _size(_deltas_result(20, 500_000, 400_000))
    cuts = 0
    for budget in range(whole - 900, whole + 60):
        res = mcp_app._fit_deltas(_deltas_result(20, 500_000, 400_000), budget=budget)
        page, kept = res["page"], len(res["deltas"])
        assert page["count"] == 500_000 and page["returned"] == kept
        assert page["next_offset"] == 400_000 + kept and page["truncated"] is True
        assert "next_offset" not in res
        if res.get("over_budget"):
            assert kept == 1
            continue
        assert _size(res) <= budget
        assert page["truncated_by_bytes"] is (kept < 20)
        if kept < 20:
            cuts += 1
            wide = {
                **res,
                "page": {
                    **page,
                    "returned": 20,
                    "next_offset": 500_000,  # the count is wider than null: the placeholder
                    "truncated": False,
                    "truncated_by_bytes": False,
                },
            }
            assert _size(wide) + _size(res["deltas"][0]) + 2 > budget
    assert cuts > 500
    last = mcp_app._fit_deltas(_deltas_result(5, 15, 10))
    assert last["page"]["next_offset"] is None and last["page"]["truncated"] is False


def test_the_paging_argument_checks() -> None:
    """The three argument checks: the 1.._MAX_LIMIT range and offset >= 0 (a bool is no number);
    a limit a tool always took unbounded is brought into range and the asked value returned."""
    ok = mcp_app._page_args_error
    assert ok(1, 0) is None and ok(200, 5) is None
    for limit, offset in ((0, 0), (201, 0), (True, 0), ("5", 0), (5, -1), (5, True), (5, None)):
        err = ok(limit, offset)
        assert err is not None and "error" in err, (limit, offset)
    assert "1..200" in ok(201, 0)["error"] and ">= 0" in ok(5, -1)["error"]
    clamp = mcp_app._clamped_limit
    assert clamp(50, 1) == (50, None) and clamp(200, 0) == (200, None)
    assert clamp(100000, 1) == (200, 100000) and clamp(0, 1) == (1, 0) and clamp(-3, 0) == (0, -3)
    assert isinstance(clamp(True, 0), dict) and isinstance(clamp(2.5, 0), dict)
    assert mcp_app._offset_error(0) is None
    assert mcp_app._offset_error(-1) is not None and mcp_app._offset_error(True) is not None


# ── the call log reads a cut page as cut ──────────────────────────────────────────────────────


def test_a_page_cut_by_bytes_is_logged_as_a_partial_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-J2: three shapes the byte ceiling cut — top-level (string-keyed edges, its row cap not
    reached), shared top-level (nvram) and the page block (get_diff_deltas) — each make the log
    line's ``truncated`` true, read by the log from the answer's own fields.

    MUTATION (verified RED, 1 failed): get_string_keyed_edges passes next_offset="next_page",
    truncated="cut_by_bytes" to _fit_page -> RED.
    MUTATION (verified RED, 1 failed): _fit_lists names its fields next_index / bytes_cut -> RED.
    MUTATION (verified RED, 1 failed): _fit_deltas writes its page fields into page["fit"] (one
    level deeper than the log reads) -> RED."""
    session = tcl.Session()
    calls: dict[str, Callable[[], dict[str, Any]]] = {}
    edges = _tools(_edges_atlas(tmp_path / "e"))
    calls["get_string_keyed_edges"] = lambda: edges["get_string_keyed_edges"](limit=200)
    nvram = _tools(_nvram_atlas(tmp_path / "n"))
    calls["get_nvram_key_flow"] = lambda: nvram["get_nvram_key_flow"](key=_KEY)
    deltas = _tools(_deltas_atlas(tmp_path / "d", 30))
    calls["get_diff_deltas"] = lambda: deltas["get_diff_deltas"](diff_id=_DIFF)
    answers = {}
    for tool, call in calls.items():
        # A budget a few rows short of the whole answer: cut by bytes, the page itself within it
        # (an over_budget page would read as cut whatever its paging fields say).
        whole = call()
        assert whole.get("truncated_by_bytes") in (False, None)
        monkeypatch.setattr(mcp_app, "_RESPONSE_BYTE_BUDGET", _size(whole) - 300)
        answers[tool] = call()
        assert "over_budget" not in answers[tool], tool
        monkeypatch.undo()
    for tool, answer in answers.items():
        assert tcl.build_line(session, tool, {}, answer)["truncated"] is True, tool
    # each was cut by the byte ceiling, not by a row cap
    assert answers["get_string_keyed_edges"].get("truncated") is False
    assert answers["get_string_keyed_edges"].get("truncated_by_bytes") is True
    assert answers["get_nvram_key_flow"].get("truncated_by_bytes") is True
    assert answers["get_diff_deltas"]["page"].get("truncated_by_bytes") is True


# ── argument checks of the tools that page now ───────────────────────────────────────────────

_NEW_PAGED = {
    "get_sink_provenance": {"evidence_ref": "run_x#fn@cmd"},
    "get_xrefs": {"run_id": "r", "function": "f"},
    "get_imports_exports": {"run_id": "r", "binary": "b"},
    "get_nvram_key_flow": {"key": "k"},
    "get_string_keyed_edges": {},
    "get_functions_referencing_string": {"run_id": "r", "text": "t"},
    "get_function_alignment": {"diff_id": _DIFF, "function": "f"},
    "list_overlays": {},
    "list_diffs": {},
}


@pytest.mark.parametrize("tool", sorted(_NEW_PAGED))
@pytest.mark.parametrize(
    ("bad", "says"),
    [
        ({"limit": 201}, "1..200"),
        ({"limit": 0}, "1..200"),
        ({"limit": True}, "1..200"),
        ({"offset": -1}, ">= 0"),
        ({"offset": True}, ">= 0"),
    ],
)
def test_a_tool_that_pages_now_refuses_a_bad_page_argument(
    tmp_path: Path, tool: str, bad: dict[str, Any], says: str
) -> None:
    """T-J14: each of the nine tools given limit/offset refuses a limit outside 1..200, an offset
    below 0, and a bool for either (Python counts True as 1), naming the range.

    MUTATION (verified RED, 45 failed): _page_args_error returns None -> RED."""
    tools = _tools(tmp_path / "atlas.db")
    got = tools[tool](**_NEW_PAGED[tool], **bad)
    assert says in str(got.get("error")), got


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("launched_by", {"target": "t"}),
        ("get_string_reference_anchors", {"run_id": "r", "text": "t"}),
        ("get_diff_deltas", {"diff_id": _DIFF}),
    ],
)
@pytest.mark.parametrize("bad", [{"limit": True}, {"offset": True}])
def test_a_tool_with_an_old_limit_refuses_a_bool(
    tmp_path: Path, tool: str, args: dict[str, Any], bad: dict[str, Any]
) -> None:
    """T-J14: the three tools whose limit was always unbounded cut a large one, but a bool for
    limit or offset is no number and is refused.

    MUTATION (verified RED, 3 failed): _clamped_limit drops its bool check -> RED."""
    got = _tools(tmp_path / "atlas.db")[tool](**args, **bad)
    assert "error" in got and "integer" in str(got["error"]), got


def test_the_sink_overlay_still_takes_a_limit_of_2000(tmp_path: Path) -> None:
    """T-J14: get_diff_sink_overlay keeps its own 1..2000 range (its docstring promises it); a
    limit of 2000 is not refused, and the answer is within the budget.

    MUTATION (verified RED, 1 failed): check its limit against _MAX_LIMIT (200) -> RED."""
    got = _tools(tmp_path / "atlas.db")["get_diff_sink_overlay"](
        diff_id=_DIFF, detail="rows", limit=2000
    )
    assert "limit must" not in str(got.get("error"))
    assert _size(got) <= mcp_app._RESPONSE_BYTE_BUDGET
    assert "1..2000" in str(
        _tools(tmp_path / "atlas.db")["get_diff_sink_overlay"](
            diff_id=_DIFF, detail="rows", limit=2001
        ).get("error")
    )


# ── one row over the budget: a page of one, marked ───────────────────────────────────────────


def test_one_row_over_the_budget_is_a_page_of_one_marked(tmp_path: Path) -> None:
    """T-J8: an edge (single list) and a writer (shared lists) each wider than the budget: the
    page holds that one row and says over_budget — never an empty page, never the row dropped —
    and next_offset still leads to the rest.

    MUTATION (verified RED, 1 failed): _fit_lists keeps no index when the first is over (kept
    starts at the budget check) -> an empty writers page -> RED."""
    edges = _tools(_edges_atlas(tmp_path / "e", n=3, pad=60_000))
    page = edges["get_string_keyed_edges"]()
    assert len(page["edges"]) == 1 and page["over_budget"] is True and page["next_offset"] == 1
    tmp = tmp_path / "n"
    tmp.mkdir()
    conn = open_atlas(tmp / "atlas.db")
    add_nvram_flow_rows(
        conn,
        [
            NvramFlowRow(
                source_run_id="run_n",
                key=_KEY,
                key_kind="constant",
                binary=f"b{i}",
                func="f",
                op="write",
                api="nvram_set_" + "v" * 60_000,
            )
            for i in range(2)
        ],
    )
    conn.close()
    page = _tools(tmp / "atlas.db")["get_nvram_key_flow"](key=_KEY)
    assert len(page["writers"]) == 1 and page["over_budget"] is True
    assert page["next_offset"] == 1 and page["total_writers"] == 2


def test_paging_module_page_list_contract() -> None:
    """page_list: the slice and the whole length; None limit = to the end; past the end = []."""
    rows = list(range(10))
    assert paging.page_list(rows, 3, 4) == ([3, 4, 5, 6], 10)
    assert paging.page_list(rows, 8, None) == ([8, 9], 10)
    assert paging.page_list(rows, 12, 4) == ([], 10)
