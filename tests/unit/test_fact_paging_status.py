# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Paging of the per-binary scan-status rows that ride with two edge listings, and the readers that
must keep reading every judgement.

get_string_keyed_edges carries ``static_string_table_status`` and launched_by (on an empty answer)
``exec_argv_status``: one status row per scanned binary, so over a run — and far more over a whole
atlas — the rows outgrow any answer, and an answer with no edge at all could not be paged. The rows
are now cut at the same index as the edges, with ``total_statuses`` beside them; what a reader
needs to judge the silence — the pass's scope, the counts by state, the binaries with no row — is
on the block, over the whole scope, readable from the first page.

The diff-judgement listing pages too (list_overlays), and the findings hand-off reads that
listing's library function: it must still read every judgement, however many there are."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from treasure_map import mcp_app
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import DetectorScanStatusRow
from treasure_map.lib.atlas.writer import add_detector_status, begin_run, finish_run
from treasure_map.lib.query import diff_annotations, review_report
from treasure_map.lib.query.exec_edges import launched_by
from treasure_map.lib.query.string_edges import get_string_keyed_edges

BUDGET = mcp_app._RESPONSE_BYTE_BUDGET
SCOPE = "absolute_2field_only"
NOTE = "a shape this pass does not read"


def _analysis_db(path: Path, names: list[str]) -> str:
    """A run's analysis.db holding only what the status counts read: its binaries' short names."""
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE binaries (id INTEGER PRIMARY KEY, name TEXT)")
    conn.executemany("INSERT INTO binaries (name) VALUES (?)", [(n,) for n in names])
    conn.commit()
    conn.close()
    return str(path)


def _status_atlas(
    tmp_path: Path,
    detector: str,
    runs: dict[str, int],
    *,
    drop: tuple[str, int] | None = None,
    extra_names: dict[str, list[str]] | None = None,
) -> Path:
    """An atlas whose runs (``{run_id: binaries}``) each hold one ``detector`` status row per
    binary, ``lib_0000`` .. — every eleventh not scanned, every twenty-third capped, the rest
    found ``i % 3`` — except ``drop`` (run, index), whose row is left out. Each run's analysis.db
    holds the same names, plus ``extra_names`` of it (binaries no row covers)."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    conn = open_atlas(tmp_path / "atlas.db")
    for run_id, n in runs.items():
        names = [f"lib_{i:04d}" for i in range(n)]
        db = _analysis_db(
            tmp_path / run_id / "analysis.db", names + (extra_names or {}).get(run_id, [])
        )
        begin_run(conn, run_id, analysis_db_path=db)
        finish_run(conn, run_id, binaries=n, functions=n)
        add_detector_status(
            conn,
            [
                DetectorScanStatusRow(
                    run_id,
                    name,
                    detector,
                    scanned=0 if i % 11 == 0 else 1,
                    supported_scope=SCOPE,
                    unsupported_note=NOTE,
                    cap_hit=1 if i % 23 == 0 else 0,
                    found_count=i % 3,
                    binary_path=f"usr/lib/{name}",
                )
                for i, name in enumerate(names)
                if (run_id, i) != drop
            ],
        )
    conn.commit()
    conn.close()
    return tmp_path / "atlas.db"


def _walk(call: Callable[..., dict[str, Any]], block: str, **args: Any) -> tuple[list[Any], list]:
    """Every page from offset 0 along next_offset: (edges, status rows), each page within the
    budget and unmarked, next_offset exactly where the page ended and null only on the last."""
    edges: list[Any] = []
    rows: list[Any] = []
    offset: int | None = 0
    for _ in range(10_000):
        page = call(**args, offset=offset)
        assert "error" not in page, page.get("error")
        assert len(json.dumps(page)) <= BUDGET and "over_budget" not in page
        got = page[block].get("statuses", [])
        edges += page["edges"]
        rows += got
        nxt = page["next_offset"]
        if nxt is None:
            return edges, rows
        assert nxt == offset + max(len(page["edges"]), len(got)) and (page["edges"] or got)
        offset = nxt
    raise AssertionError("next_offset never became null")


# ── get_string_keyed_edges: the static-table status rows ─────────────────────────────────────


def test_an_empty_run_wide_answer_pages_its_status_rows_within_the_budget(tmp_path: Path) -> None:
    """MAJOR-2: a run of 600 binaries and no edge used to answer one block of 600 rows, over the
    budget and with nothing to page. Now every page fits, unmarked; walking next_offset reads
    every row once, in the library's order; the counts are the whole run's on every page.

    MUTATION (verified RED, 1 failed): take the status paging out — the library gives every row
    and the MCP layer fits the edges alone — -> the first page is over the budget -> RED. (Either
    half alone stays within it here: the library's page of 100 short rows fits, and the MCP fit
    trims a whole block by bytes; the two are the layered guard.)"""
    atlas = _status_atlas(tmp_path, "string_tables", {"run_a": 600})
    conn = open_atlas(atlas)
    try:
        whole = get_string_keyed_edges(conn, run_id="run_a")["static_string_table_status"]
    finally:
        conn.close()
    assert len(json.dumps(whole)) > BUDGET  # the precondition: the rows alone outgrow an answer
    tool = mcp_app.make_tools(atlas)["get_string_keyed_edges"]
    first = tool(run_id="run_a")
    block = first["static_string_table_status"]
    assert len(json.dumps(first)) <= BUDGET and "over_budget" not in first
    assert block["total_statuses"] == 600 and 0 < len(block["statuses"]) <= 100
    assert block["supported_scope"] == SCOPE and block["unsupported_note"] == NOTE
    assert (block["status_rows"], block["found_total"]) == (600, sum(i % 3 for i in range(600)))
    assert block["by_state"] == {
        "scanned": 600 - len(range(0, 600, 11)),
        "cap_hit": len(range(0, 600, 23)),
        "not_scanned": len(range(0, 600, 11)),
    }
    assert block["binaries_without_status"] == 0
    assert not any("supported_scope" in r for r in block["statuses"])  # once, on the block
    edges, rows = _walk(tool, "static_string_table_status", run_id="run_a")
    assert edges == [] and rows == whole["statuses"]
    assert [r["binary"] for r in rows] == [f"lib_{i:04d}" for i in range(600)]


def test_an_atlas_wide_answer_pages_every_runs_rows(tmp_path: Path) -> None:
    """No run_id: the rows of every run, one total order (run, binary), every one reached; the
    counts and binaries_without_status are the whole atlas's.

    MUTATION (verified RED, 1 failed): cut the status rows from index 0 whatever the offset ->
    the walk reads the first rows again and never reaches run_b -> RED."""
    atlas = _status_atlas(tmp_path, "string_tables", {"run_a": 250, "run_b": 250})
    tool = mcp_app.make_tools(atlas)["get_string_keyed_edges"]
    first = tool()["static_string_table_status"]
    assert first["status_rows"] == first["total_statuses"] == 500
    _edges, rows = _walk(tool, "static_string_table_status")
    keys = [(r["run_id"], r["binary"]) for r in rows]
    assert len(keys) == len(set(keys)) == 500 and keys == sorted(keys)


def test_a_missing_status_row_is_counted_not_hidden(tmp_path: Path) -> None:
    """binaries_without_status: a run recorded 40 binaries and 39 rows -> 1 (a binary the pass
    has no word on, which no row of 39 shows); one binary's scope is no count of files -> None.

    MUTATION (verified RED, 1 failed): count the missing rows as 0 always -> RED."""
    atlas = _status_atlas(tmp_path, "string_tables", {"run_a": 40, "run_b": 5}, drop=("run_a", 7))
    conn = open_atlas(atlas)
    try:
        by_run = get_string_keyed_edges(conn, run_id="run_a")["static_string_table_status"]
        whole = get_string_keyed_edges(conn)["static_string_table_status"]
        one = get_string_keyed_edges(conn, binary="lib_0003")["static_string_table_status"]
    finally:
        conn.close()
    assert by_run["status_rows"] == 39 and by_run["binaries_without_status"] == 1
    assert whole["binaries_without_status"] == 1
    assert one["binaries_without_status"] is None and one["status_rows"] == 2


def test_edges_and_status_rows_page_at_one_index_until_both_are_read(tmp_path: Path) -> None:
    """With edges beside the rows: one top-level next_offset, null only when the edges AND the
    rows are read to their end — the edges run out first here, the rows keep it non-null.

    MUTATION (verified RED, 1 failed): fit the edges alone in the MCP layer (the status rows not
    among the lists) -> next_offset is null while status rows remain -> RED."""
    from treasure_map.lib.atlas.models import StringKeyedEdgeRow
    from treasure_map.lib.atlas.writer import add_string_keyed_edges

    atlas = _status_atlas(tmp_path, "string_tables", {"run_a": 30})
    conn = open_atlas(atlas)
    add_string_keyed_edges(
        conn,
        [
            StringKeyedEdgeRow(
                source_run_id="run_a",
                binary="lib_0001",
                from_function="dispatch",
                key=f"k{i}",
                mechanism="strcmp_gate",
                callee_name=f"h{i}",
            )
            for i in range(4)
        ],
    )
    conn.commit()
    conn.close()
    tool = mcp_app.make_tools(atlas)["get_string_keyed_edges"]
    page = tool(run_id="run_a", limit=10, offset=0)
    assert page["total_edges"] == 4 and len(page["edges"]) == 4
    assert page["next_offset"] == 10  # the edges are done, 20 status rows are not
    edges, rows = _walk(tool, "static_string_table_status", run_id="run_a", limit=10)
    assert len(edges) == 4 and len(rows) == 30


# ── launched_by: the exec_argv status rows of an empty answer ─────────────────────────────────


def test_an_empty_launched_by_over_every_run_pages_its_status_rows(tmp_path: Path) -> None:
    """MAJOR-3: no run_id and no edge (a misspelled target answers so too): the rows of every
    run used to come whole, over the budget. Now every page fits; the walk reads every row once;
    the counts are the whole atlas's; binaries_without_status counts by SHORT NAME, as the rows
    do — a name held twice in an analysis.db is one name, and a name with no row is counted.

    MUTATION (verified RED, 1 failed): take the status paging out (the library gives every row,
    the MCP layer fits the edges alone) -> over the budget -> RED.
    MUTATION (verified RED, 1 failed): count the analysis.db's binaries less the rows, rather
    than its names without a row -> 302 - 300 = 2 -> RED."""
    atlas = _status_atlas(
        tmp_path,
        "exec_argv",
        {"run_a": 300, "run_b": 300},
        extra_names={"run_a": ["lib_0001", "no_funcs.so"]},  # lib_0001 a second time; one new name
    )
    conn = open_atlas(atlas)
    try:
        whole = launched_by(conn, "nothing_launches_this")["exec_argv_status"]
    finally:
        conn.close()
    assert len(json.dumps(whole)) > BUDGET
    tool = mcp_app.make_tools(atlas)["launched_by"]
    first = tool(target="nothing_launches_this")
    block = first["exec_argv_status"]
    assert first["edges"] == [] and len(json.dumps(first)) <= BUDGET
    assert block["total_statuses"] == block["scanned_total"] == 600
    assert block["binaries_without_status"] == 1
    assert block["by_state"]["not_scanned"] == 2 * len(range(0, 300, 11))
    edges, rows = _walk(tool, "exec_argv_status", target="nothing_launches_this")
    assert edges == [] and rows == whole["statuses"]
    assert len({(r["run_id"], r["binary"]) for r in rows}) == 600


def test_an_unreadable_analysis_db_leaves_the_missing_count_unknown(tmp_path: Path) -> None:
    """A run whose analysis.db cannot be read: binaries_without_status is None — not known is not
    zero.

    MUTATION (verified RED, 1 failed): skip a run whose analysis.db cannot be read -> 0 -> RED."""
    atlas = _status_atlas(tmp_path, "exec_argv", {"run_a": 3})
    (tmp_path / "run_a" / "analysis.db").unlink()
    conn = open_atlas(atlas)
    try:
        block = launched_by(conn, "nothing_launches_this")["exec_argv_status"]
    finally:
        conn.close()
    assert block["binaries_without_status"] is None and block["total_statuses"] == 3


# ── the hand-off reads every judgement ──────────────────────────────────────────────────────


PAIR = "run_a::run_b"


def _judged_atlas(tmp_path: Path, n: int) -> Path:
    """``n`` changed_real judgements on one run pair's diff entries (their diff not in the atlas:
    the listing still lists each, as unresolved)."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    conn = open_atlas(tmp_path / "atlas.db")
    conn.executemany(
        "INSERT INTO overlay (anchor_kind, anchor_ref, run_id, verdict, rationale, attributed_to, "
        "basis_state) VALUES ('diff_subject', ?, ?, 'changed_real', 'r', 'agent', '{}')",
        [(f"{PAIR}#function_pair#libx:{i:08x}:{i:08x}", PAIR) for i in range(n)],
    )
    conn.commit()
    conn.close()
    return tmp_path / "atlas.db"


def test_the_handoff_reads_every_judgement_past_one_page(tmp_path: Path) -> None:
    """MAJOR-5: 130 judgements, more than the tool's page of 100. The library listing called with
    no limit, and the hand-off's findings read through it, hold all 130.

    MUTATION (verified RED, 1 failed): give list_diff_overlays a default limit of 100 -> the
    hand-off reads 100 -> RED."""
    atlas = _judged_atlas(tmp_path, 130)
    conn = open_atlas(atlas)
    try:
        listed = diff_annotations.list_diff_overlays(conn, run_id=PAIR, progress=False)
        found = review_report.handoff_findings(conn, PAIR)
    finally:
        conn.close()
    assert listed["count"] == len(listed["overlays"]) == 130
    assert len(found) == 130
    assert len({f["anchor_ref"] for f in found}) == 130


@pytest.mark.parametrize("limit", [7, 100])
def test_the_paged_listing_and_the_whole_one_hold_the_same_judgements(
    tmp_path: Path, limit: int
) -> None:
    """The tool's pages joined are the library's whole listing, judgement for judgement (in id
    order); a page's count is the whole listing's."""
    atlas = _judged_atlas(tmp_path, 130)
    conn = open_atlas(atlas)
    try:
        whole = diff_annotations.list_diff_overlays(conn, run_id=PAIR, progress=False)
        pages: list[dict[str, Any]] = []
        offset = 0
        while True:
            page = diff_annotations.list_diff_overlays(
                conn, run_id=PAIR, progress=False, limit=limit, offset=offset
            )
            assert page["count"] == 130 and page["total_overlays"] == 130
            pages += page["overlays"]
            offset += len(page["overlays"])
            if offset >= 130:
                break
    finally:
        conn.close()
    assert sorted(whole["overlays"], key=lambda r: r["id"]) == pages
