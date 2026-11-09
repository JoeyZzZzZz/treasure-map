# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Paging of the four fact tools that read a run's analysis.db: get_xrefs, get_imports_exports,
get_functions_referencing_string and get_string_reference_anchors.

Each page is a cut of ONE total order, so walking ``offset = next_offset`` until null reads every
row exactly once, in that order. The fixture is built so the order matters: two binaries share a
short name (and hold functions at the same address), get_xrefs merges a table read with a reverse
scan of callee lists and carries a library-level edge (no function, so no name and no address),
rows that tie on the displayed sort fields are stored in the opposite order of their tie-break,
and get_functions_referencing_string has more than the 50 hits the library caps at."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from treasure_map import mcp_app
from treasure_map.cli.mcp_cli import fact as fact_group
from treasure_map.lib import facts
from treasure_map.lib.analyze.ghidra_runner import current_pass_version
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.writer import begin_run, finish_run
from treasure_map.lib.query import entry_words, paging
from treasure_map.lib.storage.connection import open_db

RUN = "run_f"
SEEN = "2026-01-01T00:00:00"
LIB_A, LIB_B, APP, DYN = "lib/a/libdup.so", "lib/b/libdup.so", "usr/bin/app", "usr/bin/dyn"
NEEDLE = "NEEDLE_TEXT"
HUB_CALLERS = 130
APP_HITS = 60

# address_taken edges of ``target``, in their stored order (deliberately not sorted).
TAKEN = [
    {"taken_at": f"0x{a:x}", "taken_in_func": f"t{i}", "taken_in_func_addr": "0x1000"}
    for i, a in enumerate((0x9300, 0x9100, 0x9400, 0x9200))
]


def _build(tmp: Path) -> Path:
    db = tmp / "analysis.db"
    conn = open_db(db)
    pv = current_pass_version()
    for bid, path, sha, needed in (
        (1, LIB_A, "a" * 64, "[]"),
        (2, LIB_B, "b" * 64, "[]"),
        (3, APP, "c" * 64, '["libz.so"]'),
        (4, DYN, "d" * 64, '["libq.so"]'),
    ):
        conn.execute(
            "INSERT INTO binaries (id, name, path, sha256, last_seen_at, pass_version, dt_needed) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (bid, Path(path).name, path, sha, SEEN, pv, needed),
        )

    def fn(fid: int, bid: int, name: str, addr: str, *, callees: list[str] = (), text=None, **kw):
        conn.execute(
            "INSERT INTO functions (id, binary_id, name, address, pseudocode, callees, "
            "address_taken) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (fid, bid, name, addr, text, json.dumps(list(callees)), kw.get("taken", "{}")),
        )

    fn(10, 3, "target", "00001000", taken=json.dumps({"edges": TAKEN, "truncated": False}))
    # cross-binary callers of target: the same name at the same address in two same-named binaries
    fn(20, 2, "callr", "00002000")
    fn(21, 1, "callr", "00002000")
    fn(22, 1, "zfun", "00000500")
    # same-binary callers, recovered by the reverse scan of callee lists (stored address-descending)
    fn(30, 3, "c_b", "00004000", callees=["target"])
    fn(31, 3, "c_a", "00003000", callees=["target"])
    # xrefs rows stored out of the total order; one library-level (no caller function)
    for caller_bin, caller_fid, xtype in ((2, 20, "callees_exports"), (1, None, "dt_needed")):
        conn.execute(
            "INSERT INTO xrefs (caller_binary_id, caller_func_id, callee_binary_id, "
            "callee_func_id, xref_type) VALUES (?, ?, 3, 10, ?)",
            (caller_bin, caller_fid, xtype),
        )
    for caller_fid in (21, 22):
        conn.execute(
            "INSERT INTO xrefs (caller_binary_id, caller_func_id, callee_binary_id, "
            "callee_func_id, xref_type) VALUES (1, ?, 3, 10, 'callees_exports')",
            (caller_fid,),
        )
    # a function with more than 100 callers (the CLI must still print every one)
    fn(11, 3, "hub", "00001100")
    for i in range(HUB_CALLERS):
        fn(1000 + i, 3, f"h{i:03d}", f"{0x10000 + i * 16:08x}", callees=["hub"])
    # text hits: the same name at the same address in the two libdup binaries (a tie on the
    # displayed order, broken by the function id: bin 2's has the lower id), then APP_HITS in app
    fn(40, 2, "f_dup", "00003000", text=f'void f(){{ x("{NEEDLE}"); }}')
    fn(41, 1, "f_dup", "00003000", text=f'void f(){{ y("{NEEDLE}"); }}')
    for i in range(APP_HITS):
        fn(500 + i, 3, f"n{i:02d}", f"{0x20000 + i * 16:08x}", text=f"// {NEEDLE} {i}\nint z;")
    # imports: long, with a func_name tie stored opposite to its content order; exports short
    for name, lib in (
        ("dup", "libz.so"),
        ("dup", "liba.so"),
        ("aaa", "libc.so"),
        ("bbb", "libc.so"),
        ("ccc", "libc.so"),
        ("ddd", "libc.so"),
        ("eee", "libc.so"),
    ):
        conn.execute(
            "INSERT INTO imports (binary_id, func_name, lib_soname, source) "
            "VALUES (3, ?, ?, 'decompiler')",
            (name, lib),
        )
    for name, addr in (("exp2", "0x2"), ("exp1", "0x1")):
        conn.execute(
            "INSERT INTO exports (binary_id, func_name, address) VALUES (3, ?, ?)", (name, addr)
        )
    conn.execute(
        "INSERT INTO xref_unresolved_sonames (binary_id, soname, edge_layer, import_func_name, "
        "match_kind, candidate_binary_ids) VALUES (3, 'libz.so', 'dt_needed', NULL, 'exact', "
        "'[1, 2]')"
    )
    # string references of "KEY": app's first, then a tie (same binary name / string / ref) in
    # the two libdup binaries; the export capped the last one's list
    for bid, saddr, ref, func, trunc in (
        (2, "0x9000", "0x100", "fb", 1),
        (1, "0x9000", "0x100", "fa", 0),
        (3, "0x9100", "0x300", "g3", 0),
        (3, "0x9100", "0x200", "g2", 0),
        (3, "0x9100", "0x100", "g1", 0),
    ):
        conn.execute(
            "INSERT INTO string_refs (binary_id, string_addr, string_value, ref_at, ref_in_func, "
            "ref_in_func_addr, segment, truncated) VALUES (?, ?, 'KEY', ?, ?, '0x1', '.text', ?)",
            (bid, saddr, ref, func, trunc),
        )
    conn.commit()
    conn.close()
    atlas = tmp / "atlas.db"
    a = open_atlas(atlas)
    begin_run(a, RUN, analysis_db_path=str(db.resolve()))
    finish_run(a, RUN, binaries=4, functions=10)
    a.close()
    return db


@pytest.fixture
def world(tmp_path: Path) -> tuple[Path, dict[str, Callable[..., Any]]]:
    db = _build(tmp_path)
    return db, mcp_app.make_tools(tmp_path / "atlas.db")


def _ro(db: Path) -> sqlite3.Connection:
    return facts.open_analysis_ro(str(db))


def _safe(call: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    """The answer, or what the call raised — so a crash reads as an assertion, with its cause."""
    try:
        return call()
    except Exception as exc:  # noqa: BLE001
        return {"raised": repr(exc)}


def _walk(call: Callable[..., dict[str, Any]], rows: str, limit: int, **kw: Any) -> list[Any]:
    """Every page from offset 0 along next_offset: the rows in order. Every page but the last has a
    next_offset, and it is exactly where that page ended (T-J18)."""
    out: list[Any] = []
    offset = 0
    for _ in range(1000):
        got = _safe(lambda: call(limit=limit, offset=offset, **kw))
        assert "raised" not in got and "error" not in got, got
        out += got[rows]
        nxt = got["next_offset"]
        if nxt is None:
            assert offset + len(got[rows]) >= got[f"total_{rows}"]
            return out
        assert nxt == offset + len(got[rows]) and got[rows], got
        offset = nxt
    raise AssertionError("paging did not end")


def _key(e: dict[str, Any]) -> tuple[Any, ...]:
    """The order get_xrefs documents, re-derived here: binary path, address, function, type."""
    a = e["anchor"]
    return (
        a["binary_path"] or "",
        a["address"] or "",
        a["function"] or "",
        e["xref_type"] or "",
        e["library_level"],
    )


# ── get_xrefs ────────────────────────────────────────────────────────────────────────────────


def test_xref_pages_read_the_merged_caller_set_once_in_one_order(world: Any) -> None:
    """T-J15 / T-J6 / T-J18: callers from the xrefs table AND the reverse scan, a library-level
    edge among them, two same-named binaries at one address: every page size walks to the whole
    set, in the documented order, nothing read twice.

    MUTATION (verified RED, 1 failed): drop the ``or ""`` from xref_key's address part -> the
    library-level edge's None meets a string -> TypeError, read here as an assertion -> RED.
    MUTATION (verified RED, 1 failed): page_xrefs pages the merged list unsorted -> RED."""
    db, tools = world
    conn = _ro(db)
    raw = facts.get_xrefs(conn, func="target", direction="callers")["edges"]
    conn.close()
    # the fixture's premises: both sources, a library-level edge, a stored order that is not the
    # documented one, and two edges equal on everything but the binary path
    assert {e["xref_type"] for e in raw} == {"callees_exports", "dt_needed", "intra_callees"}
    assert any(e["library_level"] and e["anchor"]["address"] is None for e in raw)
    assert raw != sorted(raw, key=_key)
    assert len({(e["anchor"]["function"], e["anchor"]["address"]) for e in raw}) < len(raw)
    whole = _safe(lambda: tools["get_xrefs"](run_id=RUN, function="target", limit=200))
    assert "raised" not in whole, whole
    assert whole["total_edges"] == len(raw) == 6 and whole["next_offset"] is None
    assert whole["edges"] == sorted(raw, key=_key)
    for limit in (1, 2, 3, 5):
        got = _walk(tools["get_xrefs"], "edges", limit, run_id=RUN, function="target")
        assert got == whole["edges"], limit


def test_xref_callees_and_address_taken_page_too(world: Any) -> None:
    """callees pages like callers; address_taken keeps the stored export's order (fixed), paged.

    MUTATION (verified RED, 1 failed): sort address_taken too (drop the direction test in
    page_xrefs) -> the stored order is lost -> RED."""
    _db, tools = world
    got = _walk(
        tools["get_xrefs"], "edges", 1, run_id=RUN, function="target", direction="address_taken"
    )
    stored = [facts._norm_addr(t["taken_at"]) for t in TAKEN]
    assert stored != sorted(stored)  # the stored order really is not the sorted one
    assert [e["taken_at"] for e in got] == stored
    callees = _walk(
        tools["get_xrefs"], "edges", 1, run_id=RUN, function="zfun", direction="callees"
    )
    assert [e["anchor"]["function"] for e in callees] == ["target"]


def test_xref_pages_fit_the_byte_budget_and_still_walk_to_the_whole_set(
    world: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With a budget that cannot hold the whole set, the first page is cut by bytes (named so) and
    the walk still reads every edge once.

    MUTATION (verified RED, 1 failed): return get_xrefs' paged result without _fit_page -> the
    whole set in one answer, no truncated_by_bytes -> RED."""
    _db, tools = world
    whole = tools["get_xrefs"](run_id=RUN, function="target", limit=200)
    monkeypatch.setattr(mcp_app, "_RESPONSE_BYTE_BUDGET", len(json.dumps(whole)) - 150)
    first = tools["get_xrefs"](run_id=RUN, function="target", limit=200)
    assert first.get("truncated_by_bytes") is True and first["next_offset"] is not None
    assert len(json.dumps(first)) <= mcp_app._RESPONSE_BYTE_BUDGET
    assert _walk(tools["get_xrefs"], "edges", 200, run_id=RUN, function="target") == whole["edges"]


def test_the_cli_prints_every_edge_unpaged(world: Any) -> None:
    """T-J20: ``tmap fact xrefs`` reads the library unpaged — every one of hub's 130 callers, no
    paging fields — exactly what xrefs_with_entry_words gives.

    MUTATION (verified RED, 1 failed): give the CLI command the MCP paging (page_xrefs with limit
    100) -> 100 edges and a total_edges -> RED."""
    db, _tools = world
    res = CliRunner().invoke(fact_group, ["xrefs", "hub", "--analysis-db", str(db)])
    assert res.exit_code == 0, res.output
    printed = json.loads(res.output)
    conn = _ro(db)
    direct = entry_words.xrefs_with_entry_words(conn, func="hub", direction="callers", binary=None)
    conn.close()
    assert len(direct["edges"]) == HUB_CALLERS > 100
    assert printed.get("edges") == direct["edges"]
    assert "total_edges" not in printed and "next_offset" not in printed


# ── get_imports_exports ──────────────────────────────────────────────────────────────────────


def _imp_key(r: dict[str, Any]) -> tuple[Any, ...]:
    return (r["func_name"], json.dumps(r, sort_keys=True))


def test_import_export_lists_page_at_one_index_with_one_next_offset(world: Any) -> None:
    """T-J12 (its imports/exports form): imports long, exports and the unresolved sonames short —
    one top-level next_offset, non-null while imports remain; each total exact; every list where
    it always is; a func_name tie in one order; walking reads every list in full.

    MUTATION (verified RED, 1 failed): _fit_lists' next_offset needs EVERY list to remain
    (``any`` -> ``all``) -> null once exports run out -> RED.
    MUTATION (verified RED, 1 failed): drop the imports sort key in paging -> the func_name tie
    stays in its stored order -> RED."""
    db, tools = world
    conn = _ro(db)
    raw = facts.get_imports_exports(conn, binary="app")
    conn.close()
    # a real func_name tie, stored the other way round
    assert raw["imports"] != sorted(raw["imports"], key=_imp_key)
    tool = tools["get_imports_exports"]
    first = tool(run_id=RUN, binary="app", limit=2)
    assert list(first)[:6] == list(raw)[:6]  # the lists keep their places
    assert (
        first["total_imports"],
        first["total_exports"],
        first["total_dt_needed_unresolved"],
    ) == (
        7,
        2,
        1,
    )
    page2 = tool(run_id=RUN, binary="app", limit=2, offset=2)
    assert page2["exports"] == [] and page2["next_offset"] == 4  # exports done, imports not
    seen: dict[str, list[Any]] = {"imports": [], "exports": [], "dt_needed_unresolved": []}
    offset: int | None = 0
    while offset is not None:
        page = tool(run_id=RUN, binary="app", limit=2, offset=offset)
        for name in seen:
            seen[name] += page[name]
        offset = page["next_offset"]
    assert seen["imports"] == sorted(raw["imports"], key=_imp_key)
    assert seen["exports"] == sorted(raw["exports"], key=_imp_key)
    assert seen["dt_needed_unresolved"] == raw["dt_needed_unresolved"]


def test_undetermined_imports_stay_null_with_a_null_total(world: Any) -> None:
    """A dynamically linked binary with no import recorded: imports null (not determined), its
    total null, the other lists still paged — no crash on the null list.

    MUTATION (verified RED, 1 failed): page_lists treats a None list as empty -> total 0 -> RED."""
    _db, tools = world
    got = _safe(lambda: tools["get_imports_exports"](run_id=RUN, binary="dyn", limit=5))
    assert "raised" not in got, got
    assert got["imports"] is None and got["imports_state"] == "undetermined"
    assert got["total_imports"] is None and got["total_exports"] == 0
    assert got["next_offset"] is None


# ── get_functions_referencing_string ─────────────────────────────────────────────────────────


def test_text_hits_page_past_fifty_through_a_tie(world: Any) -> None:
    """T-J15 / the >50 reach: 62 hits (the library caps at 50), two of them at the same name and
    address in two same-named binaries; every page size walks to all 62 in one order.

    Not constructible: dropping ``f.id`` from the paged query's ORDER BY stays GREEN here. The
    plan scans ``functions`` by rowid (= f.id) into a sort that keeps equal keys in scan order, so
    the tie already reads by id; the tie-break guards plans that read the table another way. The
    order asserted below is the documented one either way.
    MUTATION (verified RED, 1 failed): page_list ignores offset (always from 0) -> RED."""
    db, tools = world
    conn = _ro(db)
    capped = facts.get_functions_referencing_string(conn, text=NEEDLE)
    conn.close()
    assert capped["returned"] == 50 and capped["truncated"] is True
    tool = tools["get_functions_referencing_string"]
    whole = tool(run_id=RUN, text=NEEDLE, limit=200)
    assert whole["total_functions"] == APP_HITS + 2 == len(whole["functions"])
    dup = [f for f in whole["functions"] if f["function"] == "f_dup"]
    assert [f["binary_path"] for f in dup] == [LIB_B, LIB_A]  # by function id
    for limit in (1, 7, 50):
        assert _walk(tool, "functions", limit, run_id=RUN, text=NEEDLE) == whole["functions"]


def test_the_first_page_is_what_the_library_gives(world: Any) -> None:
    """Drift guard: with no tie (one binary), the first page of N is the library's own N hits,
    field for field.

    MUTATION (verified RED, 1 failed): read the match line from the last line of the pseudocode
    instead of _first_match_line -> RED."""
    db, _tools = world
    conn = _ro(db)
    try:
        for n in (1, 10, 50):
            lib = facts.get_functions_referencing_string(conn, text=NEEDLE, binary="app", limit=n)
            ours = paging.functions_referencing_string(
                conn, text=NEEDLE, binary="app", offset=0, limit=n
            )
            assert ours["functions"] == lib["functions"], n
            assert ours["truncated"] is lib["truncated"] is True
    finally:
        conn.close()


def test_text_hit_counts_follow_the_byte_cut(world: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """A page cut by bytes says what it holds: returned is its hits, truncated that more follow.

    MUTATION (verified RED, 1 failed): skip the returned/truncated update after _fit_page ->
    returned stays the pre-cut count -> RED."""
    _db, tools = world
    tool = tools["get_functions_referencing_string"]
    whole = tool(run_id=RUN, text=NEEDLE, limit=20)
    monkeypatch.setattr(mcp_app, "_RESPONSE_BYTE_BUDGET", len(json.dumps(whole)) - 400)
    got = tool(run_id=RUN, text=NEEDLE, limit=20)
    assert got["truncated_by_bytes"] is True and 0 < len(got["functions"]) < 20
    assert got["returned"] == len(got["functions"])
    assert got["truncated"] is True and got["next_offset"] == len(got["functions"])
    last = tool(run_id=RUN, text=NEEDLE, limit=200, offset=APP_HITS + 1)
    assert last["truncated"] is False and last["next_offset"] is None and last["returned"] == 1


# ── get_string_reference_anchors ─────────────────────────────────────────────────────────────


def test_an_unbounded_anchor_limit_is_cut_and_said(world: Any) -> None:
    """T-J14: a limit this tool always took unbounded is cut to 200, not refused, and the answer
    says what was asked; a bool or a negative offset is refused.

    MUTATION (verified RED, 1 failed): drop the limit_clamped echo -> RED.
    MUTATION (verified RED, 1 failed): drop the bool test in _clamped_limit -> True reads as 1 ->
    RED."""
    _db, tools = world
    tool = tools["get_string_reference_anchors"]
    got = tool(run_id=RUN, text="KEY", limit=100000)
    assert "error" not in got and got["limit"] == mcp_app._MAX_LIMIT
    assert got.get("limit_clamped") == 100000 and got["total_anchors"] == 5
    assert "limit_clamped" not in tool(run_id=RUN, text="KEY", limit=3)
    for bad in ({"limit": True}, {"offset": True}, {"offset": -1}):
        assert "error" in tool(run_id=RUN, text="KEY", **bad), bad


def test_anchor_pages_walk_the_whole_set_and_name_the_export_cap(world: Any) -> None:
    """T-J6 / T-J15: every page size walks to all five references (a tie between the same-named
    binaries included) in one order; export_truncated is read over EVERY reference, so the first
    page (no capped reference on it) still says the export capped one; response_truncated and
    truncated follow next_offset.

    MUTATION (verified RED, 1 failed): read the library with the page's limit instead of every
    reference -> later pages miss references (and page one's export_truncated reads the page
    only) -> RED."""
    _db, tools = world
    tool = tools["get_string_reference_anchors"]
    whole = tool(run_id=RUN, text="KEY", limit=200)
    assert [a["binary"] for a in whole["anchors"]] == ["app"] * 3 + ["libdup.so"] * 2
    for limit in (1, 2, 4):
        assert _walk(tool, "anchors", limit, run_id=RUN, text="KEY") == whole["anchors"]
    first = tool(run_id=RUN, text="KEY", limit=2)
    assert all(a["binary"] == "app" for a in first["anchors"])
    assert first["export_truncated"] is True
    assert first["response_truncated"] is True and first["truncated"] is True
    assert first["returned"] == 2 and first["next_offset"] == 2
    last = tool(run_id=RUN, text="KEY", limit=2, offset=4)
    assert last["response_truncated"] is False and last["next_offset"] is None
