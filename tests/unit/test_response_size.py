# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Keeping a list_candidates response inside the transport, without dropping a fact.

A wide-row page at a large limit produced a ~95KB response that overflowed to a file. The fix
trims the candidate array to a byte budget — announced, paged, and with the totals kept exact, so
nothing vanishes. And the folded-symbol red-line, which used to be serialized twice, is carried
once with the second site pointing at it. Pure transport shaping: no candidate, no folded symbol,
and no blind-spot count is lost.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from treasure_map import mcp_app
from treasure_map.lib.analyze.ghidra_runner import current_pass_version
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import InstanceRow
from treasure_map.lib.atlas.writer import add_instance, begin_run, upsert_pattern
from treasure_map.lib.query import patch_view as pv
from treasure_map.lib.query import sink_overlay as so
from treasure_map.lib.storage.connection import open_db
from treasure_map.mcp_app import _RESPONSE_BYTE_BUDGET, _fit_candidates
from treasure_map.version import UNKNOWN_VERSION

_FID = [0]


def _make_candidates(
    atlas_path: Path, n: int, *, sink_class: str = "path_sink", analysis_db: Path | None = None
) -> None:
    conn = open_atlas(atlas_path)
    begin_run(conn, "run_1", analysis_db_path=str(analysis_db or "/x/analysis.db"))
    pid = upsert_pattern(
        conn,
        source_class="unknown",
        sink_class=sink_class,
        call_sequence_shape="source->...->sink",
        structural_fingerprint=f"fp_{sink_class}",
        fingerprint_algo_version="callseq-v1",
    )
    for _ in range(n):
        _FID[0] += 1
        add_instance(
            conn,
            InstanceRow(
                pattern_id=pid,
                pseudocode_hash=f"h{_FID[0]}",
                source_anchor=f"fn{_FID[0]}",
                sink_anchor="fopen",
                source_run_id="run_1",
                reachability_status="unknown",
                provenance_level="L0",
                # a wide binary_path, as a real path_sink row carries
                binary_path=f"squashfs-root/usr/lib/some/deep/vendor/path/libthing_{_FID[0]}.so",
                evidence_ref=f"run_1#{_FID[0]:08x}:000{_FID[0]:05x}@{sink_class}",
                scope_origin="intra",
                origin="unknown",
            ),
        )
    conn.close()


def _tools(atlas_path: Path) -> Any:
    return mcp_app.make_tools(atlas_path)


# ── A: the byte budget bounds the response ────────────────────────────────────────────


def test_a_large_page_is_kept_within_the_byte_budget(tmp_path: Path) -> None:
    # ★ THE OVERFLOW FIX. A page that would serialize past the budget is trimmed to fit, so the
    # response stays inside the transport instead of overflowing to a file.
    #
    # MUTATION (verified RED, 1 failed): in mcp_app.list_candidates return `candidate_rows`
    # directly instead of the byte-fitted `kept` -> the response blows past the budget again.
    atlas_path = tmp_path / "atlas.db"
    _make_candidates(atlas_path, 300)
    result = _tools(atlas_path)["list_candidates"](run_id="run_1", limit=200, verbose=False)
    assert len(json.dumps(result)) <= _RESPONSE_BYTE_BUDGET
    assert result["returned"] < 200  # it really was trimmed, so the bound is not vacuous


def test_a_size_trim_is_announced_with_the_totals(tmp_path: Path) -> None:
    # ★ A trim is a VISIBLE decision, never silent. The reader is told the page was cut, how many
    # came back, and the exact total that still exists — so a short page is never read as a small
    # corpus.
    #
    # MUTATION (verified RED, 1 failed): in mcp_app.list_candidates hard-set
    # `envelope["candidates_truncated"] = False` -> a byte cut goes unannounced.
    atlas_path = tmp_path / "atlas.db"
    _make_candidates(atlas_path, 300)
    result = _tools(atlas_path)["list_candidates"](run_id="run_1", limit=200, verbose=False)
    assert result["candidates_truncated"] is True
    assert result["returned"] == len(result["candidates"])
    assert result["total"] == 300  # exact, not the trimmed count
    assert result["corpus"] == 300
    assert result["truncated"] is True
    assert result["next_offset"] == result["returned"]


def test_paging_resumes_exactly_where_the_bytes_stopped(tmp_path: Path) -> None:
    # ★ next_offset is set from what ACTUALLY fit, not the row limit, so page 2 begins at the first
    # row page 1 could not carry — no gap, no overlap.
    #
    # MUTATION (verified RED, 1 failed): in mcp_app.list_candidates set
    # `envelope["next_offset"] = off + lim` -> page 2 skips the rows the byte trim dropped.
    atlas_path = tmp_path / "atlas.db"
    _make_candidates(atlas_path, 300)
    tools = _tools(atlas_path)
    p1 = tools["list_candidates"](run_id="run_1", limit=200, verbose=False)
    p2 = tools["list_candidates"](
        run_id="run_1", limit=200, offset=p1["next_offset"], verbose=False
    )
    p1_refs = [c["evidence_ref"] for c in p1["candidates"]]
    p2_refs = [c["evidence_ref"] for c in p2["candidates"]]
    assert set(p1_refs).isdisjoint(p2_refs)  # no overlap
    assert p2["candidates"][0]["rank"] == p1["candidates"][-1]["rank"] + 1  # no gap
    # every candidate is reachable across the two pages (nothing lost to the trim)
    assert len(set(p1_refs) | set(p2_refs)) == len(p1_refs) + len(p2_refs)


def test_a_small_query_is_not_trimmed(tmp_path: Path) -> None:
    # The budget only bites large pages; an ordinary small query returns whole, unannounced.
    atlas_path = tmp_path / "atlas.db"
    _make_candidates(atlas_path, 5)
    result = _tools(atlas_path)["list_candidates"](run_id="run_1", limit=200, verbose=False)
    assert result["returned"] == 5
    assert result["candidates_truncated"] is False
    assert result["truncated"] is False
    assert result["next_offset"] is None


# ── A: the trim is BYTE-aware, not a row count ────────────────────────────────────────


def _row(width: int) -> dict[str, Any]:
    return {"evidence_ref": "r", "payload": "x" * width}


def test_wide_rows_are_trimmed_at_fewer_rows_than_narrow_ones() -> None:
    # ★ The reason the limit is bytes and not a row count: row width varies by sink class and path
    # length (a path_sink row is wider than a cmd row). At the same budget, wider rows must fit in
    # fewer — a fixed row cap cannot bound the response.
    #
    # MUTATION (verified RED, 1 failed): in mcp_app._fit_candidates ignore per-row cost — add a
    # constant per row instead of `len(json.dumps(row))` -> width stops mattering.
    envelope: dict[str, Any] = {"note": "x"}
    narrow, narrow_cut = _fit_candidates(envelope, [_row(50) for _ in range(200)], 8000)
    wide, wide_cut = _fit_candidates(envelope, [_row(500) for _ in range(200)], 8000)
    assert narrow_cut and wide_cut
    assert len(narrow) > len(wide)  # same budget, wider rows -> fewer fit


def test_one_oversized_row_still_returns_one_never_an_empty_page() -> None:
    # A single row larger than the whole budget is trimmed-to-one and flagged — never dropped to an
    # empty page that would read as "nothing here".
    #
    # MUTATION (verified RED, 1 failed): in mcp_app._fit_candidates drop the `if kept and` guard
    # (just `if running + cost > budget`) -> the first oversized row is refused and the page is
    # empty.
    envelope: dict[str, Any] = {"note": "x"}
    kept, cut = _fit_candidates(envelope, [_row(100_000), _row(100)], 1000)
    assert len(kept) == 1  # the oversized first row is force-included, never an empty page
    assert cut is True  # and the rows after it were cut


def test_the_envelope_size_counts_against_the_budget() -> None:
    # The budget bounds the WHOLE response, so a big envelope leaves less room for rows — measured,
    # not assumed.
    small_env, big_env = {"note": "x"}, {"note": "x" * 5000}
    rows = [_row(100) for _ in range(200)]
    kept_small, _ = _fit_candidates(small_env, rows, 8000)
    kept_big, _ = _fit_candidates(big_env, rows, 8000)
    assert len(kept_small) > len(kept_big)


# ── B: folded_xref serialized once, authority in the always-present container ──────────


def _seed_folded(atlas_path: Path, analysis_db: Path) -> None:
    """A run whose analysis.db holds a folded-xref red-line row (the folded read resolves through
    the run's analysis.db, not the atlas), so both folded sites have something to carry."""
    ac = open_db(analysis_db)
    ac.execute(
        "INSERT INTO xref_folded_symbols (symbol, exporters, callers, folded_edges) "
        "VALUES ('strlen', 40, 900, 36000)"
    )
    ac.commit()
    ac.close()
    _make_candidates(atlas_path, 3, analysis_db=analysis_db)


def test_folded_xref_is_serialized_once_in_full(tmp_path: Path) -> None:
    # ★ THE DEDUP. The full symbol list appears once — at the top level — and the coverage site
    # carries a reference, not a second copy.
    #
    # MUTATION (verified RED, 1 failed): in mcp_app._coverage_block set
    # `"folded_xref_symbols": folded_xref` (the full list again) -> it is serialized twice.
    atlas_path = tmp_path / "atlas.db"
    _seed_folded(atlas_path, tmp_path / "analysis.db")
    result = _tools(atlas_path)["list_candidates"](run_id="run_1", verbose=False)
    top = result["folded_xref_symbols"]
    cov = result["coverage"]["blind_spots"]["folded_xref_symbols"]
    assert isinstance(top, list) and len(top) == 1  # the full authoritative copy
    assert isinstance(cov, dict)  # a reference, not a second list
    body = json.dumps(result)
    assert body.count('"symbol": "strlen"') == 1  # the symbol identity is serialized exactly once


def test_the_folded_authority_lives_in_the_always_present_container(tmp_path: Path) -> None:
    # ★ THE LOAD-BEARING INVARIANT. The authoritative copy must live where it cannot go missing —
    # the top-level red-line, present on every normal response — never in coverage.blind_spots,
    # which some response shapes may not produce. Deduping into a container that can be absent
    # would be a new silent drop.
    #
    # MUTATION (verified RED, 1 failed): swap the two — make top-level the reference and
    # coverage.blind_spots the full list — and the top-level authority assertion fails.
    atlas_path = tmp_path / "atlas.db"
    _seed_folded(atlas_path, tmp_path / "analysis.db")
    result = _tools(atlas_path)["list_candidates"](run_id="run_1", verbose=False)
    top = result["folded_xref_symbols"]
    assert isinstance(top, list)
    assert top and top[0]["symbol"] == "strlen"
    # the coverage reference still makes the count reachable
    cov = result["coverage"]["blind_spots"]["folded_xref_symbols"]
    assert cov["count"] == len(top)


def test_the_full_symbol_and_its_counts_stay_readable(tmp_path: Path) -> None:
    # Dedup drops a duplicate, not a fact: each folded symbol and its suppressed-edge counts are
    # still readable once.
    atlas_path = tmp_path / "atlas.db"
    _seed_folded(atlas_path, tmp_path / "analysis.db")
    result = _tools(atlas_path)["list_candidates"](run_id="run_1", verbose=False)
    (symbol,) = result["folded_xref_symbols"]
    assert symbol["symbol"] == "strlen"
    assert symbol["callers"] == 900
    assert symbol["exporters"] == 40


def test_the_two_folded_sites_are_the_same_data(tmp_path: Path) -> None:
    # Same-source regression: the top-level list and the coverage reference describe ONE folded
    # set (same _incomplete_for_run read), so the reference count matches the list length exactly.
    atlas_path = tmp_path / "atlas.db"
    _seed_folded(atlas_path, tmp_path / "analysis.db")
    result = _tools(atlas_path)["list_candidates"](run_id="run_1", verbose=False)
    assert result["coverage"]["blind_spots"]["folded_xref_symbols"]["count"] == len(
        result["folded_xref_symbols"]
    )


# ── C: the diff view's pages are fitted to the same budget ─────────────────────────────


_DIFF = "runA::runB::libx"


def _diff_rows(n_pairs: int, rows_per_pair: int) -> list[so.SinkOverlayRow]:
    rows = []
    for p in range(n_pairs):
        fa, fb = f"{0x10000 + p * 0x1000:08x}", f"{0x80000 + p * 0x1000:08x}"
        for i in range(rows_per_pair):
            off = f"0x{0x10 + 4 * i:x}"
            rows.append(
                so.SinkOverlayRow(
                    diff_id=_DIFF,
                    binary="libx",
                    sink_class="copy",
                    a_ref=f"runA#deadbeef:{fa}@copy@{off}",
                    b_ref=f"runB#deadbeef:{fb}@copy@{off}",
                    key_granularity="callsite",
                    presence="persisted",
                    presence_reason=None,
                    match_basis="instruction",
                    counterpart_call="present_same_callee",
                    alignment_confidence=0.97,
                )
            )
    return rows


def _diff_atlas(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, n_pairs: int, rows_per_pair: int
) -> Path:
    """One diff of ``libx`` with ``n_pairs`` changed pairs of ``rows_per_pair`` candidate rows each,
    one similarity-1 pair (counted, not listed) and one string-keyed edge."""
    atlas_path = tmp_path / "atlas.db"
    atlas = open_atlas(atlas_path)
    build = current_pass_version()
    for side, run, sha in (("a", "runA", "a" * 64), ("b", "runB", "b" * 64)):
        db = tmp_path / f"analysis_{side}.db"
        conn = open_db(db)
        conn.execute("INSERT INTO binaries (name, sha256) VALUES ('libx', ?)", (sha,))
        conn.commit()
        conn.close()
        atlas.execute(
            "INSERT INTO run (run_id, hunt_commit, build_hash, hunt_instances, "
            "analysis_db_path) VALUES (?, 'facade', ?, 10, ?)",
            (run, build, str(db)),
        )
    atlas.execute(
        "INSERT INTO diff_meta (diff_id, run_a_id, run_b_id, binary_a, binary_b, sha256_a, "
        "sha256_b, diff_ok, version_skew) VALUES (?, 'runA', 'runB', 'libx', 'libx', ?, ?, 1, 0)",
        (_DIFF, "a" * 64, "b" * 64),
    )
    for p in range(n_pairs):
        atlas.execute(
            "INSERT INTO function_alignment (diff_id, addr_a, addr_b, alignment_confidence, "
            "similarity, alignment_state) VALUES (?, ?, ?, 0.97, 0.8, 'aligned')",
            (_DIFF, f"{0x10000 + p * 0x1000:08x}", f"{0x80000 + p * 0x1000:08x}"),
        )
    atlas.execute(
        "INSERT INTO function_alignment (diff_id, addr_a, addr_b, alignment_confidence, "
        "similarity, alignment_state) VALUES (?, '00f00000', '00f80000', 0.97, 1.0, 'aligned')",
        (_DIFF,),
    )
    atlas.execute(
        "INSERT INTO dimension_delta (diff_id, dimension, subject_kind, subject_key, delta_kind, "
        "binary) VALUES (?, 'reachability.string_keyed_edge', 'edge', "
        "'libx|strcmp_gate|ping|00010000', 'layer_changed', 'libx')",
        (_DIFF,),
    )
    atlas.commit()
    atlas.close()
    rows = _diff_rows(n_pairs, rows_per_pair)

    def rows_of(conn: sqlite3.Connection, diff_id: str) -> so.SinkOverlayResult:
        return so.SinkOverlayResult(list(rows), so.SinkOverlayCoverage(0, 0, 0, 0, 0, False))

    def current(conn: sqlite3.Connection, diff_id: str) -> dict[str, Any]:
        return {"source_stale": False, "source_stale_reason": None, "toolchain_checked": True}

    pv._clear_view_caches()
    monkeypatch.setattr(pv, "compute_sink_overlay", rows_of)
    monkeypatch.setattr(pv, "diff_source_staleness", current)
    monkeypatch.setattr(mcp_app, "_installed_commit", lambda: UNKNOWN_VERSION)
    return atlas_path


def _fit_width(page: dict[str, Any]) -> int:
    """The width ``_fit_candidates`` measured when it stopped: the page as returned, with the two
    paging fields put back to the placeholders they were measured with (``entries_truncated``
    false; ``next_offset`` the wider of null and the total) and every entry it kept."""
    total = page["total_entries"]
    placeholder = total if len(json.dumps(total)) > len(json.dumps(None)) else None
    return len(json.dumps({**page, "entries_truncated": False, "next_offset": placeholder}))


def _lib_page(atlas_path: Path, **kw: Any) -> dict[str, Any]:
    conn = open_atlas(atlas_path)
    try:
        return pv.get_diff_patch_view(conn, _DIFF, **kw)
    finally:
        conn.close()


def test_a_wide_diff_page_is_cut_to_the_budget_full_and_announced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ A page of wide entries is cut to the budget, the cut is announced, the totals and the
    whole-diff counts stay as the view gives them, and the page is FULL: the next entry would not
    have fit.

    MUTATION (verified RED, 1 failed each): return the view's page uncut -> RED; hard-set
    ``entries_truncated`` False -> RED; leave out ``key="entries"`` at the fit (the envelope is
    then measured with every entry in it, and the page shrinks to one) -> not full -> RED."""
    atlas_path = _diff_atlas(tmp_path, monkeypatch, 12, 20)
    tool = _tools(atlas_path)["get_diff_patch_view"]
    page = tool(_DIFF)
    lib = _lib_page(atlas_path)
    assert len(json.dumps(page)) <= _RESPONSE_BYTE_BUDGET
    assert page.get("entries_truncated") is True
    assert page["total_entries"] == lib["total_entries"] == 12
    for key in ("counts", "not_listed", "review_progress", "subject_counts"):
        assert page[key] == lib[key], key
    kept = len(page["entries"])
    assert page["entries"] == lib["entries"][:kept]
    assert _fit_width(page) + len(json.dumps(lib["entries"][kept])) + 2 > _RESPONSE_BYTE_BUDGET


def test_a_diff_walk_returns_every_entry_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ next_offset resumes after the last entry that fit, so a walk returns every entry once,
    in the view's order.

    MUTATION (verified RED, 1 failed): set next_offset to ``offset + limit`` -> the walk skips the
    entries the cut dropped -> RED."""
    atlas_path = _diff_atlas(tmp_path, monkeypatch, 12, 20)
    tool = _tools(atlas_path)["get_diff_patch_view"]
    order = [e["entry_id"] for e in _lib_page(atlas_path)["entries"]]
    got: list[str] = []
    offset: int | None = 0
    pages = 0
    while offset is not None:
        page = tool(_DIFF, limit=5, offset=offset)
        assert len(json.dumps(page)) <= _RESPONSE_BYTE_BUDGET
        got += [e["entry_id"] for e in page["entries"]]
        offset = page["next_offset"]
        pages += 1
    assert got == order
    assert pages > len(order) // 5 + 1  # the budget, not the limit, set the page size


@pytest.mark.parametrize("view", ["sink_patch", "not_listed_page", "string_edge", "candidate_flat"])
def test_every_view_of_the_diff_carries_the_cut_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, view: str
) -> None:
    """Every view is paged the same way: a small page comes back as the view gives it, with
    ``entries_truncated`` false.

    MUTATION (verified RED, 3 failed): fit the sink_patch view only -> RED."""
    atlas_path = _diff_atlas(tmp_path, monkeypatch, 2, 3)
    kw: dict[str, Any] = {"limit": 1}
    if view == "not_listed_page":
        names = [k for k, v in _lib_page(atlas_path)["not_listed"].items() if v["count"]]
        kw["not_listed_page"] = names[0]
    elif view != "sink_patch":
        kw["view"] = view
    lib = _lib_page(atlas_path, **kw)
    assert lib["entries"], lib  # the view has something to page
    page = _tools(atlas_path)["get_diff_patch_view"](_DIFF, **kw)
    assert page == {**lib, "entries_truncated": False}


@pytest.mark.parametrize(
    ("total", "offset"),
    [(200, 0), (100_000, 99_700)],
    ids=["next_offset_narrower_than_null", "next_offset_wider_than_null"],
)
def test_a_page_at_the_budget_edge_stays_inside_it_byte_by_byte(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, total: int, offset: int
) -> None:
    """★ The envelope is measured with the paging fields already at placeholders at least as wide
    as their final values, so a page that fills the budget to the last byte stays inside it. The
    envelope is grown one byte at a time through a whole entry's width, so the measured width
    takes EVERY value up to the budget — the last 60 bytes included, checked.

    MUTATION (verified RED): measure the envelope before ``entries_truncated`` is set -> pages up
    to 27 bytes over -> 2 failed; keep that placeholder but measure ``next_offset`` as the view
    gave it (null) -> the wide case is 1 byte over -> 1 failed; leave out ``key="entries"`` at the
    fit -> pages not full -> 2 failed."""
    width = 300
    entries = [{"entry_id": f"e{i:05d}", "pad": "x" * (width - 30)} for i in range(200)]
    entry_width = len(json.dumps(entries[0]))
    pad = {"k": 0}

    def view(conn: sqlite3.Connection, diff_id: str, **kw: Any) -> dict[str, Any]:
        return {
            "diff_id": diff_id,
            "pad": "y" * pad["k"],
            "entries": list(entries),
            "total_entries": total,
            "next_offset": None,
        }

    monkeypatch.setattr(mcp_app, "_get_diff_patch_view", view)
    tool = _tools(tmp_path / "atlas.db")["get_diff_patch_view"]
    widths = set()
    for k in range(entry_width + 3):
        pad["k"] = k
        page = tool("d", offset=offset)
        assert len(json.dumps(page)) <= _RESPONSE_BYTE_BUDGET, k
        assert page["entries_truncated"] is True
        kept = len(page["entries"])
        assert page["next_offset"] == offset + kept
        fit = _fit_width(page)
        assert fit <= _RESPONSE_BYTE_BUDGET
        assert fit + len(json.dumps(entries[kept])) + 2 > _RESPONSE_BYTE_BUDGET, k  # full
        widths.add(fit)
    assert set(range(_RESPONSE_BYTE_BUDGET - 60, _RESPONSE_BYTE_BUDGET + 1)) <= widths


def test_the_fit_key_defaults_to_the_candidate_array() -> None:
    """``key`` names the field the rows go in; left out, it is ``candidates`` — list_candidates'
    call, which passes none, measures what it did before.

    MUTATION (verified RED, 1 failed): default ``key`` to ``"entries"`` -> RED."""
    env: dict[str, Any] = {"note": "x", "candidates": [_row(500) for _ in range(20)]}
    rows = [_row(100) for _ in range(50)]
    assert _fit_candidates(env, rows, 8000) == _fit_candidates(env, rows, 8000, key="candidates")
    assert _fit_candidates(env, rows, 8000, key="entries") != _fit_candidates(env, rows, 8000)


# ── S4: an inline_hunk that cannot fit the page is withheld whole, in the entries path only ──────


def _hunk_entry(eid: str, size: int) -> dict[str, Any]:
    """A rendered entry whose top-level delta and proposed reading each carry a ~size-byte hunk."""
    hunk = {
        "structural_lines": 3,
        "groups": 1,
        "structural": [["-" + "x" * size]],
        "substitution_groups": [],
    }
    return {
        "entry_id": eid,
        "rows": [{"a_ref": "r"}],
        "pseudocode_delta": {"kind": "structural", "inline_hunk": hunk},
        "proposed_pair_reading": {
            "state": "differs",
            "pseudocode_delta": {"kind": "structural", "inline_hunk": hunk},
        },
    }


def _entries_result(entries: list[dict[str, Any]], envelope_bytes: int) -> dict[str, Any]:
    return {
        "diff_id": "d",
        "legend": "e" * envelope_bytes,
        "entries": entries,
        "total_entries": len(entries),
        "next_offset": None,
    }


def test_a_hunk_that_cannot_fit_beside_the_envelope_is_withheld_whole() -> None:
    """★ The test is envelope + that one entry over the budget (the envelope runs 10-20KB), not the
    entry alone over it: an entry of ~30KB beside a ~20KB envelope has its hunks — the top-level
    delta's and the proposed reading's — withheld as page_budget with their counts, whole (never cut
    part-way), and its rows kept. The cached delta it came from is never written. A small entry is
    left as it is.

    MUTATION (verified RED): test the entry alone against the budget -> the 30KB entry keeps its
    hunk and is cut off this page -> RED; withhold only the top-level hunk -> RED; write the
    withheld form into the entry's own delta dict -> the cached object changes -> RED."""
    big, small = _hunk_entry("big", 14_000), _hunk_entry("small", 50)
    cached = big["pseudocode_delta"]
    out = mcp_app._fit_entries(_entries_result([small, big], 20_000), 0)
    assert len(json.dumps(out)) <= _RESPONSE_BYTE_BUDGET
    by_id = {e["entry_id"]: e for e in out["entries"]}
    want = {
        "withheld": "page_budget",
        "structural_lines": 3,
        "groups": 1,
        "read_with": "get_pseudocode",
    }
    assert by_id["big"]["pseudocode_delta"]["inline_hunk"] == want
    assert by_id["big"]["proposed_pair_reading"]["pseudocode_delta"]["inline_hunk"] == want
    assert by_id["big"]["rows"] == [{"a_ref": "r"}]
    assert "withheld" not in by_id["small"]["pseudocode_delta"]["inline_hunk"]
    assert "structural" in cached["inline_hunk"]  # the original object is untouched


def test_member_pages_never_withhold_a_hunk() -> None:
    """The defence lives in the entries path, never in _fit_page, which member pages share.

    MUTATION (verified RED): move the withholding into _fit_page -> the member row loses its hunk
    -> RED."""
    row = _hunk_entry("m", 14_000)
    result = {"legend": "e" * 20_000, "members": [row], "member_count": 1}
    out = mcp_app._fit_members(result, 0)
    assert "structural" in out["members"][0]["pseudocode_delta"]["inline_hunk"]


@pytest.mark.parametrize("bad", [-1, 21, True, "5"])
def test_rows_limit_is_ranged_at_the_tool(tmp_path: Path, bad: Any) -> None:
    """rows_limit is 0..20 at the tool (0 = a scan with no inline row); outside that it is an
    error naming the range, never clamped."""
    tool = mcp_app.make_tools(tmp_path / "atlas.db")["get_diff_patch_view"]
    out = tool("x::y::z", rows_limit=bad)
    assert "rows_limit must be an integer in 0..20" in out["error"]


def test_the_tool_and_the_instructions_say_how_to_read_a_hunk_and_scan() -> None:
    doc = " ".join(
        (mcp_app.make_tools(Path("unused.db"))["get_diff_patch_view"].__doc__ or "").split()
    )
    for phrase in (
        "inline_hunk",
        "rows_limit=0",
        "over_gate",
        "page_budget",
        "too_large",
        "local_or_comment",
        "original text",
    ):
        assert phrase in doc, phrase
    assert "rows_limit=0" in mcp_app._AGENT_INSTRUCTIONS
    assert "inline_hunk" in mcp_app._AGENT_INSTRUCTIONS


def _axes_entry(n_rows: int, axes_bytes: int, hunk_bytes: int) -> dict[str, Any]:
    """A one-entry read whose rows each carry ~axes_bytes of sink_axes, plus a hunk."""
    entry = _hunk_entry("one", hunk_bytes)
    entry["rows"] = [
        {"a_ref": f"r{i}", "sink_axes": {"a": {"class": "cmd", "pad": "x" * axes_bytes}, "b": None}}
        for i in range(n_rows)
    ]
    return entry


def test_one_entry_too_large_sheds_its_rows_axes_from_the_last_row_back() -> None:
    """I3: an entry that cannot fit beside its envelope has its rows' sink_axes withheld
    (page_budget, read with entry_id + rows_offset) one row at a time from the LAST row, re-measured
    each time, stopping as soon as it fits — the earlier rows keep theirs, the hunks stay, and
    sink_axes_withheld_rows counts the rows. Only when every row's axes are withheld and it still
    does not fit are the hunks withheld as well. The rows it came from are never written.

    MUTATION M21 (verified RED, 1 failed): withhold every row's axes at once -> RED."""
    envelope = 20_000
    entry = _axes_entry(6, 5_000, 50)
    original = json.dumps(entry)
    out = mcp_app._fit_entries(_entries_result([entry], envelope), 0)
    (got,) = out["entries"]
    assert len(json.dumps(out)) <= _RESPONSE_BYTE_BUDGET
    shed = [r["a_ref"] for r in got["rows"] if r["sink_axes"].get("withheld") == "page_budget"]
    k = got["sink_axes_withheld_rows"]
    assert 0 < k < 6 and shed == [f"r{i}" for i in range(6 - k, 6)]  # the last k, the rest kept
    # one row fewer would not have fitted, measured as the fit measures it: it stopped at the first
    base = len(
        json.dumps(
            {
                **_entries_result([], envelope),
                "total_entries": 1,
                "next_offset": None,
                "entries_truncated": False,
            }
        )
    )
    fewer = {**got, "rows": [*got["rows"][: 6 - k], entry["rows"][6 - k], *got["rows"][7 - k :]]}
    if k == 1:
        fewer = entry
    else:
        fewer["sink_axes_withheld_rows"] = k - 1
    assert base + len(json.dumps(fewer)) > _RESPONSE_BYTE_BUDGET
    assert base + len(json.dumps(got)) <= _RESPONSE_BYTE_BUDGET
    assert got["rows"][-1]["sink_axes"] == {
        "withheld": "page_budget",
        "read_with": "entry_id + rows_offset",
    }
    assert "structural" in got["pseudocode_delta"]["inline_hunk"]  # the hunk stayed
    assert json.dumps(entry) == original  # the rendered entry handed in is untouched
    big = _axes_entry(3, 2_000, 30_000)
    (both,) = mcp_app._fit_entries(_entries_result([big], envelope), 0)["entries"]
    assert both["sink_axes_withheld_rows"] == 3
    assert both["pseudocode_delta"]["inline_hunk"]["withheld"] == "page_budget"


def test_the_tool_says_how_to_read_the_guards_and_the_axes() -> None:
    """The tool description names every S7 field and the bounds of yes / no / unavailable; the
    view's legend and caveats carry them too."""
    from treasure_map.lib.query import patch_view as pv

    doc = " ".join(
        (mcp_app.make_tools(Path("unused.db"))["get_diff_patch_view"].__doc__ or "").split()
    )
    for phrase in (
        "guard_scan",
        "guards_body_ref",
        "guard_links",
        "linked_not_shown",
        "sink_axes",
        "sink_axes_with",
        "sink_axes_withheld_rows",
        "not_recorded_for_class",
        "is NOT read",
    ):
        assert phrase in doc, phrase
    assert {"guard_scan", "guard_links", "sink_axes"} <= set(pv._LEGEND)
    assert {"guards", "guard_links", "sink_axes"} <= set(pv._CAVEATS)
    assert "get_pseudocode(run_id=" in pv._LEGEND["sink_axes"]
