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
from pathlib import Path
from typing import Any

from treasure_map import mcp_app
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import InstanceRow
from treasure_map.lib.atlas.writer import add_instance, begin_run, upsert_pattern
from treasure_map.lib.storage.connection import open_db
from treasure_map.mcp_app import _RESPONSE_BYTE_BUDGET, _fit_candidates

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
