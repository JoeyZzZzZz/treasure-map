# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Coverage: what has been looked at, what has not, and the invariants that keep that answer true.

These prove the AFFORDANCE is correct — that the state of every candidate is derived from what was
recorded, that the paging order cannot move under a reader, and that a completion signal never
travels without what would falsify it. They cannot prove anyone reads carefully; that is a
question about behaviour, answered by using the tool, not by a test.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import InstanceRow
from treasure_map.lib.atlas.writer import add_instance, upsert_pattern
from treasure_map.lib.overlay import _VERDICTS, upsert_overlay
from treasure_map.lib.query import triage
from treasure_map.lib.query.coverage import (
    CONCLUDED,
    NEEDS_RECHECK,
    NEEDS_RELABEL,
    OPEN,
    UNSEEN,
    Annotation,
    CoverageIndex,
    annotation_state,
    canonical_page_key,
    coverage_report,
    load_coverage_index,
)
from treasure_map.lib.query.sink_impact import (
    DEFAULT_IMPACT_TIER,
    DEFAULT_SINK_IMPACT,
    impact_tier,
    parse_impact_order,
)

_FID = [0]

# `safe` is the one verdict that must name what blocks the input, where, and why — so a fixture
# using it has to supply that, which is itself the point being tested elsewhere.
_SAFE_BASIS = {
    "block_source": "the argument is a compile-time constant",
    "block_point": "FUN_00011000",
    "block_why": "no caller supplies the argument; it is a literal in .rodata",
}


def _annotate(conn: sqlite3.Connection, ref: str, verdict: str, rationale: str = "reason") -> None:
    upsert_overlay(
        conn,
        evidence_ref=ref,
        verdict=verdict,
        rationale=rationale,
        verdict_basis=_SAFE_BASIS if verdict == "safe" else None,
    )


def _pattern(conn: sqlite3.Connection, fp: str, *, sink_class: str = "cmd") -> int:
    return upsert_pattern(
        conn,
        source_class="unknown",
        sink_class=sink_class,
        call_sequence_shape="source->...->sink",
        structural_fingerprint=fp,
        fingerprint_algo_version="callseq-v1",
    )


def _candidate(
    conn: sqlite3.Connection,
    *,
    sink_class: str = "cmd",
    fn: str | None = None,
    ref: str | None = None,
) -> str:
    """One atlas instance, i.e. one candidate the coverage layer has to account for."""
    _FID[0] += 1
    name = fn or f"fn{_FID[0]}"
    pid = _pattern(conn, f"fp_{sink_class}", sink_class=sink_class)
    evidence_ref = ref or f"run_1#{name}@{sink_class}"
    add_instance(
        conn,
        InstanceRow(
            pattern_id=pid,
            pseudocode_hash=f"h{_FID[0]}",
            source_anchor=name,
            sink_anchor="system",
            source_run_id="run_1",
            reachability_status="unknown",
            provenance_level="L0",
            evidence_ref=evidence_ref,
            scope_origin="intra",
            origin="unknown",
        ),
    )
    return evidence_ref


def _scope(conn: sqlite3.Connection, sink_class: str | None = None) -> list[Any]:
    rows = triage(conn)
    return [c for c in rows if sink_class is None or c.sink_class == sink_class]


# ── the three layers, derived from what is already stored ─────────────────────────────


def test_a_candidate_nobody_annotated_reads_as_unseen(tmp_path: Path) -> None:
    conn = open_atlas(tmp_path / "atlas.db")
    try:
        ref = _candidate(conn)
        index = load_coverage_index(conn)
        assert index.state_for(ref) == UNSEEN
    finally:
        conn.close()


def test_inconclusive_is_an_open_state_not_a_conclusion(tmp_path: Path) -> None:
    # ★ The load-bearing distinction. `inconclusive` says "looked, cannot settle it" — a real
    # conclusion that must stay in view. Counting it as concluded would make it the cheapest way
    # to clear a page, which is the exact behaviour this layer exists to avoid rewarding.
    #
    # MUTATION (verified RED, 1 failed): in coverage.py include "inconclusive" in
    # _CONCLUDED_VERDICTS — `_CONCLUDED_VERDICTS = frozenset(_VERDICTS)` — and an open candidate
    # starts counting as concluded.
    conn = open_atlas(tmp_path / "atlas.db")
    try:
        ref = _candidate(conn)
        _annotate(conn, ref, "inconclusive", "read it, cannot say")
        index = load_coverage_index(conn)
        assert index.state_for(ref) == OPEN
        report = coverage_report(_scope(conn), index)
        assert report.states[OPEN] == 1
        assert report.states[CONCLUDED] == 0
        assert report.seen == 1  # looked at, yes; concluded, no
    finally:
        conn.close()


def test_each_current_verdict_lands_in_exactly_one_layer() -> None:
    # Exhaustive over the vocabulary: no verdict may fall through to a state nobody defined.
    seen = {v: annotation_state(Annotation(v, "unchanged")) for v in _VERDICTS}
    assert seen["inconclusive"] == OPEN
    assert {seen[v] for v in _VERDICTS if v != "inconclusive"} == {CONCLUDED}


def test_a_retired_verdict_is_sent_back_for_relabelling(tmp_path: Path) -> None:
    # A word that left the vocabulary cannot be read as either a conclusion or an open state — it
    # no longer means anything the current vocabulary defines. The real atlas holds such rows.
    #
    # MUTATION (verified RED, 1 failed): in coverage.annotation_state drop the
    # `if annotation.verdict not in _VERDICTS` branch -> a retired word is read as concluded.
    assert annotation_state(Annotation("in-progress", "unchanged")) == NEEDS_RELABEL
    index = CoverageIndex(by_ref={"r": Annotation("in-progress", "unchanged")})
    assert index.state_for("r") == NEEDS_RELABEL


def test_a_moved_basis_is_due_a_recheck_not_counted_as_settled() -> None:
    # The conclusion may still hold, but it was reached on facts that have since moved, so it is
    # not something to count as settled.
    #
    # MUTATION (verified RED, 1 failed): in coverage.annotation_state drop the basis_state branch
    # -> a conclusion whose ground moved is counted as concluded.
    assert annotation_state(Annotation("safe", "changed")) == NEEDS_RECHECK
    # 'unverifiable' is an honest can't-say about the TEXT, not a signal that anything moved:
    # treating it as a recheck would make every candidate with no stored hash permanently unsettled.
    assert annotation_state(Annotation("safe", "unverifiable")) == CONCLUDED


def test_no_verdict_expresses_work_in_progress() -> None:
    # ★ The overlay stores CONCLUSIONS, not tasks. A "working on it" verdict was retired once
    # already; coverage answers the same need from presence, so nothing here may bring it back.
    assert "in-progress" not in _VERDICTS
    assert "in_progress" not in _VERDICTS
    for verdict in _VERDICTS:
        assert "progress" not in verdict


# ── dangling: the annotation whose candidate is gone ──────────────────────────────────


def test_an_annotation_whose_candidate_vanished_is_reported_not_counted(tmp_path: Path) -> None:
    # ★ THE FIXTURE HAS TO ACTUALLY TRIGGER IT. The stored basis records what was true when the
    # annotation was WRITTEN — for this case, that the anchor resolved fine. Judging from the
    # stored value would therefore report a healthy annotation, which is why the live basis is
    # re-derived instead. The candidate is written, annotated (so the stored basis says resolved),
    # and only then removed.
    #
    # MUTATION (verified RED, 1 failed): in coverage.load_coverage_index judge from the stored
    # value — `state = "anchor_unresolved" if not (Basis.from_json(row["verdict_basis"]) or
    # Basis(True, None, False, frozenset())).resolved else "unchanged"` — and this annotation
    # comes back as a healthy conclusion.
    conn = open_atlas(tmp_path / "atlas.db")
    try:
        ref = _candidate(conn)
        _annotate(conn, ref, "safe", "checked")
        # the snapshot is in `basis_state` (NOT `verdict_basis`, which holds safe's justification)
        stored = conn.execute("SELECT basis_state FROM overlay").fetchone()[0]
        assert json.loads(stored)["resolved"] is True, "fixture must be resolved when written"

        conn.execute("DELETE FROM instance WHERE evidence_ref = ?", (ref,))
        conn.commit()

        index = load_coverage_index(conn)
        assert index.by_ref[ref].basis_state == "anchor_unresolved"
        report = coverage_report(_scope(conn), index)
        assert report.dangling == [ref]
        assert report.states[CONCLUDED] == 0  # never counted as a conclusion about anything live
    finally:
        conn.close()


# ── paging: stable, total, and independent of the view ────────────────────────────────


def test_paging_order_is_pinned_to_the_default_impact_table(tmp_path: Path) -> None:
    # ★ THE INVARIANT THE WHOLE APPROACH RESTS ON. `impact_tier` accepts an override that REPLACES
    # the default table, so a candidate's tier — and with it its page — moves when someone passes a
    # different --impact-order. Working through pages 1..N would then step over candidates that
    # quietly moved behind the reader, and "everything gets reached eventually" would be false
    # without anything looking wrong. The paging key is pinned to the default table.
    #
    # Asserted against the default table directly, NOT by sorting twice with the same key — that
    # compares a function to itself and holds no matter what the key does.
    #
    # MUTATION (verified RED, 1 failed): in coverage.canonical_page_key read a different table —
    # `impact_tier(sink_class or "", {"log": 9})` — and the pinning breaks.
    for sink_class in ("cmd", "fmt_string", "copy", "log", "a_class_nobody_mapped"):
        expected = DEFAULT_SINK_IMPACT.get(sink_class, DEFAULT_IMPACT_TIER)
        assert canonical_page_key(sink_class, "ref")[0] == -expected, sink_class
    # the whole ref is the tie-break, never a parsed piece of it (two spellings exist in the wild)
    assert canonical_page_key("cmd", "run#a@x") < canonical_page_key("cmd", "run#b@x")
    # and an override really would reorder things, so the pinning above is not a no-op
    inverted = parse_impact_order("log,copy,cmd")
    assert impact_tier("log", inverted) > impact_tier("cmd", inverted)
    assert canonical_page_key("log", "r")[0] > canonical_page_key("cmd", "r")[0]


def test_an_impact_override_does_not_move_the_unread_page(tmp_path: Path) -> None:
    # ★ The same invariant end to end, where it would actually bite: --impact-order re-ranks the
    # LISTING, and the unread page must not follow it. If it did, a reader switching lenses would
    # be handed a different "next page" and the ones that slid past would never come back.
    #
    # MUTATION (verified RED, 1 failed): in mcp_app._coverage_block sort the unread set by the
    # active view instead of the canonical key — pass `impact_overrides` through to a re-sort —
    # and the two pages below diverge.
    atlas_path = tmp_path / "atlas.db"
    conn = open_atlas(atlas_path)
    try:
        for sink_class in ("cmd", "log", "copy", "fmt_string"):
            _candidate(conn, sink_class=sink_class)
    finally:
        conn.close()

    tools = _tools(atlas_path)
    plain = tools["list_candidates"](run_id="run_1")
    flipped = tools["list_candidates"](run_id="run_1", impact_order="log,copy,cmd")
    # the override really does re-rank the listing, so this comparison means something
    assert [r["evidence_ref"] for r in plain["candidates"]] != [
        r["evidence_ref"] for r in flipped["candidates"]
    ]
    # ...and the unread page is unmoved
    assert plain["coverage"]["next_page"] == flipped["coverage"]["next_page"]


def test_annotating_one_candidate_moves_only_that_candidate(tmp_path: Path) -> None:
    # ★ "Looked at" is per candidate and nothing else. Annotating one must not change whether any
    # other candidate counts as looked at, nor where any of them sit in the paging order — the
    # order has to stay walkable while someone works through it.
    #
    # MUTATION (verified RED, 1 failed): in coverage.canonical_page_key return
    # `(0, evidence_ref)` for annotated candidates — i.e. make the key depend on anything but the
    # candidate itself — and the untouched candidates move.
    conn = open_atlas(tmp_path / "atlas.db")
    try:
        refs = [_candidate(conn) for _ in range(4)]
        scope = _scope(conn)

        def positions() -> list[str]:
            return [
                c.evidence_ref
                for c in sorted(
                    scope, key=lambda c: canonical_page_key(c.sink_class, c.evidence_ref)
                )
            ]

        before = positions()
        _annotate(conn, refs[1], "excluded", "not reachable")
        index = load_coverage_index(conn)
        assert positions() == before
        assert index.state_for(refs[1]) == CONCLUDED
        assert all(index.state_for(r) == UNSEEN for r in refs if r != refs[1])
    finally:
        conn.close()


def test_page_counts_are_recomputed_and_never_stored(tmp_path: Path) -> None:
    # Page numbers are a rendering of the unseen set, not a record of progress. Annotating one
    # candidate has to move the numbers on the next read, with nothing to invalidate.
    conn = open_atlas(tmp_path / "atlas.db")
    try:
        refs = [_candidate(conn) for _ in range(5)]
        first = coverage_report(_scope(conn), load_coverage_index(conn), page_size=2)
        assert (first.total, first.unseen, first.pages_total, first.pages_remaining) == (5, 5, 3, 3)

        _annotate(conn, refs[0], "excluded", "reason")
        _annotate(conn, refs[1], "excluded", "reason")
        _annotate(conn, refs[2], "excluded", "reason")
        second = coverage_report(_scope(conn), load_coverage_index(conn), page_size=2)
        assert (second.unseen, second.pages_remaining) == (2, 1)
        assert second.pages_total == 3  # the class did not shrink; only the remainder did
        # nothing anywhere records a page number
        stored = conn.execute("SELECT * FROM overlay").fetchall()
        assert all("page" not in key.lower() for key in stored[0].keys())
    finally:
        conn.close()


def test_the_next_page_is_the_unseen_ones_named(tmp_path: Path) -> None:
    # Named at candidate level, so the ones nobody has been through can be opened straight from
    # the answer — "they are on page 4" would leave the reader to work out which ones those are.
    conn = open_atlas(tmp_path / "atlas.db")
    try:
        refs = [_candidate(conn) for _ in range(4)]
        _annotate(conn, refs[0], "excluded", "reason")
        report = coverage_report(_scope(conn), load_coverage_index(conn), page_size=2)
        named = [row["evidence_ref"] for row in report.next_page]
        assert len(named) == 2
        assert refs[0] not in named
        assert set(named) <= set(refs[1:])
        assert all(
            {"evidence_ref", "binary", "function", "sink_class"} <= set(r) for r in report.next_page
        )
    finally:
        conn.close()


# ── the shape of the conclusions, so a cleared page is visible as one ─────────────────


def test_dismissal_weight_is_reported_separately(tmp_path: Path) -> None:
    # ★ `safe` demands a structured evidence basis; `excluded` needs only a sentence. A scope
    # cleared entirely by the second looks identical to a careful one in a bare count, and this
    # split is the only place the difference shows.
    #
    # MUTATION (verified RED, 1 failed): in coverage.py collapse the weights — map both "safe"
    # and "excluded" to one bucket — and a page of bare dismissals stops being distinguishable.
    conn = open_atlas(tmp_path / "atlas.db")
    try:
        refs = [_candidate(conn) for _ in range(4)]
        _annotate(conn, refs[0], "excluded", "reason")
        _annotate(conn, refs[1], "excluded", "reason")
        _annotate(conn, refs[2], "inconclusive", "cannot settle")
        _annotate(conn, refs[3], "suspicious", "worth digging")
        report = coverage_report(_scope(conn), load_coverage_index(conn))
        assert report.verdict_shape["dismissed_by_rationale"] == 2
        assert report.verdict_shape["open"] == 1
        assert report.verdict_shape["carried_forward"] == 1
        assert "dismissed_with_evidence" not in report.verdict_shape
    finally:
        conn.close()


def test_complete_means_none_unseen_in_this_scope(tmp_path: Path) -> None:
    conn = open_atlas(tmp_path / "atlas.db")
    try:
        refs = [_candidate(conn) for _ in range(2)]
        assert coverage_report(_scope(conn), load_coverage_index(conn)).unseen == 2
        for ref in refs:
            _annotate(conn, ref, "inconclusive", "looked")
        done = coverage_report(_scope(conn), load_coverage_index(conn))
        assert (done.unseen, done.pages_remaining) == (0, 0)
        # ...and "none unseen" is NOT "all settled": both are open.
        assert done.states[OPEN] == 2
        assert done.states[CONCLUDED] == 0
    finally:
        conn.close()


# ── end to end through the listing tool: the scenario this exists for ─────────────────


def _tools(atlas_path: Path) -> Any:
    from treasure_map import mcp_app

    return mcp_app.make_tools(atlas_path)


def test_the_one_nobody_looked_at_is_named_in_the_listing(tmp_path: Path) -> None:
    # ★ THE SCENARIO GATE. A class where all but one candidate has been annotated, and the one
    # left is the shape that gets missed: reached through a wrapper, unremarkable in the ranking.
    # The listing has to leave it in the unread set AND name it — at candidate level, so it can be
    # opened from the answer. "It is on page 3" would put the work of finding it back on the
    # reader, which is the failure being fixed.
    #
    # This proves the affordance puts it in front of someone. It cannot prove they read it.
    #
    # MUTATION (verified RED, 1 failed): in mcp_app._coverage_block drop `next_page` from the
    # returned dict -> the unread candidate is counted but never named.
    atlas_path = tmp_path / "atlas.db"
    conn = open_atlas(atlas_path)
    try:
        annotated = [_candidate(conn) for _ in range(3)]
        missed = _candidate(conn, fn="wrapper_forwarded", ref="run_1#wrapper@cmd_via_wrapper")
        for ref in annotated:
            _annotate(conn, ref, "excluded", "not reachable")
    finally:
        conn.close()

    result = _tools(atlas_path)["list_candidates"](run_id="run_1")
    coverage = result["coverage"]
    assert coverage["not_looked_at"] == 1
    assert coverage["complete"] is False
    named = [row["evidence_ref"] for row in coverage["next_page"]]
    assert named == [missed], "the unread candidate must be named, not just counted"
    rows = {row["evidence_ref"]: row for row in result["candidates"]}
    assert rows[missed]["coverage"] == "none"
    assert all(rows[ref]["coverage"] == "concluded" for ref in annotated)


def test_the_listing_carries_coverage_without_the_overlay_view(tmp_path: Path) -> None:
    # ★ Unconditional, like the ledger marker beside it: whether anyone has been through a
    # candidate is a fact about the world, not a view to switch on. What stays behind the switch
    # is the annotation's CONTENT.
    #
    # MUTATION (verified RED, 1 failed): in mcp_app.list_candidates load the index only when the
    # overlay view is on — `coverage_index = _load_coverage_index(atlas) if overlay else
    # CoverageIndex()` -> the default view stops knowing what was looked at.
    atlas_path = tmp_path / "atlas.db"
    conn = open_atlas(atlas_path)
    try:
        ref = _candidate(conn)
        _annotate(conn, ref, "suspicious", "worth digging")
    finally:
        conn.close()

    off = _tools(atlas_path)["list_candidates"](run_id="run_1", overlay=False)
    row = off["candidates"][0]
    assert row["coverage"] == "concluded"  # the FACT is there
    assert "overlay" not in row  # the CONTENT is not
    assert off["coverage"]["looked_at"] == 1


def test_a_completion_signal_never_travels_alone(tmp_path: Path) -> None:
    # ★ "Nothing unread here" is true and, on its own, misleading. Binaries that failed to analyse
    # produced no candidates at all, so reading every candidate does not reach them; and a scope
    # cleared by the cheapest dismissal is covered only in the bookkeeping sense. Both ride in the
    # same object as the completion flag, so one cannot be quoted without the other.
    #
    # MUTATION (verified RED, 1 failed): in mcp_app._coverage_block drop `blind_spots` (or
    # `verdict_shape`) from the returned dict -> a completion signal can be read on its own.
    atlas_path = tmp_path / "atlas.db"
    conn = open_atlas(atlas_path)
    try:
        refs = [_candidate(conn) for _ in range(2)]
        for ref in refs:
            _annotate(conn, ref, "excluded", "not reachable")
    finally:
        conn.close()

    coverage = _tools(atlas_path)["list_candidates"](run_id="run_1")["coverage"]
    assert coverage["complete"] is True
    assert coverage["not_looked_at"] == 0
    assert "blind_spots" in coverage
    assert {"incomplete_binaries", "partially_incomplete_binaries", "folded_xref_symbols"} <= set(
        coverage["blind_spots"]
    )
    # and the shape shows what the clearing cost: two dismissals backed by nothing but a sentence
    assert coverage["verdict_shape"] == {"dismissed_by_rationale": 2}


def test_finishing_one_class_reports_what_is_left_elsewhere(tmp_path: Path) -> None:
    # ★ "I finished cmd" must not read as "I finished the firmware".
    #
    # MUTATION (verified RED, 1 failed): in mcp_app._coverage_block drop `outside_this_scope` ->
    # a swept class looks like a swept firmware.
    atlas_path = tmp_path / "atlas.db"
    conn = open_atlas(atlas_path)
    try:
        cmd_ref = _candidate(conn, sink_class="cmd")
        _candidate(conn, sink_class="copy")
        _candidate(conn, sink_class="copy")
        _annotate(conn, cmd_ref, "excluded", "not reachable")
    finally:
        conn.close()

    result = _tools(atlas_path)["list_candidates"](run_id="run_1", only="sink_class=cmd")
    coverage = result["coverage"]
    assert coverage["complete"] is True  # this class, yes
    assert coverage["outside_this_scope"]["not_looked_at"] == 2  # the firmware, no
    assert coverage["outside_this_scope"]["pages_remaining"] >= 1


def test_explain_says_where_to_put_a_conclusion_when_there_is_none(tmp_path: Path) -> None:
    # The prompt argues from the reader's own interest — a conclusion kept outside the overlay is
    # one nothing can re-check when the code moves — and it appears only where it is true.
    #
    # MUTATION (verified RED, 1 failed): in mcp_app.explain_candidate drop the
    # `if coverage_state == "none"` guard so the hint is always attached -> it appears on a
    # candidate that already carries a conclusion, becoming per-row nagging.
    atlas_path = tmp_path / "atlas.db"
    conn = open_atlas(atlas_path)
    try:
        bare = _candidate(conn)
        done = _candidate(conn)
        _annotate(conn, done, "suspicious", "worth digging")
    finally:
        conn.close()

    tools = _tools(atlas_path)
    unannotated = tools["explain_candidate"](bare)
    assert unannotated["coverage"] == "none"
    assert "coverage_hint" in unannotated
    assert "inconclusive" in unannotated["coverage_hint"]

    annotated = tools["explain_candidate"](done)
    assert annotated["coverage"] == "concluded"
    assert "coverage_hint" not in annotated


def test_the_only_thing_coverage_adds_to_the_base_map_is_the_fact_itself(tmp_path: Path) -> None:
    # ★ THE REGRESSION GATE for making presence unconditional. It changed a listing that was
    # previously identical before and after annotating, so the difference has to be pinned to
    # exactly what was intended: the presence key on each row and the envelope block. Ordering,
    # ranks, dimensions, every tool-derived field — untouched. Anything else moving means the
    # annotation layer has started leaking into the base map with its own view switched off.
    #
    # MUTATION (verified RED, 1 failed): in mcp_app.list_candidates re-rank on coverage when the
    # overlay is off — e.g. sort `ranked` by `coverage_index.state_for(c.evidence_ref)` before
    # paging — and the rows move.
    atlas_path = tmp_path / "atlas.db"
    conn = open_atlas(atlas_path)
    try:
        refs = [_candidate(conn) for _ in range(5)]
    finally:
        conn.close()

    tools = _tools(atlas_path)
    before = tools["list_candidates"](run_id="run_1")

    conn = open_atlas(atlas_path)
    try:
        _annotate(conn, refs[2], "excluded", "not reachable")
    finally:
        conn.close()
    after = tools["list_candidates"](run_id="run_1")

    def _strip(result: dict[str, Any]) -> dict[str, Any]:
        return {
            **{k: v for k, v in result.items() if k != "coverage"},
            "candidates": [
                {k: v for k, v in row.items() if k != "coverage"} for row in result["candidates"]
            ],
        }

    assert _strip(after) == _strip(before), "annotating changed more than the coverage fact"
    assert [row["evidence_ref"] for row in after["candidates"]] == [
        row["evidence_ref"] for row in before["candidates"]
    ]
    # and the intended difference is really there, so the comparison above is not vacuous
    changed = {
        row["evidence_ref"]: row["coverage"]
        for row in after["candidates"]
        if row["coverage"] != "none"
    }
    assert changed == {refs[2]: "concluded"}
    assert (before["coverage"]["looked_at"], after["coverage"]["looked_at"]) == (0, 1)
