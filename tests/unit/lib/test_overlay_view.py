# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""The opt-in overlay-on ordering view: an agent's annotations as the outermost ordering band.

Two things have to hold at once, and each needs its own teeth:

* With the overlay OFF, the listing is byte-for-byte the base map — the annotations exist but
  change nothing. This is only meaningful if the fixture's annotations WOULD reorder the list, so
  every off-identity check here annotates at least one ``suspicious`` and one ``excluded``: with
  only no-op verdicts the order would match even if the off path leaked annotations in.
* With the overlay ON, the list is genuinely re-ranked AND every annotated row visibly carries its
  annotation. Order-only assertions would pass on a build that renders no marker at all, and
  marker-only assertions would pass on a build whose re-rank is silently discarded — so both are
  asserted, with positional (not set) comparisons.

Reverse mutations — each was applied once and observed RED (assertion failures, never collection
errors), then restored. Re-run any of them to re-verify these guards still bite:

1. off-path leak. In ``mcp_app.list_candidates`` drop both overlay guards: fetch unconditionally
   (``overlays = _list_overlays(atlas)["overlays"]``) and drop the ``if overlay:`` before
   ``_apply_overlay_view``. -> 3 failed, incl. ``test_overlay_off_is_identical_to_no_overlay``.
2. no-op re-rank (the wrong-insertion-point bug). In ``mcp_app.list_candidates`` move the
   ``_apply_overlay_view`` call to BEFORE ``_apply_view``, which re-sorts from scratch and discards
   it. -> 6 failed, incl. ``test_overlay_on_floats_and_sinks``: nothing moves at all.
3. lost re-surface. In ``overlay_view.overlay_band`` delete the ``basis_state != "unchanged"``
   branch. -> 2 failed, incl. ``test_stale_dismissal_resurfaces``: a stale dismissal stays sunk.
4. two layers merged. In ``mcp_app._candidate_row`` write the verdict into a tool-derived field
   instead of its own key (``row["controllability"] = _overlay_marker(overlay)["verdict"]``).
   -> 3 failed, incl. ``test_rows_carry_marker_in_its_own_key``.
4b. verdict disguised as a tmap dimension — the subtler half of 4, and the reason the dimension
   assertion exists: keep ``row["overlay"]`` but ALSO add ``carried["overlay"] =
   overlay["verdict"]``. The carry loop is axis-agnostic, so the verdict is adopted as if tmap had
   established it, while every additive "the row has a verdict" assertion still passes.
   -> 1 failed: ``test_rows_carry_marker_in_its_own_key`` on the ``dimensions`` assertion.
5. inner/outer flip: mutation 2 also flips this — ``test_overlay_band_is_outermost`` goes red
   because an unannotated ``filters`` match outranks the annotated candidate.
6. band-internal reshuffle. In ``overlay_view.apply_overlay_view`` sort by
   ``(band(c), c.evidence_ref or "")``. -> 1 failed: ``test_band_keeps_base_order_inside_it``.
   NOTE: this one only bites because the fixture's addresses run OPPOSITE to the base lens order
   (see the ref constants). With addresses ascending WITH the lens order, ref-alphabetical and base
   order coincide and this mutation passes green — a fixture-shaped false pass that was observed
   and fixed rather than assumed away.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from treasure_map import mcp_app
from treasure_map.lib import overlay
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import InstanceRow
from treasure_map.lib.atlas.writer import add_instance, begin_run, finish_run, upsert_pattern
from treasure_map.lib.query.overlay_view import FLOAT, NEUTRAL, SINK, overlay_band

_RUN = "run_v"

# One binary (one sha8 anchor), five functions. The entry addresses run OPPOSITE to the base lens
# order on purpose: the base map ranks these by impact x controllability, which here is descending
# address order. So base order and ref-alphabetical order are REVERSES of each other, and a
# band-internal comparison can never pass by coincidence — an implementation that tie-broke on the
# ref instead of preserving the lens order would show up flipped.
CMD_FREE = f"{_RUN}#deadbeef:00005000@cmd"  # high impact + free -> the top of the base order
CMD_UNKNOWN = f"{_RUN}#deadbeef:00004000@cmd"  # high impact, controllability unestablished
COPY_FREE = f"{_RUN}#deadbeef:00003000@copy"  # mid impact
LOG_FREE = f"{_RUN}#deadbeef:00002000@log"  # low impact -> near the bottom
CMD_CONST = f"{_RUN}#deadbeef:00001000@cmd"  # provably-constant arg -> the base map sinks it


def _seed(tmp_path: Path) -> Path:
    """An atlas whose five candidates span the base lens: impact tiers plus one proven-safe row."""
    atlas_path = tmp_path / "atlas.db"
    con = open_atlas(atlas_path)
    rows = [
        ("cmd_free", CMD_FREE, "cmd", "free_string", None),
        ("cmd_unknown", CMD_UNKNOWN, "cmd", None, None),
        ("copy_free", COPY_FREE, "copy", "free_string", None),
        ("log_free", LOG_FREE, "log", "free_string", None),
        # blocking_mechanism=const_sink_arg is what the base map reads as provably constant.
        ("cmd_const", CMD_CONST, "cmd", None, "const_sink_arg"),
    ]
    for name, ref, sink_class, source_kind, blocking in rows:
        pid = upsert_pattern(
            con,
            source_class="external_input",
            sink_class=sink_class,
            call_sequence_shape=f"source->{name}",
        )
        add_instance(
            con,
            InstanceRow(
                pattern_id=pid,
                source_run_id=_RUN,
                evidence_ref=ref,
                pseudocode_hash=f"hash-{name}",
                sink_anchor="system",
                reachability_status="unknown",
                blocking_mechanism=blocking,
                binary_path="usr/sbin/webd",
                flow_evidence=json.dumps({"source_kind": source_kind}) if source_kind else None,
            ),
        )
    begin_run(con, _RUN, analysis_db_path=str(tmp_path / "analysis.db"))
    finish_run(con, _RUN, binaries=1, functions=5)
    con.close()
    return atlas_path


def _annotate(atlas_path: Path, ref: str, verdict: str) -> None:
    con = open_atlas(atlas_path)
    try:
        overlay.upsert_overlay(con, evidence_ref=ref, verdict=verdict, rationale="under review")
    finally:
        con.close()


def _order(tools: dict, **kw: object) -> list[str]:
    """Every candidate ref in listing order — the WHOLE list, not just the first page, so an
    annotation that only moves a deep candidate cannot slip past the comparison."""
    res = tools["list_candidates"](run_id=_RUN, limit=200, **kw)
    assert not res.get("truncated"), "fixture outgrew one page; raise the limit"
    return [c["evidence_ref"] for c in res["candidates"]]


def _rows(tools: dict, **kw: object) -> dict[str, dict]:
    res = tools["list_candidates"](run_id=_RUN, limit=200, **kw)
    return {c["evidence_ref"]: c for c in res["candidates"]}


# ── the base map is untouched while the overlay is off ────────────────────────────────


def test_overlay_off_is_identical_to_no_overlay(tmp_path: Path) -> None:
    # ★ The load-bearing invariant. The fixture deliberately annotates one verdict that FLOATS and
    # one that SINKS, so the two orders can only match because the off path ignores the overlay —
    # not because these annotations happen to be no-ops.
    atlas_path = _seed(tmp_path)
    tools = mcp_app.make_tools(atlas_path)
    baseline = _order(tools)  # no annotations exist yet

    _annotate(atlas_path, LOG_FREE, "suspicious")
    _annotate(atlas_path, CMD_FREE, "excluded")
    assert _order(tools) == baseline  # overlay=False by default: the base order is unmoved

    con = open_atlas(atlas_path)
    try:
        assert overlay.list_overlays(con)["count"] == 2  # the annotations really are there
    finally:
        con.close()

    con = open_atlas(atlas_path)
    try:
        overlay.clear_overlay(con)
    finally:
        con.close()
    assert _order(tools) == baseline  # and clearing restores nothing, because nothing had moved


def test_off_rows_carry_no_overlay_key(tmp_path: Path) -> None:
    # Structural half of the same invariant: with the overlay off a row is a pure base-map row.
    atlas_path = _seed(tmp_path)
    tools = mcp_app.make_tools(atlas_path)
    _annotate(atlas_path, CMD_FREE, "suspicious")
    assert all("overlay" not in r for r in _rows(tools).values())


# ── the overlay-on view really re-ranks ───────────────────────────────────────────────


def test_overlay_on_floats_and_sinks(tmp_path: Path) -> None:
    # ★ Positional, not set-based: proves the re-rank actually happened. A build that computes the
    # band and then throws it away (applying it before the base sort re-sorts everything) fails.
    atlas_path = _seed(tmp_path)
    tools = mcp_app.make_tools(atlas_path)
    base = _order(tools)
    # Preconditions — without these the assertions below could pass vacuously.
    assert base.index(LOG_FREE) > 0, "fixture: the to-float candidate must not already be first"
    assert base.index(CMD_FREE) < len(base) - 1, "fixture: the to-sink candidate must not be last"

    _annotate(atlas_path, LOG_FREE, "suspicious")
    _annotate(atlas_path, CMD_FREE, "excluded")
    on = _order(tools, overlay=True)

    assert on[0] == LOG_FREE  # floated over every unannotated candidate
    assert on[-1] == CMD_FREE  # sank below every unannotated candidate
    assert on.index(LOG_FREE) < on.index(CMD_UNKNOWN) < on.index(CMD_FREE)


def test_overlay_on_reorders_but_never_drops(tmp_path: Path) -> None:
    # Sinking is a demotion, never a removal: the corpus is identical, only the order differs.
    atlas_path = _seed(tmp_path)
    tools = mcp_app.make_tools(atlas_path)
    _annotate(atlas_path, CMD_FREE, "excluded")
    _annotate(atlas_path, LOG_FREE, "suspicious")
    off, on = _order(tools), _order(tools, overlay=True)
    assert set(on) == set(off)
    assert len(on) == len(off)
    assert on != off  # ... and it is a real reorder, not a no-op that trivially satisfies the sets


def test_stale_dismissal_resurfaces(tmp_path: Path) -> None:
    # ★ A dismissal only keeps a candidate down while the facts it rested on hold. Move the
    # pseudocode under it and the candidate comes back up for re-review, flagged.
    atlas_path = _seed(tmp_path)
    tools = mcp_app.make_tools(atlas_path)
    _annotate(atlas_path, CMD_FREE, "excluded")
    assert _order(tools, overlay=True)[-1] == CMD_FREE  # fresh dismissal: sunk

    con = open_atlas(atlas_path)
    try:  # the base map moves under the annotation (what a re-scan of changed code would do)
        con.execute(
            "UPDATE instance SET pseudocode_hash='hash-moved' WHERE evidence_ref=?", (CMD_FREE,)
        )
        con.commit()
    finally:
        con.close()

    on = _order(tools, overlay=True)
    assert on[0] == CMD_FREE  # re-surfaced, not left sunk
    marker = _rows(tools, overlay=True)[CMD_FREE]["overlay"]
    assert marker["basis_state"] == "changed"
    assert "re-review" in marker["re_review"]
    assert marker["basis_moved"]["pseudocode"] == "changed"


# ── the two layers stay distinguishable on the row ────────────────────────────────────


def test_rows_carry_marker_in_its_own_key(tmp_path: Path) -> None:
    # ★ The agent's verdict lands in its OWN top-level key. Merging it into a tool-derived field
    # (or into `dimensions`, whose carry loop is axis-agnostic) would dress a judgement up as a
    # tmap-established fact — the exact confusion this key separation exists to prevent.
    atlas_path = _seed(tmp_path)
    tools = mcp_app.make_tools(atlas_path)
    _annotate(atlas_path, CMD_FREE, "suspicious")
    row = _rows(tools, overlay=True)[CMD_FREE]

    assert row["overlay"]["verdict"] == "suspicious"
    assert row["overlay"]["attributed_to"] == "agent-via-mcp"
    assert row["overlay"]["basis_state"] == "unchanged"
    assert "overlay" not in row["dimensions"]  # never smuggled in as a dimension
    assert "suspicious" not in row["controllability"]  # never merged into a tool-derived field
    # An unannotated candidate carries no marker at all, even with the view on.
    assert "overlay" not in _rows(tools, overlay=True)[LOG_FREE]


def test_agent_can_float_a_candidate_the_base_map_sank(tmp_path: Path) -> None:
    # ★ The disagreement case: tmap read the sink argument as provably constant and sank it; the
    # agent says look again. The agent's call wins the ORDER, and BOTH readings stay on the row —
    # so the float can never be misread as tmap having found the candidate dangerous.
    atlas_path = _seed(tmp_path)
    tools = mcp_app.make_tools(atlas_path)
    assert _order(tools)[-1] == CMD_CONST  # the base map sinks it (proven-safe demotion)

    _annotate(atlas_path, CMD_CONST, "suspicious")
    assert _order(tools, overlay=True)[0] == CMD_CONST  # the agent's reading floats it

    row = _rows(tools, overlay=True)[CMD_CONST]
    assert row["overlay"]["verdict"] == "suspicious"  # the agent's half
    assert row["controllability"] == "proven:constant"  # the base map's half, still stated


# ── ordering structure: outermost band, base order preserved inside it ────────────────


def test_overlay_band_is_outermost(tmp_path: Path) -> None:
    # The overlay band wraps the whole lens, including a --filter float: a candidate the agent
    # marked suspicious outranks an unannotated candidate that matched the filter. Deliberate —
    # the point of the view is to see your own judgements first — and pinned so a refactor that
    # quietly makes it an inner band goes red.
    atlas_path = _seed(tmp_path)
    tools = mcp_app.make_tools(atlas_path)
    flt = "controllability=free"
    assert _order(tools, filters=flt)[0] == CMD_FREE  # the filter floats a match to the top

    _annotate(atlas_path, CMD_UNKNOWN, "suspicious")  # a NON-match, annotated
    on = _order(tools, filters=flt, overlay=True)
    assert on.index(CMD_UNKNOWN) < on.index(CMD_FREE)


def test_band_keeps_base_order_inside_it(tmp_path: Path) -> None:
    # The band is a stable partition, so within one band the base lens order survives untouched —
    # the overlay biases WHICH band a candidate lands in, never the ordering inside it.
    atlas_path = _seed(tmp_path)
    tools = mcp_app.make_tools(atlas_path)
    base = _order(tools)
    _annotate(atlas_path, COPY_FREE, "suspicious")
    _annotate(atlas_path, LOG_FREE, "suspicious")
    on = _order(tools, overlay=True)

    floated = [r for r in on if r in (COPY_FREE, LOG_FREE)]
    assert floated == [r for r in base if r in (COPY_FREE, LOG_FREE)]
    assert on[:2] == floated  # ... and they did float as a block


# ── the band mapping itself ───────────────────────────────────────────────────────────


def test_band_mapping() -> None:
    def ann(verdict: str, basis_state: str = "unchanged") -> dict:
        return {"verdict": verdict, "basis_state": basis_state}

    assert overlay_band(None) == NEUTRAL  # unannotated: base-map position
    assert overlay_band(ann("suspicious")) == FLOAT
    assert overlay_band(ann("excluded")) == SINK
    assert overlay_band(ann("safe")) == SINK
    assert overlay_band(ann("inconclusive")) == NEUTRAL  # looked at, nothing decisive: stay put
    # ★ A verdict this build no longer knows (retired since the row was written) must also land
    # NEUTRAL rather than raising — the vocabulary moves, stored annotations do not.
    assert overlay_band(ann("in-progress")) == NEUTRAL
    assert overlay_band(ann("some-future-word")) == NEUTRAL
    # A dismissal whose basis moved — or that cannot be verified at all — comes back up. An
    # unverifiable basis is an honest can't-say, and a can't-say must never bury a candidate.
    assert overlay_band(ann("excluded", "changed")) == FLOAT
    assert overlay_band(ann("safe", "changed")) == FLOAT
    assert overlay_band(ann("excluded", "unverifiable")) == FLOAT
    assert overlay_band(ann("safe", "unverifiable")) == FLOAT
    # A float verdict is unaffected by staleness — it is already in the top band.
    assert overlay_band(ann("suspicious", "changed")) == FLOAT


def test_every_verdict_maps_to_a_band() -> None:
    # Mechanical completeness: a verdict added to the storage layer without a band decision here
    # would silently ride as NEUTRAL, so pin that every known verdict is accounted for.
    bands = {v: overlay_band({"verdict": v, "basis_state": "unchanged"}) for v in overlay._VERDICTS}
    assert set(bands) == {"inconclusive", "suspicious", "excluded", "safe"}
    assert set(bands.values()) == {FLOAT, NEUTRAL, SINK}


def test_apply_is_pure_and_never_reduces(tmp_path: Path) -> None:
    # The pass returns a NEW list of the same members — it never mutates its input or drops rows.
    from treasure_map.lib.query.overlay_view import apply_overlay_view

    atlas_path = _seed(tmp_path)
    con: sqlite3.Connection = open_atlas(atlas_path)
    try:
        from treasure_map.lib.query import triage as run_triage

        ranked = run_triage(con, run_id=_RUN)
    finally:
        con.close()
    before = list(ranked)
    annotations = {CMD_FREE: {"verdict": "excluded", "basis_state": "unchanged"}}
    out = apply_overlay_view(ranked, annotations)
    assert ranked == before  # input untouched
    assert len(out) == len(before)
    assert {c.evidence_ref for c in out} == {c.evidence_ref for c in before}
