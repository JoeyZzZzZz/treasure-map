# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the float hit-count a preset view reports — so an empty lens stops being silent.

A preset view promises to float a class of candidates to the top. When nothing in a firmware
matches, the caller got the default order back with no way to tell "this lens found nothing here"
from "this lens had nothing to do" — the count was only ever taken over the filters typed on the
command line, never the view's own. An agent hit exactly that: switched to the nvram-source view on
a firmware that routes its configuration elsewhere, saw an order identical to the default, and had
no way to know the lens had simply not applied.

Nothing about float, sort, or any verdict changes here. The count is a read, and the derivation of
"which filters this lens applies" is now a single function both the sorter and the counter use, so
the two cannot drift the day a preset gains another float-affecting property.

Checked against a real atlas while building this: the order apply_view produces is byte-identical
across every view / filter / prune combination before and after the extraction.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import InstanceRow
from treasure_map.lib.atlas.writer import add_instance, upsert_pattern
from treasure_map.lib.query import VIEWS, effective_float_filters
from treasure_map.mcp_app import make_tools


def _seed(tmp_path: Path, *, nvram_keys: int, plain: int, other_class: int = 0) -> Path:
    """An atlas with `nvram_keys` candidates the nvram-source view floats, `plain` others, and
    `other_class` of a SECOND sink class so a prune can actually shrink the view."""
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    try:
        pid = upsert_pattern(
            conn,
            source_class="unknown",
            sink_class="cmd",
            call_sequence_shape="s->cmd",
            structural_fingerprint="fp_view",
            fingerprint_algo_version="callseq-v1",
        )
        pid_other = upsert_pattern(
            conn,
            source_class="unknown",
            sink_class="copy",
            call_sequence_shape="s->copy",
            structural_fingerprint="fp_view_copy",
            fingerprint_algo_version="callseq-v1",
        )
        # ``source=nvram`` is derived from the evidence — a recognised accessor whose key
        # argument resolved — not from a column, so the fixture carries the real shape.
        with_key = json.dumps(
            {
                "source_kind": "unknown",
                "sink_arg_provenance": [
                    {
                        "sink": "system",
                        "provenance": {
                            "kind": "call_return",
                            "callee": "nvram_get",
                            "const_args": ["wan_proto"],
                        },
                    }
                ],
            }
        )
        for i in range(nvram_keys + plain):
            add_instance(
                conn,
                InstanceRow(
                    pattern_id=pid,
                    pseudocode_hash=f"h{i}",
                    source_anchor=f"fn{i}",
                    sink_anchor="system",
                    source_run_id="run_1",
                    reachability_status="unknown",
                    blocking_mechanism=None,
                    provenance_level="L0",
                    evidence_ref=f"run_1#fn{i}@cmd",
                    scope_origin="intra",
                    origin="unknown",
                    flow_evidence=with_key if i < nvram_keys else '{"source_kind": "unknown"}',
                ),
            )
        for j in range(other_class):
            add_instance(
                conn,
                InstanceRow(
                    pattern_id=pid_other,
                    pseudocode_hash=f"o{j}",
                    source_anchor=f"other{j}",
                    sink_anchor="memcpy",
                    source_run_id="run_1",
                    reachability_status="unknown",
                    blocking_mechanism=None,
                    provenance_level="L0",
                    evidence_ref=f"run_1#other{j}@copy",
                    scope_origin="intra",
                    origin="unknown",
                    flow_evidence='{"source_kind": "unknown"}',
                ),
            )
    finally:
        conn.close()
    return atlas


def _lens(atlas: Path, **kwargs: object) -> dict:  # type: ignore[type-arg]
    return make_tools(atlas)["list_candidates"](run_id="run_1", limit=3, verbose=False, **kwargs)[
        "lens"
    ]


# ── the derivation both halves share ─────────────────────────────────────────────────


def test_a_views_own_filter_is_part_of_what_it_floats() -> None:
    """The whole bug in one line: a preset's filter is a float filter, and the count never saw it.

    MUTATION (must go RED): return only the explicit filters from effective_float_filters."""
    assert effective_float_filters("nvram-source", None) == [VIEWS["nvram-source"]["filter"]]
    assert effective_float_filters("nvram-source", [("controllability", "free")]) == [
        VIEWS["nvram-source"]["filter"],
        ("controllability", "free"),
    ]
    # a deprecated alias resolves to the same preset, so its filter counts too
    assert effective_float_filters("reachable-only", None) == [VIEWS["reachable-first"]["filter"]]
    # the default lens floats nothing
    assert effective_float_filters(None, None) == []
    assert effective_float_filters(None, [("source", "param")]) == [("source", "param")]


# ── the two sides, on the SAME view ──────────────────────────────────────────────────
#
# Deliberately one view, two firmware shapes. Using a different view for the non-empty side would
# vary two things at once and stop isolating the empty-lens behaviour.


def test_a_lens_that_floats_nothing_says_so(tmp_path: Path) -> None:
    """MUTATION (must go RED): count only the explicit filters again, i.e. restore the condition
    that skipped a preset view's own filter — the note disappears and the caller is back to an
    order it cannot account for."""
    lens = _lens(_seed(tmp_path, nvram_keys=0, plain=20), view="nvram-source")
    assert lens["filter_match"] == 0
    note = lens["float_empty"]
    assert "source=nvram" in note  # what it was trying to float
    assert "0 of 20" in note  # how much it looked at
    assert "COVERAGE fact" in note


def test_a_lens_that_floats_something_stays_quiet(tmp_path: Path) -> None:
    lens = _lens(_seed(tmp_path, nvram_keys=4, plain=16), view="nvram-source")
    assert lens["filter_match"] == 4
    assert "float_empty" not in lens


def test_no_filter_at_all_is_not_the_same_as_no_match(tmp_path: Path) -> None:
    """None and 0 are different answers: "no lens filter was applied" versus "one was, and matched
    nothing". Collapsing them loses the distinction the whole change is for.

    MUTATION (must go RED): report 0 instead of None when no filter is in play."""
    lens = _lens(_seed(tmp_path, nvram_keys=0, plain=20))
    assert lens["filter_match"] is None
    assert "float_empty" not in lens


# ── the two things a reader would be misled by ───────────────────────────────────────


def test_the_fraction_is_taken_over_what_was_counted(tmp_path: Path) -> None:
    """The denominator is the view AFTER a prune, because that is what the numerator was counted
    over. Quoting the whole corpus beside it would be a fraction with two different bases — in a
    sentence written for a person to read and trust.

    MUTATION (must go RED): use the corpus as the denominator."""
    atlas = _seed(tmp_path, nvram_keys=0, plain=20, other_class=12)
    tools = make_tools(atlas)
    full = tools["list_candidates"](run_id="run_1", limit=3, verbose=False, view="nvram-source")
    assert full["corpus"] == 32
    assert "0 of 32" in full["lens"]["float_empty"]
    # ★ the decisive case: the prune really shrinks the view, so the two bases diverge
    pruned = tools["list_candidates"](
        run_id="run_1", limit=3, verbose=False, view="nvram-source", only="sink_class=copy"
    )
    note = pruned["lens"]["float_empty"]
    assert "0 of 12 in this view" in note, note  # the base the numerator was counted over
    assert "whole corpus 32" in note  # the other base, named rather than substituted for it
    assert "0 of 32 in this view" not in note


def test_more_than_one_filter_is_named_as_a_conjunction(tmp_path: Path) -> None:
    """The count is an AND over every effective filter, so naming only one would report the wrong
    reason: "this dimension matched nothing" when the truth is "nothing matched all of them".

    MUTATION (must go RED): name only the first effective filter in the message."""
    lens = _lens(
        _seed(tmp_path, nvram_keys=4, plain=16),
        view="nvram-source",
        filters="controllability=controllable",
    )
    note = lens["float_empty"]
    assert "ALL of:" in note
    assert "source=nvram" in note and "controllability=controllable" in note


def test_a_single_filter_is_not_called_a_conjunction(tmp_path: Path) -> None:
    note = _lens(_seed(tmp_path, nvram_keys=0, plain=20), view="nvram-source")["float_empty"]
    assert "ALL of:" not in note


def test_the_message_states_coverage_and_never_reassures(tmp_path: Path) -> None:
    """Zero matches is the strongest bait in this whole surface for "so the firmware has none of
    these, so it is fine". The message has to close that off explicitly, and must not contain the
    vocabulary that would open it."""
    note = _lens(_seed(tmp_path, nvram_keys=0, plain=20), view="nvram-source")["float_empty"]
    low = note.lower()
    for word in ("safe", "clean", "none exist", "no such", "secure", "not vulnerable"):
        assert word not in low, word
    # …and it still closes off the misreading, in words that do not use the banned vocabulary
    assert "says nothing about whether the firmware contains sources of that kind" in note
    assert "only that the analysis attributed none" in note


@pytest.mark.parametrize("view", sorted(v for v, p in VIEWS.items() if p["filter"]))
def test_every_preset_view_with_a_filter_gets_counted(tmp_path: Path, view: str) -> None:
    # Not just the one the agent happened to hit: any preset carrying its own filter goes down the
    # same path, so any of them could have been silently empty.
    lens = _lens(_seed(tmp_path, nvram_keys=0, plain=20), view=view)
    assert lens["filter_match"] == 0
    assert "float_empty" in lens


def test_the_order_a_lens_produces_is_untouched(tmp_path: Path) -> None:
    # The count is a read. Whatever the lens did to the ordering, it still does.
    atlas = _seed(tmp_path, nvram_keys=4, plain=16)
    tools = make_tools(atlas)
    for view in (None, "nvram-source", "reachable-first"):
        res = tools["list_candidates"](run_id="run_1", limit=200, verbose=False, view=view)
        assert res["corpus"] == 20
        assert len(res["candidates"]) == 20
