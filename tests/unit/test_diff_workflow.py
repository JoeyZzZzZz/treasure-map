# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The one sentence that says how a version diff is read is a single constant, and every place that
says it says it from there: the MCP server's instructions (the DIFF entry point), the two closing
lines of ``tmap diff`` and get_diff_meta's note."""

from __future__ import annotations

from pathlib import Path

import pytest

from treasure_map import mcp_app
from treasure_map.cli import hunt_cli
from treasure_map.lib.diff.driver import DiffSummary, FullDiffPlan, FullDiffSummary
from treasure_map.lib.query import diff_align
from treasure_map.lib.query.diff_workflow import DIFF_WORKFLOW


def test_the_workflow_names_the_entry_tool_and_the_calls_that_judge() -> None:
    for name in ("list_diffs", "start_diff_review", "get_diff_patch_view", "annotate_diff"):
        assert name in DIFF_WORKFLOW, name
    assert "promote" in DIFF_WORKFLOW


def test_the_instructions_have_two_entry_points_with_the_workflow_in_the_diff_one() -> None:
    """The instructions name two entry points, SCAN then DIFF; the DIFF one opens with the shared
    sentence, and the SCAN loop's step (4) stops at the ledger sentence — the diff text moved out
    of it into DIFF.

    MUTATION (verified RED, 1 failed): give the instructions their own copy of the sentence, one
    word changed -> RED; MUTATION (verified RED, 1 failed): leave a diff sentence inside step (4)
    -> RED."""
    text = mcp_app._AGENT_INSTRUCTIONS
    assert (
        "Two entry points: SCAN (one firmware's candidate map) and DIFF (two versions of " in text
    )
    scan, diff = text.index("SCAN: "), text.index("DIFF: ")
    assert scan < diff
    assert text[diff:].startswith("DIFF: " + DIFF_WORKFLOW + " get_diff_patch_view(diff_id) — ")
    step4 = text[text.index("(4) RECORD") : diff]
    assert step4.rstrip().endswith("usually not worth re-verifying.")
    assert "For a version diff, start at" not in text
    assert "start at get_diff_patch_view" not in text


def test_get_diff_meta_note_ends_with_the_workflow() -> None:
    """MUTATION (verified RED, 1 failed): drop the sentence from _META_NOTE -> RED."""
    assert diff_align._META_NOTE.endswith(" " + DIFF_WORKFLOW)


def test_get_diff_meta_note_names_skipped_micro_beside_unavailable() -> None:
    """get_diff_meta sends this note on every call: it names skipped_micro among the unverified
    counts and unavailable_by_cause as their split.

    MUTATION (verified RED, 1 failed): drop the skipped_micro sentence from _META_NOTE -> RED."""
    note = diff_align._META_NOTE
    assert "skipped_micro (a side is a micro-function" in note
    assert "unavailable_by_cause splits these two" in note


def _summary() -> DiffSummary:
    return DiffSummary(
        diff_id="runA::runB::libx",
        binary="libx",
        matched_pairs=3,
        version_skew=False,
        delta_layer_changed=0,
        delta_layer_unchanged=0,
        delta_undetermined=0,
        warnings=(),
    )


def test_the_single_binary_diff_closes_with_the_workflow(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """MUTATION (verified RED, 1 failed): close with a sentence of its own instead -> RED."""
    hunt_cli._echo_single_diff(_summary(), Path("atlas.db"), None)
    out = capsys.readouterr().out
    assert DIFF_WORKFLOW in out
    assert "get_diff_capabilities" in out  # the tools it names beside it stay
    assert "sort_by='significance'" not in out


def test_the_full_diff_closes_with_the_workflow(capsys: pytest.CaptureFixture[str]) -> None:
    """MUTATION (verified RED, 1 failed): close with a sentence of its own instead -> RED."""
    plan = FullDiffPlan(
        changed=("libx",), unchanged=(), only_in_a=(), only_in_b=(), to_diff=("libx",)
    )
    hunt_cli._echo_full_diff(FullDiffSummary(plan=plan, outcomes=(), cancelled=False), Path("a.db"))
    out = capsys.readouterr().out
    assert DIFF_WORKFLOW in out
    assert "list_diff_blindspots for un-diffed binaries" in out
    assert "sort_by='significance'" not in out


def test_an_interrupted_full_diff_counts_only_what_it_finished_as_new(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """T-I2. Cancelled after 5 of 15 planned new binaries: the roll-up says 5 new, not 15 — the
    other ten were never diffed and are left for the next run.

    MUTATION (verified RED): quote ``len(plan.to_diff)`` again -> "15 new"."""
    from treasure_map.lib.diff.driver import BinaryDiffOutcome, DiffSummary

    names = tuple(f"lib{i:02d}" for i in range(15))
    plan = FullDiffPlan(changed=names, unchanged=(), only_in_a=(), only_in_b=(), to_diff=names)

    def ok(name: str) -> BinaryDiffOutcome:
        summary = DiffSummary(
            diff_id=f"a::b::{name}",
            binary=name,
            matched_pairs=1,
            version_skew=False,
            delta_layer_changed=0,
            delta_layer_unchanged=0,
            delta_undetermined=0,
            warnings=(),
        )
        return BinaryDiffOutcome(name, summary, None)

    outcomes = tuple(ok(n) for n in names[:5])
    hunt_cli._echo_full_diff(
        FullDiffSummary(plan=plan, outcomes=outcomes, cancelled=True), Path("a.db")
    )
    out = capsys.readouterr().out
    assert "5 ok (5 new, 0 skipped-already-ok), 0 failed this run" in out
