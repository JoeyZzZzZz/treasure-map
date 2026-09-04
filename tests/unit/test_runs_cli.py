# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""CLI ergonomics for runs (M8): `tmap runs` lists the atlas's scans + lineage, `tmap triage` prints
the current run's lineage at the top (the stale-scan guard), and `--run` tab-completes run ids."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from treasure_map.cli import hunt_cli
from treasure_map.cli.hunt_cli import _complete_run_id, runs, triage
from treasure_map.lib.analyze.ghidra_runner import current_pass_version
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import InstanceRow
from treasure_map.lib.atlas.writer import add_instance, begin_run, finish_run, upsert_pattern


def _atlas_with_runs(tmp_path: Path) -> Path:
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    # a fully-recorded run
    begin_run(conn, "rt_scanned", analysis_db_path="/ws/rt/analysis.db", build_hash="pv_a")
    finish_run(conn, "rt_scanned", binaries=12, functions=3400)
    # a pre-existing run: candidates only, no lineage row
    pid = upsert_pattern(
        conn, source_class="external_input", sink_class="cmd", call_sequence_shape="s->cmd"
    )
    add_instance(
        conn,
        InstanceRow(
            pattern_id=pid,
            pseudocode_hash="h1",
            sink_anchor="FUN_1",
            source_run_id="old_preexisting",
            evidence_ref="old_preexisting#fn1",
        ),
    )
    conn.close()
    return atlas


def test_runs_lists_lineage_and_flags_unresolved(tmp_path: Path) -> None:
    atlas = _atlas_with_runs(tmp_path)
    r = CliRunner().invoke(runs, ["--atlas", str(atlas)])
    assert r.exit_code == 0, r.output
    assert "rt_scanned" in r.output
    assert "complete" in r.output  # status shown
    assert "12 bins / 3400 fns" in r.output
    # the pre-existing (instance-only) run is VISIBLE but flagged, never hidden
    assert "old_preexisting" in r.output
    assert "no lineage row" in r.output


def test_runs_json_mode(tmp_path: Path) -> None:
    atlas = _atlas_with_runs(tmp_path)
    r = CliRunner().invoke(runs, ["--atlas", str(atlas), "--json"])
    assert r.exit_code == 0, r.output
    data = json.loads(r.output)
    by_id = {row["run_id"]: row for row in data}
    assert by_id["rt_scanned"]["scan_status"] == "complete"
    assert by_id["rt_scanned"]["resolved"] is True
    assert by_id["old_preexisting"]["resolved"] is False  # honestly unresolved


def test_runs_empty_atlas_is_friendly(tmp_path: Path) -> None:
    atlas = tmp_path / "atlas.db"
    open_atlas(atlas).close()
    r = CliRunner().invoke(runs, ["--atlas", str(atlas)])
    assert r.exit_code == 0
    assert "no runs" in r.output and "tmap scan" in r.output


def test_triage_prints_run_lineage_header(tmp_path: Path) -> None:
    # ★ M8c: the current run's lineage rides the top of the triage view (the stale-scan guard).
    atlas = _atlas_with_runs(tmp_path)
    r = CliRunner().invoke(triage, ["--run", "rt_scanned", "--atlas", str(atlas)])
    assert r.exit_code == 0, r.output
    assert "run: rt_scanned" in r.output and "build pv_a" in r.output


def test_triage_unscoped_shows_run_count(tmp_path: Path) -> None:
    atlas = _atlas_with_runs(tmp_path)
    r = CliRunner().invoke(triage, ["--atlas", str(atlas)])
    assert r.exit_code == 0, r.output
    assert "run(s)" in r.output and "tmap runs" in r.output


def test_run_id_completion_matches_prefix(tmp_path: Path) -> None:
    # ★ M8b: tab-completion returns the atlas's run ids that start with the incomplete token; no
    # ambiguous short-prefix auto-match (the user SEES and picks).
    atlas = _atlas_with_runs(tmp_path)

    class _Ctx:
        params = {"atlas_path": atlas}

    out = _complete_run_id(_Ctx(), None, "rt_")  # type: ignore[arg-type]
    assert [c.value for c in out] == ["rt_scanned"]
    assert _complete_run_id(_Ctx(), None, "zzz") == []  # type: ignore[arg-type]


def _run_lines(output: str) -> list[str]:
    """The per-run lines of a listing: indented, and not one of the tier's ``→`` reason lines."""
    return [
        ln
        for ln in output.splitlines()
        if ln.startswith("  ") and not ln.strip().startswith("→") and ln.strip()
    ]


def test_the_human_listing_carries_no_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ The listing answers what is here and whether it is current. The build hash, the hunt
    stamp and the row count answer neither: they are what a machine compares, they are in
    ``--json``, and on six lines they crowded out the list they were annotating.

    MUTATION: put the ``build`` / ``hunt`` / ``rows`` parts back into ``_run_lineage_line`` -> RED.
    Measured RED at 1 failed.
    """
    # A commit the stamps can differ FROM. Without it the editable install records none and every
    # run lands on the same "cannot be confirmed" reason, before the reason under test is reached.
    monkeypatch.setattr(hunt_cli, "installed_commit", lambda: "c" * 40)
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    begin_run(conn, "stamped", analysis_db_path="/ws/a.db", build_hash="pv_a")
    finish_run(conn, "stamped", binaries=3, functions=9, hunt_commit="f" * 40, hunt_instances=1683)
    begin_run(conn, "unstamped", analysis_db_path="/ws/b.db", build_hash="pv_a")
    finish_run(conn, "unstamped", binaries=1, functions=2)
    conn.close()

    out = CliRunner().invoke(runs, ["--atlas", str(atlas)])
    assert out.exit_code == 0, out.output
    # Checked on the RUN LINES, not the whole output: the tier label and the reason both
    # legitimately contain "re-hunt", so asserting over everything is a check nothing can satisfy.
    run_lines = _run_lines(out.output)
    assert run_lines, out.output
    for line in run_lines:
        for token in ("build ", "hunt ", "rows "):
            assert token not in line, (token, line)
    # what it DOES carry: the run, its state, and one line saying what to do about it
    assert "stamped" in out.output and "3 bins / 9 fns" in out.output
    assert "needs re-extraction (2):" in out.output  # build_hash 'pv_a' is not this pipeline
    assert "`tmap rescan`" in out.output


def test_the_one_run_banner_keeps_its_provenance(tmp_path: Path) -> None:
    """★ The counterweight. The banner at the top of a candidate view exists so a STALE scan
    cannot be read in silence, and that view has no ``--json`` to fall back on — so the build hash
    stays there even though the listing dropped it. Two surfaces, two questions.

    MUTATION: point ``_echo_run_lineage`` at ``_run_lineage_line`` -> RED.
    """
    atlas = _atlas_with_runs(tmp_path)
    out = CliRunner().invoke(triage, ["--run", "rt_scanned", "--atlas", str(atlas)])
    assert out.exit_code == 0, out.output
    assert "run: rt_scanned" in out.output and "build pv_a" in out.output


def test_the_reason_is_said_once_per_tier_not_once_per_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Six runs out of date for the same reason is ONE fact about the install. Repeated beside
    every line it buried the list; with a single reason the run ids are redundant too.

    MUTATION: make ``_reason_human`` return "" -> RED.
    """
    monkeypatch.setattr(hunt_cli, "installed_commit", lambda: "c" * 40)
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    for rid in ("a_run", "b_run"):
        begin_run(conn, rid, analysis_db_path=f"/ws/{rid}.db", build_hash=current_pass_version())
        finish_run(conn, rid, binaries=2, functions=3, hunt_commit="f" * 40, hunt_instances=1)
    conn.close()

    out = CliRunner().invoke(runs, ["--atlas", str(atlas)])
    assert out.exit_code == 0, out.output
    arrows = [ln for ln in out.output.splitlines() if ln.strip().startswith("→")]
    assert len(arrows) == 1, out.output
    assert arrows[0].strip() == "→ hunted by an older tmap; re-hunt is fast (no decompile)"


def test_two_reasons_in_one_tier_are_listed_apart_with_their_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Grouping must not merge two situations into whichever sentence came first — each reason
    names the runs it is about.

    MUTATION: emit only the first reason, or drop the run ids when there are several groups -> RED.
    """
    monkeypatch.setattr(hunt_cli, "installed_commit", lambda: "c" * 40)
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    begin_run(conn, "graded_old", analysis_db_path="/ws/a.db", build_hash=current_pass_version())
    finish_run(conn, "graded_old", binaries=2, functions=3, hunt_commit="f" * 40, hunt_instances=1)
    begin_run(conn, "crashed", analysis_db_path="/ws/b.db", build_hash=current_pass_version())
    finish_run(conn, "crashed", scan_status="failed", binaries=1, functions=1)
    conn.close()

    out = CliRunner().invoke(runs, ["--atlas", str(atlas)])
    assert out.exit_code == 0, out.output
    arrows = [ln.strip() for ln in out.output.splitlines() if ln.strip().startswith("→")]
    assert len(arrows) == 2, out.output
    assert any(a.endswith(": graded_old") and "older tmap" in a for a in arrows)
    assert any(a.endswith(": crashed") and "did not finish" in a for a in arrows)


def test_an_unmapped_reason_passes_through_verbatim() -> None:
    """★ Rewriting only the reasons that were thought of is how a new one becomes invisible: the
    reader would see a familiar sentence describing a situation nobody had considered.

    MUTATION: return a catch-all sentence instead of the reason -> RED.
    """
    from treasure_map.cli.hunt_cli import _reason_human

    novel = "the moon was in the wrong phase"
    assert _reason_human("hunt", novel) == novel
    assert _reason_human("extraction", novel) == novel
    # and the mapped ones ARE rewritten, so the passthrough is not simply doing nothing
    assert "re-hunt is fast" in _reason_human("hunt", "hunted by abc123def456, running 789")
    assert "decompiles 484 binaries" in _reason_human(
        "extraction", "extracted by abc, running def", binaries=484
    )


def test_runs_groups_by_which_input_moved(tmp_path: Path) -> None:
    """★ The same three tiers `tmap rescan` uses, from the same classifier — so the command that
    lists runs and the command that refreshes them cannot disagree about which are current.

    MUTATION: classify with ``run_staleness`` instead -> RED (it treats an unconfirmable run as
    current, so the un-stamped run would be reported up to date and never offered for refresh).
    """
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    begin_run(conn, "old_extract", analysis_db_path="/ws/a.db", build_hash="facefeedfacefeed")
    finish_run(conn, "old_extract", binaries=484, functions=9)
    begin_run(conn, "old_hunt", analysis_db_path="/ws/b.db", build_hash=current_pass_version())
    finish_run(conn, "old_hunt", binaries=2, functions=3)
    conn.close()

    out = CliRunner().invoke(runs, ["--atlas", str(atlas)])
    assert out.exit_code == 0, out.output
    assert "needs re-extraction (1)" in out.output
    assert "old_extract" in out.output
    assert "needs re-hunt (1)" in out.output
    assert "old_hunt" in out.output
    assert "tmap rescan" in out.output


def test_runs_json_carries_the_stamp_and_the_classification(tmp_path: Path) -> None:
    """A script gets the same answer without re-deriving it (and so cannot derive a different one).

    MUTATION: drop the ``staleness`` key from the JSON view -> RED.
    """
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    begin_run(conn, "r", analysis_db_path="/ws/a.db", build_hash="facefeedfacefeed")
    finish_run(conn, "r", hunt_commit="f" * 40, hunt_instances=12)
    conn.close()

    out = CliRunner().invoke(runs, ["--atlas", str(atlas), "--json"])
    assert out.exit_code == 0, out.output
    row = json.loads(out.output)[0]
    assert row["hunt_commit"] == "f" * 40
    assert row["hunt_instances"] == 12
    assert row["staleness"]["axis"] == "extraction"
    assert "facefeedface" in row["staleness"]["reason"]
