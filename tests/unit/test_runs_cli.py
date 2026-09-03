# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""CLI ergonomics for runs (M8): `tmap runs` lists the atlas's scans + lineage, `tmap triage` prints
the current run's lineage at the top (the stale-scan guard), and `--run` tab-completes run ids."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

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
    assert "complete" in r.output and "build pv_a" in r.output  # lineage shown
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


def test_runs_shows_the_hunt_stamp_and_the_row_count(tmp_path: Path) -> None:
    """★ The stamp decides whether a re-scan would do any work, so it belongs on the line a person
    reads — not only in --json.

    Without it, `tmap rescan` offering to redo a run is unexplained: the human view showed the
    build hash matching and nothing else, so the run looked current. Both parts distinguish "not
    recorded" from a value: ``hunt none`` and ``rows ?`` are honestly unknown, which is not the
    same as a run that graded zero candidates.

    MUTATION: drop the hunt/rows parts from ``_run_lineage_line`` -> RED.
    """
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    begin_run(conn, "stamped", analysis_db_path="/ws/a.db", build_hash="pv_a")
    finish_run(conn, "stamped", binaries=3, functions=9, hunt_commit="f" * 40, hunt_instances=1683)
    begin_run(conn, "unstamped", analysis_db_path="/ws/b.db", build_hash="pv_a")
    finish_run(conn, "unstamped", binaries=1, functions=2)
    conn.close()

    out = CliRunner().invoke(runs, ["--atlas", str(atlas)])
    assert out.exit_code == 0, out.output
    assert "hunt ffffffffffff" in out.output
    assert "rows 1683" in out.output
    assert "hunt none" in out.output
    assert "rows ?" in out.output


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
