# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""CLI ergonomics for runs (M8): `tmap runs` lists the atlas's scans + lineage, `tmap triage` prints
the current run's lineage at the top (the stale-scan guard), and `--run` tab-completes run ids."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from treasure_map.cli.hunt_cli import _complete_run_id, runs, triage
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
