# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the atlas ``run`` lineage table + the run resolver/enumerator.

The run table is the AUTHORITY mapping a neutral run_id to its analysis.db (there is no reliable
workspaces/<run_id> path convention). These prove: begin_run/finish_run write the lifecycle
honestly (in_progress at start, complete at end, a crash leaves in_progress), get_run distinguishes
"absent" from "present but no lineage row", and list_runs unions the run table with pre-existing
instance-only runs (visible but honestly unresolved).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from treasure_map.lib.atlas import (
    InstanceRow,
    add_instance,
    begin_run,
    finish_run,
    open_atlas,
    upsert_pattern,
)
from treasure_map.lib.errors import ConfigError
from treasure_map.lib.query import get_run, list_runs, runs_where_function_exists


@pytest.fixture
def atlas_conn(tmp_path: Path) -> sqlite3.Connection:
    return open_atlas(tmp_path / "atlas.db")


def _seed_instance(conn: sqlite3.Connection, run_id: str, *, function: str = "FUN_1") -> None:
    pid = upsert_pattern(
        conn, source_class="external_input", sink_class="cmd", call_sequence_shape="s->cmd"
    )
    add_instance(
        conn,
        InstanceRow(
            pattern_id=pid,
            pseudocode_hash=f"h_{run_id}_{function}",
            sink_anchor=function,
            source_run_id=run_id,
            evidence_ref=f"{run_id}#{function}",
            binary_path=f"/fw/{run_id}/sbin/{function}",
        ),
    )


# ── begin_run / finish_run lifecycle ────────────────────────────────────────


def test_begin_run_writes_in_progress(atlas_conn: sqlite3.Connection) -> None:
    begin_run(atlas_conn, "run_a", analysis_db_path="/ws/run_a/analysis.db", build_hash="pv1")
    run = get_run(atlas_conn, "run_a")
    assert run is not None
    assert run.scan_status == "in_progress"  # started, NOT yet finished
    assert run.analysis_db_path == "/ws/run_a/analysis.db"  # the resolver field
    assert run.build_hash == "pv1"
    assert run.resolved is True


def test_finish_run_completes_with_counts(atlas_conn: sqlite3.Connection) -> None:
    begin_run(atlas_conn, "run_a", analysis_db_path="/ws/run_a/analysis.db")
    finish_run(atlas_conn, "run_a", binaries=12, functions=3400, functions_empty=7)
    run = get_run(atlas_conn, "run_a")
    assert run is not None
    assert run.scan_status == "complete"
    assert (run.binaries, run.functions, run.functions_empty) == (12, 3400, 7)
    assert run.analysis_db_path == "/ws/run_a/analysis.db"  # preserved across finish


def test_crash_leaves_in_progress(atlas_conn: sqlite3.Connection) -> None:
    # begin_run without a matching finish_run == a scan that started and never finished. The honest
    # signal is that the run stays 'in_progress' (never silently reads complete).
    begin_run(atlas_conn, "run_crash", analysis_db_path="/ws/run_crash/analysis.db")
    run = get_run(atlas_conn, "run_crash")
    assert run is not None and run.scan_status == "in_progress"


def test_rescan_resets_to_in_progress_and_refreshes_lineage(atlas_conn: sqlite3.Connection) -> None:
    begin_run(atlas_conn, "run_a", analysis_db_path="/old/analysis.db", build_hash="pv_old")
    finish_run(atlas_conn, "run_a", binaries=1, functions=1)
    # A re-scan reopens the same run_id: it must flip back to in_progress with the fresh lineage
    # (its old instances are being replaced), never keep the stale 'complete' + old build_hash.
    begin_run(atlas_conn, "run_a", analysis_db_path="/new/analysis.db", build_hash="pv_new")
    run = get_run(atlas_conn, "run_a")
    assert run is not None
    assert run.scan_status == "in_progress"
    assert run.analysis_db_path == "/new/analysis.db"
    assert run.build_hash == "pv_new"


def test_finish_run_inserts_when_row_missing(atlas_conn: sqlite3.Connection) -> None:
    # finish_run on a run with no begin_run row still records it (a finished run stays visible).
    finish_run(atlas_conn, "run_late", binaries=2, functions=9)
    run = get_run(atlas_conn, "run_late")
    assert run is not None and run.scan_status == "complete"


def test_finish_run_rejects_bad_status(atlas_conn: sqlite3.Connection) -> None:
    begin_run(atlas_conn, "run_a")
    with pytest.raises(ConfigError):
        finish_run(atlas_conn, "run_a", scan_status="done")  # not in the enum


# ── get_run: absent vs present-but-unresolved ───────────────────────────────


def test_get_run_none_when_absent(atlas_conn: sqlite3.Connection) -> None:
    assert get_run(atlas_conn, "nope") is None


def test_get_run_unresolved_for_instance_only_run(atlas_conn: sqlite3.Connection) -> None:
    # A pre-existing scan: candidates exist under this run_id, but no run-table row. get_run must
    # surface it (present) yet honestly mark it unresolved (no analysis.db path) — so a fact tool
    # distinguishes "run not in atlas" (None) from "run exists but analysis.db never recorded".
    _seed_instance(atlas_conn, "run_preexisting")
    run = get_run(atlas_conn, "run_preexisting")
    assert run is not None
    assert run.resolved is False
    assert run.analysis_db_path is None
    assert run.scan_status == "unknown"


# ── list_runs: union of run table + instance-only runs ──────────────────────


def test_list_runs_unions_resolved_and_unresolved(atlas_conn: sqlite3.Connection) -> None:
    begin_run(atlas_conn, "run_scanned", analysis_db_path="/ws/run_scanned/analysis.db")
    finish_run(atlas_conn, "run_scanned", binaries=3, functions=30)
    _seed_instance(atlas_conn, "run_preexisting")
    runs = {r.run_id: r for r in list_runs(atlas_conn)}
    assert set(runs) == {"run_scanned", "run_preexisting"}
    assert runs["run_scanned"].resolved is True
    assert runs["run_scanned"].scan_status == "complete"
    assert runs["run_preexisting"].resolved is False  # visible but no lineage


def test_list_runs_resolved_before_unresolved(atlas_conn: sqlite3.Connection) -> None:
    _seed_instance(atlas_conn, "aaa_preexisting")  # would sort first alphabetically
    begin_run(atlas_conn, "zzz_scanned", analysis_db_path="/ws/zzz/analysis.db")
    finish_run(atlas_conn, "zzz_scanned")
    order = [r.run_id for r in list_runs(atlas_conn)]
    assert order.index("zzz_scanned") < order.index("aaa_preexisting")  # resolved lead


def test_runs_where_function_exists_points_to_owning_run(atlas_conn: sqlite3.Connection) -> None:
    _seed_instance(atlas_conn, "run_x", function="FUN_target")
    _seed_instance(atlas_conn, "run_y", function="FUN_other")
    hits = runs_where_function_exists(atlas_conn, binary=None, function="FUN_target")
    assert hits == ["run_x"]
    assert runs_where_function_exists(atlas_conn, binary=None, function="FUN_absent") == []
