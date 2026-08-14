# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for lib/query/views — neutral atlas aggregations (density / twins / dormant).

Builds atlas instances directly (no analyzer) to isolate the view logic, then asserts the
group-by counts, the twin (mixed-status) detection, and the dormant reuse.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import InstanceRow
from treasure_map.lib.atlas.writer import add_instance, upsert_pattern
from treasure_map.lib.query import FINE_FP_ALGO_VERSION, density, dormant, ledger, twins


def _pattern(conn: sqlite3.Connection, fp: str, sink_class: str = "cmd") -> int:
    return upsert_pattern(
        conn,
        source_class="external_input",
        sink_class=sink_class,
        call_sequence_shape="source->format->cmd",
        structural_fingerprint=fp,
        fingerprint_algo_version="callseq-v1",
    )


def _inst(
    conn: sqlite3.Connection,
    pattern_id: int,
    *,
    status: str,
    run_id: str,
    h: str,
    origin: str = "unknown",
) -> None:
    provenance = "L1" if status in {"confirmed", "blocked"} else "L0"
    add_instance(
        conn,
        InstanceRow(
            pattern_id=pattern_id,
            pseudocode_hash=h,
            source_run_id=run_id,
            reachability_status=status,
            blocking_mechanism="a validator-style call is applied" if status == "blocked" else None,
            provenance_level=provenance,
            evidence_ref=f"fp-{pattern_id}",
            scope_origin="intra",
            origin=origin,
        ),
    )


def _atlas(tmp_path: Path) -> sqlite3.Connection:
    return open_atlas(tmp_path / "atlas.db")


# ── density ─────────────────────────────────────────────────────────────────────────


def test_density_groups_by_run_sink_and_fingerprint(tmp_path: Path) -> None:
    conn = _atlas(tmp_path)
    p_cmd = _pattern(conn, "fp_cmd", "cmd")
    p_copy = _pattern(conn, "fp_copy", "copy")
    _inst(conn, p_cmd, status="unknown", run_id="run_dcs", h="a")
    _inst(conn, p_cmd, status="unknown", run_id="run_dcs", h="b")
    _inst(conn, p_copy, status="unknown", run_id="run_dcs", h="c")

    rows = density(conn)
    by_fp = {r.structural_fingerprint: r for r in rows}
    assert by_fp["fp_cmd"].instance_count == 2
    assert by_fp["fp_cmd"].sink_class == "cmd"
    assert by_fp["fp_copy"].instance_count == 1
    conn.close()


# ── twins ─────────────────────────────────────────────────────────────────────────


def test_twins_surface_only_mixed_status_fingerprints(tmp_path: Path) -> None:
    conn = _atlas(tmp_path)
    mixed = _pattern(conn, "fp_mixed", "cmd")
    uniform = _pattern(conn, "fp_uniform", "copy")
    # mixed: one blocked + one unknown over the same fingerprint -> a twin.
    _inst(conn, mixed, status="blocked", run_id="r1", h="m1")
    _inst(conn, mixed, status="unknown", run_id="r1", h="m2")
    # uniform: two unknown -> NOT a twin.
    _inst(conn, uniform, status="unknown", run_id="r1", h="u1")
    _inst(conn, uniform, status="unknown", run_id="r1", h="u2")

    rows = twins(conn)
    fps = {r.structural_fingerprint for r in rows}
    assert fps == {"fp_mixed"}
    (twin,) = rows
    assert twin.blocked_count == 1
    assert twin.non_blocked_count == 1
    conn.close()


# ── dormant ─────────────────────────────────────────────────────────────────────────


def test_dormant_returns_blocked_instances(tmp_path: Path) -> None:
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp", "cmd")
    _inst(conn, p, status="blocked", run_id="r1", h="b1")
    _inst(conn, p, status="unknown", run_id="r1", h="u1")

    rows = dormant(conn)
    assert len(rows) == 1  # only the blocked instance
    assert rows[0]["reachability_status"] == "blocked"
    conn.close()


# ── ledger: device_spread vs pattern_breadth (the two-ledger split) ──────────────────


def _ledger_for(conn: sqlite3.Connection, pattern_id: int):  # type: ignore[no-untyped-def]
    (row,) = [r for r in ledger(conn) if r.pattern_id == pattern_id]
    return row


def test_ledger_same_hash_different_runs_breadth_one(tmp_path: Path) -> None:
    # Two instances, different source_run_id, SAME pseudocode_hash (version-pair / same blob
    # copy): device_spread counts artifact distribution (2), pattern_breadth counts distinct
    # fine fingerprints (1). This is the split that keeps copies from inflating breadth.
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp_a", "cmd")
    _inst(conn, p, status="unknown", run_id="r1", h="same")
    _inst(conn, p, status="unknown", run_id="r2", h="same")

    row = _ledger_for(conn, p)
    assert row.device_spread == 2
    assert row.pattern_breadth == 1
    conn.close()


def test_ledger_different_hash_different_runs_breadth_two(tmp_path: Path) -> None:
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp_b", "cmd")
    _inst(conn, p, status="unknown", run_id="r1", h="h1")
    _inst(conn, p, status="unknown", run_id="r2", h="h2")

    row = _ledger_for(conn, p)
    assert row.device_spread == 2
    assert row.pattern_breadth == 2
    conn.close()


def test_ledger_stock_oss_known_leaves_breadth_keeps_spread(tmp_path: Path) -> None:
    # An instance recognized as stock_oss_known exits pattern_breadth (origin not in
    # custom/unknown) but stays in device_spread (exposure counts everything).
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp_c", "cmd")
    _inst(conn, p, status="unknown", run_id="r1", h="h1", origin="unknown")
    _inst(conn, p, status="unknown", run_id="r2", h="h2", origin="stock_oss_known")

    row = _ledger_for(conn, p)
    assert row.device_spread == 2  # exposure: both runs
    assert row.pattern_breadth == 1  # only the custom/unknown instance counts
    conn.close()


def test_ledger_rows_carry_fine_fp_algo_version(tmp_path: Path) -> None:
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp_d", "cmd")
    _inst(conn, p, status="unknown", run_id="r1", h="h1")

    row = _ledger_for(conn, p)
    assert row.fine_fp_algo_version == FINE_FP_ALGO_VERSION == "fp0:pseudocode_hash"
    conn.close()


def test_pattern_breadth_is_derived_not_stored(tmp_path: Path) -> None:
    # pattern_breadth recomputes on read (a new distinct hash bumps it), and it is NOT a
    # stored column on the pattern table.
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp_e", "cmd")
    _inst(conn, p, status="unknown", run_id="r1", h="h1")
    assert _ledger_for(conn, p).pattern_breadth == 1

    _inst(conn, p, status="unknown", run_id="r1", h="h2")  # same run, new fine fingerprint
    assert _ledger_for(conn, p).pattern_breadth == 2  # recomputed on read

    pattern_cols = {r[1] for r in conn.execute("PRAGMA table_info(pattern)").fetchall()}
    assert "pattern_breadth" not in pattern_cols  # derived only, never frozen on the table
    conn.close()
