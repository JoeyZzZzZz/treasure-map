# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
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
from treasure_map.lib.query import density, dormant, twins


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
