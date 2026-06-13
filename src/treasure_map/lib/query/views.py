# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Neutral read-side aggregations over atlas instances.

Every row these readers return is a LEAD / candidate, never a confirmed result and never
a labeled bug. They are mechanism aggregations (counts, fingerprint groupings) only — no
score, no ranking, no judgment. Any interpretation of them is out of scope here.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass


@dataclass(frozen=True)
class DensityRow:
    """Count of candidate instances clustering at a (run, sink_class, fingerprint)."""

    source_run_id: str | None
    sink_class: str
    structural_fingerprint: str | None
    instance_count: int


@dataclass(frozen=True)
class TwinRow:
    """A fingerprint seen with both a blocked and a non-blocked instance (same shape, mixed)."""

    structural_fingerprint: str | None
    sink_class: str
    blocked_count: int
    non_blocked_count: int


def dormant(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Return the blocked candidate instances (R2's blocked partition, L0/L1) — free reuse."""
    return conn.execute("SELECT * FROM dormant_instance ORDER BY instance_id").fetchall()


def density(conn: sqlite3.Connection) -> list[DensityRow]:
    """Return candidate-instance density per (run, sink_class, fingerprint)."""
    rows = conn.execute(
        "SELECT source_run_id, sink_class, structural_fingerprint, instance_count "
        "FROM density_candidate "
        "ORDER BY instance_count DESC, sink_class, structural_fingerprint"
    ).fetchall()
    return [
        DensityRow(
            source_run_id=r["source_run_id"],
            sink_class=r["sink_class"],
            structural_fingerprint=r["structural_fingerprint"],
            instance_count=int(r["instance_count"]),
        )
        for r in rows
    ]


def twins(conn: sqlite3.Connection) -> list[TwinRow]:
    """Return fingerprints observed with both a blocked and a non-blocked instance."""
    rows = conn.execute(
        "SELECT structural_fingerprint, sink_class, blocked_count, non_blocked_count "
        "FROM twin_candidate "
        "ORDER BY sink_class, structural_fingerprint"
    ).fetchall()
    return [
        TwinRow(
            structural_fingerprint=r["structural_fingerprint"],
            sink_class=r["sink_class"],
            blocked_count=int(r["blocked_count"]),
            non_blocked_count=int(r["non_blocked_count"]),
        )
        for r in rows
    ]
