# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Neutral read-side aggregations over atlas instances.

Every row these readers return is a LEAD / candidate, never a confirmed result and never
a labeled bug. They are mechanism aggregations (counts, fingerprint groupings) only — no
score, no ranking, no judgment. Any interpretation of them is out of scope here.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

# M2 fine fingerprint = instance.pseudocode_hash. Every surfaced pattern_breadth carries this
# so the count is never read apart from the algorithm version it was computed under.
FINE_FP_ALGO_VERSION = "fp0:pseudocode_hash"


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


@dataclass(frozen=True)
class LedgerRow:
    """The two derived recurrence ledgers for one pattern, computed on read.

    device_spread   = distinct source_run_id over the pattern's instances (exposure; counts
                      every instance).
    pattern_breadth = distinct fine fingerprints (pseudocode_hash) over instances with origin
                      in (custom, unknown); a provisional upper bound under
                      fine_fp_algo_version (included origins = custom, unknown).
    """

    pattern_id: int
    sink_class: str
    structural_fingerprint: str | None
    device_spread: int
    pattern_breadth: int
    fine_fp_algo_version: str


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


def ledger(conn: sqlite3.Connection) -> list[LedgerRow]:
    """Return the two derived ledgers per pattern (computed on read, never stored frozen).

    pattern_breadth = distinct fine fingerprints (pseudocode_hash) over origin in
    (custom, unknown); a provisional upper bound under FINE_FP_ALGO_VERSION (included origins
    = custom, unknown). device_spread = distinct source_run_id (exposure).
    """
    rows = conn.execute(
        "SELECT pattern_id, sink_class, structural_fingerprint, device_spread, pattern_breadth "
        "FROM pattern_ledger "
        "ORDER BY pattern_breadth DESC, device_spread DESC, pattern_id"
    ).fetchall()
    return [
        LedgerRow(
            pattern_id=int(r["pattern_id"]),
            sink_class=r["sink_class"],
            structural_fingerprint=r["structural_fingerprint"],
            device_spread=int(r["device_spread"]),
            pattern_breadth=int(r["pattern_breadth"]),
            fine_fp_algo_version=FINE_FP_ALGO_VERSION,
        )
        for r in rows
    ]
