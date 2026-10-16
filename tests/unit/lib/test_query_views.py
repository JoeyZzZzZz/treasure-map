# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for lib/query/views — neutral atlas aggregations (density / ledger).

Builds atlas instances directly (no analyzer) to isolate the view logic, then asserts the
group-by counts and the two derived recurrence ledgers.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import InstanceRow
from treasure_map.lib.atlas.writer import add_instance, upsert_pattern
from treasure_map.lib.query import FINE_FP_ALGO_VERSION, density, ledger


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
    _inst(conn, p_cmd, status="unknown", run_id="run_cam", h="a")
    _inst(conn, p_cmd, status="unknown", run_id="run_cam", h="b")
    _inst(conn, p_copy, status="unknown", run_id="run_cam", h="c")

    rows = density(conn)
    by_fp = {r.structural_fingerprint: r for r in rows}
    assert by_fp["fp_cmd"].instance_count == 2
    assert by_fp["fp_cmd"].sink_class == "cmd"
    assert by_fp["fp_copy"].instance_count == 1
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
    # A labelled instance exits pattern_breadth (origin not in custom/unknown) but stays in
    # device_spread (exposure counts everything). The predicate is unchanged and still tested,
    # but nothing WRITES that label any more: the symbol-name guess that produced it was retired,
    # so rows like this one exist only in atlas data from before that, until their run is hunted
    # again. Kept because the clause is where a content-based classifier would attach, and a
    # predicate nobody tests is a predicate nobody notices breaking.
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


# ── retiring an origin label: what it can and cannot do to the ledger ─────────────────


def _breadth(conn: sqlite3.Connection, pattern_id: int) -> int:
    return _ledger_for(conn, pattern_id).pattern_breadth


def test_relabelling_stock_to_unknown_only_widens_breadth_and_by_a_bounded_amount(
    tmp_path: Path,
) -> None:
    """The one ledger the retirement actually moves, bounded in both directions.

    Re-hunting a run after the retirement rewrites its instances' origin to 'unknown', which is
    what this simulates. Two things have to hold and they are different claims:

    * breadth can only go UP. The clause admits more rows, never fewer — if it ever went down, the
      predicate would have started excluding something it did not before.
    * it goes up by AT MOST the distinct fingerprints that were being excluded, per pattern. Adding
      rows to a COUNT DISTINCT adds at most the number of distinct new values.

    ★ Per PATTERN, not summed across them. The summed delta can EXCEED the globally-distinct count
    of excluded fingerprints, because one pseudocode_hash can sit under several patterns and be
    counted once in each — so a summed delta can exceed the globally-distinct count, and an
    aggregate bound stated that way is simply not an upper bound. The
    per-pattern form is the one that is arithmetically true.

    MUTATION (must go RED): change the origin clause to admit a different set (e.g. drop 'custom',
    or exclude 'unknown') — the count then moves in a way neither bound allows."""
    conn = _atlas(tmp_path)
    p1 = _pattern(conn, "fp_a", "cmd")
    p2 = _pattern(conn, "fp_b", "copy")
    # p1: one unlabelled body, two labelled ones (one of which duplicates the unlabelled hash, so
    # the bound is not trivially the row count).
    _inst(conn, p1, status="unknown", run_id="r1", h="h1", origin="unknown")
    _inst(conn, p1, status="unknown", run_id="r1", h="h2", origin="stock_oss_known")
    _inst(conn, p1, status="unknown", run_id="r1", h="h1", origin="stock_oss_known")
    # p2: labelled only — its breadth is 0 today and becomes 1.
    _inst(conn, p2, status="unknown", run_id="r1", h="h9", origin="stock_oss_known")

    before = {p1: _breadth(conn, p1), p2: _breadth(conn, p2)}
    assert before == {p1: 1, p2: 0}

    bound = {
        pid: conn.execute(
            "SELECT COUNT(DISTINCT pseudocode_hash) FROM instance "
            "WHERE pattern_id = ? AND origin NOT IN ('custom','unknown') "
            "AND pseudocode_hash IS NOT NULL",
            (pid,),
        ).fetchone()[0]
        for pid in (p1, p2)
    }
    assert bound == {p1: 2, p2: 1}

    conn.execute("UPDATE instance SET origin = 'unknown'")  # what a re-hunt now writes
    conn.commit()

    for pid in (p1, p2):
        after = _breadth(conn, pid)
        assert after >= before[pid], "the clause admits more rows; breadth cannot shrink"
        assert after - before[pid] <= bound[pid], "grew by more than the excluded fingerprints"
    assert _breadth(conn, p1) == 2  # h1 was already counted; only h2 is new
    assert _breadth(conn, p2) == 1
    conn.close()
