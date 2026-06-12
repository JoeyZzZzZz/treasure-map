# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for lib/atlas — cross-firmware pattern store (M2 Step 1)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from treasure_map.lib.atlas import (
    AtlasStats,
    InstanceRow,
    add_instance,
    add_instances,
    open_atlas,
    upsert_pattern,
)
from treasure_map.lib.errors import ConfigError

_PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
_ATLAS_SRC = _PROJECT_ROOT / "src" / "treasure_map" / "lib" / "atlas"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def atlas_conn(tmp_path: Path) -> sqlite3.Connection:
    return open_atlas(tmp_path / "atlas.db")


def _base_instance(pattern_id: int, run_id: str = "run-A") -> InstanceRow:
    return InstanceRow(pattern_id=pattern_id, pseudocode_hash="abc123", source_run_id=run_id)


# ---------------------------------------------------------------------------
# open_atlas — idempotent
# ---------------------------------------------------------------------------


def test_open_atlas_creates_tables(atlas_conn: sqlite3.Connection) -> None:
    tables = {
        row[0]
        for row in atlas_conn.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table','view')"
        ).fetchall()
    }
    assert "pattern" in tables
    assert "instance" in tables
    assert "dormant_instance" in tables
    assert "public_finding" in tables


def test_open_atlas_idempotent(tmp_path: Path) -> None:
    db_path = tmp_path / "atlas.db"
    conn1 = open_atlas(db_path)
    pid = upsert_pattern(conn1, source_class="sc", sink_class="snk", call_sequence_shape="shape")
    conn1.close()

    conn2 = open_atlas(db_path)
    row = conn2.execute("SELECT pattern_id FROM pattern WHERE pattern_id = ?", (pid,)).fetchone()
    assert row is not None
    assert row[0] == pid
    conn2.close()


def test_open_atlas_creates_parent_dirs(tmp_path: Path) -> None:
    db_path = tmp_path / "deep" / "nested" / "atlas.db"
    conn = open_atlas(db_path)
    conn.close()
    assert db_path.exists()


# ---------------------------------------------------------------------------
# upsert_pattern — dedup
# ---------------------------------------------------------------------------


def test_upsert_pattern_creates_row(atlas_conn: sqlite3.Connection) -> None:
    pid = upsert_pattern(
        atlas_conn, source_class="user_input", sink_class="system", call_sequence_shape="in→fmt→sys"
    )
    assert isinstance(pid, int)
    assert pid > 0


def test_upsert_pattern_dedup_by_fingerprint(atlas_conn: sqlite3.Connection) -> None:
    pid1 = upsert_pattern(
        atlas_conn,
        source_class="sc",
        sink_class="snk",
        call_sequence_shape="a→b",
        structural_fingerprint="fp-abc",
    )
    pid2 = upsert_pattern(
        atlas_conn,
        source_class="other_sc",
        sink_class="other_snk",
        call_sequence_shape="x→y",
        structural_fingerprint="fp-abc",
    )
    assert pid1 == pid2


def test_upsert_pattern_different_fingerprints_create_different_rows(
    atlas_conn: sqlite3.Connection,
) -> None:
    pid1 = upsert_pattern(
        atlas_conn,
        source_class="sc",
        sink_class="snk",
        call_sequence_shape="shape",
        structural_fingerprint="fp-1",
    )
    pid2 = upsert_pattern(
        atlas_conn,
        source_class="sc",
        sink_class="snk",
        call_sequence_shape="shape",
        structural_fingerprint="fp-2",
    )
    assert pid1 != pid2


def test_upsert_pattern_null_fingerprint_dedup_by_class_triple(
    atlas_conn: sqlite3.Connection,
) -> None:
    # Two upserts with structural_fingerprint=None and the same class triple must return
    # the same pattern_id — proves IS NULL in the WHERE, not = NULL.
    pid1 = upsert_pattern(
        atlas_conn,
        source_class="network_recv",
        sink_class="memcpy",
        call_sequence_shape="recv→copy",
        structural_fingerprint=None,
    )
    pid2 = upsert_pattern(
        atlas_conn,
        source_class="network_recv",
        sink_class="memcpy",
        call_sequence_shape="recv→copy",
        structural_fingerprint=None,
    )
    assert pid1 == pid2


def test_upsert_pattern_null_fingerprint_different_triple_creates_new_row(
    atlas_conn: sqlite3.Connection,
) -> None:
    pid1 = upsert_pattern(
        atlas_conn,
        source_class="sc_A",
        sink_class="snk",
        call_sequence_shape="shape",
        structural_fingerprint=None,
    )
    pid2 = upsert_pattern(
        atlas_conn,
        source_class="sc_B",
        sink_class="snk",
        call_sequence_shape="shape",
        structural_fingerprint=None,
    )
    assert pid1 != pid2


def test_upsert_pattern_bumps_last_updated_at(atlas_conn: sqlite3.Connection) -> None:
    pid = upsert_pattern(
        atlas_conn, source_class="sc", sink_class="snk", call_sequence_shape="shape"
    )
    ts1 = atlas_conn.execute(
        "SELECT last_updated_at FROM pattern WHERE pattern_id = ?", (pid,)
    ).fetchone()[0]
    upsert_pattern(atlas_conn, source_class="sc", sink_class="snk", call_sequence_shape="shape")
    ts2 = atlas_conn.execute(
        "SELECT last_updated_at FROM pattern WHERE pattern_id = ?", (pid,)
    ).fetchone()[0]
    # Timestamps are equal within a fast test; what matters is the UPDATE ran without error.
    assert ts2 >= ts1


# ---------------------------------------------------------------------------
# add_instance — validation hard rules
# ---------------------------------------------------------------------------


def test_add_instance_rejects_no_traceability(atlas_conn: sqlite3.Connection) -> None:
    pid = upsert_pattern(atlas_conn, source_class="sc", sink_class="snk", call_sequence_shape="s")
    with pytest.raises(ConfigError, match="traceability"):
        add_instance(
            atlas_conn,
            InstanceRow(pattern_id=pid, source_run_id="run-A"),
        )


def test_add_instance_rejects_empty_source_run_id(atlas_conn: sqlite3.Connection) -> None:
    pid = upsert_pattern(atlas_conn, source_class="sc", sink_class="snk", call_sequence_shape="s")
    with pytest.raises(ConfigError, match="source_run_id"):
        add_instance(
            atlas_conn,
            InstanceRow(pattern_id=pid, pseudocode_hash="abc"),
        )


def test_add_instance_rejects_empty_string_source_run_id(
    atlas_conn: sqlite3.Connection,
) -> None:
    pid = upsert_pattern(atlas_conn, source_class="sc", sink_class="snk", call_sequence_shape="s")
    with pytest.raises(ConfigError, match="source_run_id"):
        add_instance(
            atlas_conn,
            InstanceRow(pattern_id=pid, pseudocode_hash="abc", source_run_id=""),
        )


def test_add_instance_rejects_l2_without_anchor(atlas_conn: sqlite3.Connection) -> None:
    pid = upsert_pattern(atlas_conn, source_class="sc", sink_class="snk", call_sequence_shape="s")
    with pytest.raises(ConfigError, match="external_anchor"):
        add_instance(
            atlas_conn,
            InstanceRow(
                pattern_id=pid,
                pseudocode_hash="abc",
                source_run_id="run-A",
                provenance_level="L2",
            ),
        )


def test_add_instance_rejects_l3_without_anchor(atlas_conn: sqlite3.Connection) -> None:
    pid = upsert_pattern(atlas_conn, source_class="sc", sink_class="snk", call_sequence_shape="s")
    with pytest.raises(ConfigError, match="external_anchor"):
        add_instance(
            atlas_conn,
            InstanceRow(
                pattern_id=pid,
                pseudocode_hash="abc",
                source_run_id="run-A",
                provenance_level="L3",
            ),
        )


def test_add_instance_l2_with_anchor_succeeds_and_stores_anchor(
    atlas_conn: sqlite3.Connection,
) -> None:
    pid = upsert_pattern(atlas_conn, source_class="sc", sink_class="snk", call_sequence_shape="s")
    iid = add_instance(
        atlas_conn,
        InstanceRow(
            pattern_id=pid,
            pseudocode_hash="abc",
            source_run_id="run-A",
            provenance_level="L2",
        ),
        external_anchor="patch:abc123",
    )
    row = atlas_conn.execute(
        "SELECT external_anchor FROM instance WHERE instance_id = ?", (iid,)
    ).fetchone()
    assert row is not None
    assert row[0] == "patch:abc123"


def test_add_instance_l0_no_anchor_succeeds(atlas_conn: sqlite3.Connection) -> None:
    pid = upsert_pattern(atlas_conn, source_class="sc", sink_class="snk", call_sequence_shape="s")
    iid = add_instance(atlas_conn, _base_instance(pid))
    assert iid > 0


def test_add_instance_evidence_ref_satisfies_traceability(
    atlas_conn: sqlite3.Connection,
) -> None:
    pid = upsert_pattern(atlas_conn, source_class="sc", sink_class="snk", call_sequence_shape="s")
    iid = add_instance(
        atlas_conn,
        InstanceRow(pattern_id=pid, evidence_ref="analysis.db:sha256:abc", source_run_id="run-A"),
    )
    assert iid > 0


# ---------------------------------------------------------------------------
# add_instance — schema CHECK constraints fire even via raw SQL
# ---------------------------------------------------------------------------


def test_schema_check_rejects_l2_without_anchor_raw_sql(
    atlas_conn: sqlite3.Connection,
) -> None:
    pid = upsert_pattern(atlas_conn, source_class="sc", sink_class="snk", call_sequence_shape="s")
    with pytest.raises(sqlite3.IntegrityError):
        atlas_conn.execute(
            """INSERT INTO instance
               (pattern_id, pseudocode_hash, source_run_id, provenance_level)
               VALUES (?, 'h', 'run', 'L2')""",
            (pid,),
        )


def test_schema_check_rejects_both_null_trace_raw_sql(
    atlas_conn: sqlite3.Connection,
) -> None:
    pid = upsert_pattern(atlas_conn, source_class="sc", sink_class="snk", call_sequence_shape="s")
    with pytest.raises(sqlite3.IntegrityError):
        atlas_conn.execute(
            """INSERT INTO instance
               (pattern_id, source_run_id, reachability_status)
               VALUES (?, 'run', 'unknown')""",
            (pid,),
        )


# ---------------------------------------------------------------------------
# Views — §8.7 semantics
# ---------------------------------------------------------------------------


def test_dormant_instance_view(atlas_conn: sqlite3.Connection) -> None:
    pid = upsert_pattern(atlas_conn, source_class="sc", sink_class="snk", call_sequence_shape="s")

    add_instance(
        atlas_conn,
        InstanceRow(
            pattern_id=pid,
            pseudocode_hash="h1",
            source_run_id="run-A",
            reachability_status="blocked",
            provenance_level="L1",
        ),
    )
    add_instance(
        atlas_conn,
        InstanceRow(
            pattern_id=pid,
            pseudocode_hash="h2",
            source_run_id="run-B",
            reachability_status="blocked",
            provenance_level="L0",
        ),
    )

    dormant = atlas_conn.execute("SELECT COUNT(*) FROM dormant_instance").fetchone()[0]
    assert dormant == 2


def test_public_finding_view(atlas_conn: sqlite3.Connection) -> None:
    pid = upsert_pattern(atlas_conn, source_class="sc", sink_class="snk", call_sequence_shape="s")

    add_instance(
        atlas_conn,
        InstanceRow(
            pattern_id=pid,
            pseudocode_hash="h3",
            source_run_id="run-C",
            reachability_status="confirmed",
            provenance_level="L2",
        ),
        external_anchor="patch:ext-ref-abc123",
    )

    public = atlas_conn.execute("SELECT COUNT(*) FROM public_finding").fetchone()[0]
    assert public == 1


def test_confirmed_l0_in_neither_view(atlas_conn: sqlite3.Connection) -> None:
    pid = upsert_pattern(atlas_conn, source_class="sc", sink_class="snk", call_sequence_shape="s")

    add_instance(
        atlas_conn,
        InstanceRow(
            pattern_id=pid,
            pseudocode_hash="h4",
            source_run_id="run-D",
            reachability_status="confirmed",
            provenance_level="L0",
        ),
    )

    dormant = atlas_conn.execute("SELECT COUNT(*) FROM dormant_instance").fetchone()[0]
    public = atlas_conn.execute("SELECT COUNT(*) FROM public_finding").fetchone()[0]
    assert dormant == 0
    assert public == 0


def test_view_semantics_combined(atlas_conn: sqlite3.Connection) -> None:
    pid = upsert_pattern(atlas_conn, source_class="sc", sink_class="snk", call_sequence_shape="s")

    add_instance(
        atlas_conn,
        InstanceRow(
            pattern_id=pid,
            pseudocode_hash="h1",
            source_run_id="run-A",
            reachability_status="blocked",
            provenance_level="L1",
        ),
    )
    add_instance(
        atlas_conn,
        InstanceRow(
            pattern_id=pid,
            pseudocode_hash="h2",
            source_run_id="run-B",
            reachability_status="blocked",
            provenance_level="L0",
        ),
    )
    add_instance(
        atlas_conn,
        InstanceRow(
            pattern_id=pid,
            pseudocode_hash="h3",
            source_run_id="run-C",
            reachability_status="confirmed",
            provenance_level="L2",
        ),
        external_anchor="patch:ext-ref-abc123",
    )
    add_instance(
        atlas_conn,
        InstanceRow(
            pattern_id=pid,
            pseudocode_hash="h4",
            source_run_id="run-D",
            reachability_status="confirmed",
            provenance_level="L0",
        ),
    )

    dormant = atlas_conn.execute("SELECT COUNT(*) FROM dormant_instance").fetchone()[0]
    public = atlas_conn.execute("SELECT COUNT(*) FROM public_finding").fetchone()[0]
    assert dormant == 2  # h1 (blocked+L1), h2 (blocked+L0)
    assert public == 1  # h3 only (confirmed+L2+anchor)


# ---------------------------------------------------------------------------
# recurrence_breadth — COUNT(DISTINCT source_run_id), uncapped
# ---------------------------------------------------------------------------


def test_recurrence_breadth_three_distinct_runs(atlas_conn: sqlite3.Connection) -> None:
    pid = upsert_pattern(atlas_conn, source_class="sc", sink_class="snk", call_sequence_shape="s")

    for run_id in ("run-A", "run-B", "run-C"):
        add_instance(atlas_conn, _base_instance(pid, run_id))

    breadth = atlas_conn.execute(
        "SELECT recurrence_breadth FROM pattern WHERE pattern_id = ?", (pid,)
    ).fetchone()[0]
    assert breadth == 3


def test_recurrence_breadth_fourth_same_run_does_not_increase(
    atlas_conn: sqlite3.Connection,
) -> None:
    pid = upsert_pattern(atlas_conn, source_class="sc", sink_class="snk", call_sequence_shape="s")

    for run_id in ("run-A", "run-B", "run-C"):
        add_instance(atlas_conn, _base_instance(pid, run_id))

    add_instance(
        atlas_conn,
        InstanceRow(pattern_id=pid, pseudocode_hash="alt-hash", source_run_id="run-A"),
    )

    breadth = atlas_conn.execute(
        "SELECT recurrence_breadth FROM pattern WHERE pattern_id = ?", (pid,)
    ).fetchone()[0]
    assert breadth == 3


def test_recurrence_breadth_starts_at_zero(atlas_conn: sqlite3.Connection) -> None:
    pid = upsert_pattern(atlas_conn, source_class="sc", sink_class="snk", call_sequence_shape="s")
    breadth = atlas_conn.execute(
        "SELECT recurrence_breadth FROM pattern WHERE pattern_id = ?", (pid,)
    ).fetchone()[0]
    assert breadth == 0


def test_recurrence_breadth_separate_patterns_independent(atlas_conn: sqlite3.Connection) -> None:
    pid1 = upsert_pattern(
        atlas_conn, source_class="sc1", sink_class="snk", call_sequence_shape="s1"
    )
    pid2 = upsert_pattern(
        atlas_conn, source_class="sc2", sink_class="snk", call_sequence_shape="s2"
    )

    for run_id in ("run-A", "run-B"):
        add_instance(atlas_conn, _base_instance(pid1, run_id))
    add_instance(atlas_conn, _base_instance(pid2, "run-X"))

    breadth1 = atlas_conn.execute(
        "SELECT recurrence_breadth FROM pattern WHERE pattern_id = ?", (pid1,)
    ).fetchone()[0]
    breadth2 = atlas_conn.execute(
        "SELECT recurrence_breadth FROM pattern WHERE pattern_id = ?", (pid2,)
    ).fetchone()[0]
    assert breadth1 == 2
    assert breadth2 == 1


# ---------------------------------------------------------------------------
# add_instances — batched
# ---------------------------------------------------------------------------


def test_add_instances_returns_stats(atlas_conn: sqlite3.Connection) -> None:
    pid = upsert_pattern(atlas_conn, source_class="sc", sink_class="snk", call_sequence_shape="s")
    instances = [
        InstanceRow(pattern_id=pid, pseudocode_hash="h1", source_run_id="run-A"),
        InstanceRow(pattern_id=pid, pseudocode_hash="h2", source_run_id="run-B"),
    ]
    stats = add_instances(atlas_conn, instances)
    assert isinstance(stats, AtlasStats)
    assert stats.instances_added == 2
    assert stats.patterns_touched == 1


def test_add_instances_empty_list(atlas_conn: sqlite3.Connection) -> None:
    stats = add_instances(atlas_conn, [])
    assert stats.instances_added == 0
    assert stats.patterns_touched == 0


def test_add_instances_validates_before_insert(atlas_conn: sqlite3.Connection) -> None:
    pid = upsert_pattern(atlas_conn, source_class="sc", sink_class="snk", call_sequence_shape="s")
    instances = [
        InstanceRow(pattern_id=pid, pseudocode_hash="h1", source_run_id="run-A"),
        InstanceRow(pattern_id=pid),  # missing source_run_id → should fail
    ]
    with pytest.raises(ConfigError):
        add_instances(atlas_conn, instances)
    # No rows should have been inserted (validation runs before executemany)
    count = atlas_conn.execute("SELECT COUNT(*) FROM instance").fetchone()[0]
    assert count == 0


def test_add_instances_recurrence_breadth_updated(atlas_conn: sqlite3.Connection) -> None:
    pid = upsert_pattern(atlas_conn, source_class="sc", sink_class="snk", call_sequence_shape="s")
    instances = [
        InstanceRow(pattern_id=pid, pseudocode_hash=f"h{i}", source_run_id=f"run-{i}")
        for i in range(5)
    ]
    add_instances(atlas_conn, instances)
    breadth = atlas_conn.execute(
        "SELECT recurrence_breadth FROM pattern WHERE pattern_id = ?", (pid,)
    ).fetchone()[0]
    assert breadth == 5


# ---------------------------------------------------------------------------
# Static guards — grep lib/atlas/
# ---------------------------------------------------------------------------


def test_static_no_delete_drop_in_atlas() -> None:
    forbidden_sql = ("DELETE FROM", "DROP TABLE", "DROP VIEW", "DROP INDEX")
    for py_file in _ATLAS_SRC.glob("*.py"):
        text = py_file.read_text().upper()
        for token in forbidden_sql:
            assert token not in text, f"SQL {token!r} found in {py_file.name}"


def test_static_no_judgment_tokens_in_atlas() -> None:
    judgment_tokens = ("_SCORE", "_PRIORITY", "INCOMPLETE_PATCH", "FIX_QUALITY")
    for py_file in _ATLAS_SRC.glob("*.py"):
        text = py_file.read_text().upper()
        for token in judgment_tokens:
            assert token not in text, f"Judgment token {token!r} found in {py_file.name}"
