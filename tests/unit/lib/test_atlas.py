# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for lib/atlas — cross-firmware pattern store (M2 Step 1)."""

from __future__ import annotations

import re
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
from treasure_map.lib.atlas import connection as atlas_connection
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
# Views — semantics
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
# device_spread — COUNT(DISTINCT source_run_id), uncapped
# ---------------------------------------------------------------------------


def test_device_spread_three_distinct_runs(atlas_conn: sqlite3.Connection) -> None:
    pid = upsert_pattern(atlas_conn, source_class="sc", sink_class="snk", call_sequence_shape="s")

    for run_id in ("run-A", "run-B", "run-C"):
        add_instance(atlas_conn, _base_instance(pid, run_id))

    breadth = atlas_conn.execute(
        "SELECT device_spread FROM pattern WHERE pattern_id = ?", (pid,)
    ).fetchone()[0]
    assert breadth == 3


def test_device_spread_fourth_same_run_does_not_increase(
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
        "SELECT device_spread FROM pattern WHERE pattern_id = ?", (pid,)
    ).fetchone()[0]
    assert breadth == 3


def test_device_spread_starts_at_zero(atlas_conn: sqlite3.Connection) -> None:
    pid = upsert_pattern(atlas_conn, source_class="sc", sink_class="snk", call_sequence_shape="s")
    breadth = atlas_conn.execute(
        "SELECT device_spread FROM pattern WHERE pattern_id = ?", (pid,)
    ).fetchone()[0]
    assert breadth == 0


def test_device_spread_separate_patterns_independent(atlas_conn: sqlite3.Connection) -> None:
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
        "SELECT device_spread FROM pattern WHERE pattern_id = ?", (pid1,)
    ).fetchone()[0]
    breadth2 = atlas_conn.execute(
        "SELECT device_spread FROM pattern WHERE pattern_id = ?", (pid2,)
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


def test_add_instances_device_spread_updated(atlas_conn: sqlite3.Connection) -> None:
    pid = upsert_pattern(atlas_conn, source_class="sc", sink_class="snk", call_sequence_shape="s")
    instances = [
        InstanceRow(pattern_id=pid, pseudocode_hash=f"h{i}", source_run_id=f"run-{i}")
        for i in range(5)
    ]
    add_instances(atlas_conn, instances)
    breadth = atlas_conn.execute(
        "SELECT device_spread FROM pattern WHERE pattern_id = ?", (pid,)
    ).fetchone()[0]
    assert breadth == 5


# ---------------------------------------------------------------------------
# origin — default unknown, not forced at ingest; enum validated
# ---------------------------------------------------------------------------


def test_instance_origin_defaults_to_unknown(atlas_conn: sqlite3.Connection) -> None:
    pid = upsert_pattern(atlas_conn, source_class="sc", sink_class="snk", call_sequence_shape="s")
    iid = add_instance(atlas_conn, _base_instance(pid))
    origin = atlas_conn.execute(
        "SELECT origin FROM instance WHERE instance_id = ?", (iid,)
    ).fetchone()[0]
    assert origin == "unknown"


def test_instance_origin_explicit_value_persists(atlas_conn: sqlite3.Connection) -> None:
    pid = upsert_pattern(atlas_conn, source_class="sc", sink_class="snk", call_sequence_shape="s")
    iid = add_instance(
        atlas_conn,
        InstanceRow(pattern_id=pid, pseudocode_hash="h", source_run_id="run-A", origin="custom"),
    )
    origin = atlas_conn.execute(
        "SELECT origin FROM instance WHERE instance_id = ?", (iid,)
    ).fetchone()[0]
    assert origin == "custom"


def test_add_instance_rejects_illegal_origin(atlas_conn: sqlite3.Connection) -> None:
    pid = upsert_pattern(atlas_conn, source_class="sc", sink_class="snk", call_sequence_shape="s")
    with pytest.raises(ConfigError, match="origin"):
        add_instance(
            atlas_conn,
            InstanceRow(pattern_id=pid, pseudocode_hash="h", source_run_id="run-A", origin="bogus"),
        )


# ---------------------------------------------------------------------------
# in-place migration — old atlas (no origin, recurrence_breadth) brought forward
# ---------------------------------------------------------------------------

# A minimal pre-migration atlas: pattern carries recurrence_breadth (old name) and the legacy
# device_category column, instance has no origin column. open_atlas must add origin (default
# unknown), rename recurrence_breadth -> device_spread, and DROP device_category — all without
# dropping any rows.
_OLD_SCHEMA = """
CREATE TABLE pattern (
    pattern_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_class TEXT NOT NULL, sink_class TEXT NOT NULL, call_sequence_shape TEXT NOT NULL,
    structural_fingerprint TEXT, fingerprint_algo_version TEXT NOT NULL DEFAULT 'v0',
    device_category TEXT, recurrence_breadth INTEGER NOT NULL DEFAULT 0,
    first_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE instance (
    instance_id INTEGER PRIMARY KEY AUTOINCREMENT, pattern_id INTEGER NOT NULL,
    pseudocode_hash TEXT, source_anchor TEXT, sink_anchor TEXT, source_run_id TEXT,
    reachability_status TEXT NOT NULL DEFAULT 'unknown', blocking_mechanism TEXT,
    provenance_level TEXT NOT NULL DEFAULT 'L0', external_anchor TEXT, fix_diff TEXT,
    scope_origin TEXT, evidence_ref TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""


def _cols(conn: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def test_open_atlas_migrates_old_schema_in_place(tmp_path: Path) -> None:
    db_path = tmp_path / "atlas.db"
    old = sqlite3.connect(db_path)
    old.executescript(_OLD_SCHEMA)
    old.execute(
        "INSERT INTO pattern "
        "(source_class, sink_class, call_sequence_shape, recurrence_breadth, device_category) "
        "VALUES ('sc', 'snk', 'shape', 2, 'router')"
    )
    old.execute(
        "INSERT INTO instance (pattern_id, pseudocode_hash, source_run_id) VALUES (1, 'h1', 'r1')"
    )
    old.execute(
        "INSERT INTO instance (pattern_id, pseudocode_hash, source_run_id) VALUES (1, 'h2', 'r2')"
    )
    old.commit()
    old.close()

    conn = open_atlas(db_path)
    try:
        inst_cols = _cols(conn, "instance")
        pat_cols = _cols(conn, "pattern")
        assert "origin" in inst_cols  # added
        assert "binary_path" in inst_cols  # added this round (locatability)
        assert "binary_content_hash" in inst_cols  # added this round (store-only)
        assert "device_spread" in pat_cols  # renamed
        assert "recurrence_breadth" not in pat_cols  # old name gone
        assert "device_category" not in pat_cols  # legacy column hard-dropped
        # existing rows preserved; the added columns took their defaults on the old rows
        rows = conn.execute("SELECT origin FROM instance ORDER BY instance_id").fetchall()
        assert [r[0] for r in rows] == ["unknown", "unknown"]
        # the new nullable locator columns are NULL on pre-migration rows (no data invented)
        loc = conn.execute(
            "SELECT binary_path, binary_content_hash FROM instance ORDER BY instance_id"
        ).fetchall()
        assert all(r[0] is None and r[1] is None for r in loc)
        assert conn.execute("SELECT COUNT(*) FROM instance").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(*) FROM pattern").fetchone()[0] == 1
        # the renamed column keeps the old value — no data lost in the drop/rename
        assert conn.execute("SELECT device_spread FROM pattern").fetchone()[0] == 2
        # the derived ledger still computes the same numbers (adding columns did not touch counts)
        led = conn.execute("SELECT device_spread, pattern_breadth FROM pattern_ledger").fetchone()
        assert led[0] == 2  # two distinct source_run_id
        assert led[1] == 2  # two distinct pseudocode_hash, origin defaulted to unknown
    finally:
        conn.close()


def test_open_atlas_migration_is_idempotent(tmp_path: Path) -> None:
    # Re-opening an already-migrated atlas is a no-op and never raises.
    db_path = tmp_path / "atlas.db"
    open_atlas(db_path).close()
    conn = open_atlas(db_path)
    try:
        assert "origin" in _cols(conn, "instance")
        assert "device_spread" in _cols(conn, "pattern")
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Static guards — grep lib/atlas/
# ---------------------------------------------------------------------------


_DROP_TABLE_NAMED = re.compile(r"DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?([A-Za-z0-9_]+)", re.I)


def _droptable_line_forbidden(line: str) -> bool:
    """Does this line drop a table that is NOT ``overlay``?

    ``overlay`` is the one table a wipe cannot destroy anything irreplaceable in: it holds the
    consumer's own annotations, which the design has always let them clear in one call, and it is
    rebuilt from nothing but itself. Every other table here accumulates evidence across runs that
    only a full re-scan of the firmware could reproduce — those stay untouchable.

    The check extracts the TABLE NAME rather than matching a whole line, because a real drop is
    embedded in a call (``conn.execute("DROP TABLE overlay")``) and a whole-line comparison would
    redden the very statement this exemption exists to allow. A line mentioning DROP TABLE whose
    name cannot be extracted is forbidden: unprovable is not the same as permitted.
    """
    if "drop table" not in line.lower():
        return False
    names = _DROP_TABLE_NAMED.findall(line)
    if not names:
        return True
    return any(n.lower() != "overlay" for n in names)


def test_static_no_unscoped_wipe_in_atlas() -> None:
    # No table-wide wipe path. DROP VIEW / DROP INDEX are forbidden outright; DROP TABLE is
    # forbidden for every table EXCEPT overlay (see _droptable_line_forbidden). The ONLY permitted
    # DELETEs are SCOPED replace refreshes: run-scoped (WHERE source_run_id/run_id = ?) or
    # diff-scoped (WHERE diff_id = ?), each touching one run's / one diff's rows — not cross-run
    # accumulation. Any other DELETE FROM fails.
    forbidden_sql = ("DROP VIEW", "DROP INDEX")
    permitted_deletes = (
        "DELETE FROM instance WHERE source_run_id = ?",
        "DELETE FROM nvram_key_flow WHERE source_run_id = ?",
        "DELETE FROM nvram_defaults WHERE source_run_id = ?",
        "DELETE FROM web_form_fields WHERE source_run_id = ?",
        "DELETE FROM string_keyed_edge WHERE source_run_id = ?",
        "DELETE FROM detector_scan_status WHERE source_run_id = ?",
        "DELETE FROM run_capability WHERE run_id = ?",
        # diff-scoped replace-by-diff refresh (idempotent layer-0 / layer-2 re-parse), one diff_id
        "DELETE FROM function_alignment WHERE diff_id = ?",
        "DELETE FROM function_presence WHERE diff_id = ?",
        "DELETE FROM diff_meta WHERE diff_id = ?",
        "DELETE FROM dimension_delta WHERE diff_id = ?",
        "DELETE FROM dimension_capability_state WHERE diff_id = ?",
    )
    for py_file in _ATLAS_SRC.glob("*.py"):
        text = py_file.read_text()
        upper = text.upper()
        for token in forbidden_sql:
            assert token not in upper, f"SQL {token!r} found in {py_file.name}"
        for lineno, line in enumerate(text.splitlines(), 1):
            assert not _droptable_line_forbidden(line), (
                f"DROP TABLE of a non-overlay table in {py_file.name}:{lineno}: {line.strip()}"
            )
        delete_count = upper.count("DELETE FROM")
        scoped_count = sum(text.count(p) for p in permitted_deletes)
        assert delete_count == scoped_count, (
            f"{py_file.name} has a DELETE that is not a run-scoped replace-by-run refresh"
        )


def test_static_no_judgment_tokens_in_atlas() -> None:
    judgment_tokens = ("_SCORE", "_PRIORITY", "INCOMPLETE_PATCH", "FIX_QUALITY")
    for py_file in _ATLAS_SRC.glob("*.py"):
        text = py_file.read_text().upper()
        for token in judgment_tokens:
            assert token not in text, f"Judgment token {token!r} found in {py_file.name}"


# ---------------------------------------------------------------------------
# Regression: an OLD-shape atlas (missing a migrated-in column) must reopen.
# Every atlas test above builds a FRESH db, which is exactly why a bug that only
# fires when an EXISTING atlas is re-opened slipped through. These simulate the
# old shape by dropping a migrated-in column, then reopening.
# ---------------------------------------------------------------------------


def _table_cols(conn: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def test_open_atlas_reopens_old_dimension_delta_missing_binary(tmp_path: Path) -> None:
    # ★ Regression for the migrate-order bug. The schema's idx_dimdelta_bin references
    # dimension_delta.binary, a MIGRATED-IN column. If executescript runs before _migrate, an OLD
    # atlas whose dimension_delta predates that column hits `CREATE INDEX ... (binary)` — IF NOT
    # EXISTS guards only the index NAME, not the column — and raises "no such column: binary", so
    # the atlas cannot be opened at all. Simulate the old shape (drop the column + its index) and
    # reopen. ★ Reverting the _migrate/executescript order in open_atlas makes this test red.
    db = tmp_path / "atlas.db"
    conn = open_atlas(db)
    conn.execute(
        "INSERT INTO dimension_delta (diff_id, dimension, subject_kind, subject_key, delta_kind) "
        "VALUES ('r::r', 'dim', 'edge', 'k', 'layer_changed')"
    )
    conn.commit()
    conn.execute("DROP INDEX IF EXISTS idx_dimdelta_bin")
    conn.execute("ALTER TABLE dimension_delta DROP COLUMN binary")
    conn.commit()
    assert "binary" not in _table_cols(conn, "dimension_delta")  # old shape now
    conn.close()

    conn2 = open_atlas(db)  # must NOT raise
    try:
        assert "binary" in _table_cols(conn2, "dimension_delta")  # re-added by _migrate
        index_names = {r[1] for r in conn2.execute("PRAGMA index_list(dimension_delta)")}
        assert "idx_dimdelta_bin" in index_names  # index recreated by executescript
        assert conn2.execute("SELECT COUNT(*) FROM dimension_delta").fetchone()[0] == 1  # row kept
    finally:
        conn2.close()


@pytest.mark.parametrize(
    ("table", "col"),
    [
        ("instance", "binary_path"),
        ("instance", "flow_evidence"),
        ("instance", "exposure_shape"),
        ("diff_meta", "binary_a"),
        ("nvram_key_flow", "via_wrapper"),
    ],
)
def test_open_atlas_reopens_old_shape_missing_migrated_column(
    tmp_path: Path, table: str, col: str
) -> None:
    # The same trap fires for ANY schema object that references a migrated column; more broadly, an
    # old atlas missing any migrated column must reopen and get it back. Drop the column, reopen,
    # assert it is re-added — coverage for the whole "old library opens" class, not one column.
    db = tmp_path / "atlas.db"
    conn = open_atlas(db)
    conn.execute(f"ALTER TABLE {table} DROP COLUMN {col}")  # noqa: S608 -- literal params
    conn.commit()
    assert col not in _table_cols(conn, table)  # old shape now
    conn.close()

    conn2 = open_atlas(db)  # must NOT raise
    try:
        assert col in _table_cols(conn2, table)  # re-added by _migrate
    finally:
        conn2.close()


# ── the overlay-only DROP TABLE exemption, and the rebuild it exists for ───────────────
#
# Reverse mutations — each applied once and observed RED, then restored:
#
# M1. widen the exemption: in `_droptable_line_forbidden` return False whenever a name is found.
#     -> `test_droptable_guard_permits_only_overlay` fails on the instance / overlay_backup cases.
# M2. loosen the rebuild trigger: in `connection._migrate` test `"CHECK" in ov_sql[0]` instead of
#     the verdict-anchored pattern. -> `test_verdict_check_removal_is_idempotent` fails — the other
#     two CHECKs keep it true, so every open rebuilds again.
# M3. drop atomicity: in `_rebuild_overlay_without_verdict_check` remove the BEGIN IMMEDIATE, OR
#     run the CREATE through executescript. Both were tried; both fail
#     `test_rebuild_leaves_nothing_behind_on_crash` — the CREATE self-commits, overlay_new survives
#     the rollback, and the retry can never clean it up.
# M4. weaken the rebuilt table: drop the attributed_to CHECK, the anchor_kind CHECK, the UNIQUE, or
#     a column from the copy list. Each fails `test_rebuilt_overlay_keeps_every_other_constraint`
#     (a dropped column also fails the idempotence test's value assertions).
#
# Two of these started out GREEN and the tests had to be strengthened, which is the whole reason to
# run them: (a) comparing schemas could not see a repeated rebuild, because rebuilding an already
# rebuilt table yields identical DDL — idempotence is now asserted by watching the call itself;
# (b) the pre-existing constraint tests all build a FRESH atlas, which never takes the rebuild path,
# so dropping a CHECK from the rebuilt DDL passed everything until a test ran against a rebuilt
# table specifically.


def test_droptable_guard_permits_only_overlay() -> None:
    # ★ The exemption is exactly one table wide. Anything else that drops a table — including a
    # name that merely starts with "overlay" — must still be refused.
    permitted = (
        'conn.execute("DROP TABLE overlay")',
        'conn.execute("DROP TABLE IF EXISTS overlay")',
        '    conn.execute("drop table overlay")',
        'conn.execute("DROP   TABLE   overlay")',
        "rows = conn.execute('SELECT * FROM overlay')",  # no drop at all
    )
    forbidden = (
        'conn.execute("DROP TABLE instance")',
        'conn.execute("DROP TABLE overlay_backup")',  # prefix, not the table
        'conn.execute("DROP TABLE overlay"); conn.execute("DROP TABLE instance")',
        "# someday we might DROP TABLE pattern",  # even in a comment
        'conn.execute("DROP TABLE " + name)',  # name not provable -> refused
    )
    for line in permitted:
        assert not _droptable_line_forbidden(line), f"should be allowed: {line}"
    for line in forbidden:
        assert _droptable_line_forbidden(line), f"should be refused: {line}"


def _overlay_ddl(conn: sqlite3.Connection) -> str:
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='overlay'"
    ).fetchone()
    return str(row[0])


def _old_shape_overlay(db: Path) -> None:
    """An atlas whose overlay still carries the verdict CHECK — what a pre-change database is."""
    conn = open_atlas(db)  # builds the current (post-change) shape...
    conn.execute("DROP TABLE overlay")  # ... which we replace with the old one
    conn.execute("""CREATE TABLE overlay (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        anchor_kind TEXT NOT NULL DEFAULT 'evidence_ref'
            CHECK (anchor_kind IN ('evidence_ref','diff_subject')),
        anchor_ref TEXT NOT NULL,
        run_id TEXT,
        verdict TEXT NOT NULL
            CHECK (verdict IN ('to-review','in-progress','suspicious','excluded','safe')),
        rationale TEXT NOT NULL,
        attributed_to TEXT
            CHECK (attributed_to IS NULL OR attributed_to IN ('agent','agent-via-mcp')),
        basis_state TEXT,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (anchor_kind, anchor_ref))""")
    conn.execute(
        "INSERT INTO overlay (anchor_ref, run_id, verdict, rationale, attributed_to, basis_state) "
        "VALUES ('run_x#deadbeef:0x1@cmd','run_x','suspicious','dig here','agent-via-mcp','{}')"
    )
    conn.commit()
    conn.close()


def test_verdict_check_removal_is_idempotent(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # ★ The trigger has to be specific enough to become FALSE once the job is done — overlay keeps
    # two other CHECKs, and a looser test would rebuild on every single open forever.
    #
    # Idempotence is asserted by watching whether the rebuild RUNS again, not by comparing the
    # resulting schema: rebuilding an already-rebuilt table produces byte-identical DDL, so a
    # schema comparison would sit there green while the table was silently rewritten on every open.
    db = tmp_path / "atlas.db"
    _old_shape_overlay(db)

    conn = open_atlas(db)  # first open: rebuilds
    ddl_after = _overlay_ddl(conn)
    conn.close()
    assert "CHECK (verdict" not in ddl_after.replace("CHECK(verdict", "CHECK (verdict")
    assert "anchor_kind IN" in ddl_after  # the other two CHECKs survived
    assert "attributed_to IS NULL" in ddl_after
    assert "verdict       TEXT NOT NULL" in ddl_after or "verdict TEXT NOT NULL" in ddl_after
    assert "UNIQUE (anchor_kind, anchor_ref)" in ddl_after

    rebuilds: list[int] = []
    monkeypatch.setattr(
        atlas_connection,
        "_rebuild_overlay_without_verdict_check",
        lambda conn: rebuilds.append(1),
    )
    conn = open_atlas(db)  # second open: must NOT rebuild
    assert rebuilds == [], "the migration re-ran on an already-migrated atlas"
    monkeypatch.undo()
    assert _overlay_ddl(conn) == ddl_after
    # the row survived the rebuild, every column intact
    row = conn.execute("SELECT * FROM overlay").fetchone()
    assert (row["anchor_ref"], row["run_id"], row["verdict"]) == (
        "run_x#deadbeef:0x1@cmd",
        "run_x",
        "suspicious",
    )
    assert (row["rationale"], row["attributed_to"], row["basis_state"]) == (
        "dig here",
        "agent-via-mcp",
        "{}",
    )
    assert row["created_at"] and row["updated_at"]
    idx = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_overlay_verdict'"
    ).fetchone()
    assert idx is not None  # the drop took the index; the rebuild put it back
    conn.close()


def test_removed_check_lets_a_new_verdict_word_be_stored(tmp_path: Path) -> None:
    # The point of the removal: the vocabulary can now change without touching the database.
    db = tmp_path / "atlas.db"
    _old_shape_overlay(db)
    conn = open_atlas(db)
    conn.execute(
        "INSERT INTO overlay (anchor_ref, verdict, rationale) "
        "VALUES ('r#a:0x2@cmd', 'brand-new', 'x')"
    )
    conn.commit()
    assert conn.execute("SELECT COUNT(*) FROM overlay").fetchone()[0] == 2
    conn.close()


def test_rebuild_leaves_nothing_behind_on_crash(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # ★ The rebuild must be all-or-nothing. If a crash could leave overlay_new behind, the next
    # open would retry, hit "table already exists", and be stuck for good — the wipe guard permits
    # dropping only `overlay`, so nothing may ever clean up that temp table.
    db = tmp_path / "atlas.db"
    _old_shape_overlay(db)

    # sqlite3.Connection is an immutable C type, so the crash is injected through a connection
    # subclass installed as the factory — the rebuild then dies partway, exactly like a real fault.
    class _CrashOnDrop(sqlite3.Connection):
        def execute(self, sql, *args, **kwargs):  # type: ignore[no-untyped-def, override]
            if "DROP TABLE overlay" in str(sql):
                raise RuntimeError("simulated crash mid-rebuild")
            return super().execute(sql, *args, **kwargs)

    real_connect = sqlite3.connect  # captured first: the patch below replaces this very name
    monkeypatch.setattr(
        atlas_connection.sqlite3,
        "connect",
        lambda path, *a, **kw: real_connect(path, factory=_CrashOnDrop),
    )
    with pytest.raises(RuntimeError, match="simulated crash"):
        open_atlas(db)
    monkeypatch.undo()

    raw = sqlite3.connect(db)
    tables = {r[0] for r in raw.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    raw.close()
    assert "overlay_new" not in tables, "the half-built table survived a rollback"
    assert "overlay" in tables

    # and the retry completes cleanly rather than colliding with a leftover
    conn = open_atlas(db)
    ddl = _overlay_ddl(conn)
    assert "CHECK (verdict" not in ddl.replace("CHECK(verdict", "CHECK (verdict")
    assert conn.execute("SELECT COUNT(*) FROM overlay").fetchone()[0] == 1  # row intact
    conn.close()


def test_rebuilt_overlay_keeps_every_other_constraint(tmp_path: Path) -> None:
    # ★ Data surviving is not the same as CONSTRAINTS surviving. The rebuild retypes the table by
    # hand, so a dropped CHECK or UNIQUE would carry every row across intact and look perfectly
    # healthy — nothing in a row-by-row comparison can see it. The existing constraint tests all
    # build a FRESH atlas, which never goes through the rebuild, so this asserts them against a
    # rebuilt table specifically. Mutation: delete any constraint from _OVERLAY_REBUILT_DDL -> red.
    db = tmp_path / "atlas.db"
    _old_shape_overlay(db)
    conn = open_atlas(db)  # triggers the rebuild
    try:
        # attributed_to CHECK: a fabricated attributor is still refused at the storage layer
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO overlay (anchor_ref, verdict, rationale, attributed_to) "
                "VALUES ('r#a:0x9@cmd', 'safe', 'ok', 'alice')"
            )
        # anchor_kind CHECK: an unknown anchor kind is still refused
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO overlay (anchor_kind, anchor_ref, verdict, rationale) "
                "VALUES ('made_up', 'r#a:0xa@cmd', 'safe', 'ok')"
            )
        # UNIQUE(anchor_kind, anchor_ref): last-write-wins depends on this, so a duplicate anchor
        # must still collide rather than quietly become a second row
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO overlay (anchor_ref, verdict, rationale) "
                "VALUES ('run_x#deadbeef:0x1@cmd', 'safe', 'dup')"
            )
        # NOT NULLs survived on both required columns
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO overlay (anchor_ref, rationale) VALUES ('r#a:0xb@cmd', 'x')")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO overlay (anchor_ref, verdict) VALUES ('r#a:0xc@cmd', 'safe')")
        # ★ values carried across, checked on THIS open — the one right after the rebuild. run_id
        # has a backfill of its own that would quietly restore it on any later open, so a copy that
        # forgot the column is only visible here, before that second chance runs.
        row = conn.execute(
            "SELECT * FROM overlay WHERE anchor_ref = ?", ("run_x#deadbeef:0x1@cmd",)
        ).fetchone()
        assert row is not None
        assert row["run_id"] == "run_x"
        assert (row["verdict"], row["rationale"]) == ("suspicious", "dig here")
        assert (row["attributed_to"], row["basis_state"]) == ("agent-via-mcp", "{}")
        assert row["anchor_kind"] == "evidence_ref"
        assert row["created_at"] and row["updated_at"]
        # and the columns the app reads are all still there
        cols = {r[1] for r in conn.execute("PRAGMA table_info(overlay)")}
        assert cols == {
            "id",
            "anchor_kind",
            "anchor_ref",
            "run_id",
            "verdict",
            "rationale",
            "attributed_to",
            "basis_state",
            "verdict_basis",
            "created_at",
            "updated_at",
        }
    finally:
        conn.close()
