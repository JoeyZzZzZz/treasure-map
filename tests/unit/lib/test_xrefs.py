# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for xrefs module."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from treasure_map.lib.analyze.xrefs import (
    build_xrefs,
    categorize_string,
    is_useful_ipc_string,
)
from treasure_map.lib.storage.connection import open_db

# ── String classification ─────────────────────────────────────────────────────


def test_categorize_crypto_hint() -> None:
    assert categorize_string("AES_set_encrypt_key") == "crypto_hint"
    assert categorize_string("openssl_init") == "crypto_hint"


def test_categorize_ipc_sock() -> None:
    assert categorize_string("/var/run/httpd.sock") == "ipc_sock"
    assert categorize_string("/tmp/foo.fifo") == "ipc_sock"


def test_categorize_url() -> None:
    assert categorize_string("https://api.example.com/v1") == "url"


def test_categorize_misc_when_no_match() -> None:
    assert categorize_string("random garbage 12 38 xyz") == "misc"


# ── is_useful_ipc_string ──────────────────────────────────────────────────────


def test_useful_ipc_string_passes_typical_sock() -> None:
    assert is_useful_ipc_string("/var/run/audiopush.sock") is True


def test_too_short_rejected() -> None:
    assert is_useful_ipc_string("abc") is False


def test_generic_path_rejected() -> None:
    assert is_useful_ipc_string("/tmp") is False
    assert is_useful_ipc_string("/var") is False


# ── Helper: setup synthetic DB with 2 binaries + functions/exports ────────────


def _setup_synthetic_db(tmp_path: Path) -> sqlite3.Connection:
    """Two binaries: alphapd calls strcpy; libuClibc exports strcpy."""
    conn = open_db(tmp_path / "analysis.db")
    conn.execute(
        "INSERT INTO binaries (id, name, sha256, dt_needed) VALUES (?, ?, ?, ?)",
        (1, "alphapd", "a" * 64, '["libuClibc.so"]'),
    )
    conn.execute(
        "INSERT INTO binaries (id, name, sha256, dt_needed) VALUES (?, ?, ?, ?)",
        (2, "libuClibc.so", "b" * 64, "[]"),
    )
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, callees) VALUES (?, ?, ?, ?)",
        (10, 1, "do_request", '["strcpy"]'),
    )
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, callees) VALUES (?, ?, ?, ?)",
        (20, 2, "strcpy", "[]"),
    )
    conn.execute(
        "INSERT INTO exports (binary_id, func_name, address) VALUES (?, ?, ?)",
        (2, "strcpy", "00010000"),
    )
    conn.commit()
    return conn


# ── Layer 0 ───────────────────────────────────────────────────────────────────


def test_layer0_creates_func_level_xref(tmp_path: Path) -> None:
    conn = _setup_synthetic_db(tmp_path)
    stats = build_xrefs(conn)
    assert stats.layer0_callees_exports == 1
    row = conn.execute(
        """SELECT caller_binary_id, caller_func_id,
                  callee_binary_id, callee_func_id, xref_type, confidence
           FROM xrefs WHERE xref_type = 'callees_exports'"""
    ).fetchone()
    assert row[0] == 1  # alphapd
    assert row[1] == 10  # do_request
    assert row[2] == 2  # libuClibc
    assert row[3] == 20  # strcpy
    assert row[4] == "callees_exports"
    assert row[5] == 1.0
    conn.close()


def test_layer0_skips_intra_binary(tmp_path: Path) -> None:
    conn = open_db(tmp_path / "analysis.db")
    conn.execute(
        "INSERT INTO binaries (id, name, sha256, dt_needed) VALUES (?, ?, ?, ?)",
        (1, "foo", "a" * 64, "[]"),
    )
    conn.execute(
        """INSERT INTO functions (id, binary_id, name, callees)
           VALUES (10, 1, 'caller', '["callee"]'),
                  (20, 1, 'callee', '[]')"""
    )
    conn.execute(
        "INSERT INTO exports (binary_id, func_name, address) VALUES (1, 'callee', '00010000')"
    )
    conn.commit()
    stats = build_xrefs(conn)
    assert stats.layer0_callees_exports == 0
    conn.close()


def test_layer0_processes_all_callers(tmp_path: Path) -> None:
    """Regression test for cursor re-entry bug.

    Ensures Layer 0 iterates over ALL functions, not just the first one
    (which is what happens if the cursor used for the outer SELECT is
    reused by _safe_insert_xref internally).
    """
    conn = open_db(tmp_path / "analysis.db")
    # 3 binaries: 2 callers + 1 exporter
    for bid, name, sha in [
        (1, "caller_a", "a" * 64),
        (2, "caller_b", "b" * 64),
        (3, "libc", "c" * 64),
    ]:
        conn.execute(
            "INSERT INTO binaries (id, name, sha256, dt_needed) VALUES (?, ?, ?, ?)",
            (bid, name, sha, "[]"),
        )
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, callees) VALUES (?, ?, ?, ?)",
        (10, 1, "func_a", '["strcpy"]'),
    )
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, callees) VALUES (?, ?, ?, ?)",
        (20, 2, "func_b", '["strcpy"]'),
    )
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, callees) VALUES (?, ?, ?, ?)",
        (30, 3, "strcpy", "[]"),
    )
    conn.execute(
        "INSERT INTO exports (binary_id, func_name, address) VALUES (?, ?, ?)",
        (3, "strcpy", "00010000"),
    )
    conn.commit()
    stats = build_xrefs(conn)
    assert stats.layer0_callees_exports == 2, "Both callers must produce a xref"
    distinct_callers = conn.execute(
        "SELECT COUNT(DISTINCT caller_func_id) FROM xrefs WHERE xref_type='callees_exports'"
    ).fetchone()[0]
    assert distinct_callers == 2, "Layer 0 must process both callers"
    conn.close()


# ── Layer 2 ───────────────────────────────────────────────────────────────────


def test_layer2_dt_needed_creates_lib_level_xref(tmp_path: Path) -> None:
    conn = _setup_synthetic_db(tmp_path)
    stats = build_xrefs(conn)
    assert stats.layer2_dt_needed == 1
    row = conn.execute(
        "SELECT caller_binary_id, callee_binary_id, xref_type, confidence "
        "FROM xrefs WHERE xref_type = 'dt_needed'"
    ).fetchone()
    assert row[0] == 1
    assert row[1] == 2
    assert row[3] == 0.9
    conn.close()


# ── Layer 3 ───────────────────────────────────────────────────────────────────


def test_layer3_shared_ipc_sock_creates_xref(tmp_path: Path) -> None:
    conn = open_db(tmp_path / "analysis.db")
    conn.execute(
        "INSERT INTO binaries (id, name, sha256, dt_needed) VALUES (?, ?, ?, ?)",
        (1, "audiopush", "a" * 64, "[]"),
    )
    conn.execute(
        "INSERT INTO binaries (id, name, sha256, dt_needed) VALUES (?, ?, ?, ?)",
        (2, "signalc", "b" * 64, "[]"),
    )
    sock = "/var/run/audiopush.sock"
    conn.execute(
        "INSERT INTO strings (binary_id, value, address) VALUES (?, ?, ?)",
        (1, sock, "00010000"),
    )
    conn.execute(
        "INSERT INTO strings (binary_id, value, address) VALUES (?, ?, ?)",
        (2, sock, "00020000"),
    )
    conn.commit()
    stats = build_xrefs(conn)
    assert stats.layer3_string_ipc == 1
    row = conn.execute(
        "SELECT caller_binary_id, callee_binary_id, confidence "
        "FROM xrefs WHERE xref_type = 'string_ipc'"
    ).fetchone()
    assert {row[0], row[1]} == {1, 2}
    assert row[2] == 0.5
    conn.close()


def test_layer3_filters_generic_paths(tmp_path: Path) -> None:
    conn = open_db(tmp_path / "analysis.db")
    conn.execute(
        "INSERT INTO binaries (id, name, sha256, dt_needed) VALUES (?, ?, ?, ?)",
        (1, "a", "a" * 64, "[]"),
    )
    conn.execute(
        "INSERT INTO binaries (id, name, sha256, dt_needed) VALUES (?, ?, ?, ?)",
        (2, "b", "b" * 64, "[]"),
    )
    conn.execute("INSERT INTO strings (binary_id, value, address) VALUES (1, '/tmp', '1')")
    conn.execute("INSERT INTO strings (binary_id, value, address) VALUES (2, '/tmp', '2')")
    conn.commit()
    stats = build_xrefs(conn)
    assert stats.layer3_string_ipc == 0
    conn.close()


# ── String classification side effect ─────────────────────────────────────────


def test_build_xrefs_classifies_strings(tmp_path: Path) -> None:
    conn = open_db(tmp_path / "analysis.db")
    conn.execute(
        "INSERT INTO binaries (id, name, sha256) VALUES (?, ?, ?)",
        (1, "foo", "a" * 64),
    )
    conn.execute("INSERT INTO strings (binary_id, value, address) VALUES (1, 'AES_encrypt', '1')")
    conn.execute(
        "INSERT INTO strings (binary_id, value, address) VALUES (1, '/var/run/x.sock', '2')"
    )
    conn.execute(
        "INSERT INTO strings (binary_id, value, address) VALUES (1, 'random garbage xyz', '3')"
    )
    conn.commit()
    stats = build_xrefs(conn)
    assert stats.strings_classified == 3
    rows = dict(conn.execute("SELECT value, category FROM strings").fetchall())
    assert rows["AES_encrypt"] == "crypto_hint"
    assert rows["/var/run/x.sock"] == "ipc_sock"
    assert rows["random garbage xyz"] == "misc"
    conn.close()


# ── Wipe-and-rebuild idempotence ──────────────────────────────────────────────


def test_build_xrefs_is_idempotent(tmp_path: Path) -> None:
    """Running build_xrefs twice gives same result (wipe-and-rebuild)."""
    conn = _setup_synthetic_db(tmp_path)
    stats1 = build_xrefs(conn)
    stats2 = build_xrefs(conn)
    assert stats1.total_xrefs == stats2.total_xrefs
    assert stats1.total_xrefs > 0
    count = conn.execute("SELECT COUNT(*) FROM xrefs").fetchone()[0]
    assert count == stats2.total_xrefs
    conn.close()


def test_build_xrefs_empty_db(tmp_path: Path) -> None:
    """Empty DB → all zeros, no errors."""
    conn = open_db(tmp_path / "analysis.db")
    stats = build_xrefs(conn)
    assert stats.total_xrefs == 0
    assert stats.strings_classified == 0
    conn.close()
