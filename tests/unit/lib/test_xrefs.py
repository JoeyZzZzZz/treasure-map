# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for xrefs module."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from treasure_map.lib import facts
from treasure_map.lib.analyze import xrefs as xrefs_mod
from treasure_map.lib.analyze.xrefs import (
    DEFAULT_FOLD_EDGE_THRESHOLD,
    build_xrefs,
    categorize_string,
    is_useful_ipc_string,
)
from treasure_map.lib.config.config import Config
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
    """Two binaries: appsvcd calls strcpy; libc_generic exports strcpy."""
    conn = open_db(tmp_path / "analysis.db")
    conn.execute(
        "INSERT INTO binaries (id, name, sha256, dt_needed) VALUES (?, ?, ?, ?)",
        (1, "appsvcd", "a" * 64, '["libc_generic.so"]'),
    )
    conn.execute(
        "INSERT INTO binaries (id, name, sha256, dt_needed) VALUES (?, ?, ?, ?)",
        (2, "libc_generic.so", "b" * 64, "[]"),
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
    assert row[0] == 1  # appsvcd
    assert row[1] == 10  # do_request
    assert row[2] == 2  # libc_generic
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


def test_layer0_skips_null_callee_func_id(tmp_path: Path) -> None:
    """An export with no matching function record (PLT thunk) must NOT produce a xref."""
    conn = open_db(tmp_path / "analysis.db")
    conn.execute(
        "INSERT INTO binaries (id, name, sha256, dt_needed) VALUES (?, ?, ?, ?)",
        (1, "app", "a" * 64, "[]"),
    )
    conn.execute(
        "INSERT INTO binaries (id, name, sha256, dt_needed) VALUES (?, ?, ?, ?)",
        (2, "lib", "b" * 64, "[]"),
    )
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, callees) VALUES (?, ?, ?, ?)",
        (10, 1, "caller", '["foo"]'),
    )
    # lib exports 'foo' but has NO corresponding function record (PLT thunk)
    conn.execute(
        "INSERT INTO exports (binary_id, func_name, address) VALUES (?, ?, ?)",
        (2, "foo", "00010000"),
    )
    conn.commit()
    stats = build_xrefs(conn)
    assert stats.layer0_callees_exports == 0, "Unresolved callee (PLT thunk) should be skipped"
    conn.close()


def test_build_xrefs_performance_executemany(tmp_path: Path) -> None:
    """Smoke test: 100 callers should build quickly (set-based dedup + executemany)."""
    import time

    conn = open_db(tmp_path / "analysis.db")
    # Binary 200 is the shared library; binaries 1-100 are callers
    conn.execute(
        "INSERT INTO binaries (id, name, sha256, dt_needed) VALUES (?, ?, ?, ?)",
        (200, "lib", "f" * 64, "[]"),
    )
    caller_bins = [(i, f"bin_{i}", f"{i:064d}", "[]") for i in range(1, 101)]
    conn.executemany(
        "INSERT INTO binaries (id, name, sha256, dt_needed) VALUES (?, ?, ?, ?)",
        caller_bins,
    )
    caller_funcs = [(1000 + i, i, "caller", '["shared"]') for i in range(1, 101)]
    conn.executemany(
        "INSERT INTO functions (id, binary_id, name, callees) VALUES (?, ?, ?, ?)",
        caller_funcs,
    )
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, callees) VALUES (?, ?, ?, ?)",
        (2000, 200, "shared", "[]"),
    )
    conn.execute(
        "INSERT INTO exports (binary_id, func_name, address) VALUES (?, ?, ?)",
        (200, "shared", "0"),
    )
    conn.commit()

    start = time.monotonic()
    stats = build_xrefs(conn)
    elapsed = time.monotonic() - start

    assert stats.layer0_callees_exports == 100
    assert elapsed < 2.0, f"100-caller build took {elapsed:.2f}s — perf regression"
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


# ── large-firmware scaling: batch flush + L0 high-fan-out fold ────────────────


def _fanout_db(tmp_path: Path, *, exporters: int, callers: int, symbol: str = "gensym"):  # type: ignore[no-untyped-def]
    """An 'app' binary with `callers` functions all calling `symbol`, plus `exporters` library
    binaries each exporting `symbol` (with a concrete function body). Edge contribution for the
    symbol = callers × exporters; none are intra-binary (callers live in 'app', not an exporter)."""
    conn = open_db(tmp_path / "analysis.db")
    conn.execute(
        "INSERT INTO binaries (id, name, sha256, dt_needed) VALUES (1, 'app', ?, '[]')", ("1" * 64,)
    )
    conn.executemany(
        "INSERT INTO functions (id, binary_id, name, callees) VALUES (?, 1, ?, ?)",
        [(1000 + i, f"caller_{i}", json.dumps([symbol])) for i in range(callers)],
    )
    for b in range(exporters):
        bid = 100 + b
        conn.execute(
            "INSERT INTO binaries (id, name, sha256, dt_needed) VALUES (?, ?, ?, '[]')",
            (bid, f"lib{b}.so", f"{b:064d}"),
        )
        conn.execute(
            "INSERT INTO functions (id, binary_id, name, callees) VALUES (?, ?, ?, '[]')",
            (5000 + b, bid, symbol),
        )
        conn.execute(
            "INSERT INTO exports (binary_id, func_name, address) VALUES (?, ?, ?)",
            (bid, symbol, f"{b:08x}"),
        )
    conn.commit()
    return conn


def _l0_edges(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM xrefs WHERE xref_type='callees_exports'").fetchone()[
        0
    ]


def test_batch_flush_loses_no_edges_and_no_dups(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # ★ batch flush changes WHEN edges are written, never WHAT: with a tiny batch the whole set is
    # still present exactly once. Reddens if _flush forgets to clear pending (dups) or clears with
    # no insert (losses). 8 exporters × 5 callers = 40 edges; batch of 3 forces many mid-flushes.
    monkeypatch.setattr(xrefs_mod, "XREF_FLUSH_BATCH", 3)
    conn = _fanout_db(tmp_path, exporters=8, callers=5)
    stats = build_xrefs(conn, fold_edge_threshold=10_000)  # high -> no fold, pure batch test
    assert stats.layer0_callees_exports == 40
    assert _l0_edges(conn) == 40  # every edge present exactly once (no loss, no duplicate row)
    conn.close()


def test_high_fanout_symbol_is_folded_into_ledger(tmp_path: Path) -> None:
    # ★ a generic symbol above the edge-contribution threshold AND the exporter floor is FOLDED: its
    # edges are NOT in xrefs, and it is recorded in xref_folded_symbols (never silently dropped).
    conn = _fanout_db(tmp_path, exporters=16, callers=5)  # contribution 80, exporters 16 >= floor
    stats = build_xrefs(conn, fold_edge_threshold=50)
    assert stats.layer0_callees_exports == 0  # no per-edge rows materialized for the folded symbol
    assert _l0_edges(conn) == 0
    assert stats.layer0_folded_symbols == 1 and stats.layer0_folded_edges == 80  # 5 × 16
    (row,) = conn.execute(
        "SELECT symbol, exporters, callers, folded_edges FROM xref_folded_symbols"
    ).fetchall()
    assert tuple(row) == ("gensym", 16, 5, 80)
    # ★ visible via the same facts reader the MCP surfaces (not a silent drop)
    got = facts.list_folded_xref_symbols(conn)
    assert got == [{"symbol": "gensym", "exporters": 16, "callers": 5, "folded_edges": 80}]
    conn.close()


def test_exporter_floor_protects_low_ambiguity_symbol(tmp_path: Path) -> None:
    # ★ the floor: a symbol with FEW exporters is never folded no matter how high its edge count --
    # each edge points at a near-unique target (high value). 8 exporters (< floor 16), threshold 10
    # (so contribution 40 > 10) -> still NOT folded; the 40 edges are materialized.
    conn = _fanout_db(tmp_path, exporters=8, callers=5)
    stats = build_xrefs(conn, fold_edge_threshold=10)
    assert stats.layer0_folded_symbols == 0  # floor blocked the fold
    assert stats.layer0_callees_exports == 40 and _l0_edges(conn) == 40
    assert facts.list_folded_xref_symbols(conn) == []
    conn.close()


def test_below_threshold_symbol_is_not_folded(tmp_path: Path) -> None:
    # a genuinely low-contribution symbol (16 exporters but 1 caller -> 16 edges) stays under a
    # threshold and is fully materialized -- folding only touches the real bombs.
    conn = _fanout_db(tmp_path, exporters=16, callers=1)
    stats = build_xrefs(conn, fold_edge_threshold=25_000)
    assert stats.layer0_folded_symbols == 0
    assert stats.layer0_callees_exports == 16
    conn.close()


def test_config_fold_threshold_stays_in_sync_with_xrefs_default() -> None:
    # ★ single source of truth without an import inversion: the config default and the xrefs module
    # default MUST match (pipeline passes the config value into build_xrefs). Drift -> red.
    assert Config().xref_fold_edge_threshold == DEFAULT_FOLD_EDGE_THRESHOLD


def test_l0_emits_periodic_progress_log(tmp_path: Path, monkeypatch, caplog) -> None:  # type: ignore[no-untyped-def]
    # ★ Fix ③: a long L0 pass logs periodic progress so it is visibly RUNNING, not hung (the owner
    # should not need py-spy to tell). Threshold shrunk so a small fixture crosses it.
    import logging

    monkeypatch.setattr(xrefs_mod, "_L0_PROGRESS_EVERY", 2)
    conn = _fanout_db(tmp_path, exporters=2, callers=5)  # 5 caller funcs -> crosses 2 twice
    with caplog.at_level(logging.INFO, logger="treasure_map.lib.analyze.xrefs"):
        build_xrefs(conn, fold_edge_threshold=10_000)  # high -> no fold, pure progress test
    assert any("xrefs L0:" in r.getMessage() for r in caplog.records)
    conn.close()
