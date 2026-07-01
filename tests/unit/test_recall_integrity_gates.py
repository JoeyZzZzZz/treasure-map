# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Red-line CI gates — the two invariants enforced by scripts/check_recall_integrity.py.

Gate A (never wrongly downweight): a const_sink_arg note must never sit on a free_string candidate.
Gate B (degrade must be visible): a ghidra_status='ok' binary must hold functions.

These tests prove (1) the real analyzer never writes a Gate-A violation for the exact shape that
regressed in the field — a function with both a constant system("…") and a system(free_var) — and
(2) the standalone checker's self-test distinguishes a clean workspace from a seeded-violation one.
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

from treasure_map.lib.hunt import run_analyzer2
from treasure_map.lib.storage.connection import open_db

_GATE_A_SQL = (
    "SELECT COUNT(*) FROM instance "
    "WHERE blocking_mechanism = 'const_sink_arg' "
    "AND json_extract(flow_evidence, '$.source_kind') = 'free_string'"
)

_ROOT = Path(__file__).resolve().parents[2]


def _make_analysis(tmp_path: Path, name: str, pseudocode: str, callees: list[str]) -> Path:
    db = tmp_path / "analysis.db"
    conn = open_db(db)
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256, ghidra_status, last_seen_at) "
        "VALUES (1, 'msgd', 'usr/sbin/msgd', ?, 'ok', '2026-01-01')",
        ("a" * 64,),
    )
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, pseudocode, pseudocode_hash, callees) "
        "VALUES (1, 1, ?, ?, 'h1', ?)",
        (name, pseudocode, json.dumps(callees)),
    )
    conn.commit()
    conn.close()
    return db


def test_analyzer2_never_downweights_free_string_beside_a_constant(tmp_path: Path) -> None:
    # ★ Red-line regression, end to end: the function has a free-string system(cmd) FIRST (so it is
    # the anchored candidate) and a constant system("…") after. The old whole-function regex tagged
    # it const_sink_arg and buried it; the parameter-specific downweight + write-side reconciliation
    # must leave it un-downweighted, and Gate A (const_sink_arg AND free_string) must be 0.
    pc = (
        "void handle_msg(void){ "
        "char* cmd = json_object_get_string(obj); "
        "system(cmd); "
        'system("ubus call system board"); }'
    )
    db = _make_analysis(tmp_path, "handle_msg", pc, ["json_object_get_string", "system"])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_msg")

    conn = sqlite3.connect(atlas)
    try:
        rows = conn.execute(
            "SELECT blocking_mechanism, flow_evidence FROM instance WHERE sink_anchor = 'system'"
        ).fetchall()
        gate_a = conn.execute(_GATE_A_SQL).fetchone()[0]
    finally:
        conn.close()

    assert rows, "expected a cmd candidate for the free-string system(cmd) call"
    (blocking, evidence) = rows[0]
    assert json.loads(evidence)["source_kind"] == "free_string"  # the right candidate
    assert blocking != "const_sink_arg"  # not wrongly downweighted
    assert gate_a == 0  # the invariant holds on real analyzer output


def test_check_recall_integrity_self_test_passes() -> None:
    # The standalone gate's self-test (the exact command CI runs) catches both seeded violations
    # and passes a clean workspace.
    result = subprocess.run(
        [sys.executable, str(_ROOT / "scripts" / "check_recall_integrity.py"), "--self-test"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
