# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
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


def test_help_text_does_not_miscount_the_gates() -> None:
    """--help must not still claim "two" red lines — the script enforces four gates (A-D).

    MUTATION (verified RED): restore the old "machine enforcement of two design red lines" opening
    line -> the --help text says "two" again and the assertion below fails."""
    result = subprocess.run(
        [sys.executable, str(_ROOT / "scripts" / "check_recall_integrity.py"), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    help_text = result.stdout
    assert "two design red lines" not in help_text
    assert "two red lines" not in help_text
    # the four gates it actually runs are all described, so the count is not understated
    for gate in ("Gate A", "Gate B", "Gate C", "Gate D"):
        assert gate in help_text, gate


def _atlas_with_gate_a(path: Path, *, violating: bool) -> None:
    """An atlas whose one candidate is a Gate-A violation (const_sink_arg on a free_string sink
    argument) or a clean one; its run is registered either way, so Gate C holds."""
    from treasure_map.lib.atlas.connection import open_atlas
    from treasure_map.lib.atlas.models import InstanceRow
    from treasure_map.lib.atlas.writer import add_instance, begin_run, upsert_pattern

    conn = open_atlas(path)
    begin_run(conn, "run_gate", analysis_db_path=str(path.parent / "analysis.db"))
    pid = upsert_pattern(
        conn, source_class="external_input", sink_class="cmd", call_sequence_shape="source->cmd"
    )
    add_instance(
        conn,
        InstanceRow(
            pattern_id=pid,
            pseudocode_hash="h1",
            source_anchor="handle",
            sink_anchor="system",
            source_run_id="run_gate",
            reachability_status="unknown",
            blocking_mechanism="const_sink_arg" if violating else None,
            provenance_level="L0",
            evidence_ref="run_gate#handle@cmd",
            flow_evidence=json.dumps({"source_kind": "free_string"}),
        ),
    )
    conn.close()


def test_a_database_path_holding_a_hash_sign_is_the_one_checked(tmp_path: Path) -> None:
    """The gates open the database at the path they are given, whatever it holds. A workspace
    path can carry ``#``; written into a ``file:`` URI unescaped, ``#`` starts the fragment, so
    the open lands on the path cut at it (and without ``mode=ro``) — here a clean atlas, so a
    violating one would pass.

    MUTATION (verified RED): open with ``sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)``
    in the script's ``_count`` -> the clean atlas at the cut path is read, Gate A reports nothing,
    the script exits 0, and the exit-code assertion fails."""
    real_dir = tmp_path / "fw#1"
    real_dir.mkdir()
    _atlas_with_gate_a(real_dir / "atlas.db", violating=True)
    _atlas_with_gate_a(tmp_path / "fw", violating=False)  # where the unescaped URI would land
    result = subprocess.run(
        [
            sys.executable,
            str(_ROOT / "scripts" / "check_recall_integrity.py"),
            "--atlas",
            str(real_dir / "atlas.db"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert "Gate A: 1 const_sink_arg" in result.stdout
