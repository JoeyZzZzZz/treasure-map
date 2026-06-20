# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for lib/hunt/facts — the thin-command-wrapper structural fact.

Pure functions over synthetic, vendor-neutral pseudocode, plus an atlas round-trip proving the
fact persists (and is readable once the source analysis.db is gone). The fact is structural —
it does NOT claim the forwarded value is attacker-controlled — and conservative under doubt.
This round NO recall/downweight/triage path consumes it; a guard test asserts that.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import InstanceRow
from treasure_map.lib.atlas.writer import add_instance, upsert_pattern
from treasure_map.lib.hunt.facts import _WRAPPER_MAX_STATEMENTS, is_thin_cmd_wrapper

_SRC = Path(__file__).resolve().parents[3] / "src" / "treasure_map"


# ── positives: a thin wrapper that forwards a parameter to a shell command sink ───────


def test_direct_param_forward_to_system_is_wrapper() -> None:
    pc = "void run(char* param_1){ system(param_1); }"
    assert is_thin_cmd_wrapper(pc, ["system"]) == (True, "system")


def test_named_parameter_forward_is_wrapper() -> None:
    # A human-named parameter (not a param_N placeholder) is still a parameter forward.
    pc = "void run(const char *cmd){ system(cmd); }"
    assert is_thin_cmd_wrapper(pc, ["system"]) == (True, "system")


def test_popen_forward_records_that_sink() -> None:
    pc = 'int run(char* param_1){ FILE* f = popen(param_1, "r"); return 0; }'
    assert is_thin_cmd_wrapper(pc, ["popen"]) == (True, "popen")


def test_system_preferred_when_several_shell_sinks_present() -> None:
    # Deterministic pick: when both are present the canonical 'system' is the recorded sink.
    pc = 'void run(char* param_1){ if (param_1) popen(param_1,"r"); else system(param_1); }'
    assert is_thin_cmd_wrapper(pc, ["popen", "system"]) == (True, "system")


def test_wrapper_with_a_guard_check_still_thin() -> None:
    # A forwarder that also does a couple of trivial checks is still thin (under the bound).
    pc = (
        "void run(char* param_1){ if (param_1 == 0) return; "
        "if (*param_1 == 0) return; system(param_1); }"
    )
    assert is_thin_cmd_wrapper(pc, ["system"]) == (True, "system")


# ── negatives: not a verbatim forward, not thin, or not a shell sink ──────────────────


def test_locally_built_command_is_not_wrapper() -> None:
    # ① local format construction before system -> the value is built, not forwarded verbatim.
    pc = 'void h(char* p){ char c[64]; snprintf(c,64,"x %s",p); system(c); }'
    assert is_thin_cmd_wrapper(pc, ["snprintf", "system"]) == (False, None)


def test_reassigned_parameter_is_not_verbatim_forward() -> None:
    pc = "void run(char* param_1){ param_1 = fixup(param_1); system(param_1); }"
    assert is_thin_cmd_wrapper(pc, ["fixup", "system"]) == (False, None)


def test_large_body_is_not_thin() -> None:
    # ② a function that does real work then calls system is not a thin wrapper.
    stmts = " ".join(f"int v{i} = step{i}();" for i in range(_WRAPPER_MAX_STATEMENTS + 2))
    pc = f"void run(char* param_1){{ {stmts} system(param_1); }}"
    callees = [f"step{i}" for i in range(_WRAPPER_MAX_STATEMENTS + 2)] + ["system"]
    assert is_thin_cmd_wrapper(pc, callees) == (False, None)


def test_exec_no_shell_is_not_wrapper() -> None:
    # ③ exec-without-a-shell is not a shell command sink here (its first arg is the program
    # path, and shell metacharacters are inert) -> not flagged.
    pc = 'void run(char* param_1){ execl("/bin/ls", "ls", param_1, 0); }'
    assert is_thin_cmd_wrapper(pc, ["execl"]) == (False, None)


def test_local_sourced_value_is_not_parameter_forward() -> None:
    # The forwarded value is an in-function source, not a parameter -> not a parameter forward.
    pc = "void run(void){ char* c = get_cgi(); system(c); }"
    assert is_thin_cmd_wrapper(pc, ["get_cgi", "system"]) == (False, None)


def test_no_command_sink_is_not_wrapper() -> None:
    pc = "void run(char* param_1){ strcpy(dst, param_1); }"
    assert is_thin_cmd_wrapper(pc, ["strcpy"]) == (False, None)


def test_threshold_is_fixed_and_documented() -> None:
    # The thinness bound (N) is a fixed structural threshold, asserted so a change is deliberate.
    assert _WRAPPER_MAX_STATEMENTS == 6


# ── persistence: the fact round-trips through the atlas and survives source removal ───


def _store_wrapper_instance(atlas_path: Path) -> None:
    conn = open_atlas(atlas_path)
    try:
        pid = upsert_pattern(
            conn,
            source_class="unknown",
            sink_class="cmd",
            call_sequence_shape="callseq-v1",
            structural_fingerprint="fp_wrap",
            fingerprint_algo_version="callseq-v1",
        )
        add_instance(
            conn,
            InstanceRow(
                pattern_id=pid,
                pseudocode_hash="h_wrap",
                source_anchor="run",
                sink_anchor="system",
                source_run_id="run_w",
                evidence_ref="run_w#fn1@cmd",
                is_thin_cmd_wrapper=True,
                wrapped_sink="system",
            ),
        )
    finally:
        conn.close()


def test_wrapper_fact_round_trips_through_atlas(tmp_path: Path) -> None:
    atlas = tmp_path / "atlas.db"
    _store_wrapper_instance(atlas)
    # Re-open (analysis.db never involved) and read the fact back by name.
    conn = open_atlas(atlas)
    try:
        row = conn.execute(
            "SELECT is_thin_cmd_wrapper, wrapped_sink FROM instance WHERE source_run_id = 'run_w'"
        ).fetchone()
    finally:
        conn.close()
    assert row["is_thin_cmd_wrapper"] == 1
    assert row["wrapped_sink"] == "system"


def test_wrapper_fact_default_is_false_null(tmp_path: Path) -> None:
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    try:
        pid = upsert_pattern(
            conn,
            source_class="unknown",
            sink_class="cmd",
            call_sequence_shape="callseq-v1",
            structural_fingerprint="fp_plain",
            fingerprint_algo_version="callseq-v1",
        )
        add_instance(
            conn,
            InstanceRow(
                pattern_id=pid,
                pseudocode_hash="h_plain",
                source_run_id="run_p",
                evidence_ref="run_p#fn1@cmd",
            ),
        )
        row = conn.execute(
            "SELECT is_thin_cmd_wrapper, wrapped_sink FROM instance WHERE source_run_id = 'run_p'"
        ).fetchone()
    finally:
        conn.close()
    assert row["is_thin_cmd_wrapper"] == 0
    assert row["wrapped_sink"] is None


def test_migration_adds_columns_to_legacy_atlas(tmp_path: Path) -> None:
    # An atlas created without the fact columns is brought forward in place (no rebuild): the
    # ALTERs add the columns and existing rows take the 0 / NULL defaults.
    db = tmp_path / "legacy.db"
    conn = sqlite3.connect(db)
    # A legacy shape: every column the schema's indexes reference, but WITHOUT this round's
    # fact columns. Re-applying the schema (IF NOT EXISTS) keeps the table; _migrate adds them.
    conn.executescript(
        """
        CREATE TABLE pattern (pattern_id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_class TEXT, sink_class TEXT, call_sequence_shape TEXT,
            structural_fingerprint TEXT);
        CREATE TABLE instance (instance_id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern_id INTEGER, pseudocode_hash TEXT, source_run_id TEXT, evidence_ref TEXT,
            reachability_status TEXT DEFAULT 'unknown', provenance_level TEXT DEFAULT 'L0',
            scope_origin TEXT);
        INSERT INTO instance (pattern_id, pseudocode_hash, source_run_id)
            VALUES (1, 'old', 'run_old');
        """
    )
    conn.commit()
    conn.close()

    conn = open_atlas(db)
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(instance)").fetchall()}
        row = conn.execute(
            "SELECT is_thin_cmd_wrapper, wrapped_sink FROM instance WHERE source_run_id='run_old'"
        ).fetchone()
    finally:
        conn.close()
    assert {"is_thin_cmd_wrapper", "wrapped_sink"} <= cols
    assert row["is_thin_cmd_wrapper"] == 0
    assert row["wrapped_sink"] is None


def test_no_recall_or_score_path_reads_the_fact() -> None:
    # ★ This round records the fact but consumes it NOWHERE. Guard against an accidental early
    # consumer: the recall (analyzer2), downweight, and read-side score modules must not
    # reference the fact field by name. (analyzer2 WRITES it; it must not branch on it.)
    for rel in ("lib/hunt/downweight.py", "lib/query/triage.py", "lib/query/views.py"):
        text = (_SRC / rel).read_text()
        assert "is_thin_cmd_wrapper" not in text, f"{rel} unexpectedly references the fact"
        assert "wrapped_sink" not in text, f"{rel} unexpectedly references the fact"
    # analyzer2 writes the fact but must not READ it back to alter recall/score: the only
    # occurrences are the import, the call, and the two InstanceRow kwargs — never a comparison.
    a2 = (_SRC / "lib/hunt/analyzer2.py").read_text()
    assert "if thin_wrapper" not in a2 and "if is_thin_cmd_wrapper" not in a2
