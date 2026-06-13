# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for Analyzer-1 (A1) — the first end-to-end atlas writer.

Synthetic, vendor-neutral analysis databases + a mock router (no network). Proves the
diff -> reachability -> write-atlas chain, the L0/L1-only mapping, the no-path-no-vuln
discipline (public_finding stays empty), append-only behavior, and the boundary.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.hunt import run_analyzer1
from treasure_map.lib.llm.types import LLMResponse, Tier
from treasure_map.lib.storage.connection import open_db

_HUNT_PKG = Path(__file__).resolve().parents[3] / "src" / "treasure_map" / "lib" / "hunt"
_HUNT_CLI = Path(__file__).resolve().parents[3] / "src" / "treasure_map" / "cli" / "hunt_cli.py"


class FakeRouter:
    """Async call() stub for R-diff: canned verdict text, never matters to A1's grade."""

    async def call(
        self,
        task: str,
        input_text: str,
        prompt: str,
        prompt_version: str,
        max_tokens: int = 1500,
    ) -> LLMResponse:
        content = "yes" if task == "function_match_assist" else "a neutral change description"
        tier = Tier.M if task == "function_match_assist" else Tier.L
        return LLMResponse(content=content, model_id="fake", cost_usd=0.0, cached=False, tier=tier)


def _one_fn_db(
    tmp_path: Path,
    name: str,
    *,
    fn: str,
    body: str,
    h: str,
    callees: list[str],
) -> Path:
    """Build an analysis.db holding one neutral binary with a single function."""
    db_path = tmp_path / name
    conn = open_db(db_path)
    conn.execute("INSERT INTO binaries (id, name, sha256) VALUES (1, 'webd', ?)", ("a" * 64,))
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, pseudocode, pseudocode_hash, callees) "
        "VALUES (1, 1, ?, ?, ?, ?)",
        (fn, body, h, json.dumps(callees)),
    )
    conn.commit()
    conn.close()
    return db_path


def _instances(atlas_path: Path) -> list[sqlite3.Row]:
    conn = open_atlas(atlas_path)
    try:
        return conn.execute("SELECT * FROM instance ORDER BY instance_id").fetchall()
    finally:
        conn.close()


def _count(atlas_path: Path, view: str) -> int:
    conn = open_atlas(atlas_path)
    try:
        return int(conn.execute(f"SELECT COUNT(*) FROM {view}").fetchone()[0])
    finally:
        conn.close()


# ── end-to-end: a parameter-sourced changed function grades unknown -> L0 ────────────


def test_pipeline_writes_unknown_instance_at_l0(tmp_path: Path) -> None:
    # Same symbol name, body differs -> R-diff "changed"; command built from a parameter
    # -> R2 "unknown" (never confirmed).
    a = _one_fn_db(
        tmp_path,
        "a.db",
        fn="run_tool",
        body="void run_tool(char* param_1){ system(param_1); }",
        h="old",
        callees=["system"],
    )
    b = _one_fn_db(
        tmp_path,
        "b.db",
        fn="run_tool",
        body="void run_tool(char* param_1){ if(ok) system(param_1); }",
        h="new",
        callees=["system"],
    )
    atlas = tmp_path / "atlas.db"
    stats = run_analyzer1(
        a, b, "version", atlas, FakeRouter(), run_id_a="run_base", run_id_b="run_cmp"
    )

    assert stats.instances_written == 1
    assert stats.by_status["unknown"] == 1
    assert stats.public_findings == 0  # the central no-path-no-vuln gate
    assert _count(atlas, "public_finding") == 0

    (row,) = _instances(atlas)
    assert row["reachability_status"] == "unknown"
    assert row["provenance_level"] == "L0"
    assert row["fix_diff"]  # neutral unified diff stored
    assert row["scope_origin"] == "version"
    assert row["source_run_id"] == "run_base"
    assert row["external_anchor"] is None


# ── blocked -> dormant at L1, still no public finding ───────────────────────────────


def test_blocked_candidate_lands_in_dormant(tmp_path: Path) -> None:
    # In-function source, but a validator guards the value -> R2 "blocked".
    body = "void h(){ char buf[64]; recv(fd,buf,64); if(check_field(buf)){ system(buf); } }"
    calls = ["recv", "check_field", "system"]
    a = _one_fn_db(tmp_path, "a.db", fn="h", body=body, h="old", callees=calls)
    b = _one_fn_db(tmp_path, "b.db", fn="h", body=body + " // changed", h="new", callees=calls)
    atlas = tmp_path / "atlas.db"
    stats = run_analyzer1(a, b, "version", atlas, FakeRouter(), run_id_a="rb", run_id_b="rc")

    assert stats.by_status["blocked"] == 1
    (row,) = _instances(atlas)
    assert row["reachability_status"] == "blocked"
    assert row["provenance_level"] == "L1"
    assert row["blocking_mechanism"]  # neutral mechanism set
    assert _count(atlas, "dormant_instance") == 1
    assert _count(atlas, "public_finding") == 0


# ── confirmed -> L1, still not a public finding (needs >= L2) ────────────────────────


def test_confirmed_candidate_is_l1_not_public(tmp_path: Path) -> None:
    body = "void h(){ char buf[64]; recv(fd,buf,64); system(buf); }"
    calls = ["recv", "system"]
    a = _one_fn_db(tmp_path, "a.db", fn="h", body=body, h="old", callees=calls)
    b = _one_fn_db(tmp_path, "b.db", fn="h", body=body + " // changed", h="new", callees=calls)
    atlas = tmp_path / "atlas.db"
    stats = run_analyzer1(a, b, "version", atlas, FakeRouter(), run_id_a="rb", run_id_b="rc")

    assert stats.by_status["confirmed"] == 1
    (row,) = _instances(atlas)
    assert row["reachability_status"] == "confirmed"
    assert row["provenance_level"] == "L1"  # A1 never inflates to L2/L3
    assert _count(atlas, "public_finding") == 0  # confirmed but only L1 -> not a finding


# ── no-sink changed function -> unknown, neutral instance still written ──────────────


def test_no_sink_change_is_unknown(tmp_path: Path) -> None:
    a = _one_fn_db(
        tmp_path,
        "a.db",
        fn="calc",
        body="int calc(int x){ return x+1; }",
        h="old",
        callees=["helper"],
    )
    b = _one_fn_db(
        tmp_path,
        "b.db",
        fn="calc",
        body="int calc(int x){ return x+2; }",
        h="new",
        callees=["helper"],
    )
    atlas = tmp_path / "atlas.db"
    stats = run_analyzer1(a, b, "version", atlas, FakeRouter(), run_id_a="rb", run_id_b="rc")

    assert stats.instances_written == 1
    assert stats.by_status["unknown"] == 1
    (row,) = _instances(atlas)
    assert row["reachability_status"] == "unknown"
    assert row["provenance_level"] == "L0"
    assert row["sink_anchor"] is None


# ── never L2/L3, never an external anchor ───────────────────────────────────────────


def test_a1_never_writes_l2_l3_or_anchor(tmp_path: Path) -> None:
    body = "void h(){ char buf[64]; recv(fd,buf,64); system(buf); }"
    calls = ["recv", "system"]
    a = _one_fn_db(tmp_path, "a.db", fn="h", body=body, h="o", callees=calls)
    b = _one_fn_db(tmp_path, "b.db", fn="h", body=body + " //x", h="n", callees=calls)
    atlas = tmp_path / "atlas.db"
    run_analyzer1(a, b, "version", atlas, FakeRouter(), run_id_a="rb", run_id_b="rc")

    conn = open_atlas(atlas)
    try:
        levels = [r[0] for r in conn.execute("SELECT DISTINCT provenance_level FROM instance")]
        anchors = [r[0] for r in conn.execute("SELECT external_anchor FROM instance")]
    finally:
        conn.close()
    assert all(lvl in ("L0", "L1") for lvl in levels)
    assert all(anchor is None for anchor in anchors)


# ── append-only: a second run accumulates, never wipes ──────────────────────────────


def test_second_run_appends(tmp_path: Path) -> None:
    body = "void h(){ char buf[64]; recv(fd,buf,64); system(buf); }"
    calls = ["recv", "system"]
    a = _one_fn_db(tmp_path, "a.db", fn="h", body=body, h="o", callees=calls)
    b = _one_fn_db(tmp_path, "b.db", fn="h", body=body + " //x", h="n", callees=calls)
    atlas = tmp_path / "atlas.db"
    run_analyzer1(a, b, "version", atlas, FakeRouter(), run_id_a="rb1", run_id_b="rc1")
    run_analyzer1(a, b, "version", atlas, FakeRouter(), run_id_a="rb2", run_id_b="rc2")

    assert len(_instances(atlas)) == 2  # accumulated, not wiped
    conn = open_atlas(atlas)
    try:
        # Same coarse pattern, two distinct run ids -> recurrence_breadth == 2.
        breadth = conn.execute("SELECT MAX(recurrence_breadth) FROM pattern").fetchone()[0]
    finally:
        conn.close()
    assert breadth == 2


# ── BOUNDARY ────────────────────────────────────────────────────────────────────────


def test_hunt_package_is_boundary_clean() -> None:
    # "finding" as a standalone label is banned; the schema view name public_finding(s)
    # is not a standalone match (preceded by '_'), so it is allowed.
    banned = re.compile(
        r"\b(vuln\w*|exploit\w*|payload|\bpoc\b|finding|incomplete_patch|fix_quality)\b",
        re.IGNORECASE,
    )
    section_ref = re.compile(r"§|PRD\s")
    targets = [*_HUNT_PKG.glob("*.py"), _HUNT_CLI]
    for path in targets:
        text = path.read_text()
        assert not banned.search(text), f"banned vocab in {path.name}"
        assert not section_ref.search(text), f"section/private-doc ref in {path.name}"
