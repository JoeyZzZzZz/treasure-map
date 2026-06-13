# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for Analyzer-2 (A2) — the pattern-driven atlas writer.

Synthetic, vendor-neutral analysis.db (incl. one OSS binary) + temp atlas; hermetic (no
LLM). Proves the R-pattern -> R2 -> atlas write, OSS exclusion, the L0/L1 mapping, the
empty-public_finding gate, evidence neutralization (raw literal never persisted), and the
boundary.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.hunt import run_analyzer2
from treasure_map.lib.storage.connection import open_db

_SRC = Path(__file__).resolve().parents[3] / "src" / "treasure_map"
_HUNT_A2 = _SRC / "lib" / "hunt" / "analyzer2.py"
_QUERY_PKG = _SRC / "lib" / "query"
_ATLAS_SCHEMA = _SRC / "lib" / "storage" / "atlas_schema.sql"

# A shell-ish format literal carrying a (neutral) path — the kind of raw evidence that must
# never be persisted to the atlas verbatim.
RAW_EVIDENCE = "/usr/bin/tool %s"


def _make_db(tmp_path: Path, binaries: list[dict[str, object]]) -> Path:
    db_path = tmp_path / "analysis.db"
    conn = open_db(db_path)
    fid = 0
    for bid, spec in enumerate(binaries, start=1):
        conn.execute(
            "INSERT INTO binaries (id, name, sha256) VALUES (?, ?, ?)",
            (bid, spec["name"], str(bid).zfill(64)),
        )
        if spec.get("oss"):
            conn.execute(
                "INSERT INTO components (binary_id, product, version) VALUES (?, 'tp', '1')",
                (bid,),
            )
        for func in spec.get("funcs", []):  # type: ignore[union-attr]
            fid += 1
            conn.execute(
                "INSERT INTO functions "
                "(id, binary_id, name, pseudocode, pseudocode_hash, callees) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    fid,
                    bid,
                    func["name"],
                    func["pseudocode"],
                    func.get("hash"),
                    json.dumps(func["callees"]),
                ),
            )
    conn.commit()
    conn.close()
    return db_path


def _cmd_injection_fn(name: str, *, param_sourced: bool = True) -> dict[str, object]:
    # A SOURCE callee (recv) is always present so R-pattern flags the command-injection
    # shape; the snprintf argument decides R2's grade: param_1 -> unknown, buf -> confirmed.
    arg = "param_1" if param_sourced else "buf"
    body = (
        f"void {name}(char* param_1){{ char buf[64]; recv(fd,buf,64); char cmd[128]; "
        f'snprintf(cmd,128,"{RAW_EVIDENCE}",{arg}); system(cmd); }}'
    )
    return {
        "name": name,
        "pseudocode": body,
        "hash": f"h_{name}",
        "callees": ["recv", "snprintf", "system"],
    }


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


# ── writer: rich patterns + instances, OSS excluded, L0/L1, empty public_finding ────


def test_writer_populates_atlas_oss_excluded(tmp_path: Path) -> None:
    db = _make_db(
        tmp_path,
        [
            {"name": "webd", "funcs": [_cmd_injection_fn("handle")]},
            {"name": "busybox", "oss": True, "funcs": [_cmd_injection_fn("applet")]},
        ],
    )
    atlas = tmp_path / "atlas.db"
    stats = run_analyzer2(db, atlas, source_run_id="run_dcs")

    assert stats.oss_excluded == 1
    assert stats.matches == 1  # only the custom binary's match
    assert stats.instances_written == 1
    assert _count(atlas, "public_finding") == 0

    conn = open_atlas(atlas)
    try:
        algo = conn.execute("SELECT fingerprint_algo_version FROM pattern").fetchall()
        levels = [r[0] for r in conn.execute("SELECT DISTINCT provenance_level FROM instance")]
        anchors = [r[0] for r in conn.execute("SELECT external_anchor FROM instance")]
    finally:
        conn.close()
    assert all(r[0] == "callseq-v1" for r in algo)  # the RICH pattern, not diff-coarse
    assert all(lvl in ("L0", "L1") for lvl in levels)
    assert all(anchor is None for anchor in anchors)


# ── evidence neutralization: raw literal never persisted ────────────────────────────


def test_raw_evidence_is_not_persisted(tmp_path: Path) -> None:
    db = _make_db(tmp_path, [{"name": "webd", "funcs": [_cmd_injection_fn("handle")]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_dcs")

    (row,) = _instances(atlas)
    # evidence_ref holds a neutral structural descriptor (the fingerprint), not the literal.
    assert row["evidence_ref"] != RAW_EVIDENCE
    # The raw firmware-derived literal appears in NO column of the stored row.
    assert all(RAW_EVIDENCE not in str(row[k]) for k in row.keys())


# ── parameter-sourced -> unknown -> L0 (R2's hard invariant carried through) ─────────


def test_parameter_sourced_match_is_unknown_l0(tmp_path: Path) -> None:
    fn = _cmd_injection_fn("handle", param_sourced=True)
    db = _make_db(tmp_path, [{"name": "webd", "funcs": [fn]}])
    atlas = tmp_path / "atlas.db"
    stats = run_analyzer2(db, atlas, source_run_id="r")
    assert stats.by_status["unknown"] == 1
    (row,) = _instances(atlas)
    assert row["reachability_status"] == "unknown"
    assert row["provenance_level"] == "L0"


# ── append-only: second run accumulates, recurrence_breadth recomputed ──────────────


def test_second_run_appends_and_recomputes_breadth(tmp_path: Path) -> None:
    db = _make_db(tmp_path, [{"name": "webd", "funcs": [_cmd_injection_fn("handle")]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_1")
    run_analyzer2(db, atlas, source_run_id="run_2")

    assert len(_instances(atlas)) == 2
    conn = open_atlas(atlas)
    try:
        breadth = conn.execute("SELECT MAX(recurrence_breadth) FROM pattern").fetchone()[0]
    finally:
        conn.close()
    assert breadth == 2  # two distinct source_run_id over the same fingerprint


# ── BOUNDARY ────────────────────────────────────────────────────────────────────────


def test_a2_sources_are_boundary_clean() -> None:
    banned = re.compile(
        r"\b(vuln\w*|exploit\w*|payload|\bpoc\b|finding|defect|incomplete_patch|fix_quality|"
        r"priority|risk[_ ]?score)\b",
        re.IGNORECASE,
    )
    section_ref = re.compile(r"§|PRD\s")
    targets = [_HUNT_A2, *_QUERY_PKG.glob("*.py"), _ATLAS_SCHEMA]
    for path in targets:
        text = path.read_text()
        assert not banned.search(text), f"banned vocab in {path.name}"
        assert not section_ref.search(text), f"section/private-doc ref in {path.name}"
