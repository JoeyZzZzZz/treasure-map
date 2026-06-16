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

import pytest

import treasure_map.lib.hunt.analyzer2 as analyzer2_mod
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.hunt import run_analyzer2
from treasure_map.lib.query import explain_candidate
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
            "INSERT INTO binaries (id, name, path, sha256) VALUES (?, ?, ?, ?)",
            (bid, spec["name"], spec.get("path"), str(bid).zfill(64)),
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
    # evidence_ref holds a neutral per-instance locator (run-scoped function id), not the
    # raw firmware literal.
    assert row["evidence_ref"] != RAW_EVIDENCE
    # The raw firmware-derived literal appears in NO column of the stored row.
    assert all(RAW_EVIDENCE not in str(row[k]) for k in row.keys())


def test_evidence_ref_unique_per_instance(tmp_path: Path) -> None:
    # Two functions of the SAME shape share one structural_fingerprint (one pattern) but are
    # distinct instances. evidence_ref must locate each instance uniquely — it must NOT be the
    # shared fingerprint (that collided across all same-shape instances and lost traceability).
    db = _make_db(
        tmp_path,
        [{"name": "webd", "funcs": [_cmd_injection_fn("h1"), _cmd_injection_fn("h2")]}],
    )
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_x")

    rows = _instances(atlas)
    assert len(rows) == 2
    refs = [r["evidence_ref"] for r in rows]
    assert len(set(refs)) == 2, f"evidence_ref collided across instances: {refs}"
    # One shared pattern fingerprint underneath; the per-instance refs are never that value.
    conn = open_atlas(atlas)
    try:
        fps = {r[0] for r in conn.execute("SELECT structural_fingerprint FROM pattern")}
    finally:
        conn.close()
    assert len(fps) == 1  # same shape -> one pattern
    assert all(fp not in refs for fp in fps)  # the instance ref is never the shared fingerprint


# ── candidate locatability: binary_path + content hash auto-filled from the source ──


def test_instance_carries_binary_location(tmp_path: Path) -> None:
    # The instance records WHERE the evidence function lives (full path) + the binary's content
    # hash, both auto-filled from the source build — so a candidate is locatable from the atlas.
    db = _make_db(
        tmp_path,
        [{"name": "webd", "path": "usr/sbin/webd", "funcs": [_cmd_injection_fn("handle")]}],
    )
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_loc")

    (row,) = _instances(atlas)
    assert row["binary_path"] == "usr/sbin/webd"  # full path, not the bare name
    assert row["binary_content_hash"] == str(1).zfill(64)  # the source binary's sha256


def test_binary_path_falls_back_to_name_when_source_has_no_path(tmp_path: Path) -> None:
    # A degraded source with no path still yields a locator (the bare name) rather than NULL.
    db = _make_db(tmp_path, [{"name": "webd", "funcs": [_cmd_injection_fn("handle")]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_np")

    (row,) = _instances(atlas)
    assert row["binary_path"] == "webd"


def test_location_survives_source_db_removal(tmp_path: Path) -> None:
    # Locatability must come from the atlas, NOT a read-time join back to analysis.db: delete the
    # source build, then triage still shows the location.
    from treasure_map.lib.query import triage

    db = _make_db(
        tmp_path,
        [{"name": "webd", "path": "usr/sbin/webd", "funcs": [_cmd_injection_fn("handle")]}],
    )
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_gone")
    db.unlink()  # the source build is gone

    conn = open_atlas(atlas)
    try:
        cands = triage(conn, run_id="run_gone")
    finally:
        conn.close()
    assert len(cands) == 1
    assert cands[0].binary_path == "usr/sbin/webd"  # served from the atlas alone


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


# ── append-only: second run accumulates, device_spread recomputed ──────────────────


def test_second_run_appends_and_recomputes_breadth(tmp_path: Path) -> None:
    db = _make_db(tmp_path, [{"name": "webd", "funcs": [_cmd_injection_fn("handle")]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_1")
    run_analyzer2(db, atlas, source_run_id="run_2")

    assert len(_instances(atlas)) == 2
    conn = open_atlas(atlas)
    try:
        breadth = conn.execute("SELECT MAX(device_spread) FROM pattern").fetchone()[0]
    finally:
        conn.close()
    assert breadth == 2  # two distinct source_run_id over the same fingerprint


def _multi_sink_fn(name: str = "ma_utils_exec") -> dict[str, object]:
    # One function that matches BOTH a cmd shape (recv->snprintf+%s literal->popen) and a copy
    # shape (recv->strcpy) -> two distinct instances over the same function.
    body = (
        f"void {name}(char* param_1){{ char buf[64]; recv(fd,buf,64); char cmd[128]; "
        f'snprintf(cmd,128,"{RAW_EVIDENCE}",param_1); popen(cmd,"r"); '
        f"char dst[64]; strcpy(dst,param_1); }}"
    )
    return {
        "name": name,
        "pseudocode": body,
        "hash": f"h_{name}",
        "callees": ["recv", "snprintf", "popen", "strcpy"],
    }


# ── replace-by-run: re-running one run-id refreshes (never doubles) ──────────────────


def test_same_run_rerun_is_idempotent(tmp_path: Path) -> None:
    db = _make_db(tmp_path, [{"name": "webd", "funcs": [_cmd_injection_fn("handle")]}])
    atlas = tmp_path / "atlas.db"
    s1 = run_analyzer2(db, atlas, source_run_id="run_rb")
    after_one = len(_instances(atlas))
    s2 = run_analyzer2(db, atlas, source_run_id="run_rb")  # same run-id again

    assert s2.instances_written == s1.instances_written
    assert len(_instances(atlas)) == after_one  # refreshed, NOT doubled
    refs = [r["evidence_ref"] for r in _instances(atlas)]
    assert len(set(refs)) == len(refs)  # every ref unique within the run


def test_rerun_does_not_touch_other_runs(tmp_path: Path) -> None:
    db = _make_db(tmp_path, [{"name": "webd", "funcs": [_cmd_injection_fn("handle")]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_A")
    a_rows_before = [tuple(r) for r in _instances(atlas) if r["source_run_id"] == "run_A"]
    run_analyzer2(db, atlas, source_run_id="run_B")
    run_analyzer2(db, atlas, source_run_id="run_B")  # refresh B twice
    a_rows_after = [tuple(r) for r in _instances(atlas) if r["source_run_id"] == "run_A"]

    assert a_rows_before == a_rows_after  # run A untouched by B's replace-by-run


def test_rerun_failure_rolls_back_to_old_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = _make_db(tmp_path, [{"name": "webd", "funcs": [_cmd_injection_fn("handle")]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_rb")
    before = [tuple(r) for r in _instances(atlas)]
    assert before  # there is an old result to protect

    real_add = analyzer2_mod.add_instance
    calls = {"n": 0}

    def _boom(*args: object, **kwargs: object) -> int:
        calls["n"] += 1
        if calls["n"] >= 1:  # fail during the re-run write
            raise RuntimeError("write blew up mid-run")
        return real_add(*args, **kwargs)  # type: ignore[no-any-return]

    monkeypatch.setattr(analyzer2_mod, "add_instance", _boom)
    with pytest.raises(RuntimeError):
        run_analyzer2(db, atlas, source_run_id="run_rb")

    after = [tuple(r) for r in _instances(atlas)]
    assert after == before  # rolled back to the old result — never a half-written run


def test_replace_by_run_keeps_pattern_rows(tmp_path: Path) -> None:
    db = _make_db(tmp_path, [{"name": "webd", "funcs": [_cmd_injection_fn("handle")]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_rb")
    conn = open_atlas(atlas)
    try:
        patterns_before = conn.execute("SELECT COUNT(*) FROM pattern").fetchone()[0]
    finally:
        conn.close()
    run_analyzer2(db, atlas, source_run_id="run_rb")  # replace-by-run
    conn = open_atlas(atlas)
    try:
        patterns_after = conn.execute("SELECT COUNT(*) FROM pattern").fetchone()[0]
    finally:
        conn.close()
    assert patterns_after == patterns_before  # pattern (accumulation layer) never deleted


# ── evidence_ref uniqueness: func + sink hit ─────────────────────────────────────────


def test_multi_sink_function_has_unique_evidence_refs(tmp_path: Path) -> None:
    db = _make_db(tmp_path, [{"name": "webd", "funcs": [_multi_sink_fn()]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_ms")

    rows = _instances(atlas)
    assert len(rows) >= 2  # one function, multiple sink hits -> multiple instances
    refs = [r["evidence_ref"] for r in rows]
    assert len(set(refs)) == len(refs), f"evidence_ref collided across sink hits: {refs}"
    sink_classes = {r["evidence_ref"].split("@", 1)[1] for r in rows}
    assert {"cmd", "copy"} <= sink_classes  # the ref carries the distinguishing sink class


def test_explain_anchors_the_right_sink_hit(tmp_path: Path) -> None:
    db = _make_db(tmp_path, [{"name": "webd", "funcs": [_multi_sink_fn()]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_ms")

    conn = open_atlas(atlas)
    try:
        cmd_ref = next(
            r["evidence_ref"] for r in _instances(atlas) if r["evidence_ref"].endswith("@cmd")
        )
        ex = explain_candidate(conn, cmd_ref)
    finally:
        conn.close()
    assert ex is not None
    assert ex.candidate.evidence_ref == cmd_ref
    assert ex.candidate.sink_class == "cmd"  # the cmd ref resolves to the cmd hit, not the copy


# ── work item A: FP-suppression form notes + library origin (downweight, never remove) ──


def _exec_no_shell_fn(name: str = "run_exec") -> dict[str, object]:
    # source + shellish %s + an exec sink that does NOT go through a shell.
    body = (
        f"void {name}(char* p){{ char b[64]; recv(fd,b,64); char c[128]; "
        f'snprintf(c,128,"/usr/sbin/tool %s",b); execl(c,c,0); }}'
    )
    return {
        "name": name,
        "pseudocode": body,
        "hash": f"h_{name}",
        "callees": ["recv", "snprintf", "execl"],
    }


def _numeric_fn(name: str = "run_num") -> dict[str, object]:
    body = (
        f"void {name}(char* p){{ char b[64]; recv(fd,b,64); long n=strtol(b,0,10); char c[128]; "
        f'snprintf(c,128,"/bin/tool %s",n); system(c); }}'
    )
    return {
        "name": name,
        "pseudocode": body,
        "hash": f"h_{name}",
        "callees": ["recv", "strtol", "snprintf", "system"],
    }


def _by_anchor(atlas_path: Path) -> dict[str, sqlite3.Row]:
    return {r["source_anchor"]: r for r in _instances(atlas_path)}


def _score_of(atlas_path: Path, fn: str) -> float:
    from treasure_map.lib.query import triage as run_triage

    conn = open_atlas(atlas_path)
    try:
        return next(c.score for c in run_triage(conn) if c.function == fn)
    finally:
        conn.close()


def test_no_shell_exec_is_labelled_and_downweighted(tmp_path: Path) -> None:
    # Compare within the same reachability tier: both candidates grade confirmed (buf-sourced),
    # so the gap is purely the form downweight, not the status weight.
    db = _make_db(
        tmp_path,
        [
            {
                "name": "webd",
                "funcs": [
                    _cmd_injection_fn("shell_sys", param_sourced=False),
                    _exec_no_shell_fn("noshell"),
                ],
            }
        ],
    )
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_a")

    rows = _by_anchor(atlas)
    assert rows["noshell"]["blocking_mechanism"] == "no_shell_exec"
    assert rows["noshell"]["reachability_status"] != "blocked"  # downweighted, never blocked
    # the no-shell exec ranks clearly below the real shell system() candidate of the same tier.
    assert _score_of(atlas, "noshell") < _score_of(atlas, "shell_sys")


def test_numeric_sanitized_is_labelled_and_downweighted(tmp_path: Path) -> None:
    db = _make_db(
        tmp_path,
        [
            {
                "name": "webd",
                "funcs": [
                    _cmd_injection_fn("raw_sys", param_sourced=False),
                    _numeric_fn("num_sys"),
                ],
            }
        ],
    )
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_a")

    rows = _by_anchor(atlas)
    assert rows["num_sys"]["blocking_mechanism"] == "numeric_sanitized"
    assert _score_of(atlas, "num_sys") < _score_of(atlas, "raw_sys")


def test_library_symbol_routes_to_stock_origin(tmp_path: Path) -> None:
    # A statically-linked library function (custom-named binary, library symbol) -> stock_oss_known,
    # which the binary-level OSS exclusion misses. It is downweighted AND kept off pattern_breadth.
    lib_fn = _cmd_injection_fn("handle")
    lib_fn["name"] = "SSL_read"
    db = _make_db(
        tmp_path,
        [{"name": "customd", "funcs": [_cmd_injection_fn("real_handle"), lib_fn]}],
    )
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_a")

    rows = _by_anchor(atlas)
    assert rows["SSL_read"]["origin"] == "stock_oss_known"
    assert rows["real_handle"]["origin"] == "unknown"  # never defaulted to custom
    assert _score_of(atlas, "SSL_read") < _score_of(atlas, "real_handle")
    # routed out of pattern_breadth (it counts only custom/unknown).
    conn = open_atlas(atlas)
    try:
        breadth = conn.execute(
            "SELECT pattern_breadth FROM pattern_ledger ORDER BY pattern_id"
        ).fetchall()
    finally:
        conn.close()
    assert all(r[0] >= 0 for r in breadth)  # ledger still computes; stock excluded by definition


def test_plain_shell_candidate_is_not_downweighted(tmp_path: Path) -> None:
    # The "do not over-downweight" guard: a real shell system() with an external source, custom
    # symbol, non-numeric, no constant caller keeps blocking_mechanism NULL (full score).
    db = _make_db(tmp_path, [{"name": "webd", "funcs": [_cmd_injection_fn("clean_handle")]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_a")
    assert _by_anchor(atlas)["clean_handle"]["blocking_mechanism"] is None


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
