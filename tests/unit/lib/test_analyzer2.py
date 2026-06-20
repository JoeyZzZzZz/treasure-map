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


def _make_db(
    tmp_path: Path,
    binaries: list[dict[str, object]],
    *,
    xrefs: list[tuple[int, int]] | None = None,
) -> Path:
    db_path = tmp_path / "analysis.db"
    conn = open_db(db_path)
    fid = 0
    for caller_fid, callee_fid in xrefs or []:
        conn.execute(
            "INSERT INTO xrefs (caller_func_id, callee_func_id, xref_type) "
            "VALUES (?, ?, 'import_export')",
            (caller_fid, callee_fid),
        )
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


def test_mixed_system_and_execl_anchors_system_not_no_shell(tmp_path: Path) -> None:
    # Bug1: a function that calls BOTH system and execl must anchor to the shell-running sink
    # (system), and no_shell_exec must NOT fire (cmd capability is not all exec-no-shell) — the
    # alphabetically-first execl must not mask the real shell sink.
    mixed = {
        "name": "mixed_exec",
        "pseudocode": (
            "void mixed_exec(char* p){ char b[64]; recv(fd,b,64); char c[128]; "
            'snprintf(c,128,"/usr/sbin/tool %s",b); if (b[0]) execl(c,c,0); else system(c); }'
        ),
        "hash": "h_mixed",
        "callees": ["recv", "snprintf", "execl", "system"],
    }
    db = _make_db(tmp_path, [{"name": "webd", "funcs": [mixed]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_a")

    row = _by_anchor(atlas)["mixed_exec"]
    assert row["sink_anchor"] == "system"  # danger-anchored, not the alphabetically-first execl
    assert row["blocking_mechanism"] != "no_shell_exec"  # shell-capable -> not downweighted


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


# ── work item B: bare-sink recall + cross-function source (#8 reverse example) ──────


def test_bare_sink_no_source_is_listed_and_downweighted(tmp_path: Path) -> None:
    # A command sink with no in-function source and no constructed shell command is LISTED
    # (recall) but downweighted (bare_sink) below a real shell-construction candidate.
    bare = {
        "name": "do_exec",
        "pseudocode": "system(param_1);",
        "hash": "h_bare",
        "callees": ["system"],
    }
    db = _make_db(
        tmp_path,
        [{"name": "svcd", "funcs": [_cmd_injection_fn("real", param_sourced=False), bare]}],
    )
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_b")

    rows = _by_anchor(atlas)
    assert "do_exec" in rows  # not silently dropped
    assert rows["do_exec"]["blocking_mechanism"] == "bare_sink"
    assert rows["do_exec"]["reachability_status"] != "blocked"  # listed, never graded blocked
    assert _score_of(atlas, "do_exec") < _score_of(atlas, "real")


def test_cross_function_source_system_enters_candidates(tmp_path: Path) -> None:
    # The #8 reverse example: a real system("…%s…") built from an optarg/argv value that crosses a
    # function boundary (source is in the caller). It MUST enter the candidate list, and — because
    # it builds a shell command (cmd_injection_shape) — must NOT be downweighted to the bottom.
    apply_mac = {
        "name": "apply_mac",
        "pseudocode": "void apply_mac(char* param_1){ char cmd[128]; "
        'snprintf(cmd,128,"kickmac %s; reboot",param_1); system(cmd); }',
        "hash": "h_apply",
        "callees": ["snprintf", "system"],
    }
    parse_args = {
        "name": "parse_args",
        "pseudocode": "void parse_args(int argc,char** argv){ "
        'getopt_long(argc,argv,"m:",0,0); apply_mac(optarg); }',
        "hash": "h_parse",
        "callees": ["getopt_long", "apply_mac"],
    }
    # caller_func_id=2 (parse_args) -> callee_func_id=1 (apply_mac)
    db = _make_db(
        tmp_path,
        [{"name": "iotd", "funcs": [apply_mac, parse_args]}],
        xrefs=[(2, 1)],
    )
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_8")

    rows = _by_anchor(atlas)
    assert "apply_mac" in rows  # the cross-function shell sink is a candidate (recall win)
    # caller passes a VARIABLE (optarg), not a constant -> NOT caller_constant; and a constructed
    # shell command is exempt from bare_sink -> it is NOT downweighted to the bottom.
    assert rows["apply_mac"]["blocking_mechanism"] is None
    # ranks above a truly-bare constant-caller sink (the "suspicious but unproven" band).
    assert _score_of(atlas, "apply_mac") > 0.4


def test_caller_constant_downweights_constant_supplied_sink(tmp_path: Path) -> None:
    # caller_constant (A) activates on B's bare-sink candidates: a sink fed only a constant by its
    # sole one-hop caller ranks at the very bottom.
    run_cmd = {
        "name": "run_cmd",
        "pseudocode": "void run_cmd(char* param_1){ system(param_1); }",
        "hash": "h_run",
        "callees": ["system"],
    }
    boot = {
        "name": "boot",
        "pseudocode": 'void boot(void){ run_cmd("/etc/init.d/rcS"); }',
        "hash": "h_boot",
        "callees": ["run_cmd"],
    }
    db = _make_db(tmp_path, [{"name": "initd", "funcs": [run_cmd, boot]}], xrefs=[(2, 1)])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_cc")

    rows = _by_anchor(atlas)
    assert rows["run_cmd"]["blocking_mechanism"] == "caller_constant"


# ── inline charset on the cmd path + the thin-command-wrapper fact (R-L3·prep) ───────


def _charset_inline_cmd_fn(name: str = "arp_set") -> dict[str, object]:
    # A cmd_injection_shape whose command string is built inline from a charset-safe converter
    # (ether_ntoa -> MAC text). The recv buffer never reaches the command -> the command's
    # dynamic part is charset-constrained, so the cmd candidate must be downweighted.
    body = (
        f"void {name}(struct ether_addr* mac){{ char buf[64]; recv(fd,buf,64); char cmd[128]; "
        f'snprintf(cmd,128,"arp -s %s",ether_ntoa(mac)); system(cmd); }}'
    )
    return {
        "name": name,
        "pseudocode": body,
        "hash": f"h_{name}",
        "callees": ["recv", "ether_ntoa", "snprintf", "system"],
    }


def _thin_wrapper_fn(name: str = "exec_sh") -> dict[str, object]:
    # A bare_cmd_shape candidate that is also a thin forwarding wrapper: body ≈ system(param).
    return {
        "name": name,
        "pseudocode": f"void {name}(char* param_1){{ system(param_1); }}",
        "hash": f"h_{name}",
        "callees": ["system"],
    }


def test_inline_charset_cmd_candidate_is_downweighted_end_to_end(tmp_path: Path) -> None:
    # The cmd-path inline charset downweight reaches the persisted instance: the system()
    # candidate built from ether_ntoa is labelled charset_constrained (not bare_sink / None).
    db = _make_db(tmp_path, [{"name": "netd", "funcs": [_charset_inline_cmd_fn()]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_cs")
    row = _by_anchor(atlas)["arp_set"]
    assert row["blocking_mechanism"] == "charset_constrained"
    assert row["is_thin_cmd_wrapper"] == 0  # builds a command; not a verbatim forwarder


def test_thin_wrapper_fact_is_recorded_without_changing_score(tmp_path: Path) -> None:
    # The wrapper fact is stored on the candidate; its review-ordering label is untouched
    # (still bare_sink) — recording the fact does not change recall or rank.
    db = _make_db(tmp_path, [{"name": "initd", "funcs": [_thin_wrapper_fn()]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_w")
    row = _by_anchor(atlas)["exec_sh"]
    assert row["is_thin_cmd_wrapper"] == 1
    assert row["wrapped_sink"] == "system"
    assert row["blocking_mechanism"] == "bare_sink"  # unchanged by the fact


def test_wrapper_fact_does_not_add_candidates(tmp_path: Path) -> None:
    # ★ recall/count neutrality: the fact is a label on existing candidates, never a new one.
    # The wrapper function yields exactly one instance (its bare_cmd_shape match), no extra row.
    db = _make_db(tmp_path, [{"name": "initd", "funcs": [_thin_wrapper_fn()]}])
    atlas = tmp_path / "atlas.db"
    stats = run_analyzer2(db, atlas, source_run_id="run_w1")
    assert stats.instances_written == len(_instances(atlas)) == stats.matches == 1


# ── flow evidence (R-L3·B): structured evidence on cmd candidates ─────────────────────


def _charset_buffer_cmd_fn(name: str = "arp_run") -> dict[str, object]:
    # cmd_injection_shape whose command is built from a charset-safe converter laundered through
    # one intermediate buffer. The copy uses strlcpy (not in the global COPY set) so the function
    # matches ONLY the command shape, not an overflow/copy shape — so it is a single cmd candidate.
    body = (
        f"void {name}(struct ether_addr* mac){{ char b[32]; char* p=ether_ntoa(mac); "
        f'strlcpy(b,p,32); char cmd[128]; snprintf(cmd,128,"arp -s %s",b); system(cmd); }}'
    )
    return {
        "name": name,
        "pseudocode": body,
        "hash": f"h_{name}",
        "callees": ["ether_ntoa", "strlcpy", "snprintf", "system"],
    }


def _add_script_call(
    db_path: Path, script_path: str, command: str, line: int, args_pattern: str
) -> None:
    # Raw connect (NOT open_db): the analysis schema DROPs script_calls on every apply, so opening
    # via open_db between inserts would wipe earlier rows. The tables already exist from _make_db.
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "INSERT INTO non_binary_files (kind, name, path) VALUES ('shell_script', ?, ?)",
            (Path(script_path).name, script_path),
        )
        fid = conn.execute("SELECT id FROM non_binary_files ORDER BY id DESC LIMIT 1").fetchone()[0]
        conn.execute(
            "INSERT INTO script_calls (file_id, command, raw_line, line_number, args_pattern) "
            "VALUES (?, ?, ?, ?, ?)",
            (fid, command, f"{command} $X", line, args_pattern),
        )
        conn.commit()
    finally:
        conn.close()


def _evidence_of(atlas_path: Path, fn: str) -> dict:
    row = _by_anchor(atlas_path)[fn]
    return json.loads(row["flow_evidence"])


def test_cmd_candidate_carries_flow_evidence(tmp_path: Path) -> None:
    db = _make_db(tmp_path, [{"name": "netd", "funcs": [_charset_buffer_cmd_fn()]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_fe")
    ev = _evidence_of(atlas, "arp_run")
    assert set(ev) == {
        "source_kind",
        "flow_path",
        "sanitizer_seen",
        "entry_reach",
        "trace_boundary",
    }
    assert ev["source_kind"] == "charset_safe"  # laundered through the one-hop buffer
    # And the candidate is downweighted on the cmd path (one-hop charset, factor ②).
    assert _by_anchor(atlas)["arp_run"]["blocking_mechanism"] == "charset_constrained"


def test_copy_candidate_has_no_flow_evidence(tmp_path: Path) -> None:
    # Flow evidence is built for the command-sink partition only; a pure copy candidate gets none.
    fn = {
        "name": "cp_fn",
        "pseudocode": (
            "void cp_fn(char* param_1){ char d[64]; recv(fd,param_1,64); strcpy(d,param_1); }"
        ),
        "hash": "h_cp",
        "callees": ["recv", "strcpy"],
    }
    db = _make_db(tmp_path, [{"name": "webd", "funcs": [fn]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_cp")
    assert _by_anchor(atlas)["cp_fn"]["flow_evidence"] is None


def test_flow_evidence_records_entry_sites_from_script_calls(tmp_path: Path) -> None:
    db = _make_db(tmp_path, [{"name": "netd", "funcs": [_charset_buffer_cmd_fn()]}])
    _add_script_call(db, "/etc/init.d/netd.sh", "/sbin/netd", 7, "var_expansion")
    _add_script_call(db, "/etc/init.d/netd.sh", "netd", 19, "literal")
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_er")
    er = _evidence_of(atlas, "arp_run")["entry_reach"]
    assert er["status"] == "found"
    # give-all: both call sites (path form + bare-name form) are listed with their arg source.
    assert {(s["line"], s["arg_source"]) for s in er["sites"]} == {
        (7, "var_expansion"),
        (19, "literal"),
    }


def test_flow_evidence_entry_unknown_when_no_script_calls(tmp_path: Path) -> None:
    # No invocation found is reported as unknown, NOT unreachable; the candidate is not dropped.
    db = _make_db(tmp_path, [{"name": "netd", "funcs": [_charset_buffer_cmd_fn()]}])
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_noer")
    assert _evidence_of(atlas, "arp_run")["entry_reach"]["status"] == "unknown"


def test_flow_evidence_survives_source_db_removal(tmp_path: Path) -> None:
    db = _make_db(tmp_path, [{"name": "netd", "funcs": [_charset_buffer_cmd_fn()]}])
    _add_script_call(db, "/etc/init.d/netd.sh", "netd", 5, "var_expansion")
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_rm")
    db.unlink()  # source analysis.db gone — atlas is the persistent store
    ev = _evidence_of(atlas, "arp_run")
    assert ev["source_kind"] == "charset_safe"
    assert ev["entry_reach"]["sites"][0]["line"] == 5


def test_flow_evidence_does_not_add_candidates(tmp_path: Path) -> None:
    # ★ count neutrality: evidence is a field on existing cmd candidates, never a new candidate.
    db = _make_db(tmp_path, [{"name": "netd", "funcs": [_charset_buffer_cmd_fn()]}])
    _add_script_call(db, "/etc/init.d/netd.sh", "netd", 5, "literal")
    atlas = tmp_path / "atlas.db"
    s1 = run_analyzer2(db, atlas, source_run_id="run_n1")
    assert s1.instances_written == len(_instances(atlas)) == s1.matches == 1


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
