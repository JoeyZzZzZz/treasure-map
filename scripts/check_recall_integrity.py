#!/usr/bin/env python3
# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Recall-integrity gates — machine enforcement of the design red lines below (Gates A-D).

These invariants used to be docstring-only contracts, so their breaches surfaced only in a live
audit. This script turns them into a runnable gate (the same idea as check-vendor-neutrality.sh):
a violation is a non-zero exit, so CI fails red instead of trusting programmer discipline.

Gate A — never wrongly downweight (self-consistency):
    NO candidate may carry the ``const_sink_arg`` form note while its own sink argument is a
    ``free_string`` source. That combination is the whole-function-regex bug: a constant elsewhere
    in the function wrongly downweighting a tainted callsite. The downweight is parameter-specific
    and the analyzer reconciles the note against source_kind, so the count must be 0.

Gate B — degrade must be visible (no silent failure):
    NO binary may claim ``ghidra_status='ok'`` (functions were produced) yet hold 0 rows in the
    functions table. A partial/empty run must be recorded ``failed`` (retried) or, when genuinely
    code-free, ``ok_empty`` — never a functionless "ok" frozen as clean.

Gate C — old data must not pass as current (one authority on which runs exist):
    NO instance may name a source_run_id that has no row in ``run``. Such rows are a scan whose
    results outlived its lineage: no build hash, no scan status, no path back to the analysis they
    came from — yet they still count toward device spread and still list as candidates.

Gate D — the shape scan skips no function with callees (one authority on what was looked at):
    ``functions_with_callees + callee_parse_failed == functions_scanned``
    (``scanner.shape_scan_invariant_holds``). Every function the SQL pre-filter admitted either
    reached the detectors or is counted as a data gap. The pass used to skip whole binaries by
    name, and the only trace was a CLI counter — a recall decision taken at scan time, invisible
    to every reader of the result. The equation makes "was it looked at" answerable from the
    numbers instead of from the code.

Gate E — a provably-constant marker holds on the function it was read from (needs both databases):
    a ``const_sink_arg`` on a PATH sink means every call to that sink in the function passes a
    literal at every path argument (rename's destination as much as its source); on a shell sink,
    at least one call to it opens with a literal and splices no variable into it. A marker the
    function's own text contradicts was written by a reader that has since been fixed, or by one
    that is wrong now. Calls the text does not show (a stub-rendered ``FUN_<addr>(…)``) cannot be
    checked here: such instances are counted as unverifiable, never as violations.

Usage:
    check_recall_integrity.py --atlas ATLAS.db --analysis ANALYSIS.db   # check real databases
    check_recall_integrity.py --self-test                              # CI: synthetic clean+dirty

Exit code 0 when every checked invariant holds (count 0); 1 on any violation or a self-test miss.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import tempfile
from pathlib import Path

from treasure_map.lib.errors import ConfigError
from treasure_map.lib.pattern import scanner
from treasure_map.lib.pattern.models import PatternStats

# Gate A: const_sink_arg must never coexist with a free_string sink argument.
_GATE_A_SQL = (
    "SELECT COUNT(*) FROM instance "
    "WHERE blocking_mechanism = 'const_sink_arg' "
    "AND json_extract(flow_evidence, '$.source_kind') = 'free_string'"
)

# Gate B: a binary marked ghidra_status='ok' must hold at least one function row.
_GATE_B_SQL = (
    "SELECT COUNT(*) FROM binaries b "
    "WHERE b.ghidra_status = 'ok' "
    "AND NOT EXISTS (SELECT 1 FROM functions f WHERE f.binary_id = b.id)"
)


# Gate C: every candidate's run must be a registered run. An instance whose source_run_id has no
# row in `run` is a scan that left its results behind without its lineage — no build hash, no scan
# status, no path back to the analysis it came from. Those rows still feed device_spread (each
# unregistered label counts as another device) and still list as candidates, so they are read as
# findings from a firmware nobody can identify. The `run` table is the single authority on which
# runs exist; anything claiming a run it does not name is a leftover.
_GATE_C_SQL = (
    "SELECT COUNT(*) FROM instance WHERE source_run_id IS NOT NULL "
    "AND source_run_id NOT IN (SELECT run_id FROM run)"
)


def _count(db_path: Path, sql: str) -> int:
    """Run a COUNT(*) invariant query against a database opened read-only."""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        return int(conn.execute(sql).fetchone()[0])
    finally:
        conn.close()


def gate_a_violations(atlas_db: Path) -> int:
    """Count const_sink_arg candidates whose sink argument is a free_string source (must be 0)."""
    return _count(atlas_db, _GATE_A_SQL)


def gate_b_violations(analysis_db: Path) -> int:
    """Count binaries claiming ghidra_status='ok' with 0 functions (must be 0)."""
    return _count(analysis_db, _GATE_B_SQL)


def gate_c_violations(atlas_db: Path) -> int:
    """Count instances whose source_run_id names no registered run (must be 0).

    ★ This does not CLEAN anything, and it is not how the current leftovers get removed — a
    re-hunt of the run under its own name does that, writing the run row and replacing the
    instances in one pass. This exists for the two ways the problem comes back after that: a
    re-hunt under a DIFFERENT name (the rows under the old label have nothing to remove them), and
    a future "delete this run" that forgets to take its instances with it.

    Deliberately read-only, and deliberately not a write-side foreign key: the path that produced
    these rows — instances written before their run row — is already closed by the writer, which
    registers the run first. A constraint there would be risk spent on a route nothing takes."""
    return _count(atlas_db, _GATE_C_SQL)


def gate_d_violations(analysis_db: Path) -> int:
    """Count functions the shape scan admitted but neither scanned nor counted (must be 0).

    Re-derives the invariant by RUNNING the scan, so this measures what the code actually did
    rather than re-implementing the rule. ``scan`` raises when the invariant fails, which is the
    same finding — reported as one violation rather than by reading the exception's prose."""
    try:
        stats = scanner.scan(analysis_db).stats
    except ConfigError:
        return 1
    return stats.functions_scanned - stats.functions_with_callees - stats.callee_parse_failed


_GATE_E_SQL = (
    "SELECT i.evidence_ref, i.sink_anchor, p.sink_class FROM instance i "
    "JOIN pattern p ON p.pattern_id = i.pattern_id WHERE i.blocking_mechanism = 'const_sink_arg'"
)


def _function_text(analysis: sqlite3.Connection, evidence_ref: str) -> str | None:
    """The pseudocode of the function ``run#<sha8>:<entry>@…`` names, or None."""
    try:
        ident = evidence_ref.split("#", 1)[1].split("@", 1)[0]
        sha8, addr = ident.split(":", 1)
    except (IndexError, ValueError):
        return None
    row = analysis.execute(
        "SELECT f.pseudocode FROM functions f JOIN binaries b ON b.id = f.binary_id "
        "WHERE b.sha256 LIKE ? AND f.address = ? LIMIT 1",
        (sha8 + "%", addr),
    ).fetchone()
    return row[0] if row is not None and row[0] else None


def gate_e_violations(atlas_db: Path, analysis_db: Path) -> tuple[int, int]:
    """(violations, unverifiable) of Gate E over the instances whose function is in this
    analysis database."""
    from treasure_map.lib.hunt.downweight import _SHELL_RUN_SINKS, _sink_arg_is_literal
    from treasure_map.lib.pattern.classes import all_path_calls_literal, call_offsets

    atlas = sqlite3.connect(f"{atlas_db.resolve().as_uri()}?mode=ro", uri=True)
    analysis = sqlite3.connect(f"{analysis_db.resolve().as_uri()}?mode=ro", uri=True)
    violations = unverifiable = 0
    try:
        for ref, sink, sink_class in atlas.execute(_GATE_E_SQL).fetchall():
            text = _function_text(analysis, ref)
            if text is None:
                continue  # another run's function, or one this database does not hold
            n = len(call_offsets(text, sink)) if sink else 0
            if n == 0:
                unverifiable += 1
            elif sink_class == "path_sink":
                violations += not all_path_calls_literal(text, sink)
            elif sink in _SHELL_RUN_SINKS:
                violations += not any(
                    _sink_arg_is_literal(text, sink, None, None, k) for k in range(n)
                )
    finally:
        atlas.close()
        analysis.close()
    return violations, unverifiable


def _check_real(atlas_db: Path | None, analysis_db: Path | None) -> int:
    fail = 0
    if atlas_db is not None:
        n = gate_a_violations(atlas_db)
        if n:
            print(f"❌ Gate A: {n} const_sink_arg candidate(s) with a free_string sink argument")
            fail = 1
        else:
            print("✓ Gate A: no const_sink_arg / free_string contradiction")
        n = gate_c_violations(atlas_db)
        if n:
            print(f"❌ Gate C: {n} instance(s) whose source_run_id names no registered run")
            fail = 1
        else:
            print("✓ Gate C: every instance names a registered run")
    if analysis_db is not None:
        n = gate_b_violations(analysis_db)
        if n:
            print(f"❌ Gate B: {n} binary(ies) marked ghidra_status='ok' with 0 functions")
            fail = 1
        else:
            print("✓ Gate B: every ghidra_status='ok' binary has functions")
        n = gate_d_violations(analysis_db)
        if n:
            print(f"❌ Gate D: {n} function(s) with callees skipped by the shape scan")
            fail = 1
        else:
            print("✓ Gate D: every function with callees was scanned or counted as a parse failure")
    if atlas_db is not None and analysis_db is not None:
        n, unread = gate_e_violations(atlas_db, analysis_db)
        if n:
            print(f"❌ Gate E: {n} const_sink_arg marker(s) the function's own text contradicts")
            fail = 1
        else:
            print(f"✓ Gate E: every checkable const_sink_arg holds ({unread} unverifiable)")
    return fail


def _build_self_test_dbs(root: Path, *, violating: bool) -> tuple[Path, Path]:
    """Build a synthetic (atlas, analysis) pair — clean, or seeded with one Gate-A + one Gate-B
    violation — using the REAL schema so the check runs against production table shapes."""
    from treasure_map.lib.atlas.connection import open_atlas
    from treasure_map.lib.atlas.models import InstanceRow
    from treasure_map.lib.atlas.writer import add_instance, begin_run, upsert_pattern
    from treasure_map.lib.storage.connection import open_db

    analysis = root / f"analysis_{'bad' if violating else 'ok'}.db"
    conn = open_db(analysis)
    # A healthy 'ok' binary always has a function.
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256, ghidra_status, last_seen_at) "
        "VALUES (1, 'good', 'bin/good', 'g', 'ok', '2026-01-01')"
    )
    conn.execute("INSERT INTO functions (binary_id, name) VALUES (1, 'main')")
    # Gate E: the function a path-sink const_sink_arg was read from — rename's destination a
    # literal (clean) or the caller's parameter (violating).
    destination = "param_1" if violating else '"/tmp/b"'
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256, ghidra_status, last_seen_at) "
        "VALUES (3, 'mover', 'bin/mover', ?, 'ok', '2026-01-01')",
        ("c" * 64,),
    )
    conn.execute(
        "INSERT INTO functions (binary_id, name, address, pseudocode) VALUES "
        "(3, 'FUN_00001000', '00001000', ?)",
        (f'void FUN_00001000(char *param_1){{ rename("/tmp/a", {destination}); }}',),
    )
    if violating:
        # Gate B violation: 'ok' but no functions.
        conn.execute(
            "INSERT INTO binaries (id, name, path, sha256, ghidra_status, last_seen_at) "
            "VALUES (2, 'bad', 'bin/bad', 'b', 'ok', '2026-01-01')"
        )
    conn.commit()
    conn.close()

    atlas = root / f"atlas_{'bad' if violating else 'ok'}.db"
    aconn = open_atlas(atlas)
    if not violating:
        # Register the run the instances below name. The clean fixture has to do this or it fails
        # Gate C itself — which is the gate doing its job: a scan that writes candidates without
        # registering its run is exactly the leftover state being guarded against. The violating
        # fixture skips it, and that omission IS its Gate C violation.
        begin_run(aconn, "run_selftest", analysis_db_path=str(analysis))
    pid = upsert_pattern(
        aconn,
        source_class="external_input",
        sink_class="cmd",
        call_sequence_shape="source->cmd",
        structural_fingerprint="fp_selftest",
        fingerprint_algo_version="callseq-v1",
    )
    path_pid = upsert_pattern(
        aconn,
        source_class="unknown",
        sink_class="path_sink",
        call_sequence_shape="path_sink",
        structural_fingerprint="fp_selftest_path",
        fingerprint_algo_version="callseq-v1",
    )
    add_instance(
        aconn,
        InstanceRow(
            pattern_id=path_pid,
            pseudocode_hash="h_path",
            source_anchor="FUN_00001000",
            sink_anchor="rename",
            source_run_id="run_selftest",
            reachability_status="unknown",
            blocking_mechanism="const_sink_arg",
            provenance_level="L0",
            evidence_ref="run_selftest#cccccccc:00001000@path_sink@0x000010",
            scope_origin="intra",
            origin="unknown",
            binary_path="bin/mover",
        ),
    )
    # A clean instance: const_sink_arg with a non-free source_kind is allowed.
    add_instance(
        aconn,
        InstanceRow(
            pattern_id=pid,
            pseudocode_hash="h_ok",
            source_anchor="fn_ok",
            sink_anchor="system",
            source_run_id="run_selftest",
            reachability_status="unknown",
            blocking_mechanism="const_sink_arg",
            provenance_level="L0",
            evidence_ref="run#fn1@cmd",
            scope_origin="intra",
            origin="custom",
            binary_path="bin/good",
            flow_evidence=json.dumps({"source_kind": "unknown"}),
        ),
    )
    if violating:
        # Gate A violation: const_sink_arg on a free_string candidate.
        add_instance(
            aconn,
            InstanceRow(
                pattern_id=pid,
                pseudocode_hash="h_bad",
                source_anchor="fn_bad",
                sink_anchor="system",
                source_run_id="run_selftest",
                reachability_status="unknown",
                blocking_mechanism="const_sink_arg",
                provenance_level="L0",
                evidence_ref="run#fn2@cmd",
                scope_origin="intra",
                origin="custom",
                binary_path="bin/good",
                flow_evidence=json.dumps({"source_kind": "free_string"}),
            ),
        )
    aconn.close()
    return atlas, analysis


def _self_test() -> int:
    """Prove the gates distinguish a clean workspace from a seeded-violation one.

    A true machine gate: it fails if the checker stops catching either violation, or if a clean
    workspace is falsely flagged."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        clean_atlas, clean_analysis = _build_self_test_dbs(root, violating=False)
        bad_atlas, bad_analysis = _build_self_test_dbs(root, violating=True)

        checks = {
            "clean Gate A == 0": gate_a_violations(clean_atlas) == 0,
            "clean Gate B == 0": gate_b_violations(clean_analysis) == 0,
            "clean Gate C == 0": gate_c_violations(clean_atlas) == 0,
            "violating Gate A > 0": gate_a_violations(bad_atlas) > 0,
            "violating Gate B > 0": gate_b_violations(bad_analysis) > 0,
            "violating Gate C > 0": gate_c_violations(bad_atlas) > 0,
            "clean Gate E == 0": gate_e_violations(clean_atlas, clean_analysis)[0] == 0,
            "violating Gate E > 0": gate_e_violations(bad_atlas, bad_analysis)[0] > 0,
            # Gate D is a pure arithmetic property of the stats, so it is exercised as one: a
            # partition that adds up, and one that does not. Stubbing the scan body to fake a
            # skip would test the stub. The real scan is what `--analysis` checks.
            "clean Gate D holds": scanner.shape_scan_invariant_holds(
                PatternStats(
                    functions_scanned=3,
                    functions_with_callees=1,
                    callee_parse_failed=2,
                    pattern_a=0,
                    pattern_b=0,
                )
            ),
            "violating Gate D fails": not scanner.shape_scan_invariant_holds(
                PatternStats(
                    functions_scanned=3,
                    functions_with_callees=1,
                    callee_parse_failed=0,
                    pattern_a=0,
                    pattern_b=0,
                )
            ),
        }
    ok = True
    for name, passed in checks.items():
        print(f"{'✓' if passed else '❌'} self-test: {name}")
        ok = ok and passed
    if ok:
        print("✓ recall-integrity self-test: gates catch violations and pass a clean workspace")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--atlas", type=Path, default=None, help="atlas.db to check (Gate A).")
    parser.add_argument(
        "--analysis", type=Path, default=None, help="analysis.db to check (Gate B)."
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Build synthetic clean + violating databases and assert the gates catch them (CI).",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test()
    if args.atlas is None and args.analysis is None:
        parser.error("provide --atlas and/or --analysis, or --self-test")
    return _check_real(args.atlas, args.analysis)


if __name__ == "__main__":
    sys.exit(main())
