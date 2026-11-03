# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""What an extraction gets back that a busy session lost, and what it no longer makes up.

* An analyzer that threw during Ghidra's analysis (the analysis goes on without it, exit code 0):
  recognised from this attempt's log, recorded as the extracted row's blind spot, and the binary
  re-run once in an isolated session — the better of the two extractions kept, whole.
* The pointer recovery (W14) refuses seeds above the code Ghidra's own analysis made into
  functions, and seeds whose bytes read as a C string — before anything is disassembled.
* Decompiles left unfinished: the retries run until a deadline the session's wall clock leaves, a
  binary still holding a large unfinished one is re-run isolated (with a larger output limit when
  its output passed the limit), and an isolated re-run that still left them is remembered so the
  next scan under the same pass, Ghidra and budget does not buy it again.

Zero real data: a fake analyzeHeadless or a fake ``run_ghidra`` writing what the scripts would, and
the two Ghidra scripts read as text. The Ghidra behaviour itself is checked on real binaries
outside the unit tests.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from tests.unit.lib.test_ghidra_runner import _good_json, _make_runner, _write_small_elf
from tests.unit.lib.test_pipeline import _NAMES, _e2e_cfg, _firmware, _ghidra
from tests.unit.lib.test_scan_export import _report, _with_extension
from treasure_map.lib.analyze import ghidra_ingest, ghidra_runner
from treasure_map.lib.analyze.db_ingest import decompile_rerun_record, decompile_rerun_skips
from treasure_map.lib.analyze.elf_inventory import ElfRecord
from treasure_map.lib.analyze.ghidra_ingest import ingest_ghidra_output
from treasure_map.lib.analyze.ghidra_runner import (
    GhidraResult,
    GhidraRunner,
    _analyzer_exception,
    _decompile_counts,
    export_paths,
    retry_budget_seconds,
)
from treasure_map.lib.analyze.pipeline import AnalyzeResult, run_analyze
from treasure_map.lib.analyze.stub_resolve import resolve_stubs, stub_table_marker
from treasure_map.lib.storage.connection import open_db
from treasure_map.lib.workspace.workspace import Workspace

MODULE = "treasure_map.lib.analyze.ghidra_runner"
_GHIDRA_DIR = Path(ghidra_ingest.__file__).parent / "ghidra"

# The shape of the line Ghidra logs for an analyzer that threw (synthetic messages).
_MIPS_LINE = (
    "2026-01-01 00:00:00 ERROR (MipsAddressAnalyzer) caught exception "
    "java.util.concurrent.ExecutionException: ghidra.util.exception.AssertException: "
    "Unexpected Exception\n"
)
_ARM_LINE = (
    "2026-01-01 00:00:01 ERROR (ArmAnalyzer) caught exception "
    "java.util.concurrent.ExecutionException: java.lang.NullPointerException: Cannot invoke "
    '"a.b.C.d(a.b.E)" because "value" is null\n'
)


# ── F-1: recognising an analyzer that threw ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("log", "expected"),
    [
        (_MIPS_LINE, "analyzer_exception:MipsAddressAnalyzer:AssertException"),
        (_ARM_LINE, "analyzer_exception:ArmAnalyzer:NullPointerException"),
        # several distinct ones: the first, and how many others
        (
            _MIPS_LINE + _ARM_LINE + _MIPS_LINE,
            "analyzer_exception:MipsAddressAnalyzer:AssertException(+1)",
        ),
        # a script's exception (no analyzer in parentheses) is not an analyzer's
        ("ERROR ExportBinExport.java> java.lang.IllegalStateException: x\n", None),
        ("INFO  REPORT: Analysis succeeded\n", None),
        # no class in the chain at all
        ("ERROR (SomeAnalyzer) caught exception oops\n", "analyzer_exception:SomeAnalyzer:unknown"),
        # the concurrency wrapper alone names no class of the analyzer's own
        (
            "ERROR (SomeAnalyzer) caught exception java.util.concurrent.ExecutionException: boom\n",
            "analyzer_exception:SomeAnalyzer:unknown",
        ),
        # the innermost of two: the last class the chain names
        (
            "ERROR (SomeAnalyzer) caught exception java.lang.RuntimeException: "
            "java.lang.IllegalStateException: x\n",
            "analyzer_exception:SomeAnalyzer:IllegalStateException",
        ),
    ],
)
def test_the_analyzer_exception_is_read_from_the_log(
    tmp_path: Path, log: str, expected: str | None
) -> None:
    """★ The analyzer and the innermost exception class of the chain (the concurrency wrapper left
    out); several distinct ones name the first with (+N).

    MUTATION (verified RED): keep ExecutionException as the class -> RED; take the first class
    of the chain instead of the last -> RED; drop the (+N) suffix -> RED."""
    p = tmp_path / "x.log"
    p.write_text(log)
    assert _analyzer_exception(p, 0) == expected


def test_only_this_attempts_part_of_the_log_counts(tmp_path: Path) -> None:
    """``-log`` appends: an earlier attempt's exception, before this attempt's offset, says
    nothing about this attempt.

    MUTATION (verified RED): read the log from 0 -> RED."""
    p = tmp_path / "x.log"
    p.write_text(_MIPS_LINE)
    offset = p.stat().st_size
    with p.open("a") as f:
        f.write("INFO  REPORT: Analysis succeeded\n")
    assert _analyzer_exception(p, offset) is None


def _once(
    tmp_path: Path,
    *,
    log: str = "",
    rc: int = 0,
    counts: tuple[int, int, int] | None = None,
    timeout: int = 100,
    large_payload: bool = False,
    extension: bool = False,
) -> tuple[GhidraResult, dict[str, Any]]:
    """One session over a fake analyzeHeadless that writes a finished extraction and ``log``;
    ``counts`` (timeouts, large, payload) puts a decompile_counts head on the JSON."""
    out_dir = tmp_path / "output"
    out_dir.mkdir(parents=True, exist_ok=True)
    binary = tmp_path / "httpd"
    _write_small_elf(binary)
    seen: dict[str, Any] = {}

    def fake_sub(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        seen.update(env=dict(env), timeout=timeout)
        d = Path(env["OUTPUT_DIR"])
        body = _good_json(env)
        if counts is not None:
            t, lg, pl = counts
            head = (
                f'{{"decompile_counts":{{"timeouts":{t},"timeouts_large":{lg},'
                f'"payload_exceeded":{pl}}},'
            )
            body = head + body[1:]
        (d / f"httpd_{env['SHA8']}_ghidra.json").write_text(body)
        with (d / f"httpd_{env['SHA8']}.log").open("a") as f:
            f.write(log)
        return rc, ""

    runner = _make_runner(tmp_path)
    if extension:
        from tests.unit.lib.test_scan_export import _EXT

        runner.set_extension(_EXT)
    with patch(f"{MODULE}._run_subprocess", fake_sub):
        result = runner.run_ghidra(
            binary,
            out_dir,
            timeout=timeout,
            arch="x86:LE:64:default",
            sha8="deadbeef",
            retry=False,
            large_payload=large_payload,
        )
    return result, seen


@pytest.mark.parametrize("rc", [0, -1])
def test_a_finished_session_records_the_analyzer_that_threw(tmp_path: Path, rc: int) -> None:
    """★ Both ways a session ends in a finished extraction (exit 0, and killed at its wall clock
    after the extraction was written): still a success with its functions, and the blind spot is
    named — apart from ``reason``, which only a failure has.

    MUTATION (verified RED): read the log only on the rc == 0 path -> the rc = -1 case -> RED;
    put it in ``reason`` -> RED."""
    result, _ = _once(tmp_path, log=_MIPS_LINE, rc=rc)
    assert result.success is True and result.function_count == 1
    assert result.reason is None
    assert result.degrade_reason == "analyzer_exception:MipsAddressAnalyzer:AssertException"


def test_an_earlier_attempts_exception_does_not_mark_this_one(tmp_path: Path) -> None:
    """The session reads its own part of the appended log: a clean attempt after one that
    threw has no blind spot.

    MUTATION (verified RED): read the session's log from 0 -> RED."""
    first, _ = _once(tmp_path, log=_MIPS_LINE)
    assert first.degrade_reason is not None
    second, _ = _once(tmp_path, log="INFO  REPORT: Analysis succeeded\n")
    assert second.success is True and second.degrade_reason is None


def test_a_clean_session_has_no_degrade_reason(tmp_path: Path) -> None:
    result, _ = _once(tmp_path, log="INFO  REPORT: Analysis succeeded\n")
    assert result.success is True and result.degrade_reason is None


def _ingest_one(tmp_path: Path, stamp: tuple[str, str, str | None]) -> dict[str, Any]:
    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)
    rec = ElfRecord(path=tmp_path / "x", name="x", arch="a", elf_type="executable", sha256="a" * 64)
    (out / f"x_{rec.sha256[:8]}_ghidra.json").write_text(
        json.dumps({"functions": [{"name": "f", "address": "0x1000", "size": 64}]})
    )
    conn = open_db(tmp_path / "analysis.db")
    conn.execute("INSERT INTO binaries (id, name, sha256) VALUES (1, 'x', ?)", (rec.sha256,))
    ingest_ghidra_output(conn, out, [rec], {rec.sha256: 1}, success_stamp={rec.sha256: stamp})
    row = dict(
        conn.execute(
            "SELECT ghidra_ok, ghidra_status, ghidra_status_reason FROM binaries WHERE id = 1"
        ).fetchone()
    )
    row["functions"] = conn.execute("SELECT COUNT(*) FROM functions").fetchone()[0]
    conn.close()
    return row


def test_the_success_stamp_writes_the_blind_spot_on_the_extracted_row(tmp_path: Path) -> None:
    """★ ghidra_ok stays 1, the functions are stored, and ghidra_status_reason carries the blind
    spot; a clean extraction writes NULL there.

    MUTATION (verified RED): keep writing NULL as the success reason -> RED."""
    got = _ingest_one(tmp_path / "a", ("ok", "11.4.3", "analyzer_exception:A:B"))
    assert got == {
        "ghidra_ok": 1,
        "ghidra_status": "ok",
        "ghidra_status_reason": "analyzer_exception:A:B",
        "functions": 1,
    }
    assert _ingest_one(tmp_path / "b", ("ok", "11.4.3", None))["ghidra_status_reason"] is None


# ── phase 2: a fake run_ghidra per binary ────────────────────────────────────────────────────


class _Plan:
    """A fake run_ghidra: per binary, one outcome per call. An outcome is a dict with any of
    ``fail`` (a failed extraction), ``threw`` (degrade reason), ``functions``, ``large`` and
    ``payload`` (unfinished decompiles) and ``export`` ("ok" or a failed status)."""

    def __init__(self, plan: dict[str, list[dict[str, Any]]]) -> None:
        self.plan = {k: list(v) for k, v in plan.items()}
        self.calls: list[tuple[str, int, bool]] = []

    def __call__(
        self,
        runner: Any,
        binary: Path,
        output_dir: Path,
        timeout: int,
        arch: str,
        sha8: str = "",
        retry: bool = True,
        large_payload: bool = False,
    ) -> GhidraResult:
        self.calls.append((binary.name, timeout, large_payload))
        o = self.plan[binary.name].pop(0)
        if o.get("fail"):
            return GhidraResult(
                binary=binary,
                output_file=None,
                success=False,
                elapsed=0.0,
                reason="timeout",
                timeout_budget=timeout,
                export_status="scan_failed:timeout",
            )
        n = int(o.get("functions", 1))
        stubs = resolve_stubs(binary)
        data = {
            "pass_version": runner.pass_version(),
            "sha8": sha8,
            "stub_marker": stub_table_marker(None if stubs is None else stubs.names),
            "functions": [
                {"name": f"f{j}", "address": f"0010{j:04x}", "size": 64, "callees": []}
                for j in range(n)
            ],
            "imports": [],
            "exports": [],
            "strings": [],
        }
        out = output_dir / f"{binary.name}_{sha8}_ghidra.json"
        out.write_text(json.dumps(data))
        export = o.get("export", "extension_missing")
        exp, rep = export_paths(output_dir, binary, sha8)
        usable = export == "ok"
        if usable:
            exp.write_bytes(b"export of " + binary.name.encode() + str(len(self.calls)).encode())
            rep.write_text(json.dumps(_report()))
        return GhidraResult(
            binary=binary,
            output_file=out,
            success=True,
            elapsed=0.0,
            analysis_status="ok",
            function_count=n,
            degrade_reason=o.get("threw"),
            decompile_large_timeouts=o.get("large", 0),
            decompile_payload_exceeded=o.get("payload", 0),
            timeout_budget=timeout,
            export_status=export,
            export_budget=timeout,
            export_file=exp if usable else None,
            export_report_file=rep if usable else None,
            export_report=_report() if usable else None,
        )


def _recs(tmp_path: Path, names: tuple[str, ...]) -> list[ElfRecord]:
    out = []
    for i, n in enumerate(names):
        p = tmp_path / n
        _write_small_elf(p)
        out.append(ElfRecord(path=p, name=n, arch="x", elf_type="executable", sha256=f"{i}" * 64))
    return out


def _run_all(
    tmp_path: Path, plan: _Plan, names: tuple[str, ...], settled: set[str] | None = None
) -> tuple[list[GhidraResult], list[GhidraResult], list[GhidraResult], GhidraRunner]:
    recs = _recs(tmp_path, names)
    finals: list[GhidraResult] = []
    exports: list[GhidraResult] = []
    runner = _make_runner(tmp_path)
    with patch.object(GhidraRunner, "run_ghidra", lambda self, *a, **k: plan(self, *a, **k)):
        with patch.object(ghidra_runner, "validate_registry", lambda p: None):
            results = runner.run_all(
                recs,
                tmp_path / "out",
                on_final=lambda r, x: finals.append(x),
                on_export=lambda r, x: exports.append(x),
                decompile_settled=settled,
            )
    return results, finals, exports, runner


_THREW = "analyzer_exception:MipsAddressAnalyzer:AssertException"


def test_an_extraction_during_which_an_analyzer_threw_is_rerun_isolated(tmp_path: Path) -> None:
    """★ Phase 1 finished while an analyzer threw (it lost functions): the extraction is final at
    once, the binary runs once more in phase 2, and the clean re-run is settled whole in its place
    (no blind spot, its function count). A clean binary next to it is not re-run.

    MUTATION (verified RED): leave degraded successes out of the phase-2 list -> one call -> RED;
    settle on phase 1 regardless -> RED."""
    plan = _Plan(
        {
            "svc_a": [{"threw": _THREW, "functions": 5}, {"functions": 9}],
            "svc_b": [{"functions": 12}],
        }
    )
    _res, finals, exports, _r = _run_all(tmp_path, plan, ("svc_a", "svc_b"))
    assert [c[0] for c in plan.calls].count("svc_a") == 2
    assert [c[0] for c in plan.calls].count("svc_b") == 1
    assert {f.binary.name for f in finals} == {"svc_a", "svc_b"}
    (settled,) = exports
    assert settled.export_only is False
    assert (settled.degrade_reason, settled.function_count) == (None, 9)


@pytest.mark.parametrize(
    ("first_n", "rerun_n", "kept"),
    [(5, 7, "rerun"), (7, 5, "first")],
)
def test_two_extractions_during_which_an_analyzer_threw_keep_the_one_with_more_functions(
    tmp_path: Path, first_n: int, rerun_n: int, kept: str
) -> None:
    """★ The re-run threw too: the extraction with more functions is kept, with its blind spot
    (the label is the fallback). Phase 1's kept = it stands (export_only, nothing replaced).

    MUTATION (verified RED): always keep the re-run -> the second case -> RED."""
    plan = _Plan(
        {
            "svc_a": [
                {"threw": _THREW, "functions": first_n},
                {"threw": _THREW, "functions": rerun_n},
            ]
        }
    )
    _res, _f, exports, _r = _run_all(tmp_path, plan, ("svc_a",))
    (settled,) = exports
    assert settled.degrade_reason == _THREW
    if kept == "rerun":
        assert (settled.export_only, settled.function_count) == (False, rerun_n)
    else:
        assert (settled.export_only, settled.function_count) == (True, first_n)


# ── the session is kept whole: an export only with the extraction of its own session ─────────


def _ok(**kw: Any) -> GhidraResult:
    base: dict[str, Any] = {
        "binary": Path("b"),
        "output_file": Path("b.json"),
        "success": True,
        "elapsed": 0.0,
        "analysis_status": "ok",
        "function_count": 10,
        "decompile_large_timeouts": 0,
        "decompile_payload_exceeded": 0,
        "export_status": "ok",
        "export_budget": 300,
    }
    base.update(kw)
    return GhidraResult(**base)


@pytest.mark.parametrize(
    ("first", "rerun", "expect"),
    [
        # the re-run's extraction is better: kept whole, its failed export with it
        (
            {"degrade_reason": _THREW},
            {"export_status": "failed:timeout", "export_budget": 600},
            ("rerun", False, "failed:timeout", 600),
        ),
        # phase 1's is better: it stands with its own usable export; the re-run's is dropped
        (
            {},
            {"degrade_reason": _THREW, "export_status": "ok", "export_budget": 600},
            ("first", True, "ok", 300),
        ),
        # phase 1's is better and both exports failed: the larger budget it failed at is recorded
        (
            {"export_status": "failed:timeout"},
            {"degrade_reason": _THREW, "export_status": "failed:timeout", "export_budget": 600},
            ("first", True, "failed:timeout", 600),
        ),
        # phase 1's is better, its export failed, the re-run's usable: not taken over
        (
            {"export_status": "failed:timeout"},
            {"decompile_large_timeouts": 2, "export_status": "ok", "export_budget": 600},
            ("first", True, "failed:timeout", 300),
        ),
        # neither better, phase 1's export failed: as an export re-run (whole when it exported)
        (
            {"export_status": "failed:timeout"},
            {"export_status": "ok", "export_budget": 600},
            ("rerun", False, "ok", 600),
        ),
        # the re-run failed: phase 1 stands
        (
            {"degrade_reason": _THREW},
            {"success": False, "analysis_status": "failed", "export_status": "scan_failed:x"},
            ("first", True, "ok", 300),
        ),
        # fewer decompiles left unfinished is the better extraction
        (
            {"decompile_large_timeouts": 5},
            {"decompile_large_timeouts": 1, "export_status": "ok", "export_budget": 600},
            ("rerun", False, "ok", 600),
        ),
    ],
)
def test_the_settled_session_is_whole(
    first: dict[str, Any], rerun: dict[str, Any], expect: tuple[str, bool, str, int]
) -> None:
    """★ Whichever extraction is kept brings its own session's export (or failed export) — never
    the other session's export file. A failed export of the kept re-run is left for the next
    scan's export check.

    MUTATION (verified RED): take the re-run's usable export onto phase 1's extraction -> the
    fourth case -> RED; keep phase 1 on a tie whatever its export -> the fifth -> RED."""
    a = _ok(**first)
    b = _ok(function_count=11, **rerun)
    got = GhidraRunner._settle_rerun(a, b)
    which, export_only, status, budget = expect
    assert got.function_count == (11 if which == "rerun" else 10)
    assert (got.export_only, got.export_status, got.export_budget) == (export_only, status, budget)
    # phase 1 kept whole, export outcome included: nothing of it is to be written again
    assert got.stored_stands == (which == "first" and (status, budget) == (a.export_status, 300))


# ── F-2: the two seeds W14 refuses, read in the script ───────────────────────────────────────


def _code(path: Path) -> str:
    return "\n".join(re.sub(r"//.*$", "", line) for line in path.read_text().splitlines())


def test_the_native_ceiling_is_taken_before_the_script_creates_anything() -> None:
    """★ The ceiling is the top of the functions Ghidra's own analysis made — read before the first
    block promotion (which would raise it with functions this script made), never from the entry
    set taken after it.

    MUTATION (verified RED): take it after promoteBlocks -> RED; count external functions -> RED;
    count bodies outside executable memory (the EXTERNAL block's thunks) -> RED."""
    code = _code(_GHIDRA_DIR / "PromoteUndefined.java")
    run = code[code.index("protected void run()") :]
    assert "nativeCeiling = maxFunctionBodyEnd()" in run
    assert run.index("nativeCeiling = maxFunctionBodyEnd()") < run.index("promoteBlocks()")
    assert "recoverFromPointers(exec, data, nativeCeiling, rec)" in run
    body = code[code.index("private Address maxFunctionBodyEnd()") :]
    body = body[: body.index("\n  }\n")]
    assert "funcsBefore" not in body and "isExternal()" in body
    # the import thunks the ELF loader puts in its EXTERNAL block past the image do not count
    assert "block.isExternalBlock() || !block.isExecute()" in body


def test_seeds_above_the_ceiling_or_reading_as_a_c_string_are_refused_before_disassembly() -> None:
    """★ Both refusals sit before any disassembly of the seed; no ceiling (no function at all)
    refuses every seed instead of comparing against null; the C-string probe is >= 4 printable
    bytes then NUL within 64 bytes; the count is exported.

    MUTATION (verified RED): drop the null check -> RED; move the string check after the
    disassembly -> RED; drop the recover_rejected_string option -> RED."""
    code = _code(_GHIDRA_DIR / "PromoteUndefined.java")
    rec = code[code.index("private boolean recoverFromPointers(") :]
    rec = rec[: rec.index("private int errorsIn(")]
    ceiling = "nativeCeiling == null || a.compareTo(nativeCeiling) > 0"
    string = "looksLikeCString(mem, a)"
    assert ceiling in rec and string in rec
    disasm = rec.index("new ArmDisassembleCommand")
    assert rec.index(ceiling) < disasm
    assert rec.index(string) < disasm
    assert "STRING_PROBE_BYTES = 64" in code and "STRING_MIN_PRINTABLE = 4" in code
    probe = code[code.index("private static boolean looksLikeCString(") :]
    probe = probe[: probe.index("\n  }\n")]
    assert "run >= STRING_MIN_PRINTABLE && run < n && b[run] == 0" in probe
    assert 'opts.setInt("recover_rejected_string"' in code


def test_the_extractor_writes_the_refused_string_count_into_the_promote_record() -> None:
    """The count travels PromoteUndefined options -> ExportFunctions' promote object (whose
    all-or-nothing check includes it) -> the ingest.

    MUTATION (verified RED): leave it out of promoteRecord's JSON -> RED."""
    code = _code(_GHIDRA_DIR / "ExportFunctions.java")
    rec = code[code.index("private String promoteRecord()") :]
    rec = rec[: rec.index("private String originField(")]
    assert 'opts.getInt("recover_rejected_string", -1)' in rec
    assert "recoverRejectedString < 0" in rec
    assert '",\\"recover_rejected_string\\":" + recoverRejectedString' in rec


# ── F-3: the decompile retries, the counts and the isolated re-run ───────────────────────────


def test_the_decompile_counts_are_read_from_the_head_of_the_output(tmp_path: Path) -> None:
    """★ Read from the head the extractor writes first — and only there: the same object anywhere
    else in the file is not this output's count.

    MUTATION (verified RED): search instead of match -> the nested object reads (7, 0) -> RED."""
    a = tmp_path / "a.json"
    a.write_text(
        '{"decompile_counts":{"timeouts":3,"timeouts_large":2,"payload_exceeded":1},"x":1}'
    )
    assert _decompile_counts(a) == (2, 1)
    b = tmp_path / "b.json"
    # the same object, but not the head: nested under another key
    b.write_text(
        '{"other":{"decompile_counts":{"timeouts":7,"timeouts_large":7,"payload_exceeded":0}}}'
    )
    assert _decompile_counts(b) == (None, None)
    assert _decompile_counts(tmp_path / "missing.json") == (None, None)


def test_a_finished_session_carries_its_decompile_counts(tmp_path: Path) -> None:
    result, _ = _once(tmp_path, counts=(4, 2, 1))
    assert (result.decompile_large_timeouts, result.decompile_payload_exceeded) == (2, 1)
    assert ghidra_runner.unfinished_decompiles(result) == 3


@pytest.mark.parametrize("extension", [True, False])
def test_the_retries_run_until_a_deadline_the_wall_clock_leaves(
    tmp_path: Path, extension: bool
) -> None:
    """★ The deadline is the session's start + its wall clock, less half the export's budget and
    the margin; the fixed budget is still handed in (the extractor never retries for less).

    MUTATION (verified RED): leave the deadline out of the environment -> RED; reserve the whole
    export budget -> RED."""
    with patch(f"{MODULE}.time.time", return_value=1000.0):
        _res, seen = _once(tmp_path, timeout=100, extension=extension)
    env = seen["env"]
    wall = 100 + 60 + (100 if extension else 0)
    assert seen["timeout"] == wall
    reserve = 50 if extension else 0
    assert env.get("TMAP_DECOMPILE_DEADLINE_MS") == str((1000 + wall - reserve - 60) * 1000)
    assert env["TMAP_DECOMPILE_RETRY_BUDGET_S"] == ("50" if extension else "30")


def _xmx(mb: int) -> str:
    """The JVM heap flag for ``mb`` megabytes."""
    return f"-Xmx{mb}m"


def test_a_large_payload_rerun_raises_the_output_limit_and_the_heap(tmp_path: Path) -> None:
    """★ Only a re-run asked for it gets the larger output limit, and a heap that holds it.

    MUTATION (verified RED): never set TMAP_DECOMPILE_PAYLOAD_MB -> RED; keep the size-scaled
    heap -> RED."""
    _r, plain = _once(tmp_path / "a")
    assert "TMAP_DECOMPILE_PAYLOAD_MB" not in plain["env"]
    assert _xmx(512) in plain["env"]["JAVA_TOOL_OPTIONS"]
    _r, big = _once(tmp_path / "b", large_payload=True)
    assert big["env"].get("TMAP_DECOMPILE_PAYLOAD_MB") == "256"
    assert _xmx(1536) in big["env"]["JAVA_TOOL_OPTIONS"]


def test_unfinished_decompiles_send_the_binary_to_an_isolated_rerun(tmp_path: Path) -> None:
    """★ A large timeout or an output past the limit -> re-run at the doubled budget with the larger
    output limit (under load a function can time out before it reaches the limit); a binary in
    decompile_settled is not re-run for them; nothing unfinished -> no re-run; a re-run for an
    analyzer exception alone keeps the default limit. The re-run that finished them is settled
    whole.

    MUTATION (verified RED): leave unfinished successes out of phase 2 -> RED; ignore
    decompile_settled -> "settled" runs twice -> RED; never pass large_payload -> RED; pass it
    only for an output past the limit -> "big" -> RED; pass it for every re-run -> "threw" ->
    RED."""
    plan = _Plan(
        {
            "big": [{"large": 2}, {"large": 0}],
            "mp4": [{"payload": 1}, {"payload": 0}],
            "settled": [{"large": 1}],
            "clean": [{}],
            "threw": [{"threw": _THREW}, {}],
        }
    )
    names = ("big", "mp4", "settled", "clean", "threw")
    recs = _recs(tmp_path, names)
    _res, _f, exports, runner = _run_all(tmp_path, plan, names, settled={recs[2].sha256})
    phase2 = {c[0]: c for c in plan.calls[len(names) :]}
    base = runner._config.headless_timeout_seconds
    assert set(phase2) == {"big", "mp4", "threw"}
    assert phase2["big"][1:] == (min(1800, 2 * base), True)
    assert phase2["mp4"][2] is True
    assert phase2["threw"][2] is False  # re-run for the analyzer alone: the default limit
    assert all(e.export_only is False and e.decompile_rerun_budget is None for e in exports)


def test_an_isolated_rerun_that_still_left_them_records_its_budget(tmp_path: Path) -> None:
    """★ The re-run still left a large decompile unfinished: the settled result carries the
    budget it ran under (recorded so the next scan does not buy the same attempt), whichever
    extraction is kept.

    MUTATION (verified RED): record only when the re-run is kept -> the "first" case -> RED."""
    plan = _Plan(
        {
            "lib": [{"large": 1}, {"large": 1}],
            "worse": [{"large": 1}, {"large": 3}],
        }
    )
    recs = _recs(tmp_path, ("lib", "worse"))
    _res, _f, exports, runner = _run_all(tmp_path, plan, ("lib", "worse"))
    budget = retry_budget_seconds(recs[0].path, runner._config.headless_timeout_seconds)
    by = {e.binary.name: e for e in exports}
    assert by["lib"].decompile_rerun_budget == budget
    assert by["worse"].export_only is True and by["worse"].decompile_large_timeouts == 1
    assert by["worse"].decompile_rerun_budget == budget


def _rerun_db(tmp_path: Path, rows: list[tuple[str, str | None]]) -> sqlite3.Connection:
    conn = open_db(tmp_path / "analysis.db")
    for i, (name, rerun) in enumerate(rows):
        conn.execute(
            "INSERT INTO binaries (id, name, sha256, ghidra_ok, decompile_rerun) "
            "VALUES (?, ?, ?, 1, ?)",
            (i + 1, name, f"{i}" * 64, rerun),
        )
    conn.commit()
    return conn


def test_a_rerun_that_could_not_finish_is_not_bought_again_under_the_same_conditions(
    tmp_path: Path,
) -> None:
    """★ Skipped only when pass, Ghidra and a no-larger budget are all positively the same; any
    other pass or Ghidra, a larger budget, an unknown Ghidra, a malformed record or none re-runs.

    MUTATION (verified RED): skip on a matching pass alone -> "other_ghidra" skipped -> RED;
    re-run when the budget is equal (> becomes >=) -> "same" re-runs -> RED."""
    names = ("same", "other_pass", "other_ghidra", "bigger", "junk", "none")
    recs = _recs(tmp_path, names)
    now = retry_budget_seconds(recs[0].path, 300)
    assert now is not None
    rows = [
        ("same", decompile_rerun_record("P", "11.4.3", now)),
        ("other_pass", decompile_rerun_record("Q", "11.4.3", now)),
        ("other_ghidra", decompile_rerun_record("P", "12.0", now)),
        ("bigger", decompile_rerun_record("P", "11.4.3", now - 1)),
        ("junk", "{not json"),
        ("none", None),
    ]
    conn = _rerun_db(tmp_path, rows)
    try:
        skips = decompile_rerun_skips(
            conn, recs, pass_version="P", timeout_base=300, ghidra_version="11.4.3"
        )
        assert skips == {recs[0].sha256}
        assert (
            decompile_rerun_skips(
                conn, recs, pass_version="P", timeout_base=300, ghidra_version="unknown"
            )
            == set()
        )
    finally:
        conn.close()


# ── the pipeline: what is stored, recorded and said ─────────────────────────────────────────


def _scan(fs: Path, ws_dir: Path, home: Path, plan: _Plan, **kw: Any) -> AnalyzeResult:
    with patch.object(GhidraRunner, "run_ghidra", lambda self, *a, **k: plan(self, *a, **k)):
        with Workspace(ws_dir) as ws:
            return run_analyze(fs, ws, _e2e_cfg(home), **kw)


def _rows(db: Path) -> dict[str, dict[str, Any]]:
    conn = open_db(db)
    try:
        return {
            r["name"]: {
                "reason": r["ghidra_status_reason"],
                "functions": conn.execute(
                    "SELECT COUNT(*) FROM functions WHERE binary_id = ?", (r["id"],)
                ).fetchone()[0],
                "rerun": json.loads(r["decompile_rerun"]) if r["decompile_rerun"] else None,
            }
            for r in conn.execute("SELECT * FROM binaries")
        }
    finally:
        conn.close()


def test_the_scan_stores_the_better_extraction_and_names_what_kept_its_blind_spot(
    tmp_path: Path,
) -> None:
    """★ End to end: a binary whose analyzer threw and whose clean re-run has more functions is
    stored from the re-run (reason NULL); one whose re-run threw again keeps the extraction with
    more functions and its reason, and the scan names it.

    MUTATION (verified RED): store phase 1 only (drop on_export's whole-session store) -> the
    first binary keeps 1 function and its reason -> RED; leave the degraded list out of the
    result -> RED."""
    a, b, c = _NAMES[:3]
    plan = _Plan(
        {
            a: [{"threw": _THREW, "functions": 1}, {"functions": 3}],
            b: [{"threw": _THREW, "functions": 2}, {"threw": _THREW, "functions": 1}],
            c: [{"functions": 2}],
            **{n: [{"functions": 2}] for n in _NAMES[3:]},
        }
    )
    fs = _firmware(tmp_path)
    result = _scan(fs, tmp_path / "ws", _ghidra(tmp_path), plan)
    rows = _rows(tmp_path / "ws" / "analysis.db")
    assert (rows[a]["reason"], rows[a]["functions"]) == (None, 3)
    assert (rows[b]["reason"], rows[b]["functions"]) == (_THREW, 2)
    assert rows[c]["reason"] is None
    assert result.analyzer_degraded_binaries == [{"binary": b, "reason": _THREW}]


def test_the_scan_records_a_rerun_that_could_not_finish_and_the_next_scan_honours_it(
    tmp_path: Path,
) -> None:
    """★ The isolated re-run still left a large decompile: the row records the pass, Ghidra and
    budget. A --reanalyze under the same conditions re-extracts it but does not re-run it isolated
    again; --force-retry does. A stored extraction with none left clears the record.

    MUTATION (verified RED): skip the record write -> RED; leave decompile_settled out of run_all
    -> the second scan calls it twice -> RED."""
    a = _NAMES[0]
    others = {n: [{"functions": 2}] * 4 for n in _NAMES[1:]}
    plan = _Plan(
        {a: [{"large": 1}, {"large": 1}, {"large": 1}, {"large": 1}, {"large": 0}], **others}
    )
    fs = _firmware(tmp_path)
    home = _ghidra(tmp_path)
    _scan(fs, tmp_path / "ws", home, plan)
    rec = _rows(tmp_path / "ws" / "analysis.db")[a]["rerun"]
    assert rec is not None and rec["ghidra_version"] == "11.0" and rec["budget"] > 0
    assert sum(1 for c in plan.calls if c[0] == a) == 2

    before = len(plan.calls)
    _scan(fs, tmp_path / "ws", home, plan, reanalyze=a)
    assert sum(1 for c in plan.calls[before:] if c[0] == a) == 1  # re-extracted, not re-run

    before = len(plan.calls)
    _scan(fs, tmp_path / "ws", home, plan, reanalyze=a, force_retry=True)
    assert sum(1 for c in plan.calls[before:] if c[0] == a) == 2  # forced: re-run isolated
    assert _rows(tmp_path / "ws" / "analysis.db")[a]["rerun"] is None  # the re-run finished them


def test_the_scan_summary_names_the_binaries_that_kept_an_analyzer_exception() -> None:
    """MUTATION (verified RED): leave _warn_analyzer_degraded out of report_extraction_state ->
    RED."""
    import click
    from click.testing import CliRunner

    from treasure_map.cli.analyze_cli import report_extraction_state

    class _R:
        incomplete_binaries: list[str] = []
        no_functions_binaries: list[str] = []
        kept_earlier_binaries: list[dict[str, Any]] = []
        reanalyze_pending = 0
        analyzer_degraded_binaries = [{"binary": "svc_a", "reason": _THREW}]

    @click.command()
    def cmd() -> None:
        report_extraction_state(_R(), None)

    out = CliRunner().invoke(cmd, [])
    assert out.exit_code == 0, out.output
    assert "1 binaries were extracted while a Ghidra analyzer threw" in out.stderr
    assert f"svc_a ({_THREW})" in out.stderr


# ── F-3 in the extractor, read as text ───────────────────────────────────────────────────────


def test_the_extractor_retries_by_deadline_smallest_first_and_counts_what_is_left() -> None:
    """★ First limit 60 s for a body of 32 KB or more; the retries share max(fixed budget, deadline
    - now), smallest body first, each at most min(600, left / remaining); an output past the limit
    is error + payload_exceeded (never timeout); the counts are the first key of the JSON.

    MUTATION (verified RED): keep the fixed budget only -> RED; drop the size sort -> RED; write
    the counts after "binary" -> RED; record a payload error's raw message -> RED."""
    code = _code(_GHIDRA_DIR / "ExportFunctions.java")
    assert "DECOMPILE_TIMEOUT_LARGE_S = 60" in code
    assert "DECOMPILE_LARGE_BODY_BYTES = 32768" in code
    assert "DECOMPILE_RETRY_TIMEOUT_S = 600" in code
    assert "DECOMPILE_UNFINISHED_LARGE_BYTES = 8192" in code
    assert "firstLimit(func)" in code
    loop = code[code.index("long retryStart = System.currentTimeMillis();") :]
    loop = loop[: loop.index("String decompileCounts")]
    assert "Math.max(retryBudgetMs, deadline - retryStart)" in loop
    assert "retryOrder.sort(" in loop and "getNumAddresses()" in loop
    assert "Math.min(DECOMPILE_RETRY_TIMEOUT_S, Math.max(1L, leftS / remaining))" in loop
    assert "payloadExceeded(msg) ? DECOMPILE_PAYLOAD_EXCEEDED" in code
    assert 'contains("buffer size exceeded")' in code
    assert "opts.setMaxPayloadMBytes(payloadMBytes())" in code
    write = code[code.index('pw.print("{");') :]
    counts, binary = '"\\"decompile_counts\\":"', '"\\"binary\\":\\""'
    assert counts in write and binary in write
    assert write.index(counts) < write.index(binary)


def test_a_payload_error_is_stored_as_an_error_with_its_cause(tmp_path: Path) -> None:
    """The extractor's error + payload_exceeded lands as decompile_status 'error' with the cause
    in decompile_error — not as a timeout."""
    out = tmp_path / "out"
    out.mkdir()
    rec = ElfRecord(path=tmp_path / "x", name="x", arch="a", elf_type="executable", sha256="a" * 64)
    fn = {
        "name": "f",
        "address": "0x1000",
        "size": 105000,
        "decompile_status": "error",
        "decompile_error": "payload_exceeded",
    }
    (out / f"x_{rec.sha256[:8]}_ghidra.json").write_text(json.dumps({"functions": [fn]}))
    conn = open_db(tmp_path / "analysis.db")
    conn.execute("INSERT INTO binaries (id, name, sha256) VALUES (1, 'x', ?)", (rec.sha256,))
    ingest_ghidra_output(conn, out, [rec], {rec.sha256: 1})
    got = conn.execute("SELECT decompile_status, decompile_error FROM functions").fetchone()
    conn.close()
    assert tuple(got) == ("error", "payload_exceeded")


def test_the_schema_declares_the_rerun_record_in_both_places(tmp_path: Path) -> None:
    """New databases (schema.sql) and older ones (the migration) both carry decompile_rerun and
    promote_recover_rejected_string.

    MUTATION (verified RED): drop decompile_rerun from _ADDED_COLUMNS -> the legacy case -> RED."""
    schema = Path(ghidra_ingest.__file__).parents[1] / "storage" / "schema.sql"
    raw = sqlite3.connect(tmp_path / "s.db")
    raw.executescript(schema.read_text())
    cols = {r[1] for r in raw.execute("PRAGMA table_info(binaries)")}
    raw.close()
    assert {"decompile_rerun", "promote_recover_rejected_string"} <= cols
    legacy = tmp_path / "old.db"
    raw = sqlite3.connect(legacy)
    raw.execute("CREATE TABLE binaries (id INTEGER PRIMARY KEY, name TEXT, sha256 TEXT UNIQUE)")
    raw.commit()
    raw.close()
    conn = open_db(legacy)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(binaries)")}
    conn.close()
    assert {"decompile_rerun", "promote_recover_rejected_string"} <= cols


def test_replace_keeps_the_rerun_budget_field() -> None:
    """The settled result is a dataclass copy: the budget field survives ``replace``."""
    assert replace(_ok(), decompile_rerun_budget=600).decompile_rerun_budget == 600


_FIRST_THREW = {"threw": _THREW, "functions": 3, "export": "ok"}


@pytest.mark.parametrize(
    ("first", "second"),
    [
        (_FIRST_THREW, {"fail": True}),  # the re-run's extraction failed
        (_FIRST_THREW, {"threw": _THREW, "functions": 1, "export": "ok"}),  # fewer functions
        # neither better (one large decompile left each); the re-run's export failed
        ({"large": 1, "export": "ok"}, {"large": 1, "export": "failed:timeout"}),
    ],
    ids=["rerun_failed", "first_better", "tie_rerun_export_failed"],
)
def test_phase_ones_session_kept_whole_keeps_its_archive(
    tmp_path: Path, first: dict[str, Any], second: dict[str, Any]
) -> None:
    """★ Phase 2 settles on phase 1's whole session: the row keeps the export status AND the
    archive phase 1 stored (archive named, intact), and the next plain scan does not re-run the
    binary for an archive it believes missing.

    MUTATION (verified RED): write the kept session's export status again in _persist_export (the
    old export-only write, which names no archive) -> archive None -> RED; never mark the kept
    session (stored_stands) -> RED."""
    from tests.unit.lib.test_scan_export import _exports
    from treasure_map.lib.binexport_archive import archive_intact

    a = _NAMES[0]
    plan = _Plan({a: [first, second], **{n: [{"export": "ok"}] for n in _NAMES[1:]}})
    fs = _firmware(tmp_path)
    home = _ghidra(tmp_path)
    _with_extension(home)
    _scan(fs, tmp_path / "ws", home, plan)
    status, meta = _exports(tmp_path / "ws" / "analysis.db")[a]
    assert status == "ok"
    assert meta is not None and meta.get("archive")
    assert archive_intact(tmp_path / "ws" / "binexport", meta)
    calls = len(plan.calls)
    _scan(fs, tmp_path / "ws", home, plan)
    assert len(plan.calls) == calls  # nothing re-run: every row is current, archive included
