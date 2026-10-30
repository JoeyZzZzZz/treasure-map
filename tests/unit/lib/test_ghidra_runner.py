# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from treasure_map.lib.analyze.elf_inventory import ElfRecord
from treasure_map.lib.analyze.ghidra_runner import (
    GhidraRunner,
    _build_cmd,
    _classify_analysis,
    _patch_elf_for_ghidra,
    compute_pass_version,
    find_headless,
)
from treasure_map.lib.analyze.stub_resolve import StubResolution, stub_table_marker
from treasure_map.lib.config.config import GhidraConfig, GhidraLocalConfig
from treasure_map.lib.errors import GhidraNotFoundError
from treasure_map.lib.pattern.extractor_names import RegistryError

# ── helpers ───────────────────────────────────────────────────────────────────


def _make_runner(tmp_path: Path, headless: Path | None = None) -> GhidraRunner:
    """Return a GhidraRunner with a pre-set headless path (skip discovery)."""
    hl = headless or (tmp_path / "fake_analyzeHeadless")
    return GhidraRunner(GhidraConfig(), headless=hl)


def _write_small_elf(path: Path) -> None:
    """Write a minimal valid ELF magic so stat().st_size works."""
    path.write_bytes(b"\x7fELF" + b"\x00" * 100)


def _echoed_stub_marker(env: dict[str, str]) -> str:
    """The ``stub_marker`` the real extractor writes: the sha256 of the stub table it loaded
    (re-normalised; for a table the driver serialised that is the file's own content), or "none"
    when TMAP_STUB_NAMES was not set."""
    path = env.get("TMAP_STUB_NAMES")
    if not path:
        return "none"
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _good_json(env: dict[str, str] | None = None) -> str:
    """Return a >200-byte valid Ghidra output JSON. Given the run's ``env``, it carries the
    ``pass_version`` / ``sha8`` / ``stub_marker`` markers the real extractor echoes back from
    PASS_VERSION / SHA8 / TMAP_STUB_NAMES."""
    markers = (
        {}
        if env is None
        else {
            "pass_version": env["PASS_VERSION"],
            "sha8": env["SHA8"],
            "stub_marker": _echoed_stub_marker(env),
        }
    )
    return json.dumps(
        markers
        | {
            "binary": "httpd",
            "functions": [
                {
                    "name": "main",
                    "address": "0x401000",
                    "size": 100,
                    "is_exported": 1,
                    "callees": ["malloc", "free"],
                    "pseudocode": "int main(int argc, char **argv) { return 0; }",
                }
            ],
            "imports": [{"func_name": "malloc", "lib_name": "libc.so.6"}],
            "exports": [{"func_name": "main", "address": "0x401000"}],
            "strings": [{"value": "Hello, World!", "address": "0x402000"}],
        }
    )


# ── find_headless: priority order ────────────────────────────────────────────


def test_find_headless_config_home(tmp_path: Path) -> None:
    """Step 1: config.local.home wins over env and PATH."""
    hl = tmp_path / "support" / "analyzeHeadless"
    hl.parent.mkdir()
    hl.write_text("#!/bin/sh")
    config = GhidraConfig(local=GhidraLocalConfig(home=tmp_path))
    assert find_headless(config) == hl


def test_find_headless_env_var(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Step 2: GHIDRA_HOME env var is used when config.local.home is None."""
    hl = tmp_path / "support" / "analyzeHeadless"
    hl.parent.mkdir()
    hl.write_text("#!/bin/sh")
    monkeypatch.setenv("GHIDRA_HOME", str(tmp_path))
    assert find_headless(GhidraConfig()) == hl


def test_find_headless_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Step 3: shutil.which is used as last resort."""
    fake_hl = tmp_path / "analyzeHeadless"
    fake_hl.write_text("#!/bin/sh")
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    monkeypatch.setattr(shutil, "which", lambda _name: str(fake_hl))
    assert find_headless(GhidraConfig()) == fake_hl


def test_find_headless_raises_with_locations(monkeypatch: pytest.MonkeyPatch) -> None:
    """Step 4: GhidraNotFoundError lists searched paths and install URL."""
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    with pytest.raises(GhidraNotFoundError, match="analyzeHeadless"):
        find_headless(GhidraConfig())


def test_find_headless_config_beats_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Config home takes priority over GHIDRA_HOME env."""
    cfg_hl = tmp_path / "cfg_ghidra" / "support" / "analyzeHeadless"
    cfg_hl.parent.mkdir(parents=True)
    cfg_hl.write_text("#!/bin/sh")
    env_hl = tmp_path / "env_ghidra" / "support" / "analyzeHeadless"
    env_hl.parent.mkdir(parents=True)
    env_hl.write_text("#!/bin/sh")
    monkeypatch.setenv("GHIDRA_HOME", str(tmp_path / "env_ghidra"))
    config = GhidraConfig(local=GhidraLocalConfig(home=tmp_path / "cfg_ghidra"))
    assert find_headless(config) == cfg_hl


# ── _build_cmd ────────────────────────────────────────────────────────────────


def test_build_cmd_structure(tmp_path: Path) -> None:
    """Command must contain all required analyzeHeadless arguments."""
    headless = tmp_path / "analyzeHeadless"
    binary = tmp_path / "httpd"
    arch = "MIPS:BE:32:default"
    proj_dir = tmp_path / "proj"
    output_dir = tmp_path / "out"
    script_dir = tmp_path / "scripts"
    sha8 = "deadbeef"

    cmd = _build_cmd(headless, binary, arch, proj_dir, output_dir, script_dir, sha8, 300)

    assert cmd[0] == str(headless)
    assert cmd[1] == str(proj_dir)
    assert "-processor" in cmd
    assert cmd[cmd.index("-processor") + 1] == arch
    assert "-import" in cmd
    assert cmd[cmd.index("-import") + 1] == str(binary)
    # The functions the analysis left out are created first, then the extraction runs. With no
    # export asked for, nothing else runs and only the extraction scripts' directory is searched.
    posts = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-postScript"]
    assert posts == ["PromoteUndefined.java", "ExportFunctions.java"]
    assert "-scriptPath" in cmd
    assert cmd[cmd.index("-scriptPath") + 1] == str(script_dir)
    assert "-deleteProject" in cmd
    assert "-analysisTimeoutPerFile" in cmd
    assert cmd[cmd.index("-analysisTimeoutPerFile") + 1] == "300"
    assert "-log" in cmd


# ── _classify_analysis (red-line: success requires produced functions, not file size) ──

MODULE = "treasure_map.lib.analyze.ghidra_runner"


def test_classify_ok_when_functions_present(tmp_path: Path) -> None:
    out = tmp_path / "b_ghidra.json"
    out.write_text(_good_json())
    assert _classify_analysis(out, tmp_path / "b") == ("ok", 1)


def test_classify_failed_when_output_missing(tmp_path: Path) -> None:
    assert _classify_analysis(tmp_path / "absent.json", tmp_path / "b") == ("failed", 0)


def test_classify_failed_when_malformed(tmp_path: Path) -> None:
    out = tmp_path / "b_ghidra.json"
    out.write_text("{ truncated shell, not json")
    assert _classify_analysis(out, tmp_path / "b") == ("failed", 0)


def _marked_json(functions: list[Any], *, pass_version: str = "p1", sha8: str = "aabb1122") -> str:
    """An extractor output carrying all three markers (no stub table: ``none``)."""
    return json.dumps(
        {
            "pass_version": pass_version,
            "sha8": sha8,
            "stub_marker": "none",
            "functions": functions,
            "imports": [],
            "exports": [],
            "strings": [],
        }
    )


def test_classify_empty_functions_on_code_binary_is_no_functions(tmp_path: Path) -> None:
    """T-N1. A parsed output whose three markers are this run's, on a binary WITH code, holding 0
    functions: the extraction finished and found nothing it could call a function. That is
    ``no_functions`` — recorded, not retried by the same pass, and not clean. Everything that is
    not that exact case stays as it was: a marker mismatch and a malformed file are ``failed``, a
    code-free object is ``ok_empty``.

    MUTATION (verified RED): return ``("failed", 0)`` for code + 0 functions again."""
    out = tmp_path / "b_ghidra.json"
    out.write_text(_marked_json([]))
    with patch(f"{MODULE}.has_substantial_text", lambda _b: True):
        assert _classify_analysis(out, tmp_path / "b", "p1", "aabb1122", "none") == (
            "no_functions",
            0,
        )
        # another pass's / binary's / stub table's output is never this run's result
        assert _classify_analysis(out, tmp_path / "b", "p2", "aabb1122", "none") == ("failed", 0)
        assert _classify_analysis(out, tmp_path / "b", "p1", "deadbeef", "none") == ("failed", 0)
        assert _classify_analysis(out, tmp_path / "b", "p1", "aabb1122", "abc") == ("failed", 0)
        out.write_text("{ truncated shell, not json")
        assert _classify_analysis(out, tmp_path / "b", "p1", "aabb1122", "none") == ("failed", 0)
    out.write_text(_marked_json([]))
    with patch(f"{MODULE}.has_substantial_text", lambda _b: False):
        assert _classify_analysis(out, tmp_path / "b", "p1", "aabb1122", "none") == ("ok_empty", 0)


def _no_functions_sub(output_dir: Path, sha8: str, log_lines: str = ""):  # type: ignore[no-untyped-def]
    """A stand-in Ghidra run that exports a marker-correct, functionless JSON and appends
    ``log_lines`` to the run's log (``-log`` appends)."""

    def fake_sub(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        out = output_dir / f"httpd_{sha8}_ghidra.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(_marked_json([], pass_version=env["PASS_VERSION"], sha8=env["SHA8"]))
        if log_lines:
            with (output_dir / f"httpd_{sha8}.log").open("a") as f:
                f.write(log_lines)
        return 0, ""

    return fake_sub


def test_a_no_functions_run_is_a_success_and_a_timeout_in_its_own_log_is_not(
    tmp_path: Path,
) -> None:
    """T-N1 (the run). ``_run_once`` records no_functions as a success with no failure reason; the
    same output under an analysis timeout THIS run logged is a timeout failure, as before.

    MUTATION (verified RED): leave no_functions out of the success statuses."""
    output_dir = tmp_path / "output"
    binary = tmp_path / "httpd"
    _write_small_elf(binary)
    sha8 = "aabb1122"
    runner = _make_runner(tmp_path)
    with (
        patch(f"{MODULE}.has_substantial_text", lambda _b: True),
        patch(f"{MODULE}._run_subprocess", _no_functions_sub(output_dir, sha8)),
    ):
        r = runner.run_ghidra(binary, output_dir, 60, "x86:LE:64:default", sha8, retry=False)
    assert (r.success, r.analysis_status, r.reason) == (True, "no_functions", None)

    timed_out = "INFO  REPORT: Analysis timed out at 60 seconds\n"
    with (
        patch(f"{MODULE}.has_substantial_text", lambda _b: True),
        patch(f"{MODULE}._run_subprocess", _no_functions_sub(output_dir, sha8, timed_out)),
    ):
        r = runner.run_ghidra(binary, output_dir, 60, "x86:LE:64:default", sha8, retry=False)
    assert (r.success, r.reason) == (False, "timeout")


# ── the log is appended to: only this attempt's part of it is read (S10) ──────────────────────


def _ok_sub(output_dir: Path, sha8: str, log_lines: str):  # type: ignore[no-untyped-def]
    def fake_sub(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        out = output_dir / f"httpd_{sha8}_ghidra.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(_good_json(env))
        with (output_dir / f"httpd_{sha8}.log").open("a") as f:
            f.write(log_lines)
        return 0, ""

    return fake_sub


def test_an_earlier_runs_timeout_line_does_not_fail_this_run(tmp_path: Path) -> None:
    """T-G1. ``-log`` appends, so an earlier run's analysis-timeout line is still in the file. A run
    that only adds ordinary lines and exports a good output is ``ok``; a run that writes the line
    itself is a timeout.

    MUTATION (verified RED): search the whole log again (offset ignored) -> the first run reads as
    a timeout."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    binary = tmp_path / "httpd"
    _write_small_elf(binary)
    sha8 = "aabb1122"
    log = output_dir / f"httpd_{sha8}.log"
    log.write_text("INFO  earlier run\nINFO  REPORT: Analysis timed out at 300 seconds\n")
    runner = _make_runner(tmp_path)
    with patch(f"{MODULE}._run_subprocess", _ok_sub(output_dir, sha8, "INFO  analysis done\n")):
        r = runner.run_ghidra(binary, output_dir, 60, "x86:LE:64:default", sha8, retry=False)
    assert (r.success, r.analysis_status, r.function_count) == (True, "ok", 1)
    assert r.log_offset > 0  # really measured past the earlier run's lines

    own = "INFO  REPORT: Analysis timed out at 60 seconds\n"
    with patch(f"{MODULE}._run_subprocess", _ok_sub(output_dir, sha8, own)):
        r = runner.run_ghidra(binary, output_dir, 60, "x86:LE:64:default", sha8, retry=False)
    assert (r.success, r.reason) == (False, "timeout")


def test_a_rolled_over_log_is_read_whole(tmp_path: Path) -> None:
    """A log now SHORTER than where this attempt started was rolled over (Ghidra starts a fresh
    file past its size limit): all of it is this attempt's, so its timeout line still counts.

    MUTATION (verified RED): drop the "file smaller than the offset -> read from 0" fallback -> the
    seek lands past the end, nothing is read, the half analysis is cached as ok."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    binary = tmp_path / "httpd"
    _write_small_elf(binary)
    sha8 = "aabb1122"
    log = output_dir / f"httpd_{sha8}.log"
    log.write_text("x" * 4096)  # an earlier run's large log

    def fake_sub(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        (output_dir / f"httpd_{sha8}_ghidra.json").write_text(_good_json(env))
        log.write_text("INFO  REPORT: Analysis timed out at 60 seconds\n")  # the fresh file
        return 0, ""

    with patch(f"{MODULE}._run_subprocess", fake_sub):
        r = _make_runner(tmp_path).run_ghidra(
            binary, output_dir, 60, "x86:LE:64:default", sha8, retry=False
        )
    assert r.log_offset == 4096
    assert (r.success, r.reason) == (False, "timeout")


def test_an_earlier_runs_import_failure_does_not_send_a_timeout_down_the_patch_path(
    tmp_path: Path,
) -> None:
    """T-G2. An "Import failed" an earlier run left in the appended log says nothing about this
    run, which timed out: no ELF patch, no patched re-run, reason timeout.

    MUTATION (verified RED): read the whole log for "Import failed" again -> the patch path runs
    and the reason becomes import_failed."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    binary = tmp_path / "httpd"
    _write_small_elf(binary)
    sha8 = "aabb1122"
    (output_dir / f"httpd_{sha8}.log").write_text("ERROR Import failed for httpd\n")
    patched: list[Path] = []

    def fake_patch(src: Path) -> None:
        patched.append(src)
        return None

    def fake_sub(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        return -1, "timeout"

    with (
        patch(f"{MODULE}._run_subprocess", fake_sub),
        patch(f"{MODULE}._patch_elf_for_ghidra", fake_patch),
    ):
        r = _make_runner(tmp_path).run_ghidra(
            binary, output_dir, 60, "x86:LE:64:default", sha8, retry=False
        )
    assert patched == []
    assert (r.success, r.reason) == (False, "timeout")


def test_classify_empty_functions_on_codefree_object_is_ok_empty(tmp_path: Path) -> None:
    # A genuinely code-free object (no substantial .text) with 0 functions is legitimately empty —
    # ok_empty so it is not re-analyzed forever.
    out = tmp_path / "b_ghidra.json"
    out.write_text(json.dumps({"functions": [], "imports": [], "exports": [], "strings": []}))
    with patch(f"{MODULE}.has_substantial_text", lambda _b: False):
        assert _classify_analysis(out, tmp_path / "b") == ("ok_empty", 0)


# ── run_ghidra: subprocess mocked ─────────────────────────────────────────────


def test_run_ghidra_success(tmp_path: Path) -> None:
    """When subprocess returns 0 and output file exists, result.success is True."""
    output_dir = tmp_path / "output"
    binary = tmp_path / "httpd"
    _write_small_elf(binary)
    sha8 = "aabb1122"

    def fake_sub(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        out = output_dir / f"httpd_{sha8}_ghidra.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(_good_json(env))
        return 0, ""

    runner = _make_runner(tmp_path)
    with patch(f"{MODULE}._run_subprocess", fake_sub):
        result = runner.run_ghidra(
            binary, output_dir, timeout=60, arch="x86:LE:64:default", sha8=sha8
        )

    assert result.success is True
    assert result.output_file == output_dir / f"httpd_{sha8}_ghidra.json"
    assert result.retried is False


def test_run_ghidra_failure_no_output(tmp_path: Path) -> None:
    """Returns success=False when subprocess exits non-zero and output is absent."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    binary = tmp_path / "httpd"
    _write_small_elf(binary)

    def fake_sub(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        return 1, "ERROR"

    runner = _make_runner(tmp_path)
    with patch(f"{MODULE}._run_subprocess", fake_sub):
        result = runner.run_ghidra(
            binary, output_dir, timeout=60, arch="x86:LE:64:default", sha8="00000000"
        )

    assert result.success is False
    assert result.output_file is None


def test_run_ghidra_timeout(tmp_path: Path) -> None:
    """Timeout (-1 returncode, no output file) → success=False."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    binary = tmp_path / "httpd"
    _write_small_elf(binary)

    def fake_sub(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        return -1, "timeout"

    runner = _make_runner(tmp_path)
    with patch(f"{MODULE}._run_subprocess", fake_sub):
        result = runner.run_ghidra(
            binary, output_dir, timeout=5, arch="x86:LE:64:default", sha8="00000000"
        )

    assert result.success is False


def test_run_ghidra_retries_on_import_failed(tmp_path: Path) -> None:
    """Exactly one retry is attempted when log contains 'Import failed'."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    binary = tmp_path / "httpd"
    _write_small_elf(binary)
    sha8 = "cafebabe"
    call_count = 0

    def fake_sub(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            (output_dir / f"httpd_{sha8}.log").write_text("ERROR: Import failed for httpd")
            return 1, "Import failed"
        # Second call: produce valid output
        (output_dir / f"httpd_{sha8}_ghidra.json").write_text(_good_json(env))
        return 0, ""

    def fake_patch(src: Path) -> tuple[Path, Path]:
        tmpdir = tmp_path / "patch_tmpdir"
        tmpdir.mkdir(exist_ok=True)
        patched = tmpdir / src.name
        shutil.copy2(src, patched)
        return patched, tmpdir

    runner = _make_runner(tmp_path)
    with (
        patch(f"{MODULE}._run_subprocess", fake_sub),
        patch(f"{MODULE}._patch_elf_for_ghidra", fake_patch),
    ):
        result = runner.run_ghidra(
            binary, output_dir, timeout=60, arch="x86:LE:64:default", sha8=sha8
        )

    assert call_count == 2, f"Expected 2 subprocess calls, got {call_count}"
    assert result.success is True
    assert result.retried is True


def test_run_ghidra_retries_once_on_non_import_failure(tmp_path: Path) -> None:
    """A non-import failure (chiefly a timeout) retries exactly once at a doubled budget.

    A large binary whose analysis+export overran the per-file timeout leaves no JSON; the failure
    is not an import problem, so it must not be a one-shot death sentence. Here the retry still
    fails, so the result is an honest failure — but retried is True and a 2× budget was used."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    binary = tmp_path / "httpd"
    _write_small_elf(binary)
    sha8 = "deadc0de"
    timeouts: list[int] = []

    def fake_sub(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        timeouts.append(timeout)
        return -1, "timeout"

    runner = _make_runner(tmp_path)
    with patch(f"{MODULE}._run_subprocess", fake_sub):
        result = runner.run_ghidra(
            binary, output_dir, timeout=60, arch="x86:LE:64:default", sha8=sha8
        )

    assert len(timeouts) == 2, f"Expected 2 subprocess calls, got {len(timeouts)}"
    assert timeouts[1] > timeouts[0], "retry must use a larger (2×) budget than the first attempt"
    assert result.success is False  # a still-failing retry is honestly a failure
    assert result.retried is True


def test_run_ghidra_timeout_retry_then_success(tmp_path: Path) -> None:
    """First attempt times out (no output); the 2× retry finishes and produces valid output."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    binary = tmp_path / "httpd"
    _write_small_elf(binary)
    sha8 = "0badf00d"
    call_count = 0

    def fake_sub(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return -1, "timeout"  # first budget exhausted, no JSON written
        (output_dir / f"httpd_{sha8}_ghidra.json").write_text(_good_json(env))
        return 0, ""

    runner = _make_runner(tmp_path)
    with patch(f"{MODULE}._run_subprocess", fake_sub):
        result = runner.run_ghidra(
            binary, output_dir, timeout=60, arch="x86:LE:64:default", sha8=sha8
        )

    assert call_count == 2
    assert result.success is True
    assert result.retried is True
    assert result.output_file == output_dir / f"httpd_{sha8}_ghidra.json"


# ── run_all ───────────────────────────────────────────────────────────────────


def test_run_all_calls_progress_callback(tmp_path: Path) -> None:
    """progress_callback fires per record in phase 1 ('ghidra') and per FAILED record in the serial
    phase 2 ('ghidra_retry'), each with the done/total/name/ok keys."""
    records = [
        ElfRecord(
            path=tmp_path / name,
            name=name,
            arch="x86:LE:64:default",
            elf_type="executable",
            sha256=sha,
        )
        for name, sha in [("a", "aaa"), ("b", "bbb")]
    ]
    for r in records:
        _write_small_elf(r.path)

    def fake_sub(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        return 1, ""

    progress: list[tuple[str, dict[str, Any]]] = []
    runner = _make_runner(tmp_path)
    with patch(f"{MODULE}._run_subprocess", fake_sub):
        runner.run_all(
            records, tmp_path / "out", progress_callback=lambda s, m: progress.append((s, m))
        )

    p1 = [m for s, m in progress if s == "ghidra"]
    p2 = [m for s, m in progress if s == "ghidra_retry"]
    assert {m["name"] for m in p1} == {"a", "b"}  # phase 1: one per record
    assert {m["name"] for m in p2} == {"a", "b"}  # both failed -> both retried serially in phase 2
    assert all(set(m) == {"done", "total", "name", "ok"} for _, m in progress)


def test_run_all_returns_one_result_per_record(tmp_path: Path) -> None:
    """run_all always returns exactly len(records) results."""
    records = [
        ElfRecord(
            path=tmp_path / f"bin_{i}",
            name=f"bin_{i}",
            arch="x86:LE:64:default",
            elf_type="executable",
            sha256=f"sha{i}" * 10,
        )
        for i in range(4)
    ]
    for r in records:
        _write_small_elf(r.path)

    def fake_sub(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        return 0, ""

    runner = _make_runner(tmp_path)
    with patch(f"{MODULE}._run_subprocess", fake_sub):
        results = runner.run_all(records, tmp_path / "out")

    assert len(results) == 4


# ── _patch_elf_for_ghidra ─────────────────────────────────────────────────────


def test_patch_elf_returns_none_for_non_elf(tmp_path: Path) -> None:
    """Non-ELF files → returns None (no patch needed)."""
    f = tmp_path / "script.sh"
    f.write_bytes(b"#!/bin/sh\necho hello\n")
    assert _patch_elf_for_ghidra(f) is None


def test_patch_elf_patched_file_has_same_name(tmp_path: Path) -> None:
    """Patched file must have the same filename as the original."""
    # Construct a minimal ELF64 LE with a SHT_ARM_ATTRIBUTES section header
    # that triggers the patch so the function actually creates an output.
    import struct as _s

    # ELF64 little-endian header (64 bytes) + one section header (64 bytes)
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    e_type = _s.pack("<H", 2)  # ET_EXEC
    e_machine = _s.pack("<H", 0x28)  # ARM
    e_version = _s.pack("<I", 1)
    e_entry = _s.pack("<Q", 0)
    e_phoff = _s.pack("<Q", 0)
    e_shoff = _s.pack("<Q", 64)  # section headers start right after ELF header
    e_flags = _s.pack("<I", 0)
    e_ehsize = _s.pack("<H", 64)
    e_phentsize = _s.pack("<H", 56)
    e_phnum = _s.pack("<H", 0)
    e_shentsize = _s.pack("<H", 64)
    e_shnum = _s.pack("<H", 1)
    e_shstrndx = _s.pack("<H", 0)

    elf_header = (
        e_ident
        + e_type
        + e_machine
        + e_version
        + e_entry
        + e_phoff
        + e_shoff
        + e_flags
        + e_ehsize
        + e_phentsize
        + e_phnum
        + e_shentsize
        + e_shnum
        + e_shstrndx
    )
    assert len(elf_header) == 64

    # One section header: SHT_ARM_ATTRIBUTES (0x70000003)
    sh_name = _s.pack("<I", 0)
    sh_type = _s.pack("<I", 0x70000003)  # SHT_ARM_ATTRIBUTES
    sh_flags = _s.pack("<Q", 0)
    sh_addr = _s.pack("<Q", 0)
    sh_offset = _s.pack("<Q", 128)  # offset = past both headers
    sh_size = _s.pack("<Q", 4)
    sh_link = _s.pack("<I", 0)
    sh_info = _s.pack("<I", 0)
    sh_addralign = _s.pack("<Q", 1)
    sh_entsize = _s.pack("<Q", 0)
    section_header = (
        sh_name
        + sh_type
        + sh_flags
        + sh_addr
        + sh_offset
        + sh_size
        + sh_link
        + sh_info
        + sh_addralign
        + sh_entsize
    )
    assert len(section_header) == 64

    elf_data = elf_header + section_header + b"\x00" * 4
    src = tmp_path / "my_binary"
    src.write_bytes(elf_data)

    result = _patch_elf_for_ghidra(src)
    assert result is not None
    patched_file, tmpdir = result
    try:
        assert patched_file.name == "my_binary"
        assert patched_file.exists()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ── extraction-pass content hash (cache-key dimension) ────────────────────────


def test_compute_pass_version_changes_when_pass_edited(tmp_path: Path) -> None:
    # Editing the extraction pass must change its content hash so the cache re-dirties. Even a
    # one-character comment change flips the hash (content hash, not a hand-bumped constant).
    d = tmp_path / "scripts"
    d.mkdir()
    java = d / "ExportFunctions.java"
    java.write_text("// v1\nclass ExportFunctions {}\n")
    v1 = compute_pass_version(d)
    java.write_text("// v2 (one comment char changed)\nclass ExportFunctions {}\n")
    v2 = compute_pass_version(d)
    assert v1 != v2
    # stable: recomputing over identical content yields the same hash (deterministic cache key)
    java.write_text("// v1\nclass ExportFunctions {}\n")
    assert compute_pass_version(d) == v1


def test_compute_pass_version_covers_sibling_scripts(tmp_path: Path) -> None:
    # A helper .java added beside ExportFunctions changes the pass too, so it is part of the hash.
    d = tmp_path / "scripts"
    d.mkdir()
    (d / "ExportFunctions.java").write_text("class ExportFunctions {}\n")
    base = compute_pass_version(d)
    (d / "Helper.java").write_text("class Helper {}\n")
    assert compute_pass_version(d) != base


def test_compute_pass_version_missing_dir_is_stable(tmp_path: Path) -> None:
    # A missing script dir yields a stable sentinel (never raises) so a scan still runs.
    missing = tmp_path / "nope"
    assert compute_pass_version(missing) == compute_pass_version(missing)


def test_runner_pass_version_matches_its_script_dir(tmp_path: Path) -> None:
    d = tmp_path / "scripts"
    d.mkdir()
    (d / "ExportFunctions.java").write_text("class ExportFunctions {}\n")
    runner = GhidraRunner(GhidraConfig(), script_dir=d, headless=tmp_path / "hl")
    assert runner.pass_version() == compute_pass_version(d)


# ── Ghidra-version detection ────────────────────────────


def test_detect_ghidra_version_reads_application_properties(tmp_path: Path) -> None:
    # ★ the version behind analyzeHeadless is read from <home>/Ghidra/application.properties
    # (home = the headless path's parent.parent -- analyzeHeadless lives in <home>/support/). A
    # well-formed properties file yields application.version, ignoring the other keys.
    from treasure_map.lib.analyze.ghidra_runner import detect_ghidra_version

    home = tmp_path / "ghidra_11.4.3_PUBLIC"
    (home / "support").mkdir(parents=True)
    (home / "Ghidra").mkdir()
    (home / "Ghidra" / "application.properties").write_text(
        "application.name=Ghidra\napplication.version=11.4.3\napplication.release.name=PUBLIC\n"
    )
    assert detect_ghidra_version(home / "support" / "analyzeHeadless") == "11.4.3"


def test_detect_ghidra_version_unreadable_is_unknown_not_none(tmp_path: Path) -> None:
    # ★ TEETH: a missing/unreadable application.properties returns the EXPLICIT
    # UNKNOWN_VERSION string, never None -- a None would let a downstream version compare
    # short-circuit into a silent "same version". Mutating the failure return to None reddens this
    # (None == UNKNOWN_VERSION is False). Anchors on the constant (single source), not the literal.
    from treasure_map.lib.analyze.ghidra_runner import detect_ghidra_version
    from treasure_map.version import UNKNOWN_VERSION

    # no Ghidra/ tree at all -> read_text raises OSError -> the explicit sentinel
    assert detect_ghidra_version(tmp_path / "nowhere" / "support" / "analyzeHeadless") == (
        UNKNOWN_VERSION
    )


def test_detect_ghidra_version_missing_key_is_unknown(tmp_path: Path) -> None:
    # ★ a properties file that exists but has NO application.version key -> the sentinel,
    # never a guess or a crash (an installation whose properties format drifted stays honest).
    from treasure_map.lib.analyze.ghidra_runner import detect_ghidra_version
    from treasure_map.version import UNKNOWN_VERSION

    home = tmp_path / "ghidra"
    (home / "support").mkdir(parents=True)
    (home / "Ghidra").mkdir()
    (home / "Ghidra" / "application.properties").write_text("application.name=Ghidra\n")
    assert detect_ghidra_version(home / "support" / "analyzeHeadless") == UNKNOWN_VERSION


# ── large-firmware scaling: reason, dynamic timeout, two-phase serial retry ──


def _sized_file(path: Path, mb: int) -> Path:
    with open(path, "wb") as f:
        f.truncate(mb * 1024 * 1024)  # sparse: reports size without writing the bytes
    return path


def test_dynamic_timeout_scales_with_size_and_caps(tmp_path: Path) -> None:
    # ★ a size-scaled timeout: small -> base; big -> proportionally more; huge -> ceiling (never
    # unbounded). Replaces the flat one-size-fits-all that timed a 28M library out under a small.
    from treasure_map.lib.analyze.ghidra_runner import _TIMEOUT_CEILING_SECONDS, _dynamic_timeout

    assert _dynamic_timeout(_sized_file(tmp_path / "sm", 1), 300) == 300  # < 10MB -> base
    assert _dynamic_timeout(_sized_file(tmp_path / "big", 28), 300) == int(300 * 2.8)  # scaled
    assert _dynamic_timeout(_sized_file(tmp_path / "huge", 500), 300) == _TIMEOUT_CEILING_SECONDS


def test_run_ghidra_reason_timeout(tmp_path: Path) -> None:
    # ★ a timeout failure carries reason='timeout' so a consumer knows a re-scan may finish it.
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    binary = tmp_path / "b"
    _write_small_elf(binary)

    def fake_sub(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        return -1, "timeout"

    runner = _make_runner(tmp_path)
    with patch(f"{MODULE}._run_subprocess", fake_sub):
        r = runner.run_ghidra(
            binary, output_dir, timeout=60, arch="x86:LE:64:default", sha8="deadbeef", retry=False
        )
    assert r.success is False and r.reason == "timeout"


def test_run_ghidra_reason_no_output(tmp_path: Path) -> None:
    # ★ a non-zero exit with no JSON is 'no_output', DISTINCT from a timeout -- a structural fail.
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    binary = tmp_path / "b"
    _write_small_elf(binary)

    def fake_sub(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        return 1, "err"

    runner = _make_runner(tmp_path)
    with patch(f"{MODULE}._run_subprocess", fake_sub):
        r = runner.run_ghidra(
            binary, output_dir, timeout=60, arch="x86:LE:64:default", sha8="deadbeef", retry=False
        )
    assert r.success is False and r.reason == "no_output"


def test_run_ghidra_retry_false_skips_the_timeout_retry(tmp_path: Path) -> None:
    # ★ retry=False runs ONE attempt (no in-pool timeout retry) -- what run_all uses in phase 1 so
    # the CPU-contending retry is deferred to the serial phase 2. retry=True runs the retry.
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    binary = tmp_path / "b"
    _write_small_elf(binary)
    calls = {"n": 0}

    def fake_sub(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        calls["n"] += 1
        return -1, "timeout"

    runner = _make_runner(tmp_path)
    with patch(f"{MODULE}._run_subprocess", fake_sub):
        r = runner.run_ghidra(
            binary, output_dir, timeout=60, arch="x86:LE:64:default", sha8="deadbeef", retry=False
        )
    assert calls["n"] == 1 and r.retried is False  # exactly one attempt, no retry
    calls["n"] = 0
    with patch(f"{MODULE}._run_subprocess", fake_sub):
        runner.run_ghidra(
            binary, output_dir, timeout=60, arch="x86:LE:64:default", sha8="deadbeef", retry=True
        )
    assert calls["n"] == 2  # retry=True -> the one timeout retry ran


def _big_rec(tmp_path: Path) -> ElfRecord:
    rec = ElfRecord(
        path=tmp_path / "big",
        name="big",
        arch="x86:LE:64:default",
        elf_type="executable",
        sha256="deadbeef",
    )
    _write_small_elf(rec.path)
    return rec


def test_run_all_two_phase_serial_retry_recovers(tmp_path: Path) -> None:
    # ★ phase 1 runs each binary ONCE in parallel; a failure is retried SERIALLY in phase 2 (a
    # 'ghidra_retry' event fires). This distinguishes the two-phase design from an in-pool retry,
    # which would recover inside phase 1 with NO ghidra_retry event and no isolated CPU.
    rec = _big_rec(tmp_path)
    calls = {"n": 0}

    def fake_sub(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        calls["n"] += 1
        if calls["n"] == 1:
            return -1, "timeout"  # phase 1: fail
        out = Path(env["OUTPUT_DIR"]) / f"big_{env['SHA8']}_ghidra.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(_good_json(env))
        return 0, ""  # phase 2: succeed

    events: list[tuple[str, dict[str, Any]]] = []
    runner = _make_runner(tmp_path)
    with patch(f"{MODULE}._run_subprocess", fake_sub):
        results = runner.run_all(
            [rec], tmp_path / "out", progress_callback=lambda s, m: events.append((s, m))
        )
    assert calls["n"] == 2  # ONE phase-1 attempt + ONE phase-2 retry (not an in-pool 3rd attempt)
    assert results[0].success is True and results[0].retried is True
    assert any(s == "ghidra_retry" and m["name"] == "big" for s, m in events)  # phase 2 ran


def test_run_all_phase2_failure_stays_failed_with_reason(tmp_path: Path) -> None:
    # ★ a binary that fails BOTH phases stays failed, honestly, with its reason (never a fake ok).
    rec = _big_rec(tmp_path)
    calls = {"n": 0}

    def fake_sub(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        calls["n"] += 1
        return -1, "timeout"

    runner = _make_runner(tmp_path)
    with patch(f"{MODULE}._run_subprocess", fake_sub):
        results = runner.run_all([rec], tmp_path / "out")
    assert calls["n"] == 2  # phase 1 + phase 2, then it stays failed
    assert results[0].success is False and results[0].reason == "timeout"


# ── the budget a failure was given: recorded, and re-derivable by ONE formula ─────────


def test_retry_budget_is_the_isolated_retrys_and_it_is_what_run_all_spends(
    tmp_path: Path,
) -> None:
    """One formula for "what budget does this binary's last attempt get", and both readers use it.

    ``run_all`` spends it in phase 2 and the dirty check re-derives it to ask whether a re-run would
    be a different attempt. Two copies of the expression would agree right up until one was
    adjusted, and then a binary would be measured against a budget nobody was going to hand it. So
    the value is read back out of the subprocess call phase 2 actually makes.

    MUTATION (must go RED): compute phase 2's budget inline again instead of calling the shared
    function, then change one of them."""
    from treasure_map.lib.analyze.ghidra_runner import retry_budget_seconds

    rec = _big_rec(tmp_path)
    _sized_file(rec.path, 28)
    base = GhidraConfig().headless_timeout_seconds
    seen: list[int] = []

    def fake_sub(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        seen.append(timeout)
        return -1, "timeout"

    runner = _make_runner(tmp_path)
    with patch(f"{MODULE}._run_subprocess", fake_sub):
        runner.run_all([rec], tmp_path / "out")

    expected = retry_budget_seconds(rec.path, base)
    assert expected == min(1800, int(300 * 2.8) * 2)
    # _run_subprocess is handed the budget + 60s of overhead; phase 2 is the second call.
    assert seen[1] - 60 == expected


def test_a_failure_records_the_budget_its_last_attempt_ran_under(tmp_path: Path) -> None:
    """The recorded budget is measured, not computed — and it is the LAST attempt's, not the first.

    A binary that fails twice failed at the bigger of the two, and that is the number the next scan
    has to beat. Recording the first attempt's would understate what the binary was given, and the
    next scan would then skip it on time it never actually had.

    MUTATION (must go RED): carry ``r1.timeout_budget`` into the synthesized failure result, or
    compute the budget at record time instead of stamping the attempt."""
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    binary = tmp_path / "b"
    _write_small_elf(binary)

    def fake_sub(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        return -1, "timeout"

    runner = _make_runner(tmp_path)
    with patch(f"{MODULE}._run_subprocess", fake_sub):
        one = runner.run_ghidra(
            binary, output_dir, timeout=60, arch="x86:LE:64:default", sha8="dead", retry=False
        )
        two = runner.run_ghidra(
            binary, output_dir, timeout=60, arch="x86:LE:64:default", sha8="dead", retry=True
        )
    assert one.timeout_budget == 60  # a single attempt: the budget it ran under
    assert two.timeout_budget == 120  # retried at the doubled budget: THAT is what it failed at


def test_a_result_that_never_ran_records_no_budget(tmp_path: Path) -> None:
    """A crash placeholder carries no budget, and must not pretend to.

    ``run_all`` synthesizes one of these when a worker raises before any attempt completed. A zero
    or a guessed budget there would be a number the binary never received; None reaches the dirty
    check as "nothing to compare" and it re-runs."""
    from treasure_map.lib.analyze.ghidra_runner import GhidraResult

    placeholder = GhidraResult(binary=tmp_path / "b", output_file=None, success=False, elapsed=0.0)
    assert placeholder.timeout_budget is None


# ── stale-output guards: a run must never be credited with a file it did not write ─────────────


def _foreign_json(pass_version: str, sha8: str) -> str:
    """A well-formed output that describes ANOTHER extraction (a different pass or binary)."""
    data = json.loads(_good_json())
    data["pass_version"] = pass_version
    data["sha8"] = sha8
    return json.dumps(data)


def _run_once_with(tmp_path: Path, fake_sub, sha8: str = "deadbeef"):  # type: ignore[no-untyped-def]
    output_dir = tmp_path / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    binary = tmp_path / "httpd"
    _write_small_elf(binary)
    runner = _make_runner(tmp_path)
    with patch(f"{MODULE}._run_subprocess", fake_sub):
        result = runner.run_ghidra(
            binary, output_dir, timeout=60, arch="x86:LE:64:default", sha8=sha8, retry=False
        )
    return result, output_dir / f"httpd_{sha8}_ghidra.json"


def test_a_kill_after_the_analysis_timed_out_is_a_failure_whatever_is_on_disk(
    tmp_path: Path,
) -> None:
    """Killed at the wall clock in a session whose analysis timed out = a failed scan, whatever
    file is present — here the JSON even carries THIS run's correct markers — and its export is
    never kept (scan_failed:timeout).

    MUTATION (verified RED): judge a killed run by its JSON before the analysis timeout ->
    success -> RED."""

    def fake_sub(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        out = Path(env["OUTPUT_DIR"]) / f"httpd_{env['SHA8']}_ghidra.json"
        out.write_text(_good_json(env))
        log = Path(env["OUTPUT_DIR"]) / f"httpd_{env['SHA8']}.log"
        log.write_text("INFO  REPORT: Analysis timed out at 60 seconds\n")
        return -1, "timeout"

    result, _ = _run_once_with(tmp_path, fake_sub)
    assert (result.success, result.reason, result.output_file) == (False, "timeout", None)
    assert result.export_status == "scan_failed:timeout"


def test_a_kill_after_the_extraction_finished_keeps_the_extraction(tmp_path: Path) -> None:
    """★ Killed at the wall clock after the extraction wrote this run's JSON (no analysis
    timeout): the scan of the binary succeeded — only the export, which runs after it, was cut off
    (failed:timeout when an export was asked for; extension_missing when none could be). With no
    JSON written the kill is a timeout failure, as before.

    MUTATION (verified RED): fail every killed run -> RED."""

    def killed_after_json(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        out = Path(env["OUTPUT_DIR"]) / f"httpd_{env['SHA8']}_ghidra.json"
        out.write_text(_good_json(env))
        return -1, "timeout"

    def killed_before_json(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        return -1, "timeout"

    result, json_path = _run_once_with(tmp_path / "a", killed_after_json)
    assert (result.success, result.output_file) == (True, json_path)
    assert result.export_status == "extension_missing"  # the runner has no extension here
    result, _ = _run_once_with(tmp_path / "b", killed_before_json)
    assert (result.success, result.reason) == (False, "timeout")
    assert result.export_status == "scan_failed:timeout"


def test_an_output_left_by_an_earlier_run_is_cleared_before_the_run(tmp_path: Path) -> None:
    """A previous scan's JSON at the target path is removed before Ghidra starts, so a run that
    writes nothing reports no_output — it can never be credited with the old file's functions.

    MUTATION (must go RED): drop the pre-run unlink in ``_run_once`` (the old file is then read and
    the reason becomes stale_output instead of no_output)."""
    sha8 = "deadbeef"
    preset = tmp_path / "output" / f"httpd_{sha8}_ghidra.json"
    preset.parent.mkdir(parents=True)
    preset.write_text(_foreign_json("feedfacefeedface", sha8))  # an older pass, functions > 0

    def fake_sub(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        return 0, ""  # exits cleanly, writes nothing

    result, out = _run_once_with(tmp_path, fake_sub, sha8)
    assert result.success is False
    assert result.reason == "no_output"
    assert not out.exists()


def test_an_output_with_foreign_markers_is_stale_not_success(tmp_path: Path) -> None:
    """A JSON that appears at the path but was written by another pass (copied in, a mixed-in old
    workspace) is stale_output. Two variants: wrong pass, and right pass but wrong binary.

    MUTATION (must go RED): make ``_markers_mismatch`` return False (or skip it in
    ``_classify_analysis``) -> the foreign file is counted as this run's success."""
    for wrong_pass, wrong_sha8 in ((True, False), (False, True)):

        def fake_sub(
            cmd: list[str],
            env: dict[str, str],
            timeout: int,
            cwd: Path | None = None,
            wp: bool = wrong_pass,
            ws: bool = wrong_sha8,
        ) -> tuple[int, str]:
            out = Path(env["OUTPUT_DIR"]) / f"httpd_{env['SHA8']}_ghidra.json"
            out.write_text(
                _foreign_json(
                    "feedfacefeedface" if wp else env["PASS_VERSION"],
                    "cafebabe" if ws else env["SHA8"],
                )
            )
            return 0, ""

        sub = tmp_path / ("p" if wrong_pass else "s")
        result, _ = _run_once_with(sub, fake_sub)
        assert result.success is False, (wrong_pass, wrong_sha8)
        assert result.reason == "stale_output", (wrong_pass, wrong_sha8)


def test_classify_rejects_a_missing_marker_when_one_is_expected(tmp_path: Path) -> None:
    """A JSON with no markers (an extractor from before they existed) never satisfies an expected
    pass/sha8: absence is a mismatch, not a pass."""
    out = tmp_path / "b_ghidra.json"
    out.write_text(_good_json())  # no markers
    assert _classify_analysis(out, tmp_path / "b", "feedfacefeedface", "deadbeef") == ("failed", 0)
    assert _classify_analysis(out, tmp_path / "b") == ("ok", 1)  # no expectation -> no check


# ── the stub table handed to the extractor, and the marker that proves it was read ────────────


def _resolution(names: dict[int, str]) -> StubResolution:
    return StubResolution(names=names, regions=())


def _run_with(
    tmp_path: Path,
    resolution: StubResolution | None,
    echo: Any = _echoed_stub_marker,
) -> tuple[Any, dict[str, str], Path]:
    """Run one binary through run_ghidra with a fake extractor that echoes ``echo(env)`` as its stub
    marker (the real one by default). Returns (result, env it was handed, output dir)."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    binary = tmp_path / "httpd"
    _write_small_elf(binary)
    sha8 = "deadbeef"
    output_dir = tmp_path / "out"
    seen: dict[str, str] = {}

    def fake_sub(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        seen.update(env)
        data = json.loads(_good_json(env))
        data["stub_marker"] = echo(env)
        out = output_dir / f"httpd_{sha8}_ghidra.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(data))
        return 0, ""

    runner = _make_runner(tmp_path)
    with (
        patch(f"{MODULE}._run_subprocess", fake_sub),
        patch(f"{MODULE}.resolve_stubs", return_value=resolution),
    ):
        result = runner.run_ghidra(
            binary, output_dir, timeout=60, arch="MIPS:BE:32:default", sha8=sha8
        )
    return result, seen, output_dir


def test_a_resolved_stub_table_is_written_for_the_binary_and_handed_in(tmp_path: Path) -> None:
    """The binary's own table, serialised next to its output, path passed in TMAP_STUB_NAMES.

    MUTATION (verified RED): drop the `env["TMAP_STUB_NAMES"] = ...` line -> the extractor echoes
    "none", the expected marker is the table's hash, the run is refused."""
    result, env, out = _run_with(tmp_path, _resolution({0x41EB38: "system", 0x400010: "memcpy"}))
    table = out / "httpd_deadbeef.stubs.tsv"
    assert result.success is True
    assert env["TMAP_STUB_NAMES"] == str(table)
    assert table.read_text() == "400010\tmemcpy\n41eb38\tsystem\n"


def test_no_resolution_hands_no_table_even_if_the_environment_carries_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A binary with no resolvable stubs gets no table — and must not inherit one from the parent
    process, which would be another binary's."""
    monkeypatch.setenv("TMAP_STUB_NAMES", str(tmp_path / "someone_elses.stubs.tsv"))
    result, env, out = _run_with(tmp_path, None)
    assert result.success is True
    assert "TMAP_STUB_NAMES" not in env
    assert not (out / "httpd_deadbeef.stubs.tsv").exists()


def test_an_output_that_read_the_wrong_stub_table_is_refused(tmp_path: Path) -> None:
    """A JVM that loaded another binary's table (or none, when one was meant) echoes a different
    hash; its output is not this binary's extraction, however right its pass and sha8 markers are.

    MUTATION (verified RED): drop the stub check from _markers_mismatch -> both runs succeed."""
    other = stub_table_marker({0x41EB38: "popen"})
    result, _, _ = _run_with(tmp_path / "a", _resolution({0x41EB38: "system"}), lambda env: other)
    assert result.success is False
    assert result.reason == "stale_output"
    result, _, _ = _run_with(tmp_path / "b", _resolution({0x41EB38: "system"}), lambda env: "none")
    assert result.success is False
    assert result.reason == "stale_output"


def test_a_table_where_none_was_meant_is_refused(tmp_path: Path) -> None:
    result, _, _ = _run_with(tmp_path, None, lambda env: stub_table_marker({0x41EB38: "system"}))
    assert result.success is False
    assert result.reason == "stale_output"


def test_an_earlier_runs_stub_table_is_cleared_before_the_run(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    stale = out / "httpd_deadbeef.stubs.tsv"
    stale.write_text("41eb38\tsystem\n")
    result, env, _ = _run_with(tmp_path, None)
    assert result.success is True
    assert not stale.exists()


def test_run_all_refuses_a_malformed_registry_before_any_jvm(tmp_path: Path) -> None:
    """A registry the extractor would reject stops the scan once, up front, instead of failing
    every binary one JVM at a time.

    MUTATION (verified RED): drop the validate_registry call from run_all -> subprocesses start."""
    script_dir = tmp_path / "ghidra"
    script_dir.mkdir()
    (script_dir / "extractor_names.tsv").write_text("not\ta\theader\n")
    rec = ElfRecord(
        path=tmp_path / "a",
        name="a",
        arch="x86:LE:64:default",
        elf_type="executable",
        sha256="a" * 64,
    )
    _write_small_elf(rec.path)
    calls: list[list[str]] = []

    def fake_sub(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        calls.append(cmd)
        return 1, ""

    runner = GhidraRunner(GhidraConfig(), headless=tmp_path / "hl", script_dir=script_dir)
    with patch(f"{MODULE}._run_subprocess", fake_sub), pytest.raises(RegistryError):
        runner.run_all([rec], tmp_path / "out")
    assert calls == []


# ── a launch failure is not a timeout; Ghidra's own analysis timeout is one ──────────


def test_a_launch_failure_is_not_a_timeout(tmp_path: Path) -> None:
    """A launcher that could not start spent no budget: recorded as launch_failed with no
    budget, so the next scan tries again instead of skipping it as a known timeout.

    MUTATION: report a launch error as returncode -1 again -> RED."""
    from treasure_map.lib.analyze.ghidra_runner import LAUNCH_FAILED_RC

    output_dir = tmp_path / "output"
    binary = tmp_path / "httpd"
    _write_small_elf(binary)

    def fake_sub(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        return LAUNCH_FAILED_RC, "[Errno 13] Permission denied: 'analyzeHeadless'"

    with patch(f"{MODULE}._run_subprocess", fake_sub):
        result = _make_runner(tmp_path).run_ghidra(
            binary, output_dir, timeout=60, arch="x86:LE:64:default", sha8="00000000"
        )
    assert result.success is False
    assert (result.reason, result.timeout_budget) == ("launch_failed", None)


def test_a_launch_error_from_the_subprocess_layer_is_launch_failed(tmp_path: Path) -> None:
    """MUTATION: return -1 for an exception raised by Popen -> RED."""
    from treasure_map.lib.analyze.ghidra_runner import LAUNCH_FAILED_RC, _run_subprocess

    rc, text = _run_subprocess([str(tmp_path / "missing-launcher")], {}, 5)
    assert rc == LAUNCH_FAILED_RC and text


def test_ghidras_own_analysis_timeout_is_a_timeout_not_ok(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """-analysisTimeoutPerFile stops the analysis, the post-script still exports, the exit is 0:
    the JSON is half an analysis. It must read as a timeout, and say so in the log.

    MUTATION: ignore the analysis-timeout line in the log -> the half JSON is cached as ok -> RED.
    MUTATION: drop the failure warning -> RED."""
    output_dir = tmp_path / "output"
    binary = tmp_path / "httpd"
    _write_small_elf(binary)
    sha8 = "aabb1122"

    def fake_sub(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        out = output_dir / f"httpd_{sha8}_ghidra.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(_good_json(env))
        (output_dir / f"httpd_{sha8}.log").write_text(
            "INFO  ANALYZING all memory\nINFO  REPORT: Analysis timed out at 60 seconds\n"
        )
        return 0, ""

    with caplog.at_level("WARNING"), patch(f"{MODULE}._run_subprocess", fake_sub):
        result = _make_runner(tmp_path).run_ghidra(
            binary, output_dir, timeout=60, arch="x86:LE:64:default", sha8=sha8, retry=False
        )
    assert result.success is False and result.reason == "timeout"
    assert any("httpd failed (timeout)" in r.getMessage() for r in caplog.records)


# ── run_all hands each record's FINAL result to on_final as it arrives (S1) ────────────────────


def _named_records(tmp_path: Path, names: list[str]) -> list[ElfRecord]:
    recs = [
        ElfRecord(
            path=tmp_path / n,
            name=n,
            arch="x86:LE:64:default",
            elf_type="executable",
            sha256=hashlib.sha256(n.encode()).hexdigest(),
        )
        for n in names
    ]
    for r in recs:
        _write_small_elf(r.path)
    return recs


def test_every_record_reaches_on_final_once_with_its_returned_result(tmp_path: Path) -> None:
    """T-S1. Five records: three succeed at once, one fails phase 1 and succeeds in phase 2, one
    fails phase 1 and its phase-2 retry crashes (phase 1's result stands). Each record is handed
    over exactly once, with the very object the returned list holds; a success before its own
    progress event; a phase-1 failure only once phase 1 is over.

    MUTATION (verified RED): call on_final for phase-1 failures too -> twice for two records.
    MUTATION (verified RED): skip on_final on a crashed retry -> one record never handed over."""
    names = ["ok_1", "ok_2", "ok_3", "late_ok", "never_ok"]
    recs = _named_records(tmp_path, names)
    attempts: dict[str, int] = {}

    def fake_sub(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        name = Path(cmd[-1]).name
        attempts[name] = attempts.get(name, 0) + 1
        if name == "never_ok" and attempts[name] == 2:
            raise RuntimeError("the retry crashed")
        if name.startswith("ok_") or (name == "late_ok" and attempts[name] == 2):
            out = Path(env["OUTPUT_DIR"]) / f"{name}_{env['SHA8']}_ghidra.json"
            out.write_text(_good_json(env))
            return 0, ""
        return -1, "timeout"

    events: list[tuple[str, str, Any]] = []
    runner = _make_runner(tmp_path)
    with patch(f"{MODULE}._run_subprocess", fake_sub):
        results = runner.run_all(
            recs,
            tmp_path / "out",
            progress_callback=lambda step, m: events.append(("progress", step, m["name"])),
            on_final=lambda rec, res: events.append(("final", rec.name, res)),
        )
    finals = [(n, res) for kind, n, res in events if kind == "final"]
    assert sorted(n for n, _ in finals) == sorted(names)  # each exactly once
    by_name = dict(finals)
    for i, rec in enumerate(recs):
        assert by_name[rec.name] is results[i]
    assert [results[i].success for i in range(5)] == [True, True, True, True, False]
    assert results[4].reason == "timeout"  # phase 1's result, the retry having crashed
    last_phase1 = max(i for i, e in enumerate(events) if e[:2] == ("progress", "ghidra"))
    for n in ("late_ok", "never_ok"):
        assert events.index(("final", n, by_name[n])) > last_phase1
    for n in ("ok_1", "ok_2", "ok_3"):
        assert events.index(("final", n, by_name[n])) < events.index(("progress", "ghidra", n))


def test_an_interrupt_in_phase_one_hands_over_only_what_finished(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """T-S2. A Ctrl-C arrives on the calling thread at the k-th progress event while a JVM is still
    running: on_final has been called k times (a success is handed over before its progress
    event), the interrupt propagates, and no process group is left registered or alive. The binary
    cut off is not reported as a failure.

    MUTATION (verified RED): hand a success over AFTER its progress event -> k-1 calls."""
    from treasure_map.lib.analyze import ghidra_runner

    real_sub = ghidra_runner._run_subprocess
    recs = _named_records(tmp_path, ["ok_1", "ok_2", "ok_3", "slow"])
    pids: list[int] = []

    def fake_sub(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        name = Path(cmd[-1]).name
        if name == "slow":
            return real_sub(["sleep", "30"], dict(env), 60)
        out = Path(env["OUTPUT_DIR"]) / f"{name}_{env['SHA8']}_ghidra.json"
        out.write_text(_good_json(env))
        return 0, ""

    k = 2
    seen = {"n": 0}

    def progress(step: str, meta: dict[str, Any]) -> None:
        if step != "ghidra":
            return
        seen["n"] += 1
        if seen["n"] == k:
            # wait until the slow JVM stand-in is really running, so the teardown has one to kill
            import time

            deadline = time.monotonic() + 10
            while not ghidra_runner._active_pgids and time.monotonic() < deadline:
                time.sleep(0.02)
            pids.extend(ghidra_runner._active_pgids)
            raise KeyboardInterrupt

    finals: list[str] = []
    runner = GhidraRunner(GhidraConfig(max_parallel_jvms=4), headless=tmp_path / "hl")
    try:
        with (
            caplog.at_level("WARNING"),
            patch(f"{MODULE}._run_subprocess", fake_sub),
            patch(f"{MODULE}.clamp_parallelism_to_memory", lambda n: (n, None)),
            pytest.raises(KeyboardInterrupt),
        ):
            runner.run_all(
                recs,
                tmp_path / "out",
                progress_callback=progress,
                on_final=lambda rec, res: finals.append(rec.name),
            )
    finally:
        ghidra_runner._reset_shutdown()
    assert len(finals) == k
    assert pids, "the slow stand-in never started; the teardown had nothing to kill"
    assert not ghidra_runner._active_pgids
    for pid in pids:
        with pytest.raises(ProcessLookupError):
            os.killpg(pid, 0)
    assert not any("slow failed" in r.getMessage() for r in caplog.records)


def test_a_failing_on_final_tears_the_pool_down(tmp_path: Path) -> None:
    """T-S3. ``on_final`` raising (a failed store) is handled like an interrupt: launches are
    refused, the live groups are killed, and the error propagates.

    MUTATION (verified RED): catch only KeyboardInterrupt again -> no shutdown is begun."""
    from treasure_map.lib.analyze import ghidra_runner

    recs = _named_records(tmp_path, ["ok_1", "ok_2", "ok_3"])

    def fake_sub(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        name = Path(cmd[-1]).name
        (Path(env["OUTPUT_DIR"]) / f"{name}_{env['SHA8']}_ghidra.json").write_text(_good_json(env))
        return 0, ""

    calls = {"n": 0, "terminate": 0}
    real_terminate = ghidra_runner.terminate_all

    def spy_terminate(grace: float = 2.0) -> None:
        calls["terminate"] += 1
        real_terminate(grace)

    def failing_final(rec: ElfRecord, res: Any) -> None:
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("the store failed")

    runner = _make_runner(tmp_path)
    try:
        with (
            patch(f"{MODULE}._run_subprocess", fake_sub),
            patch(f"{MODULE}.terminate_all", spy_terminate),
            pytest.raises(RuntimeError, match="the store failed"),
        ):
            runner.run_all(recs, tmp_path / "out", on_final=failing_final)
        assert ghidra_runner._shutting_down is True
        assert calls["terminate"] >= 1
    finally:
        ghidra_runner._reset_shutdown()
