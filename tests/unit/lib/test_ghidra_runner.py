# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import json
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
from treasure_map.lib.config.config import GhidraConfig, GhidraLocalConfig
from treasure_map.lib.errors import GhidraNotFoundError

# ── helpers ───────────────────────────────────────────────────────────────────


def _make_runner(tmp_path: Path, headless: Path | None = None) -> GhidraRunner:
    """Return a GhidraRunner with a pre-set headless path (skip discovery)."""
    hl = headless or (tmp_path / "fake_analyzeHeadless")
    return GhidraRunner(GhidraConfig(), headless=hl)


def _write_small_elf(path: Path) -> None:
    """Write a minimal valid ELF magic so stat().st_size works."""
    path.write_bytes(b"\x7fELF" + b"\x00" * 100)


def _good_json() -> str:
    """Return a >200-byte valid Ghidra output JSON."""
    return json.dumps(
        {
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
    assert "-postScript" in cmd
    assert cmd[cmd.index("-postScript") + 1] == "ExportFunctions.java"
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


def test_classify_empty_functions_on_code_binary_is_failed(tmp_path: Path) -> None:
    # ★ Red-line: a >200-byte but functionless shell for a binary that HAS code is a FAILED
    # analysis, never "clean" — it must not be frozen as done.
    out = tmp_path / "b_ghidra.json"
    out.write_text(json.dumps({"functions": [], "imports": [], "exports": [], "strings": []}))
    with patch(f"{MODULE}.has_substantial_text", lambda _b: True):
        assert _classify_analysis(out, tmp_path / "b") == ("failed", 0)


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

    def fake_sub(cmd: list[str], env: dict[str, str], timeout: int) -> tuple[int, str]:
        out = output_dir / f"httpd_{sha8}_ghidra.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(_good_json())
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

    def fake_sub(cmd: list[str], env: dict[str, str], timeout: int) -> tuple[int, str]:
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

    def fake_sub(cmd: list[str], env: dict[str, str], timeout: int) -> tuple[int, str]:
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

    def fake_sub(cmd: list[str], env: dict[str, str], timeout: int) -> tuple[int, str]:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            (output_dir / f"httpd_{sha8}.log").write_text("ERROR: Import failed for httpd")
            return 1, "Import failed"
        # Second call: produce valid output
        (output_dir / f"httpd_{sha8}_ghidra.json").write_text(_good_json())
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


def test_run_ghidra_no_retry_without_import_failed(tmp_path: Path) -> None:
    """Only one attempt when failure log does NOT contain 'Import failed'."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    binary = tmp_path / "httpd"
    _write_small_elf(binary)
    sha8 = "deadc0de"
    call_count = 0

    def fake_sub(cmd: list[str], env: dict[str, str], timeout: int) -> tuple[int, str]:
        nonlocal call_count
        call_count += 1
        (output_dir / f"httpd_{sha8}.log").write_text("ERROR: OutOfMemoryError")
        return 1, "OOM"

    runner = _make_runner(tmp_path)
    with patch(f"{MODULE}._run_subprocess", fake_sub):
        result = runner.run_ghidra(
            binary, output_dir, timeout=60, arch="x86:LE:64:default", sha8=sha8
        )

    assert call_count == 1
    assert result.success is False
    assert result.retried is False


# ── run_all ───────────────────────────────────────────────────────────────────


def test_run_all_calls_progress_callback(tmp_path: Path) -> None:
    """progress_callback is invoked once per record with correct keys."""
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

    def fake_sub(cmd: list[str], env: dict[str, str], timeout: int) -> tuple[int, str]:
        return 1, ""

    progress: list[tuple[str, dict[str, Any]]] = []
    runner = _make_runner(tmp_path)
    with patch(f"{MODULE}._run_subprocess", fake_sub):
        runner.run_all(
            records, tmp_path / "out", progress_callback=lambda s, m: progress.append((s, m))
        )

    assert len(progress) == 2
    assert all(step == "ghidra" for step, _ in progress)
    assert {m["name"] for _, m in progress} == {"a", "b"}


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

    def fake_sub(cmd: list[str], env: dict[str, str], timeout: int) -> tuple[int, str]:
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


# ── Fix A: extraction-pass content hash (cache-key dimension) ─────────────────


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
