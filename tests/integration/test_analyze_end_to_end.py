# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""End-to-end pipeline integration tests — Round 1 and Round 2.

Ghidra is mocked so the scan + DB + partial-invalidation logic runs in CI
without analyzeHeadless installed.  A separate @skipif(no_ghidra) test covers
the full pipeline including real Ghidra.
"""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from treasure_map.lib.analyze.elf_inventory import ElfRecord
from treasure_map.lib.analyze.ghidra_runner import GhidraResult
from treasure_map.lib.analyze.pipeline import run_analyze
from treasure_map.lib.config.config import Config
from treasure_map.lib.storage.connection import open_db
from treasure_map.lib.workspace.workspace import Workspace

_FIXTURES = Path(__file__).parent.parent / "fixtures" / "elfs"
_TRUE_ELF = _FIXTURES / "true_x86_64"
_LIBZ_ELF = _FIXTURES / "libz_x86_64.so"

no_fixture = not _TRUE_ELF.exists() or not _LIBZ_ELF.exists()
no_ghidra = shutil.which("analyzeHeadless") is None

_PIPELINE_MODULE = "treasure_map.lib.analyze.pipeline"


def _mock_runner() -> MagicMock:
    runner = MagicMock()
    runner.get_headless.return_value = Path("/fake/headless")
    runner.run_all.return_value = []
    return runner


def _succeed_all(recs: list[ElfRecord], *_a: object, **_kw: object) -> list[GhidraResult]:
    """Mock run_all side_effect: return success for every record."""
    return [
        GhidraResult(binary=r.path, output_file=Path("/fake"), success=True, elapsed=1.0)
        for r in recs
    ]


# ── Round 1 Self-Test (find_elfs + ingest, Ghidra mocked) ────────────────────


@pytest.mark.skipif(no_fixture, reason="ELF fixtures missing")
def test_round1_self_test(tmp_path: Path) -> None:
    """Round 1: running twice with same workspace.

    First run: real scan + ingest; Ghidra mocked to succeed.
    Second run: scan_filesystem still runs; dirty=0 (all ghidra_ok=1); run_all not called.

    Verifies:
    - binary_count == 2 on both runs
    - dirty_count == 0 on second run
    - ghidra_skipped == 2 on second run
    - DB has exactly 2 rows
    """
    fs_root = tmp_path / "rootfs"
    (fs_root / "bin").mkdir(parents=True)
    shutil.copy(_TRUE_ELF, fs_root / "bin" / "true")
    shutil.copy(_LIBZ_ELF, fs_root / "bin" / "libz.so")

    workspace_path = tmp_path / "workspace"
    cfg = Config()

    # First run: Ghidra succeeds for both binaries → both ghidra_ok=1
    runner1 = _mock_runner()
    runner1.run_all.side_effect = _succeed_all

    with patch(_PIPELINE_MODULE + ".GhidraRunner", return_value=runner1):
        with Workspace(workspace_path) as ws:
            result1 = asyncio.run(run_analyze(fs_root, ws, cfg))

    assert result1.binary_count == 2
    assert result1.dirty_count == 2
    assert result1.ghidra_ok == 2

    # Second run: scan runs, but all sha256 have ghidra_ok=1 → dirty=0
    runner2 = _mock_runner()
    with patch(_PIPELINE_MODULE + ".GhidraRunner", return_value=runner2):
        with Workspace(workspace_path) as ws:
            result2 = asyncio.run(run_analyze(fs_root, ws, cfg))

    runner2.run_all.assert_not_called()
    assert result2.binary_count == 2
    assert result2.dirty_count == 0
    assert result2.ghidra_skipped == 2

    # DB must have exactly 2 rows
    conn = open_db(workspace_path / "analysis.db")
    db_count = conn.execute("SELECT COUNT(*) FROM binaries").fetchone()[0]
    conn.close()
    assert db_count == 2


# ── Round 2 Partial Invalidation ─────────────────────────────────────────────


@pytest.mark.skipif(no_fixture, reason="ELF fixtures missing")
def test_round2_partial_invalidation(tmp_path: Path) -> None:
    """Round 2: patch diff scenario (partial invalidation).

    Simulates a vendor releasing a new firmware version where one binary
    has been patched.  Only the modified binary should be re-analyzed by
    Ghidra; the unchanged binary should be skipped via sha256 cache.

    Real-world scenario: user analyzed firmware v1.058, vendor releases
    v1.060 with httpd patched for CVE-XXXX.  User re-extracts to same dir
    and re-runs `tmap analyze`.  Only httpd should re-run Ghidra.

    Test technique: flip 1 byte in libz ELF header to change its sha256.
    This is a test shortcut that simulates "binary content changed by vendor
    patch" — not a use case where users manually edit bytes.
    """
    fs_root = tmp_path / "rootfs"
    (fs_root / "bin").mkdir(parents=True)
    shutil.copy(_TRUE_ELF, fs_root / "bin" / "true")
    shutil.copy(_LIBZ_ELF, fs_root / "bin" / "libz.so")

    workspace_path = tmp_path / "workspace"
    cfg = Config()

    # First run: both binaries are dirty → Ghidra succeeds for both
    runner1 = _mock_runner()
    runner1.run_all.side_effect = _succeed_all

    with patch(_PIPELINE_MODULE + ".GhidraRunner", return_value=runner1):
        with Workspace(workspace_path) as ws:
            result1 = asyncio.run(run_analyze(fs_root, ws, cfg))

    assert result1.binary_count == 2
    assert result1.dirty_count == 2
    assert result1.ghidra_ok == 2
    assert result1.ghidra_skipped == 0

    # Flip 1 byte in e_type field (offset 0x10) of libz.so.
    # Simulates: vendor released a patched binary in new firmware version.
    libz_path = fs_root / "bin" / "libz.so"
    data = bytearray(libz_path.read_bytes())
    data[0x10] ^= 0xFF
    libz_path.write_bytes(bytes(data))

    # Second run: only libz should be dirty (sha256 changed)
    runner2 = _mock_runner()
    captured_records: list[list[ElfRecord]] = []

    def _capture_and_succeed(
        recs: list[ElfRecord], *_a: object, **_kw: object
    ) -> list[GhidraResult]:
        captured_records.append(list(recs))
        return _succeed_all(recs)

    runner2.run_all.side_effect = _capture_and_succeed

    with patch(_PIPELINE_MODULE + ".GhidraRunner", return_value=runner2):
        with Workspace(workspace_path) as ws:
            result2 = asyncio.run(run_analyze(fs_root, ws, cfg))

    assert result2.binary_count == 2
    assert result2.dirty_count == 1, "Only libz should be dirty (sha256 changed)"
    assert result2.ghidra_skipped == 1, "true should be skipped (sha256 unchanged)"
    assert len(captured_records) == 1, "run_all called once"
    assert len(captured_records[0]) == 1, "exactly 1 record passed to run_all"
    assert captured_records[0][0].name == "libz.so"

    # DB state after Run 2: 3 rows total (true + old libz + new libz)
    conn = open_db(workspace_path / "analysis.db")
    try:
        all_rows = conn.execute("SELECT sha256, ghidra_ok FROM binaries").fetchall()
        assert len(all_rows) == 3, "content-identity: old libz row is preserved"
        assert all(row["ghidra_ok"] == 1 for row in all_rows), "all 3 rows analyzed"

        # current_binaries view returns exactly 2 (true + new libz from this scan)
        current = conn.execute("SELECT name FROM current_binaries").fetchall()
        current_names = sorted(row["name"] for row in current)
        assert current_names == ["libz.so", "true"]
    finally:
        conn.close()


# ── Round 1 Full Pipeline (requires real Ghidra) ─────────────────────────────


@pytest.mark.skipif(no_ghidra, reason="analyzeHeadless not in PATH")
@pytest.mark.skipif(no_fixture, reason="ELF fixtures missing")
def test_round1_full_pipeline(tmp_path: Path) -> None:
    """Round 1 Full: scan + real Ghidra, second run all cached."""
    fs_root = tmp_path / "rootfs"
    (fs_root / "bin").mkdir(parents=True)
    shutil.copy(_TRUE_ELF, fs_root / "bin" / "true")

    workspace_path = tmp_path / "workspace"
    cfg = Config()

    # First run: real Ghidra
    with Workspace(workspace_path) as ws:
        result1 = asyncio.run(run_analyze(fs_root, ws, cfg))

    assert result1.binary_count >= 1

    # Second run: all sha256 should be done → run_all not called
    with patch(_PIPELINE_MODULE + ".GhidraRunner") as mock_runner_cls:
        mock_runner = _mock_runner()
        mock_runner_cls.return_value = mock_runner
        with Workspace(workspace_path) as ws:
            result2 = asyncio.run(run_analyze(fs_root, ws, cfg))
        mock_runner.run_all.assert_not_called()

    assert result2.binary_count == result1.binary_count
    assert result2.dirty_count == 0
