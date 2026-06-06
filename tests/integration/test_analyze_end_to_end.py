# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""End-to-end pipeline integration test — Round 1 Self-Test.

Ghidra is mocked so the find_elfs + DB + checkpoint round-trip runs in CI
without Ghidra installed.  A separate @skipif(no_ghidra) test covers the
full pipeline including analyzeHeadless.
"""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

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


# ── Round 1 Self-Test (find_elfs, Ghidra mocked) ─────────────────────────────


@pytest.mark.skipif(no_fixture, reason="ELF fixtures missing")
def test_round1_find_elfs_self_test(tmp_path: Path) -> None:
    """Round 1: running twice with same workspace hits checkpoint on second run.

    Verifies:
    - Real scan_filesystem + ingest_elfs populate the DB with 2 ELFs
    - Second run hits find_elfs checkpoint and reloads records from DB
    - binary_count is identical across both runs
    - scan_filesystem is called exactly once
    - DB binaries table has exactly 2 rows
    """
    fs_root = tmp_path / "rootfs"
    (fs_root / "bin").mkdir(parents=True)
    shutil.copy(_TRUE_ELF, fs_root / "bin" / "true")
    shutil.copy(_LIBZ_ELF, fs_root / "bin" / "libz.so")

    workspace_path = tmp_path / "workspace"
    cfg = Config()
    runner = _mock_runner()

    # Use real scan_filesystem; only mock GhidraRunner
    with patch(_PIPELINE_MODULE + ".GhidraRunner", return_value=runner) as mock_runner_cls:
        mock_runner_cls.return_value = runner

        # First run — fresh workspace
        with Workspace(workspace_path) as ws:
            result1 = asyncio.run(run_analyze(fs_root, ws, cfg))

        assert result1.binary_count == 2

        # Second run — same workspace: find_elfs checkpoint must hit
        runner2 = _mock_runner()
        with patch(_PIPELINE_MODULE + ".GhidraRunner", return_value=runner2):
            with patch(_PIPELINE_MODULE + ".scan_filesystem") as mock_scan2:
                with Workspace(workspace_path) as ws:
                    result2 = asyncio.run(run_analyze(fs_root, ws, cfg))

                mock_scan2.assert_not_called()

    assert result2.binary_count == result1.binary_count

    # DB must have exactly 2 unique binaries
    conn = open_db(workspace_path / "analysis.db")
    db_count = conn.execute("SELECT COUNT(*) FROM binaries").fetchone()[0]
    conn.close()
    assert db_count == 2

    # Both steps are checkpointed
    with Workspace(workspace_path) as ws:
        assert ws.is_done("find_elfs")
        assert ws.is_done("ghidra")


@pytest.mark.skipif(no_ghidra, reason="analyzeHeadless not in PATH")
@pytest.mark.skipif(no_fixture, reason="ELF fixtures missing")
def test_round1_full_pipeline(tmp_path: Path) -> None:
    """Round 1 Full: scan + real Ghidra, second run checkpointed."""
    fs_root = tmp_path / "rootfs"
    (fs_root / "bin").mkdir(parents=True)
    shutil.copy(_TRUE_ELF, fs_root / "bin" / "true")

    workspace_path = tmp_path / "workspace"
    cfg = Config()

    # First run
    with Workspace(workspace_path) as ws:
        result1 = asyncio.run(run_analyze(fs_root, ws, cfg))

    assert result1.binary_count >= 1

    # Second run — both steps should hit checkpoint
    with patch(_PIPELINE_MODULE + ".scan_filesystem") as mock_scan:
        with patch(_PIPELINE_MODULE + ".GhidraRunner") as mock_runner_cls:
            mock_runner = _mock_runner()
            mock_runner_cls.return_value = mock_runner
            with Workspace(workspace_path) as ws:
                result2 = asyncio.run(run_analyze(fs_root, ws, cfg))
            mock_scan.assert_not_called()
            mock_runner.run_all.assert_not_called()

    assert result2.binary_count == result1.binary_count
