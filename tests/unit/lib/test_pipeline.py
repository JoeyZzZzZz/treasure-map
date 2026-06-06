# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for lib/analyze/pipeline.py.

Ghidra is fully mocked — these tests never touch analyzeHeadless.
They verify the checkpoint/skip logic, fail-fast behavior, and result fields.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from treasure_map.lib.analyze.db_ingest import ingest_elfs
from treasure_map.lib.analyze.elf_inventory import ElfRecord
from treasure_map.lib.analyze.ghidra_runner import GhidraResult
from treasure_map.lib.analyze.pipeline import AnalyzeResult, run_analyze
from treasure_map.lib.config.config import Config
from treasure_map.lib.errors import GhidraNotFoundError
from treasure_map.lib.storage.connection import open_db
from treasure_map.lib.workspace.workspace import Workspace

MODULE = "treasure_map.lib.analyze.pipeline"


# ── helpers ───────────────────────────────────────────────────────────────────


def _cfg() -> Config:
    return Config()


def _rec(name: str = "httpd", sha: str = "abc123def4567890") -> ElfRecord:
    return ElfRecord(
        path=Path(f"/fake/bin/{name}"),
        name=name,
        arch="ARM:LE:32:v7",
        elf_type="executable",
        sha256=sha,
        dt_needed=["libc.so.0"],
        protections={"nx": True, "pie": False, "canary": False, "relro": "none", "fortify": False},
    )


def _ok_ghidra(rec: ElfRecord) -> GhidraResult:
    return GhidraResult(
        binary=rec.path, output_file=Path("/fake/out.json"), success=True, elapsed=1.0
    )


def _fail_ghidra(rec: ElfRecord) -> GhidraResult:
    return GhidraResult(binary=rec.path, output_file=None, success=False, elapsed=0.5)


def _mock_runner(run_all_return: list[GhidraResult] | None = None) -> MagicMock:
    runner = MagicMock()
    runner.get_headless.return_value = Path("/fake/headless")
    runner.run_all.return_value = run_all_return or []
    return runner


# ── fail-fast ─────────────────────────────────────────────────────────────────


async def test_fail_fast_before_any_disk_work(tmp_path: Path) -> None:
    """GhidraNotFoundError is raised before scan_filesystem is called."""
    runner = MagicMock()
    runner.get_headless.side_effect = GhidraNotFoundError("Ghidra not found")

    with patch(f"{MODULE}.GhidraRunner", return_value=runner):
        with patch(f"{MODULE}.scan_filesystem") as mock_scan:
            with Workspace(tmp_path / "ws") as ws:
                with pytest.raises(GhidraNotFoundError):
                    await run_analyze(tmp_path / "fs", ws, _cfg())

            mock_scan.assert_not_called()


# ── find_elfs checkpoint ──────────────────────────────────────────────────────


async def test_find_elfs_checkpoint_skips_scan(tmp_path: Path) -> None:
    """When find_elfs is already done, scan_filesystem is not called."""
    rec = _rec()

    # Pre-populate DB and mark step done
    ws_path = tmp_path / "ws"
    Workspace(ws_path).close()  # initialise workspace dir + DB schema
    conn = open_db(ws_path / "analysis.db")
    ingest_elfs(conn, [rec])
    conn.close()
    with Workspace(ws_path) as ws:
        ws.mark_done("find_elfs", {"binary_count": 1})

    runner = _mock_runner()
    with patch(f"{MODULE}.GhidraRunner", return_value=runner):
        with patch(f"{MODULE}.scan_filesystem") as mock_scan:
            with Workspace(ws_path) as ws:
                result = await run_analyze(tmp_path / "fs", ws, _cfg())

            mock_scan.assert_not_called()

    assert result.binary_count == 1


async def test_find_elfs_checkpoint_restores_dt_needed(tmp_path: Path) -> None:
    """Records loaded from DB have dt_needed and protections restored."""
    rec = _rec()
    ws_path = tmp_path / "ws"
    Workspace(ws_path).close()
    conn = open_db(ws_path / "analysis.db")
    ingest_elfs(conn, [rec])
    conn.close()
    with Workspace(ws_path) as ws:
        ws.mark_done("find_elfs")

    captured: list[list[ElfRecord]] = []
    runner = _mock_runner()
    runner.run_all.side_effect = lambda recs, *a, **kw: captured.append(recs) or []

    with patch(f"{MODULE}.GhidraRunner", return_value=runner):
        with Workspace(ws_path) as ws:
            await run_analyze(tmp_path / "fs", ws, _cfg())

    assert len(captured) == 1
    loaded = captured[0][0]
    assert loaded.dt_needed == ["libc.so.0"]


# ── ghidra checkpoint ─────────────────────────────────────────────────────────


async def test_ghidra_checkpoint_skips_run_all(tmp_path: Path) -> None:
    """When ghidra is already done, runner.run_all is not called."""
    rec = _rec()
    ws_path = tmp_path / "ws"
    Workspace(ws_path).close()
    conn = open_db(ws_path / "analysis.db")
    ingest_elfs(conn, [rec])
    conn.close()
    with Workspace(ws_path) as ws:
        ws.mark_done("find_elfs", {"binary_count": 1})
        ws.mark_done("ghidra", {"ok": 1, "failed": 0})

    runner = _mock_runner()
    with patch(f"{MODULE}.GhidraRunner", return_value=runner):
        with Workspace(ws_path) as ws:
            result = await run_analyze(tmp_path / "fs", ws, _cfg())

        runner.run_all.assert_not_called()

    assert result.ghidra_ok == 0  # 0 because step was skipped this run
    assert result.ghidra_failed == 0


# ── empty records ─────────────────────────────────────────────────────────────


async def test_empty_fs_ghidra_skipped_and_checkpointed(tmp_path: Path) -> None:
    """Zero ELFs → ghidra step is skipped but both steps are checkpointed."""
    runner = _mock_runner()
    with patch(f"{MODULE}.GhidraRunner", return_value=runner):
        with patch(f"{MODULE}.scan_filesystem", return_value=[]):
            with Workspace(tmp_path / "ws") as ws:
                result = await run_analyze(tmp_path / "fs", ws, _cfg())

            runner.run_all.assert_not_called()

    assert result.binary_count == 0

    with Workspace(tmp_path / "ws") as ws:
        assert ws.is_done("find_elfs")
        assert ws.is_done("ghidra")


# ── progress callback ─────────────────────────────────────────────────────────


async def test_progress_callback_fires_on_both_steps(tmp_path: Path) -> None:
    """Workspace fires progress_callback when each step is marked done."""
    rec = _rec()
    steps: list[str] = []

    runner = _mock_runner([_ok_ghidra(rec)])
    with patch(f"{MODULE}.GhidraRunner", return_value=runner):
        with patch(f"{MODULE}.scan_filesystem", return_value=[rec]):
            with patch(f"{MODULE}.ingest_elfs"):
                with Workspace(
                    tmp_path / "ws", progress_callback=lambda s, _m: steps.append(s)
                ) as ws:
                    await run_analyze(tmp_path / "fs", ws, _cfg())

    assert "find_elfs" in steps
    assert "ghidra" in steps


# ── AnalyzeResult fields ──────────────────────────────────────────────────────


async def test_analyze_result_fields(tmp_path: Path) -> None:
    """AnalyzeResult carries correct counts and db_path."""
    rec1 = _rec("httpd", "aaa111")
    rec2 = _rec("dropbear", "bbb222")
    records = [rec1, rec2]

    runner = _mock_runner([_ok_ghidra(rec1), _fail_ghidra(rec2)])
    with patch(f"{MODULE}.GhidraRunner", return_value=runner):
        with patch(f"{MODULE}.scan_filesystem", return_value=records):
            with patch(f"{MODULE}.ingest_elfs"):
                with Workspace(tmp_path / "ws") as ws:
                    result = await run_analyze(tmp_path / "fs", ws, _cfg())

    assert isinstance(result, AnalyzeResult)
    assert result.binary_count == 2
    assert result.ghidra_ok == 1
    assert result.ghidra_failed == 1
    assert result.db_path == tmp_path / "ws" / "analysis.db"
    assert result.elapsed > 0


# ── run_analyze propagates progress_callback to run_all ──────────────────────


async def test_progress_callback_passed_to_run_all(tmp_path: Path) -> None:
    """run_analyze forwards progress_callback to GhidraRunner.run_all."""
    rec = _rec()
    runner = _mock_runner([_ok_ghidra(rec)])

    def cb(s: str, m: dict[str, Any]) -> None:
        pass

    with patch(f"{MODULE}.GhidraRunner", return_value=runner):
        with patch(f"{MODULE}.scan_filesystem", return_value=[rec]):
            with patch(f"{MODULE}.ingest_elfs"):
                with Workspace(tmp_path / "ws") as ws:
                    await run_analyze(tmp_path / "fs", ws, _cfg(), progress_callback=cb)

    _args, kwargs = runner.run_all.call_args
    assert kwargs.get("progress_callback") is cb or cb in _args
