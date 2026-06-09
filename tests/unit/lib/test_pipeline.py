# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for lib/analyze/pipeline.py.

Ghidra is fully mocked — these tests never touch analyzeHeadless.
They verify fail-fast behaviour, dirty-set routing, and result fields.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from treasure_map.lib.analyze.elf_inventory import ElfRecord
from treasure_map.lib.analyze.ghidra_runner import GhidraResult
from treasure_map.lib.analyze.pipeline import AnalyzeResult, run_analyze
from treasure_map.lib.config.config import Config
from treasure_map.lib.errors import GhidraNotFoundError
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


def _mock_ingest(dirty_shas: set[str]) -> MagicMock:
    """Return a mock ingest_elfs that reports the given shas as dirty."""
    sha_to_id = {sha: i + 1 for i, sha in enumerate(dirty_shas)}
    return MagicMock(return_value=(sha_to_id, dirty_shas))


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


# ── dirty set routing ─────────────────────────────────────────────────────────


async def test_dirty_set_empty_skips_ghidra(tmp_path: Path) -> None:
    """When ingest_elfs reports 0 dirty shas, runner.run_all is not called."""
    rec = _rec()
    runner = _mock_runner()

    with patch(f"{MODULE}.GhidraRunner", return_value=runner):
        with patch(f"{MODULE}.scan_filesystem", return_value=[rec]):
            with patch(f"{MODULE}.ingest_elfs", _mock_ingest(set())):
                with Workspace(tmp_path / "ws") as ws:
                    result = await run_analyze(tmp_path / "fs", ws, _cfg())

    runner.run_all.assert_not_called()
    assert result.binary_count == 1
    assert result.dirty_count == 0
    assert result.ghidra_skipped == 1
    assert result.ghidra_ok == 0


async def test_dirty_set_partial_only_runs_dirty(tmp_path: Path) -> None:
    """With 2 records and 1 already done, run_all receives only the dirty one."""
    rec1 = _rec("httpd", "aaa111")
    rec2 = _rec("dropbear", "bbb222")
    records = [rec1, rec2]

    captured: list[list[ElfRecord]] = []

    runner = _mock_runner()
    runner.run_all.side_effect = lambda recs, *a, **kw: (
        captured.append(list(recs)) or [_ok_ghidra(r) for r in recs]
    )

    with patch(f"{MODULE}.GhidraRunner", return_value=runner):
        with patch(f"{MODULE}.scan_filesystem", return_value=records):
            # Only rec2 is dirty (rec1 has ghidra_ok=1 in DB)
            with patch(f"{MODULE}.ingest_elfs", _mock_ingest({"bbb222"})):
                with Workspace(tmp_path / "ws") as ws:
                    result = await run_analyze(tmp_path / "fs", ws, _cfg())

    assert len(captured) == 1
    assert len(captured[0]) == 1
    assert captured[0][0].sha256 == "bbb222"
    assert result.binary_count == 2
    assert result.dirty_count == 1
    assert result.ghidra_skipped == 1


# ── empty filesystem ──────────────────────────────────────────────────────────


async def test_empty_fs_ghidra_skipped(tmp_path: Path) -> None:
    """Zero ELFs found → Ghidra step is not called."""
    runner = _mock_runner()
    with patch(f"{MODULE}.GhidraRunner", return_value=runner):
        with patch(f"{MODULE}.scan_filesystem", return_value=[]):
            with Workspace(tmp_path / "ws") as ws:
                result = await run_analyze(tmp_path / "fs", ws, _cfg())

    runner.run_all.assert_not_called()
    assert result.binary_count == 0
    assert result.dirty_count == 0
    assert result.ghidra_skipped == 0


# ── AnalyzeResult fields ──────────────────────────────────────────────────────


async def test_analyze_result_fields(tmp_path: Path) -> None:
    """AnalyzeResult carries correct counts and db_path."""
    rec1 = _rec("httpd", "aaa111")
    rec2 = _rec("dropbear", "bbb222")
    records = [rec1, rec2]

    runner = _mock_runner([_ok_ghidra(rec1), _fail_ghidra(rec2)])
    with patch(f"{MODULE}.GhidraRunner", return_value=runner):
        with patch(f"{MODULE}.scan_filesystem", return_value=records):
            # Both records are dirty
            with patch(f"{MODULE}.ingest_elfs", _mock_ingest({"aaa111", "bbb222"})):
                with Workspace(tmp_path / "ws") as ws:
                    result = await run_analyze(tmp_path / "fs", ws, _cfg())

    assert isinstance(result, AnalyzeResult)
    assert result.binary_count == 2
    assert result.dirty_count == 2
    assert result.ghidra_ok == 1
    assert result.ghidra_failed == 1
    assert result.ghidra_skipped == 0
    assert result.functions_ingested == 0
    assert result.imports_ingested == 0
    assert result.exports_ingested == 0
    assert result.strings_ingested == 0
    assert result.layer0_xrefs == 0
    assert result.layer1_xrefs == 0
    assert result.layer2_xrefs == 0
    assert result.layer3_xrefs == 0
    assert result.strings_classified == 0
    assert result.total_xrefs == 0
    assert result.db_path == tmp_path / "ws" / "analysis.db"
    assert result.elapsed > 0


# ── progress callback ─────────────────────────────────────────────────────────


async def test_progress_callback_passed_to_run_all(tmp_path: Path) -> None:
    """run_analyze forwards progress_callback to GhidraRunner.run_all."""
    rec = _rec()
    runner = _mock_runner([_ok_ghidra(rec)])

    def cb(s: str, m: dict[str, Any]) -> None:
        pass

    with patch(f"{MODULE}.GhidraRunner", return_value=runner):
        with patch(f"{MODULE}.scan_filesystem", return_value=[rec]):
            with patch(f"{MODULE}.ingest_elfs", _mock_ingest({rec.sha256})):
                with Workspace(tmp_path / "ws") as ws:
                    await run_analyze(tmp_path / "fs", ws, _cfg(), progress_callback=cb)

    _args, kwargs = runner.run_all.call_args
    assert kwargs.get("progress_callback") is cb or cb in _args
