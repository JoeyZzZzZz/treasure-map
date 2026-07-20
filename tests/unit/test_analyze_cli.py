# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the analyze CLI wrapper.

Stubs load_config / Workspace / run_analyze so the command runs without Ghidra,
proving the thin wrapper drives the pipeline and prints the result block.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from click.testing import CliRunner

from treasure_map.cli.analyze_cli import analyze
from treasure_map.lib.config.config import Config


def _fake_result(db_path: Path) -> SimpleNamespace:
    """A stand-in AnalyzeResult exposing every attribute the CLI prints."""
    fields = {
        "db_path": db_path,
        "binary_count": 0,
        "dirty_count": 0,
        "ghidra_ok": 0,
        "ghidra_failed": 0,
        "ghidra_skipped": 0,
        "functions_ingested": 0,
        "imports_ingested": 0,
        "exports_ingested": 0,
        "strings_ingested": 0,
        "layer0_xrefs": 0,
        "layer1_xrefs": 0,
        "layer2_xrefs": 0,
        "layer3_xrefs": 0,
        "strings_classified": 0,
        "total_xrefs": 0,
        "non_binary_files_ingested": 0,
        "script_calls_ingested": 0,
        "config_entries_ingested": 0,
        "credentials_ingested": 0,
        "web_endpoints_ingested": 0,
        "elapsed": 0.1,
        "incomplete_binaries": [],
    }
    return SimpleNamespace(**fields)


class _DummyWorkspace:
    """Minimal context-manager workspace stub."""

    def __init__(self, path: Path, **_: Any) -> None:
        self.path = path
        self.db_path = path / "analysis.db"

    def __enter__(self) -> _DummyWorkspace:
        return self

    def __exit__(self, *_: object) -> None:
        return None


def _patch_pipeline(monkeypatch: pytest.MonkeyPatch, db_path: Path) -> None:
    """Stub load_config / Workspace / run_analyze so analyze runs without Ghidra."""

    async def _fake_run_analyze(*_: Any, **__: Any) -> SimpleNamespace:
        return _fake_result(db_path)

    monkeypatch.setattr(
        "treasure_map.lib.config.config.load_config",
        lambda _cfg=None: Config(llm=None),
    )
    monkeypatch.setattr(
        "treasure_map.lib.workspace.workspace.Workspace",
        _DummyWorkspace,
    )
    monkeypatch.setattr(
        "treasure_map.lib.analyze.pipeline.run_analyze",
        _fake_run_analyze,
    )


def test_analyze_runs_pipeline_and_prints_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_pipeline(monkeypatch, tmp_path / "analysis.db")

    fs_root = tmp_path / "fs"
    fs_root.mkdir()
    result = CliRunner().invoke(analyze, [str(fs_root), "--workspace", "ws"])

    assert result.exit_code == 0, result.output
    assert "Functions ingested:" in result.output
    assert "DB       :" in result.output
