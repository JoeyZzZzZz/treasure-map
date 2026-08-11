# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the analyze CLI wrapper.

Stubs load_config / Workspace / run_analyze so the command runs without Ghidra,
proving the thin wrapper drives the pipeline and prints the result block.
"""

from __future__ import annotations

from dataclasses import fields as _dataclass_fields
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from treasure_map.cli.analyze_cli import analyze
from treasure_map.lib.analyze.pipeline import AnalyzeResult
from treasure_map.lib.config.config import Config

# Fields that are not plain counters, so they carry a real stand-in value.
_NON_COUNTER = {"db_path", "elapsed", "incomplete_binaries"}


def _fake_result(db_path: Path) -> AnalyzeResult:
    """A stand-in AnalyzeResult, built FROM the real dataclass rather than hand-listed.

    The previous version was a SimpleNamespace with every printed attribute typed out by hand, so
    the moment the CLI printed one more field the stub silently lacked it — surfacing as an
    AttributeError buried inside a CliRunner result, and only in CI. Deriving the counters from
    ``AnalyzeResult`` itself means a new counter can never make this stub stale."""
    counters = {f.name: 0 for f in _dataclass_fields(AnalyzeResult) if f.name not in _NON_COUNTER}
    return AnalyzeResult(db_path=db_path, elapsed=0.1, incomplete_binaries=[], **counters)


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

    async def _fake_run_analyze(*_: Any, **__: Any) -> AnalyzeResult:
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
