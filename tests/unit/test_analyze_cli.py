# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the analyze CLI summarize wiring (R1).

Covers the opt-in gating (no router built without --summarize) and the degrade
paths (missing LLM config / missing S-tier key skip with a message, never raise).
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import click
import pytest
from click.testing import CliRunner

import treasure_map.cli.analyze_cli as analyze_cli
from treasure_map.cli.analyze_cli import _summarize, analyze
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


def test_analyze_without_summarize_does_not_summarize(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_pipeline(monkeypatch, tmp_path / "analysis.db")
    called = {"n": 0}
    monkeypatch.setattr(analyze_cli, "_summarize", lambda *a, **k: called.__setitem__("n", 1))

    fs_root = tmp_path / "fs"
    fs_root.mkdir()
    result = CliRunner().invoke(analyze, [str(fs_root), "--workspace", str(tmp_path / "ws")])

    assert result.exit_code == 0, result.output
    assert called["n"] == 0  # opt-in: helper not invoked without the flag


def test_analyze_with_summarize_invokes_helper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_pipeline(monkeypatch, tmp_path / "analysis.db")
    seen: dict[str, Any] = {}

    def _spy(cfg: Any, ws: Path, db: Path, limit: int | None) -> None:
        seen["limit"] = limit

    monkeypatch.setattr(analyze_cli, "_summarize", _spy)

    fs_root = tmp_path / "fs"
    fs_root.mkdir()
    result = CliRunner().invoke(
        analyze,
        [str(fs_root), "--workspace", str(tmp_path / "ws"), "--summarize", "--summary-limit", "7"],
    )

    assert result.exit_code == 0, result.output
    assert seen.get("limit") == 7


# ── degrade paths ───────────────────────────────────────────────────────────────


def test_summarize_helper_skips_when_llm_unconfigured(tmp_path: Path) -> None:
    cfg = Config(llm=None)

    @click.command()
    def _cmd() -> None:
        _summarize(cfg, tmp_path, tmp_path / "analysis.db", None)

    result = CliRunner().invoke(_cmd, [])
    assert result.exit_code == 0
    assert "summary skipped: LLM not configured" in result.output


def test_summarize_helper_skips_on_missing_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("FAKE_S_KEY_TMTEST", raising=False)
    cfg = Config.model_validate(
        {
            "llm": {
                "tiers": {
                    "S": {
                        "provider": "deepseek",
                        "model": "deepseek-chat",
                        "base_url": "https://api.deepseek.com",
                        "api_key_env": "FAKE_S_KEY_TMTEST",
                    },
                    "M": {
                        "provider": "deepseek",
                        "model": "deepseek-reasoner",
                        "base_url": "https://api.deepseek.com",
                        "api_key_env": "FAKE_S_KEY_TMTEST",
                    },
                    "L": {
                        "provider": "anthropic",
                        "model": "claude-x",
                        "base_url": "https://api.anthropic.com/v1",
                        "api_key_env": "FAKE_L_KEY_TMTEST",
                    },
                }
            }
        }
    )

    @click.command()
    def _cmd() -> None:
        _summarize(cfg, tmp_path, tmp_path / "analysis.db", None)

    result = CliRunner().invoke(_cmd, [])
    assert result.exit_code == 0
    assert "summary skipped: S-tier key not configured" in result.output
