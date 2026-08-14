# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the tmap init CLI command (M2 Step 2)."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from treasure_map.cli.init_cli import init
from treasure_map.lib.setup.initializer import InitResult

# ── helpers ───────────────────────────────────────────────────────────────────


def _make_result(tmp_path: Path, checks: tuple[tuple[str, bool, str], ...]) -> InitResult:
    return InitResult(
        config_path=tmp_path / "config.yaml",
        env_path=tmp_path / ".env",
        atlas_dir=tmp_path,
        checks=checks,
    )


# ── basic wiring ──────────────────────────────────────────────────────────────


def test_init_cli_non_interactive_exits_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "treasure_map.cli.init_cli.run_init",
        lambda **_: _make_result(tmp_path, (("java", True, "/usr/bin/java"),)),
    )
    result = CliRunner().invoke(init, ["--non-interactive"])
    assert result.exit_code == 0


def test_init_cli_passes_force_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def _fake(**kwargs: object) -> InitResult:
        captured.update(kwargs)
        return _make_result(tmp_path, ())

    monkeypatch.setattr("treasure_map.cli.init_cli.run_init", _fake)
    CliRunner().invoke(init, ["--force", "--non-interactive"])
    assert captured.get("force") is True


def test_init_cli_passes_non_interactive_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    def _fake(**kwargs: object) -> InitResult:
        captured.update(kwargs)
        return _make_result(tmp_path, ())

    monkeypatch.setattr("treasure_map.cli.init_cli.run_init", _fake)
    CliRunner().invoke(init, ["--non-interactive"])
    assert captured.get("non_interactive") is True


def test_init_cli_passes_check_only_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def _fake(**kwargs: object) -> InitResult:
        captured.update(kwargs)
        return _make_result(tmp_path, (("x", True, "ok"),))

    monkeypatch.setattr("treasure_map.cli.init_cli.run_init", _fake)
    CliRunner().invoke(init, ["--check-only"])
    assert captured.get("check_only") is True


# ── check_only exit code ──────────────────────────────────────────────────────


def test_check_only_exits_nonzero_when_any_check_red(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "treasure_map.cli.init_cli.run_init",
        lambda **_: _make_result(tmp_path, (("java", False, "not on PATH"),)),
    )
    result = CliRunner().invoke(init, ["--check-only"])
    assert result.exit_code != 0


def test_check_only_exits_zero_when_all_green(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "treasure_map.cli.init_cli.run_init",
        lambda **_: _make_result(tmp_path, (("java", True, "/usr/bin/java"),)),
    )
    result = CliRunner().invoke(init, ["--check-only"])
    assert result.exit_code == 0


# ── error handling ────────────────────────────────────────────────────────────


def test_file_exists_error_becomes_click_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _raise(**_: object) -> InitResult:
        raise FileExistsError("config.yaml already exists — pass --force to overwrite")

    monkeypatch.setattr("treasure_map.cli.init_cli.run_init", _raise)
    result = CliRunner().invoke(init, [])
    assert result.exit_code != 0
    assert "already exists" in result.output


def test_treasure_map_error_becomes_click_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from treasure_map.lib.errors import ConfigError

    def _raise(**_: object) -> InitResult:
        raise ConfigError("bad config")

    monkeypatch.setattr("treasure_map.cli.init_cli.run_init", _raise)
    result = CliRunner().invoke(init, ["--non-interactive"])
    assert result.exit_code != 0
    assert "ConfigError" in result.output


# ── output format ─────────────────────────────────────────────────────────────


def test_non_check_only_prints_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "treasure_map.cli.init_cli.run_init",
        lambda **_: _make_result(tmp_path, (("java", True, "/usr/bin/java"),)),
    )
    result = CliRunner().invoke(init, ["--non-interactive"])
    assert "Config" in result.output
    assert "Secrets" in result.output


def test_check_only_prints_checks_not_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "treasure_map.cli.init_cli.run_init",
        lambda **_: _make_result(tmp_path, (("java", True, "/usr/bin/java"),)),
    )
    result = CliRunner().invoke(init, ["--check-only"])
    assert "Preflight checks" in result.output
    # Path lines are not printed in check_only mode
    assert "Config :" not in result.output
