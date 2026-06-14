# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for lib/setup — local onboarding initializer (M2 Step 2)."""

from __future__ import annotations

import stat
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
import yaml

from treasure_map.lib.errors import GhidraNotFoundError
from treasure_map.lib.setup.initializer import (
    _DEFAULT_CONFIG_YAML,
    _collect_default_env_vars,
    _configure_ghidra,
    _provision_dirs,
    _run_doctor,
    _write_config,
    _write_env,
    run_init,
)

_FIND_HEADLESS = "treasure_map.lib.analyze.ghidra_runner.find_headless"


def _make_ghidra_root(base: Path, name: str = "ghidra_11") -> Path:
    """Create a fake Ghidra install root containing support/analyzeHeadless."""
    root = base / name
    (root / "support").mkdir(parents=True)
    (root / "support" / "analyzeHeadless").write_text("#!/bin/sh\n")
    return root


def _ghidra_home(fake_home: Path) -> Any:
    data = yaml.safe_load((fake_home / ".treasure-map" / "config.yaml").read_text())
    return data["ghidra"]["local"]["home"]


# ── fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture()
def fake_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect home to tmp_path for the test.

    Sets both Path.home() and $HOME so Path.home() and os.path.expanduser('~')
    (used by the config path validators) resolve to the same directory — the
    regression guard for the provision/check drift fix.
    """
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


def _noop_prompt(msg: str) -> str:  # noqa: ARG001
    return ""


# ── _collect_default_env_vars ─────────────────────────────────────────────────


def test_collect_default_env_vars_returns_unique_names() -> None:
    names = _collect_default_env_vars()
    assert "DEEPSEEK_API_KEY" in names
    assert "ANTHROPIC_API_KEY" in names
    # Each name appears exactly once
    assert len(names) == len(set(names))


# ── _provision_dirs ───────────────────────────────────────────────────────────


def test_provision_dirs_creates_each_path(fake_home: Path) -> None:
    tm_home = fake_home / ".treasure-map"
    _provision_dirs([tm_home, tm_home / "workspaces"])
    assert tm_home.is_dir()
    assert (tm_home / "workspaces").is_dir()


def test_provision_dirs_is_idempotent(fake_home: Path) -> None:
    tm_home = fake_home / ".treasure-map"
    _provision_dirs([tm_home])
    _provision_dirs([tm_home])  # must not raise


# ── _write_config ─────────────────────────────────────────────────────────────


def test_write_config_creates_valid_yaml(fake_home: Path) -> None:
    config_path = fake_home / ".treasure-map" / "config.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    _write_config(config_path, force=False)
    data: dict[str, Any] = yaml.safe_load(config_path.read_text())
    assert "llm" in data
    assert "atlas" in data
    assert data["atlas"]["db_path"] == "~/.treasure-map/atlas.db"


def test_write_config_no_api_key_values(fake_home: Path) -> None:
    config_path = fake_home / ".treasure-map" / "config.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    _write_config(config_path, force=False)
    content = config_path.read_text()
    # Values like sk-... or actual secrets must not be present
    assert "api_key_env" in content
    # The file must not contain any inline key values (only env var names)
    for line in content.splitlines():
        if "api_key_env" in line:
            assert "sk-" not in line


def test_write_config_raises_if_exists_without_force(fake_home: Path) -> None:
    config_path = fake_home / ".treasure-map" / "config.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    _write_config(config_path, force=False)
    with pytest.raises(FileExistsError, match="--force"):
        _write_config(config_path, force=False)


def test_write_config_force_overwrites(fake_home: Path) -> None:
    config_path = fake_home / ".treasure-map" / "config.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text("old: content\n")
    _write_config(config_path, force=True)
    data: dict[str, Any] = yaml.safe_load(config_path.read_text())
    assert "llm" in data


# ── _write_env ────────────────────────────────────────────────────────────────


def test_write_env_mode_0600(fake_home: Path) -> None:
    env_path = fake_home / ".treasure-map" / ".env"
    env_path.parent.mkdir(parents=True, exist_ok=True)
    _write_env(env_path, env_vars=["DEEPSEEK_API_KEY"], prompt=_noop_prompt, non_interactive=True)
    mode = stat.S_IMODE(env_path.stat().st_mode)
    assert mode == 0o600


def test_write_env_non_interactive_writes_empty_file(fake_home: Path) -> None:
    env_path = fake_home / ".treasure-map" / ".env"
    env_path.parent.mkdir(parents=True, exist_ok=True)
    _write_env(
        env_path,
        env_vars=["DEEPSEEK_API_KEY", "ANTHROPIC_API_KEY"],
        prompt=_noop_prompt,
        non_interactive=True,
    )
    assert env_path.read_text() == ""


def test_write_env_interactive_captures_values(fake_home: Path) -> None:
    env_path = fake_home / ".treasure-map" / ".env"
    env_path.parent.mkdir(parents=True, exist_ok=True)
    responses = {"DEEPSEEK_API_KEY": "sk-deep-123", "ANTHROPIC_API_KEY": ""}

    def _fake_prompt(msg: str) -> str:
        for k, v in responses.items():
            if k in msg:
                return v
        return ""

    _write_env(
        env_path,
        env_vars=["DEEPSEEK_API_KEY", "ANTHROPIC_API_KEY"],
        prompt=_fake_prompt,
        non_interactive=False,
    )
    content = env_path.read_text()
    assert "DEEPSEEK_API_KEY=sk-deep-123" in content
    assert "ANTHROPIC_API_KEY" not in content  # empty → not written


# ── run_init — file creation ──────────────────────────────────────────────────


def test_run_init_creates_expected_files(fake_home: Path) -> None:
    result = run_init(force=False, non_interactive=True, prompt=_noop_prompt)
    assert result.config_path.exists()
    assert result.env_path.exists()
    assert (fake_home / ".treasure-map" / "workspaces").is_dir()


def test_run_init_returns_correct_paths(fake_home: Path) -> None:
    result = run_init(force=False, non_interactive=True, prompt=_noop_prompt)
    assert result.config_path == fake_home / ".treasure-map" / "config.yaml"
    assert result.env_path == fake_home / ".treasure-map" / ".env"
    assert result.atlas_dir == fake_home / ".treasure-map"


def test_run_init_config_yaml_is_parseable(fake_home: Path) -> None:
    run_init(force=False, non_interactive=True, prompt=_noop_prompt)
    data: dict[str, Any] = yaml.safe_load((fake_home / ".treasure-map" / "config.yaml").read_text())
    assert data["atlas"]["db_path"] == "~/.treasure-map/atlas.db"
    assert data["log_level"] == "INFO"


def test_run_init_check_only_writes_nothing(fake_home: Path) -> None:
    run_init(check_only=True, prompt=_noop_prompt)
    assert not (fake_home / ".treasure-map" / "config.yaml").exists()
    assert not (fake_home / ".treasure-map" / ".env").exists()


def test_run_init_raises_if_config_exists_without_force(fake_home: Path) -> None:
    run_init(force=False, non_interactive=True, prompt=_noop_prompt)
    with pytest.raises(FileExistsError):
        run_init(force=False, non_interactive=True, prompt=_noop_prompt)


def test_run_init_force_succeeds_on_second_call(fake_home: Path) -> None:
    run_init(force=False, non_interactive=True, prompt=_noop_prompt)
    run_init(force=True, non_interactive=True, prompt=_noop_prompt)  # must not raise


# ── run_init — doctor checks ──────────────────────────────────────────────────


def test_run_init_checks_is_tuple_of_triples(fake_home: Path) -> None:
    result = run_init(force=False, non_interactive=True, prompt=_noop_prompt)
    assert isinstance(result.checks, tuple)
    for item in result.checks:
        name, ok, detail = item
        assert isinstance(name, str)
        assert isinstance(ok, bool)
        assert isinstance(detail, str)


def test_run_init_atlas_dir_check_is_green_after_provisioning(fake_home: Path) -> None:
    result = run_init(force=False, non_interactive=True, prompt=_noop_prompt)
    atlas_check = next((c for c in result.checks if c[0] == "atlas_dir"), None)
    assert atlas_check is not None
    assert atlas_check[1] is True, f"atlas_dir check failed: {atlas_check[2]}"


def test_run_init_workspace_dir_check_is_green_after_provisioning(fake_home: Path) -> None:
    result = run_init(force=False, non_interactive=True, prompt=_noop_prompt)
    ws_check = next((c for c in result.checks if c[0] == "workspace_dir"), None)
    assert ws_check is not None
    assert ws_check[1] is True, f"workspace_dir check failed: {ws_check[2]}"


def test_run_init_provisions_and_greens_custom_workspace_dir(
    fake_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: a non-default workspace_dir must still be provisioned and green.

    Guards the provision/check drift fix — run_init provisions the *config-resolved*
    path, not a hardcoded tm_home/workspaces, so a customized location stays consistent.
    """
    custom_ws = fake_home / "elsewhere" / "ws"
    custom_yaml = dict(_DEFAULT_CONFIG_YAML)
    custom_yaml["workspace_dir"] = str(custom_ws)
    monkeypatch.setattr("treasure_map.lib.setup.initializer._DEFAULT_CONFIG_YAML", custom_yaml)
    result = run_init(force=False, non_interactive=True, prompt=_noop_prompt)
    assert custom_ws.is_dir(), "custom workspace_dir must be provisioned"
    ws_check = next((c for c in result.checks if c[0] == "workspace_dir"), None)
    assert ws_check is not None
    assert ws_check[1] is True, f"workspace_dir check failed: {ws_check[2]}"


def test_check_only_atlas_dir_red_when_not_provisioned(fake_home: Path) -> None:
    result = run_init(check_only=True, prompt=_noop_prompt)
    atlas_check = next((c for c in result.checks if c[0] == "atlas_dir"), None)
    assert atlas_check is not None
    assert atlas_check[1] is False


# ── _run_doctor — isolated unit ───────────────────────────────────────────────


def test_run_doctor_java_check_reflects_path(tmp_path: Path) -> None:
    with patch("treasure_map.lib.setup.initializer.shutil.which") as mock_which:
        mock_which.side_effect = lambda x: "/usr/bin/java" if x == "java" else None
        checks = _run_doctor(tmp_path, None)
    java_check = next(c for c in checks if c[0] == "java")
    assert java_check[1] is True
    assert java_check[2] == "/usr/bin/java"


def test_run_doctor_api_key_check_with_missing_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from treasure_map.lib.config.config import Config

    monkeypatch.delenv("FAKE_API_KEY_TMTEST", raising=False)
    cfg = Config.model_validate(
        {
            "llm": {
                "tiers": {
                    "S": {
                        "provider": "test",
                        "model": "t",
                        "base_url": "http://x",
                        "api_key_env": "FAKE_API_KEY_TMTEST",
                    },
                    "M": {
                        "provider": "test",
                        "model": "t",
                        "base_url": "http://x",
                        "api_key_env": "FAKE_API_KEY_TMTEST",
                    },
                    "L": {
                        "provider": "test",
                        "model": "t",
                        "base_url": "http://x",
                        "api_key_env": "FAKE_API_KEY_TMTEST",
                    },
                }
            }
        }
    )
    checks = _run_doctor(tmp_path, cfg)
    key_checks = [c for c in checks if c[0].startswith("key:")]
    assert len(key_checks) == 1  # deduplicated
    assert key_checks[0][1] is False


def test_run_doctor_api_key_check_green_when_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from treasure_map.lib.config.config import Config

    monkeypatch.setenv("FAKE_API_KEY_TMTEST2", "present-value")
    cfg = Config.model_validate(
        {
            "llm": {
                "tiers": {
                    "S": {
                        "provider": "test",
                        "model": "t",
                        "base_url": "http://x",
                        "api_key_env": "FAKE_API_KEY_TMTEST2",
                    },
                    "M": {
                        "provider": "test",
                        "model": "t",
                        "base_url": "http://x",
                        "api_key_env": "FAKE_API_KEY_TMTEST2",
                    },
                    "L": {
                        "provider": "test",
                        "model": "t",
                        "base_url": "http://x",
                        "api_key_env": "FAKE_API_KEY_TMTEST2",
                    },
                }
            }
        }
    )
    checks = _run_doctor(tmp_path, cfg)
    key_checks = [c for c in checks if c[0].startswith("key:")]
    assert len(key_checks) == 1
    assert key_checks[0][1] is True


# ── run_init — Ghidra configuration step (R0-fix) ─────────────────────────────


def test_init_ghidra_autodetect_accepts_without_prompt(fake_home: Path) -> None:
    msgs: list[str] = []

    def _record_prompt(msg: str) -> str:
        msgs.append(msg)
        return ""

    with patch(_FIND_HEADLESS, return_value=Path("/opt/ghidra/support/analyzeHeadless")):
        run_init(non_interactive=False, prompt=_record_prompt)

    # Auto-detected: no Ghidra prompt fired, and the resolved install root is PERSISTED to
    # config.yaml so a later analyze in a new shell (no GHIDRA_HOME/PATH) still finds it.
    assert not any("Ghidra install root" in m for m in msgs)
    assert _ghidra_home(fake_home) == "/opt/ghidra"


def test_init_ghidra_prompt_validates_and_writes(fake_home: Path) -> None:
    root = _make_ghidra_root(fake_home)
    answers = iter([str(fake_home / "nope"), str(root)])  # invalid, then valid

    def _prompt(msg: str) -> str:
        return next(answers) if "Ghidra install root" in msg else ""

    with patch(_FIND_HEADLESS, side_effect=GhidraNotFoundError("not found")):
        run_init(non_interactive=False, prompt=_prompt)

    assert _ghidra_home(fake_home) == str(root)


def test_init_ghidra_invalid_path_not_written(fake_home: Path) -> None:
    def _prompt(msg: str) -> str:
        # Always return a path lacking support/analyzeHeadless.
        return str(fake_home / "not-ghidra") if "Ghidra install root" in msg else ""

    with patch(_FIND_HEADLESS, side_effect=GhidraNotFoundError("not found")):
        run_init(non_interactive=False, prompt=_prompt)

    assert _ghidra_home(fake_home) is None  # bad path never written


def test_init_non_interactive_no_ghidra_leaves_unset(fake_home: Path) -> None:
    msgs: list[str] = []

    def _record_prompt(msg: str) -> str:
        msgs.append(msg)
        return ""

    with patch(_FIND_HEADLESS, side_effect=GhidraNotFoundError("not found")):
        result = run_init(non_interactive=True, prompt=_record_prompt)

    assert not any("Ghidra install root" in m for m in msgs)  # never prompts
    assert _ghidra_home(fake_home) is None
    assert result.config_path.exists()  # init still succeeds


def test_init_ghidra_path_goes_to_config_not_env(fake_home: Path) -> None:
    root = _make_ghidra_root(fake_home)

    def _prompt(msg: str) -> str:
        return str(root) if "Ghidra install root" in msg else ""

    with patch(_FIND_HEADLESS, side_effect=GhidraNotFoundError("not found")):
        run_init(non_interactive=False, prompt=_prompt)

    env_text = (fake_home / ".treasure-map" / ".env").read_text()
    assert "ghidra" not in env_text.lower()  # secrets file is untouched by the Ghidra step
    assert str(root) not in env_text
    cfg_text = (fake_home / ".treasure-map" / "config.yaml").read_text()
    assert str(root) in cfg_text  # the path (non-secret) belongs in config.yaml


def test_prompt_messages_carry_no_trailing_colon(fake_home: Path) -> None:
    # click's prompt() appends its own ": " suffix, so a message that already ends in ": "
    # would render a double colon. Guard both prompts: their messages must NOT end with a colon.
    captured: list[str] = []

    def _capture(msg: str) -> str:
        captured.append(msg)
        return ""  # skip / leave unset

    env_path = fake_home / ".treasure-map" / ".env"
    env_path.parent.mkdir(parents=True, exist_ok=True)
    _write_env(
        env_path,
        env_vars=["DEEPSEEK_API_KEY"],
        prompt=_capture,
        non_interactive=False,
    )

    config_path = fake_home / ".treasure-map" / "config.yaml"
    _write_config(config_path, force=True)
    with patch(_FIND_HEADLESS, side_effect=GhidraNotFoundError("not found")):
        _configure_ghidra(config_path, non_interactive=False, prompt=_capture, echo=lambda _m: None)

    assert captured  # both prompts actually fired
    for msg in captured:
        assert not msg.rstrip().endswith(":"), f"message would double click's colon: {msg!r}"
