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
    _configure_workspace_dir,
    _provision_dirs,
    _run_doctor,
    _set_ghidra_home,
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


def test_collect_default_env_vars_is_empty() -> None:
    # The tool ships no built-in secrets — analysis is hermetic (no network calls), so there are no
    # default API-key env vars to scaffold. The .env stays a bare operator-owned placeholder.
    assert _collect_default_env_vars() == []


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
    assert "ghidra" in data
    assert "atlas" in data
    assert data["atlas"]["db_path"] == "~/.treasure-map/atlas.db"


def test_write_config_carries_no_secret_values(fake_home: Path) -> None:
    config_path = fake_home / ".treasure-map" / "config.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    _write_config(config_path, force=False)
    content = config_path.read_text()
    # The default config ships no secrets of any kind (no inline key values, no key placeholders).
    assert "sk-" not in content


def test_write_config_reuses_existing_without_force(fake_home: Path) -> None:
    # Idempotent: an existing config.yaml is reused untouched, never an error (a fresh install
    # over a persisted ~/.treasure-map/ must not read as "already initialized — aborting").
    config_path = fake_home / ".treasure-map" / "config.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text("custom: kept\n")
    _write_config(config_path, force=False)  # must not raise
    assert config_path.read_text() == "custom: kept\n"  # reused verbatim, not regenerated


def test_write_config_force_overwrites(fake_home: Path) -> None:
    config_path = fake_home / ".treasure-map" / "config.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text("old: content\n")
    _write_config(config_path, force=True)
    data: dict[str, Any] = yaml.safe_load(config_path.read_text())
    assert "ghidra" in data
    assert "old" not in data  # regenerated, not merged


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


def test_run_init_is_idempotent_second_call_succeeds(fake_home: Path) -> None:
    # Re-running init (e.g. after a reinstall over a persisted ~/.treasure-map/) must succeed.
    run_init(force=False, non_interactive=True, prompt=_noop_prompt)
    run_init(force=False, non_interactive=True, prompt=_noop_prompt)  # must not raise
    assert (fake_home / ".treasure-map" / "config.yaml").exists()


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
    _configure_workspace_dir(
        config_path, non_interactive=False, prompt=_capture, echo=lambda _m: None
    )

    assert captured  # all prompts actually fired
    for msg in captured:
        assert not msg.rstrip().endswith(":"), f"message would double click's colon: {msg!r}"


# ── run_init — idempotent re-run / reinstall (R0e) ────────────────────────────


def test_reinit_preserves_existing_env_keys(fake_home: Path) -> None:
    # A re-run where the user presses Enter must NOT wipe keys saved on the first run.
    env_path = fake_home / ".treasure-map" / ".env"
    env_path.parent.mkdir(parents=True, exist_ok=True)
    env_path.write_text("DEEPSEEK_API_KEY=sk-saved-1\nANTHROPIC_API_KEY=sk-saved-2\n")

    with patch(_FIND_HEADLESS, side_effect=GhidraNotFoundError("not found")):
        run_init(non_interactive=False, prompt=_noop_prompt)  # Enter on every prompt

    content = env_path.read_text()
    assert "DEEPSEEK_API_KEY=sk-saved-1" in content
    assert "ANTHROPIC_API_KEY=sk-saved-2" in content  # not clobbered


def test_force_leaves_env_intact(fake_home: Path) -> None:
    # --force regenerates config.yaml only; it must never touch .env (secrets).
    env_path = fake_home / ".treasure-map" / ".env"
    env_path.parent.mkdir(parents=True, exist_ok=True)
    env_path.write_text("DEEPSEEK_API_KEY=sk-saved-1\n")

    with patch(_FIND_HEADLESS, side_effect=GhidraNotFoundError("not found")):
        run_init(force=True, non_interactive=True, prompt=_noop_prompt)

    assert env_path.read_text() == "DEEPSEEK_API_KEY=sk-saved-1\n"


def test_reinit_reuses_configured_ghidra_without_prompt(fake_home: Path) -> None:
    # ghidra.local.home already set + valid: reuse it, do not re-prompt or re-detect.
    root = _make_ghidra_root(fake_home)
    config_path = fake_home / ".treasure-map" / "config.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    _write_config(config_path, force=True)
    _set_ghidra_home(config_path, root)

    msgs: list[str] = []

    def _record(msg: str) -> str:
        msgs.append(msg)
        return ""

    # find_headless raises: if reuse fails, the only way to succeed would be the prompt — so a
    # silent no-prompt run proves the existing config path was honored.
    with patch(_FIND_HEADLESS, side_effect=GhidraNotFoundError("not found")):
        _configure_ghidra(config_path, non_interactive=False, prompt=_record, echo=_noop_prompt)

    assert not any("Ghidra install root" in m for m in msgs)  # not re-prompted
    assert _ghidra_home(fake_home) == str(root)  # still configured


# ── run_init — workspace base dir confirm/persist (R0f) ───────────────────────


def _workspace_dir(fake_home: Path) -> Any:
    data = yaml.safe_load((fake_home / ".treasure-map" / "config.yaml").read_text())
    return data.get("workspace_dir")


def test_init_workspace_base_enter_keeps_default(fake_home: Path) -> None:
    # Pressing Enter at the workspace prompt keeps the existing/default value untouched.
    with patch(_FIND_HEADLESS, side_effect=GhidraNotFoundError("not found")):
        run_init(non_interactive=False, prompt=_noop_prompt)
    assert _workspace_dir(fake_home) == "~/.treasure-map/workspaces"


def test_init_workspace_base_typed_path_persists(fake_home: Path) -> None:
    custom = str(fake_home / "big-disk" / "ws")

    def _prompt(msg: str) -> str:
        return custom if "Workspace base" in msg else ""

    with patch(_FIND_HEADLESS, side_effect=GhidraNotFoundError("not found")):
        run_init(non_interactive=False, prompt=_prompt)
    assert _workspace_dir(fake_home) == custom


def test_init_workspace_base_non_interactive_no_prompt(fake_home: Path) -> None:
    msgs: list[str] = []

    def _record(msg: str) -> str:
        msgs.append(msg)
        return ""

    run_init(non_interactive=True, prompt=_record)
    assert not any("Workspace base" in m for m in msgs)  # never prompts
    assert _workspace_dir(fake_home) == "~/.treasure-map/workspaces"
