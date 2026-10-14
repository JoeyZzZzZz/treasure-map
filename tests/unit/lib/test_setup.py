# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
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
    _configure_workspace_dir,
    _provision_dirs,
    _set_ghidra_home,
    _write_config,
    _write_env,
    run_init,
)

from .setup import fakes

_FIND_HEADLESS = "treasure_map.lib.analyze.ghidra_runner.find_headless"
_GHIDRA_PROMPT = "No Ghidra 11.4.3 found"


def _make_ghidra_root(base: Path, name: str = "myghidra") -> Path:
    """A fake Ghidra 11.4.3 install root. The default name is NOT ghidra_*_PUBLIC, so discovery's
    directory scan does not find it — only config, $GHIDRA_HOME, PATH or the prompt do."""
    return fakes.make_ghidra(base / name)


@pytest.fixture(autouse=True)
def _offline_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every init here runs as linux-x86_64 and offline: a download the plan includes fails as a
    FetchError (reported, never the network)."""
    monkeypatch.setattr("treasure_map.lib.setup.platform.detect_platform", lambda: fakes.linux())
    monkeypatch.setattr("treasure_map.lib.setup.fetch.UrlFetcher", fakes.RefusingFetcher)


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


def test_run_init_checks_carry_name_ok_detail_and_state(fake_home: Path) -> None:
    result = run_init(force=False, non_interactive=True, prompt=_noop_prompt)
    assert isinstance(result.checks, tuple)
    for item in result.checks:
        name, ok, detail, state = item
        assert isinstance(name, str)
        assert isinstance(ok, bool)
        assert isinstance(detail, str)
        # ok is False exactly for the states that fail a --check-only run
        assert ok is (state not in ("missing", "wrong", "unknown"))


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


def test_run_init_installs_completion_and_the_doctor_reports_it(
    fake_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Completion is a STANDARD init step (no flag): a full run installs the script and the doctor
    # carries a 'completion' check. bash-completion is forced present so the result is stable.
    monkeypatch.setenv("SHELL", "/bin/bash")
    from treasure_map.lib.setup import completion as comp

    monkeypatch.setattr(comp, "_bash_completion_present", lambda: True)
    result = run_init(force=False, non_interactive=True, prompt=_noop_prompt)

    script = fake_home / ".local" / "share" / "bash-completion" / "completions" / "tmap"
    assert script.exists(), "completion script was not installed by init"
    comp_check = next((c for c in result.checks if c[0] == "completion"), None)
    assert comp_check is not None and comp_check[1] is True  # installed + active -> green
    # ★ never edits the user's rc file
    assert not (fake_home / ".bashrc").exists()


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


# ── the doctor's java check — by version and javac, not by presence ──────────────────


def test_doctor_java_check_reads_the_version_and_javac(tmp_path: Path) -> None:
    """A JDK 17 on PATH used to read ✅ because only ``which java`` was asked; Ghidra 11.4.3
    refuses it. The check now reads the JDK's release file and wants javac.

    MUTATION: return to ``shutil.which("java")`` alone -> the JDK 17 and the JRE read ok -> RED."""
    from treasure_map.lib.setup.doctor import DoctorInputs, _java_check
    from treasure_map.lib.setup.toolchain_lock import load_lock

    def state_for(home: Path) -> str:
        host = fakes.make_host(tmp_path, which={"java": str(home / "bin" / "java")})
        inp = DoctorInputs(fakes.linux(), host, None, None, load_lock(), None, True)  # type: ignore[arg-type]
        return _java_check(inp).state

    assert state_for(fakes.make_jdk(tmp_path / "jdk17", "17.0.9")) == "wrong"
    assert state_for(fakes.make_jdk(tmp_path / "jre21", javac=False)) == "wrong"
    assert state_for(fakes.make_jdk(tmp_path / "jdk21")) == "ok"
    assert state_for(fakes.make_jdk(tmp_path / "jdk25", "25.0.1")) == "warn"


# ── run_init — Ghidra configuration step (R0-fix) ─────────────────────────────


def test_init_ghidra_autodetect_accepts_without_prompt(
    fake_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _make_ghidra_root(fake_home)
    monkeypatch.setenv("GHIDRA_HOME", str(root))
    msgs: list[str] = []

    def _record_prompt(msg: str) -> str:
        msgs.append(msg)
        return ""

    run_init(non_interactive=False, prompt=_record_prompt)

    # Found: no Ghidra prompt fired, and the install root is PERSISTED to config.yaml so a later
    # analyze in a new shell (no GHIDRA_HOME/PATH) still finds it.
    assert not any(_GHIDRA_PROMPT in m for m in msgs)
    assert _ghidra_home(fake_home) == str(root)


def test_init_ghidra_prompt_validates_and_writes(fake_home: Path) -> None:
    root = _make_ghidra_root(fake_home)
    answers = iter([str(fake_home / "nope"), str(root)])  # invalid, then valid

    def _prompt(msg: str) -> str:
        return next(answers) if _GHIDRA_PROMPT in msg else ""

    run_init(non_interactive=False, prompt=_prompt)

    assert _ghidra_home(fake_home) == str(root)


def test_init_ghidra_wrong_version_is_not_accepted(fake_home: Path) -> None:
    """A Ghidra that is not exactly the pinned version is refused at the prompt as it is in
    discovery."""
    old = fakes.make_ghidra(fake_home / "old", version="11.4.2")

    def _prompt(msg: str) -> str:
        return str(old) if _GHIDRA_PROMPT in msg else ""

    result = run_init(non_interactive=False, prompt=_prompt)

    assert _ghidra_home(fake_home) is None
    assert any("Ghidra" in n for n in result.needs_you)


def test_init_ghidra_invalid_path_not_written(fake_home: Path) -> None:
    def _prompt(msg: str) -> str:
        # Always return a path that is no Ghidra.
        return str(fake_home / "not-ghidra") if _GHIDRA_PROMPT in msg else ""

    run_init(non_interactive=False, prompt=_prompt)

    assert _ghidra_home(fake_home) is None  # bad path never written


def test_init_non_interactive_no_ghidra_leaves_unset(fake_home: Path) -> None:
    msgs: list[str] = []

    def _record_prompt(msg: str) -> str:
        msgs.append(msg)
        return ""

    result = run_init(non_interactive=True, prompt=_record_prompt)

    assert not any(_GHIDRA_PROMPT in m for m in msgs)  # never prompts
    assert _ghidra_home(fake_home) is None
    assert result.config_path.exists()  # init still succeeds


def test_init_ghidra_path_goes_to_config_not_env(fake_home: Path) -> None:
    root = _make_ghidra_root(fake_home)

    def _prompt(msg: str) -> str:
        return str(root) if _GHIDRA_PROMPT in msg else ""

    run_init(non_interactive=False, prompt=_prompt)

    env_text = (fake_home / ".treasure-map" / ".env").read_text()
    assert "ghidra" not in env_text.lower()  # secrets file is untouched by the Ghidra step
    assert str(root) not in env_text
    cfg_text = (fake_home / ".treasure-map" / "config.yaml").read_text()
    assert str(root) in cfg_text  # the path (non-secret) belongs in config.yaml


def test_prompt_messages_carry_no_trailing_colon(fake_home: Path) -> None:
    # click's prompt() appends its own ": " suffix, so a message that already ends in ": "
    # would render a double colon. Guard every prompt init asks: none may end with a colon.
    captured: list[str] = []

    def _capture(msg: str) -> str:
        captured.append(msg)
        return "n" if msg.startswith("Apply") else ""

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
    _configure_workspace_dir(
        config_path, non_interactive=False, prompt=_capture, echo=lambda _m: None
    )
    run_init(non_interactive=False, prompt=_capture)

    assert any(_GHIDRA_PROMPT in m for m in captured)  # the toolchain prompts fired too
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
    # ghidra.local.home already set + valid: reuse it, do not re-prompt.
    root = _make_ghidra_root(fake_home)
    config_path = fake_home / ".treasure-map" / "config.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    _write_config(config_path, force=True)
    _set_ghidra_home(config_path, root)

    msgs: list[str] = []

    def _record(msg: str) -> str:
        msgs.append(msg)
        return ""

    # Nothing else can find it (no GHIDRA_HOME, no PATH, a name the scan skips): a silent
    # no-prompt run proves the existing config path was honored.
    run_init(non_interactive=False, prompt=_record)

    assert not any(_GHIDRA_PROMPT in m for m in msgs)  # not re-prompted
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


# ── completion activation: init only touches an rc with explicit consent ───────────────


def _rc_state(home: Path) -> dict[str, str | None]:
    """Byte snapshot of every rc init could conceivably touch (None = absent)."""
    names = (".bashrc", ".zshrc", ".bash_profile", ".zprofile")
    return {n: (home / n).read_text() if (home / n).exists() else None for n in names}


def test_non_interactive_init_never_touches_the_rc(
    fake_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ★ An unattended init changing a shell rc is exactly the no-consent edit the rule forbids —
    # and there is nobody there to agree. It must print the line and write nothing.
    monkeypatch.setenv("SHELL", "/bin/zsh")
    monkeypatch.setattr("treasure_map.lib.setup.completion._bash_completion_present", lambda: False)
    (fake_home / ".zshrc").write_text("# mine\n")
    before = _rc_state(fake_home)

    lines: list[str] = []
    run_init(force=False, non_interactive=True, prompt=_noop_prompt, echo=lines.append)

    assert _rc_state(fake_home) == before  # byte-identical
    assert any("to activate" in line for line in lines)  # ... and the hint was still printed


def test_interactive_yes_appends_the_block_and_flips_the_doctor(
    fake_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Enter (the [Y/n] default) is a yes: the block lands, and the preflight that runs afterwards
    # reports the completion check green rather than a stale red.
    monkeypatch.setenv("SHELL", "/bin/zsh")
    result = run_init(force=False, non_interactive=False, prompt=lambda _msg: "")

    body = (fake_home / ".zshrc").read_text()
    assert "# >>> tmap completion >>>" in body and "fpath=(" in body
    completion = [c for c in result.checks if c[0] == "completion"]
    assert completion and completion[0][1] is True


def test_interactive_no_leaves_the_rc_alone(
    fake_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Declining keeps the current behaviour exactly: no rc write, the hint printed, doctor red.
    monkeypatch.setenv("SHELL", "/bin/zsh")
    lines: list[str] = []
    result = run_init(
        force=False,
        non_interactive=False,
        prompt=lambda msg: "n" if "completion line" in msg else "",
        echo=lines.append,
    )

    assert not (fake_home / ".zshrc").exists()
    assert any("to activate" in line for line in lines)
    completion = [c for c in result.checks if c[0] == "completion"]
    assert completion and completion[0][1] is False


def test_unrecognised_answer_is_treated_as_no(
    fake_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Ambiguity errs toward leaving the user's file alone — only Enter / y / yes writes.
    monkeypatch.setenv("SHELL", "/bin/zsh")
    run_init(
        force=False,
        non_interactive=False,
        prompt=lambda msg: "maybe" if "completion line" in msg else "",
    )
    assert not (fake_home / ".zshrc").exists()
