# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for shell completion install (the standard init step)."""

from __future__ import annotations

from pathlib import Path

import pytest

from treasure_map.lib.setup import completion as comp


def test_detect_shell_maps_bash_and_zsh_only() -> None:
    assert comp.detect_shell({"SHELL": "/bin/bash"}) == "bash"
    assert comp.detect_shell({"SHELL": "/usr/bin/zsh"}) == "zsh"
    assert comp.detect_shell({"SHELL": "/usr/bin/fish"}) is None  # out of scope, not a failure
    assert comp.detect_shell({}) is None


@pytest.mark.parametrize("shell", ["bash", "zsh"])
def test_install_writes_a_working_script_to_the_autoload_dir(shell: str, tmp_path: Path) -> None:
    out = comp.install_completion(shell, tmp_path)
    assert out is not None
    assert out.path == comp.target_path(shell, tmp_path)
    assert out.wrote is True
    text = out.path.read_text()
    # The runtime trigger var + program name must be present, or `tmap <tab>` cannot call back.
    assert "_TMAP_COMPLETE" in text
    assert "tmap" in text


@pytest.mark.parametrize("shell", ["bash", "zsh"])
def test_install_is_idempotent(shell: str, tmp_path: Path) -> None:
    first = comp.install_completion(shell, tmp_path)
    second = comp.install_completion(shell, tmp_path)
    assert first is not None and second is not None
    assert first.wrote is True
    assert second.wrote is False  # unchanged content -> not rewritten (re-run / --force safe)


def test_install_never_edits_shell_rc_files(tmp_path: Path) -> None:
    # ★ Hard rule: init writes to the shell's own autoload dir, NEVER to an rc file.
    for shell in ("bash", "zsh"):
        comp.install_completion(shell, tmp_path)
    assert not (tmp_path / ".bashrc").exists()
    assert not (tmp_path / ".zshrc").exists()
    assert not (tmp_path / ".zprofile").exists()
    assert not (tmp_path / ".bash_profile").exists()


def test_doctor_reports_not_installed_before_install(tmp_path: Path) -> None:
    name, ok, detail = comp.completion_check(tmp_path, "bash")
    assert name == "completion"
    assert ok is False
    assert "not installed" in detail


def test_doctor_reports_active_when_bash_completion_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(comp, "_bash_completion_present", lambda: True)
    comp.install_completion("bash", tmp_path)
    _, ok, detail = comp.completion_check(tmp_path, "bash")
    assert ok is True
    assert "active" in detail


def test_doctor_is_honest_when_bash_completion_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ★ Never claim success it cannot verify: with bash-completion absent, the doctor is red and
    # names the exact line to add — not a silent green.
    monkeypatch.setattr(comp, "_bash_completion_present", lambda: False)
    comp.install_completion("bash", tmp_path)
    _, ok, detail = comp.completion_check(tmp_path, "bash")
    assert ok is False
    assert "source" in detail and "~/.bashrc" in detail


def test_zsh_doctor_flips_to_active_once_fpath_is_configured(tmp_path: Path) -> None:
    comp.install_completion("zsh", tmp_path)
    _, ok, detail = comp.completion_check(tmp_path, "zsh")
    assert ok is False  # installed but fpath not set up -> honest 'not active yet'
    assert "fpath" in detail

    comp_dir = comp.target_path("zsh", tmp_path).parent  # type: ignore[union-attr]
    (tmp_path / ".zshrc").write_text(
        f"fpath=({comp_dir} $fpath)\nautoload -Uz compinit\ncompinit\n"
    )
    _, ok2, _ = comp.completion_check(tmp_path, "zsh")
    assert ok2 is True  # the config now references the dir on fpath -> confirmed active


def test_doctor_skips_cleanly_for_unsupported_shell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SHELL", "/usr/bin/fish")  # an out-of-scope shell -> detect_shell None
    name, ok, detail = comp.completion_check(tmp_path)  # shell defaults to detect_shell()
    # a pass with a note (nothing to install), never a failure
    assert (name, ok) == ("completion", True)
    assert "nothing to install" in detail
