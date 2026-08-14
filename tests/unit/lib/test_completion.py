# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
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


# ── consented rc activation (init appends the line only after an explicit yes) ─────────
#
# Reverse mutations — each applied once and observed RED (assertion failures, not errors), then
# restored. Re-run any to re-verify these guards bite:
#
# 1. idempotence. In `completion.activate_completion` disable the `if _MARK_START in existing:`
#    early return. -> 2 failed: `test_activation_is_idempotent[bash|zsh]` — the block lands twice.
# 2. no-consent write. In `initializer._offer_activation` drop `non_interactive` from the guard
#    (leaving `if rc is None:`). -> 1 failed: `test_non_interactive_init_never_touches_the_rc` —
#    an unattended init edits the user's rc.
# 3. false success. In `activate_completion` return `added=True, error=None` from the write's
#    `except OSError`. -> 2 failed: `test_unwritable_rc_fails_honestly[bash|zsh]` — an rc the
#    filesystem refused is reported as added.
# 4. lost markers. In `activate_completion` set `block = f"\n{line}\n"` (no fences). -> 5 failed:
#    `test_appended_block_is_fenced_and_removable[bash|zsh]` plus both idempotence cases and the
#    init-level yes case — the fences ARE the idempotence and removability mechanism, so dropping
#    them breaks re-running and un-doing at once.


def _install(shell: str, home: Path) -> Path:
    out = comp.install_completion(shell, home)
    assert out is not None
    return out.path


@pytest.mark.parametrize("shell", ["bash", "zsh"])
def test_activation_appends_only_the_bare_line(shell: str, tmp_path: Path) -> None:
    # The rc gets shell CODE, never the human hint sentence ("add to ~/.zshrc: ...") that the
    # not-active path prints — appending prose to an rc is a syntax error, not an activation.
    path = _install(shell, tmp_path)
    res = comp.activate_completion(shell, tmp_path, path)
    assert res is not None and res.ok and res.added
    body = res.rc.read_text()
    assert "add to ~/" not in body  # the instruction sentence never reaches the file
    if shell == "bash":
        assert f"source {path}" in body
    else:
        assert f"fpath=({path.parent} $fpath)" in body and "compinit" in body


@pytest.mark.parametrize("shell", ["bash", "zsh"])
def test_activation_is_idempotent(shell: str, tmp_path: Path) -> None:
    # ★ Running init repeatedly must leave EXACTLY one block, not a growing stack of them.
    path = _install(shell, tmp_path)
    first = comp.activate_completion(shell, tmp_path, path)
    second = comp.activate_completion(shell, tmp_path, path)
    assert first is not None and second is not None
    assert first.added is True and first.already is False
    assert second.added is False and second.already is True  # recognised, skipped
    rc_text = second.rc.read_text()
    assert rc_text.count(comp._MARK_START) == 1
    assert rc_text.count(comp._MARK_END) == 1


@pytest.mark.parametrize("shell", ["bash", "zsh"])
def test_appended_block_is_fenced_and_removable(shell: str, tmp_path: Path) -> None:
    # ★ The fences are the whole reversibility story: a user can cut from one marker to the other
    # and be byte-for-byte back where they started.
    rc = comp.rc_path(shell, tmp_path)
    assert rc is not None
    original = "# my own settings\nexport EDITOR=vi\n"
    rc.write_text(original)
    path = _install(shell, tmp_path)
    comp.activate_completion(shell, tmp_path, path)

    body = rc.read_text()
    assert original in body  # append-only: the user's own lines are untouched
    start, end = body.index(comp._MARK_START), body.index(comp._MARK_END)
    assert start < end
    stripped = body[:start] + body[end + len(comp._MARK_END) :]
    assert stripped.strip() == original.strip()  # cutting the fenced block restores the file


@pytest.mark.parametrize("shell", ["bash", "zsh"])
def test_activation_flips_the_doctor_green(shell: str, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # The doctor must reflect reality both ways: red while only the script is installed, green once
    # the rc actually carries the line. (bash-completion forced absent so the rc is the only path.)
    monkeypatch.setattr(comp, "_bash_completion_present", lambda: False)
    path = _install(shell, tmp_path)
    _, before, _ = comp.completion_check(tmp_path, shell)
    assert before is False  # installed but inert -> honest red
    comp.activate_completion(shell, tmp_path, path)
    _, after, detail = comp.completion_check(tmp_path, shell)
    assert after is True and "active" in detail


@pytest.mark.parametrize("shell", ["bash", "zsh"])
def test_unwritable_rc_fails_honestly(shell: str, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # ★ Never claim an edit the filesystem refused. Simulated by making the open() fail, so the
    # check is deterministic regardless of the uid the suite runs as (root ignores a chmod).
    path = _install(shell, tmp_path)

    def _boom(*_a: object, **_k: object) -> None:
        raise PermissionError("read-only file system")

    monkeypatch.setattr(Path, "open", _boom)
    res = comp.activate_completion(shell, tmp_path, path)
    assert res is not None
    assert res.ok is False and res.added is False
    assert "read-only" in (res.error or "")
    # and the rc really was not created/changed
    rc = comp.rc_path(shell, tmp_path)
    assert rc is not None and not rc.exists()
