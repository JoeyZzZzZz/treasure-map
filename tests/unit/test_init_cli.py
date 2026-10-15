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
    assert ".env   :" in result.output


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


# ── exit codes ────────────────────────────────────────────────────────────────


def _red(tmp_path: Path) -> InitResult:
    from treasure_map.lib.setup.doctor import check

    return InitResult(
        config_path=tmp_path / "c",
        env_path=tmp_path / "e",
        atlas_dir=tmp_path,
        checks=(check("binexport", "missing", "not loaded"),),
    )


def test_unattended_init_fails_when_the_machine_is_not_ready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A script running `tmap init --yes` reads the exit code alone.

    MUTATION: exit 0 whatever the checks say -> RED (first two)."""
    monkeypatch.setattr("treasure_map.cli.init_cli.run_init", lambda **_: _red(tmp_path))
    assert CliRunner().invoke(init, ["--yes"]).exit_code == 1
    assert CliRunner().invoke(init, ["--non-interactive"]).exit_code == 1
    assert CliRunner().invoke(init, []).exit_code == 0  # a person read the checks


def test_ctrl_c_at_a_line_prompt_is_130(monkeypatch: pytest.MonkeyPatch) -> None:
    """MUTATION: let click's Abort through -> exit 1 -> RED."""
    import click

    def _abort(**_: object) -> InitResult:
        raise click.exceptions.Abort

    monkeypatch.setattr("treasure_map.cli.init_cli.run_init", _abort)
    assert CliRunner().invoke(init, []).exit_code == 130


def test_the_runs_probe_writes_nothing_beside_the_atlas(tmp_path: Path) -> None:
    """★ A WAL atlas closed cleanly is a single file; reading it through mode=ro would leave
    -wal and -shm beside it. The doctor reads, it does not write.

    MUTATION: always open mode=ro -> two new files -> RED."""
    import sqlite3

    from treasure_map.cli.init_cli import runs_currency
    from treasure_map.lib.atlas.connection import open_atlas
    from treasure_map.lib.config.config import AtlasConfig, Config

    atlas = tmp_path / "atlas" / "atlas.db"
    conn = open_atlas(atlas)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.commit()
    conn.close()
    sqlite3.connect(atlas).close()  # checkpoint: a clean single file
    before = sorted(p.name for p in atlas.parent.iterdir())
    assert before == ["atlas.db"]
    opened: list[str] = []
    real_connect = sqlite3.connect

    def spy(database: str, *a: object, **k: object) -> sqlite3.Connection:
        opened.append(f"{database} uri={k.get('uri')}")
        return real_connect(database, *a, **k)  # type: ignore[arg-type]

    import pytest as _pytest

    with _pytest.MonkeyPatch.context() as mp:
        mp.setattr(sqlite3, "connect", spy)
        result = runs_currency(Config(atlas=AtlasConfig(db_path=atlas)))
    assert result.count == 0
    assert sorted(p.name for p in atlas.parent.iterdir()) == before
    # read-only by construction, not by luck: a read-write handle could migrate the atlas
    assert len(opened) == 1 and opened[0].endswith("uri=True")
    assert "immutable=1" in opened[0] or "mode=ro" in opened[0]


def test_the_agent_prompts_are_written_out_in_full(capsys: pytest.CaptureFixture[str]) -> None:
    """The next steps are copied into an agent as they stand: no sentence cut short with '…'.

    MUTATION: shorten a prompt line with an ellipsis -> RED."""
    from treasure_map.cli.init_cli import _AUDIT_PROMPT, _DIFF_PROMPT, _next_steps

    _next_steps(InitResult(Path("c"), Path("e"), Path("a"), ()), False)
    out = capsys.readouterr().out
    assert "…" not in out
    for line in (*_AUDIT_PROMPT, *_DIFF_PROMPT):
        assert f"     {line}\n" in out
    assert "annotate_diff" in out and "get_diff_patch_view" in out
