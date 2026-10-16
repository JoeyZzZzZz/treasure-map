# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for _source_env_file and AtlasConfig."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from treasure_map.lib.config.config import AtlasConfig, Config, _source_env_file, load_config
from treasure_map.lib.errors import ConfigError

# ── _source_env_file ──────────────────────────────────────────────────────────


def test_source_env_file_sets_unset_var(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("TM_TEST_VAR_ALPHA=hello\n")
    monkeypatch.delenv("TM_TEST_VAR_ALPHA", raising=False)
    _source_env_file(env_file)
    assert os.environ["TM_TEST_VAR_ALPHA"] == "hello"
    monkeypatch.delenv("TM_TEST_VAR_ALPHA", raising=False)


def test_source_env_file_does_not_override_existing_var(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("TM_TEST_VAR_BETA=from-file\n")
    monkeypatch.setenv("TM_TEST_VAR_BETA", "from-environ")
    _source_env_file(env_file)
    assert os.environ["TM_TEST_VAR_BETA"] == "from-environ"


def test_source_env_file_absent_file_is_noop(tmp_path: Path) -> None:
    env_file = tmp_path / "does-not-exist.env"
    _source_env_file(env_file)  # must not raise


def test_source_env_file_skips_blank_lines(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("\n\n  \nTM_TEST_VAR_GAMMA=value\n\n")
    monkeypatch.delenv("TM_TEST_VAR_GAMMA", raising=False)
    _source_env_file(env_file)
    assert os.environ.get("TM_TEST_VAR_GAMMA") == "value"
    monkeypatch.delenv("TM_TEST_VAR_GAMMA", raising=False)


def test_source_env_file_skips_comment_lines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("# This is a comment\nTM_TEST_VAR_DELTA=set\n")
    monkeypatch.delenv("TM_TEST_VAR_DELTA", raising=False)
    _source_env_file(env_file)
    assert os.environ.get("TM_TEST_VAR_DELTA") == "set"
    monkeypatch.delenv("TM_TEST_VAR_DELTA", raising=False)


def test_source_env_file_strips_double_quotes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text('TM_TEST_VAR_EPSILON="quoted-value"\n')
    monkeypatch.delenv("TM_TEST_VAR_EPSILON", raising=False)
    _source_env_file(env_file)
    assert os.environ.get("TM_TEST_VAR_EPSILON") == "quoted-value"
    monkeypatch.delenv("TM_TEST_VAR_EPSILON", raising=False)


def test_source_env_file_strips_single_quotes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("TM_TEST_VAR_ZETA='single-quoted'\n")
    monkeypatch.delenv("TM_TEST_VAR_ZETA", raising=False)
    _source_env_file(env_file)
    assert os.environ.get("TM_TEST_VAR_ZETA") == "single-quoted"
    monkeypatch.delenv("TM_TEST_VAR_ZETA", raising=False)


def test_source_env_file_handles_export_prefix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("export TM_TEST_VAR_ETA=exported\n")
    monkeypatch.delenv("TM_TEST_VAR_ETA", raising=False)
    _source_env_file(env_file)
    assert os.environ.get("TM_TEST_VAR_ETA") == "exported"
    monkeypatch.delenv("TM_TEST_VAR_ETA", raising=False)


def test_source_env_file_skips_malformed_line_without_equals(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("NO_EQUALS_SIGN\nKEY=ok\n")
    # Must not raise; the malformed line is silently ignored
    _source_env_file(env_file)


def test_source_env_file_handles_value_with_equals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("TM_TEST_VAR_THETA=base64==\n")
    monkeypatch.delenv("TM_TEST_VAR_THETA", raising=False)
    _source_env_file(env_file)
    assert os.environ.get("TM_TEST_VAR_THETA") == "base64=="
    monkeypatch.delenv("TM_TEST_VAR_THETA", raising=False)


# ── load_config integration with TM_ENV_FILE ─────────────────────────────────


def test_load_config_sources_env_file_via_tm_env_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("TM_TEST_PROBE_IOTA=sourced-value\n")
    monkeypatch.setenv("TM_ENV_FILE", str(env_file))
    monkeypatch.delenv("TM_TEST_PROBE_IOTA", raising=False)
    load_config()
    assert os.environ.get("TM_TEST_PROBE_IOTA") == "sourced-value"
    monkeypatch.delenv("TM_TEST_PROBE_IOTA", raising=False)


def test_load_config_env_file_does_not_override_existing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("TM_TEST_PROBE_KAPPA=from-file\n")
    monkeypatch.setenv("TM_ENV_FILE", str(env_file))
    monkeypatch.setenv("TM_TEST_PROBE_KAPPA", "from-environ")
    load_config()
    assert os.environ["TM_TEST_PROBE_KAPPA"] == "from-environ"


def test_load_config_absent_env_file_returns_valid_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TM_ENV_FILE", str(tmp_path / "nonexistent.env"))
    cfg = load_config()
    assert cfg.log_level == "INFO"


# ── AtlasConfig ───────────────────────────────────────────────────────────────


def test_atlas_config_default_path_is_under_treasure_map() -> None:
    cfg = AtlasConfig()
    assert cfg.db_path == Path.home() / ".treasure-map" / "atlas.db"


def test_atlas_config_tilde_expansion() -> None:
    cfg = AtlasConfig(db_path="~/.treasure-map/custom.db")
    assert cfg.db_path == Path.home() / ".treasure-map" / "custom.db"
    assert "~" not in str(cfg.db_path)


def test_atlas_config_absolute_path_preserved() -> None:
    cfg = AtlasConfig(db_path="/tmp/test_atlas.db")
    assert cfg.db_path == Path("/tmp/test_atlas.db")


def test_config_includes_atlas_field() -> None:
    from treasure_map.lib.config.config import Config

    cfg = Config()
    assert hasattr(cfg, "atlas")
    assert isinstance(cfg.atlas, AtlasConfig)
    assert cfg.atlas.db_path == Path.home() / ".treasure-map" / "atlas.db"


# ── never from the working directory ──────────────────────────────────────────


def test_a_config_yaml_in_the_working_directory_is_never_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """tmap runs inside unpacked firmware: a config.yaml there must not pick the Ghidra tmap
    executes, the BinDiff/JDK put first on PATH, or where the atlas and workspaces go.

    MUTATION: merge ./config.yaml after the user config again -> every key below takes the
    firmware's value -> RED."""
    fw = tmp_path / "fw"
    fw.mkdir()
    (fw / "config.yaml").write_text(
        f"ghidra:\n  local:\n    home: {fw}/evil\n"
        f"toolchain:\n  java_home: {fw}/jdk\n  bindiff: {fw}/bin/bindiff\n"
        f"atlas:\n  db_path: {fw}/atlas.db\n"
        f"workspace_dir: {fw}/ws\n"
    )
    monkeypatch.chdir(fw)
    cfg = load_config()
    assert cfg.ghidra.local.home is None
    assert cfg.toolchain.java_home is None and cfg.toolchain.bindiff is None
    assert not str(cfg.atlas.db_path).startswith(str(fw))
    assert not str(cfg.workspace_dir).startswith(str(fw))


# ── a relative path in a config file is read from that file's directory ──────────────────────


def test_a_relative_path_in_config_yaml_is_read_from_its_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``ghidra.local.home: foo`` means ~/.treasure-map/foo wherever tmap is run — not a
    directory named foo inside whatever firmware tree is the working directory.

    MUTATION: merge the file without resolve_relative_paths -> the paths follow the working
    directory -> RED."""
    tm = Path.home() / ".treasure-map"
    (tm / "config.yaml").write_text(
        "ghidra:\n  local:\n    home: foo\n"
        "toolchain:\n  java_home: jdk/21\n  bindiff: bin/bindiff\n"
        "atlas:\n  db_path: data/atlas.db\n"
        "workspace_dir: ws\n"
    )
    fw = tmp_path / "fw"
    fw.mkdir()
    monkeypatch.chdir(fw)
    cfg = load_config()
    assert cfg.ghidra.local.home == tm / "foo"
    assert cfg.toolchain.java_home == tm / "jdk" / "21"
    assert cfg.toolchain.bindiff == tm / "bin" / "bindiff"
    assert cfg.atlas.db_path == tm / "data" / "atlas.db"
    assert cfg.workspace_dir == tm / "ws"


def test_absolute_and_home_paths_are_left_as_written(tmp_path: Path) -> None:
    from treasure_map.lib.config.config import resolve_relative_paths

    data = {"workspace_dir": "~/ws", "atlas": {"db_path": str(tmp_path / "a.db")}, "x": "rel"}
    out = resolve_relative_paths(data, tmp_path / "conf" / "config.yaml")
    assert out == data and out is not data


def test_a_relative_path_in_an_extra_config_is_read_from_that_files_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    extra = tmp_path / "profiles" / "big.yaml"
    extra.parent.mkdir()
    extra.write_text("workspace_dir: ws\n")
    monkeypatch.chdir(tmp_path)
    cfg = load_config(Path("profiles/big.yaml"))
    assert cfg.workspace_dir == tmp_path / "profiles" / "ws"


# ── a path from the .env or the environment is never read from the working directory ──────────

_PATH_VARS = (
    "TM_GHIDRA__LOCAL__HOME",
    "TM_TOOLCHAIN__JAVA_HOME",
    "TM_TOOLCHAIN__BINDIFF",
    "TM_ATLAS__DB_PATH",
    "TM_WORKSPACE_DIR",
)


def _load() -> tuple[Config | None, str | None]:
    """``load_config()``, with a ConfigError turned into the outcome a test asserts on."""
    try:
        return load_config(), None
    except ConfigError as exc:
        return None, str(exc)


@pytest.mark.parametrize("where", ["default", "named by TM_ENV_FILE"])
def test_a_relative_path_in_the_env_file_is_read_from_its_directory(
    where: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``TM_TOOLCHAIN__JAVA_HOME=jdk/21`` in a .env means jdk/21 beside that .env wherever tmap
    is run, as the same key in a config file would — and it is set absolute in the environment,
    so a child tmap inherits it that way. A .env outside ~/.treasure-map tells "the .env's
    directory" apart from "~/.treasure-map".

    MUTATION: read it from the working directory (``Path.cwd() / value``) -> every path lands in
    the firmware tree -> RED (observed).
    MUTATION: read it from ~/.treasure-map whatever the .env -> RED for the second case (observed).
    MUTATION: drop the resolution -> the relative value reaches the environment check and loading
    fails -> RED (assertion on the outcome; observed)."""
    env_dir = Path.home() / ".treasure-map"
    if where != "default":
        env_dir = tmp_path / "profiles"
        env_dir.mkdir()
        monkeypatch.setenv("TM_ENV_FILE", str(env_dir / "big.env"))
    (env_dir / ("big.env" if where != "default" else ".env")).write_text(
        "TM_GHIDRA__LOCAL__HOME=foo\n"
        "TM_TOOLCHAIN__JAVA_HOME=jdk/21\n"
        "TM_TOOLCHAIN__BINDIFF=bin/bindiff\n"
        "TM_ATLAS__DB_PATH=data/atlas.db\n"
        "TM_WORKSPACE_DIR=ws\n"
    )
    fw = tmp_path / "fw"
    fw.mkdir()
    monkeypatch.chdir(fw)
    cfg, error = _load()
    assert error is None and cfg is not None, error
    assert cfg.ghidra.local.home == env_dir / "foo"
    assert cfg.toolchain.java_home == env_dir / "jdk" / "21"
    assert cfg.toolchain.bindiff == env_dir / "bin" / "bindiff"
    assert cfg.atlas.db_path == env_dir / "data" / "atlas.db"
    assert cfg.workspace_dir == env_dir / "ws"
    assert os.environ["TM_TOOLCHAIN__JAVA_HOME"] == str(env_dir / "jdk" / "21")


@pytest.mark.parametrize("var", _PATH_VARS)
def test_a_relative_path_in_the_environment_is_refused(
    var: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A ``TM_*`` path exported in the shell has no file whose directory it could be read from,
    and the working directory is never that base: a relative one stops loading with an error
    naming the variable, instead of naming another file in each firmware tree tmap is run in.

    MUTATION: drop the check in _apply_env_overrides -> the relative path is loaded -> RED
    (observed)."""
    monkeypatch.setenv(var, "rel/x")
    monkeypatch.chdir(tmp_path)
    cfg, error = _load()
    assert cfg is None and error is not None
    assert f"{var}='rel/x' is a relative path" in error, error


def test_an_absolute_or_home_path_in_the_environment_is_used_as_given(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MUTATION: count a ``~`` path as relative (``os.path.isabs`` without ``expanduser``) ->
    ``~/ws`` is refused -> RED (observed)."""
    monkeypatch.setenv("TM_WORKSPACE_DIR", "~/ws")
    monkeypatch.setenv("TM_ATLAS__DB_PATH", str(tmp_path / "a.db"))
    cfg, error = _load()
    assert error is None and cfg is not None, error
    assert cfg.workspace_dir == Path.home() / "ws"
    assert cfg.atlas.db_path == tmp_path / "a.db"


def test_a_relative_env_file_name_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``TM_ENV_FILE=conf/.env`` would source a .env from whatever directory tmap runs in, and a
    firmware tree's own one could then pick the Ghidra tmap executes. It is refused, and nothing
    from that file reaches the environment.

    MUTATION: drop the TM_ENV_FILE check -> the firmware tree's .env is sourced and its Ghidra is
    loaded -> RED (observed)."""
    fw = tmp_path / "fw"
    (fw / "conf").mkdir(parents=True)
    (fw / "conf" / ".env").write_text(f"TM_GHIDRA__LOCAL__HOME={fw}/evil\n")
    monkeypatch.chdir(fw)
    monkeypatch.setenv("TM_ENV_FILE", "conf/.env")
    cfg, error = _load()
    assert cfg is None and error is not None
    assert "TM_ENV_FILE='conf/.env' is a relative path" in error, error
    assert "TM_GHIDRA__LOCAL__HOME" not in os.environ
