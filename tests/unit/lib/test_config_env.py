# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for _source_env_file and AtlasConfig."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from treasure_map.lib.config.config import AtlasConfig, _source_env_file, load_config

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
