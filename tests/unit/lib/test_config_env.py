# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for _source_env_file and AtlasConfig (M2 Step 2 config additions)."""

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
