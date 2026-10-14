# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""config.yaml's JDK and BinDiff go first in every tmap process's environment — and an unset key
changes nothing."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from treasure_map.lib.config.config import Config, ToolchainConfig
from treasure_map.lib.setup.toolchain_env import apply_toolchain_env

from . import fakes


def test_a_configured_toolchain_leads_path(tmp_path: Path) -> None:
    jdk = fakes.make_jdk(tmp_path / "jdk")
    bindiff = fakes.make_bindiff(tmp_path / "bd" / "bin" / "bindiff")
    env = {"PATH": "/usr/bin:/bin"}
    apply_toolchain_env(Config(toolchain=ToolchainConfig(java_home=jdk, bindiff=bindiff)), env)
    assert env["JAVA_HOME"] == str(jdk)
    assert env["PATH"].split(":")[:2] == [str(bindiff.parent), str(jdk / "bin")]
    once = dict(env)
    apply_toolchain_env(Config(toolchain=ToolchainConfig(java_home=jdk, bindiff=bindiff)), env)
    assert env["PATH"].count(str(jdk / "bin")) == 1 and once["JAVA_HOME"] == env["JAVA_HOME"]


def test_unset_keys_change_nothing(tmp_path: Path) -> None:
    """MUTATION: write JAVA_HOME / PATH even with nothing configured -> RED."""
    env = {"PATH": "/usr/bin:/bin", "JAVA_HOME": "/theirs"}
    notes = apply_toolchain_env(Config(), env)
    assert env == {"PATH": "/usr/bin:/bin", "JAVA_HOME": "/theirs"} and notes == []


def test_an_unusable_key_is_a_note_not_a_change(tmp_path: Path) -> None:
    jdk17 = fakes.make_jdk(tmp_path / "jdk17", "17.0.1")
    env = {"PATH": "/usr/bin"}
    notes = apply_toolchain_env(Config(toolchain=ToolchainConfig(java_home=jdk17)), env)
    assert env == {"PATH": "/usr/bin"} and len(notes) == 1 and "not used" in notes[0]


@pytest.mark.parametrize("argv", [["init", "--help"], ["mcp", "--help"]])
def test_a_broken_config_does_not_lock_out_init(argv: list[str]) -> None:
    """★ A config.yaml that is not YAML must not stop ``tmap init`` from repairing it.

    MUTATION: let load_config raise the bare YAML error (no ConfigError wrapping) -> the group
    callback crashes -> RED."""
    from treasure_map.cli.main import main

    cfg = Path.home() / ".treasure-map" / "config.yaml"
    cfg.write_text("ghidra: [unclosed\n")
    result = CliRunner().invoke(main, argv)
    assert result.exit_code == 0, result.output
    assert "warning:" in result.output and "not applied" in result.output
