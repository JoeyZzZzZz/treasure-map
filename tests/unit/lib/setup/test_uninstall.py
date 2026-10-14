# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Uninstall removes what the ledger records and nothing else; data stays without the phrase."""

from __future__ import annotations

from pathlib import Path

import yaml
from click.testing import CliRunner

from treasure_map.lib.diff.toolchain import binexport_lib_digest
from treasure_map.lib.setup import clients as cl
from treasure_map.lib.setup import uninstall as un
from treasure_map.lib.setup.ledger import LEDGER_NAME, Ledger

from . import fakes


def _chost(home: Path) -> cl.ClientHost:
    return cl.ClientHost(home, {}, fakes.linux(), lambda _n: None, fakes.fake_run())


def _run(home: Path) -> un.UninstallReport:
    tm = home / ".treasure-map"
    return un.uninstall(
        home=home,
        tm_home=tm,
        client_host=_chost(home),
        tmap=None,
        config_path=tm / "config.yaml",
        echo=lambda _m: None,
    )


def test_a_user_tool_named_in_config_is_never_removed(tmp_path: Path) -> None:
    """★ config points at the user's own Ghidra (not in the ledger): it stays, and so does the
    key.

    MUTATION: remove what config.yaml points at -> RED."""
    home = Path.home()
    tm = home / ".treasure-map"
    mine = fakes.make_ghidra(tmp_path / "my-ghidra")
    managed = fakes.make_jdk(tm / "toolchain" / "jdk-21.0.12.1+1")
    (tm / "config.yaml").write_text(
        yaml.safe_dump(
            {"ghidra": {"local": {"home": str(mine)}}, "toolchain": {"java_home": str(managed)}}
        )
    )
    ledger = Ledger(tm / "toolchain" / LEDGER_NAME)
    ledger.add_pending("jdk", "dir", managed)
    ledger.commit("jdk")
    report = _run(home)
    assert mine.is_dir() and not managed.exists()
    cfg = yaml.safe_load((tm / "config.yaml").read_text())
    assert cfg["ghidra"]["local"]["home"] == str(mine)
    assert cfg["toolchain"]["java_home"] is None
    assert not report.refused


def test_a_replaced_binexport_is_refused(tmp_path: Path) -> None:
    """★ The user swapped the BinExport tmap put in their Ghidra's settings dir: not removed.

    MUTATION: skip the digest comparison -> it is deleted -> RED."""
    home = Path.home()
    tm = home / ".treasure-map"
    ext = fakes.make_binexport(tmp_path / "settings" / "Extensions" / "BinExport")
    ledger = Ledger(tm / "toolchain" / LEDGER_NAME)
    ledger.add_pending("binexport", "dir", ext)
    ledger.commit("binexport", lib_digest=binexport_lib_digest(ext))
    (ext / "lib" / "BinExport.jar").write_bytes(b"their own build")
    report = _run(home)
    assert ext.is_dir()
    assert report.refused and "changed since tmap installed it" in report.refused[0]


def test_an_unchanged_binexport_outside_the_toolchain_dir_is_removed(tmp_path: Path) -> None:
    home = Path.home()
    tm = home / ".treasure-map"
    ext = fakes.make_binexport(tmp_path / "settings" / "Extensions" / "BinExport")
    ledger = Ledger(tm / "toolchain" / LEDGER_NAME)
    ledger.add_pending("binexport", "dir", ext)
    ledger.commit("binexport", lib_digest=binexport_lib_digest(ext))
    _run(home)
    assert not ext.exists()


def test_the_completion_rc_block_is_removed_and_nothing_else(tmp_path: Path) -> None:
    from treasure_map.lib.setup.completion import (
        _MARK_END,
        _MARK_START,
        target_path,
    )

    home = Path.home()
    tm = home / ".treasure-map"
    script = target_path("zsh", home)
    assert script is not None
    script.parent.mkdir(parents=True)
    script.write_text("#compdef tmap\n")
    rc = home / ".zshrc"
    rc.write_text(f"# mine\n\n{_MARK_START}\nfpath=(x $fpath)\n{_MARK_END}\nalias l=ls\n")
    ledger = Ledger(tm / "toolchain" / LEDGER_NAME)
    ledger.add_pending("completion", "file", script, rc_block=str(rc))
    ledger.commit("completion")
    _run(home)
    assert not script.exists()
    assert rc.read_text() == "# mine\nalias l=ls\n"  # the newline added with the block goes too
    assert not (tm / "toolchain" / LEDGER_NAME).exists()


def test_data_stays_without_the_phrase(tmp_path: Path) -> None:
    """★ --purge-data --yes without the typed phrase deletes nothing.

    MUTATION: let --yes stand in for the phrase -> RED."""
    from treasure_map.cli.uninstall_cli import uninstall

    home = Path.home()
    tm = home / ".treasure-map"
    (tm / "atlas.db").write_bytes(b"atlas")
    (tm / "workspaces" / "w1").mkdir(parents=True)
    result = CliRunner().invoke(uninstall, ["--yes"], input="")
    assert result.exit_code == 0, result.output
    assert (tm / "atlas.db").exists() and (tm / "workspaces" / "w1").exists()
    result = CliRunner().invoke(uninstall, ["--purge-data", "--yes"], input="yes\n")
    assert (tm / "atlas.db").exists() and (tm / "workspaces" / "w1").exists()
    assert "data kept" in result.output
    result = CliRunner().invoke(uninstall, ["--purge-data", "--yes"], input="delete my data\n")
    assert not (tm / "atlas.db").exists() and not (tm / "workspaces").exists()
    assert "now run: uv tool uninstall tmap-agents" in result.output
