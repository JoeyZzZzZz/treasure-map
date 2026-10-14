# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Uninstall removes what the ledger records and nothing else; data stays without the phrase."""

from __future__ import annotations

from pathlib import Path

import pytest
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
    # not running from uv's tool environment here: the program is left to the user
    assert "the tmap program stays" in result.output


def test_uv_self_uninstall_only_for_the_uv_tool_environment(tmp_path: Path) -> None:
    """MUTATION: drop the prefix comparison -> an editable / pip install would be uninstalled
    through uv -> RED."""
    from treasure_map.lib.setup.discover import RunResult

    tools = tmp_path / "tools"
    (tools / "tmap-agents").mkdir(parents=True)

    def run(argv: list[str], **_k: object) -> RunResult:
        assert argv[1:] == ["tool", "dir"]
        return RunResult(0, f"{tools}\n", "")

    which = {"uv": "/x/uv"}.get
    assert un.uv_self_uninstall(tools / "tmap-agents", tmp_path, which, run) == [
        "/x/uv",
        "tool",
        "uninstall",
        "tmap-agents",
    ]
    assert un.uv_self_uninstall(tmp_path / "venv", tmp_path, which, run) is None
    assert un.uv_self_uninstall(tools / "tmap-agents", tmp_path, lambda _n: None, run) is None


def _self_uninstall_cli(
    monkeypatch: pytest.MonkeyPatch, args: list[str], input_text: str = ""
) -> tuple[list[list[str]], str, int]:
    import os

    from treasure_map.cli import uninstall_cli

    execs: list[list[str]] = []

    def fake_exec(_file: str, argv: list[str]) -> None:
        execs.append(list(argv))
        raise SystemExit(0)

    monkeypatch.setattr(
        un, "uv_self_uninstall", lambda *_a: ["/x/uv", "tool", "uninstall", "tmap-agents"]
    )
    monkeypatch.setattr(os, "execvp", fake_exec)
    result = CliRunner().invoke(uninstall_cli.uninstall, args, input=input_text)
    return execs, result.output, result.exit_code


def test_the_program_is_removed_last_through_uv(monkeypatch: pytest.MonkeyPatch) -> None:
    """--yes removes it; a 'no' keeps it and says how; --dry-run only plans it."""
    execs, out, code = _self_uninstall_cli(monkeypatch, ["--yes"])
    assert execs == [["/x/uv", "tool", "uninstall", "tmap-agents"]] and code == 0
    assert "last: remove the tmap program itself" in out
    execs, out, _code = _self_uninstall_cli(monkeypatch, [], input_text="y\nn\n")
    assert execs == [] and "now run: /x/uv tool uninstall tmap-agents" in out
    execs, out, _code = _self_uninstall_cli(monkeypatch, ["--dry-run"])
    assert execs == [] and "last: remove the tmap program itself" in out


def test_the_program_stays_while_something_needs_fixing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A refused ledger entry: removing tmap now would leave the user without the tool to finish.

    MUTATION: drop the failure guard -> uv runs anyway -> RED."""
    home = Path.home()
    tm = home / ".treasure-map"
    ext = fakes.make_binexport(tmp_path / "settings" / "Extensions" / "BinExport")
    ledger = Ledger(tm / "toolchain" / LEDGER_NAME)
    ledger.add_pending("binexport", "dir", ext)
    ledger.commit("binexport", lib_digest="0" * 64)  # no longer matches: refused
    execs, out, code = _self_uninstall_cli(monkeypatch, ["--yes"])
    assert execs == [] and code == 1
    assert "the tmap program stays until the items above are fixed" in out


def test_a_completion_entry_elsewhere_is_refused(tmp_path: Path) -> None:
    """Only the file at tmap's completion location is removed for a completion entry.

    MUTATION: accept any completion path -> the named file is deleted -> RED."""
    home = Path.home()
    tm = home / ".treasure-map"
    victim = tmp_path / "important.txt"
    victim.write_text("mine")
    ledger = Ledger(tm / "toolchain" / LEDGER_NAME)
    ledger.add_pending("completion", "file", victim)
    ledger.commit("completion")
    report = _run(home)
    assert victim.is_file(), "a completion entry deleted a file outside tmap's location"
    assert victim.read_text() == "mine" and report.refused


def test_an_edit_is_restored_only_while_the_line_is_tmaps(tmp_path: Path) -> None:
    """MUTATION: restore unconditionally -> the user's own line is overwritten -> RED."""
    home = Path.home()
    tm = home / ".treasure-map"
    props = tmp_path / "launch.properties"
    ledger = Ledger(tm / "toolchain" / LEDGER_NAME)
    for current, expected in (
        ("JAVA_HOME_OVERRIDE=/tm/jdk\n", "JAVA_HOME_OVERRIDE=\n"),
        ("JAVA_HOME_OVERRIDE=/their/jdk\n", "JAVA_HOME_OVERRIDE=/their/jdk\n"),
    ):
        props.write_text(current)
        ledger.add_pending(
            "ghidra_jdk_override",
            "edit",
            props,
            line_before="JAVA_HOME_OVERRIDE=",
            line_after="JAVA_HOME_OVERRIDE=/tm/jdk",
        )
        ledger.commit("ghidra_jdk_override")
        _run(home)
        assert props.read_text() == expected


def test_a_ledger_naming_the_toolchain_dir_itself_is_refused() -> None:
    home = Path.home()
    tm = home / ".treasure-map"
    (tm / "toolchain" / "keep").mkdir(parents=True)
    ledger = Ledger(tm / "toolchain" / LEDGER_NAME)
    ledger.add_pending("jdk", "dir", tm / "toolchain")
    ledger.commit("jdk")
    report = _run(home)
    assert (tm / "toolchain" / "keep").is_dir() and report.refused


def test_an_unreadable_config_is_reported_not_skipped(tmp_path: Path) -> None:
    home = Path.home()
    tm = home / ".treasure-map"
    managed = fakes.make_jdk(tm / "toolchain" / "jdk-21")
    (tm / "config.yaml").write_text("toolchain: [unclosed\n")
    ledger = Ledger(tm / "toolchain" / LEDGER_NAME)
    ledger.add_pending("jdk", "dir", managed)
    ledger.commit("jdk")
    report = _run(home)
    assert any("config.yaml is unreadable" in m for m in report.manual)
