# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Uninstall removes what the ledger records and nothing else; data stays without the phrase."""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from treasure_map.lib.diff.toolchain import binexport_lib_digest
from treasure_map.lib.setup import clients as cl
from treasure_map.lib.setup import uninstall as un
from treasure_map.lib.setup.ledger import LEDGER_NAME, Ledger
from treasure_map.lib.setup.tmap_files import ENV_TEXT, config_text

from . import fakes


def _chost(home: Path) -> cl.ClientHost:
    return cl.ClientHost(home, {}, fakes.linux(), lambda _n: None, fakes.fake_run())


def _tmap_db(path: Path, tables: tuple[str, ...]) -> Path:
    import sqlite3

    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    for name in tables:
        conn.execute(f"CREATE TABLE {name} (id INTEGER)")
    conn.commit()
    conn.close()
    return path


def _atlas(path: Path) -> Path:
    return _tmap_db(path, ("run", "instance"))


def _workspace(path: Path) -> Path:
    _tmap_db(path / "analysis.db", ("binaries", "functions"))
    return path


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
    _atlas(tm / "atlas.db")
    _workspace(tm / "workspaces" / "w1")
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


def test_purge_deletes_only_what_is_provably_tmaps(tmp_path: Path) -> None:
    """★ The workspace base may be any directory the user named: only its tmap workspaces go,
    and the base stays while anything else is in it. config.yaml / .env go only when tmap wrote
    them.

    MUTATION: delete the whole workspace base (rmtree) -> the user's directory and file go -> RED.
    MUTATION: delete .env whoever wrote it -> the user's .env goes -> RED."""
    home = tmp_path / "home"
    tm = home / ".treasure-map"
    base = tmp_path / "projects"
    _workspace(base / "w1")
    (base / "mine").mkdir()
    (base / "mine" / "notes.txt").write_text("mine")
    (base / "plain").mkdir()  # no analysis.db: not provably a workspace
    _atlas(tm / "atlas.db")
    (tm / "config.yaml").write_text(config_text(tm / "config.yaml", {"workspace_dir": str(base)}))
    (tm / ".env").write_text("MY_KEY=1\n")
    plan = un.purge_plan(tm_home=tm, atlas=tm / "atlas.db", workspace_dir=base, home=home)
    assert un.purge_data(plan, un.PURGE_PHRASE)
    assert not (base / "w1").exists() and not (tm / "atlas.db").exists()
    assert (base / "mine" / "notes.txt").is_file() and (base / "plain").is_dir()
    assert not (tm / "config.yaml").exists()
    assert (tm / ".env").is_file() and (tm / ".env").read_text() == "MY_KEY=1\n"
    assert any(".env: not written by tmap init" in k for k in plan.keep)
    assert f"{base}: 2 other entries (not tmap workspaces): mine, plain" in plan.keep


def test_purge_takes_tmaps_env_and_an_older_inits_empty_one(tmp_path: Path) -> None:
    home = tmp_path / "home"
    tm = home / ".treasure-map"
    tm.mkdir(parents=True, exist_ok=True)
    (tm / ".env").write_text(ENV_TEXT + "TM_X=1\n")  # tmap's, edited since: still tmap's
    plan = un.purge_plan(tm_home=tm, atlas=tm / "atlas.db", workspace_dir=tm / "ws", home=home)
    assert tm / ".env" in plan.delete
    (tm / ".env").write_text("")
    plan = un.purge_plan(tm_home=tm, atlas=tm / "atlas.db", workspace_dir=tm / "ws", home=home)
    assert tm / ".env" in plan.delete


def test_purge_deletes_no_workspace_when_the_base_is_home_or_above(tmp_path: Path) -> None:
    """★ workspace_dir: "~" (or "/") must not turn a purge into deleting the user's directories,
    even ones holding a tmap analysis.db.

    MUTATION: drop the home/ancestor refusal -> the directory under home goes -> RED."""
    home = tmp_path / "home"
    tm = home / ".treasure-map"
    _workspace(home / "proj")
    for base in (home, tmp_path):
        plan = un.purge_plan(tm_home=tm, atlas=tm / "atlas.db", workspace_dir=base, home=home)
        assert home / "proj" not in plan.delete and base not in plan.rmdir_if_empty
        assert any("the home directory or above it" in k for k in plan.keep)


def test_a_non_tmap_atlas_is_kept(tmp_path: Path) -> None:
    home = tmp_path / "home"
    tm = home / ".treasure-map"
    tm.mkdir(parents=True, exist_ok=True)
    (tm / "atlas.db").write_bytes(b"not a database")
    plan = un.purge_plan(tm_home=tm, atlas=tm / "atlas.db", workspace_dir=tm / "ws", home=home)
    assert tm / "atlas.db" not in plan.delete
    assert any("not a tmap atlas" in k for k in plan.keep)


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


def test_the_rc_block_comes_out_of_a_non_utf8_rc_byte_for_byte(tmp_path: Path) -> None:
    """An rc with a latin-1 line: the block goes, every other byte stays.

    MUTATION: read the rc as UTF-8 text -> UnicodeDecodeError, nothing removed -> RED."""
    from treasure_map.lib.setup.completion import _MARK_END, _MARK_START

    rc = tmp_path / ".zshrc"
    mine = b"# caf\xe9\nalias l=ls\n"
    rc.write_bytes(mine + f"\n{_MARK_START}\nfpath=(x $fpath)\n{_MARK_END}\n".encode())
    outcome = "ok"
    try:
        note = un._remove_rc_block(rc)
    except Exception as exc:  # noqa: BLE001 -- the mutation's failure must read as an assertion
        outcome, note = repr(exc), ""
    assert outcome == "ok" and note.startswith("removed")
    assert rc.read_bytes() == mine


def test_a_failed_rc_rewrite_leaves_the_rc_and_the_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The rc is rewritten atomically: a failure mid-write leaves it exactly as it was, says so,
    and keeps the ledger entry so a later run removes the block.

    MUTATION: rewrite the rc in place (write_text) -> it is changed and reported removed -> RED."""
    from treasure_map.lib.setup.completion import _MARK_END, _MARK_START, target_path

    home = Path.home()
    tm = home / ".treasure-map"
    script = target_path("zsh", home)
    assert script is not None
    script.parent.mkdir(parents=True)
    script.write_text("#compdef tmap\n")
    rc = home / ".zshrc"
    before = f"# mine\n\n{_MARK_START}\nfpath=(x $fpath)\n{_MARK_END}\n"
    rc.write_text(before)
    ledger = Ledger(tm / "toolchain" / LEDGER_NAME)
    ledger.add_pending("completion", "file", script, rc_block=str(rc))
    ledger.commit("completion")

    def _no_disk(_path: Path, _data: bytes, _mode: int) -> None:
        raise OSError("disk full")  # the atomic writer fails before its rename: nothing changed

    monkeypatch.setattr(cl, "_atomic_write", _no_disk)
    report = _run(home)
    assert rc.read_text() == before
    assert any("could not write" in m for m in report.manual)
    assert Ledger.load(tm / "toolchain" / LEDGER_NAME).find("completion") is not None


# ── a configuration or directory tmap may not write: reported, and the rest still goes ───────

_ROOT = os.geteuid() == 0
_needs_non_root = pytest.mark.skipif(_ROOT, reason="root ignores directory permissions")


@contextmanager
def _mode(path: Path, mode: int) -> Iterator[None]:
    os.chmod(path, mode)
    try:
        yield
    finally:
        os.chmod(path, 0o755)


def _managed_jdk(tm: Path) -> Path:
    jdk = fakes.make_jdk(tm / "toolchain" / "jdk-21")
    ledger = Ledger(tm / "toolchain" / LEDGER_NAME)
    ledger.add_pending("jdk", "dir", jdk)
    ledger.commit("jdk")
    return jdk


def _run_reporting(home: Path) -> tuple[un.UninstallReport | None, str]:
    """``_run``, with an escaping exception turned into the outcome a test asserts on."""
    try:
        return _run(home), "ok"
    except Exception as exc:  # noqa: BLE001 -- the mutation's failure must read as an assertion
        return None, repr(exc)


@_needs_non_root
def test_an_unwritable_agent_config_is_a_manual_step_and_the_toolchain_still_goes() -> None:
    """A read-only ~/.cursor: its entry cannot be removed. That is a to-do for the user with the
    file untouched — and the toolchain is still removed.

    MUTATION: drop json_transaction's OSError guard -> the message no longer says the file was
    not modified -> RED (assertion). With unregister's guard dropped too, the PermissionError
    escapes uninstall and nothing of the toolchain is removed -> RED (assertion)."""
    home = Path.home()
    tm = home / ".treasure-map"
    jdk = _managed_jdk(tm)
    cursor = home / ".cursor"
    cursor.mkdir()
    config = cursor / "mcp.json"
    body = json.dumps({"mcpServers": {"treasure-map": {"command": "/x/tmap", "args": ["mcp"]}}})
    config.write_text(body)
    with _mode(cursor, 0o555):
        report, outcome = _run_reporting(home)
    assert outcome == "ok" and report is not None
    lines = [m for m in report.manual if m.startswith("Cursor:")]
    assert len(lines) == 1 and "could not write" in lines[0] and "not modified" in lines[0]
    assert "remove its treasure-map entry by hand" in lines[0]
    assert config.read_text() == body
    assert not jdk.exists()


@_needs_non_root
def test_an_unwritable_dsh_patch_file_is_a_manual_step() -> None:
    """MUTATION: drop _unregister_dsh's OSError guard -> only the catch-all answers, without
    naming the file it could not write -> RED (assertion)."""
    home = Path.home()
    tm = home / ".treasure-map"
    jdk = _managed_jdk(tm)
    dsh = home / ".dsh"
    dsh.mkdir()
    patch = dsh / cl.DSH_PATCH_FILE
    patch.write_text(cl.dsh_block("/x/tmap"))
    with _mode(dsh, 0o555):
        report, outcome = _run_reporting(home)
    assert outcome == "ok" and report is not None
    lines = [m for m in report.manual if m.startswith("dsh:")]
    assert len(lines) == 1 and f"could not write {patch}" in lines[0], lines
    assert "treasure-map-mcp insert" in lines[0]
    assert patch.read_text() == cl.dsh_block("/x/tmap") and not jdk.exists()


@_needs_non_root
def test_an_unreadable_agent_directory_does_not_stop_the_uninstall() -> None:
    """~/.cursor without read or search permission: even reading the entry fails. unregister's
    catch-all turns that into a to-do, and the toolchain is still removed. This calls the library
    step directly; the command, which surveys the agents first, is tested below.

    MUTATION: call the unguarded _unregister from unregister -> PermissionError escapes, the
    toolchain stays -> RED (assertion)."""
    home = Path.home()
    tm = home / ".treasure-map"
    jdk = _managed_jdk(tm)
    cursor = home / ".cursor"
    cursor.mkdir()
    (cursor / "mcp.json").write_text("{}")
    with _mode(cursor, 0o000):
        report, outcome = _run_reporting(home)
    assert outcome == "ok" and report is not None
    lines = [m for m in report.manual if m.startswith("Cursor:")]
    assert len(lines) == 1 and "could not change its configuration" in lines[0], lines
    assert not jdk.exists()


@_needs_non_root
def test_a_toolchain_path_that_cannot_be_removed_leaves_its_entry_and_the_rest_goes() -> None:
    """MUTATION: drop the per-entry OSError guard -> the PermissionError stops the loop before
    the other entry is removed -> RED (assertion)."""
    home = Path.home()
    tm = home / ".treasure-map"
    jdk = _managed_jdk(tm)
    stuck = tm / "toolchain" / "bindiff-8"
    (stuck / "locked").mkdir(parents=True)
    (stuck / "locked" / "f").write_text("x")
    ledger = Ledger.load(tm / "toolchain" / LEDGER_NAME)
    ledger.add_pending("bindiff", "dir", stuck)  # newest: handled first
    ledger.commit("bindiff")
    with _mode(stuck / "locked", 0o555):
        report, outcome = _run_reporting(home)
    assert outcome == "ok" and report is not None
    assert any(m.startswith(f"could not remove {stuck}") for m in report.manual), report.manual
    assert not jdk.exists()
    left = Ledger.load(tm / "toolchain" / LEDGER_NAME)
    assert left.find("bindiff") is not None and left.find("jdk") is None


def _no_agent_dirs_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """The command reads the real environment: an agent directory exported in the developer's
    shell must not be what it surveys."""
    for var in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "DSH_HOME"):
        monkeypatch.delenv(var, raising=False)


@_needs_non_root
def test_the_cli_goes_on_past_an_agent_directory_it_cannot_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``tmap uninstall --yes`` with ~/.cursor unreadable (mode 000): the survey that makes the
    plan cannot read Cursor's configuration either. Cursor's entry becomes a step to do by hand,
    the toolchain is still removed, and the command exits 1 for that step — it does not stop at
    the plan.

    MUTATION: survey calls inspect unguarded -> "stopped: [Errno 13] ..." before the plan, the
    JDK still there -> RED (assertion; observed)."""
    from treasure_map.cli.uninstall_cli import uninstall

    _no_agent_dirs_from_the_environment(monkeypatch)
    monkeypatch.setattr(un, "uv_self_uninstall", lambda *_a: None)
    home = Path.home()
    jdk = _managed_jdk(home / ".treasure-map")
    cursor = home / ".cursor"
    cursor.mkdir()
    body = json.dumps({"mcpServers": {"treasure-map": {"command": "/x/tmap", "args": ["mcp"]}}})
    (cursor / "mcp.json").write_text(body)
    with _mode(cursor, 0o000):
        result = CliRunner().invoke(uninstall, ["--yes"])
    out = result.output
    assert "stopped:" not in out, out
    assert f"remove treasure-map from Cursor ({cursor / 'mcp.json'})" in out, out
    assert "✗ Cursor: could not change its configuration" in out, out
    assert "remove its treasure-map entry by hand" in out
    assert not jdk.exists()
    assert (cursor / "mcp.json").read_text() == body
    assert isinstance(result.exception, SystemExit) and result.exit_code == 1


def test_the_cli_reports_a_filesystem_error_instead_of_a_traceback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A filesystem error that no step expected (here the uninstall step itself raises one) ends
    the command with "stopped: ..." and exit 1 — no traceback.

    MUTATION: drop the CLI's OSError guard -> the PermissionError escapes -> RED (assertion;
    observed)."""
    from treasure_map.cli.uninstall_cli import uninstall

    def _refused(**_k: object) -> un.UninstallReport:
        raise PermissionError(13, "Permission denied", str(Path.home() / "somewhere"))

    _no_agent_dirs_from_the_environment(monkeypatch)
    monkeypatch.setattr(un, "uninstall", _refused)
    monkeypatch.setattr(un, "uv_self_uninstall", lambda *_a: None)
    result = CliRunner().invoke(uninstall, ["--yes"])
    assert isinstance(result.exception, SystemExit), repr(result.exception)
    assert result.exit_code == 1
    assert "stopped: [Errno 13] Permission denied" in result.output + result.stderr


def _completion_entry(home: Path, rc: Path, **extra: object) -> Path:
    from treasure_map.lib.setup.completion import target_path

    script = target_path("bash", home)
    assert script is not None
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text("# tmap completion\n")
    ledger = Ledger(home / ".treasure-map" / "toolchain" / LEDGER_NAME)
    ledger.add_pending("completion", "file", script, rc_block=str(rc), **extra)
    ledger.commit("completion")
    return script


def test_an_rc_tmap_created_goes_once_it_is_empty_again() -> None:
    """macOS: tmap created ~/.bash_profile for its block. Left behind empty, it would still stop
    bash from reading ~/.profile — so uninstall deletes it once nothing else is in it.

    MUTATION: ignore the ledger's rc_created -> the empty file stays -> RED."""
    from treasure_map.lib.setup.completion import _MARK_END, _MARK_START

    home = Path.home()
    rc = home / ".bash_profile"
    rc.write_text(f"\n{_MARK_START}\nsource x\n{_MARK_END}\n")  # as activate_completion wrote it
    _completion_entry(home, rc, rc_created=True)
    report = _run(home)
    assert not rc.exists(), rc.read_bytes()
    assert any(f"removed {rc} (tmap created it" in m for m in report.removed)


def test_an_rc_tmap_created_but_the_user_wrote_to_stays() -> None:
    """MUTATION: delete a created rc without checking it is empty -> the user's line goes -> RED."""
    from treasure_map.lib.setup.completion import _MARK_END, _MARK_START

    home = Path.home()
    rc = home / ".bash_profile"
    rc.write_text(f"\n{_MARK_START}\nsource x\n{_MARK_END}\nexport EDITOR=vi\n")
    _completion_entry(home, rc, rc_created=True)
    _run(home)
    assert rc.is_file() and rc.read_text() == "export EDITOR=vi\n"


def test_an_rc_tmap_created_that_is_now_a_symlink_is_written_through_not_deleted(
    tmp_path: Path,
) -> None:
    """tmap created ~/.bash_profile; the user later made it a link into a dotfiles repository,
    and the linked file holds only the block. The block comes out of the linked file and the link
    stays: deleting it would take the user's link, not a file tmap made.

    MUTATION: delete a created rc left empty even when it is a symbolic link (drop
    ``not rc.is_symlink()``) -> the link is gone -> RED (observed)."""
    from treasure_map.lib.setup.completion import _MARK_END, _MARK_START

    home = Path.home()
    target = tmp_path / "dotfiles" / "bash_profile"
    target.parent.mkdir()
    target.write_text(f"\n{_MARK_START}\nsource x\n{_MARK_END}\n")
    rc = home / ".bash_profile"
    rc.symlink_to(target)
    _completion_entry(home, rc, rc_created=True)
    report = _run(home)
    assert rc.is_symlink() and os.path.realpath(rc) == os.path.realpath(target)
    assert target.read_text() == ""
    assert f"removed tmap's completion block from {rc}" in report.removed, report.removed


def test_an_rc_the_user_had_stays_even_when_empty() -> None:
    """The rc existed before tmap (no rc_created): emptied of the block, it is still the user's.

    MUTATION: delete any rc left empty, created or not -> RED."""
    from treasure_map.lib.setup.completion import _MARK_END, _MARK_START

    home = Path.home()
    rc = home / ".profile"
    rc.write_text(f"\n{_MARK_START}\nsource x\n{_MARK_END}\n")
    _completion_entry(home, rc)
    _run(home)
    assert rc.is_file() and rc.read_text() == ""


def test_a_sqlite_atlas_without_tmaps_tables_is_kept(tmp_path: Path) -> None:
    """A real SQLite file at the atlas path is not enough: it must hold tmap's tables (both of
    them; one name in common is not tmap's database).

    MUTATION: _tmap_database accepts any SQLite file (return True after the header check) ->
    the file is planned for deletion -> RED."""
    home = tmp_path / "home"
    tm = home / ".treasure-map"
    atlas = _tmap_db(tm / "atlas.db", ("run", "notes"))
    plan = un.purge_plan(tm_home=tm, atlas=atlas, workspace_dir=tm / "ws", home=home)
    assert atlas not in plan.delete
    assert any(f"{atlas}: not a tmap atlas" in k for k in plan.keep)


def test_a_symlinked_atlas_is_kept_and_named(tmp_path: Path) -> None:
    """An atlas path that is a symbolic link is not followed — not even to tmap's own database:
    it is kept, and named with that reason rather than as "not a tmap atlas".

    MUTATION: drop the symbolic-link branch -> the link to a real tmap atlas is listed as "not a
    tmap atlas" -> RED (observed)."""
    home = Path.home()
    tm = home / ".treasure-map"
    real = _atlas(tmp_path / "elsewhere" / "atlas.db")
    link = tm / "atlas.db"
    link.symlink_to(real)
    plan = un.purge_plan(tm_home=tm, atlas=link, workspace_dir=tm / "ws", home=home)
    assert link not in plan.delete and real not in plan.delete
    assert f"{link}: a symbolic link; tmap does not follow it" in plan.keep, plan.keep
    assert un.purge_data(plan, un.PURGE_PHRASE)
    assert link.is_symlink() and real.is_file()


def test_a_workspace_whose_sqlite_analysis_db_is_not_tmaps_is_kept(tmp_path: Path) -> None:
    """A directory holding an ``analysis.db`` that is SQLite but not tmap's: nothing in it goes.

    MUTATION: _tmap_database accepts any SQLite file -> the directory's contents are planned for
    deletion -> RED."""
    home = tmp_path / "home"
    tm = home / ".treasure-map"
    base = tmp_path / "projects"
    theirs = base / "theirs"
    _tmap_db(theirs / "analysis.db", ("binaries", "notes"))
    (theirs / "notes.txt").write_text("mine")
    plan = un.purge_plan(tm_home=tm, atlas=tm / "atlas.db", workspace_dir=base, home=home)
    assert not [p for p in plan.delete if p == theirs or theirs in p.parents], plan.delete
    assert un.purge_data(plan, un.PURGE_PHRASE)
    assert (theirs / "analysis.db").is_file() and (theirs / "notes.txt").is_file()


def test_the_rc_keeps_its_permission_bits(tmp_path: Path) -> None:
    """A 0600 rc stays 0600 once the block is out.

    MUTATION: write the rc back with a fixed 0644 -> RED."""
    import stat as st

    from treasure_map.lib.setup.completion import _MARK_END, _MARK_START

    rc = tmp_path / ".zshrc"
    rc.write_text(f"# mine\n\n{_MARK_START}\nfpath=(x $fpath)\n{_MARK_END}\n")
    os.chmod(rc, 0o600)
    note = un._remove_rc_block(rc)
    assert note.startswith("removed") and rc.read_text() == "# mine\n"
    assert st.S_IMODE(rc.stat().st_mode) == 0o600


def test_purge_takes_only_what_a_scan_wrote_in_a_workspace(tmp_path: Path) -> None:
    """A workspace base set to where the firmware lives: a workspace directory then holds the
    user's image beside tmap's analysis.db. Only what the scan wrote goes; the image, the
    unpacked tree and the directory stay, and are listed.

    MUTATION: delete the whole workspace directory (rmtree) -> the user's image goes -> RED.
    MUTATION: take any state.db, not only tmap's old checkpoint database -> RED."""
    home = tmp_path / "home"
    tm = home / ".treasure-map"
    base = tmp_path / "fw"
    ws = _workspace(base / "router")
    (ws / "analysis.db-wal").write_bytes(b"")
    (ws / ".tmap-scan.lock").write_text("")
    (ws / "ghidra_output").mkdir()
    (ws / "ghidra_output" / "busybox_deadbeef_ghidra.json").write_text("{}")
    _tmap_db(ws / "state.db", ("steps",))
    (ws / "firmware.img").write_bytes(b"FW")
    (ws / "squashfs-root" / "bin").mkdir(parents=True)
    other = _workspace(base / "other")
    _tmap_db(other / "state.db", ("notes",))  # a state.db that is not tmap's
    plan = un.purge_plan(tm_home=tm, atlas=tm / "atlas.db", workspace_dir=base, home=home)
    assert un.purge_data(plan, un.PURGE_PHRASE)
    assert ws.is_dir() and sorted(p.name for p in ws.iterdir()) == ["firmware.img", "squashfs-root"]
    assert (ws / "firmware.img").read_bytes() == b"FW" and (ws / "squashfs-root" / "bin").is_dir()
    assert other.is_dir() and sorted(p.name for p in other.iterdir()) == ["state.db"]
    assert any(
        k == f"{ws}: 2 other entries (not written by tmap): firmware.img, squashfs-root"
        for k in plan.keep
    ), plan.keep


def test_an_emptied_workspace_goes_and_a_base_the_user_chose_stays(tmp_path: Path) -> None:
    """A workspace directory left empty is removed; the base the user named is not, even empty
    — only the default base inside ~/.treasure-map goes with it.

    MUTATION: remove the workspace base whenever it is empty -> RED."""
    home = tmp_path / "home"
    tm = home / ".treasure-map"
    base = tmp_path / "projects"
    _workspace(base / "w1")
    plan = un.purge_plan(tm_home=tm, atlas=tm / "atlas.db", workspace_dir=base, home=home)
    assert un.purge_data(plan, un.PURGE_PHRASE)
    assert not (base / "w1").exists()
    assert base.is_dir() and list(base.iterdir()) == []


def test_what_purge_keeps_is_listed_by_name(tmp_path: Path) -> None:
    """Kept entries are named, not only counted: the workspace base's other entries (a long list
    is cut with "and N more"), a symlinked config.yaml, and anything else in ~/.treasure-map.

    MUTATION: list only the count -> RED.
    MUTATION: leave ~/.treasure-map's other entries unlisted -> RED."""
    home = tmp_path / "home"
    tm = home / ".treasure-map"
    base = tmp_path / "projects"
    for i in range(12):
        (base / f"d{i:02d}").mkdir(parents=True)
    _atlas(tm / "atlas.db")
    (tm / "atlas.db.bak").write_bytes(b"x")
    dotfiles = tmp_path / "dotfiles.yaml"
    dotfiles.write_text(config_text(dotfiles, {"workspace_dir": str(base)}))
    (tm / "config.yaml").symlink_to(dotfiles)
    plan = un.purge_plan(tm_home=tm, atlas=tm / "atlas.db", workspace_dir=base, home=home)
    assert (
        f"{base}: 12 other entries (not tmap workspaces): "
        "d00, d01, d02, d03, d04, d05, d06, d07, d08, d09 and 2 more"
    ) in plan.keep, plan.keep
    assert f"{tm / 'config.yaml'}: a symbolic link; tmap does not follow it" in plan.keep
    assert f"{tm}: 1 other entry (not tmap data): atlas.db.bak" in plan.keep, plan.keep
    assert un.purge_data(plan, un.PURGE_PHRASE)
    assert (tm / "atlas.db.bak").is_file() and dotfiles.is_file()


def test_a_relative_config_key_pointing_at_a_removed_path_is_cleared(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``toolchain.java_home: toolchain/jdk-21`` names ~/.treasure-map/toolchain/jdk-21 (read from
    the config's directory): once that JDK is removed, the key is cleared.

    MUTATION: test the key's raw text (read from the working directory) -> it stays -> RED."""
    home = Path.home()
    tm = home / ".treasure-map"
    _managed_jdk(tm)
    (tm / "config.yaml").write_text(
        yaml.safe_dump({"toolchain": {"java_home": "toolchain/jdk-21"}})
    )
    monkeypatch.chdir(tmp_path)
    report = _run(home)
    assert yaml.safe_load((tm / "config.yaml").read_text())["toolchain"]["java_home"] is None
    assert any("cleared toolchain.java_home" in r for r in report.removed)
