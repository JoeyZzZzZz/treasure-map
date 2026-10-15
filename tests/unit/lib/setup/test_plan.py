# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""``tmap init`` end to end on a fake machine: the three modes, what each may write, a full
install from (fake) pinned archives, and the runs that must write nothing."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from treasure_map.lib.diff import toolchain as tc
from treasure_map.lib.setup import initializer
from treasure_map.lib.setup.doctor import McpProbe
from treasure_map.lib.setup.initializer import PlatformUnsupportedError, run_init

from . import fakes

_REAL_DETECT = tc.detect_toolchain


@pytest.fixture()
def home() -> Path:
    return Path.home()  # the conftest's throwaway home


@pytest.fixture()
def archives(monkeypatch: pytest.MonkeyPatch) -> dict[str, bytes]:
    data = fakes.fake_archives()
    lock = fakes.fake_lock(data)
    monkeypatch.setattr("treasure_map.lib.setup.toolchain_lock.load_lock", lambda: lock)
    return data


def _detect_all_clients(home: Path) -> None:
    (home / ".claude").mkdir()
    (home / ".codex").mkdir()
    (home / ".cursor").mkdir()
    desktop = home / ".config" / "Claude" / "claude_desktop_config.json"
    desktop.parent.mkdir(parents=True)
    desktop.write_text("{}")
    (home / ".dsh").mkdir()


def _tree(root: Path) -> dict[str, tuple[bytes, int]]:
    out = {}
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            p = Path(dirpath) / f
            out[str(p.relative_to(root))] = (p.read_bytes(), p.stat().st_mtime_ns)
    return out


def _host(home: Path, log: list[list[str]] | None = None, **kw: Any) -> Any:
    return fakes.make_host(
        home, which={"claude": "/x/claude", "codex": "/x/codex"}, run=fakes.fake_run(log=log), **kw
    )


def test_yes_without_client_writes_no_agent_config(home: Path, archives: dict[str, bytes]) -> None:
    """★ --yes downloads, but registers nothing it was not named: five agents detected, zero
    written.

    MUTATION: register every detected agent under --yes -> RED."""
    _detect_all_clients(home)
    before = {
        p: _tree(home / p) for p in (".claude", ".codex", ".cursor", ".config/Claude", ".dsh")
    }
    log: list[list[str]] = []
    fetcher = fakes.BytesFetcher(archives)
    run_init(
        assume_yes=True,
        prompt=lambda _m: pytest.fail("--yes asked a question"),
        platform=fakes.linux(),
        host=_host(home, log),
        fetcher=fetcher,
        tmap=fakes._exe(home / "bin" / "tmap"),
        mcp_probe=lambda *_a: McpProbe(None, False, "not probed"),
    )
    assert not [c for c in log if Path(c[0]).name in ("claude", "codex")]
    assert {p: _tree(home / p) for p in before} == before
    assert not (home / ".claude.json").exists()


def test_yes_with_client_registers_only_that_one(home: Path, archives: dict[str, bytes]) -> None:
    _detect_all_clients(home)
    tmap = fakes._exe(home / "bin" / "tmap")
    run_init(
        assume_yes=True,
        clients=("cursor",),
        prompt=lambda _m: "",
        platform=fakes.linux(),
        host=_host(home),
        fetcher=fakes.BytesFetcher(archives),
        tmap=tmap,
        mcp_probe=lambda *_a: McpProbe(None, False, "not probed"),
    )
    entry = json.loads((home / ".cursor" / "mcp.json").read_text())["mcpServers"]["treasure-map"]
    assert entry == {"command": str(tmap), "args": ["mcp"]}
    assert not (home / ".dsh" / "cordis.patch.yml").exists()


def test_non_interactive_never_downloads_and_yes_downloads_each_missing_piece(
    home: Path, archives: dict[str, bytes]
) -> None:
    """MUTATION: treat --non-interactive like --yes -> the fetcher is called -> RED."""
    quiet = fakes.BytesFetcher(archives)
    run_init(
        non_interactive=True,
        prompt=lambda _m: "",
        platform=fakes.linux(),
        host=_host(home),
        fetcher=quiet,
        tmap=None,
    )
    assert quiet.calls == []
    loud = fakes.BytesFetcher(archives)
    result = run_init(
        assume_yes=True,
        prompt=lambda _m: "",
        platform=fakes.linux(),
        host=_host(home),
        fetcher=loud,
        tmap=None,
    )
    names = sorted(u.rsplit("/", 1)[-1] for u in loud.calls)
    assert names == sorted(archives)  # JDK, Ghidra, BinExport, BinDiff — once each
    assert not result.failed


def test_a_fresh_install_reads_as_a_readable_toolchain_in_the_same_process(
    home: Path, archives: dict[str, bytes], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ After --yes installs everything, the doctor in the SAME process reads the toolchain —
    config.yaml's new keys were applied to this process's environment.

    MUTATION: skip re-applying the toolchain env after writing config -> no bindiff on PATH ->
    diff_toolchain_readable 'wrong' -> RED."""
    monkeypatch.setattr(tc, "detect_toolchain", _REAL_DETECT)
    empty = tmp_path / "emptybin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))  # no machine bindiff can answer for ours
    result = run_init(
        assume_yes=True,
        prompt=lambda _m: "",
        platform=fakes.linux(),
        host=_host(home, environ=os.environ),
        fetcher=fakes.BytesFetcher(archives),
        tmap=None,
    )
    by_name = {c.name: c for c in result.checks}
    assert by_name["diff_toolchain_readable"].state == "ok", by_name["diff_toolchain_readable"]
    assert by_name["binexport"].state == "ok"
    tdir = home / ".treasure-map" / "toolchain"
    cfg = (home / ".treasure-map" / "config.yaml").read_text()
    assert str(tdir / "bindiff-8" / "opt" / "bindiff" / "bin" / "bindiff") in cfg
    props = tdir / "ghidra_11.4.3_PUBLIC" / "support" / "launch.properties"
    assert props.read_text() == f"JAVA_HOME_OVERRIDE={tdir / 'jdk-21.0.12.1+1'}\n"
    ledger = json.loads((tdir / "installed.json").read_text())
    # the installed BinExport's digest is recorded — uninstall refuses a copy without one
    from treasure_map.lib.diff.toolchain import binexport_lib_digest

    be = next(e for e in ledger["entries"] if e["id"] == "binexport")
    assert be.get("lib_digest") == binexport_lib_digest(Path(be["path"]))
    assert {e["id"] for e in ledger["entries"] if e["state"] == "committed"} >= {
        "jdk",
        "ghidra",
        "ghidra_jdk_override",
        "binexport",
        "bindiff",
    }
    # a second run plans nothing
    lines: list[str] = []
    again = run_init(
        assume_yes=True,
        prompt=lambda _m: "",
        echo=lines.append,
        platform=fakes.linux(),
        host=_host(home, environ=os.environ),
        fetcher=fakes.RefusingFetcher(),
        tmap=None,
    )
    assert again.nothing_to_do and "  everything current, nothing to do" in lines


def test_an_unsupported_platform_writes_nothing(home: Path) -> None:
    """MUTATION: provision ~/.treasure-map before the platform gate -> RED."""
    from treasure_map.lib.setup.platform import detect_platform

    (home / ".treasure-map").rmdir()
    with pytest.raises(PlatformUnsupportedError):
        run_init(
            assume_yes=True,
            prompt=lambda _m: "",
            platform=detect_platform(system="Linux", machine="aarch64", environ={}, glibc=None),
        )
    assert not (home / ".treasure-map").exists()


def test_dry_run_and_check_only_write_nothing(home: Path, archives: dict[str, bytes]) -> None:
    """★ Not a byte, not an mtime — the user's atlas included; the live MCP probe runs under a
    throwaway home.

    MUTATION: let --check-only probe with the real home -> RED (probe home); write config on a
    dry run -> RED (tree)."""
    tm = home / ".treasure-map"
    (tm / "config.yaml").write_text("workspace_dir: ~/.treasure-map/workspaces\n")
    (tm / "atlas.db").write_bytes(b"SQLite format 3\x00 pretend")
    staging = tm / "toolchain" / ".staging-old"
    staging.mkdir(parents=True)
    _detect_all_clients(home)
    before = _tree(home)
    probed: list[str] = []

    def probe(_tmap: Path, env: Any) -> McpProbe:
        probed.append(env["HOME"])
        return McpProbe(None, False, "not started")

    tmap = fakes._exe(home / "bin" / "tmap")
    before = _tree(home)
    run_init(
        dry_run=True,
        assume_yes=True,
        clients=("cursor", "dsh"),
        prompt=lambda _m: "",
        platform=fakes.linux(),
        host=_host(home),
        fetcher=fakes.BytesFetcher(archives),
        tmap=tmap,
    )
    assert _tree(home) == before and staging.is_dir()
    run_init(
        check_only=True,
        prompt=lambda _m: "",
        platform=fakes.linux(),
        host=_host(home),
        tmap=tmap,
        mcp_probe=probe,
    )
    assert _tree(home) == before
    assert probed and all(not Path(h).is_relative_to(home) for h in probed)


def test_a_declined_plan_changes_nothing(home: Path, archives: dict[str, bytes]) -> None:
    before = _tree(home)
    fetcher = fakes.BytesFetcher(archives)
    result = run_init(
        prompt=lambda m: "n" if m.startswith("Apply") else "",
        platform=fakes.linux(),
        host=_host(home),
        fetcher=fetcher,
        tmap=None,
        use_tty=False,
    )
    assert fetcher.calls == [] and not result.applied
    assert _tree(home) == before


def test_an_explicit_path_that_fails_is_not_replaced(home: Path, tmp_path: Path) -> None:
    good = fakes.make_ghidra(home / "tools" / "ghidra_11.4.3_PUBLIC")  # discoverable
    old = fakes.make_ghidra(tmp_path / "old", version="11.4.2")
    with pytest.raises(initializer.SetupError, match="11.4.2"):
        run_init(
            non_interactive=True,
            ghidra=old,
            prompt=lambda _m: "",
            platform=fakes.linux(),
            host=_host(home),
            tmap=None,
        )
    assert good.exists()


def test_unpublished_binexport_is_reported_not_skipped(home: Path) -> None:
    """The shipped lock still carries the BinExport placeholder: init says so."""
    g = fakes.make_ghidra(home / "tools" / "ghidra_11.4.3_PUBLIC")
    fakes.make_jdk(home / ".jdks" / "jdk21")
    lines: list[str] = []
    result = run_init(
        assume_yes=True,
        prompt=lambda _m: "",
        echo=lines.append,
        platform=fakes.linux(),
        host=_host(home),
        fetcher=fakes.RefusingFetcher(),
        tmap=None,
    )
    assert g.exists()
    assert "unavailable: BinExport artifact not published yet" in result.needs_you
    assert any("unavailable: BinExport artifact not published yet" in ln for ln in lines)


# ── audit follow-ups ─────────────────────────────────────────────────────────────────────────


def test_init_sweeps_staging_left_by_an_interrupted_run(home: Path) -> None:
    """MUTATION: make sweep_staging a no-op -> the leftover stays -> RED."""
    left = home / ".treasure-map" / "toolchain" / ".staging-deadbeef"
    (left / "unpacked").mkdir(parents=True)
    run_init(
        non_interactive=True,
        prompt=lambda _m: "",
        platform=fakes.linux(),
        host=_host(home),
        tmap=None,
    )
    assert not left.exists()


def test_force_writes_back_what_it_found(home: Path, tmp_path: Path) -> None:
    """--force rebuilds config.yaml from defaults AND writes the chosen toolchain back in the
    same run — never a config that has lost its Ghidra.

    MUTATION: write only changed keys under --force -> ghidra.local.home is gone -> RED."""
    import yaml

    g = fakes.make_ghidra(tmp_path / "g")
    jdk = fakes.make_jdk(tmp_path / "jdk")
    bd = fakes.make_bindiff(tmp_path / "bd" / "bindiff")
    cfg = home / ".treasure-map" / "config.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "ghidra": {"local": {"home": str(g)}},
                "toolchain": {"java_home": str(jdk), "bindiff": str(bd)},
                "workspace_dir": str(tmp_path / "ws"),
            }
        )
    )
    run_init(
        force=True,
        non_interactive=True,
        prompt=lambda _m: "",
        platform=fakes.linux(),
        host=_host(home),
        tmap=None,
    )
    data = yaml.safe_load(cfg.read_text())
    assert data["ghidra"]["local"]["home"] == str(g)
    assert data["toolchain"] == {"java_home": str(jdk), "bindiff": str(bd)}
    assert data["workspace_dir"] == str(tmp_path / "ws")


def test_binexport_for_a_users_ghidra_goes_to_its_settings_dir(home: Path, tmp_path: Path) -> None:
    """★ tmap never writes into a Ghidra install it did not make.

    MUTATION: install into <ghidra>/Ghidra/Extensions regardless -> RED."""
    from treasure_map.lib.setup.ledger import Ledger
    from treasure_map.lib.setup.plan import binexport_target

    g = fakes.make_ghidra(tmp_path / "users-ghidra")
    host = _host(home)
    ledger = Ledger(home / ".treasure-map" / "toolchain" / "installed.json")
    target = binexport_target(host, g, ledger)
    assert (
        target == home / ".config" / "ghidra" / "ghidra_11.4.3_PUBLIC" / "Extensions" / "BinExport"
    )
    ledger.add_pending("ghidra", "dir", g)
    ledger.commit("ghidra")
    assert binexport_target(host, g, ledger) == g / "Ghidra" / "Extensions" / "BinExport"


def test_a_rerun_neither_rewrites_the_ledger_nor_forgets_the_rc(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MUTATION: record completion on every run with this run's rc -> an unattended re-run drops
    the rc block an earlier yes added (uninstall would leave it behind) -> RED."""
    monkeypatch.setenv("SHELL", "/bin/zsh")
    run_init(
        prompt=lambda _m: "",
        platform=fakes.linux(),
        host=_host(home),
        tmap=None,
        use_tty=False,
        fetcher=fakes.RefusingFetcher(),
    )
    ledger_file = home / ".treasure-map" / "toolchain" / "installed.json"
    first = json.loads(ledger_file.read_text())
    comp = next(e for e in first["entries"] if e["id"] == "completion")
    assert comp["rc_block"] == str(home / ".zshrc")
    before = (ledger_file.read_bytes(), ledger_file.stat().st_mtime_ns)
    run_init(
        non_interactive=True,
        prompt=lambda _m: "",
        platform=fakes.linux(),
        host=_host(home),
        tmap=None,
    )
    assert (ledger_file.read_bytes(), ledger_file.stat().st_mtime_ns) == before


def test_an_entry_already_in_place_is_neither_a_to_do_nor_a_restart(home: Path) -> None:
    """A dsh profile already serving treasure-map: nothing written, nothing to do, no restart.

    MUTATION: list the profile layer under 'needs you', or name every selected agent in the
    restart line -> RED."""
    tmap = fakes._exe(home / "bin" / "tmap")
    prof = home / ".dsh" / "profiles" / "web"
    prof.mkdir(parents=True)
    (prof / "cordis.yml").write_text("[]\n")
    (prof / "cordis.patch.yml").write_text(
        "- insert:\n    - id: mcp-treasure-map\n      name: '@deepseek-ai/dsh-mcp-client'\n"
        f"      config:\n        serverName: treasure-map\n        transport: stdio\n"
        f"        command: {tmap}\n        args: [mcp]\n"
    )
    result = run_init(
        assume_yes=True,
        clients=("dsh",),
        prompt=lambda _m: "",
        platform=fakes.linux(),
        host=_host(home),
        fetcher=fakes.RefusingFetcher(),
        tmap=tmap,
        mcp_probe=lambda *_a: McpProbe(None, False, "not probed"),
    )
    assert not any(n.startswith("dsh:") for n in result.needs_you)
    assert result.registered == ()
    assert not (home / ".dsh" / "cordis.patch.yml").exists()


def test_an_agent_config_that_cannot_be_written_is_a_to_do(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A permission error writing one agent's configuration is that agent's to-do, not a
    traceback that leaves the rest of init undone.

    MUTATION: let the OSError out of the register step -> RED."""
    from treasure_map.lib.setup import clients as cl

    def _denied(*_a: object, **_k: object) -> None:
        raise PermissionError("[Errno 13] Permission denied: 'cordis.patch.yml'")

    monkeypatch.setattr(cl, "register", _denied)
    (home / ".dsh").mkdir()
    outcome = "ok"
    result = None
    try:
        result = run_init(
            assume_yes=True,
            clients=("dsh",),
            prompt=lambda _m: "",
            platform=fakes.linux(),
            host=_host(home),
            fetcher=fakes.RefusingFetcher(),
            tmap=fakes._exe(home / "bin" / "tmap"),
            mcp_probe=lambda *_a: McpProbe(None, False, "not probed"),
        )
    except OSError as exc:
        outcome = repr(exc)
    assert outcome == "ok" and result is not None
    assert any("could not write its configuration" in n for n in result.needs_you)


def test_an_unwritable_home_is_a_message_not_a_traceback(monkeypatch: pytest.MonkeyPatch) -> None:
    """MUTATION: drop the OSError catch in the init command -> a traceback -> RED."""
    from click.testing import CliRunner

    from treasure_map.cli import init_cli

    def _denied(**_k: object) -> None:
        raise PermissionError("[Errno 13] Permission denied: '/home/u/.treasure-map'")

    monkeypatch.setattr(init_cli, "run_init", _denied)
    result = CliRunner().invoke(init_cli.init, ["--yes"])
    assert isinstance(result.exception, SystemExit) and result.exit_code == 1
    assert "Permission denied" in result.output


def test_force_keeps_the_atlas_names_each_reset_and_backs_up(home: Path, tmp_path: Path) -> None:
    """--force rebuilds the structure but never quietly moves where the data is, says which
    values it resets, and keeps the old file.

    MUTATION: drop the atlas carry-over -> atlas.db_path is back at the default -> RED.
    MUTATION: drop the backup -> RED. MUTATION: drop the reset lines from the plan -> RED."""
    import yaml

    cfg = home / ".treasure-map" / "config.yaml"
    atlas = tmp_path / "data" / "atlas.db"
    original = yaml.safe_dump(
        {
            "atlas": {"db_path": str(atlas)},
            "ghidra": {"headless_timeout_seconds": 900},
            "workspace_dir": str(tmp_path / "ws"),
        }
    )
    cfg.write_text(original)
    lines: list[str] = []
    run_init(
        force=True,
        non_interactive=True,
        prompt=lambda _m: "",
        echo=lines.append,
        platform=fakes.linux(),
        host=_host(home),
        tmap=None,
    )
    data = yaml.safe_load(cfg.read_text())
    assert data["atlas"]["db_path"] == str(atlas)
    assert data["workspace_dir"] == str(tmp_path / "ws")
    backup = cfg.with_name("config.yaml.tmap.backup")
    assert backup.is_file() and backup.read_text() == original
    assert any("reset ghidra.headless_timeout_seconds: 900 -> 300" in ln for ln in lines)
