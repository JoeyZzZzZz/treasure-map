# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The doctor's states: unknown is never ✅ and fails the run; warn and info never fail it."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from treasure_map.lib.setup import clients as cl
from treasure_map.lib.setup.doctor import (
    Check,
    DoctorInputs,
    McpProbe,
    _mcp_atlas_check,
    _mcp_live_check,
    check,
    expected_tool_names,
)
from treasure_map.lib.setup.initializer import InitResult
from treasure_map.lib.setup.toolchain_lock import load_lock

from . import fakes


def _inputs(home: Path, **kw: object) -> DoctorInputs:
    host = fakes.make_host(home)
    chost = cl.ClientHost(home, {}, fakes.linux(), lambda _n: None, fakes.fake_run())
    base: dict[str, object] = dict(
        platform=fakes.linux(),
        host=host,
        client_host=chost,
        cfg=None,
        lock=load_lock(),
        tmap=None,
        check_only=True,
    )
    base.update(kw)
    return DoctorInputs(**base)  # type: ignore[arg-type]


def _cli_exit(checks: tuple[Check, ...], monkeypatch: pytest.MonkeyPatch) -> tuple[int, str]:
    from treasure_map.cli import init_cli

    monkeypatch.setattr(
        init_cli,
        "run_init",
        lambda **_k: InitResult(Path("c"), Path("e"), Path("a"), checks),
    )
    result = CliRunner().invoke(init_cli.init, ["--check-only"])
    return result.exit_code, result.output


def test_unknown_fails_the_run_and_never_shows_a_tick(monkeypatch: pytest.MonkeyPatch) -> None:
    """★ MUTATION: count 'unknown' as passing -> exit 0 -> RED; count 'warn' as failing -> the
    second exit is 1 -> RED."""
    code, out = _cli_exit(
        (check("ok_one", "ok", "fine"), check("ghidra_native", "unknown", "cannot read")),
        monkeypatch,
    )
    assert code == 1
    assert "? ghidra_native" in out and "✅ ghidra_native" not in out
    code, out = _cli_exit(
        (check("platform", "warn", "unverified"), check("mcp.codex", "info", "detected")),
        monkeypatch,
    )
    assert code == 0 and "⚠ platform" in out


def test_a_dangling_last_run_pointer_is_wrong(tmp_path: Path) -> None:
    """MUTATION: skip the pointer check -> 'info: created on first use' -> RED."""
    from treasure_map.lib.last_run import write_last_run

    home = Path.home()
    write_last_run(tmp_path / "a.db", tmp_path / "gone" / "atlas.db", "r1")
    assert _mcp_atlas_check(_inputs(home)).state == "wrong"
    (tmp_path / "gone").mkdir()
    (tmp_path / "gone" / "atlas.db").write_bytes(b"")
    assert _mcp_atlas_check(_inputs(home)).state == "ok"


def test_mcp_live_compares_tool_names_not_counts(tmp_path: Path) -> None:
    """★ Same number of tools, one name different -> wrong.

    MUTATION: compare len() only -> ok -> RED."""
    want = expected_tool_names()
    swapped = frozenset(sorted(want)[1:]) | {"a_tool_tmap_does_not_have"}
    assert len(swapped) == len(want)
    tmap = fakes._exe(tmp_path / "bin" / "tmap")
    inp = _inputs(Path.home(), tmap=tmap, mcp_probe=lambda *_a: McpProbe(swapped, True))
    assert _mcp_live_check(inp, "ok").state == "wrong"
    inp = _inputs(Path.home(), tmap=tmap, mcp_probe=lambda *_a: McpProbe(want, True))
    assert _mcp_live_check(inp, "ok").state == "ok"
    inp = _inputs(Path.home(), tmap=tmap, mcp_probe=lambda *_a: McpProbe(None, False, "boom"))
    res = _mcp_live_check(inp, "ok")
    assert res.state == "wrong" and "boom" in res.detail


def test_a_foreign_entry_reads_wrong_and_not_modified(tmp_path: Path) -> None:
    from treasure_map.lib.setup.doctor import _client_checks

    home = Path.home()
    cfg = home / ".cursor" / "mcp.json"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(json.dumps({"mcpServers": {"treasure-map": {"command": "node"}}}))
    tmap = fakes._exe(tmp_path / "bin" / "tmap")
    inp = _inputs(home, tmap=tmap)
    inp.client_host = cl.ClientHost(home, {}, fakes.linux(), lambda _n: None, fakes.fake_run())
    checks = {c.name: c for c in _client_checks(inp)}
    assert checks["mcp.cursor"].state == "wrong" and "not modified" in checks["mcp.cursor"].detail


def test_an_unreadable_toolchain_names_what_failed_above() -> None:
    """MUTATION: drop the blockers -> the generic line -> RED."""
    from treasure_map.lib.setup.doctor import _diff_toolchain_check

    inp = _inputs(Path.home(), detect_toolchain=lambda: None)
    res = _diff_toolchain_check(inp, ["binexport"])
    assert res.state == "wrong" and res.detail.startswith("because binexport failed above")
    generic = _diff_toolchain_check(inp, [])
    assert generic.state == "wrong" and "BinExport" in generic.detail


def test_ghidras_launcher_is_asked_without_save(tmp_path: Path) -> None:
    """★ ``-save`` would write the user's java_home.save — the doctor reads only.

    MUTATION: add -save -> RED."""
    from treasure_map.lib.setup.discover import RunResult
    from treasure_map.lib.setup.doctor import _ghidra_jdk_effective

    log: list[list[str]] = []
    jdk = fakes.make_jdk(tmp_path / "jdk")

    def run(argv: list[str], **_k: object) -> RunResult:
        log.append(list(argv))
        return RunResult(0, f"{jdk}\n", "")

    host = fakes.make_host(tmp_path / "home", which={"java": str(jdk / "bin" / "java")}, run=run)
    inp = _inputs(Path.home(), host=host)
    res = _ghidra_jdk_effective(inp, fakes.make_ghidra(tmp_path / "g"))
    assert res.state == "ok"
    assert "-jdk_home" in log[0] and "-save" not in log[0]


def test_a_shadowed_registration_is_wrong(tmp_path: Path) -> None:
    """MUTATION: report 'shadowed' as ok -> RED."""
    from treasure_map.lib.setup.doctor import _client_checks

    home = Path.home()
    tmap = fakes._exe(tmp_path / "bin" / "tmap")
    proj = tmp_path / "proj"
    proj.mkdir()
    good = {"type": "stdio", "command": str(tmap), "args": ["mcp"], "env": {}}
    (home / ".claude.json").write_text(
        json.dumps(
            {
                "mcpServers": {"treasure-map": good},
                "projects": {str(proj): {"mcpServers": {"treasure-map": {"command": str(tmap)}}}},
            }
        )
    )
    checks = {c.name: c for c in _client_checks(_inputs(home, tmap=tmap))}
    assert checks["mcp.claude-code"].state == "wrong"


def test_a_ghidra_without_launch_properties_is_wrong(tmp_path: Path) -> None:
    """The launcher refuses to start without support/launch.properties — never a ✅.

    MUTATION: drop the check -> 'ok' -> RED."""
    from treasure_map.lib.config.config import Config, GhidraConfig, GhidraLocalConfig
    from treasure_map.lib.setup.doctor import _ghidra_checks

    g = fakes.make_ghidra(tmp_path / "g")
    (g / "support" / "launch.properties").unlink()
    cfg = Config(ghidra=GhidraConfig(local=GhidraLocalConfig(home=g)))
    checks, _home = _ghidra_checks(_inputs(Path.home(), cfg=cfg))
    assert checks[0].state == "wrong" and "launch.properties" in checks[0].detail


def test_the_config_check() -> None:
    from treasure_map.lib.setup.doctor import _config_check

    tm = Path.home() / ".treasure-map"
    assert _config_check(_inputs(Path.home())).state == "missing"
    (tm / "config.yaml").write_text("ghidra: [unclosed\n")
    assert _config_check(_inputs(Path.home())).state == "wrong"
    (tm / "config.yaml").write_text("log_level: INFO\n")
    assert _config_check(_inputs(Path.home())).state == "ok"


def test_an_inactive_completion_warns_without_failing_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A fresh zsh user after `tmap init --yes`: the script is installed, the rc is (rightly) not
    edited without a yes. tmap works; the line to add is shown.

    MUTATION: count installed-but-inactive as wrong -> RED."""
    from treasure_map.lib.setup import doctor

    detail = "zsh: installed at /x/_tmap; not active yet — add this line to ~/.zshrc: fpath=(…)"
    monkeypatch.setattr(
        "treasure_map.lib.setup.completion.completion_check",
        lambda _home, shell=None: ("completion", False, detail),
    )
    checks = doctor._dir_checks(_inputs(tmp_path, tm_home=tmp_path / ".treasure-map"))
    comp = next(c for c in checks if c.name == "completion")
    assert comp.state == "warn" and comp.ok and comp.detail == detail


def test_the_doctor_does_not_read_the_macos_java_stub_as_a_jdk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MUTATION: take /usr/bin/java's /usr as the JDK home on macOS -> 'unknown' -> RED."""
    import sys

    from treasure_map.lib.setup import doctor

    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(doctor.os.path, "realpath", lambda p: str(p))
    assert doctor.effective_java_home({}, lambda _n: "/usr/bin/java") is None
