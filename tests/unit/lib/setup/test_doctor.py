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
