# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Agent registration: write exactly tmap's entry, recognise what is not tmap's, and never leave a
half-written configuration behind."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from treasure_map.lib.setup import clients as cl
from treasure_map.lib.setup.discover import RunResult

from . import fakes


def _host(home: Path, *, which: dict[str, str] | None = None, run: Any = None) -> cl.ClientHost:
    table = which or {}
    return cl.ClientHost(
        home=home,
        environ={},
        platform=fakes.linux(),
        which=lambda n: table.get(n),
        run=run or fakes.fake_run(),
    )


@pytest.fixture()
def tmap(tmp_path: Path) -> Path:
    return fakes._exe(tmp_path / "bin" / "tmap")


def test_cursor_json_transaction_touches_only_our_key(tmp_path: Path, tmap: Path) -> None:
    """★ Other servers and top-level keys come back byte-for-byte equal in value.

    MUTATION: drop the restore on a bad read-back -> the corrupted file stays -> RED (second
    half)."""
    home = tmp_path / "h"
    cfg = home / ".cursor" / "mcp.json"
    cfg.parent.mkdir(parents=True)
    original = {"theme": "dark", "mcpServers": {"other": {"command": "node", "args": ["x.js"]}}}
    cfg.write_text(json.dumps(original))
    out = cl.register("cursor", _host(home), tmap)
    assert out.ok, out.message
    after = json.loads(cfg.read_text())
    assert after["mcpServers"]["treasure-map"] == {"command": str(tmap), "args": ["mcp"]}
    del after["mcpServers"]["treasure-map"]
    assert after == original
    assert (home / ".cursor" / "mcp.json.tmap.backup").read_text() == json.dumps(original)
    assert cl.inspect("cursor", _host(home), tmap).state == "aligned"


def test_a_bad_read_back_restores_the_original_bytes(
    tmp_path: Path, tmap: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "h"
    cfg = home / ".cursor" / "mcp.json"
    cfg.parent.mkdir(parents=True)
    raw = b'{"mcpServers": {"other": {"command": "node"}},  "k": 1}'
    cfg.write_bytes(raw)
    monkeypatch.setattr(cl, "_read_back", lambda _p: b'{"mcpServers": {}}')
    out = cl.register("cursor", _host(home), tmap)
    assert not out.ok and "restored" in out.message
    assert cfg.read_bytes() == raw


def test_a_foreign_entry_is_never_modified(tmp_path: Path, tmap: Path) -> None:
    """MUTATION: treat a foreign entry as stale -> it is overwritten -> RED."""
    home = tmp_path / "h"
    cfg = home / ".cursor" / "mcp.json"
    cfg.parent.mkdir(parents=True)
    raw = json.dumps({"mcpServers": {"treasure-map": {"command": "node", "args": ["s.js"]}}})
    cfg.write_text(raw)
    assert cl.inspect("cursor", _host(home), tmap).state == "foreign"
    out = cl.register("cursor", _host(home), tmap)
    assert not out.ok and "not modified" in out.message
    assert cfg.read_text() == raw


@pytest.mark.parametrize(
    "entry",
    [
        {"command": "/old/bin/treasure-map-mcp", "args": []},
        {"command": "TMAP", "args": ["mcp", "--atlas", "/x/atlas.db"]},
        {"command": "TMAP", "args": ["mcp"], "env": {"TREASURE_MAP_ATLAS_DB": "/x"}},
        {"command": "/elsewhere/tmap", "args": ["mcp"]},
    ],
)
def test_what_reads_stale(tmp_path: Path, tmap: Path, entry: dict[str, Any]) -> None:
    """MUTATION: compare command basenames only -> the --atlas / env / other-path entries read
    aligned -> RED."""
    entry = {k: (str(tmap) if v == "TMAP" else v) for k, v in entry.items()}
    assert cl.classify(entry, tmap).state == "stale"
    assert cl.classify({"command": str(tmap), "args": ["mcp"]}, tmap).state == "aligned"


def test_claude_code_local_scope_shadows_user_scope(tmp_path: Path, tmap: Path) -> None:
    """★ The user entry is right, but a project's local entry of the same name wins there.

    MUTATION: read only the top-level mcpServers -> 'aligned' -> RED."""
    home = tmp_path / "h"
    home.mkdir()
    proj = tmp_path / "proj"
    proj.mkdir()
    good = {"type": "stdio", "command": str(tmap), "args": ["mcp"], "env": {}}
    stale = {"command": str(tmap), "args": ["mcp", "--atlas", "/x"]}
    (home / ".claude.json").write_text(
        json.dumps(
            {
                "mcpServers": {"treasure-map": good},
                "projects": {str(proj): {"mcpServers": {"treasure-map": stale}}},
            }
        )
    )
    st = cl.inspect("claude-code", _host(home), tmap)
    assert st.state == "shadowed" and st.shadowing == (proj,)


def test_claude_code_registers_through_its_cli(tmp_path: Path, tmap: Path) -> None:
    home = tmp_path / "h"
    home.mkdir()
    calls: list[list[str]] = []

    def run(argv: list[str], *, cwd: Path | None = None, timeout: float = 30) -> RunResult:
        calls.append(list(argv))
        if argv[:3] == ["claude", "mcp", "add"]:
            (home / ".claude.json").write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "treasure-map": {
                                "type": "stdio",
                                "command": argv[-2],
                                "args": ["mcp"],
                                "env": {},
                            }
                        }
                    }
                )
            )
        return RunResult(0, "", "")

    out = cl.register("claude-code", _host(home, which={"claude": "/x/claude"}, run=run), tmap)
    assert out.ok, out.message
    assert calls == [["claude", "mcp", "add", "-s", "user", "treasure-map", "--", str(tmap), "mcp"]]


def test_no_cli_means_manual(tmp_path: Path, tmap: Path) -> None:
    out = cl.register("codex", _host(tmp_path / "h"), tmap)
    assert not out.ok and out.manual and "[mcp_servers.treasure-map]" in out.manual


def test_dsh_appends_once_and_refuses_what_it_cannot_parse(tmp_path: Path, tmap: Path) -> None:
    """★ The patch file is only appended to; a second run adds nothing; a file with !!js tags or
    anchors is not touched.

    MUTATION: append on every run -> two entries -> RED."""
    home = tmp_path / "h"
    (home / ".dsh").mkdir(parents=True)
    patch = home / ".dsh" / "cordis.patch.yml"
    before = "- insert:\n    - id: other\n      name: x\n"
    patch.write_text(before)
    host = _host(home)
    assert cl.register("dsh", host, tmap).ok
    text = patch.read_text()
    assert text.startswith(before)
    assert cl.inspect("dsh", host, tmap).state == "aligned"
    again = cl.register("dsh", host, tmap)
    assert again.ok and patch.read_text() == text
    patch.write_text("- insert: !!js/function 'x'\n")
    out = cl.register("dsh", host, tmap)
    assert not out.ok and out.manual
    assert patch.read_text() == "- insert: !!js/function 'x'\n"
    patch.write_text("- &a {x: 1}\n- *a\n")
    assert not cl.register("dsh", host, tmap).ok


def test_dsh_unregister_removes_only_our_block(tmp_path: Path, tmap: Path) -> None:
    home = tmp_path / "h"
    (home / ".dsh").mkdir(parents=True)
    patch = home / ".dsh" / "cordis.patch.yml"
    before = "- insert:\n    - id: other\n      name: x\n"
    patch.write_text(before)
    assert cl.register("dsh", _host(home), tmap).ok
    outs = cl.unregister("dsh", _host(home), tmap)
    assert all(o.ok for o in outs)
    assert patch.read_text() == before


def test_tmap_executable_requires_the_name(tmp_path: Path) -> None:
    exe = fakes._exe(tmp_path / "bin" / "tmap")
    assert cl.tmap_executable(str(exe)) == exe
    other = fakes._exe(tmp_path / "bin" / "python3")
    assert cl.tmap_executable(str(other)) is None
