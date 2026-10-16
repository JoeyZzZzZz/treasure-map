# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Agent registration: write exactly tmap's entry, recognise what is not tmap's, and never leave a
half-written configuration behind."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

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


def _dsh_would_load(path: Path) -> bool:
    """dsh's own rule for its home patch layer (dsh-app-boot loadOptionalPatches/parsePatchList):
    an absent file is no patches; a file that exists must load as a top-level YAML array."""
    return not path.exists() or isinstance(yaml.safe_load(path.read_text()), list)


def test_dsh_unregister_removes_a_patch_file_that_held_only_our_block(
    tmp_path: Path, tmap: Path
) -> None:
    """init created the home patch file for tmap's block alone. Taking the block out must not
    leave an empty file — dsh loads that as null and refuses to start. The file is removed:
    absent is "no patches" to dsh, which is how the machine was before init.

    MUTATION (verified RED): the 0.1.0 removal (write the remainder as-is, read it back with
    tmap's lenient read) -> an empty file stays -> the not-exists assertion fails.
    MUTATION (verified RED): never take the remove branch -> the file is kept as "[]" -> RED."""
    home = tmp_path / "h"
    (home / ".dsh").mkdir(parents=True)
    patch = home / ".dsh" / "cordis.patch.yml"
    host = _host(home)
    assert cl.register("dsh", host, tmap).ok and patch.exists()
    outs = cl.unregister("dsh", host, tmap)
    assert all(o.ok for o in outs), [o.message for o in outs]
    assert not patch.exists()
    assert _dsh_would_load(patch)


def test_dsh_unregister_keeps_the_users_comment_as_a_list_dsh_loads(
    tmp_path: Path, tmap: Path
) -> None:
    """The user's own comment and tmap's block: the comment stays, and since a comment-only file
    loads as null (refused by dsh), the remainder is closed with an explicit empty list.

    MUTATION (verified RED): drop the closing "[]" -> the comment-only remainder fails the
    read-back and the original is restored -> the outcome is a failure."""
    home = tmp_path / "h"
    (home / ".dsh").mkdir(parents=True)
    patch = home / ".dsh" / "cordis.patch.yml"
    patch.write_text("# my dsh notes\n")
    host = _host(home)
    assert cl.register("dsh", host, tmap).ok
    outs = cl.unregister("dsh", host, tmap)
    assert all(o.ok for o in outs), [o.message for o in outs]
    assert patch.read_text() == "# my dsh notes\n[]\n"
    assert _dsh_would_load(patch)


def test_dsh_unregister_through_a_symlink_keeps_the_link(tmp_path: Path, tmap: Path) -> None:
    """A patch file kept in a dotfiles directory and linked into the dsh home: emptied of tmap's
    block, it stays a link to a file dsh loads — deleting the link would cut the user's dotfiles
    out of their setup.

    MUTATION (verified RED): drop the symlink exception from the remove branch -> the link itself
    is deleted -> the is_symlink assertion fails."""
    home = tmp_path / "h"
    (home / ".dsh").mkdir(parents=True)
    dotfiles = tmp_path / "dotfiles"
    dotfiles.mkdir()
    target = dotfiles / "cordis.patch.yml"
    link = home / ".dsh" / "cordis.patch.yml"
    link.symlink_to(target)  # dangling until the first write goes through it
    host = _host(home)
    assert cl.register("dsh", host, tmap).ok
    assert link.is_symlink() and target.is_file()
    outs = cl.unregister("dsh", host, tmap)
    assert all(o.ok for o in outs), [o.message for o in outs]
    assert link.is_symlink() and link.resolve() == target.resolve()
    assert target.read_text() == "[]\n"
    assert _dsh_would_load(link)


def test_dsh_init_after_uninstall_replaces_the_closing_empty_list(
    tmp_path: Path, tmap: Path
) -> None:
    """After an uninstall left a comment and "[]", the next init registers again: a block list
    entry cannot follow a flow "[]" (the result would not parse), so that line is replaced.

    MUTATION (verified RED): append after the "[]" instead -> the result does not parse, the
    original is restored -> register fails."""
    home = tmp_path / "h"
    (home / ".dsh").mkdir(parents=True)
    patch = home / ".dsh" / "cordis.patch.yml"
    patch.write_text("# my dsh notes\n[]\n")
    host = _host(home)
    out = cl.register("dsh", host, tmap)
    assert out.ok, out.message
    assert patch.read_text() == "# my dsh notes\n" + cl.dsh_block(tmap)
    assert cl.inspect("dsh", host, tmap).state == "aligned"
    assert _dsh_would_load(patch)


def test_dsh_unregister_undoes_a_write_dsh_could_not_load(
    tmp_path: Path, tmap: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The read-back is dsh's rule, not tmap's lenient read: a write that leaves an empty file
    (which tmap reads as an empty list, but dsh refuses) is undone and reported as a failure.

    MUTATION (verified RED): drop the dsh-acceptance check from the read-back -> the empty file
    passes and the outcome is ok -> RED."""
    home = tmp_path / "h"
    (home / ".dsh").mkdir(parents=True)
    patch = home / ".dsh" / "cordis.patch.yml"
    patch.write_text("- insert:\n    - id: other\n      name: x\n")
    host = _host(home)
    assert cl.register("dsh", host, tmap).ok
    registered = patch.read_text()
    real = cl._atomic_write
    calls: list[bytes] = []

    def _bad_first_write(path: Path, data: bytes, mode: int) -> None:
        calls.append(data)
        real(path, b"" if len(calls) == 1 else data, mode)

    monkeypatch.setattr(cl, "_atomic_write", _bad_first_write)
    outs = cl.unregister("dsh", host, tmap)
    assert not any(o.ok for o in outs), [o.message for o in outs]
    assert patch.read_text() == registered  # restored: nothing of the user's lost


def test_tmap_executable_requires_the_name(tmp_path: Path) -> None:
    exe = fakes._exe(tmp_path / "bin" / "tmap")
    assert cl.tmap_executable(str(exe)) == exe
    other = fakes._exe(tmp_path / "bin" / "python3")
    assert cl.tmap_executable(str(other)) is None


def _profile(home: Path, name: str, patch: str) -> Path:
    prof = home / ".dsh" / "profiles" / name
    prof.mkdir(parents=True)
    (prof / "cordis.yml").write_text("[]\n")
    (prof / "cordis.patch.yml").write_text(patch)
    return prof / "cordis.patch.yml"


def _hand_entry(command: str, entry_id: str = "mcp-treasure-map") -> str:
    return (
        "# Your patch layer for this dsh profile\n"
        "- insert:\n"
        f"    - id: {entry_id}\n"
        "      name: '@deepseek-ai/dsh-mcp-client'\n"
        "      config:\n"
        "        serverName: treasure-map\n"
        "        transport: stdio\n"
        f"        command: {command}\n"
        "        args: [ 'mcp' ]\n"
    )


def test_dsh_reads_a_hand_written_profile_entry_and_adds_no_second_one(
    tmp_path: Path, tmap: Path
) -> None:
    """★ dsh layers the profile's cordis.patch.yml under the home-level one, so an entry the user
    wrote in a profile already serves treasure-map — whatever its id. Appending another to the
    home layer would start the server twice.

    MUTATION: recognise tmap's entry by tmap's own id only -> 'missing' -> a second entry is
    appended -> RED."""
    home = tmp_path / "h"
    prof = _profile(home, "web", _hand_entry(str(tmap)))
    before = prof.read_text()
    host = _host(home)
    st = cl.inspect("dsh", host, tmap)
    assert st.state == "aligned" and st.config_path == prof and not st.editable
    assert cl.register("dsh", host, tmap).ok
    assert not (home / ".dsh" / "cordis.patch.yml").exists()
    assert prof.read_text() == before
    outs = cl.unregister("dsh", host, tmap)
    assert all(o.ok and o.message.startswith("left alone") for o in outs)
    assert prof.read_text() == before


def test_dsh_a_profile_entry_for_another_tmap_is_stale_and_not_edited(
    tmp_path: Path, tmap: Path
) -> None:
    """MUTATION: skip the profile layers -> 'missing' -> the home layer gets a second entry ->
    RED."""
    home = tmp_path / "h"
    prof = _profile(home, "web", _hand_entry("/old/place/tmap"))
    host = _host(home)
    st = cl.inspect("dsh", host, tmap)
    assert st.state == "stale" and st.config_path == prof
    out = cl.register("dsh", host, tmap)
    assert not out.ok and out.manual
    assert not (home / ".dsh" / "cordis.patch.yml").exists()


def test_dsh_writes_the_home_layer_that_reaches_every_profile(tmp_path: Path, tmap: Path) -> None:
    home = tmp_path / "h"
    _profile(home, "web", "- id: ui-settings-general\n")
    _profile(home, "headless", "[]\n")
    (home / ".dsh" / "profiles" / "node_modules").mkdir()  # not a profile: no cordis.yml
    host = _host(home)
    assert cl.register("dsh", host, tmap).ok
    st = cl.inspect("dsh", host, tmap)
    assert st.state == "aligned" and st.config_path == home / ".dsh" / "cordis.patch.yml"


def test_dsh_home_follows_dsh_rules(tmp_path: Path) -> None:
    """A blank $DSH_HOME is unset; ``~`` expands — as dsh itself resolves its home.

    MUTATION: take $DSH_HOME verbatim -> a blank one becomes the working directory -> RED."""
    home = tmp_path / "h"

    def at(value: str | None) -> Path:
        env = {} if value is None else {"DSH_HOME": value}
        return cl.dsh_home(
            cl.ClientHost(home, env, fakes.linux(), lambda _n: None, fakes.fake_run())
        )

    assert at(None) == home / ".dsh"
    assert at("   ") == home / ".dsh"
    assert at("~/alt") == home / "alt"
    assert at("/srv/dsh") == Path("/srv/dsh")


def test_dsh_same_server_name_over_http_is_foreign(tmp_path: Path, tmap: Path) -> None:
    home = tmp_path / "h"
    _profile(
        home,
        "web",
        "- insert:\n    - id: x\n      name: n\n      config:\n        serverName: treasure-map\n"
        "        transport: streamable-http\n        url: http://127.0.0.1:1/mcp\n",
    )
    assert cl.inspect("dsh", _host(home), tmap).state == "foreign"


# ── audit follow-ups ─────────────────────────────────────────────────────────────────────────


def test_uninstall_leaves_a_foreign_entry_alone(tmp_path: Path, tmap: Path) -> None:
    """MUTATION: count a foreign entry as tmap's in unregister -> it is deleted -> RED."""
    home = tmp_path / "h"
    cfg = home / ".cursor" / "mcp.json"
    cfg.parent.mkdir(parents=True)
    raw = json.dumps({"mcpServers": {"treasure-map": {"command": "node", "args": ["s.js"]}}})
    cfg.write_text(raw)
    outs = cl.unregister("cursor", _host(home), tmap)
    assert cfg.read_text() == raw and all(o.ok for o in outs)


def test_a_symlinked_config_stays_a_link(tmp_path: Path, tmap: Path) -> None:
    """★ A config kept in a dotfiles repository: the link stays, the file it points at changes.

    MUTATION: write onto the link path -> it becomes a detached regular file -> RED."""
    home = tmp_path / "h"
    real = tmp_path / "dotfiles" / "mcp.json"
    real.parent.mkdir(parents=True)
    real.write_text(json.dumps({"mcpServers": {}}))
    link = home / ".cursor" / "mcp.json"
    link.parent.mkdir(parents=True)
    link.symlink_to(real)
    assert cl.register("cursor", _host(home), tmap).ok
    assert link.is_symlink()
    assert json.loads(real.read_text())["mcpServers"]["treasure-map"]["command"] == str(tmap)


def test_other_keys_keep_their_characters(tmp_path: Path, tmap: Path) -> None:
    home = tmp_path / "h"
    cfg = home / ".cursor" / "mcp.json"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(json.dumps({"note": "固件 ✓", "mcpServers": {}}, ensure_ascii=False))
    assert cl.register("cursor", _host(home), tmap).ok
    assert "固件 ✓" in cfg.read_text(encoding="utf-8")


def test_removing_a_shadowing_entry_runs_inside_that_project(tmp_path: Path) -> None:
    """MUTATION: run `claude mcp remove -s local` without cwd -> it acts on whatever directory
    init was started from -> RED."""
    proj = tmp_path / "proj"
    proj.mkdir()
    seen: list[Path | None] = []

    def run(argv: list[str], *, cwd: Path | None = None, timeout: float = 30) -> RunResult:
        seen.append(cwd)
        return RunResult(0, "", "")

    out = cl.remove_shadowing(_host(tmp_path / "h", which={"claude": "/x/claude"}, run=run), proj)
    assert out.ok and seen == [proj]


def test_tmap_executable_keeps_the_shim_path(tmp_path: Path) -> None:
    """A uv tool shim is a symlink into a versioned environment; registering the target would
    break on the next upgrade.

    MUTATION: resolve symlinks -> the environment path is returned -> RED."""
    target = fakes._exe(tmp_path / "env" / "bin" / "tmap")
    shim = tmp_path / "bin" / "tmap"
    shim.parent.mkdir()
    shim.symlink_to(target)
    assert cl.tmap_executable(str(shim)) == shim


def test_a_project_mcp_json_is_reported_and_shadows(tmp_path: Path, tmap: Path) -> None:
    """MUTATION: skip the project .mcp.json files -> 'aligned' -> RED."""
    home = tmp_path / "h"
    home.mkdir()
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / ".mcp.json").write_text(json.dumps({"mcpServers": {"treasure-map": {"command": "x"}}}))
    good = {"type": "stdio", "command": str(tmap), "args": ["mcp"], "env": {}}
    (home / ".claude.json").write_text(
        json.dumps({"mcpServers": {"treasure-map": good}, "projects": {str(proj): {}}})
    )
    st = cl.inspect("claude-code", _host(home), tmap)
    assert st.state == "shadowed" and any(".mcp.json" in r for r in st.reported)


def test_a_vanished_project_directory_shadows_nothing(tmp_path: Path, tmap: Path) -> None:
    home = tmp_path / "h"
    home.mkdir()
    good = {"type": "stdio", "command": str(tmap), "args": ["mcp"], "env": {}}
    gone = str(tmp_path / "deleted-project")
    (home / ".claude.json").write_text(
        json.dumps(
            {
                "mcpServers": {"treasure-map": good},
                "projects": {gone: {"mcpServers": {"treasure-map": {"command": str(tmap)}}}},
            }
        )
    )
    st = cl.inspect("claude-code", _host(home), tmap)
    assert st.state == "aligned" and st.shadowing == () and gone in st.detail


def test_a_failed_re_add_puts_the_previous_entry_back(tmp_path: Path, tmap: Path) -> None:
    """MUTATION: drop the put-back -> the user is left with no entry at all -> RED."""
    home = tmp_path / "h"
    home.mkdir()
    old = {"type": "stdio", "command": "/old/tmap", "args": ["mcp"], "env": {}}
    (home / ".claude.json").write_text(json.dumps({"mcpServers": {"treasure-map": old}}))
    calls: list[list[str]] = []

    def run(argv: list[str], *, cwd: Path | None = None, timeout: float = 30) -> RunResult:
        calls.append(list(argv))
        return RunResult(1 if argv[2] == "add" else 0, "", "boom")

    out = cl.register("claude-code", _host(home, which={"claude": "/x/claude"}, run=run), tmap)
    assert not out.ok and "put back" in out.message
    assert calls[-1][:3] == ["claude", "mcp", "add-json"] and json.loads(calls[-1][-1]) == old


def test_a_hand_edited_dsh_block_is_not_removed(tmp_path: Path, tmap: Path) -> None:
    """MUTATION: remove tmap's entry by rewriting the parsed YAML -> the user's edit and every
    comment in the file are lost -> RED."""
    home = tmp_path / "h"
    (home / ".dsh").mkdir(parents=True)
    host = _host(home)
    assert cl.register("dsh", host, tmap).ok
    patch = home / ".dsh" / "cordis.patch.yml"
    edited = "# my notes\n" + patch.read_text().replace(
        "transport: stdio", "transport: stdio  # ok"
    )
    patch.write_text(edited)
    outs = cl.unregister("dsh", host, tmap)
    assert not outs[0].ok and patch.read_text() == edited


def test_claude_desktop_is_not_written_while_it_runs(tmp_path: Path, tmap: Path) -> None:
    """Unattended: skipped. Interactive: asked to quit, and checked again afterwards.

    MUTATION: skip either the running check or the re-check -> the file is written under a
    running app -> RED."""
    home = tmp_path / "h"
    cfg = home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    cfg.parent.mkdir(parents=True)
    cfg.write_text("{}")

    def running(argv: list[str], *, cwd: Path | None = None, timeout: float = 30) -> RunResult:
        return RunResult(0 if argv[0] == "pgrep" else 1, "", "")

    host = cl.ClientHost(home, {}, fakes.darwin_arm(), lambda _n: None, running)
    assert not cl.register("claude-desktop", host, tmap).ok
    asked: list[str] = []
    out = cl.register("claude-desktop", host, tmap, confirm_quit=asked.append)
    assert asked and not out.ok and "still running" in out.message
    assert cfg.read_text() == "{}"
