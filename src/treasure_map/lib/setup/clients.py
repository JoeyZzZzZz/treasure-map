# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Register the treasure-map MCP server with the user's agents — and only touch what is ours.

The entry is always the same: server ``treasure-map``, command = the absolute path of the running
``tmap``, args ``["mcp"]``, no env (``tmap mcp`` reads config.yaml itself). Every client's state
is read straight from its configuration file:

  * ``missing``  — no ``treasure-map`` entry.
  * ``aligned``  — exactly the entry above.
  * ``stale``    — a tmap entry that differs (another path, ``--atlas``, an env, the retired
    ``treasure-map-mcp`` command); it is replaced.
  * ``foreign``  — a ``treasure-map`` entry that is not tmap's; it is NEVER modified.
  * ``invalid``  — the file cannot be parsed; that client is not written.
  * ``shadowed`` — (Claude Code) the user entry is right, but a project-local entry of the same
    name wins inside that project.

Where the client has a CLI (Claude Code, Codex) the CLI writes; Cursor and Claude Desktop get a
JSON transaction (backup, atomic replace, read back, restore the original bytes on any
difference); dsh's patch file is only ever appended to. Whatever cannot be written comes back as
the exact text to paste.
"""

from __future__ import annotations

import copy
import json
import os
import re
import shutil
import sys
import tempfile
import tomllib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml

from treasure_map.lib.setup.discover import Runner
from treasure_map.lib.setup.platform import Platform

SERVER = "treasure-map"
CLIENT_IDS = ("claude-code", "codex", "cursor", "claude-desktop", "dsh")
LABELS = {
    "claude-code": "Claude Code",
    "codex": "Codex",
    "cursor": "Cursor",
    "claude-desktop": "Claude Desktop",
    "dsh": "dsh",
}
DSH_ENTRY_ID = "treasure-map-mcp"
DSH_PATCH_FILE = "cordis.patch.yml"

EntryState = Literal["missing", "aligned", "stale", "foreign", "invalid", "shadowed", "unknown"]


def tmap_executable(argv0: str | None = None) -> Path | None:
    """The running ``tmap`` as an absolute path (symlinks NOT resolved — a uv tool shim keeps
    working across upgrades), or None when tmap was not started as ``tmap``."""
    a = sys.argv[0] if argv0 is None else argv0
    if os.path.isabs(a):
        p = Path(a)
    else:
        found = shutil.which(a) if os.sep not in a else None
        p = Path(found or a).absolute()
    return p if p.name == "tmap" and os.access(p, os.X_OK) else None


@dataclass(frozen=True)
class ClientHost:
    home: Path
    environ: Mapping[str, str]
    platform: Platform
    which: Callable[[str], str | None]
    run: Runner


@dataclass(frozen=True)
class ClientState:
    client: str
    detected: bool
    state: EntryState
    detail: str
    config_path: Path | None
    shadowing: tuple[Path, ...] = ()  # Claude Code project dirs whose local tmap entry wins
    reported: tuple[str, ...] = ()  # same-name entries tmap reports but never edits
    has_cli: bool = False
    editable: bool = True  # False: the entry sits in a file tmap reports but does not edit

    @property
    def label(self) -> str:
        return LABELS[self.client]


@dataclass(frozen=True)
class Outcome:
    ok: bool
    message: str
    manual: str | None = None  # what to paste when tmap could not write it


@dataclass(frozen=True)
class _Classified:
    state: EntryState
    why: str = ""


def _is_tmap_command(command: object) -> bool:
    return isinstance(command, str) and Path(command).name in ("tmap", "treasure-map-mcp")


def classify(entry: object, tmap: Path | None) -> _Classified:
    """One ``treasure-map`` entry against the expected one."""
    if entry is None:
        return _Classified("missing")
    if not isinstance(entry, dict):
        return _Classified("foreign", "not a server entry tmap would write")
    command = entry.get("command")
    args = entry.get("args") or []
    env = entry.get("env") or {}
    if not _is_tmap_command(command):
        return _Classified("foreign", f"command {command!r} is not tmap")
    if tmap is None:
        return _Classified("unknown", "cannot tell which tmap is running (not started as `tmap`)")
    if Path(str(command)).name == "treasure-map-mcp":
        return _Classified("stale", "uses the retired treasure-map-mcp command")
    if args != ["mcp"]:
        return _Classified("stale", f"args {args!r} (expected ['mcp'])")
    if env:
        return _Classified("stale", "carries an env block")
    if command != str(tmap):
        return _Classified("stale", f"points at {command} (running: {tmap})")
    return _Classified("aligned")


def _manual_cli(tmap: Path | None) -> str:
    return f"claude mcp add -s user {SERVER} -- {tmap or '<path to tmap>'} mcp"


def _manual_codex(tmap: Path | None) -> str:
    return f'[mcp_servers.{SERVER}]\ncommand = "{tmap or "<path to tmap>"}"\nargs = ["mcp"]'


def _manual_json(tmap: Path | None) -> str:
    entry = {"mcpServers": {SERVER: {"command": str(tmap or "<path to tmap>"), "args": ["mcp"]}}}
    return json.dumps(entry, indent=2)


def dsh_block(tmap: Path | str) -> str:
    return (
        "- insert:\n"
        f"    - id: {DSH_ENTRY_ID}\n"
        "      name: '@deepseek-ai/dsh-mcp-client'\n"
        "      config:\n"
        f"        serverName: {SERVER}\n"
        "        transport: stdio\n"
        f"        command: {json.dumps(str(tmap))}\n"
        "        args: [mcp]\n"
    )


def manual_text(client: str, tmap: Path | None) -> str:
    if client == "claude-code":
        return _manual_cli(tmap)
    if client == "codex":
        return _manual_codex(tmap)
    if client == "dsh":
        return dsh_block(tmap or "<path to tmap>")
    return _manual_json(tmap)


# ── where each client keeps its configuration ───────────────────────────────────────────────


def claude_json(host: ClientHost) -> Path:
    base = host.environ.get("CLAUDE_CONFIG_DIR")
    return (Path(base) if base else host.home) / ".claude.json"


def codex_config(host: ClientHost) -> Path:
    base = host.environ.get("CODEX_HOME")
    return (Path(base) if base else host.home / ".codex") / "config.toml"


def cursor_config(host: ClientHost) -> Path:
    return host.home / ".cursor" / "mcp.json"


def desktop_config(host: ClientHost) -> Path:
    if host.platform.is_darwin:
        return (
            host.home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
        )
    return host.home / ".config" / "Claude" / "claude_desktop_config.json"


def dsh_home(host: ClientHost) -> Path:
    """dsh's home as dsh resolves it: a non-blank ``$DSH_HOME`` (``~`` expanded), else
    ``~/.dsh`` — the same for a global and an npx install, since the package decides it."""
    base = (host.environ.get("DSH_HOME") or "").strip()
    if not base:
        return host.home / ".dsh"
    if base == "~" or base.startswith(("~/", "~\\")):
        return host.home / base[2:] if len(base) > 1 else host.home
    return Path(base)


def dsh_patch(host: ClientHost) -> Path:
    """The home-level patch layer ``$DSH_HOME/cordis.patch.yml``: dsh applies it over every
    profile's own layer, so one entry here reaches every profile. This is the file tmap writes."""
    return dsh_home(host) / DSH_PATCH_FILE


def dsh_profile_patches(host: ClientHost) -> list[Path]:
    """Each profile's own layer (``profiles/<name>/cordis.patch.yml``; a profile is a directory
    holding ``cordis.yml``). tmap only reads these — an entry the user wrote there counts."""
    root = dsh_home(host) / "profiles"
    try:
        dirs = sorted(d for d in root.iterdir() if (d / "cordis.yml").is_file())
    except OSError:
        return []
    return [d / DSH_PATCH_FILE for d in dirs if (d / DSH_PATCH_FILE).is_file()]


def detected(client: str, host: ClientHost) -> bool:
    if client == "claude-code":
        return bool(
            host.which("claude") or (host.home / ".claude").is_dir() or claude_json(host).exists()
        )
    if client == "codex":
        return bool(host.which("codex") or codex_config(host).parent.is_dir())
    if client == "cursor":
        return (host.home / ".cursor").is_dir()
    if client == "claude-desktop":
        if host.platform.is_darwin:
            return desktop_config(host).parent.is_dir()
        return desktop_config(host).is_file()
    if client == "dsh":
        return dsh_home(host).is_dir()
    raise ValueError(client)


# ── reading ──────────────────────────────────────────────────────────────────────────────────


def _load_json_object(path: Path) -> dict[str, Any] | None:
    """The file's top-level object; {} when absent; None when it cannot be parsed as one."""
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_bytes())
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _servers(obj: Mapping[str, Any]) -> Mapping[str, Any]:
    servers = obj.get("mcpServers")
    return servers if isinstance(servers, dict) else {}


def _inspect_claude(host: ClientHost, tmap: Path | None) -> ClientState:
    path = claude_json(host)
    has_cli = host.which("claude") is not None
    found = detected("claude-code", host)
    data = _load_json_object(path)
    if data is None:
        return ClientState(
            "claude-code", found, "invalid", f"{path} is not valid JSON", path, has_cli=has_cli
        )
    top = classify(_servers(data).get(SERVER), tmap)
    shadowing: list[Path] = []
    reported: list[str] = []
    gone: list[str] = []
    projects = data.get("projects")
    for proj_dir, proj in sorted(projects.items()) if isinstance(projects, dict) else []:
        if not Path(proj_dir).is_dir():
            # A project directory that no longer exists shadows nothing (no session can start
            # there), and `cd` into it could not remove the entry anyway: noted, not counted.
            if isinstance(proj, dict) and _servers(proj).get(SERVER) is not None:
                gone.append(proj_dir)
            continue
        if isinstance(proj, dict):
            local = _servers(proj).get(SERVER)
            if local is not None:
                c = classify(local, tmap)
                if c.state == "foreign":
                    reported.append(f"local scope in {proj_dir}: not tmap's ({c.why})")
                else:
                    shadowing.append(Path(proj_dir))
        mcp_json = Path(proj_dir) / ".mcp.json"
        proj_file = _load_json_object(mcp_json) if mcp_json.is_file() else {}
        if proj_file and SERVER in _servers(proj_file):
            reported.append(f"{mcp_json} (project file; tmap does not edit it)")
    state: EntryState = top.state
    detail = top.why
    if gone:
        detail = (detail + "; " if detail else "") + (
            "ignored: entries for project directories that no longer exist: " + ", ".join(gone)
        )
    if top.state == "aligned" and (shadowing or reported):
        state = "shadowed"
        where = [str(d) for d in shadowing] + reported
        detail = "a project entry of the same name wins in: " + "; ".join(where)
    return ClientState(
        "claude-code", found, state, detail, path, tuple(shadowing), tuple(reported), has_cli
    )


def _inspect_codex(host: ClientHost, tmap: Path | None) -> ClientState:
    path = codex_config(host)
    has_cli = host.which("codex") is not None
    found = detected("codex", host)
    if not path.exists():
        return ClientState("codex", found, "missing", "", path, has_cli=has_cli)
    try:
        data = tomllib.loads(path.read_text())
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        return ClientState("codex", found, "invalid", f"{path}: {exc}", path, has_cli=has_cli)
    servers = data.get("mcp_servers")
    entry = servers.get(SERVER) if isinstance(servers, dict) else None
    c = classify(entry, tmap)
    return ClientState("codex", found, c.state, c.why, path, has_cli=has_cli)


def _inspect_json_client(
    client: str, path: Path, host: ClientHost, tmap: Path | None
) -> ClientState:
    found = detected(client, host)
    data = _load_json_object(path)
    if data is None:
        return ClientState(client, found, "invalid", f"{path} is not a JSON object", path)
    raw_servers = data.get("mcpServers")
    if raw_servers is not None and not isinstance(raw_servers, dict):
        return ClientState(client, found, "invalid", f"{path}: mcpServers is not an object", path)
    c = classify(_servers(data).get(SERVER), tmap)
    return ClientState(client, found, c.state, c.why, path)


_YAML_UNSAFE = re.compile(r"!!js|(^|[\s\[{,:-])[&*][A-Za-z0-9_.-]+", re.MULTILINE)


@dataclass(frozen=True)
class _DshRead:
    text: str
    items: list[Any] | None  # None: tmap cannot safely edit this file
    why: str = ""


def _read_dsh(path: Path) -> _DshRead:
    if not path.exists():
        return _DshRead("", [])
    try:
        text = path.read_text()
    except (OSError, UnicodeDecodeError) as exc:
        return _DshRead("", None, str(exc))
    if _YAML_UNSAFE.search(text):
        return _DshRead(text, None, "uses !!js tags or YAML anchors/aliases")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return _DshRead(text, None, f"not valid YAML: {exc}")
    if data is None:
        return _DshRead(text, [])
    if not isinstance(data, list):
        return _DshRead(text, None, "its top level is not a list")
    return _DshRead(text, data)


def _dsh_entries(items: Sequence[Any]) -> list[dict[str, Any]]:
    """Every inserted entry serving ``treasure-map`` — whatever its id (a hand-written one is
    tmap's server too, and a second one beside it would start the server twice)."""
    out: list[dict[str, Any]] = []
    for item in items:
        inserts = item.get("insert") if isinstance(item, dict) else None
        for e in inserts if isinstance(inserts, list) else []:
            config = e.get("config") if isinstance(e, dict) else None
            if isinstance(config, dict) and config.get("serverName") == SERVER:
                out.append(e)
    return out


def _dsh_classify(entry: dict[str, Any], tmap: Path | None) -> _Classified:
    config = entry.get("config") or {}
    if config.get("transport") not in (None, "stdio"):
        return _Classified("foreign", f"transport {config.get('transport')!r}")
    return classify(
        {"command": config.get("command"), "args": config.get("args"), "env": config.get("env")},
        tmap,
    )


def _dsh_expected(tmap: Path) -> dict[str, Any]:
    entries = yaml.safe_load(dsh_block(tmap))[0]["insert"]
    expected: dict[str, Any] = entries[0]
    return expected


_DSH_SEVERITY = ("foreign", "invalid", "stale", "unknown", "aligned")


def _inspect_dsh(host: ClientHost, tmap: Path | None) -> ClientState:
    """Read the home layer AND every profile layer: an entry in any of them is the server."""
    home_patch = dsh_patch(host)
    found = detected("dsh", host)
    read = _read_dsh(home_patch)
    if read.items is None:
        return ClientState("dsh", found, "invalid", f"{home_patch} {read.why}", home_patch)
    hits: list[tuple[Path, dict[str, Any]]] = [(home_patch, e) for e in _dsh_entries(read.items)]
    for prof in dsh_profile_patches(host):
        pr = _read_dsh(prof)
        if pr.items is None:
            if SERVER in pr.text:
                return ClientState(
                    "dsh",
                    found,
                    "unknown",
                    f"{prof} {pr.why}; cannot read its {SERVER} entry",
                    prof,
                )
            continue
        hits += [(prof, e) for e in _dsh_entries(pr.items)]
    if not hits:
        return ClientState("dsh", found, "missing", "", home_patch)
    states = [(_dsh_classify(e, tmap), where) for where, e in hits]
    worst = min(states, key=lambda s: _DSH_SEVERITY.index(s[0].state))
    in_home = any(w == home_patch for _c, w in states)
    reported = [
        f"{w} (a profile layer: tmap reads it, never edits it)"
        for w in dict.fromkeys(w for _c, w in states if w != home_patch)
    ]
    if len(hits) > 1 and worst[0].state == "aligned":
        files = ", ".join(str(w) for _c, w in states)
        return ClientState(
            "dsh",
            found,
            "stale",
            f"{SERVER} is inserted {len(hits)} times: {files}",
            worst[1],
            reported=tuple(reported),
            editable=in_home,
        )
    return ClientState(
        "dsh",
        found,
        worst[0].state,
        worst[0].why,
        worst[1],
        reported=tuple(reported),
        editable=in_home,
    )


def inspect(client: str, host: ClientHost, tmap: Path | None) -> ClientState:
    if client == "claude-code":
        return _inspect_claude(host, tmap)
    if client == "codex":
        return _inspect_codex(host, tmap)
    if client == "cursor":
        return _inspect_json_client(client, cursor_config(host), host, tmap)
    if client == "claude-desktop":
        return _inspect_json_client(client, desktop_config(host), host, tmap)
    if client == "dsh":
        return _inspect_dsh(host, tmap)
    raise ValueError(client)


# ── writing ──────────────────────────────────────────────────────────────────────────────────


def _read_back(path: Path) -> bytes:
    """The bytes a write left behind (a seam a test uses to simulate a bad write)."""
    return path.read_bytes()


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    """Replace the content of ``path`` atomically. A symlink is written THROUGH: the file it
    points at gets the new content and the link stays a link (a config kept in a dotfiles
    repository must not be turned into a detached copy)."""
    path = Path(os.path.realpath(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _restore(path: Path, original: bytes | None, mode: int) -> None:
    if original is None:
        path.unlink(missing_ok=True)
    else:
        _atomic_write(path, original, mode)


def _without_ours(obj: Mapping[str, Any], had_servers_key: bool) -> dict[str, Any]:
    out = copy.deepcopy(dict(obj))
    servers = out.get("mcpServers")
    if isinstance(servers, dict):
        servers.pop(SERVER, None)
        if not servers and not had_servers_key:
            out.pop("mcpServers")
    return out


def json_transaction(path: Path, desired: dict[str, Any] | None) -> Outcome:
    """Set (``desired``) or delete (None) ``mcpServers["treasure-map"]`` in a JSON file, touching
    nothing else: back up the first time, write atomically, read back, and put the original bytes
    back when the result is not exactly the intended change."""
    existed = path.exists()
    original = path.read_bytes() if existed else None
    obj = _load_json_object(path)
    if obj is None:
        return Outcome(False, f"{path} is not a JSON object; not modified")
    raw_servers = obj.get("mcpServers")
    if raw_servers is not None and not isinstance(raw_servers, dict):
        return Outcome(False, f"{path}: mcpServers is not an object; not modified")
    had_servers_key = "mcpServers" in obj
    new = copy.deepcopy(obj)
    servers = new.setdefault("mcpServers", {})
    if desired is None:
        if SERVER not in servers:
            return Outcome(True, f"{path}: no {SERVER} entry")
        del servers[SERVER]
    else:
        servers[SERVER] = desired
    mode = (path.stat().st_mode & 0o777) if existed else 0o600
    backup = path.with_name(path.name + ".tmap.backup")
    if existed and not backup.exists() and original is not None:
        _atomic_write(backup, original, mode)
    _atomic_write(path, (json.dumps(new, indent=2, ensure_ascii=False) + "\n").encode(), mode)
    try:
        back = json.loads(_read_back(path))
    except (OSError, ValueError):
        back = None
    good = (
        isinstance(back, dict)
        and _servers(back).get(SERVER) == desired
        and _without_ours(back, had_servers_key) == _without_ours(obj, had_servers_key)
    )
    if not good:
        _restore(path, original, mode)
        return Outcome(False, f"{path}: the write did not read back as intended; restored")
    verb = "removed from" if desired is None else "written to"
    return Outcome(True, f"{SERVER} {verb} {path}")


def _desktop_running(host: ClientHost) -> bool:
    if not host.platform.is_darwin:
        return False
    res = host.run(["pgrep", "-x", "Claude"])
    return res is not None and res.returncode == 0


def _cli(host: ClientHost, argv: list[str], cwd: Path | None = None) -> tuple[bool, str]:
    res = host.run(argv, cwd=cwd, timeout=60)
    if res is None:
        return False, f"could not run {argv[0]}"
    if res.returncode != 0:
        tail = (res.stderr or res.stdout).strip().splitlines()
        return False, f"`{' '.join(argv[:4])} …` failed: {tail[-1] if tail else res.returncode}"
    return True, ""


def register(
    client: str,
    host: ClientHost,
    tmap: Path | None,
    *,
    confirm_quit: Callable[[str], None] | None = None,
) -> Outcome:
    """Make ``client``'s user-level entry the expected one. ``confirm_quit`` (interactive only)
    is asked to wait while the user quits Claude Desktop."""
    manual = manual_text(client, tmap)
    if tmap is None:
        return Outcome(False, "tmap was not started as `tmap`; register it by hand", manual)
    state = inspect(client, host, tmap)
    if state.state == "foreign":
        return Outcome(False, f"a different {SERVER} server is configured; not modified", manual)
    if state.state == "invalid":
        return Outcome(False, f"{state.detail}; not modified", manual)
    if state.state in ("aligned", "shadowed"):
        return Outcome(True, "already registered")
    if client == "claude-code":
        if not state.has_cli:
            return Outcome(False, "the claude CLI is not on PATH", manual)
        old = None
        if state.state == "stale":
            old = _servers(_load_json_object(claude_json(host)) or {}).get(SERVER)
            ok, why = _cli(host, ["claude", "mcp", "remove", "-s", "user", SERVER])
            if not ok:
                return Outcome(False, why, manual)
        ok, why = _cli(host, ["claude", "mcp", "add", "-s", "user", SERVER, "--", str(tmap), "mcp"])
        if not ok:
            if old is not None:  # never leave the user with less than they had
                back, _w = _cli(
                    host,
                    ["claude", "mcp", "add-json", "-s", "user", SERVER, json.dumps(old)],
                )
                why += "; the previous entry was " + ("put back" if back else "NOT put back")
            return Outcome(False, why, manual)
        after = inspect(client, host, tmap)
        if after.state not in ("aligned", "shadowed"):
            return Outcome(False, f"after `claude mcp add` the entry reads {after.state}", manual)
        return Outcome(True, f"registered (user scope) in {after.config_path}")
    if client == "codex":
        if not state.has_cli:
            return Outcome(False, "the codex CLI is not on PATH", manual)
        if state.state == "stale":
            ok, why = _cli(host, ["codex", "mcp", "remove", SERVER])
            if not ok:
                return Outcome(False, why, manual)
        ok, why = _cli(host, ["codex", "mcp", "add", SERVER, "--", str(tmap), "mcp"])
        if not ok:
            return Outcome(False, why, manual)
        after = inspect(client, host, tmap)
        if after.state != "aligned":
            return Outcome(False, f"after `codex mcp add` the entry reads {after.state}", manual)
        return Outcome(True, f"registered in {after.config_path}")
    if client in ("cursor", "claude-desktop"):
        if client == "claude-desktop" and _desktop_running(host):
            if confirm_quit is None:
                return Outcome(
                    False, "Claude Desktop is running; quit it and run tmap init", manual
                )
            confirm_quit("Quit Claude Desktop, then press Enter")
            if _desktop_running(host):
                return Outcome(False, "Claude Desktop is still running; skipped", manual)
        assert state.config_path is not None
        out = json_transaction(state.config_path, {"command": str(tmap), "args": ["mcp"]})
        return out if out.ok else Outcome(False, out.message, manual)
    if client == "dsh":
        return _register_dsh(host, tmap, state)
    raise ValueError(client)


def _register_dsh(host: ClientHost, tmap: Path, state: ClientState) -> Outcome:
    """Append to the home layer — only when no layer serves treasure-map yet."""
    manual = dsh_block(tmap)
    path = dsh_patch(host)
    if state.state != "missing":
        return Outcome(
            False,
            f"{state.config_path} has a {SERVER} entry ({state.detail}); edit it by hand",
            manual,
        )
    read = _read_dsh(path)
    if read.items is None:
        return Outcome(False, f"{path} {read.why}; not modified", manual)
    original = path.read_bytes() if path.exists() else None
    text = read.text
    if text and not text.endswith("\n"):
        text += "\n"
    new_text = text + dsh_block(tmap)
    mode = (path.stat().st_mode & 0o777) if path.exists() else 0o600
    _atomic_write(path, new_text.encode(), mode)
    back = _read_dsh(path)
    ours = _dsh_entries(back.items) if back.items is not None else []
    prefix_kept = _read_back(path).decode(errors="replace").startswith(read.text)
    if len(ours) != 1 or ours[0] != _dsh_expected(tmap) or not prefix_kept:
        _restore(path, original, mode)
        return Outcome(False, f"{path}: the append did not read back as intended; restored", manual)
    return Outcome(True, f"appended to {path} (restart dsh; tools appear as mcp__{SERVER}__*)")


def remove_shadowing(host: ClientHost, project_dir: Path) -> Outcome:
    argv = ["claude", "mcp", "remove", "-s", "local", SERVER]
    manual = f"cd {project_dir} && {' '.join(argv)}"
    if host.which("claude") is None:
        return Outcome(False, "the claude CLI is not on PATH", manual)
    if not project_dir.is_dir():
        return Outcome(False, f"{project_dir} no longer exists", manual)
    ok, why = _cli(host, argv, cwd=project_dir)
    return Outcome(
        ok, why or f"removed the local-scope entry in {project_dir}", None if ok else manual
    )


def unregister(client: str, host: ClientHost, tmap: Path | None) -> list[Outcome]:
    """Remove tmap's entries from ``client`` (user scope, and Claude Code's local scope). A
    foreign entry and project files are left alone."""
    state = inspect(client, host, tmap)
    outs: list[Outcome] = []
    ours = state.state in ("aligned", "stale", "shadowed", "unknown")
    if client == "claude-code":
        if ours:
            if not state.has_cli:
                cmd = f"claude mcp remove -s user {SERVER}"
                outs.append(Outcome(False, "the claude CLI is not on PATH", cmd))
            else:
                ok, why = _cli(host, ["claude", "mcp", "remove", "-s", "user", SERVER])
                outs.append(Outcome(ok, why or "removed the user-scope entry"))
        for d in state.shadowing:
            outs.append(remove_shadowing(host, d))
        for r in state.reported:
            outs.append(Outcome(True, f"left alone: {r}"))
        return outs
    if not ours:
        if state.state == "foreign":
            outs.append(Outcome(True, f"left alone: a {SERVER} entry that is not tmap's"))
        return outs
    if client == "codex":
        if not state.has_cli:
            return [Outcome(False, "the codex CLI is not on PATH", f"codex mcp remove {SERVER}")]
        ok, why = _cli(host, ["codex", "mcp", "remove", SERVER])
        return [Outcome(ok, why or "removed")]
    if client in ("cursor", "claude-desktop"):
        assert state.config_path is not None
        return [json_transaction(state.config_path, None)]
    if client == "dsh":
        if not state.editable:
            return [Outcome(True, f"left alone: {r}") for r in state.reported]
        return [_unregister_dsh(host), *(Outcome(True, f"left alone: {r}") for r in state.reported)]
    raise ValueError(client)


def _unregister_dsh(host: ClientHost) -> Outcome:
    path = dsh_patch(host)
    read = _read_dsh(path)
    ours = _dsh_entries(read.items) if read.items is not None else []
    command = ours[0].get("config", {}).get("command") if len(ours) == 1 else None
    if not isinstance(command, str):
        return Outcome(False, f"cannot locate tmap's block in {path}; remove it by hand")
    block = dsh_block(command)
    if read.text.count(block) != 1:
        return Outcome(False, f"tmap's block in {path} was edited; remove it by hand")
    original = path.read_bytes()
    mode = path.stat().st_mode & 0o777
    _atomic_write(path, read.text.replace(block, "", 1).encode(), mode)
    back = _read_dsh(path)
    if back.items is None or _dsh_entries(back.items):
        _restore(path, original, mode)
        return Outcome(False, f"{path}: removal did not read back cleanly; restored")
    return Outcome(True, f"removed tmap's block from {path}")


@dataclass
class Survey:
    states: dict[str, ClientState] = field(default_factory=dict)

    def detected(self) -> list[str]:
        return [c for c in CLIENT_IDS if self.states[c].detected]


def survey(host: ClientHost, tmap: Path | None) -> Survey:
    return Survey({c: inspect(c, host, tmap) for c in CLIENT_IDS})
