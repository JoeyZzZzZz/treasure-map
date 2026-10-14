# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""``tmap uninstall``: take away what ``tmap init`` put here, and nothing else.

Only two kinds of thing are removed: tmap's own entries in the agents' configurations, and the
paths the install ledger records (the downloaded toolchain, BinExport, the completion script and
its rc block). A path the ledger does not record is never removed — not the user's own JDK,
Ghidra or BinDiff, even when config.yaml points at them. Before a recorded path is deleted it must
still be what tmap put there: under ``~/.treasure-map/toolchain``, or (BinExport in a user's
Ghidra) a ``BinExport`` directory whose jars still hash to what tmap installed.

The data — config, atlas, workspaces — stays unless ``--purge-data`` is given AND the user types
the confirmation phrase; ``--yes`` does not stand in for it.
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from treasure_map.lib.diff.toolchain import binexport_lib_digest
from treasure_map.lib.setup import clients as cl
from treasure_map.lib.setup.completion import _MARK_END, _MARK_START, target_path
from treasure_map.lib.setup.discover import Runner
from treasure_map.lib.setup.ledger import (
    LEDGER_NAME,
    Entry,
    Ledger,
    atomic_write_text,
    strictly_under,
)

PURGE_PHRASE = "delete my data"


@dataclass
class UninstallReport:
    removed: list[str] = field(default_factory=list)
    refused: list[str] = field(default_factory=list)
    kept: list[str] = field(default_factory=list)
    manual: list[str] = field(default_factory=list)

    @property
    def failed(self) -> bool:
        return bool(self.refused or self.manual)


def _inside(path: Path, root: Path) -> bool:
    try:
        return Path(os.path.realpath(path)).is_relative_to(os.path.realpath(root))
    except (OSError, ValueError):
        return False


def _completion_paths(home: Path) -> set[str]:
    out = set()
    for shell in ("bash", "zsh"):
        p = target_path(shell, home)
        if p is not None:
            out.add(os.path.realpath(p))
    return out


def safe_to_remove(entry: Entry, *, toolchain_dir: Path, home: Path) -> str | None:
    """None when ``entry``'s path may be removed; else why not."""
    path = Path(entry.path)
    if entry.id == "completion":
        if os.path.realpath(path) in _completion_paths(home):
            return None
        return f"{path} is not where tmap installs completion"
    if entry.kind == "edit":
        return None  # restored, never deleted; checked in _restore_edit
    if strictly_under(path, toolchain_dir):
        return None
    if entry.id == "binexport" and path.name == "BinExport":
        recorded = entry.extra.get("lib_digest")
        if not path.exists():
            return None
        if not isinstance(recorded, str) or binexport_lib_digest(path) != recorded:
            return f"{path} changed since tmap installed it (its jars differ); not removed"
        return None
    return f"{path} is outside {toolchain_dir}; not removed"


def _restore_edit(entry: Entry) -> str:
    path = Path(entry.path)
    if not path.exists():
        return f"skipped {path} (gone with the managed Ghidra)"
    before = entry.extra.get("line_before")
    after = entry.extra.get("line_after")
    if not isinstance(before, str) or not isinstance(after, str):
        return f"left {path}: the ledger does not record the line"
    from treasure_map.lib.setup.plan import replace_line

    if replace_line(path, after, before):
        return f"restored {path}"
    return f"left {path}: its line is no longer tmap's"


def _remove_rc_block(rc: Path) -> str:
    try:
        text = rc.read_text()
    except OSError as exc:
        return f"could not read {rc}: {exc}"
    start = text.find(_MARK_START)
    end = text.find(_MARK_END, start)
    if start < 0 or end < 0:
        return f"{rc}: no tmap completion block"
    end += len(_MARK_END)
    if text[end : end + 1] == "\n":
        end += 1
    if start > 0 and text[start - 1] == "\n":
        start -= 1  # the newline the block was added with
    rc.write_text(text[:start] + text[end:])
    return f"removed tmap's completion block from {rc}"


def _remove_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.is_dir():
        shutil.rmtree(path)


def plan_lines(ledger: Ledger, survey: cl.Survey, *, toolchain_dir: Path, home: Path) -> list[str]:
    lines: list[str] = []
    for cid in cl.CLIENT_IDS:
        st = survey.states[cid]
        if st.state in ("aligned", "stale", "shadowed", "unknown") and st.editable:
            lines.append(f"remove treasure-map from {st.label} ({st.config_path})")
        for d in st.shadowing:
            lines.append(f"remove the local-scope entry in {d}")
        for r in st.reported:
            lines.append(f"leave alone: {r}")
    for e in reversed(ledger.entries):
        why = safe_to_remove(e, toolchain_dir=toolchain_dir, home=home)
        verb = "restore" if e.kind == "edit" else "remove"
        if why is None:
            lines.append(f"{verb} {e.path} ({e.id})")
        else:
            lines.append(f"refuse {e.path}: {why}")
    return lines


def uninstall(
    *,
    home: Path,
    tm_home: Path,
    client_host: cl.ClientHost,
    tmap: Path | None,
    config_path: Path,
    echo: Callable[[str], None],
) -> UninstallReport:
    report = UninstallReport()
    toolchain_dir = tm_home / "toolchain"
    # 1. agents
    for cid in cl.CLIENT_IDS:
        for out in cl.unregister(cid, client_host, tmap):
            (report.removed if out.ok else report.manual).append(
                f"{cl.LABELS[cid]}: {out.message}" + (f" — run: {out.manual}" if out.manual else "")
            )
    # 2. ledger, newest first
    ledger_path = toolchain_dir / LEDGER_NAME
    ledger = Ledger.load(ledger_path)
    removed_paths: list[Path] = []
    for e in list(reversed(ledger.entries)):
        why = safe_to_remove(e, toolchain_dir=toolchain_dir, home=home)
        if why is not None:
            report.refused.append(why)
            continue
        if e.kind == "edit":
            report.removed.append(_restore_edit(e))
            ledger.remove(e.id)
            continue
        path = Path(e.path)
        if path.exists() or path.is_symlink():
            _remove_path(path)
            report.removed.append(f"removed {path}")
            removed_paths.append(path)
        rc = e.extra.get("rc_block")
        if e.id == "completion" and isinstance(rc, str) and rc:
            report.removed.append(_remove_rc_block(Path(rc)))
        ledger.remove(e.id)
    # 3. config keys that pointed at what was removed
    if config_path.exists() and removed_paths:
        try:
            data = yaml.safe_load(config_path.read_text()) or {}
        except (OSError, yaml.YAMLError) as exc:
            data = None
            report.manual.append(
                f"{config_path} is unreadable ({exc}); clear any key pointing at a removed path"
            )
        if isinstance(data, dict):
            touched = False
            for keys in (
                ("ghidra", "local", "home"),
                ("toolchain", "java_home"),
                ("toolchain", "bindiff"),
            ):
                node: Any = data
                for k in keys[:-1]:
                    node = node.get(k) if isinstance(node, dict) else None
                if not isinstance(node, dict):
                    continue
                value = node.get(keys[-1])
                if isinstance(value, str) and any(
                    _inside(Path(os.path.expanduser(value)), p) for p in removed_paths
                ):
                    node[keys[-1]] = None
                    touched = True
                    report.removed.append(f"cleared {'.'.join(keys)} in {config_path}")
            if touched:
                atomic_write_text(config_path, yaml.safe_dump(data, default_flow_style=False))
    downloads = toolchain_dir / ".downloads"
    if downloads.is_dir() and not downloads.is_symlink():
        shutil.rmtree(downloads, ignore_errors=True)
        report.removed.append(f"removed {downloads} (unfinished downloads)")
    if not ledger.entries and ledger_path.exists():
        ledger_path.unlink()
        try:
            toolchain_dir.rmdir()
        except OSError:
            pass
    return report


def _size(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    total = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += (Path(root) / f).stat().st_size
            except OSError:
                pass
    return total


def data_paths(atlas: Path, workspace_dir: Path) -> list[Path]:
    out = [atlas, atlas.with_name(atlas.name + "-wal"), atlas.with_name(atlas.name + "-shm")]
    return [p for p in out if p.exists()] + ([workspace_dir] if workspace_dir.exists() else [])


def describe_data(paths: list[Path]) -> list[str]:
    return [f"{p} ({_size(p) / 1_000_000:.1f} MB)" for p in paths]


def purge_data(paths: list[Path], answer: str) -> bool:
    """Delete ``paths`` only when ``answer`` is exactly the confirmation phrase."""
    if answer.strip() != PURGE_PHRASE:
        return False
    for p in paths:
        _remove_path(p)
    return True


DIST = "tmap-agents"


def uv_self_uninstall(
    prefix: Path, home: Path, which: Callable[[str], str | None], run: Runner
) -> list[str] | None:
    """The command that removes the running tmap itself — ``uv tool uninstall tmap-agents`` —
    or None when this tmap does not run from uv's ``tmap-agents`` tool environment (an editable
    checkout, a pip install, another tool name): then tmap does not know how it was installed and
    leaves the program alone."""
    from treasure_map.lib.setup.update import find_uv, runs_from_uv_tool

    uv = find_uv(home, which)
    if uv is None or not runs_from_uv_tool(prefix, uv, run):
        return None
    return [uv, "tool", "uninstall", DIST]
