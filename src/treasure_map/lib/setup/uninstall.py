# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""``tmap uninstall``: take away what ``tmap init`` put here, and nothing else.

Only two kinds of thing are removed: tmap's own entries in the agents' configurations, and the
paths the install ledger records (the downloaded toolchain, BinExport, the completion script and
its rc block). A path the ledger does not record is never removed — not the user's own JDK,
Ghidra or BinDiff, even when config.yaml points at them. Before a recorded path is deleted it must
still be what tmap put there: under ``~/.treasure-map/toolchain``, or (BinExport in a user's
Ghidra) a ``BinExport`` directory whose jars still hash to what tmap installed.

The data stays unless ``--purge-data`` is given AND the user types the confirmation phrase;
``--yes`` does not stand in for it. Even then only what is provably tmap's goes (``purge_plan``):
the atlas and workspaces when they are tmap's databases, config.yaml and .env when tmap wrote them.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import stat
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
from treasure_map.lib.setup.tmap_files import config_text, written_by_tmap

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
    """Cut tmap's marked block out of the user's rc — as bytes, so a line in any encoding stays
    exactly as it was — and write the rest back atomically, keeping the file's mode (and writing
    through a symlink)."""
    try:
        data = rc.read_bytes()
        mode = stat.S_IMODE(rc.stat().st_mode)
    except OSError as exc:
        return f"could not read {rc}: {exc}"
    start = data.find(_MARK_START.encode())
    end = data.find(_MARK_END.encode(), start)
    if start < 0 or end < 0:
        return f"{rc}: no tmap completion block"
    end += len(_MARK_END.encode())
    if data[end : end + 1] == b"\n":
        end += 1
    if start > 0 and data[start - 1 : start] == b"\n":
        start -= 1  # the newline the block was added with
    try:
        cl._atomic_write(rc, data[:start] + data[end:], mode)
    except OSError as exc:
        return f"could not write {rc}: {exc}; its tmap completion block is still there"
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
            note = _remove_rc_block(Path(rc))
            if note.startswith("could not"):
                report.manual.append(note)
                continue  # the entry stays, so a later run removes the block
            report.removed.append(note)
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
                atomic_write_text(config_path, config_text(config_path, data))
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


_SQLITE_MAGIC = b"SQLite format 3\x00"
_ATLAS_TABLES = frozenset({"run", "instance"})
_ANALYSIS_TABLES = frozenset({"binaries", "functions"})


def _tmap_database(path: Path, tables: frozenset[str]) -> bool:
    """Whether ``path`` is a regular SQLite file holding ``tables`` (opened read-only)."""
    if path.is_symlink() or not path.is_file():
        return False
    try:
        with path.open("rb") as fh:
            if fh.read(len(_SQLITE_MAGIC)) != _SQLITE_MAGIC:
                return False
        conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
        try:
            names = {
                r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
        finally:
            conn.close()
    except (OSError, sqlite3.Error):
        return False
    return tables <= names


@dataclass(frozen=True)
class PurgePlan:
    """What ``--purge-data`` deletes, what it leaves (each with the reason), and the directories it
    removes afterwards only if nothing else is left in them."""

    delete: tuple[Path, ...]
    keep: tuple[str, ...]
    rmdir_if_empty: tuple[Path, ...]


def purge_plan(*, tm_home: Path, atlas: Path, workspace_dir: Path, home: Path) -> PurgePlan:
    """Only what is provably tmap's: the atlas when it is a SQLite file with tmap's tables, each
    directory directly under the workspace base whose ``analysis.db`` is tmap's (never the base
    itself — it may be any directory the user named — and nothing at all when the base is the home
    directory or above it), config.yaml and .env when tmap wrote them (an empty .env is an older
    init's placeholder), and tmap's last-run pointer."""
    delete: list[Path] = []
    keep: list[str] = []
    rmdir: list[Path] = []
    if _tmap_database(atlas, _ATLAS_TABLES):
        delete.append(atlas)
        delete += [
            p for p in (atlas.with_name(atlas.name + s) for s in ("-wal", "-shm")) if p.exists()
        ]
    elif atlas.exists():
        keep.append(f"{atlas}: not a tmap atlas")
    base = Path(os.path.realpath(workspace_dir))
    real_home = Path(os.path.realpath(home))
    if base == real_home or base in real_home.parents:
        keep.append(
            f"{workspace_dir}: the home directory or above it; no workspace there is deleted"
        )
    elif workspace_dir.is_dir():
        foreign = 0
        for child in sorted(workspace_dir.iterdir()):
            if (
                not child.is_symlink()
                and child.is_dir()
                and _tmap_database(child / "analysis.db", _ANALYSIS_TABLES)
            ):
                delete.append(child)
            else:
                foreign += 1
        if foreign:
            keep.append(f"{workspace_dir}: {foreign} entries that are not tmap workspaces")
        rmdir.append(workspace_dir)
    for name in ("config.yaml", ".env"):
        p = tm_home / name
        if p.is_symlink() or not p.is_file():
            continue
        if written_by_tmap(p) or (name == ".env" and p.stat().st_size == 0):
            delete.append(p)
        else:
            keep.append(f"{p}: not written by tmap init")
    if (tm_home / "last_run.json").is_file():
        delete.append(tm_home / "last_run.json")
    rmdir.append(tm_home)
    return PurgePlan(tuple(delete), tuple(keep), tuple(rmdir))


def describe_data(paths: tuple[Path, ...] | list[Path]) -> list[str]:
    return [f"{p} ({_size(p) / 1_000_000:.1f} MB)" for p in paths]


def purge_data(plan: PurgePlan, answer: str) -> bool:
    """Carry out ``plan`` only when ``answer`` is exactly the confirmation phrase."""
    if answer.strip() != PURGE_PHRASE:
        return False
    for p in plan.delete:
        _remove_path(p)
    for d in plan.rmdir_if_empty:
        try:
            d.rmdir()
        except OSError:
            pass  # something else is still in it
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
