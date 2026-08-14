# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Filesystem symlink inventory — one honest record per symbolic link under the firmware root.

A firmware rootfs routes a large share of its commands through symlinks: ``/bin/sh -> busybox``,
``/sbin/ifconfig -> ../bin/busybox``, and so on. Without this table a cross-binary "A execs B"
edge cannot tell "B is really busybox" from "B was never extracted", so the whole link-mediated
half of the edge set reads as a coverage hole.

★ This layer records LINKS AND THEIR FINAL TARGET ONLY. It does not repair what the extraction
tool destroyed, and it does not guess an applet's real implementation — deciding that
``bin/find -> /dev/null`` means "a busybox applet the unpacker flattened" needs an applet roster,
which is a semantic judgement this layer refuses to make. A damaged link is recorded as damaged,
with the reason, and the reader judges.

Three damage classes are separated because they mean different things to a reader:

``devnull_placeholder``
    The link target is exactly ``/dev/null``. Some extraction tools write this placeholder for a
    link they could not reproduce; some devices genuinely point a node there. Both land here, on
    purpose — telling them apart is the semantic call above. Judged on the FULL target path only,
    never on the basename: a real file named ``null`` is not a placeholder.
``escapes_root``
    The target normalizes to somewhere outside the firmware root. Checked BEFORE existence so a
    climbing link (``foo -> ../../../../etc/passwd``) can never be answered by the HOST
    filesystem — a host file must never make a firmware link read as resolved.
``dangling``
    The target stays inside the root but nothing is there.

A chain longer than ``_MAX_CHAIN`` hops (or a cycle) is recorded ``chain_unresolved`` rather than
followed forever — a cycle must never read as resolved.
"""

from __future__ import annotations

import logging
import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

# The placeholder some extraction tools leave behind for a link they could not reproduce.
_DEVNULL = "/dev/null"

# Symlink-to-symlink hops followed before giving up. A rootfs chain is 1-2 hops in practice; the
# cap exists so a cycle terminates as UNRESOLVED instead of spinning.
_MAX_CHAIN = 8

CORRUPT_DEVNULL = "devnull_placeholder"
CORRUPT_DANGLING = "dangling"
CORRUPT_ESCAPES_ROOT = "escapes_root"
CORRUPT_CHAIN = "chain_unresolved"


@dataclass(frozen=True)
class SymlinkRecord:
    """One symbolic link: where it lives, what it points at, and whether that target is usable.

    ``link_path`` is relative to the firmware root (matching ``non_binary_files.path``);
    ``target_raw`` is the link value verbatim as ``readlink`` returned it; ``target_name`` is the
    basename of the FINAL target after following the chain. ``resolved`` is 1 only when the chain
    ended on something that exists inside the root — every damage class reports 0 plus the reason,
    so a reader never mistakes a broken link for a missing one."""

    link_path: str
    link_name: str
    target_raw: str
    target_name: str
    resolved: int
    corrupt_reason: str | None


def _norm(path: Path) -> Path:
    """Lexical normalization (``..`` collapsed) WITHOUT touching the filesystem.

    Deliberately not ``Path.resolve()``: resolve() follows symlinks on the HOST, which would let a
    host-side link decide a firmware link's target."""
    return Path(os.path.normpath(path))


def _reroot(target: str, link_parent: Path, fs_root: Path) -> Path | None:
    """Where does ``target`` land inside the firmware root? None when it escapes the root.

    An ABSOLUTE target is relative to the firmware's own root, not the host's — ``/bin/busybox``
    inside the image means ``<fs_root>/bin/busybox``. A relative target resolves against the
    directory holding the link."""
    root = _norm(fs_root)
    cand = root / target.lstrip("/") if target.startswith("/") else link_parent / target
    norm = _norm(cand)
    if norm != root and root not in norm.parents:
        return None
    return norm


def classify_symlink(link: Path, fs_root: Path) -> SymlinkRecord:
    """Follow ``link`` to its final target inside ``fs_root`` and record the outcome.

    Damage is judged in this order — placeholder, escaping, then missing — because each later test
    is only meaningful once the earlier one is ruled out: an escaping target must not be tested for
    existence at all (that would consult the host filesystem)."""
    rel = link.relative_to(fs_root).as_posix()
    raw = os.readlink(link)

    if os.path.normpath(raw) == _DEVNULL:
        # Judged on the full path ONLY. A basename test would flag a real file named "null".
        return SymlinkRecord(rel, link.name, raw, "null", 0, CORRUPT_DEVNULL)

    current = link
    value = raw
    for _ in range(_MAX_CHAIN):
        nxt = _reroot(value, current.parent, fs_root)
        if nxt is None:
            return SymlinkRecord(rel, link.name, raw, Path(value).name, 0, CORRUPT_ESCAPES_ROOT)
        if nxt.is_symlink():
            current = nxt
            value = os.readlink(nxt)
            continue
        if not nxt.exists():
            return SymlinkRecord(rel, link.name, raw, nxt.name, 0, CORRUPT_DANGLING)
        return SymlinkRecord(rel, link.name, raw, nxt.name, 1, None)
    return SymlinkRecord(rel, link.name, raw, Path(value).name, 0, CORRUPT_CHAIN)


class SymlinkCollector:
    """Collects symlink records during a filesystem walk; safe to share between several walks.

    Records are keyed by link path, so offering the same link twice (two walks over the same root)
    stores it once — sharing one collector can never double-count. ``offer`` answers "was this a
    symlink?", which is exactly the test a walk already performs before skipping the entry, so a
    walk adopts the collector by replacing its own ``is_symlink()`` test with this call.

    ★ The symlink test MUST run before any ``is_file()`` test. ``is_file()`` follows the link, so a
    placeholder or dangling link answers False there and is skipped as "not a regular file" — the
    two damage classes that matter most would never be seen."""

    def __init__(self, fs_root: Path) -> None:
        self._fs_root = fs_root
        self._by_path: dict[str, SymlinkRecord] = {}

    def offer(self, path: Path) -> bool:
        """Record ``path`` when it is a symlink. Returns True when it was one (walk should skip it).

        An unreadable link still answers True — the walk must skip it either way — but records
        nothing; it is a link we could not describe, never a link we claim does not exist."""
        if not path.is_symlink():
            return False
        try:
            record = classify_symlink(path, self._fs_root)
        except (OSError, ValueError):
            logger.debug("symlink unreadable, not recorded: %s", path)
            return True
        self._by_path[record.link_path] = record
        return True

    @property
    def records(self) -> list[SymlinkRecord]:
        """Every collected link, ordered by path (deterministic across runs)."""
        return [self._by_path[k] for k in sorted(self._by_path)]


def write_symlinks(conn: sqlite3.Connection, records: list[SymlinkRecord]) -> int:
    """Wipe-and-rebuild the fs_symlinks table from ``records``; return the row count.

    Same semantics as the other derived tables (xrefs, non_binary_files): the previous inventory is
    dropped and replaced, never incrementally merged, so a re-analyze of a changed root cannot
    leave a stale link behind."""
    conn.execute("DELETE FROM fs_symlinks")
    conn.executemany(
        "INSERT INTO fs_symlinks "
        "(link_path, link_name, target_raw, target_name, resolved, corrupt_reason) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        [
            (r.link_path, r.link_name, r.target_raw, r.target_name, r.resolved, r.corrupt_reason)
            for r in records
        ],
    )
    conn.commit()
    logger.info("symlinks: %d links recorded", len(records))
    return len(records)
