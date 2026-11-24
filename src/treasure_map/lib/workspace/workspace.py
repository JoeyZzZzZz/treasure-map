# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import fcntl
import logging
import os
import sqlite3
from pathlib import Path
from typing import IO

from treasure_map.lib.errors import WorkspaceError
from treasure_map.lib.ro_db import ro_connect

logger = logging.getLogger(__name__)


class Workspace:
    """One analysis run's directory: the folder that holds its ``analysis.db``.

    A context manager so a run can ``with Workspace(path):`` and have the directory provisioned.
    The directory holds no checkpoint of its own: a scan's resume is decided by the per-binary
    pass_version in analysis.db.

    Entering it takes an exclusive lock on the workspace, held until exit: two scans writing one
    analysis.db at once would each re-key the other's rows. A second scan of the same workspace is
    refused instead of interleaved. The lock is an OS file lock, so a scan that dies releases it.
    """

    _LOCK_NAME = ".tmap-scan.lock"

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.mkdir(parents=True, exist_ok=True)
        self._lock: IO[str] | None = None
        logger.debug("Workspace at %s", self.path)

    def close(self) -> None:
        if self._lock is not None:
            fcntl.flock(self._lock, fcntl.LOCK_UN)
            self._lock.close()
            self._lock = None

    def __enter__(self) -> Workspace:
        fh = (self.path / self._LOCK_NAME).open("a")
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            fh.close()
            raise WorkspaceError(
                f"another tmap process is scanning workspace {self.path} — wait for it to finish "
                "(two scans of one workspace would overwrite each other's results)"
            ) from None
        self._lock = fh
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @property
    def db_path(self) -> Path:
        """Path to the analysis SQLite database inside this workspace."""
        return self.path / "analysis.db"


def workspace_of(db_path: Path, workspace_dir: Path) -> Path | None:
    """The workspace directory whose analysis.db ``db_path`` is, or None when it is not one.

    A workspace keeps its database at ``<dir>/analysis.db``. That directory counts as a workspace
    when it sits directly under ``workspace_dir`` (where ``-w`` names resolve), or when it already
    holds the lock file a scan takes, which covers a workspace made under an earlier base. Any
    other analysis.db, a copy kept elsewhere for instance, is not one; the caller then takes no
    lock and creates nothing beside it."""
    if db_path.name != "analysis.db":
        return None
    ws = db_path.parent
    try:
        under_base = ws.resolve().parent == workspace_dir.expanduser().resolve()
        return ws if under_base or (ws / Workspace._LOCK_NAME).is_file() else None
    except OSError:
        return None


def workspace_holds_other_firmware(db_path: Path, fs_root: Path) -> str | None:
    """The firmware root a workspace's ``analysis.db`` was last scanned from, when that is NOT
    ``fs_root``; else None. Read-only, and any error reading the database answers None.

    A scan writes each current binary's path into the database. When every one of them sits under
    ``fs_root`` the workspace already holds this same firmware (a re-scan, not an overwrite) and the
    answer is None. Otherwise the answer is the common root of the paths it does hold — the firmware
    a caller is about to overwrite. ``fs_root`` is the resolved root the caller passes; the binary
    paths a current scan writes are resolved the same way, so a same-firmware re-scan compares
    equal. The query matches ``current_binaries`` but is spelled out so a pre-view db reads too."""
    if not db_path.is_file():
        return None
    try:
        conn = ro_connect(db_path)
        try:
            paths = [
                r[0]
                for r in conn.execute(
                    "SELECT path FROM binaries "
                    "WHERE last_seen_at IS (SELECT MAX(last_seen_at) FROM binaries) "
                    "AND path IS NOT NULL AND path <> ''"
                ).fetchall()
            ]
        finally:
            conn.close()
    except sqlite3.Error:
        return None
    if not paths:
        return None
    root = str(fs_root)
    if any(p == root or p.startswith(root + os.sep) for p in paths):
        return None
    try:
        return str(os.path.commonpath(paths))
    except ValueError:
        # Mixed absolute and relative paths have no common root; name the first as the witness.
        return str(paths[0])
