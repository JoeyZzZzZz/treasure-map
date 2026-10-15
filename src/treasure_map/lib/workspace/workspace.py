# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import fcntl
import logging
from collections.abc import Callable
from pathlib import Path
from typing import IO, Any

from treasure_map.lib.errors import WorkspaceError

logger = logging.getLogger(__name__)

# Kept for callers that type a scan/diff progress callback; the Workspace no longer fires one.
ProgressCallback = Callable[[str, dict[str, Any]], None]


class Workspace:
    """One analysis run's directory: the folder that holds its ``analysis.db``.

    A context manager so a run can ``with Workspace(path):`` and have the directory provisioned.
    It no longer keeps a step-checkpoint database (``state.db``): a scan's resume is decided by
    the per-binary pass_version in analysis.db, and the checkpoint table was only ever read by its
    own tests.

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
