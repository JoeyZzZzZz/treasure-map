# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Kept for callers that type a scan/diff progress callback; the Workspace no longer fires one.
ProgressCallback = Callable[[str, dict[str, Any]], None]


class Workspace:
    """One analysis run's directory: the folder that holds its ``analysis.db``.

    A context manager so a run can ``with Workspace(path):`` and have the directory provisioned.
    It no longer keeps a step-checkpoint database (``state.db``): a scan's resume is decided by
    the per-binary pass_version in analysis.db, and the checkpoint table was only ever read by its
    own tests."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.mkdir(parents=True, exist_ok=True)
        logger.debug("Workspace at %s", self.path)

    def close(self) -> None:
        return None

    def __enter__(self) -> Workspace:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    @property
    def db_path(self) -> Path:
        """Path to the analysis SQLite database inside this workspace."""
        return self.path / "analysis.db"
