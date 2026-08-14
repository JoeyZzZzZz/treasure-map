# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import logging
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from treasure_map.lib.errors import WorkspaceError

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[str, dict[str, Any]], None]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS steps (
    name         TEXT PRIMARY KEY,
    completed_at DATETIME NOT NULL
);
"""


class Workspace:
    """SQLite-backed checkpoint store for a single analysis run.

    Each step is identified by a string name. Completed steps persist across
    process restarts so long runs can resume from the last checkpoint.
    """

    def __init__(
        self,
        path: Path,
        progress_callback: ProgressCallback | None = None,
    ) -> None:
        self.path = path
        self.progress_callback = progress_callback
        self._db_path = path / "state.db"
        self._conn: sqlite3.Connection | None = None
        self._ensure_init()

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def _ensure_init(self) -> None:
        self.path.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self._db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        logger.debug("Workspace opened at %s", self.path)

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> Workspace:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ── checkpoint API ────────────────────────────────────────────────────────

    def is_done(self, step: str) -> bool:
        """Return True if *step* was previously marked complete."""
        self._assert_open()
        row = self._conn.execute(  # type: ignore[union-attr]
            "SELECT 1 FROM steps WHERE name = ?", (step,)
        ).fetchone()
        return row is not None

    def mark_done(self, step: str, meta: dict[str, Any] | None = None) -> None:
        """Record *step* as completed and fire progress_callback."""
        self._assert_open()
        now = datetime.now(UTC).isoformat()
        try:
            self._conn.execute(  # type: ignore[union-attr]
                "INSERT OR REPLACE INTO steps (name, completed_at) VALUES (?, ?)",
                (step, now),
            )
            self._conn.commit()  # type: ignore[union-attr]
        except sqlite3.Error as exc:
            raise WorkspaceError(f"Failed to mark step '{step}' done: {exc}") from exc

        logger.debug("Step done: %s", step)
        if self.progress_callback:
            self.progress_callback(step, meta or {})

    def clear_downstream(self, step: str, downstream: list[str]) -> None:
        """Invalidate *downstream* steps when *step* must be re-run.

        This is called when a file's sha256 changes and we need to re-run
        the steps that depend on it.
        """
        self._assert_open()
        to_clear = [s for s in downstream if self.is_done(s)]
        if not to_clear:
            return
        placeholders = ",".join("?" * len(to_clear))
        self._conn.execute(  # type: ignore[union-attr]
            f"DELETE FROM steps WHERE name IN ({placeholders})", to_clear
        )
        self._conn.commit()  # type: ignore[union-attr]
        logger.info("Cleared downstream steps: %s", to_clear)

    def list_done(self) -> list[str]:
        """Return names of all completed steps, ordered by completion time."""
        self._assert_open()
        rows = self._conn.execute(  # type: ignore[union-attr]
            "SELECT name FROM steps ORDER BY completed_at"
        ).fetchall()
        return [r["name"] for r in rows]

    def reset(self) -> None:
        """Delete all checkpoint records (does not delete workspace files)."""
        self._assert_open()
        self._conn.execute("DELETE FROM steps")  # type: ignore[union-attr]
        self._conn.commit()  # type: ignore[union-attr]
        logger.info("Workspace reset: %s", self.path)

    # ── internals ─────────────────────────────────────────────────────────────

    @property
    def db_path(self) -> Path:
        """Path to the analysis SQLite database inside this workspace."""
        return self.path / "analysis.db"

    def _assert_open(self) -> None:
        if self._conn is None:
            raise WorkspaceError("Workspace is closed")
