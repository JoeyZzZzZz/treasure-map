# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The "last run" pointer — what `tmap mcp` reads to start without explicit paths.

A user's analysis.db usually lives OUTSIDE the managed workspace base (a scratch disk, a custom
project tree), so "the most recent scan" cannot be found by scanning the workspace directory. The
producing commands (`scan` / `analyze` / `hunt`) instead write a small pointer recording the
ABSOLUTE analysis.db path, its atlas path, the run id, and a timestamp. `tmap mcp` reads it so the
common case ("I just scanned, now serve it") needs no arguments. Explicit paths always win.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

_POINTER_PATH = Path.home() / ".treasure-map" / "last_run.json"


def pointer_path() -> Path:
    """The default location of the last-run pointer (~/.treasure-map/last_run.json)."""
    return _POINTER_PATH


@dataclass(frozen=True)
class LastRun:
    """The recorded most-recent run: absolute db paths, the run id, and when it was written."""

    analysis_db: Path
    atlas_db: Path
    run_id: str
    recorded_at: str


def write_last_run(
    analysis_db: Path | str,
    atlas_db: Path | str,
    run_id: str,
    *,
    path: Path | None = None,
) -> Path:
    """Record the just-produced run as the last run (absolute paths). Returns the pointer path.

    Best-effort and never fatal to the caller: a write failure (read-only home, etc.) is swallowed
    so a successful scan is never turned into an error by a convenience pointer."""
    target = path if path is not None else _POINTER_PATH
    payload = {
        "analysis_db": str(Path(analysis_db).resolve()),
        "atlas_db": str(Path(atlas_db).resolve()),
        "run_id": run_id,
        "recorded_at": datetime.now(UTC).isoformat(),
    }
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, indent=2) + "\n")
    except OSError:
        pass
    return target


def read_last_run(*, path: Path | None = None) -> LastRun | None:
    """Read the last-run pointer, or None when it is absent or unreadable (never raises)."""
    target = path if path is not None else _POINTER_PATH
    if not target.exists():
        return None
    try:
        data = json.loads(target.read_text())
        return LastRun(
            analysis_db=Path(data["analysis_db"]),
            atlas_db=Path(data["atlas_db"]),
            run_id=str(data["run_id"]),
            recorded_at=str(data.get("recorded_at", "")),
        )
    except (OSError, ValueError, KeyError, TypeError):
        return None
