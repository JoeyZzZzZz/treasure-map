# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Open a SQLite database strictly read-only, from a path that may contain anything.

``f"file:{path}?mode=ro"`` is wrong for a path holding ``#``, ``?`` or ``%``: ``#`` and ``?`` start
the URI's fragment and query, so the open silently targets a DIFFERENT file (and, with the query
cut off, loses ``mode=ro`` and may CREATE an empty database); ``%`` is read as a percent-escape and
fails. A firmware's unpacked tree and the workspace name derived from it both reach these paths, so
the escaping is not optional. ``Path.as_uri()`` percent-encodes every such byte."""

from __future__ import annotations

import sqlite3
from pathlib import Path


def ro_uri(path: str | Path) -> str:
    """The ``file:…?mode=ro`` URI for ``path``, with the path component properly escaped."""
    return Path(path).resolve().as_uri() + "?mode=ro"


def ro_connect(path: str | Path, *, row_factory: bool = False) -> sqlite3.Connection:
    """Connect read-only through an escaped URI; ``row_factory`` sets ``sqlite3.Row``."""
    conn = sqlite3.connect(ro_uri(path), uri=True)
    if row_factory:
        conn.row_factory = sqlite3.Row
    return conn
