# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Non-binary ingester framework: plain frozen dataclasses + callable pointers.

No ABC, no Protocol, no inheritance (Drift Pattern 9). A NonBinaryIngester is
a frozen dataclass holding two plain callables and a stable kind identifier.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class NonBinaryFile:
    """Represents a single candidate non-binary file found during the walk."""

    path: Path
    rel_path: str
    name: str
    sha256: str
    size_bytes: int
    head: bytes
    text: str | None


# detect: pure function, no DB access. Returns a subtype label if this ingester
# claims the file, else None. First non-None wins (INGESTER_REGISTRY order).
DetectFn = Callable[[NonBinaryFile], "str | None"]

# ingest: writes ingester sub-table rows for an already-registered master row.
# Returns the number of sub-rows written. Does NOT commit (orchestrator owns
# the transaction boundary, matching build_xrefs semantics).
IngestFn = Callable[[sqlite3.Connection, int, NonBinaryFile], int]


@dataclass(frozen=True)
class NonBinaryIngester:
    """Frozen dataclass binding a kind label to its detect + ingest callables."""

    kind: str
    detect: DetectFn
    ingest: IngestFn
