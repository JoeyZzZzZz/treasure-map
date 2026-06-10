# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Non-binary ingester orchestrator: walk → detect → register → ingest.

Semantics: WIPE-AND-REBUILD on every analyze run (§13.3), same as build_xrefs.
DELETE FROM non_binary_files at the start cascades to script_calls via FK.
Single conn.commit() at the end; orchestrator owns the transaction boundary.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from treasure_map.lib.analyze.elf_inventory import sha256_file
from treasure_map.lib.analyze.non_binary.framework import NonBinaryFile, NonBinaryIngester

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[str, dict[str, Any]], None]

_MAX_BYTES = 5 * 1024 * 1024  # skip blobs > 5 MiB


@dataclass
class NonBinaryStats:
    """Counters returned by run_all_ingesters, surfaced to AnalyzeResult."""

    files_scanned: int = 0
    files_ingested: int = 0
    by_kind: dict[str, int] = field(default_factory=dict)
    script_calls: int = 0


def _walk_non_binary(fs_root: Path) -> list[NonBinaryFile]:
    """Yield NonBinaryFile records for every candidate non-ELF file under fs_root.

    Skips: symlinks, directories, ELF magic files, files > _MAX_BYTES.
    """
    candidates: list[NonBinaryFile] = []
    for fpath in sorted(fs_root.rglob("*")):
        if not fpath.is_file() or fpath.is_symlink():
            continue
        try:
            size = fpath.stat().st_size
            if size > _MAX_BYTES:
                continue
            with fpath.open("rb") as fh:
                head = fh.read(512)
            if head[:4] == b"\x7fELF":
                continue

            sha = sha256_file(fpath)
            try:
                raw_bytes = fpath.read_bytes()
                text: str | None = raw_bytes.decode("utf-8") if b"\x00" not in head else None
            except (UnicodeDecodeError, OSError):
                text = None

            candidates.append(
                NonBinaryFile(
                    path=fpath,
                    rel_path=str(fpath.relative_to(fs_root)),
                    name=fpath.name,
                    sha256=sha,
                    size_bytes=size,
                    head=head,
                    text=text,
                )
            )
        except (OSError, PermissionError):
            pass
    return candidates


def _register_file(
    conn: sqlite3.Connection,
    ingester: NonBinaryIngester,
    subtype: str,
    f: NonBinaryFile,
) -> int:
    """Insert a non_binary_files master row; return its rowid."""
    detected_via = (
        "shebang"
        if (f.text and f.text.split("\n", 1)[0].startswith("#!"))
        else ("extension" if "." in f.name else "heuristic")
    )
    cur = conn.execute(
        """INSERT INTO non_binary_files
           (kind, subtype, name, path, sha256, size_bytes, detected_via)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (ingester.kind, subtype, f.name, f.rel_path, f.sha256, f.size_bytes, detected_via),
    )
    return int(cur.lastrowid)  # type: ignore[arg-type]


def run_all_ingesters(
    conn: sqlite3.Connection,
    fs_root: Path,
    *,
    skip_ingesters: frozenset[str] = frozenset(),
    progress_callback: ProgressCallback | None = None,
) -> NonBinaryStats:
    """Wipe and rebuild non_binary_files + sub-tables from the firmware fs_root.

    Runs each active ingester in INGESTER_REGISTRY order; first detect()-match
    claims the file (first-match-wins, same as STRING_RULES in xrefs.py).
    """
    from treasure_map.lib.analyze.non_binary import INGESTER_REGISTRY

    stats = NonBinaryStats()
    cur = conn.cursor()

    cur.execute("DELETE FROM non_binary_files")
    conn.commit()

    active = [i for i in INGESTER_REGISTRY if i.kind not in skip_ingesters]
    if not active:
        return stats

    candidates = _walk_non_binary(fs_root)
    stats.files_scanned = len(candidates)

    if progress_callback:
        progress_callback("non_binary_scan", {"files_scanned": stats.files_scanned})

    for f in candidates:
        for ingester in active:
            subtype = ingester.detect(f)
            if subtype is None:
                continue
            file_id = _register_file(conn, ingester, subtype, f)
            sub_rows = ingester.ingest(conn, file_id, f)
            stats.files_ingested += 1
            stats.by_kind[ingester.kind] = stats.by_kind.get(ingester.kind, 0) + 1
            stats.script_calls += sub_rows
            break

    conn.commit()

    if progress_callback:
        progress_callback(
            "non_binary_done",
            {
                "files_ingested": stats.files_ingested,
                "script_calls": stats.script_calls,
                "by_kind": stats.by_kind,
            },
        )

    logger.info(
        "non_binary: %d scanned, %d ingested (%s), %d script_calls",
        stats.files_scanned,
        stats.files_ingested,
        stats.by_kind,
        stats.script_calls,
    )
    return stats
