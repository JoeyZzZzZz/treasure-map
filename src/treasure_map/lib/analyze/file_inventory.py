# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Every file under the firmware root, and whether this scan took it in.

The scan reads a firmware through two inventories: the ELF walk (``elf_inventory.scan_filesystem``)
and the non-binary ingesters (``non_binary.orchestrator``). A file neither took in is invisible to
every later step — a diff of two runs cannot show that it changed, was removed or was added. This
table makes those files visible: one row per regular or special file under the root, with what the
scan took it in as, or why it did not. It records facts only; it never judges whether a file
matters.

``inventoried_as`` is read from what the two inventories actually took THIS scan (the ELF records
handed in, the ``non_binary_files`` rows the ingesters wrote), never re-guessed. For a file they did
not take, ``not_inventoried_reason`` replays the same tests in the same order those inventories
apply, so the reason is the one that kept it out:

  ELF (starts with the ELF magic), in ``scan_filesystem``'s order:
    * ``elf_unreadable``       — its header cannot be parsed (``detect_arch`` fails)
    * ``unsupported_arch``     — a machine the scan has no processor for
    * ``et_rel``               — a relocatable object (a kernel module, say): no loadable segment
    * ``no_loadable_segments`` — no PT_LOAD data in the file (a split or malformed image)
    * ``duplicate_content``    — the same bytes were taken in at another path
  anything else:
    * ``too_large``            — over the non-binary ingesters' size limit
    * ``ingest_failed``        — an ingester claimed it and then failed on it
    * ``no_ingester``          — no ingester recognises it (an extensionless text file, say)
  either:
    * ``not_regular_file``     — a device node, FIFO or socket (its content is never read)
    * ``unreadable``           — the file could not be opened

``file_type`` is read from the bytes, with no file-type library: ``elf_exec`` / ``elf_dyn`` /
``elf_rel`` / ``elf_core`` / ``elf_other`` from the ELF header's ``e_type``; ``script`` for a
``#!`` first line; ``empty``; ``text`` when the first 8 KiB hold no NUL and read as UTF-8; else
``binary``; ``special`` for a non-regular file and ``unreadable`` when it cannot be opened.

Symbolic links are not rows here: ``fs_symlinks`` records them. Directories are not rows.
WIPE-AND-REBUILD on every scan, like the symlink and non-binary inventories.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import stat
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from treasure_map.lib.analyze.elf_inventory import (
    ElfRecord,
    detect_arch,
    has_loadable_segments,
    sha256_file,
)
from treasure_map.lib.analyze.fs_names import db_text
from treasure_map.lib.analyze.non_binary.orchestrator import _MAX_BYTES

logger = logging.getLogger(__name__)

_ELF_MAGIC = b"\x7fELF"
_TEXT_SAMPLE = 8192
# e_type values of the ELF header (ELF spec), by the file_type they are recorded as.
_E_TYPES = {1: "elf_rel", 2: "elf_exec", 3: "elf_dyn", 4: "elf_core"}
_ET_REL = 1


@dataclass
class FileInventoryStats:
    files: int = 0
    inventoried: int = 0
    by_reason: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class _Row:
    path: str
    sha256: str | None
    size: int | None
    file_type: str
    inventoried_as: str | None
    not_inventoried_reason: str | None


def _elf_e_type(head: bytes) -> int | None:
    """The ELF header's e_type (2 bytes at offset 16, in the byte order EI_DATA names), or None
    when the header is too short or names no byte order."""
    if len(head) < 18 or head[5] not in (1, 2):
        return None
    return int.from_bytes(head[16:18], "little" if head[5] == 1 else "big")


def file_type_of(head: bytes, size: int) -> str:
    """The file type read from a file's first bytes (see the module docstring)."""
    if head[:4] == _ELF_MAGIC:
        e_type = _elf_e_type(head)
        return _E_TYPES.get(e_type, "elf_other") if e_type is not None else "elf_other"
    if size == 0:
        return "empty"
    if head[:2] == b"#!":
        return "script"
    sample = head[:_TEXT_SAMPLE]
    if b"\x00" in sample:
        return "binary"
    try:
        sample.decode("utf-8")
    except UnicodeDecodeError as exc:
        # A sample cut through a multi-byte character fails only at its very end.
        if not (len(sample) == _TEXT_SAMPLE and exc.start >= len(sample) - 3):
            return "binary"
    return "text"


def _elf_reason(path: Path, head: bytes, sha: str, elf_shas: set[str]) -> str:
    """Why ``scan_filesystem`` left out an ELF file: its tests, in its order."""
    arch = detect_arch(path)
    if not arch:
        return "elf_unreadable"
    if arch.startswith("UNKNOWN_"):
        return "unsupported_arch"
    if not has_loadable_segments(path):
        return "et_rel" if _elf_e_type(head) == _ET_REL else "no_loadable_segments"
    if sha in elf_shas:
        return "duplicate_content"
    # Every test passed now; the walk must have failed to read it then.
    return "unreadable"


def _walk(fs_root: Path) -> Iterable[tuple[Path, os.stat_result]]:
    """Every non-directory, non-symlink entry under ``fs_root``, in path order. Symlinked
    directories are not entered (the ELF and non-binary walks do not enter them either)."""
    for dirpath, dirnames, filenames in os.walk(fs_root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            p = Path(dirpath) / name
            try:
                st = p.lstat()
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                continue  # recorded in fs_symlinks
            yield p, st


def build_file_inventory(
    conn: sqlite3.Connection,
    fs_root: Path,
    elf_records: Iterable[ElfRecord],
    *,
    ingest_failed: Iterable[str] = (),
) -> FileInventoryStats:
    """Wipe and rebuild ``file_inventory`` for ``fs_root``. Run AFTER the ELF walk (its records are
    ``elf_records``) and the non-binary ingesters (their rows are read from ``non_binary_files``;
    ``ingest_failed`` is the relative paths an ingester claimed and failed on). Commits."""
    elf_by_path: dict[str, ElfRecord] = {}
    for rec in elf_records:
        try:
            elf_by_path[str(Path(rec.path).relative_to(fs_root))] = rec
        except ValueError:
            continue
    elf_shas = {rec.sha256 for rec in elf_by_path.values()}
    non_binary = {
        str(path): (str(kind), sha)
        for path, kind, sha in conn.execute("SELECT path, kind, sha256 FROM non_binary_files")
    }
    failed = {db_text(p) for p in ingest_failed}

    rows: list[_Row] = []
    for path, st in _walk(fs_root):
        rel = str(path.relative_to(fs_root))
        rel_db = db_text(rel)
        if not stat.S_ISREG(st.st_mode):
            rows.append(_Row(rel_db, None, None, "special", None, "not_regular_file"))
            continue
        size = st.st_size
        try:
            with path.open("rb") as fh:
                head = fh.read(_TEXT_SAMPLE)
        except OSError:
            rows.append(_Row(rel_db, None, size, "unreadable", None, "unreadable"))
            continue
        ftype = file_type_of(head, size)
        taken = elf_by_path.get(rel)
        if taken is not None:
            rows.append(_Row(rel_db, taken.sha256, size, ftype, "elf", None))
            continue
        nb = non_binary.get(rel_db)
        if nb is not None:
            rows.append(_Row(rel_db, nb[1], size, ftype, f"non_binary:{nb[0]}", None))
            continue
        try:
            sha: str | None = sha256_file(path)
        except OSError:
            rows.append(_Row(rel_db, None, size, ftype, None, "unreadable"))
            continue
        if head[:4] == _ELF_MAGIC:
            reason = _elf_reason(path, head, sha or "", elf_shas)
        elif size > _MAX_BYTES:
            reason = "too_large"
        elif rel_db in failed:
            reason = "ingest_failed"
        else:
            reason = "no_ingester"
        rows.append(_Row(rel_db, sha, size, ftype, None, reason))

    conn.execute("DELETE FROM file_inventory")
    conn.executemany(
        "INSERT INTO file_inventory (path, sha256, size, file_type, inventoried_as, "
        "not_inventoried_reason) VALUES (?, ?, ?, ?, ?, ?)",
        [
            (r.path, r.sha256, r.size, r.file_type, r.inventoried_as, r.not_inventoried_reason)
            for r in rows
        ],
    )
    conn.commit()

    stats = FileInventoryStats(files=len(rows))
    for r in rows:
        if r.inventoried_as is not None:
            stats.inventoried += 1
        else:
            reason = r.not_inventoried_reason or ""
            stats.by_reason[reason] = stats.by_reason.get(reason, 0) + 1
    logger.info(
        "file_inventory: %d files, %d inventoried, not inventoried: %s",
        stats.files,
        stats.inventoried,
        stats.by_reason,
    )
    return stats
