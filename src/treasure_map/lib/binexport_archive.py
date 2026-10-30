# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Where a scan keeps each binary's BinExport export, and how a diff gets it back.

A scan exports every binary it extracts, in the same Ghidra session (lib/analyze/ghidra_runner).
The export and its report are gzip-compressed into ``binexport/`` beside the workspace's
analysis.db, one pair per (sha256, pass_version):

    binexport/<sha256>_<pass_version>_<session>.BinExport.gz
    binexport/<sha256>_<pass_version>_<session>.export_report.json.gz

``<session>`` is new for every archive written, so an archive is never overwritten in place: the
row names its own files, the new files are written beside the old ones, and the old ones are removed
only after the row naming the new ones is committed (an interrupt in between leaves the row and its
own, intact files — never a row whose name now holds another session's export).

Never shared across workspaces by content: two sessions export one binary differently, and a diff
must compare two exports each made in the session that made its side's functions. Within one
workspace a sha256 is one binary row, so one pair is current per binary; any other pair of that
sha256 is removed once a new outcome is stored.

The binary row records the outcome (``binaries.binexport_status``: ok / degraded / failed:<why> /
scan_failed:<why> / extension_missing) and what the export was made by
(``binaries.binexport_scan_meta``, a JSON object). Only ok and degraded have an archive.

Files are written under a ``.tmp`` name and moved into place, so a crash never leaves a partial
archive under the final name; the row is written after the files. READ helpers never write.
Standard library only.
"""

from __future__ import annotations

import gzip
import json
import os
import shutil
import sqlite3
import uuid
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ARCHIVE_DIRNAME = "binexport"
EXPORT_SUFFIX = ".BinExport.gz"
REPORT_SUFFIX = ".export_report.json.gz"

# binexport_status values. failed:<why> and scan_failed:<why> carry a reason after the colon.
STATUS_OK = "ok"
STATUS_DEGRADED = "degraded"
STATUS_EXTENSION_MISSING = "extension_missing"
FAILED_PREFIX = "failed:"
SCAN_FAILED_PREFIX = "scan_failed:"
FAILED_TIMEOUT = "failed:timeout"
# The export was made but could not be archived (disk full, permissions): local, not the export's.
FAILED_ARCHIVE_ERROR = "failed:archive_error"
# The two statuses an export file stands behind.
USABLE_STATUSES = frozenset({STATUS_OK, STATUS_DEGRADED})


def archive_dir(analysis_db_path: str | Path) -> Path:
    """The archive directory of the workspace whose analysis.db is at ``analysis_db_path``."""
    return Path(analysis_db_path).parent / ARCHIVE_DIRNAME


def archive_names(sha256: str, pass_version: str, session: str = "") -> tuple[str, str]:
    """(export file name, report file name) of one binary's archive, written in ``session``."""
    stem = f"{sha256}_{pass_version}" + (f"_{session}" if session else "")
    return stem + EXPORT_SUFFIX, stem + REPORT_SUFFIX


def _gzip_into(src: Path, dest: Path) -> int:
    """Compress ``src`` to ``dest`` through ``dest.tmp`` and an atomic replace; the size of
    ``dest``."""
    tmp = dest.with_name(dest.name + ".tmp")
    try:
        with src.open("rb") as fin, gzip.open(tmp, "wb", compresslevel=6) as fout:
            shutil.copyfileobj(fin, fout, 1 << 20)
        os.replace(tmp, dest)
    finally:
        tmp.unlink(missing_ok=True)
    return dest.stat().st_size


@dataclass(frozen=True)
class Archived:
    export_name: str  # file name inside the archive directory
    report_name: str
    export_bytes: int  # the compressed export's size


def write_archive(
    export_file: Path, report_file: Path, dest_dir: Path, sha256: str, pass_version: str
) -> Archived:
    """Compress one binary's export and report into ``dest_dir``. Raises OSError when either cannot
    be written (the caller records the export as failed)."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    export_name, report_name = archive_names(sha256, pass_version, uuid.uuid4().hex[:12])
    _gzip_into(report_file, dest_dir / report_name)
    size = _gzip_into(export_file, dest_dir / export_name)
    return Archived(export_name, report_name, size)


def _readable(path: Path) -> bool:
    """Whether a gzip file is there and decompresses whole (its CRC and length check out)."""
    try:
        with gzip.open(path, "rb") as fh:
            while fh.read(1 << 20):
                pass
        return True
    except (OSError, EOFError, zlib.error):
        return False


def archive_files(dest_dir: Path, meta: dict[str, Any] | None) -> tuple[Path, Path] | None:
    """(export, report) paths a stored meta names, or None when it names none."""
    if not meta:
        return None
    export_name, report_name = meta.get("archive"), meta.get("report_archive")
    if not isinstance(export_name, str) or not isinstance(report_name, str):
        return None
    return dest_dir / export_name, dest_dir / report_name


def archive_intact(dest_dir: Path, meta: dict[str, Any] | None) -> bool:
    """Whether the archive a stored meta names is there and decompresses whole — the check that a
    recorded ok / degraded export still has the file it claims."""
    files = archive_files(dest_dir, meta)
    return files is not None and all(_readable(p) for p in files)


def extract_archive(
    dest_dir: Path, meta: dict[str, Any] | None, into: Path, side: str
) -> tuple[Path, Path]:
    """Decompress one archive into ``into`` as ``<side>.BinExport`` and its report beside it (the
    names lib/diff/export_report reads). Raises OSError when it cannot."""
    files = archive_files(dest_dir, meta)
    if files is None:
        raise OSError("no archive is recorded for this binary")
    export_out = into / f"{side}.BinExport"
    report_out = into / f"{side}.export_report.json"
    for src, dest in zip(files, (export_out, report_out), strict=True):
        try:
            with gzip.open(src, "rb") as fin, dest.open("wb") as fout:
                shutil.copyfileobj(fin, fout, 1 << 20)
        except (EOFError, zlib.error) as exc:
            raise OSError(f"{src.name}: {exc}") from exc
    return export_out, report_out


def remove_other_archives(dest_dir: Path, sha256: str, keep: tuple[str, ...] = ()) -> int:
    """Delete every archive file of ``sha256`` except those named in ``keep``; how many went."""
    if not dest_dir.is_dir():
        return 0
    gone = 0
    for path in dest_dir.glob(f"{sha256}_*"):
        if path.name in keep:
            continue
        try:
            path.unlink()
            gone += 1
        except OSError:
            pass
    return gone


def parse_meta(raw: str | None) -> dict[str, Any] | None:
    """A stored ``binexport_scan_meta``, or None when there is none or it is not a JSON object."""
    if not raw:
        return None
    try:
        value = json.loads(raw)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


@dataclass(frozen=True)
class StoredExport:
    """One binary's recorded export outcome, read from its analysis.db."""

    status: str | None  # None: the row predates exports (needs a re-scan)
    meta: dict[str, Any] | None
    dest_dir: Path


def read_stored_export(analysis_db_path: str | None, sha256: str | None) -> StoredExport | None:
    """The export outcome recorded for the binary with this sha256, or None when the database or
    the row cannot be read (a can't-tell, never "no export")."""
    if not analysis_db_path or not sha256 or not Path(analysis_db_path).exists():
        return None
    uri = f"file:{Path(analysis_db_path).resolve()}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error:
        return None
    try:
        row = conn.execute(
            "SELECT binexport_status, binexport_scan_meta FROM binaries WHERE sha256 = ?",
            (sha256,),
        ).fetchone()
    except sqlite3.Error:
        return None
    finally:
        conn.close()
    if row is None:
        return None
    return StoredExport(row[0], parse_meta(row[1]), archive_dir(analysis_db_path))


def read_all_stored_exports(analysis_db_path: str | None) -> dict[str, StoredExport] | None:
    """sha256 -> recorded export outcome, for every binary row of one analysis.db (one read for a
    whole run), or None when the database cannot be read."""
    if not analysis_db_path or not Path(analysis_db_path).exists():
        return None
    uri = f"file:{Path(analysis_db_path).resolve()}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error:
        return None
    dest = archive_dir(analysis_db_path)
    try:
        return {
            sha: StoredExport(status, parse_meta(meta), dest)
            for sha, status, meta in conn.execute(
                "SELECT sha256, binexport_status, binexport_scan_meta FROM binaries "
                "WHERE sha256 IS NOT NULL"
            )
        }
    except sqlite3.Error:
        return None
    finally:
        conn.close()


def uncompressed_size(path: Path) -> int:
    """A gzip file's decompressed size from its trailer (modulo 4 GiB, as gzip records it); 0 when
    it cannot be read."""
    try:
        with path.open("rb") as fh:
            fh.seek(-4, os.SEEK_END)
            return int.from_bytes(fh.read(4), "little")
    except OSError:
        return 0


def _files_present(dest_dir: Path, meta: dict[str, Any] | None) -> bool:
    files = archive_files(dest_dir, meta)
    return files is not None and all(f.is_file() for f in files)


def stale_exports(
    analysis_db_path: str | None, export_hash: str | None, shas: set[str] | None = None
) -> tuple[int, int] | None:
    """(how many, of how many) EXTRACTED binaries (ghidra_ok=1) of the firmware's CURRENT inventory
    (``current_binaries``: a row the last scan did not see is no longer the firmware's) that a scan
    with ``export_hash`` would re-scan for their export — none recorded, an archive that could not
    be written or whose files are gone, the extension now available where it was missing, or an
    export (or a failed attempt at one) made with another export hash; ``shas`` limits it to those
    binaries. A binary whose extraction failed is not counted: whether it is re-run is its
    extraction's question. None when the database cannot be read. ``export_hash`` None (no
    extension here): only what a scan without it would redo counts (no export recorded, a usable
    status whose archive is gone)."""
    if not analysis_db_path or not Path(analysis_db_path).exists():
        return None
    uri = f"file:{Path(analysis_db_path).resolve()}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error:
        return None
    try:
        rows = [
            (sha, status, parse_meta(meta))
            for sha, status, meta in conn.execute(
                "SELECT sha256, binexport_status, binexport_scan_meta FROM current_binaries "
                "WHERE sha256 IS NOT NULL AND ghidra_ok = 1"
            )
            if shas is None or sha in shas
        ]
    except sqlite3.Error:
        return None
    finally:
        conn.close()
    dest = archive_dir(analysis_db_path)
    stale = 0
    for _sha, status, meta in rows:
        if status is None:
            stale += 1
        elif status in USABLE_STATUSES and not _files_present(dest, meta):
            stale += 1  # the status no longer has its files (a scan re-makes it, extension or not)
        elif export_hash is None:
            continue
        elif status == FAILED_ARCHIVE_ERROR:
            stale += 1
        elif status == STATUS_EXTENSION_MISSING:
            stale += 1
        elif (status in USABLE_STATUSES or status.startswith(FAILED_PREFIX)) and (
            (meta or {}).get("export_hash") != export_hash
        ):
            stale += 1
    return stale, len(rows)
