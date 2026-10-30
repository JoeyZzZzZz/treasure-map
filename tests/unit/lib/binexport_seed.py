# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Test helper: give the binaries of a test analysis.db the archived export a scan would have
written with them (lib/binexport_archive), so a diff's preflight finds it.

The archive files hold placeholder bytes: tests that run a diff stub the step that reads them
(``driver._obtain_export``) or BinDiff itself.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from treasure_map.lib.binexport_archive import archive_dir, archive_names

SCRIPT_HASH = "0123456789abcdef"
BINEXPORT = "11.4.3+lib:000000000000"
EXPORT_HASH = "test-export-hash"


def export_meta(
    sha256: str,
    pass_version: str,
    *,
    script_hash: str = SCRIPT_HASH,
    binexport: str = BINEXPORT,
    ghidra_version: str = "11.4.3",
    export_hash: str = EXPORT_HASH,
) -> dict[str, Any]:
    """The binexport_scan_meta of an ok export of one binary. A test sha longer than a real one is
    hashed for the file names (they must fit a path), and the binary's own sha rides along under
    ``sha256`` (a test-only key) for a stub to tell the binaries apart."""
    name_sha = sha256 if len(sha256) <= 64 else hashlib.sha256(sha256.encode()).hexdigest()
    export_name, report_name = archive_names(name_sha, pass_version)
    return {
        "sha256": sha256,
        "export_hash": export_hash,
        "script_hash": script_hash,
        "binexport": binexport,
        "builder": "fallback",
        "pass_version": pass_version,
        "ghidra_version": ghidra_version,
        "budget_seconds": 300,
        "archive": export_name,
        "report_archive": report_name,
        "archive_bytes": 0,
    }


def archive_exports(db_path: Path | str, **meta_kw: Any) -> None:
    """Record an ok export, with its archive on disk, for every binary row of ``db_path`` that has a
    sha256 (rows with no pass_version get one named 'pv')."""
    dest = archive_dir(db_path)
    dest.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db_path)
    try:
        rows = con.execute(
            "SELECT id, sha256, COALESCE(pass_version, 'pv') FROM binaries WHERE sha256 IS NOT NULL"
        ).fetchall()
        for row_id, sha, pv in rows:
            meta = export_meta(sha, pv, **meta_kw)
            report = {
                "builder": "fallback",
                "mode": "scan",
                "entry_addresses_added": 0,
                "flow_graphs_dropped": 0,
                "dropped_functions": [],
                "degenerate_functions": [],
            }
            with gzip.open(dest / meta["archive"], "wb") as fh:
                fh.write(b"\x00placeholder export\x00")
            with gzip.open(dest / meta["report_archive"], "wb") as fh:
                fh.write(json.dumps(report).encode())
            con.execute(
                "UPDATE binaries SET binexport_status = 'ok', binexport_scan_meta = ? WHERE id = ?",
                (json.dumps(meta, sort_keys=True), row_id),
            )
        con.commit()
    finally:
        con.close()


def stored_export(dest_dir: Path, binary: str, side: str) -> Any:
    """A recorded ok export of ``binary`` on one side, its archive files on disk under
    ``dest_dir`` — what a diff's preflight hands the compute step. Its meta carries the test-only
    ``name`` (``<binary>_<side>.so``) a stub can tell the binaries apart by."""
    from treasure_map.lib.binexport_archive import StoredExport

    dest_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{binary}_{side}"
    for name in (f"{stem}.BinExport.gz", f"{stem}.export_report.json.gz"):
        with gzip.open(dest_dir / name, "wb") as fh:
            fh.write(b"\x00placeholder\x00")
    meta = {
        **export_meta("0" * 64, "pv"),
        "archive": f"{stem}.BinExport.gz",
        "report_archive": f"{stem}.export_report.json.gz",
        "name": f"{stem}.so",
    }
    return StoredExport("ok", meta, dest_dir)
