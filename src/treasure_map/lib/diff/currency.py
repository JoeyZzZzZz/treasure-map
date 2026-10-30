# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Does a recorded diff still match what it was computed from?

A diff reads more than the two binaries' bytes. Per side it reads the functions the extraction pass
produced for the binary, and the hunt's output for it: the candidate call sites the instruction
pairs are chosen by, the binary's string-keyed edges, the run's analysis capabilities and the
run-row versions the version-skew check compares. And it is computed by the diff code itself. The
content hash (``sha256_a``/``sha256_b``) covers only the bytes, so a re-extraction, a re-hunt with
different output, or a change to the diff code would leave a stored diff reading as current.

Each of those inputs is recorded with the diff as a STAMP and later compared, by plain equality,
with what the same input is now:

  * extraction — the diffed binary's own ``binaries.pass_version`` and ``binaries.ghidra_version``,
    looked up by its sha256 in the run's analysis.db. The binary's own values, not the run's
    roll-up: a run's ``build_hash`` becomes a ``mixed:N`` count when an UNRELATED binary fails a
    re-extraction, which says nothing about this one.
  * hunt inputs — a digest of exactly the hunt output the diff reads (``hunt_inputs_digest``), so
    a re-hunt that reproduces the same output leaves the diff current.
  * diff code — ``diff_code_version()``, a hash of the Python code that writes the diff
    (lib/diff/code_version), and per side ``export_code_hash``, the hash of the export scripts
    that made that side's archived export (its ``binexport_scan_meta``; lib/export_stamp).
  * the external toolchain — the Ghidra and BinExport the two sides' scans exported with (from
    their archives' metadata; a diff runs neither) and the BinDiff installed now
    (lib/diff/toolchain).
    Compared only when they can be read; a machine that cannot read them does not reset or force
    anything on their account.

Equality is plain equality: None equals None. A binary that has never been extracted has no pass
on either occasion, and that is the same answer twice, not an unknown.

BOUNDARY: third-party Python libraries and the interpreter are not recorded (the diff modules use
only the standard library and sqlite). ``ghidra_version`` is the version the scan recorded for the
binary; the Ghidra the diff ran is the toolchain stamp.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from treasure_map.lib.binexport_archive import USABLE_STATUSES, StoredExport
from treasure_map.lib.diff.toolchain import Toolchain
from treasure_map.lib.ro_db import ro_connect

# The diff_meta columns a re-diff decision compares (scanned_at / hunt_instances are not among
# them: they only let a reader skip recomputing the hunt-input digest, see the read side).
COMPARED_COLUMNS = (
    "extraction_pass_a",
    "extraction_pass_b",
    "ghidra_version_a",
    "ghidra_version_b",
    "hunt_inputs_hash_a",
    "hunt_inputs_hash_b",
    "diff_code_version",
    "export_code_hash_a",
    "export_code_hash_b",
    "toolchain_ghidra",
    "toolchain_binexport",
    "toolchain_bindiff",
)
TOOLCHAIN_COLUMNS = ("toolchain_ghidra", "toolchain_binexport", "toolchain_bindiff")


@dataclass(frozen=True)
class SideStamp:
    """What one side of a diff was computed from."""

    extraction_pass: str | None
    ghidra_version: str | None
    hunt_inputs_hash: str | None
    scanned_at: str | None
    hunt_instances: int | None
    export_code_hash: str | None = None


@dataclass(frozen=True)
class DiffStamps:
    a: SideStamp
    b: SideStamp
    diff_code_version: str | None
    toolchain: Toolchain | None = None

    def compared(self) -> dict[str, object]:
        """The compared stamps keyed by their diff_meta column (see COMPARED_COLUMNS)."""
        return {
            "extraction_pass_a": self.a.extraction_pass,
            "extraction_pass_b": self.b.extraction_pass,
            "ghidra_version_a": self.a.ghidra_version,
            "ghidra_version_b": self.b.ghidra_version,
            "hunt_inputs_hash_a": self.a.hunt_inputs_hash,
            "hunt_inputs_hash_b": self.b.hunt_inputs_hash,
            "diff_code_version": self.diff_code_version,
            "export_code_hash_a": self.a.export_code_hash,
            "export_code_hash_b": self.b.export_code_hash,
            **toolchain_columns(self.toolchain),
        }


def toolchain_columns(toolchain: Toolchain | None) -> dict[str, str | None]:
    """The diff_meta toolchain columns for ``toolchain`` (all None when it was not read)."""
    return {
        "toolchain_ghidra": toolchain.ghidra if toolchain else None,
        "toolchain_binexport": toolchain.binexport if toolchain else None,
        "toolchain_bindiff": toolchain.bindiff if toolchain else None,
    }


UNSTAMPED = DiffStamps(
    SideStamp(None, None, None, None, None), SideStamp(None, None, None, None, None), None
)


def stamps_equal(stored: Mapping[str, object], current: Mapping[str, object]) -> bool:
    """Plain equality of every compared stamp (None == None)."""
    return all(stored.get(c) == current.get(c) for c in COMPARED_COLUMNS)


def read_extraction(
    analysis_db_path: str | None,
) -> dict[str, tuple[str | None, str | None]] | None:
    """``{sha256 -> (pass_version, ghidra_version)}`` over every binary row of an analysis.db, or
    None when the database cannot be read (a can't-tell, never an empty answer)."""
    if not analysis_db_path or not Path(analysis_db_path).exists():
        return None
    try:
        conn = ro_connect(analysis_db_path)
    except sqlite3.Error:
        return None
    try:
        return {
            sha: (pv, gv)
            for sha, pv, gv in conn.execute(
                "SELECT sha256, pass_version, ghidra_version FROM binaries WHERE sha256 IS NOT NULL"
            )
        }
    except sqlite3.Error:
        return None
    finally:
        conn.close()


def extraction_stamp(
    analysis_db_path: str | None, sha: str | None
) -> tuple[str | None, str | None]:
    """``(pass_version, ghidra_version)`` of the binary with this sha256, or (None, None) when there
    is no such row or the database cannot be read."""
    if not sha or not analysis_db_path or not Path(analysis_db_path).exists():
        return None, None
    try:
        conn = ro_connect(analysis_db_path)
    except sqlite3.Error:
        return None, None
    try:
        row = conn.execute(
            "SELECT pass_version, ghidra_version FROM binaries WHERE sha256 = ?", (sha,)
        ).fetchone()
    except sqlite3.Error:
        return None, None
    finally:
        conn.close()
    return (row[0], row[1]) if row is not None else (None, None)


def _canonical_rows(cursor: sqlite3.Cursor) -> list[str]:
    """Each row as a JSON array, sorted: a NULL column cannot be ordered against a string, but its
    JSON text can, and two equal row sets always serialize to one list."""
    return sorted(json.dumps(list(r), separators=(",", ":")) for r in cursor)


def hunt_inputs_digest(
    atlas: sqlite3.Connection, run_id: str, sha: str | None, binary: str | None
) -> str:
    """A digest of the hunt output one side of a diff reads, and nothing else.

    The parts are the ones the diff actually consumes: the candidate call-site addresses its
    instruction pairs are selected by (``layer0._candidate_callsite_addrs``, by sha256), the
    binary's string_keyed_edge rows in the columns the edge delta loads (``layer2._EDGE_COLS``, by
    short name), every run_capability row of the run (present / declared absent / no row are three
    different inputs), and the run row's tool and decompiler versions the version-skew check
    compares. A column the diff never reads (a candidate's reachability, say) is deliberately left
    out, so changing it does not make a diff stale."""
    # imported here: layer0 imports this module, and layer2 imports layer0, so importing either
    # at module level would be circular
    from treasure_map.lib.diff.layer0 import _candidate_callsite_addrs
    from treasure_map.lib.diff.layer2 import _EDGE_COLS

    addrs = sorted(_candidate_callsite_addrs(atlas, run_id, sha)) if sha else []
    edges = _canonical_rows(
        atlas.execute(
            f"SELECT {_EDGE_COLS} FROM string_keyed_edge "  # noqa: S608 -- literal column list
            "WHERE source_run_id = ? AND binary = ?",
            (run_id, binary),
        )
    )
    caps = _canonical_rows(
        atlas.execute("SELECT capability, present FROM run_capability WHERE run_id = ?", (run_id,))
    )
    versions = atlas.execute(
        "SELECT tool_version, ghidra_version FROM run WHERE run_id = ?", (run_id,)
    ).fetchone()
    parts = {
        "callsite_addrs": addrs,
        "edges": edges,
        "capabilities": caps,
        "run_versions": list(versions) if versions is not None else None,
    }
    blob = json.dumps(parts, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def run_hunt_marks(atlas: sqlite3.Connection, run_id: str) -> tuple[str | None, int | None] | None:
    """``(scanned_at, hunt_instances)`` of a run row, or None when the atlas has no such run."""
    row = atlas.execute(
        "SELECT scanned_at, hunt_instances FROM run WHERE run_id = ?", (run_id,)
    ).fetchone()
    if row is None:
        return None
    return row[0], row[1]


def side_stamp(
    atlas: sqlite3.Connection,
    run_id: str,
    analysis_db_path: str | None,
    sha: str | None,
    binary: str | None,
    export: StoredExport | None = None,
) -> SideStamp:
    """The current stamps of one side; ``export`` is that side's archived export (None, or not
    usable, when there is none), whose metadata names the export scripts that made it."""
    pv, gv = extraction_stamp(analysis_db_path, sha)
    marks = run_hunt_marks(atlas, run_id) or (None, None)
    script_hash = (
        (export.meta or {}).get("script_hash")
        if export is not None and export.status in USABLE_STATUSES
        else None
    )
    return SideStamp(
        extraction_pass=pv,
        ghidra_version=gv,
        hunt_inputs_hash=hunt_inputs_digest(atlas, run_id, sha, binary),
        scanned_at=marks[0],
        hunt_instances=marks[1],
        export_code_hash=script_hash if isinstance(script_hash, str) else None,
    )


def _join_sides(a: object, b: object) -> str | None:
    """One value for a toolchain column from the two sides' exports: the value when they agree,
    ``a|b`` when they do not, None when either is unknown."""
    if not isinstance(a, str) or not isinstance(b, str):
        return None
    return a if a == b else f"{a}|{b}"


def diff_toolchain(
    export_a: StoredExport | None, export_b: StoredExport | None, bindiff: str | None
) -> Toolchain | None:
    """The toolchain one diff is computed by: the Ghidra and BinExport the two sides' scans
    exported with (from their archives' metadata — a diff runs neither), and the BinDiff installed
    now. None — not checked — when the BinDiff version or either side's cannot be read."""
    meta_a = (export_a.meta if export_a else None) or {}
    meta_b = (export_b.meta if export_b else None) or {}
    ghidra = _join_sides(meta_a.get("ghidra_version"), meta_b.get("ghidra_version"))
    binexport = _join_sides(meta_a.get("binexport"), meta_b.get("binexport"))
    if bindiff is None or ghidra is None or binexport is None:
        return None
    return Toolchain(ghidra=ghidra, binexport=binexport, bindiff=bindiff)
