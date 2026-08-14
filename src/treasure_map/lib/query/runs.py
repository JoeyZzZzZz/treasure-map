# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Run-lineage reads over the atlas: resolve a run_id to its analysis.db, and enumerate runs.

``get_run`` is the RESOLVER a run-aware fact tool routes on (run_id -> analysis.db path).
``list_runs`` is the enumerator behind the list_runs tool / ``tmap runs``. Both UNION the
authoritative ``run`` table with the runs seen only via ``instance.source_run_id`` (a pre-existing
scan that predates the run table): such a run stays VISIBLE but is honestly marked
``resolved=False`` (no lineage row, no resolvable analysis.db) so it is never hidden and never looks
complete. Read-only; no verdict.
"""

from __future__ import annotations

import sqlite3

from treasure_map.lib.atlas.models import RunRow

_RUN_COLUMNS = (
    "run_id",
    "analysis_db_path",
    "firmware_path",
    "firmware_sha256",
    "build_hash",
    "tool_version",
    "ghidra_version",
    "machine",
    "binaries",
    "functions",
    "functions_empty",
    "scan_status",
    "scanned_at",
    "updated_at",
)


def _row_to_runrow(row: sqlite3.Row) -> RunRow:
    return RunRow(
        run_id=row["run_id"],
        analysis_db_path=row["analysis_db_path"],
        firmware_path=row["firmware_path"],
        firmware_sha256=row["firmware_sha256"],
        build_hash=row["build_hash"],
        tool_version=row["tool_version"],
        ghidra_version=row["ghidra_version"],
        machine=row["machine"],
        binaries=row["binaries"],
        functions=row["functions"],
        functions_empty=row["functions_empty"],
        scan_status=row["scan_status"],
        scanned_at=row["scanned_at"],
        updated_at=row["updated_at"],
        resolved=True,
    )


def get_run(conn: sqlite3.Connection, run_id: str) -> RunRow | None:
    """Resolve one run_id to its lineage row, or None when the run is absent from this atlas.

    A run with a real ``run`` row resolves with ``resolved=True`` and its analysis_db_path. A run
    seen ONLY via instance.source_run_id (a pre-existing scan, no lineage row) resolves with
    ``resolved=False`` and no analysis_db_path — present but unresolved (re-scan to record lineage),
    so a fact tool can distinguish "run not in this atlas" (None) from "run exists but its
    analysis.db was never recorded" (a row with analysis_db_path=None)."""
    row = conn.execute(
        f"SELECT {', '.join(_RUN_COLUMNS)} FROM run WHERE run_id = ?", (run_id,)
    ).fetchone()
    if row is not None:
        return _row_to_runrow(row)
    seen = conn.execute(
        "SELECT 1 FROM instance WHERE source_run_id = ? LIMIT 1", (run_id,)
    ).fetchone()
    if seen is not None:
        # A pre-existing scan: has candidates but no lineage row. Visible, honestly unresolved.
        return RunRow(run_id=run_id, scan_status="unknown", resolved=False)
    return None


def runs_where_function_exists(
    conn: sqlite3.Connection, *, binary: str | None, function: str
) -> list[str]:
    """The run_ids whose atlas instances place ``function`` (optionally in ``binary``).

    A cheap index query over the instance table (source_run_id + binary_path + sink/source anchors),
    NOT an analysis.db open. Lets a run-aware fact tool tell "wrong run — this function lives in run
    Y" apart from "no such function anywhere" without decompiling. Best-effort: it matches the
    function against the recorded anchors/paths, so a miss here is not proof of absence."""
    like_bin = f"%{binary}%" if binary else "%"
    rows = conn.execute(
        """SELECT DISTINCT source_run_id FROM instance
           WHERE source_run_id IS NOT NULL
             AND (sink_anchor = :fn OR source_anchor = :fn
                  OR evidence_ref LIKE '%' || :fn OR binary_path LIKE '%' || :fn || '%')
             AND (:likebin = '%' OR binary_path LIKE :likebin)
           ORDER BY source_run_id""",
        {"fn": function, "likebin": like_bin},
    ).fetchall()
    return [r[0] for r in rows]


def list_runs(conn: sqlite3.Connection) -> list[RunRow]:
    """Enumerate every run in this atlas, newest scan first.

    UNION of the authoritative ``run`` table (resolved=True, full lineage) and the runs seen only
    via instance.source_run_id (resolved=False, scan_status='unknown', no analysis.db) — so a
    pre-existing scan is never hidden, yet is honestly flagged as having no recorded lineage.
    Resolved runs lead, ordered by ``scanned_at`` descending (SQLite's ISO-string timestamp sorts
    chronologically); the unresolved (instance-only) runs follow, ordered by run_id."""
    resolved: list[RunRow] = [
        _row_to_runrow(r)
        for r in conn.execute(
            f"SELECT {', '.join(_RUN_COLUMNS)} FROM run ORDER BY scanned_at DESC, run_id"
        ).fetchall()
    ]
    known = {r.run_id for r in resolved}
    unresolved: list[RunRow] = [
        RunRow(run_id=r[0], scan_status="unknown", resolved=False)
        for r in conn.execute(
            "SELECT DISTINCT source_run_id FROM instance "
            "WHERE source_run_id IS NOT NULL ORDER BY source_run_id"
        ).fetchall()
        if r[0] not in known
    ]
    return resolved + unresolved
