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
from dataclasses import dataclass

from treasure_map.lib.atlas.models import RunRow
from treasure_map.version import UNKNOWN_VERSION

_RUN_COLUMNS = (
    "run_id",
    "analysis_db_path",
    "firmware_path",
    "firmware_sha256",
    "build_hash",
    "hunt_commit",
    "hunt_instances",
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
        hunt_commit=row["hunt_commit"],
        hunt_instances=row["hunt_instances"],
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


@dataclass(frozen=True)
class Staleness:
    """Whether a run's stored result was PROVABLY produced by different code than is running now.

    ★ The bar is a positive mismatch — two real values that differ — never a failure to confirm a
    match. That is the opposite bar from the hunt-skip decision, and deliberately so: skipping work
    on an unconfirmed match risks serving a stale answer as fresh, while refusing to answer on an
    unconfirmed match makes every pre-stamp run unreadable and every editable install permanently
    mute. So a missing stamp, an unreadable hash, and an install with no recorded commit all read
    as "cannot tell", which this layer reports as a caveat and never as a refusal.

    ``axis`` names WHICH input changed: 'extraction' (the facts in the analysis.db would be
    re-derived differently) or 'hunt' (the same facts would be graded differently). ``remedy`` is
    the concrete command, which depends on whether the run recorded a firmware root to re-read.
    """

    stale: bool
    axis: str | None
    detail: str
    remedy: str


def _remedy_for(run: RunRow) -> str:
    """The concrete next command for a run that cannot be answered from as it stands.

    Never a bare "this is stale": a reader who is told what is wrong and not what to do about it
    has been given a dead end."""
    if run.firmware_path:
        return f"`tmap rescan {run.run_id}` re-reads {run.firmware_path} and refreshes this run."
    # No firmware root to re-read. Re-scanning is the fix, but it needs the firmware back, which
    # may take a while — and meanwhile what this run already extracted is still on disk and still
    # readable. Naming that route matters because the alternative reads as "nothing you can do":
    # the analysis.db is a different tool surface (the CLI annotates the extraction mismatch and
    # prints the fact, where the run-routed path declines), not a way around the same check.
    # Offered only when there IS a recorded analysis.db — otherwise the command has no argument.
    if run.analysis_db_path:
        return (
            f"this run recorded no firmware root, so it cannot be re-read automatically. What it "
            f"already extracted is still readable directly: "
            f"`tmap fact <subcommand> --analysis-db {run.analysis_db_path}` prints the facts with "
            f"an extraction-mismatch note attached. To refresh the run itself, "
            f"`tmap scan <firmware-root> --run-id {run.run_id}` once you have the firmware."
        )
    return (
        f"this run recorded no firmware root, so it cannot be re-read automatically — "
        f"`tmap scan <firmware-root> --run-id {run.run_id}` once you have the extracted firmware."
    )


def run_staleness(run: RunRow, *, build_hash: str | None, commit: str) -> Staleness:
    """Compare a run's stored lineage against the code running now.

    ``build_hash`` is the extraction pipeline's current content hash and ``commit`` the running
    install's commit; either may be unknown, which yields a not-stale result with a stated reason.
    """
    stored_build = run.build_hash
    if (
        stored_build
        and build_hash
        # 'mixed:N' is a count, not a hash: the run's binaries were extracted by more than one
        # pipeline version. It cannot be compared, so it is reported as unconfirmable rather than
        # decided either way.
        and not stored_build.startswith("mixed:")
        and stored_build != build_hash
    ):
        return Staleness(
            True,
            "extraction",
            f"extracted by pipeline {stored_build}, running {build_hash} — the facts stored for "
            "this run would be re-derived differently by the code answering you now.",
            _remedy_for(run),
        )
    if (
        run.hunt_commit
        and run.hunt_commit != UNKNOWN_VERSION
        and commit != UNKNOWN_VERSION
        and run.hunt_commit != commit
    ):
        return Staleness(
            True,
            "hunt",
            f"hunted by tmap {run.hunt_commit[:12]}, running {commit[:12]} — the candidates stored "
            "for this run were graded by different code than is answering you now.",
            _remedy_for(run),
        )
    # Not provably stale. Say which comparisons could not be made, so "not stale" is never read as
    # "confirmed current" when in fact nothing was comparable.
    unknowns = []
    if not stored_build or not build_hash or (stored_build or "").startswith("mixed:"):
        unknowns.append("extraction hash")
    if not run.hunt_commit or run.hunt_commit == UNKNOWN_VERSION or commit == UNKNOWN_VERSION:
        unknowns.append("hunt commit")
    if unknowns:
        return Staleness(
            False,
            None,
            f"could not compare {' or '.join(unknowns)} for this run — not shown to be stale, "
            "which is not the same as shown to be current.",
            _remedy_for(run),
        )
    return Staleness(
        False, None, "extraction hash and hunt commit both match the running tmap.", ""
    )
