# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Plan and execute `tmap runs --delete`: remove a run, a run pair's diffs, or one binary diff from
the atlas, atomically.

Two phases so the command is all-or-nothing. ``plan_delete`` resolves and validates every id, works
out the diffs and annotations each removal touches, writes NOTHING, and takes the scan lock of any
workspace a delete reaches (so a running scan or hunt is never deleted out from under). Any failure
raises before a row is touched. ``execute_delete`` then runs every delete in ONE transaction.

Files are never removed: a deleted run's workspace is reported, not touched. Human annotations
(overlay / overlay_history) are kept — they re-attach if the same run id is scanned or the same pair
is diffed again — so the plan only COUNTS them."""

from __future__ import annotations

import fcntl
import os
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO

from treasure_map.lib.atlas.models import RunRow
from treasure_map.lib.atlas.writer import delete_diff, delete_run, delete_run_pair_diffs
from treasure_map.lib.errors import TreasureMapError
from treasure_map.lib.query.diff_align import pair_diffs, reverse_direction_diffs
from treasure_map.lib.query.runs import get_run, list_runs
from treasure_map.lib.workspace.workspace import Workspace, workspace_of

_PER_RUN_KINDS = (
    "instances",
    "nvram_flow",
    "string_keyed_edges",
    "exec_edges",
    "detector_status",
    "capabilities",
    "nvram_defaults",
    "web_form_fields",
)


@dataclass(frozen=True)
class WorkspaceReport:
    """What a deleted run's files are, which are KEPT. ``path`` is the workspace directory, or the
    analysis.db path when that database is not inside a tmap workspace, or None when the run
    recorded no analysis.db. ``size_bytes`` is the workspace's on-disk size (files only, symlinks
    not followed), None on error or when there is no workspace. ``also_recorded_by`` names the
    other runs in this atlas whose analysis.db sits in the same directory (so deleting the run's
    row does not orphan a directory another run still points at)."""

    run_id: str
    path: Path | None
    size_bytes: int | None
    also_recorded_by: list[str]


@dataclass(frozen=True)
class DeletePlan:
    """A validated, not-yet-applied delete: the runs, run pairs and single diffs to remove, the
    deduped diff ids they add up to, the annotation count kept, one WorkspaceReport per run, and the
    scan locks held over the touched workspaces (released by ``release``)."""

    runs: list[str]
    pairs: list[tuple[str, str]]
    diff_ids: list[str]
    annotations_kept: int
    workspaces: list[WorkspaceReport]
    locks: tuple[IO[str], ...] = field(default=(), repr=False, compare=False)

    def release(self) -> None:
        """Unlock and close every scan lock the plan holds. Safe to call more than once."""
        for handle in self.locks:
            try:
                fcntl.flock(handle, fcntl.LOCK_UN)
            except (OSError, ValueError):
                pass
            try:
                handle.close()
            except (OSError, ValueError):
                pass


def _diff_exists(conn: sqlite3.Connection, diff_id: str) -> bool:
    return (
        conn.execute("SELECT 1 FROM diff_meta WHERE diff_id = ? LIMIT 1", (diff_id,)).fetchone()
        is not None
    )


def _classify(
    conn: sqlite3.Connection, run_id_or_ref: str, run_ids: set[str]
) -> tuple[str, object]:
    """Resolve one ``--delete`` id to ('run', id) / ('pair', (a, b)) / ('diff', diff_id), or raise.

    An id equal to a run id is a run (an unresolved, instance-only run included). ``a::b`` with
    diffs recorded that way is a pair; ``a::b::binary`` naming a stored diff is one diff. An id that
    is BOTH a run and a diff is ambiguous and the whole command is refused (a --run-id is free text
    and may hold '::'). An id that is neither, written ``a::b`` with diffs only the other way round,
    suggests the swap; anything else is unknown."""
    parts = run_id_or_ref.split("::")
    is_run = run_id_or_ref in run_ids
    pair = (
        (parts[0], parts[1])
        if len(parts) == 2 and pair_diffs(conn, parts[0], parts[1])[0] > 0
        else None
    )
    single = run_id_or_ref if len(parts) == 3 and _diff_exists(conn, run_id_or_ref) else None
    if is_run and (pair is not None or single is not None):
        raise TreasureMapError(
            f"ambiguous id '{run_id_or_ref}': it names both a run and a diff — "
            "rename the run, or delete the run and the diff in separate commands"
        )
    if is_run:
        return "run", run_id_or_ref
    if pair is not None:
        return "pair", pair
    if single is not None:
        return "diff", single
    if len(parts) == 2 and reverse_direction_diffs(conn, parts[0], parts[1]) > 0:
        raise TreasureMapError(
            f"no diffs recorded as {parts[0]}::{parts[1]}; did you mean {parts[1]}::{parts[0]}?"
        )
    raise TreasureMapError(f"unknown id '{run_id_or_ref}' (see tmap runs)")


def _dir_size(directory: Path) -> int | None:
    """Sum of the file sizes under ``directory`` (symlinks not followed); None on error."""
    try:
        total = 0
        for root, _dirs, files in os.walk(directory, followlinks=False):
            for name in files:
                try:
                    total += os.lstat(os.path.join(root, name)).st_size
                except OSError:
                    pass
        return total
    except OSError:
        return None


def _also_recorded_by(run_rows: list[RunRow], ws: Path, deleted_runs: set[str]) -> list[str]:
    """Runs in this atlas (outside the delete set) whose analysis.db is in directory ``ws``."""
    try:
        ws_resolved = ws.resolve()
    except OSError:
        return []
    out: list[str] = []
    for r in run_rows:
        if r.run_id in deleted_runs or not r.analysis_db_path:
            continue
        try:
            if Path(r.analysis_db_path).resolve().parent == ws_resolved:
                out.append(r.run_id)
        except OSError:
            continue
    return out


def _count_annotations_kept(
    conn: sqlite3.Connection, deleted_runs: set[str], deleted_pairs: set[str]
) -> int:
    """Overlay rows whose subject this delete removes — kept, not deleted, so only counted. A row is
    affected when its run_id IS a deleted run (a scan judgement), splits on '::' into two parts one
    of which is a deleted run (a diff judgement on a pair the run is a side of), or equals a deleted
    pair. Matched exactly, never with LIKE: a run id holds '_', a LIKE wildcard."""
    kept = 0
    rows = conn.execute("SELECT run_id, COUNT(*) FROM overlay GROUP BY run_id").fetchall()
    for run_id, n in rows:
        if run_id is None:
            continue
        if run_id in deleted_runs:
            kept += n
            continue
        parts = run_id.split("::")
        if len(parts) == 2 and (parts[0] in deleted_runs or parts[1] in deleted_runs):
            kept += n
            continue
        if run_id in deleted_pairs:
            kept += n
    return kept


def plan_delete(conn: sqlite3.Connection, ids: list[str], *, workspace_dir: Path) -> DeletePlan:
    """Resolve and validate every id, summarise what their removal touches, and take the scan lock
    of each workspace a deleted run reaches. Raises TreasureMapError on any invalid id, or on a
    workspace with a scan running; on failure no row is touched and any lock taken is released."""
    run_rows = list_runs(conn)
    run_ids = {r.run_id for r in run_rows}
    runs: list[str] = []
    pairs: list[tuple[str, str]] = []
    single_diffs: list[str] = []
    for one in ids:
        kind, value = _classify(conn, one, run_ids)
        if kind == "run":
            if value not in runs:
                runs.append(value)  # type: ignore[arg-type]
        elif kind == "pair":
            if value not in pairs:
                pairs.append(value)  # type: ignore[arg-type]
        elif value not in single_diffs:
            single_diffs.append(value)  # type: ignore[arg-type]

    diff_id_set: set[str] = set(single_diffs)
    for run_id in runs:
        diff_id_set.update(
            r[0]
            for r in conn.execute(
                "SELECT diff_id FROM diff_meta WHERE run_a_id = ? OR run_b_id = ?", (run_id, run_id)
            )
        )
    for a, b in pairs:
        diff_id_set.update(
            r[0]
            for r in conn.execute(
                "SELECT diff_id FROM diff_meta WHERE run_a_id = ? AND run_b_id = ?", (a, b)
            )
        )

    deleted_runs = set(runs)
    deleted_pairs = {f"{a}::{b}" for a, b in pairs}
    annotations_kept = _count_annotations_kept(conn, deleted_runs, deleted_pairs)

    workspaces: list[WorkspaceReport] = []
    locks: list[IO[str]] = []
    try:
        for run_id in runs:
            run = get_run(conn, run_id)
            recorded = run.analysis_db_path if run is not None else None
            if not recorded:
                workspaces.append(WorkspaceReport(run_id, None, None, []))
                continue
            db_path = Path(recorded)
            ws = workspace_of(db_path, workspace_dir)
            if ws is None:
                workspaces.append(WorkspaceReport(run_id, db_path, None, []))
                continue
            workspaces.append(
                WorkspaceReport(
                    run_id, ws, _dir_size(ws), _also_recorded_by(run_rows, ws, deleted_runs)
                )
            )
            lock_path = ws / Workspace._LOCK_NAME
            if lock_path.is_file():
                # Open WITHOUT creating (r+), and do not go through Workspace: its __init__ mkdirs
                # and __enter__ opens the lock with "a", either of which would create a file here.
                handle: IO[str] = lock_path.open("r+")
                locks.append(handle)  # appended before flock so cleanup covers an open-but-unlocked
                try:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise TreasureMapError(
                        f"a scan or hunt of run '{run_id}' is in progress — "
                        "let it finish, then delete"
                    ) from None
    except BaseException:
        for handle in locks:
            try:
                fcntl.flock(handle, fcntl.LOCK_UN)
            except (OSError, ValueError):
                pass
            try:
                handle.close()
            except (OSError, ValueError):
                pass
        raise

    return DeletePlan(
        runs=runs,
        pairs=pairs,
        diff_ids=sorted(diff_id_set),
        annotations_kept=annotations_kept,
        workspaces=workspaces,
        locks=tuple(locks),
    )


def execute_delete(conn: sqlite3.Connection, plan: DeletePlan) -> dict[str, int]:
    """Apply the plan in one transaction and return the per-kind counts removed. Does NOT release
    the plan's locks — the caller does, in a finally. A repeated delete (a diff a run already took)
    is a no-op, so the three passes never conflict."""
    totals = {k: 0 for k in _PER_RUN_KINDS}
    for run_id in plan.runs:
        rc = delete_run(conn, run_id, commit=False)
        for k in _PER_RUN_KINDS:
            totals[k] += rc[k]
    for a, b in plan.pairs:
        delete_run_pair_diffs(conn, a, b, commit=False)
    for diff_id in plan.diff_ids:
        delete_diff(conn, diff_id, commit=False)
    conn.commit()
    return {"runs": len(plan.runs), "pairs": len(plan.pairs), "diffs": len(plan.diff_ids), **totals}
