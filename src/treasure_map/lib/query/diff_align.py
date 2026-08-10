# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Read-only query face over the layer-0 (alignment) and layer-2 (dimension-delta) diff tables.

The 80%-case alignment workflow: "I found something at A-side address X -- did B patch it?" So a
single-side address resolves to its aligned counterpart, carrying BOTH the raw
``alignment_confidence`` (trust in the pairing) and ``similarity`` (change magnitude) plus the
honest ``alignment_state`` -- never only the thresholded state (a continuous quantity must not
collapse to a binary one). Names ride along as a pairing SANITY signal a consumer reads, never a
verdict the tool draws.

The layer-2 read face (``get_diff_deltas`` / ``get_diff_meta`` / ``get_diff_capabilities``) surfaces
the tri-state dimension deltas, the diff's meta facts, and the per-dimension capability state. Every
one is READ-ONLY and takes the atlas connection EXPLICITLY (no ambient/default-atlas fallback), only
ever emits facts, and NEVER a change/quality verdict -- a delta is a projection of existing
annotations, an ``layer_changed`` is not 'this matters', and an empty result is not 'no changes'.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from treasure_map.lib.diff.driver import _DIFF_RETRY_LIMIT
from treasure_map.lib.diff.layer0 import norm_hex

_ALIGN_NOTE = (
    "an ALIGNMENT FACT (BinDiff matched these addresses), NOT a change verdict. "
    "alignment_confidence = trust in the pairing; similarity = how much the pair differs (a "
    "change-magnitude fact, not a verdict). A pair can be similarity=1.0 yet confidence ~0.02 -- "
    "read alignment_state together with the raw confidence, never the state alone. The names are a "
    "pairing sanity signal for you to judge, never a verdict."
)


def _row_to_pair(r: sqlite3.Row) -> dict[str, Any]:
    return {
        "addr_a": r["addr_a"],
        "addr_b": r["addr_b"],
        "name_a": r["name_a"],
        "name_b": r["name_b"],
        "alignment_confidence": r["alignment_confidence"],
        "similarity": r["similarity"],
        "alignment_state": r["alignment_state"],
        "basicblocks": r["basicblocks"],
        "edges": r["edges"],
        "instructions": r["instructions"],
    }


def _align_by_side(atlas: sqlite3.Connection, diff_id: str, addr: str, side: str) -> dict[str, Any]:
    col = "addr_a" if side == "a" else "addr_b"
    norm = norm_hex(addr)
    rows = atlas.execute(
        f"SELECT addr_a, addr_b, name_a, name_b, alignment_confidence, similarity, "  # noqa: S608
        f"alignment_state, basicblocks, edges, instructions "
        f"FROM function_alignment WHERE diff_id = ? AND {col} = ?",  # noqa: S608 -- col is a literal
        (diff_id, norm),
    ).fetchall()
    if not rows:
        return {
            "found": False,
            "diff_id": diff_id,
            "query": {"side": side, "addr": norm},
            "note": (
                "no matched pair for this address in this diff. That is NOT proof the function was "
                "added/removed -- an unmatched function is listed in function_presence, and a diff "
                "covers only the tool's view, never all changes. " + _ALIGN_NOTE
            ),
        }
    return {
        "found": True,
        "diff_id": diff_id,
        "query": {"side": side, "addr": norm},
        "pairs": [_row_to_pair(r) for r in rows],
        "note": _ALIGN_NOTE,
    }


def align_by_a(atlas: sqlite3.Connection, diff_id: str, addr: str) -> dict[str, Any]:
    """Given an A-side (before) address, its aligned B-side counterpart(s) with confidence +
    similarity + state. The forward direction of the "did B patch what I found in A?" workflow."""
    return _align_by_side(atlas, diff_id, addr, "a")


def align_by_b(atlas: sqlite3.Connection, diff_id: str, addr: str) -> dict[str, Any]:
    """Given a B-side (after) address, its aligned A-side counterpart(s). The reverse direction."""
    return _align_by_side(atlas, diff_id, addr, "b")


# ── layer-2 read face: dimension deltas / meta / capabilities (READ-ONLY, facts only) ───

_DELTA_NOTE = (
    "Each row is a PROJECTION of two already-computed annotations, NOT a change/quality verdict. "
    "layer_changed = the patch changed this aligned function's edge set -- NOT proof the change "
    "matters; you judge that. delta_undetermined is NOT 'unchanged' -- read its "
    "undetermined_reason (an enum that may grow; do not branch on it). state_a/state_b are OPAQUE "
    "strings you interpret. An EMPTY result is NOT 'no changes' -- check get_diff_capabilities for "
    "which dimensions this diff can even produce a delta for."
)

_META_NOTE = (
    "version_skew=1 -> every delta in this diff is version_skew undetermined; do not read it as "
    "'no change'. It compares only the analysis-tool version, not the firmware. A NULL "
    "ghidra_version means that side did not record one. unmatched_b = B-side functions with no "
    "A-side match (presence layer, the WEAKEST signal -- look at layer_changed, not this). "
    "diff_ok=0 means this binary did NOT diff (diff_status='failed', diff_status_reason = why): an "
    "empty get_diff_deltas for it is a BLIND SPOT, not 'no change'. diff_ok=1 = usable output."
)

_CAP_NOTE = (
    "delta_supported=0 for a dimension means it is VISIBLE but this diff produces no per-subject "
    "delta for it -- an EXPLICIT non-judgement, never a silent omission. state_a/state_b are each "
    "side's analysis capability (present / declared_absent / registration_unknown)."
)

_EMPTY_DELTAS_NOTE = (
    "EMPTY is NOT 'no changes'. Two very different cases produce it: (a) the binary diffed fine "
    "but no dimension changed, or (b) the binary did NOT diff at all (a blind spot). Check "
    "get_diff_meta -> diff_ok/diff_status: diff_ok=0 means it failed (see diff_status_reason). "
    "list_diff_blindspots enumerates the run-pair's un-diffed binaries. Also see "
    "get_diff_capabilities for dimensions this diff cannot delta."
)

_DELTA_COLS = (
    "subject_kind",
    "subject_key",
    "state_a",
    "state_b",
    "delta_kind",
    "undetermined_scope",
    "undetermined_reason",
    "alignment_confidence",
)

_META_COLS = (
    "binary_a",
    "binary_b",
    "version_skew",
    "tool_version_a",
    "tool_version_b",
    "ghidra_version_a",
    "ghidra_version_b",
    "matched_pairs",
    "alignment_undetermined",
    "matched_in_domain_a",
    "matched_in_domain_b",
    "unmatched_a",
    "unmatched_b",
    "out_of_inventory_a",
    "out_of_inventory_b",
    "functions_total_a",
    "functions_total_b",
    "functions_empty_a",
    "functions_empty_b",
    "micro_skipped_a",
    "micro_skipped_b",
    "presence_computed_a",
    "presence_computed_b",
    "bindiff_source",
    "diff_ok",
    "diff_status",
    "diff_status_reason",
    "diff_attempts",
)


def get_diff_deltas(
    atlas: sqlite3.Connection,
    diff_id: str,
    *,
    binary: str | None = None,
    dimension: str | None = None,
    delta_kind: str | None = None,
    limit: int = 100,
    offset: int = 0,
    verbose: bool = False,
) -> dict[str, Any]:
    """The tri-state dimension deltas for one diff, filterable by binary / dimension / delta_kind.

    ``binary`` filters on the REAL ``binary`` column (parsed from subject_key at write time), not a
    ``subject_key LIKE`` prefix -- a LIKE would go wrong the moment a binary name carries a ``|`` or
    a prefix collides. verbose=false (default) returns only the delta rows + paging (context is a
    budget); verbose=true adds the honesty note + legend. The honesty invariants live in the tool
    docstring and always apply -- an empty result is NOT proof of 'no changes'."""
    where = ["diff_id = ?"]
    params: list[Any] = [diff_id]
    if binary is not None:
        where.append("binary = ?")
        params.append(binary)
    if dimension is not None:
        where.append("dimension = ?")
        params.append(dimension)
    if delta_kind is not None:
        where.append("delta_kind = ?")
        params.append(delta_kind)
    clause = " AND ".join(where)
    total = atlas.execute(
        f"SELECT COUNT(*) FROM dimension_delta WHERE {clause}",  # noqa: S608 -- clause is literal
        params,
    ).fetchone()[0]
    lo = max(0, offset)
    lim = max(0, limit)
    rows = atlas.execute(
        f"SELECT {', '.join(_DELTA_COLS)} FROM dimension_delta WHERE {clause} "  # noqa: S608
        "ORDER BY id LIMIT ? OFFSET ?",
        [*params, lim, lo],
    ).fetchall()
    deltas = [dict(zip(_DELTA_COLS, r, strict=True)) for r in rows]
    hi = lo + len(deltas)
    result: dict[str, Any] = {
        "diff_id": diff_id,
        "filters": {"binary": binary, "dimension": dimension, "delta_kind": delta_kind},
        "deltas": deltas,
        "page": {
            "count": total,
            "returned": len(deltas),
            "offset": lo,
            "truncated": hi < total,
            "next_offset": hi if hi < total else None,
        },
    }
    if verbose:
        result["note"] = _DELTA_NOTE
        result["legend"] = {
            "delta_kind": "layer_changed | layer_unchanged | delta_undetermined (tri-state)",
            "undetermined_scope": "data | capability (the sole consumer key)",
            "empty_result": "not 'no changes' -- see get_diff_capabilities",
        }
    elif total == 0:
        # An empty result is the trap this tool must not spring: it reads as 'no change' but the
        # binary may not have diffed at all (diff_ok=0). Surface the honesty note EVEN in the terse
        # (non-verbose) mode, precisely because that is where a consumer is most likely to misread
        # an empty result -- point them at the diff_status and the blind-spot listing.
        result["note"] = _EMPTY_DELTAS_NOTE
    return result


def get_diff_meta(atlas: sqlite3.Connection, diff_id: str) -> dict[str, Any]:
    """The diff's meta facts (binary scope, versions, alignment + presence counts).

    All non-derived columns, echoed raw. ``found=False`` when there is no such diff -- an empty
    answer is explicit, never a silent zero-row that reads as 'nothing changed'."""
    row = atlas.execute(
        f"SELECT {', '.join(_META_COLS)} FROM diff_meta WHERE diff_id = ?",  # noqa: S608
        (diff_id,),
    ).fetchone()
    if row is None:
        return {
            "found": False,
            "diff_id": diff_id,
            "note": "no diff_meta for this diff_id -- run `tmap diff` for it first.",
        }
    return {
        "found": True,
        "diff_id": diff_id,
        "meta": dict(zip(_META_COLS, row, strict=True)),
        "note": _META_NOTE,
    }


def get_diff_capabilities(atlas: sqlite3.Connection, diff_id: str) -> dict[str, Any]:
    """Per-dimension capability state for one diff: which dimensions each side could analyse and
    whether this diff can produce a delta for them. Makes a 'no delta' dimension VISIBLE as a
    declared gap instead of an invisible absence."""
    cols = ("dimension", "state_a", "state_b", "delta_supported")
    rows = atlas.execute(
        f"SELECT {', '.join(cols)} FROM dimension_capability_state "  # noqa: S608 -- cols literal
        "WHERE diff_id = ? ORDER BY dimension",
        (diff_id,),
    ).fetchall()
    return {
        "diff_id": diff_id,
        "capabilities": [dict(zip(cols, r, strict=True)) for r in rows],
        "note": _CAP_NOTE,
    }


_LIST_DIFFS_NOTE = (
    "Each row is ONE binary's diff between two runs (diff_id = {run_a}::{run_b}::{binary}). The "
    "counts are tri-state PROJECTIONS, not verdicts: layer_changed = the binary's changed aligned "
    "functions, NOT proof the change matters; delta_undetermined is NOT 'unchanged'. An EMPTY list "
    "means no diff has been run for that filter yet — not 'nothing changed'. diff_ok=0 rows are "
    "BLIND SPOTS (diff_status='failed', diff_status_reason = why, diff_attempts = tries): the "
    "binary did not diff, so its zero counts are 'unknown', never 'no change' — "
    "list_diff_blindspots focuses just those. Pick a binary, then read get_diff_deltas / meta."
)

_LIST_DIFFS_COLS = (
    "diff_id",
    "binary",
    "run_a_id",
    "run_b_id",
    "matched_pairs",
    "version_skew",
    "diff_ok",
    "diff_status",
    "diff_status_reason",
    "diff_attempts",
    "layer_changed",
    "layer_unchanged",
    "delta_undetermined",
)


def list_diffs(
    atlas: sqlite3.Connection,
    run_a_id: str | None = None,
    run_b_id: str | None = None,
) -> dict[str, Any]:
    """Every binary diffed between two runs, with each one's change profile AND its diff status —
    the browse view after a full diff. Optionally filter to a run-pair. Read-only; counts tri-state
    projections, never a verdict or a ranking (a diff is a map, not a score). diff_ok/diff_status
    ride each row so a failed (un-diffed) binary is visible, never mistaken for 'no change'."""
    where: list[str] = []
    params: list[Any] = []
    if run_a_id is not None:
        where.append("dm.run_a_id = ?")
        params.append(run_a_id)
    if run_b_id is not None:
        where.append("dm.run_b_id = ?")
        params.append(run_b_id)
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    rows = atlas.execute(
        "SELECT dm.diff_id, dm.binary_a, dm.run_a_id, dm.run_b_id, dm.matched_pairs, "  # noqa: S608
        "dm.version_skew, dm.diff_ok, dm.diff_status, dm.diff_status_reason, dm.diff_attempts, "
        "SUM(CASE WHEN dd.delta_kind='layer_changed' THEN 1 ELSE 0 END), "
        "SUM(CASE WHEN dd.delta_kind='layer_unchanged' THEN 1 ELSE 0 END), "
        "SUM(CASE WHEN dd.delta_kind='delta_undetermined' THEN 1 ELSE 0 END) "
        "FROM diff_meta dm LEFT JOIN dimension_delta dd ON dd.diff_id = dm.diff_id "
        f"{clause} GROUP BY dm.diff_id ORDER BY dm.run_a_id, dm.run_b_id, dm.binary_a",
        params,
    ).fetchall()
    return {
        "diffs": [dict(zip(_LIST_DIFFS_COLS, r, strict=True)) for r in rows],
        "count": len(rows),
        "filters": {"run_a_id": run_a_id, "run_b_id": run_b_id},
        "note": _LIST_DIFFS_NOTE,
    }


_BLINDSPOT_NOTE = (
    "The binaries a full diff could NOT analyse between two runs (diff_ok=0) — the blind spots a "
    "consumer of the deltas must see so an un-diffed binary is never read as 'no change' (UNKNOWN "
    "is not SAFE). Each row: why it failed (diff_status_reason), how many times it was attempted "
    "(diff_attempts), and whether it has hit the retry cap (suspected_hard=1 -> a likely-"
    "deterministic toolchain boundary, skipped on later full diffs unless force_retry; 0 -> a "
    "likely-transient failure that the next full diff retries). suspected_hard is a HINT from "
    "repeated identical-content failures, never proof the binary is undiffable — its content "
    "changing resets the count."
)


def list_diff_blindspots(
    atlas: sqlite3.Connection,
    run_a_id: str | None = None,
    run_b_id: str | None = None,
    *,
    retry_limit: int = _DIFF_RETRY_LIMIT,
) -> dict[str, Any]:
    """The un-diffed (diff_ok=0) binaries of a run-pair: the explicit blind-spot listing so a
    'no delta' can never masquerade as 'no change'. ``suspected_hard`` = diff_attempts >= the retry
    cap (a likely hard boundary). Optionally filter to a run-pair. Read-only, facts only.

    A blind spot is per-binary, and a per-binary row's id reads ``run_a::run_b::binary``. A row
    whose id is just ``run_a::run_b`` describes the run-pair itself, not any one binary, so listing
    it would invent a blind spot on a binary nobody failed to diff. Compared against the id built
    from this row's own run columns rather than by counting separators, since a binary name may
    contain them."""
    where = ["diff_ok = 0", "diff_id <> run_a_id || '::' || run_b_id"]
    params: list[Any] = []
    if run_a_id is not None:
        where.append("run_a_id = ?")
        params.append(run_a_id)
    if run_b_id is not None:
        where.append("run_b_id = ?")
        params.append(run_b_id)
    clause = " AND ".join(where)
    rows = atlas.execute(
        "SELECT diff_id, binary_a, diff_status_reason, diff_attempts "  # noqa: S608 -- clause literal
        f"FROM diff_meta WHERE {clause} ORDER BY run_a_id, run_b_id, binary_a",
        params,
    ).fetchall()
    blindspots = [
        {
            "diff_id": r[0],
            "binary": r[1],
            "diff_status_reason": r[2],
            "diff_attempts": r[3],
            "suspected_hard": 1 if (r[3] or 0) >= retry_limit else 0,
        }
        for r in rows
    ]
    return {
        "blindspots": blindspots,
        "count": len(blindspots),
        "filters": {"run_a_id": run_a_id, "run_b_id": run_b_id},
        "retry_limit": retry_limit,
        "note": _BLINDSPOT_NOTE,
    }
