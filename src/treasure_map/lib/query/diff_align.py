# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
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


# ── has the ground under a diff moved since it was computed? ──────────────────────────
#
# A diff is a statement about two specific builds. Re-scan one of them with different content and
# the alignment underneath still reads as current: the addresses it matched belong to a binary that
# no longer exists. Nothing corrects for that on its own, so the check happens where the result is
# CONSUMED — the one point every reader passes through.
#
# ★ THE TEST IS THE GENERATION, NEVER THE CLOCK. "This run was re-scanned after the diff" says
# nothing: re-scanning identical content is the common case and leaves every alignment valid. Only
# a changed content hash means the diff describes something that is gone. Judging by timestamps
# would flag the entire table on any re-scan, which is the same failure — old data treated as
# current — pointed the other way.
#
# ★ COMPARED BY EXISTENCE, NOT BY PICKING A ROW. The diff records a binary's SHORT NAME, and one
# name really can cover several files in a scan (a real firmware has four such names in one run,
# each with two distinct hashes — including one that was itself diffed). Reading "the" hash for a
# name would be a coin flip, and half the time it would call an unchanged diff stale. So: the
# stored hash matching ANY hash under that name means the file that was diffed is still there,
# unchanged. Only when it matches none of them has the ground moved.

STALE_UNKNOWN = "source_unavailable"  # cannot tell — never reported as stale, never as fresh
STALE_NO_STAMP = "generation_unstamped"  # the diff predates the hash being recorded
STALE_CHANGED = "source_content_changed"
STALE_GONE = "source_binary_absent"


def _current_generation(atlas: sqlite3.Connection, run_id: str) -> dict[str, set[str]] | None:
    """Every content hash the run's CURRENT scan holds, keyed by binary short name.

    ★ Read from the run's own analysis.db, resolved through the ``analysis_db_path`` the run row
    records for exactly this purpose. The atlas's own per-candidate hash is the wrong source: it
    exists only for binaries that produced a candidate, so on a real firmware it covers about a
    third of the binaries that were diffed — and treating "no hash here" as "changed" would brand
    most of an unchanged table stale.

    None means the source could not be read at all (no path recorded, file gone, unreadable). That
    is a can't-tell, and it is kept distinct from an answer: a diff is never called stale because
    its source was unreachable."""
    row = atlas.execute("SELECT analysis_db_path FROM run WHERE run_id = ?", (run_id,)).fetchone()
    if row is None or not row[0]:
        return None
    try:
        conn = sqlite3.connect(f"file:{row[0]}?mode=ro", uri=True)
    except sqlite3.Error:
        return None
    try:
        out: dict[str, set[str]] = {}
        for name, sha in conn.execute("SELECT name, sha256 FROM current_binaries"):
            if name and sha:
                out.setdefault(name, set()).add(sha)
        return out
    except sqlite3.Error:
        return None  # a pre-view analysis.db: cannot tell, so say so
    finally:
        conn.close()


def _freshness(
    generation: dict[str, set[str]] | None, binary: str | None, stored_sha: str | None
) -> tuple[bool | None, str | None]:
    """Is this diff still about the build it was computed from? (stale, reason).

    ``stale`` is None when the question cannot be answered — reported as such rather than resolved
    in either direction, because "we could not check" and "we checked and it is fine" are
    different things to hand a reader."""
    if generation is None:
        return None, STALE_UNKNOWN
    if not stored_sha:
        return None, STALE_NO_STAMP  # written before the stamp existed; nothing to compare
    present = generation.get(binary or "")
    if present is None:
        return True, STALE_GONE  # the scan no longer holds a binary by that name at all
    if stored_sha in present:
        return False, None  # the diffed file is still there, byte for byte
    return True, STALE_CHANGED


def _combine(a: bool | None, b: bool | None) -> bool | None:
    """One answer from the two sides of a diff.

    Either side having moved makes the whole diff a statement about a build that is gone. A side
    that could not be checked does NOT make it stale — it makes it unverified, which is a third
    answer and is reported as one rather than rounded toward either."""
    if a or b:
        return True
    return None if (a is None or b is None) else False


class _GenerationCache:
    """One lookup per run, reused across the rows of a listing."""

    def __init__(self, atlas: sqlite3.Connection) -> None:
        self._atlas = atlas
        self._by_run: dict[str, dict[str, set[str]] | None] = {}

    def for_run(self, run_id: str | None) -> dict[str, set[str]] | None:
        if not run_id:
            return None
        if run_id not in self._by_run:
            self._by_run[run_id] = _current_generation(self._atlas, run_id)
        return self._by_run[run_id]


def _is_whole_run_row(diff_id: str, run_a_id: str, run_b_id: str) -> bool:
    """Is this the abandoned run-pair row, rather than a diff of one binary?

    A diff aligns ONE binary, and its id carries that binary as a third segment. A row whose id is
    just the two run ids is left over from before that was true, and it describes nothing a reader
    can act on.

    ★ Identified by the SHAPE OF THE ID, never by ``diff_ok``. A failed per-binary diff also has
    diff_ok=0, and that one is a blind spot a reader must keep seeing — filtering on the flag would
    take it out along with the leftover, hiding a binary that could not be diffed behind the same
    silence as one that was never meant to be listed."""
    return diff_id == f"{run_a_id}::{run_b_id}"


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
    meta = atlas.execute(
        "SELECT run_a_id, run_b_id, binary_a, sha256_a, sha256_b FROM diff_meta WHERE diff_id = ?",
        (diff_id,),
    ).fetchone()
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
    cache = _GenerationCache(atlas)
    stale_a, reason_a = (
        _freshness(cache.for_run(meta["run_a_id"]), meta["binary_a"], meta["sha256_a"])
        if meta is not None
        else (None, STALE_UNKNOWN)
    )
    stale_b, reason_b = (
        _freshness(cache.for_run(meta["run_b_id"]), meta["binary_a"], meta["sha256_b"])
        if meta is not None
        else (None, STALE_UNKNOWN)
    )
    result: dict[str, Any] = {
        "diff_id": diff_id,
        "filters": {"binary": binary, "dimension": dimension, "delta_kind": delta_kind},
        "deltas": deltas,
        # ★ Whether these deltas still describe builds that exist. Attached to EVERY response, not
        # only the verbose one: a reader who trimmed the notes to save room is exactly the reader
        # who would otherwise act on a diff of a build that is gone. It is ORTHOGONAL to
        # diff_status — a diff can have computed perfectly and still be about a file that has since
        # been replaced — so it is reported separately and never folded into that field.
        "source_stale": _combine(stale_a, stale_b),
        "source_stale_reason": reason_a or reason_b,
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
    "list_diff_blindspots focuses just those. Pick a binary, then read get_diff_deltas / meta. "
    "★ source_stale says whether the diff still describes builds that exist: true = a side's "
    "binary content changed (or that binary is gone from the scan), so the alignment underneath "
    "points at a file that no longer exists — re-run the diff before reading its deltas as "
    "current. false = the diffed files are still there byte for byte, which is the normal result "
    "of re-scanning unchanged sources. null = could not be checked (source analysis.db "
    "unreachable, or the diff predates the content stamp) — read source_stale_reason; it is NOT a "
    "clean bill. Judged on CONTENT, never on which happened later: re-scanning identical sources "
    "leaves every diff valid."
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
        "SUM(CASE WHEN dd.delta_kind='delta_undetermined' THEN 1 ELSE 0 END), "
        "dm.sha256_a, dm.sha256_b "
        "FROM diff_meta dm LEFT JOIN dimension_delta dd ON dd.diff_id = dm.diff_id "
        f"{clause} GROUP BY dm.diff_id ORDER BY dm.run_a_id, dm.run_b_id, dm.binary_a",
        params,
    ).fetchall()
    cache = _GenerationCache(atlas)
    diffs: list[dict[str, Any]] = []
    for r in rows:
        row = dict(zip(_LIST_DIFFS_COLS, r[: len(_LIST_DIFFS_COLS)], strict=True))
        if _is_whole_run_row(row["diff_id"], row["run_a_id"], row["run_b_id"]):
            continue  # a leftover run-pair row: it describes no binary, so it answers nothing
        stale_a, reason_a = _freshness(cache.for_run(row["run_a_id"]), row["binary"], r[13])
        stale_b, reason_b = _freshness(cache.for_run(row["run_b_id"]), row["binary"], r[14])
        # ★ Either side moving makes the diff a statement about a build that is gone. An
        # unanswerable side does not make it stale — it makes it unverified, which is said out loud
        # rather than rounded to either answer.
        row["source_stale"] = _combine(stale_a, stale_b)
        row["source_stale_reason"] = reason_a or reason_b
        diffs.append(row)
    return {
        "diffs": diffs,
        "count": len(diffs),
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
