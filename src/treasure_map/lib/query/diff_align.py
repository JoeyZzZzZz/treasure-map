# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Read-only query face over the layer-0 (alignment) and layer-2 (dimension-delta) diff tables.

The 80%-case alignment workflow: "I found something at A-side address X -- did B patch it?" So a
single-side address (or a function name, which may match several functions -- all listed, none
picked) resolves to its aligned counterpart, carrying BOTH the raw
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
from collections.abc import Iterable
from typing import Any

from treasure_map.lib.diff.code_version import diff_code_version, export_code_hash
from treasure_map.lib.diff.currency import (
    hunt_inputs_digest,
    read_extraction,
    run_hunt_marks,
    toolchain_columns,
)
from treasure_map.lib.diff.driver import _DIFF_RETRY_LIMIT
from treasure_map.lib.diff.layer0 import norm_hex
from treasure_map.lib.diff.toolchain import current_toolchain
from treasure_map.lib.query.diff_workflow import DIFF_WORKFLOW
from treasure_map.lib.ro_db import ro_connect

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
# ★ The bytes are not all a diff is computed from. It also reads, per side, the binary's extraction
# and the hunt's output for it, and it is produced by the diff code — each recorded with the diff
# as a stamp (lib/diff/currency) and compared here with what it is now, by plain equality.
STALE_DIFF_LOGIC = "diff_logic_changed"  # computed by different diff code than is running
STALE_TOOLCHAIN = "toolchain_changed"  # computed by another Ghidra / BinExport / BinDiff version
STALE_EXTRACTION = "extraction_changed"  # the binary's extraction pass differs
STALE_GHIDRA = "ghidra_changed"  # the binary's recorded decompiler version differs
STALE_HUNT_INPUTS = "hunt_inputs_changed"  # the hunt output the diff read differs

# Both sides are judged and the highest-ranked reason found is the one reported (first = highest).
_REASON_RANK = (
    STALE_GONE,
    STALE_CHANGED,
    STALE_DIFF_LOGIC,
    STALE_TOOLCHAIN,
    STALE_EXTRACTION,
    STALE_GHIDRA,
    STALE_HUNT_INPUTS,
    STALE_NO_STAMP,
    STALE_UNKNOWN,
)
# The reasons that make a diff stale (source_stale true); the other two leave it unverified (null).
_STALE_REASONS = frozenset(_REASON_RANK[:7])

# The diff_meta columns the staleness check reads.
_STAMP_COLS = (
    "run_a_id",
    "run_b_id",
    "binary_a",
    "binary_b",
    "sha256_a",
    "sha256_b",
    "extraction_pass_a",
    "extraction_pass_b",
    "ghidra_version_a",
    "ghidra_version_b",
    "hunt_inputs_hash_a",
    "hunt_inputs_hash_b",
    "scanned_at_a",
    "scanned_at_b",
    "hunt_instances_a",
    "hunt_instances_b",
    "diff_code_version",
    "export_builder_a",
    "export_builder_b",
    "export_code_hash_a",
    "export_code_hash_b",
    "toolchain_ghidra",
    "toolchain_binexport",
    "toolchain_bindiff",
)


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
        conn = ro_connect(row[0])
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


class _GenerationCache:
    """One lookup per run, reused across the rows of a listing."""

    def __init__(self, atlas: sqlite3.Connection) -> None:
        self._atlas = atlas
        self._by_run: dict[str, dict[str, set[str]] | None] = {}
        self._extraction: dict[str, dict[str, tuple[str | None, str | None]] | None] = {}
        self._marks: dict[str, tuple[str | None, int | None, int] | None] = {}
        self._digests: dict[tuple[str, str | None, str | None], str] = {}

    def for_run(self, run_id: str | None) -> dict[str, set[str]] | None:
        if not run_id:
            return None
        if run_id not in self._by_run:
            self._by_run[run_id] = _current_generation(self._atlas, run_id)
        return self._by_run[run_id]

    def extraction(self, run_id: str) -> dict[str, tuple[str | None, str | None]] | None:
        """``{sha256 -> (pass_version, ghidra_version)}`` of the run's analysis.db, or None."""
        if run_id not in self._extraction:
            row = self._atlas.execute(
                "SELECT analysis_db_path FROM run WHERE run_id = ?", (run_id,)
            ).fetchone()
            self._extraction[run_id] = read_extraction(row[0] if row is not None else None)
        return self._extraction[run_id]

    def hunt_marks(self, run_id: str) -> tuple[str | None, int | None, int] | None:
        """``(scanned_at, hunt_instances, live instance rows)`` of a run; None when it is gone."""
        if run_id not in self._marks:
            marks = run_hunt_marks(self._atlas, run_id)
            live = self._atlas.execute(
                "SELECT COUNT(*) FROM instance WHERE source_run_id = ?", (run_id,)
            ).fetchone()[0]
            self._marks[run_id] = None if marks is None else (marks[0], marks[1], live)
        return self._marks[run_id]

    def hunt_digest(self, run_id: str, sha: str | None, binary: str | None) -> str:
        key = (run_id, sha, binary)
        if key not in self._digests:
            self._digests[key] = hunt_inputs_digest(self._atlas, run_id, sha, binary)
        return self._digests[key]


def _side_reasons(cache: _GenerationCache, meta: Any, side: str) -> set[str]:
    """Every staleness reason one side of a diff shows, except the hunt-input one (which costs a
    query and is only looked for when nothing ranked above it was found — see diff_staleness)."""
    run_id = meta[f"run_{side}_id"]
    sha = meta[f"sha256_{side}"]
    reasons: set[str] = set()
    _, sha_reason = _freshness(cache.for_run(run_id), meta[f"binary_{side}"], sha)
    if sha_reason is not None:
        reasons.add(sha_reason)
    if meta["diff_code_version"] is None:
        # Written before the input stamps were recorded: nothing to compare them with.
        reasons.add(STALE_NO_STAMP)
        return reasons
    ext = cache.extraction(run_id) if run_id else None
    if ext is None:
        reasons.add(STALE_UNKNOWN)
    elif sha in ext:  # a sha no longer present is already reported above as absent/changed
        pv, gv = ext[sha]
        if pv != meta[f"extraction_pass_{side}"]:
            reasons.add(STALE_EXTRACTION)
        if gv != meta[f"ghidra_version_{side}"]:
            reasons.add(STALE_GHIDRA)
    return reasons


def _hunt_inputs_changed(cache: _GenerationCache, meta: Any, side: str) -> bool | None:
    """Whether the hunt output this side of the diff read has changed; None when the run is gone.

    ★ Fast path: the tables the digest covers are only ever written inside a hunt, and a hunt
    rewrites run.scanned_at before touching them and run.hunt_instances after. When both still equal
    what the diff recorded — and the run still holds exactly that many candidate rows, so none were
    added or removed outside a hunt — no hunt has run since, and the digest is not recomputed.
    Anything differing (or unrecorded) means it is recomputed and compared, so a hunt that
    reproduced the same output leaves the diff current.

    BOUNDARY: the guard holds only for writes made by a hunt. Rows of the tables the digest covers
    (the candidate instances, string_keyed_edge, run_capability, the run row's tool and Ghidra
    versions) added, removed or edited outside a hunt keep the fast path, and the diff reads as
    current. The one exception is a change to the run's total number of instance rows, which the
    live count sees. The full diff's own re-diff decision never takes the fast path: it always
    recomputes the digest."""
    run_id = meta[f"run_{side}_id"]
    marks = cache.hunt_marks(run_id) if run_id else None
    if marks is None:
        return None
    scanned_at, instances, live = marks
    stored_at, stored_n = meta[f"scanned_at_{side}"], meta[f"hunt_instances_{side}"]
    unchanged = (scanned_at, instances, live) == (stored_at, stored_n, stored_n)
    if stored_at is not None and stored_n is not None and unchanged:
        return False
    digest = cache.hunt_digest(run_id, meta[f"sha256_{side}"], meta[f"binary_{side}"])
    return bool(digest != meta[f"hunt_inputs_hash_{side}"])


def diff_staleness(cache: _GenerationCache, meta: Any) -> tuple[bool | None, str | None]:
    """(source_stale, source_stale_reason) for one diff_meta row carrying ``_STAMP_COLS``.

    Each side is judged on every axis — its bytes, its extraction, the hunt output the diff read —
    plus the diff code version, and the highest-ranked reason found on either side is reported
    (``_REASON_RANK``). ``source_stale`` is true for a reason that means the diff no longer
    describes its inputs, null for one that means it could not be checked (no stamp, or the source
    unreadable), and false only when every axis was checked and matched."""
    reasons = _side_reasons(cache, meta, "a") | _side_reasons(cache, meta, "b")
    if meta["diff_code_version"] is not None:
        if meta["diff_code_version"] != diff_code_version() or any(
            meta[f"export_code_hash_{s}"] != export_code_hash(meta[f"export_builder_{s}"])
            for s in "ab"
        ):
            reasons.add(STALE_DIFF_LOGIC)
        toolchain = current_toolchain()
        if toolchain is not None and any(
            meta[c] != v for c, v in toolchain_columns(toolchain).items()
        ):
            reasons.add(STALE_TOOLCHAIN)
    rank = {r: i for i, r in enumerate(_REASON_RANK)}
    higher = [r for r in reasons if rank[r] < rank[STALE_HUNT_INPUTS]]
    if meta["diff_code_version"] is not None and not higher:
        for side in ("a", "b"):
            if _hunt_inputs_changed(cache, meta, side):
                reasons.add(STALE_HUNT_INPUTS)
                break
    if not reasons:
        return False, None
    best = min(reasons, key=rank.__getitem__)
    return (True if best in _STALE_REASONS else None), best


def _meta_stamps(atlas: sqlite3.Connection, diff_id: str) -> Any:
    """The diff_meta row's ``_STAMP_COLS`` as a mapping, or None when there is no such diff."""
    row = atlas.execute(
        f"SELECT {', '.join(_STAMP_COLS)} FROM diff_meta WHERE diff_id = ?",  # noqa: S608
        (diff_id,),
    ).fetchone()
    return dict(zip(_STAMP_COLS, row, strict=True)) if row is not None else None


def diff_source_staleness(
    atlas: sqlite3.Connection, diff_id: str, cache: _GenerationCache | None = None
) -> dict[str, Any]:
    """``{"source_stale", "source_stale_reason", "toolchain_checked"}`` for one diff, for every diff
    read surface. A diff_id with no diff_meta row cannot be checked: null with
    ``source_unavailable``. ``toolchain_checked`` says whether this reader could read the installed
    toolchain to compare with (see ``toolchain_checked``)."""
    meta = _meta_stamps(atlas, diff_id)
    if meta is None:
        return {
            "source_stale": None,
            "source_stale_reason": STALE_UNKNOWN,
            "toolchain_checked": toolchain_checked(),
        }
    stale, reason = diff_staleness(cache or _GenerationCache(atlas), meta)
    return {
        "source_stale": stale,
        "source_stale_reason": reason,
        "toolchain_checked": toolchain_checked(),
    }


def toolchain_checked() -> bool:
    """Whether this reader can read the installed Ghidra / BinExport / BinDiff versions. When it
    cannot, a diff computed by other versions cannot be told apart, and the answer says so here
    instead of turning every diff's source_stale into null."""
    return current_toolchain() is not None


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


def diffs_source_staleness(
    atlas: sqlite3.Connection, diff_ids: Iterable[str]
) -> dict[str, dict[str, Any]]:
    """``diff_source_staleness`` for several diffs, sharing one lookup per run."""
    cache = _GenerationCache(atlas)
    return {d: diff_source_staleness(atlas, d, cache) for d in sorted(set(diff_ids))}


def staleness_summary(by_diff: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Counts over ``diffs_source_staleness``: how many diffs are stale (true), unverified (null)
    and current (false), and how many carry each reason."""
    by_reason: dict[str, int] = {}
    for v in by_diff.values():
        reason = v["source_stale_reason"]
        if reason is not None:
            by_reason[reason] = by_reason.get(reason, 0) + 1
    flags = [v["source_stale"] for v in by_diff.values()]
    return {
        "diffs": len(flags),
        "stale": sum(1 for f in flags if f is True),
        "unverified": sum(1 for f in flags if f is None),
        "current": sum(1 for f in flags if f is False),
        "by_reason": dict(sorted(by_reason.items())),
    }


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
        # why a side's function is not held as it is by its export, or null (the pair is then
        # alignment_undetermined whatever its confidence)
        "export_gap_a": r["export_gap_a"],
        "export_gap_b": r["export_gap_b"],
    }


def _align_by_side(atlas: sqlite3.Connection, diff_id: str, addr: str, side: str) -> dict[str, Any]:
    col = "addr_a" if side == "a" else "addr_b"
    norm = norm_hex(addr)
    rows = atlas.execute(
        f"SELECT addr_a, addr_b, name_a, name_b, alignment_confidence, similarity, "  # noqa: S608
        f"alignment_state, basicblocks, edges, instructions, export_gap_a, export_gap_b "
        f"FROM function_alignment WHERE diff_id = ? AND {col} = ?",  # noqa: S608 -- col is a literal
        (diff_id, norm),
    ).fetchall()
    if not rows:
        gap = atlas.execute(
            "SELECT export_gap FROM function_presence WHERE diff_id = ? AND side = ? AND addr = ?",
            (diff_id, side, norm),
        ).fetchone()
        return {
            "found": False,
            "diff_id": diff_id,
            "query": {"side": side, "addr": norm},
            # non-null when the function is unmatched because its export did not hold it as it is
            "export_gap": gap[0] if gap is not None else None,
            **diff_source_staleness(atlas, diff_id),
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
        **diff_source_staleness(atlas, diff_id),
        "note": _ALIGN_NOTE,
    }


_ALIGN_COLUMNS = (
    "addr_a, addr_b, name_a, name_b, alignment_confidence, similarity, alignment_state, "
    "basicblocks, edges, instructions, export_gap_a, export_gap_b"
)

_NOT_PROOF = (
    "That is NOT proof the function was added/removed -- an unmatched function is listed in "
    "function_presence, and a diff covers only the tool's view, never all changes. "
)


def align_by_function(
    atlas: sqlite3.Connection, diff_id: str, function: str, side: str
) -> dict[str, Any]:
    """One function's aligned counterpart(s), the function named by a name OR an address.

    The address forms are the ones every function tool reads (``facts._addr_candidates``: 0x /
    FUN_ hex, a digits-only value as hex and as decimal); the name is matched exactly against the
    side's stored name. Both are tried at once — a hex-looking name is looked up both ways — and
    ``query.matched_by`` says which hit. The one difference from the function tools: a name can
    match more than one function on a side (an import stub and the body beside it), and then the
    answer lists every candidate (``reason: ambiguous``) instead of picking one. So does a
    digits-only value read as two addresses that both exist. No match lists the side's unmatched
    functions of that name or address under ``presence`` (function_presence)."""
    from treasure_map.lib.facts import _addr_candidates

    addr_col, name_col = ("addr_a", "name_a") if side == "a" else ("addr_b", "name_b")
    cands = sorted(_addr_candidates(function))
    marks = ", ".join("?" * len(cands))
    by_addr = f" OR {addr_col} IN ({marks})" if cands else ""
    presence_by_addr = f" OR addr IN ({marks})" if cands else ""
    rows = atlas.execute(
        f"SELECT {_ALIGN_COLUMNS} FROM function_alignment "  # noqa: S608 -- literal columns
        f"WHERE diff_id = ? AND ({name_col} = ?{by_addr}) ORDER BY {addr_col}, addr_a, addr_b",
        (diff_id, function, *cands),
    ).fetchall()
    by_name = any(r[name_col] == function for r in rows)
    by_number = any(r[addr_col] in cands for r in rows)
    matched_by = (
        "name+addr"
        if by_name and by_number
        else "name"
        if by_name
        else "addr"
        if by_number
        else None
    )
    query = {"side": side, "input": function, "matched_by": matched_by, "addr_candidates": cands}
    head: dict[str, Any] = {"diff_id": diff_id, "query": query}
    groups: dict[str, list[sqlite3.Row]] = {}
    for r in rows:
        groups.setdefault(r[addr_col], []).append(r)
    if len(groups) == 1:
        return {
            "found": True,
            **head,
            "pairs": [_row_to_pair(r) for r in rows],
            **diff_source_staleness(atlas, diff_id),
            "note": _ALIGN_NOTE,
        }
    if len(groups) > 1:
        return {
            "found": False,
            "reason": "ambiguous",
            **head,
            "candidates": [
                {
                    addr_col: addr,
                    name_col: group[0][name_col],
                    "instructions": group[0]["instructions"],
                    "basicblocks": group[0]["basicblocks"],
                    "pairs": [_row_to_pair(r) for r in group],
                }
                for addr, group in sorted(groups.items())
            ],
            **diff_source_staleness(atlas, diff_id),
            "note": (
                f"{len(groups)} functions on side {side} match this input; none is picked. A name "
                "can match an import stub and the function body beside it (a stub usually has a "
                "few instructions and 1 basic block), and a digits-only value reads as hex and as "
                "decimal. Re-issue with one candidate's address. " + _NOT_PROOF + _ALIGN_NOTE
            ),
        }
    presence = atlas.execute(
        f"SELECT addr, name, presence_state, export_gap FROM function_presence "  # noqa: S608
        f"WHERE diff_id = ? AND side = ? AND (name = ?{presence_by_addr}) "
        "ORDER BY addr",
        (diff_id, side, function, *cands),
    ).fetchall()
    miss = (
        "no matched pair for this address in this diff. "
        if cands
        else f"this diff's export holds no function of that name on side {side}; pass an address. "
    )
    return {
        "found": False,
        **head,
        # each unmatched function of this name or address; export_gap is non-null when it is
        # unmatched because its export did not hold it as it is
        "presence": [dict(p) for p in presence],
        **diff_source_staleness(atlas, diff_id),
        "note": miss + _NOT_PROOF + _ALIGN_NOTE,
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
    "A-side match (presence layer, the WEAKEST signal: a function with no counterpart is never "
    "read as added or removed). ``functions`` splits the aligned pairs by what their pseudocode "
    "and callee sets say (get_diff_patch_view's pseudocode_sameness): unchanged (both match), "
    "changed (with_scoped_sink_delta = bucket A or a changed sink length constant; "
    "no_scoped_signal = no in-scope sink signal, NOT 'noise'), unverified "
    "(identical_text_unverified — the text matched, but the match rests on an unknown image "
    "extent, a decompile the decompiler marked incomplete, or two body byte counts that differ, "
    "split by body class in identical_text_unverified_by_body — + identical_callee_unverified + "
    "unavailable (a side's text could not be read) + skipped_micro (a side is a micro-function not "
    "decompiled by design; unavailable_by_cause splits these two by cause, summing to both); "
    "neither unchanged nor changed), and no_body (an import / PLT stub, counted apart); beside "
    "them alignment_undetermined (split by each pair's proposed reading in "
    "alignment_undetermined_reading, never into the aligned counts) and one_sided by "
    "presence_state. withheld = the whole diff is undetermined: no counts at all (a blind spot, "
    "with blind_spot='did_not_diff' when it failed), never zeros. "
    "diff_ok=0 means this binary did NOT diff (diff_status='failed', diff_status_reason = why): an "
    "empty get_diff_deltas for it is a BLIND SPOT, not 'no change'. diff_ok=1 = usable output. "
    "baseline_dropped=1 = the diff had a stored candidate baseline that a re-diff dropped (it "
    "failed, or the baseline could not be stored again). "
    "ghidra_version is the diffed binary's own (the run's on a diff written before the stamps). "
    + DIFF_WORKFLOW
)

_CAP_NOTE = (
    "delta_supported=0 for a dimension means it is VISIBLE but this diff produces no per-subject "
    "delta for it -- an EXPLICIT non-judgment, never a silent omission. state_a/state_b are each "
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
    "baseline_dropped",
    "export_builder_a",
    "export_builder_b",
    "export_entry_addresses_added_a",
    "export_entry_addresses_added_b",
    "export_flow_graphs_dropped_a",
    "export_flow_graphs_dropped_b",
    "export_degenerate_functions_a",
    "export_degenerate_functions_b",
    "bindiff_vertex0_fallbacks",
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
    # The sink overlay writes subject_kind='candidate' rows into the same table; they are the
    # dedicated get_diff_sink_overlay tool's domain and must never leak into this edge/dimension
    # view.
    where = ["diff_id = ?", "subject_kind != 'candidate'"]
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
        # ★ Whether these deltas still describe their inputs. Attached to EVERY response, not only
        # the verbose one: a reader who trimmed the notes to save room is exactly the reader who
        # would otherwise act on a diff of a build that is gone. It is ORTHOGONAL to diff_status —
        # a diff can have computed perfectly and still be about a file that has since been
        # replaced — so it is reported separately and never folded into that field.
        **diff_source_staleness(atlas, diff_id),
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
    answer is explicit, never a silent zero-row that reads as 'nothing changed'. ``banners``: a
    withheld diff's banners as the view gives them; otherwise the read-first banner when an
    undetermined pair is flagged anchored_differs or anchored_micro_side
    (patch_view.anchored_differs_banner), else empty."""
    row = atlas.execute(
        f"SELECT {', '.join(_META_COLS)} FROM diff_meta WHERE diff_id = ?",  # noqa: S608
        (diff_id,),
    ).fetchone()
    if row is None:
        return {
            "found": False,
            "diff_id": diff_id,
            "banners": [],
            "note": "no diff_meta for this diff_id -- run `tmap diff` for it first.",
        }
    # patch_view imports this module, so the view is imported here, at call time.
    from treasure_map.lib.query.patch_view import anchored_differs_banner, function_states

    meta = dict(zip(_META_COLS, row, strict=True))
    functions = function_states(atlas, diff_id)
    if functions is not None and functions.get("withheld") and not meta["diff_ok"]:
        functions["blind_spot"] = "did_not_diff"
    banners: list[str] = []
    if functions is not None and functions.get("withheld"):
        banners = list(functions.get("banners", []))
    elif (banner := anchored_differs_banner(functions)) is not None:
        banners.append(banner)
    return {
        "found": True,
        "diff_id": diff_id,
        "meta": meta,
        "functions": functions,
        "banners": banners,
        **diff_source_staleness(atlas, diff_id),
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
        **diff_source_staleness(atlas, diff_id),
        "note": _CAP_NOTE,
    }


_LIST_DIFFS_NOTE = (
    "Each row is ONE binary's diff between two runs (diff_id = {run_a}::{run_b}::{binary}). "
    "``functions`` counts FUNCTIONS from what the diff stored: aligned pairs, how many of them "
    "BinDiff scored below similarity 1 (a pair with no recorded score counted among them, never "
    "read as 1), pairs whose alignment is undetermined, and the functions "
    "with no counterpart by presence_state (never 'added' / 'removed'). Similarity 1 is NOT "
    "'unchanged' — it is blind to constants and buffer sizes; whether an aligned pair really "
    "changed (unchanged / changed / unverified / no_body, by pseudocode) is per diff: "
    "get_diff_meta(diff_id). The string-keyed dispatch edges are a switchable view, "
    "get_diff_deltas(diff_id), not counted here. An EMPTY list means no diff has been run for "
    "that filter yet — not 'nothing changed'. diff_ok=0 rows are BLIND SPOTS (blind_spot="
    "'did_not_diff', diff_status='failed', diff_status_reason = why, diff_attempts = tries): the "
    "binary did not diff, so it has no counts (functions=null), never zeros — "
    "list_diff_blindspots focuses just those. With both run ids, ``coverage`` says what no diff "
    "of the pair can see: the failed diffs and the candidate-holding binaries no diff covers, "
    "with the binaries byte-identical in both runs kept apart (no diff needed; their candidates "
    "are on the scan map). baseline_dropped=1 = the diff had a stored candidate "
    "baseline that a re-diff dropped (it failed, or the baseline could not be stored again). Pick "
    "a binary, then start with start_diff_review (get_diff_meta for the meta and the "
    "per-function split). "
    "★ source_stale says whether the diff still describes what it was computed from: true = a "
    "side's binary content changed or is gone (source_content_changed / source_binary_absent), "
    "the diff code or the export script it ran changed (diff_logic_changed), the diff was "
    "computed by another Ghidra / BinExport / BinDiff than is installed (toolchain_changed), the "
    "binary was re-extracted (extraction_changed / ghidra_changed), or the hunt output the diff "
    "read changed (hunt_inputs_changed) — re-run the diff before reading its deltas as current. "
    "toolchain_checked=false = this reader could not read the installed toolchain, so a diff "
    "computed by other tool versions cannot be told apart here (it does not make source_stale "
    "null). false = every "
    "input was checked and still matches, the normal result of re-scanning or re-hunting without "
    "a change. null = could not be checked (source analysis.db unreachable, or the diff predates "
    "the stamps: generation_unstamped) — read source_stale_reason; it is NOT a clean bill. When "
    "several apply, the first in the order above is reported. Judged on CONTENT, never on which "
    "happened later."
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
    "baseline_dropped",
    "alignment_undetermined",
)


def pair_diffs(atlas: sqlite3.Connection, run_a_id: str, run_b_id: str) -> tuple[int, str | None]:
    """How many diff rows record ``run_a_id`` as the A side and ``run_b_id`` as the B side, and the
    smallest of their ids (None when there is none). Every row counts, failed ones included: a
    failed diff was still asked for in that direction."""
    row = atlas.execute(
        "SELECT COUNT(*), MIN(diff_id) FROM diff_meta WHERE run_a_id = ? AND run_b_id = ?",
        (run_a_id, run_b_id),
    ).fetchone()
    return int(row[0]), row[1]


def reverse_direction_diffs(atlas: sqlite3.Connection, run_a_id: str, run_b_id: str) -> int:
    """How many diffs record the two runs the other way round, when NONE records them this way
    round; 0 otherwise.

    A and B are the before and after roles, and a diff is not symmetric in them. A pair asked for
    in the direction nothing was diffed in, while diffs exist in the other, is most often the two
    roles passed swapped; the count lets a reader say so without answering for the other
    direction. A run paired with itself has no other way round."""
    if run_a_id == run_b_id or pair_diffs(atlas, run_a_id, run_b_id)[0]:
        return 0
    return pair_diffs(atlas, run_b_id, run_a_id)[0]


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
        "dm.baseline_dropped, dm.alignment_undetermined, "
        + ", ".join(f"dm.{c}" for c in _STAMP_COLS)
        + f" FROM diff_meta dm {clause} ORDER BY dm.run_a_id, dm.run_b_id, dm.binary_a",
        params,
    ).fetchall()
    # Two grouped counts over the stored tables, scoped like the listing: never a view, never a
    # pseudocode read — the per-diff split by pseudocode_sameness is get_diff_meta's.
    scope = f"SELECT dm.diff_id FROM diff_meta dm {clause}"  # noqa: S608
    below_1 = dict(
        atlas.execute(
            "SELECT diff_id, COUNT(*) FROM function_alignment "  # noqa: S608
            "WHERE alignment_state = 'aligned' AND (similarity IS NULL OR similarity < 1) "
            f"AND diff_id IN ({scope}) GROUP BY diff_id",
            params,
        ).fetchall()
    )
    one_sided: dict[str, dict[str, dict[str, int]]] = {}
    for did, side, state, n in atlas.execute(
        "SELECT diff_id, side, presence_state, COUNT(*) FROM function_presence "  # noqa: S608
        f"WHERE diff_id IN ({scope}) GROUP BY diff_id, side, presence_state",
        params,
    ):
        one_sided.setdefault(did, {}).setdefault(side, {})[state or "unrecorded"] = n
    cache = _GenerationCache(atlas)
    diffs: list[dict[str, Any]] = []
    for r in rows:
        row = dict(zip(_LIST_DIFFS_COLS, r[: len(_LIST_DIFFS_COLS)], strict=True))
        if _is_whole_run_row(row["diff_id"], row["run_a_id"], row["run_b_id"]):
            continue  # a leftover run-pair row: it describes no binary, so it answers nothing
        meta = dict(zip(_STAMP_COLS, r[len(_LIST_DIFFS_COLS) :], strict=True))
        undetermined = int(row.pop("alignment_undetermined") or 0)
        if row["diff_ok"]:
            row["functions"] = {
                "aligned": int(row["matched_pairs"] or 0) - undetermined,
                "aligned_similarity_below_1": int(below_1.get(row["diff_id"], 0)),
                "alignment_undetermined": undetermined,
                "one_sided": one_sided.get(row["diff_id"], {}),
            }
            row["blind_spot"] = None
        else:
            # A diff that did not run has no counts to give: zeros would read as "nothing moved".
            row["functions"] = None
            row["blind_spot"] = "did_not_diff"
        # ★ Either side moving makes the diff a statement about inputs that are gone. An
        # unanswerable side does not make it stale — it makes it unverified, which is said out loud
        # rather than rounded to either answer.
        row["source_stale"], row["source_stale_reason"] = diff_staleness(cache, meta)
        row["toolchain_checked"] = toolchain_checked()
        diffs.append(row)
    result: dict[str, Any] = {
        "diffs": diffs,
        "count": len(diffs),
        "filters": {"run_a_id": run_a_id, "run_b_id": run_b_id},
        "note": _LIST_DIFFS_NOTE,
    }
    if run_a_id is not None and run_b_id is not None:
        result["coverage"] = run_pair_coverage(atlas, run_a_id, run_b_id, diffs)
    return result


def run_pair_coverage(
    atlas: sqlite3.Connection, run_a: str, run_b: str, diffs: list[dict[str, Any]]
) -> dict[str, Any]:
    """What the diffs of one run pair cannot see, beside their counts: the diffs that failed, and
    the candidate-holding binaries no diff covers — the genuine blind spots (one side only, or
    shadowed by a same-named binary that was diffed) apart from the binaries byte-identical in both
    runs, which needed no diff and are only a pointer to the scan's candidate map.
    ``all_candidate_binaries_covered`` is false while a failed diff or a genuine blind spot
    remains; an identical binary never makes it false."""
    blind, identical = split_not_diffed(not_diffed_binaries(atlas, run_a, run_b))
    failed = [d["diff_id"] for d in diffs if not d["diff_ok"]]
    return {
        "failed_diffs": failed,
        "not_diffed_binaries": blind,
        "identical_binaries": identical,
        "all_candidate_binaries_covered": not failed and not blind,
        "see": (
            "list_diff_blindspots for the failed diffs. identical_binaries are byte-identical in "
            f"both runs, so no diff covers them and none can show what is in them — their "
            f"candidates are on the scan's candidate map: list_candidates(run_id={run_b!r}). "
            "get_diff_sink_overlay's binary_not_diffed rows still include those identical "
            "binaries; this split is the one to read as blind spots."
        ),
    }


_BLINDSPOT_NOTE = (
    "The binaries a full diff could NOT analyse between two runs (diff_ok=0) — the blind spots a "
    "consumer of the deltas must see so an un-diffed binary is never read as 'no change' (UNKNOWN "
    "is not SAFE). Each row: why it failed (diff_status_reason), how many times it was attempted "
    "(diff_attempts), and whether it has hit the retry cap (suspected_hard=1 -> a likely-"
    "deterministic toolchain boundary, skipped on later full diffs unless force_retry; 0 -> a "
    "likely-transient failure that the next full diff retries). suspected_hard is a HINT from "
    "repeated identical-content failures, never proof the binary is undiffable — its content, or "
    "what the diff reads (extraction, hunt output, diff code), changing resets the count. "
    "diff_status_reason='extraction_unstamped' = the binary has no recorded extraction (re-scan "
    "the run). baseline_dropped=1 = the diff had a stored candidate baseline, dropped by this "
    "failure or an earlier re-diff and not stored again. source_stale / source_stale_reason as in "
    "list_diffs. 'partial' lists the diffs that DID succeed but whose export could not hold some "
    "functions as they are (a flow graph dropped for having no entry block, or a block entered "
    "through a delay slot): those functions and every subject resting on them read undetermined "
    "with reason degenerate_block_source; marked_rows counts the presence / alignment rows marked. "
    "diff_status_reason='bindiff_flowgraph' = BinDiff rejected a flow graph of an export (the "
    "export is repaired before BinDiff runs, so this is not expected); 'bindiff_failed' = any "
    "other BinDiff failure."
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
        "SELECT diff_id, binary_a, diff_status_reason, diff_attempts, baseline_dropped, "  # noqa: S608
        + ", ".join(_STAMP_COLS)
        + f" FROM diff_meta WHERE {clause} ORDER BY run_a_id, run_b_id, binary_a",
        params,
    ).fetchall()
    cache = _GenerationCache(atlas)
    blindspots = []
    for r in rows:
        stale, reason = diff_staleness(cache, dict(zip(_STAMP_COLS, r[5:], strict=True)))
        blindspots.append(
            {
                "diff_id": r[0],
                "binary": r[1],
                "diff_status_reason": r[2],
                "diff_attempts": r[3],
                "suspected_hard": 1 if (r[3] or 0) >= retry_limit else 0,
                # 1 = this failure replaced a good diff and its stored candidate baseline with it
                "baseline_dropped": r[4] or 0,
                "source_stale": stale,
                "source_stale_reason": reason,
                "toolchain_checked": toolchain_checked(),
            }
        )
    return {
        "blindspots": blindspots,
        "count": len(blindspots),
        "partial": _partial_blindspots(atlas, cache, run_a_id, run_b_id),
        "filters": {"run_a_id": run_a_id, "run_b_id": run_b_id},
        "retry_limit": retry_limit,
        "note": _BLINDSPOT_NOTE,
    }


# ── the binaries no diff of a run pair covers (one classifier, shared) ──────────────────────

# Why a candidate whose binary was not diffed sits where it does. The two blind-spot reasons mirror
# the run-pair reasons lib/query/sink_overlay emits for get_diff_sink_overlay; identical_both_sides
# is the finer split that map does not make — a binary byte-for-byte present on the OTHER side was
# not diffed because there was nothing to diff, so it is no blind spot. One classifier, read by the
# review progress block, list_diffs and the diff command alike, so they cannot disagree.
NOT_DIFFED_IDENTICAL = "identical_both_sides"
NOT_DIFFED_BLIND = ("binary_not_diffed", "shadowed_by_name_collision")


def _short_name(path: str | None) -> str | None:
    """A binary path's short name (its basename), matched against diff_meta.binary_a / binary_b."""
    return path.rsplit("/", 1)[-1] if path else None


def not_diffed_reason(
    sha: str | None, name: str | None, *, diffed_names: set[str], other_shas: set[str]
) -> str:
    """Why a candidate whose binary content is not among the pair's diffed hashes is where it is.
    Identical content on the other side is not a blind spot; a same-named binary that WAS diffed
    shadowed it; otherwise the binary is on this side only."""
    if sha is not None and sha in other_shas:
        return NOT_DIFFED_IDENTICAL
    if name in diffed_names:
        return "shadowed_by_name_collision"
    return "binary_not_diffed"


def not_diffed_binaries(atlas: sqlite3.Connection, run_a: str, run_b: str) -> dict[str, Any]:
    """The binaries holding candidates that no diff of the pair covers, read straight from the atlas
    — diff_meta for what was diffed, instance for every candidate — WITHOUT recomputing the pair's
    sink overlay (which rebuilds every diff; this reads the same set, by content hash).

    Per side and reason: how many binaries (by path), how many candidates, and every binary's short
    name. A candidate whose binary content is present on the OTHER side too is identical across the
    pair and reads as ``identical_both_sides``, kept apart from the two genuine blind-spot reasons
    (``binary_not_diffed``, ``shadowed_by_name_collision``) so it never counts as one."""
    diffs = atlas.execute(
        "SELECT sha256_a, sha256_b, binary_a, binary_b FROM diff_meta "
        "WHERE run_a_id = ? AND run_b_id = ?",
        (run_a, run_b),
    ).fetchall()
    run_shas = {
        side: {
            sha
            for (sha,) in atlas.execute(
                "SELECT DISTINCT binary_content_hash FROM instance WHERE source_run_id = ?", (run,)
            )
            if sha
        }
        for side, run in (("a", run_a), ("b", run_b))
    }
    out: dict[str, Any] = {}
    for side, run, sha_col, name_col in (("a", run_a, 0, 2), ("b", run_b, 1, 3)):
        diffed_sha = {d[sha_col] for d in diffs if d[sha_col]}
        diffed_names = {d[name_col] for d in diffs if d[name_col]}
        other_shas = run_shas["b" if side == "a" else "a"]
        groups: dict[str, dict[str, set[str | None]]] = {}
        for ref, sha, path in atlas.execute(
            "SELECT evidence_ref, binary_content_hash, binary_path FROM instance "
            "WHERE source_run_id = ?",
            (run,),
        ):
            if sha is not None and sha in diffed_sha:
                continue  # its binary content was one side of a diff — covered
            reason = not_diffed_reason(
                sha, _short_name(path), diffed_names=diffed_names, other_shas=other_shas
            )
            g = groups.setdefault(reason, {"refs": set(), "paths": set()})
            g["refs"].add(ref)
            g["paths"].add(path)
        for reason, g in sorted(groups.items()):
            out.setdefault(side, {})[reason] = {
                "binaries": len(g["paths"]),
                "candidates": len(g["refs"]),
                "names": sorted({_short_name(p) or "(no path recorded)" for p in g["paths"]}),
            }
    return out


def split_not_diffed(
    not_diffed: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """``(blind, identical)`` of a :func:`not_diffed_binaries` result: the genuine blind spots
    (one side only, or shadowed by a same-named binary that was diffed) per side and reason, and —
    apart, as counts only — the binaries byte-identical on both sides, which needed no diff."""
    blind: dict[str, Any] = {}
    identical: dict[str, Any] = {}
    for side, by_reason in not_diffed.items():
        mine = {r: v for r, v in by_reason.items() if r in NOT_DIFFED_BLIND}
        if mine:
            blind[side] = mine
        same = by_reason.get(NOT_DIFFED_IDENTICAL)
        if same is not None:
            identical[side] = {"binaries": same["binaries"], "candidates": same["candidates"]}
    return blind, identical


_PARTIAL_COLS = (
    "export_builder_a",
    "export_builder_b",
    "export_flow_graphs_dropped_a",
    "export_flow_graphs_dropped_b",
    "export_degenerate_functions_a",
    "export_degenerate_functions_b",
    "export_entry_addresses_added_a",
    "export_entry_addresses_added_b",
    "bindiff_vertex0_fallbacks",
)


def _partial_blindspots(
    atlas: sqlite3.Connection,
    cache: _GenerationCache,
    run_a_id: str | None,
    run_b_id: str | None,
) -> list[dict[str, Any]]:
    """The diffs that succeeded (diff_ok=1) but whose export could not hold some functions as they
    are (lib/diff/export_report): those functions, and every subject resting on them, read
    undetermined (degenerate_block_source). Each row carries the export counts and how many
    presence / alignment rows of the diff are marked."""
    where = [
        "diff_ok = 1",
        "(COALESCE(export_flow_graphs_dropped_a, 0) + COALESCE(export_flow_graphs_dropped_b, 0) "
        "+ COALESCE(export_degenerate_functions_a, 0) "
        "+ COALESCE(export_degenerate_functions_b, 0)) > 0",
    ]
    params: list[Any] = []
    if run_a_id is not None:
        where.append("run_a_id = ?")
        params.append(run_a_id)
    if run_b_id is not None:
        where.append("run_b_id = ?")
        params.append(run_b_id)
    rows = atlas.execute(
        "SELECT diff_id, binary_a, "  # noqa: S608 -- literal column lists
        + ", ".join(_PARTIAL_COLS + _STAMP_COLS)
        + f" FROM diff_meta WHERE {' AND '.join(where)} ORDER BY run_a_id, run_b_id, binary_a",
        params,
    ).fetchall()
    out: list[dict[str, Any]] = []
    n = len(_PARTIAL_COLS)
    for r in rows:
        marked = atlas.execute(
            "SELECT (SELECT COUNT(*) FROM function_presence WHERE diff_id = ? "
            "AND export_gap IS NOT NULL) + (SELECT COUNT(*) FROM function_alignment "
            "WHERE diff_id = ? AND (export_gap_a IS NOT NULL OR export_gap_b IS NOT NULL))",
            (r[0], r[0]),
        ).fetchone()[0]
        stale, reason = diff_staleness(cache, dict(zip(_STAMP_COLS, r[2 + n :], strict=True)))
        out.append(
            {
                "diff_id": r[0],
                "binary": r[1],
                **dict(zip(_PARTIAL_COLS, r[2 : 2 + n], strict=True)),
                "marked_rows": marked,
                "source_stale": stale,
                "source_stale_reason": reason,
                "toolchain_checked": toolchain_checked(),
            }
        )
    return out
