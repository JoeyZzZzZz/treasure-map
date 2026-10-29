# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Reading and checking judgements on a diff's function-level view, against the view itself.

lib/overlay.py writes every overlay row; this module is what it asks before writing a diff-side
one, and what lists them. Each of these rebuilds the diff's view (patch_view.build_diff_view) — the
same build get_diff_patch_view reads — so a judgement is always checked against exactly the entries
a reader was shown.

  * ``capture_diff_basis`` — the anchor a judgement is written on must name an entry, or a
    candidate row of one, that the view lists now; what it rests on is snapshotted from it.
  * ``check_promotion`` — whether a judgement on an entry may be carried onto one of its
    candidates (see its docstring for the rules and why each exists).
  * ``list_diff_overlays`` — every diff-side judgement with its live state; for one run pair,
    also the progress over every diff of that pair, with what no diff covers beside it. A judgement
    on a non-binary file is read on its own path (file_diff.file_review), never by a binary diff.
  * ``file_scope`` / ``require_file_checked_anchor`` — where a judgement on a non-binary file is
    checked: the run pair's files, and a binary diff's view when a ``diff_id`` named the pair.

Nothing here writes.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from treasure_map.lib.errors import ConfigError
from treasure_map.lib.overlay import _DIFF_VERDICTS
from treasure_map.lib.query import diff_review as dr
from treasure_map.lib.query.coverage import NEEDS_RECHECK
from treasure_map.lib.query.diff_align import (
    list_diff_blindspots,
    not_diffed_binaries,
    split_not_diffed,
)
from treasure_map.lib.query.patch_view import BuiltDiff, ViewReview, _Entry, build_diff_view

# Where a candidate row has to land for its entry's judgement to be carried onto it. A row that
# lands A, or persisted, or P as a function whose counterpart is established to be missing, says
# something about that candidate a candidate verdict can stand on. Every other landing — B, R, a
# banner, and anything a later reason adds — is refused: the reason list may grow, and a row this
# check does not know must not pass because it was not named.
_PROMOTABLE_LANDINGS = ("A", "persisted")
_P_PROMOTABLE_SUBCLASS = "unmatched_analysis_complete"


class PromotionRefusedError(ConfigError):
    """A promotion refused, with the facts that refused it (``details``) for the caller."""

    def __init__(self, message: str, details: dict[str, Any]) -> None:
        super().__init__(message)
        self.details = details


# ── the diff a judgement is written into ────────────────────────────────────────────────────


def _binary_diff(atlas: sqlite3.Connection, diff_id: str) -> dict[str, Any]:
    """One binary's diff, or a refusal. A run pair is refused by name: everything checked here —
    the entries, whether the diff is current — is per diff, and a pair would skip it."""
    found = dr.as_dicts(
        atlas.execute(
            "SELECT diff_id, run_a_id, run_b_id, binary_a FROM diff_meta WHERE diff_id = ?",
            (diff_id,),
        )
    )
    row = found[0] if found else None
    is_pair = atlas.execute(
        "SELECT 1 FROM diff_meta WHERE run_a_id || '::' || run_b_id = ? LIMIT 1", (diff_id,)
    ).fetchone()
    if is_pair is not None and (
        row is None or row["diff_id"] == dr.run_pair(row["run_a_id"], row["run_b_id"])
    ):
        raise ConfigError(
            f"{diff_id!r} names a run pair, not one binary's diff — pass a diff_id from "
            "list_diffs ({run_a}::{run_b}::{binary})"
        )
    if row is None:
        raise ConfigError(f"no diff {diff_id!r} in this atlas (see list_diffs)")
    if not row["binary_a"]:
        raise ConfigError(
            f"diff {diff_id!r} records no binary name, which every anchor carries — re-run it"
        )
    return row


def _built(atlas: sqlite3.Connection, diff_id: str) -> BuiltDiff:
    built = build_diff_view(atlas, diff_id)
    assert built is not None  # the diff_meta row was just read
    if built.withheld is not None:
        raise ConfigError(
            f"diff {diff_id!r} is undetermined as a whole ({', '.join(built.banners)}): nothing "
            "in it can be judged until that is resolved"
        )
    return built


def _check_anchor(anchor_ref: str, meta: dict[str, Any]) -> tuple[str, str]:
    run_a, run_b, binary = meta["run_a_id"], meta["run_b_id"], meta["binary_a"]
    parts = dr.split_anchor(anchor_ref, run_a, run_b)
    if parts is None:
        raise ConfigError(
            f"{anchor_ref!r} is not an anchor of this diff's run pair "
            f"({dr.run_pair(run_a, run_b)}#<subject>#<key>) — copy it from the entry's anchor_ref"
        )
    kind, key = parts
    named = dr.key_binary(kind, key)
    if kind != "candidate" and named != binary:
        raise ConfigError(
            f"{anchor_ref!r} names binary {named!r}, but diff {meta['diff_id']!r} is of {binary!r}"
        )
    return kind, key


def capture_diff_basis(atlas: sqlite3.Connection, diff_id: str, anchor_ref: str) -> dict[str, Any]:
    """The snapshot a judgement on ``anchor_ref`` is stored with, or a refusal when the anchor does
    not name something the view lists now: a listed entry, or a candidate row of one."""
    meta = _binary_diff(atlas, diff_id)
    _check_anchor(anchor_ref, meta)
    built = _built(atlas, diff_id)
    return capture_diff_basis_on(atlas, built, meta, diff_id, anchor_ref)


def capture_diff_basis_on(
    atlas: sqlite3.Connection,
    built: BuiltDiff,
    meta: dict[str, Any],
    diff_id: str,
    anchor_ref: str,
) -> dict[str, Any]:
    """``capture_diff_basis`` against an already-built view and ``_binary_diff`` meta — the batch
    builds both once and reuses them. Same anchor check, same refusal, same snapshot."""
    _check_anchor(anchor_ref, meta)
    subjects = dr.subjects_of(built.entries, meta["run_a_id"], meta["run_b_id"], meta["binary_a"])
    subject = subjects.get(anchor_ref)
    if subject is None:
        raise ConfigError(
            f"{anchor_ref!r} names nothing get_diff_patch_view lists for {diff_id!r} now — an "
            "entry, or a candidate row of one (an identical pair is not listed, and an anchor "
            "is matched exactly as the view prints it)"
        )
    return dr.snapshot(diff_id, subject)


# ── a no_real_change's `checked` / a changed_real's `evidence`: anchors must resolve ─────────
#
# `checked` reasons for a verdict that SINKS an entry, so an item that looks like an anchor must
# actually resolve in this diff's current view; one that does not is refused and named. Items
# that are not anchor-shaped are kept as plain-text notes and do not count. At least one anchor must
# resolve. `is_diff_anchor` reuses the view's own parsers; `_anchor_marker` is the closed set of
# "looks like an anchor" forms (a plain English note never matches one).

# Any run pair's function_pair / function_presence / candidate anchor: an anchor of another run
# pair still LOOKS like one, so it must resolve here, not pass as plain text.
_PAIR_ANCHOR_MARKER = re.compile(
    r"^[^\s#]+::[^\s#]+#(?:function_pair|function_presence|candidate)#"
)
_ENTRY_ID_MARKER = re.compile(r"^(?:pair:[0-9a-fx]+:[0-9a-fx]+|[ab]:[0-9a-fx]+)$")
# An evidence_ref / row_ref: run + a >=8-hex sha prefix + ':' (a function-level short form too).
_EVIDENCE_REF_MARKER = re.compile(r"^[^#\s]+#[0-9a-f]{8,}:")


def _anchor_marker(item: str) -> str | None:
    """The kind of anchor ``item`` LOOKS like (a closed set), or None for a plain-text note."""
    if _PAIR_ANCHOR_MARKER.match(item):
        return "anchor_ref"
    if _ENTRY_ID_MARKER.match(item):
        return "entry_id"
    if "#f2:" in item:
        return "group_ref"
    if _EVIDENCE_REF_MARKER.match(item):
        return "row_ref"
    return None


def is_diff_anchor(
    atlas: sqlite3.Connection,
    built: BuiltDiff,
    meta: dict[str, Any],
    side_meta: Any,
    item: str,
    *,
    subjects: dict[str, dr.Subject] | None = None,
    entry_ids: set[str] | None = None,
    row_refs: set[str] | None = None,
) -> str | None:
    """The kind of anchor ``item`` RESOLVES to in this diff's current view, or None. Each branch
    reuses the view's own parser: an entry / candidate anchor (``split_anchor`` + a live subject),
    an ``entry_id``, a ``row_ref`` (a row's a_ref / b_ref), or a ``group_ref`` naming a current
    group (``group_in_diff`` — up to, not including, the "about this entry" relation: a read group
    counts as read whoever's entry it is). The precomputed lookups let a batch build them once."""
    from treasure_map.lib.query.diff_group_freshness import group_in_diff

    run_a, run_b, binary = meta["run_a_id"], meta["run_b_id"], meta["binary_a"]
    if subjects is None:
        subjects = dr.subjects_of(built.entries, run_a, run_b, binary)
    if entry_ids is None:
        entry_ids = {e.entry_id for e in built.entries}
    if row_refs is None:
        row_refs = {ref for e in built.entries for r in e.rows for ref in (r.a_ref, r.b_ref) if ref}
    parts = dr.split_anchor(item, run_a, run_b)
    if parts is not None and subjects.get(item) is not None:
        return parts[0]  # function_pair / function_presence / candidate
    if item in entry_ids:
        return "entry_id"
    if item in row_refs:
        return "row_ref"
    if group_in_diff(atlas, built, side_meta, item):
        return "group_ref"
    return None


def _rule_for(field: str) -> str:
    """``CHECKED_RULE`` worded for the field being checked (``checked`` or ``evidence``)."""
    return dr.CHECKED_RULE if field == "checked" else dr.CHECKED_RULE.replace("checked", field, 1)


def require_checked_anchor(
    atlas: sqlite3.Connection,
    built: BuiltDiff,
    meta: dict[str, Any],
    side_meta: Any,
    items: list[str],
    field: str,
) -> None:
    """Enforce the ``checked`` / ``evidence`` anchor rule: every item that LOOKS like an
    anchor must resolve in the view (else a named refusal), plain text is kept but does not count,
    and at least one anchor must resolve. ``field`` is the key name, for the message wording."""
    run_a, run_b, binary = meta["run_a_id"], meta["run_b_id"], meta["binary_a"]
    subjects = dr.subjects_of(built.entries, run_a, run_b, binary)
    entry_ids = {e.entry_id for e in built.entries}
    row_refs = {ref for e in built.entries for r in e.rows for ref in (r.a_ref, r.b_ref) if ref}
    hits = 0
    for i, raw in enumerate(items):
        item = raw.strip()
        kind = is_diff_anchor(
            atlas,
            built,
            meta,
            side_meta,
            item,
            subjects=subjects,
            entry_ids=entry_ids,
            row_refs=row_refs,
        )
        if kind is not None:
            hits += 1
            continue
        marker = _anchor_marker(item)
        if marker is not None:
            raise ConfigError(
                f"{field}[{i}] looks like a {marker} anchor but names nothing in this diff's "
                "current view"
            )
        # a plain-text note: kept, but it does not count toward the anchor threshold
    if hits == 0:
        raise ConfigError(_rule_for(field))


# ── a judgement on a non-binary file ─────────────────────────────────────────────────────────

_NON_BINARY_MARKER = re.compile(r"^[^\s#]+::[^\s#]+#non_binary#")


@dataclass
class FileScope:
    """Where a judgement on a non-binary file is checked: the run pair, its files' subjects, and —
    when a ``diff_id`` named the pair — that diff's view (None when withheld or not asked for)."""

    run_a: str
    run_b: str
    subjects: dict[str, dr.Subject]
    diff_id: str | None = None
    built: BuiltDiff | None = None
    meta: dict[str, Any] | None = None
    side_meta: Any = None


def file_scope(
    atlas: sqlite3.Connection, *, diff_id: str | None = None, run_pair: str | None = None
) -> FileScope:
    """The scope of a non-binary file's judgement, named by ``run_pair`` or by the ``diff_id`` of a
    binary diff of the same pair. A diff undetermined as a whole still names its pair: its files
    are read all the same, only its function anchors cannot resolve in ``checked``."""
    from treasure_map.lib.query.file_diff import (
        FileDiffError,
        file_subjects,
        read_pair,
        split_run_pair,
    )
    from treasure_map.lib.query.same_shape_siblings import _meta as _side_meta

    built: BuiltDiff | None = None
    meta: dict[str, Any] | None = None
    side_meta: Any = None
    if diff_id is not None:
        meta = _binary_diff(atlas, diff_id)
        run_a, run_b = str(meta["run_a_id"]), str(meta["run_b_id"])
        try:
            built = _built(atlas, diff_id)
            side_meta = _side_meta(atlas, diff_id)
        except ConfigError:
            built = None
    else:
        assert run_pair is not None
        runs = split_run_pair(atlas, run_pair)
        if runs is None:
            raise ConfigError(
                f"run pair {run_pair!r} does not name two runs in this atlas — pass "
                "'{run_a}::{run_b}' with both taken from list_runs"
            )
        run_a, run_b = runs
    try:
        subjects = file_subjects(read_pair(atlas, run_a, run_b))
    except FileDiffError as exc:
        raise ConfigError(str(exc)) from exc
    return FileScope(run_a, run_b, subjects, diff_id, built, meta, side_meta)


def require_file_checked_anchor(
    atlas: sqlite3.Connection, scope: FileScope, items: list[str], field: str
) -> None:
    """The ``checked`` / ``evidence`` rule on a non-binary file's judgement: an item resolves when
    it is a file anchor get_file_diff lists for the pair now, or — when a diff_id named the pair —
    an anchor of that diff's current view. A file anchor that names no file, or a function /
    candidate anchor with no diff view to read it in, is refused by name; plain text is kept but
    does not count; at least one anchor must resolve."""
    hits = 0
    for i, raw in enumerate(items):
        item = raw.strip()
        if item in scope.subjects:
            hits += 1
            continue
        if scope.built is not None and scope.meta is not None:
            if is_diff_anchor(atlas, scope.built, scope.meta, scope.side_meta, item) is not None:
                hits += 1
                continue
        if _NON_BINARY_MARKER.match(item):
            raise ConfigError(
                f"{field}[{i}] looks like a non_binary anchor but names no file get_file_diff "
                f"lists for {scope.run_a}::{scope.run_b} now"
            )
        marker = _anchor_marker(item)
        if marker is not None:
            if scope.built is None:
                raise ConfigError(
                    f"{field}[{i}] looks like a {marker} anchor: a function or candidate anchor "
                    "resolves only in a binary diff's view — pass diff_id instead of run_pair"
                )
            raise ConfigError(
                f"{field}[{i}] looks like a {marker} anchor but names nothing in this diff's "
                "current view"
            )
    if hits == 0:
        raise ConfigError(_rule_for(field))


# ── promotion ──────────────────────────────────────────────────────────────────────────────


def _entry(built: BuiltDiff, meta: dict[str, Any], entry_id: str) -> _Entry:
    """The listed entry named by its entry_id, or by its anchor_ref."""
    if entry_id.split("#", 2)[1:2] == ["non_binary"]:
        raise ConfigError(
            "promote carries a judgment onto a candidate of a function entry; a non-binary file "
            "has no candidate rows"
        )
    by_id = {e.entry_id: e for e in built.entries}
    if entry_id in by_id:
        return by_id[entry_id]
    if "#" in entry_id:
        kind, _ = _check_anchor(entry_id, meta)
        if kind == "candidate":
            raise ConfigError(
                "promote takes an entry (its entry_id or anchor_ref), not a candidate anchor — "
                "name the candidate with row_ref"
            )
        run_a, run_b, binary = meta["run_a_id"], meta["run_b_id"], meta["binary_a"]
        for e in built.entries:
            if dr.entry_anchor(e, run_a, run_b, binary) == entry_id:
                return e
    raise ConfigError(f"{entry_id!r} is not an entry get_diff_patch_view lists for this diff now")


def check_promotion(
    atlas: sqlite3.Connection,
    *,
    diff_id: str,
    entry_id: str,
    row_ref: str,
    allow_stale_source: bool = False,
) -> dict[str, Any]:
    """The origin a promotion is stored with, or a refusal (``PromotionRefusedError``) naming why.

    1. WHERE THE ROW LANDS — read from the row's own ``landing``, which the view already computed,
       and never from its ``presence``: every A row reads ``presence_undetermined``, because the
       overlay never claims a call was added or removed, and that is a safe default, not doubt
       about the row. Allowed: A, persisted, and P with subclass ``unmatched_analysis_complete``
       (a P row whose function was not analysed — ``absent`` — says nothing about the candidate).
       Everything else is refused with its landing, subclass and presence_reason as the view
       states them. Every row of the entry that carries ``row_ref`` must pass.
    2. WHETHER THE COUNTERPART IS DETERMINED — a pair that is ``alignment_undetermined``, or a
       function with no counterpart whose presence is anything but
       ``unmatched_analysis_complete`` (analysis incomplete, or the two inventories disagree), is
       refused whatever its rows say.
    3. WHETHER THE DIFF IS CURRENT — ``source_stale`` must be false; true or null is refused unless
       ``allow_stale_source``, which is then recorded in the origin.

    The origin records the diff, the entry's anchor, and the carrying row's ``landing`` +
    ``subclass`` — where the judgement was carried from. A recorded landing, ``persisted``
    included, says where it came from, NOT that the code is unchanged; whether the basis has moved
    is ``basis_state``, read separately.
    """
    meta = _binary_diff(atlas, diff_id)
    built = _built(atlas, diff_id)
    e = _entry(built, meta, entry_id)
    anchor = dr.entry_anchor(e, meta["run_a_id"], meta["run_b_id"], meta["binary_a"])
    carrying = [
        v for r, v in zip(e.rows, e.row_views, strict=True) if row_ref in (r.a_ref, r.b_ref)
    ]
    if not carrying:
        refs = sorted({ref for r in e.rows for ref in (r.a_ref, r.b_ref) if ref})
        raise PromotionRefusedError(
            f"row_ref {row_ref!r} is not the a_ref or b_ref of any row of {e.entry_id}",
            {"entry_id": e.entry_id, "row_refs": refs},
        )
    for v in carrying:
        landing, subclass = v["landing"], v["subclass"]
        if landing in _PROMOTABLE_LANDINGS:
            continue
        if landing == "P" and subclass == _P_PROMOTABLE_SUBCLASS:
            continue
        raise PromotionRefusedError(
            f"the row of {row_ref!r} lands {landing} (subclass {subclass!r}, presence_reason "
            f"{v['presence_reason']!r}): only a row that lands A or persisted, or P with subclass "
            f"{_P_PROMOTABLE_SUBCLASS!r}, can carry a candidate verdict",
            {
                "landing": landing,
                "subclass": subclass,
                "presence_reason": v["presence_reason"],
            },
        )
    if e.pair is not None and e.pair.state != "aligned":
        raise PromotionRefusedError(
            f"{e.entry_id} is {e.pair.state}: whether the two functions are counterparts is not "
            "established",
            {"alignment_state": e.pair.state},
        )
    if e.unpaired is not None and e.unpaired.presence_state != _P_PROMOTABLE_SUBCLASS:
        raise PromotionRefusedError(
            f"{e.entry_id} has presence_state {e.unpaired.presence_state!r}: that it has no "
            "counterpart is not established",
            {"presence_state": e.unpaired.presence_state},
        )
    # The carrying row (one ref -> one row) is promotable, checked above; its landing and subclass
    # travel with the judgement so a later reader knows where it was carried from.
    promoted = carrying[0]
    origin: dict[str, Any] = {
        "diff_id": diff_id,
        "anchor_ref": anchor,
        "landing": promoted["landing"],
        "subclass": promoted["subclass"],
    }
    stale = built.staleness.get("source_stale")
    if stale is not False:
        now = {
            "source_stale": stale,
            "source_stale_reason": built.staleness.get("source_stale_reason"),
        }
        if not allow_stale_source:
            raise PromotionRefusedError(
                f"diff {diff_id!r} is not current (source_stale={stale!r}, reason "
                f"{now['source_stale_reason']!r}): re-run it and promote again, or pass "
                "allow_stale_source=true, which is recorded with the judgment",
                now,
            )
        origin["promoted_while_source_stale"] = now
    return origin


# ── listing ────────────────────────────────────────────────────────────────────────────────


_LIST_NOTE = (
    "YOUR judgments on diff entries (annotate_diff) — decisions, not tool facts; the diff and its "
    "view are unchanged whether this is empty or full. review_state is the entry's state in the "
    "progress count: 'needs_recheck' when basis_state is not 'unchanged' (basis_moved names what "
    "moved; 'diff_withheld' = the diff is undetermined as a whole now) or when the diff is not "
    "current (source_stale not false). basis_state 'anchor_unresolved' = the subject is gone (the "
    "functions were paired differently, or a candidate was re-keyed): the judgment is dangling. "
    "Nothing is dropped."
)


def _is_file_row(row: dict[str, Any]) -> bool:
    from treasure_map.lib.query.file_diff import is_non_binary_anchor

    return is_non_binary_anchor(str(row["anchor_ref"]))


def _file_judgements(
    atlas: sqlite3.Connection,
    rows: list[dict[str, Any]],
    file_staleness: Callable[[str, str], dict[str, Any]] | None,
) -> dict[int, dr.DiffAnnotation]:
    """Each non-binary file judgement (overlay row id ->) read on the file path, its run pair's
    files read once. A pair whose runs or files cannot be read leaves its judgements unresolved,
    with the reason."""
    from treasure_map.lib.query.file_diff import (
        FileDiffError,
        file_review,
        read_pair,
        split_run_pair,
    )

    out: dict[int, dr.DiffAnnotation] = {}
    by_pair: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        by_pair.setdefault(str(r["run_id"]), []).append(r)
    for pair, members in by_pair.items():
        runs = split_run_pair(atlas, pair)
        judged: dict[str, dr.DiffAnnotation] = {}
        why = "run_pair_unknown"
        if runs is not None:
            run_a, run_b = runs
            staleness = file_staleness(run_a, run_b) if file_staleness is not None else {}
            try:
                judged = file_review(
                    atlas,
                    run_a,
                    run_b,
                    source_stale=staleness.get("source_stale"),
                    source_stale_reason=staleness.get("source_stale_reason"),
                    pf=read_pair(atlas, run_a, run_b),
                )
            except FileDiffError:
                why = "files_unreadable"
        for r in members:
            out[r["id"]] = judged.get(r["anchor_ref"]) or dr.DiffAnnotation(
                anchor_ref=r["anchor_ref"],
                verdict=r["verdict"],
                basis_state=dr.ANCHOR_UNRESOLVED,
                moved={},
                source_stale=None,
                source_stale_reason=why,
            )
    return out


def _pair_diffs(atlas: sqlite3.Connection, pair: str) -> list[dict[str, Any]]:
    """Every binary diff of one run pair, matched on the pair as a whole."""
    return dr.as_dicts(
        atlas.execute(
            "SELECT diff_id, run_a_id, run_b_id, binary_a, diff_ok FROM diff_meta "
            "WHERE run_a_id || '::' || run_b_id = ? AND diff_id <> run_a_id || '::' || run_b_id "
            "ORDER BY diff_id",
            (pair,),
        )
    )


def _diff_of(row: dict[str, Any], diffs: list[dict[str, Any]]) -> str | None:
    stored = dr.stored_snapshot(row["basis_state"])
    for d in diffs:
        if dr.belongs_to(
            row["anchor_ref"],
            stored,
            diff_id=d["diff_id"],
            run_a=d["run_a_id"],
            run_b=d["run_b_id"],
            binary=d["binary_a"],
        ):
            return str(d["diff_id"])
    return None


def list_diff_overlays(
    atlas: sqlite3.Connection,
    *,
    verdict: str | None = None,
    run_id: str | None = None,
    file_staleness: Callable[[str, str], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Every judgement on a diff entry, optionally one verdict and/or one run pair
    (``run_id`` = ``{run_a}::{run_b}``), each read against its diff's view as it is now.

    A judgement on a non-binary file is read apart, against the run pair's files
    (file_diff.file_review), never through a binary diff: it carries ``diff_id`` null and its
    ``run_pair``. ``file_staleness(run_a, run_b)`` gives its ``source_stale`` /
    ``source_stale_reason`` — the caller's reading of the two runs; without it they are unknown
    (None), which reads ``needs_recheck``.

    With ``run_id`` it also carries ``review_progress`` over EVERY diff of that pair — which
    rebuilds every one of their views: seconds per hundred diffs (about 10 s for a pair of 126
    diffs). The binaries no diff covers are read straight from the atlas, not by recomputing the
    pair's sink overlay."""
    if verdict is not None and verdict not in _DIFF_VERDICTS:
        raise ConfigError(f"verdict must be one of {list(_DIFF_VERDICTS)}; got {verdict!r}")
    conds, params = ["anchor_kind = 'diff_subject'"], []
    if verdict is not None:
        conds.append("verdict = ?")
        params.append(verdict)
    if run_id is not None:
        conds.append("run_id = ?")
        params.append(run_id)
    rows = dr.as_dicts(
        atlas.execute(
            "SELECT id, anchor_kind, anchor_ref, run_id, verdict, rationale, attributed_to, "
            "basis_state, verdict_basis, updated_at FROM overlay "
            f"WHERE {' AND '.join(conds)} ORDER BY verdict, updated_at DESC",  # noqa: S608
            params,
        )
    )
    file_judged = _file_judgements(atlas, [r for r in rows if _is_file_row(r)], file_staleness)
    named = {str(r["run_id"]) for r in rows if r["run_id"] and not _is_file_row(r)}
    if run_id is not None:
        named.add(run_id)
    pairs = {pair: _pair_diffs(atlas, pair) for pair in sorted(named)}
    of_row = {
        r["id"]: None if _is_file_row(r) else _diff_of(r, pairs.get(r["run_id"], [])) for r in rows
    }
    wanted = {d for d in of_row.values() if d is not None}
    if run_id is not None:
        wanted |= {str(d["diff_id"]) for d in pairs[run_id]}
    reviews: dict[str, ViewReview] = {}
    for wanted_id in sorted(wanted):
        built = build_diff_view(atlas, wanted_id)
        if built is not None:
            reviews[wanted_id] = ViewReview(atlas, built)

    out = []
    by_verdict: dict[str, int] = {}
    by_state: dict[str, int] = {}
    for r in rows:
        diff_id = of_row[r["id"]]
        review = reviews.get(diff_id) if diff_id is not None else None
        judged = review.judged.get(r["anchor_ref"]) if review is not None else None
        if _is_file_row(r):
            judged = file_judged[r["id"]]
        if judged is None:  # its diff is gone, or the anchor names none of the pair's diffs
            judged = dr.DiffAnnotation(
                anchor_ref=r["anchor_ref"],
                verdict=r["verdict"],
                basis_state=dr.ANCHOR_UNRESOLVED,
                moved={},
                source_stale=None,
                source_stale_reason="source_diff_gone",
            )
        parts = r["anchor_ref"].split("#", 2)
        state = judged.state
        row_out: dict[str, Any] = {
            "id": r["id"],
            "anchor_kind": r["anchor_kind"],
            "anchor_ref": r["anchor_ref"],
            "run_id": r["run_id"],
            "diff_id": diff_id,
        }
        if _is_file_row(r):
            row_out["run_pair"] = r["run_id"]
        out.append(
            {
                **row_out,
                "subject_kind": parts[1] if len(parts) == 3 else None,
                "verdict": r["verdict"],
                "attributed_to": r["attributed_to"],
                "rationale": r["rationale"],
                "review_state": state,
                "basis_state": judged.basis_state,
                "basis_moved": judged.moved,
                "source_stale": judged.source_stale,
                "source_stale_reason": judged.source_stale_reason,
                "verdict_basis": json.loads(r["verdict_basis"]) if r["verdict_basis"] else None,
                "updated_at": r["updated_at"],
            }
        )
        by_verdict[r["verdict"]] = by_verdict.get(r["verdict"], 0) + 1
        by_state[state] = by_state.get(state, 0) + 1
    result: dict[str, Any] = {
        "overlays": out,
        "count": len(out),
        "counts_by_verdict": by_verdict,
        "counts_by_review_state": by_state,
        "filter": {"verdict": verdict, "run_id": run_id, "anchor_kind": "diff_subject"},
        "note": _LIST_NOTE,
    }
    if run_id is not None:
        result["review_progress"] = pair_progress(atlas, run_id, pairs[run_id], reviews)
    return result


# ── progress over a whole run pair ─────────────────────────────────────────────────────────


def pair_progress(
    atlas: sqlite3.Connection,
    pair: str,
    diffs: list[dict[str, Any]],
    reviews: dict[str, ViewReview],
) -> dict[str, Any]:
    """Progress over every listed entry of every diff of one run pair, and — inseparable from it —
    what none of those entries can cover: the diffs that failed, the diffs undetermined as a whole,
    and the binaries no diff covers. ``complete`` is never true while any of the three is
    non-empty, whatever the count of entries says."""
    if not diffs:
        return {
            "unit": "entry",
            "run_pair": pair,
            "diffs": 0,
            "complete": False,
            "note": f"no diff of the run pair {pair!r} in this atlas (see list_diffs)",
        }
    run_a, run_b = diffs[0]["run_a_id"], diffs[0]["run_b_id"]
    failed_ids = {str(d["diff_id"]) for d in diffs if not d["diff_ok"]}
    items: list[dr.Item] = []
    withheld: list[dict[str, Any]] = []
    dangling: list[str] = []
    by_binary: dict[str, dict[str, int]] = {}
    for d in diffs:
        diff_id = str(d["diff_id"])
        review = reviews.get(diff_id)
        if review is None:
            continue
        if review.withheld:
            if diff_id not in failed_ids:
                withheld.append({"diff_id": diff_id, "banners": list(review.built.banners)})
            continue
        dangling += review.dangling
        mine = [
            replace(i, order=(diff_id, *i.order), diff_id=diff_id) for i in review.items.values()
        ]
        items += mine
        n = dr.counts(mine)
        by_binary[str(d["binary_a"])] = {
            "total": n["total"],
            "not_looked_at": n["not_looked_at"],
            "needs_recheck": n["states"][NEEDS_RECHECK],
        }
    blind = list_diff_blindspots(atlas, run_a, run_b)
    failed = [
        {k: b[k] for k in ("diff_id", "binary", "diff_status_reason", "diff_attempts")}
        for b in blind["blindspots"]
    ]
    blind_not_diffed, identical_not_diffed = split_not_diffed(
        not_diffed_binaries(atlas, run_a, run_b)
    )
    numbers = dr.counts(items)
    return {
        "unit": "entry",
        "run_pair": pair,
        "diffs": len(diffs),
        **numbers,
        "next_page": dr.next_page(items),
        # per diff of the pair, by its binary (the diff_id is {run_pair}::{binary})
        "by_binary": by_binary,
        "dangling_annotations": sorted(dangling),
        # binaries byte-identical on both sides: no diff was warranted, so no blind spot — kept out
        # of 'complete' and apart from the genuine not-diffed binaries below.
        "identical_not_diffed_binaries": identical_not_diffed,
        "blind_spots": {
            "failed_diffs": failed,
            "withheld_diffs": withheld,
            "not_diffed_binaries": blind_not_diffed,
            "see": (
                "list_diff_blindspots(run_a, run_b) for the failed diffs; "
                "get_diff_sink_overlay(run_a, run_b, reason='binary_not_diffed') for their "
                "candidates — note that map counts a binary identical on both sides as "
                "binary_not_diffed too, so it also lists the identical_not_diffed_binaries this "
                "block keeps separate"
            ),
        },
        "complete": (
            numbers["not_looked_at"] == 0 and not failed and not withheld and not blind_not_diffed
        ),
        "note": (
            dr.PROGRESS_NOTE
            + " Over a run pair, 'complete' also needs no failed diff, no diff undetermined as a "
            "whole, and no binary that no diff covers: entries cannot be listed for those, so "
            "having judged every listed entry does not reach them. A binary byte-identical on both "
            "sides is not one of those — it needed no diff (identical_not_diffed_binaries). "
            "next_page here is in the candidate_tier order; get_diff_patch_view names the next "
            "ones in the order its page is read in."
        ),
    }
