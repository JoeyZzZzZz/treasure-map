# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""What a judgement's answer points to, read when it is written: facts the view already holds or
another read-only tool computes, attached to the write's answer. Nothing here is stored, and
nothing here moves a judgement, its review state, a bucket, an attention or an order.

``other_direction`` — on a judgement of ANY diff verdict about an entry of a binary diff: how many
of the entry's candidate rows carry a ref on the A side only, and how many on the B side only,
with the call that reads them (the entry by its ``entry_id``, its rows paged by ``rows_offset``).
Both directions are always given, the same way. It counts the rows the view holds (each row's
``a_ref`` / ``b_ref``); it says nothing of what a one-sided row means — a row with a ref on one
side only is not a call gone or new (the view never says that: a function with no counterpart is
``function_unmatched``, a call seen on one side of a matched pair ``presence_undetermined``). An
entry with no such row, or an anchor that is no entry of a binary diff, gets
``other_direction_unavailable`` with why, never nothing.

``same_shape`` — on a ``changed_real`` whose ``change_kind`` names ``sink_removed`` or
``sink_replaced``, unless the judgement already leaned on a same-shape group (a ``group_ref`` of
that kind; a callee group's does not count): for each of the entry's candidate rows with an A-side
ref at a call's own address, that call's same-shape group in this diff (lib/query/
same_shape_siblings) — ``group_ref``, ``member_count``, ``by_landing`` — once per group, with the
group's members outside this diff across the run pair (``members_outside_input_diff``) and the two
calls that read it. Where a member landed is its own diff's answer: no ``by_landing`` is given
across the run pair. Computed for at most ``SAME_SHAPE_SECONDS`` per write call (a group already
begun finishes); the groups left are ``same_shape_deferred`` with their calls. A row with only a
function-level ref (no call address of its own) is no group's member: an entry with no other row
gets ``same_shape_unavailable`` with why.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Any

from treasure_map.lib.query import diff_review as dr

# The change kinds whose judgement is told the same-shape groups of its calls.
SAME_SHAPE_KINDS = frozenset({"sink_removed", "sink_replaced"})
# How long one write call (one judgement or one batch) spends on same-shape groups.
SAME_SHAPE_SECONDS = 10.0
# A same-shape group's ref holds this; a callee group's does not.
_SAME_SHAPE_GROUP_MARK = "#f2:"


def entry_subject(
    atlas: sqlite3.Connection, built: Any, meta: dict[str, Any], anchor_ref: str
) -> dr.Subject | None:
    """The subject ``anchor_ref`` names in a built diff's listed view (an entry, or a candidate
    row of one), or None."""
    from treasure_map.lib.query.patch_view import listed_view

    entries = listed_view(atlas, built).entries
    subjects = dr.subjects_of(entries, meta["run_a_id"], meta["run_b_id"], meta["binary_a"])
    return subjects.get(anchor_ref)


def other_direction(diff_id: str | None, subject: dr.Subject | None, why: str) -> dict[str, Any]:
    """``{"other_direction": {...}}`` for an entry holding a row with a ref on one side only, else
    ``{"other_direction_unavailable": why}`` (``why`` says why there is no entry when
    ``subject`` is None)."""
    if subject is None or subject.entry is None or diff_id is None:
        return {"other_direction_unavailable": why}
    e = subject.entry
    views = e.row_views
    a_only = sum(1 for v in views if v.get("a_ref") and not v.get("b_ref"))
    b_only = sum(1 for v in views if v.get("b_ref") and not v.get("a_ref"))
    if not views:
        return {"other_direction_unavailable": "the entry has no candidate row"}
    if a_only == 0 and b_only == 0:
        return {
            "other_direction_unavailable": (
                f"each of the entry's {len(views)} candidate rows has a ref on both sides"
            )
        }
    return {
        "other_direction": {
            "a_side_only_rows": a_only,
            "b_side_only_rows": b_only,
            "read_with": (
                f"get_diff_patch_view(diff_id={json.dumps(diff_id)}, "
                f"entry_id={json.dumps(e.entry_id)}, rows_offset=0)"
            ),
        }
    }


def wants_same_shape(verdict: str, basis: dict[str, Any] | None, group_ref: str | None) -> bool:
    """Whether a judgement is told its calls' same-shape groups (see the module docstring)."""
    if verdict != "changed_real":
        return False
    kinds = (basis or {}).get("change_kind")
    if isinstance(kinds, str):
        kinds = [kinds]
    if not isinstance(kinds, list) or not SAME_SHAPE_KINDS & set(kinds):
        return False
    return not (isinstance(group_ref, str) and _SAME_SHAPE_GROUP_MARK in group_ref)


@dataclass
class SameShapePass:
    """What one write call (one judgement, or every item of a batch) reads its same-shape groups
    through: the reads shared by its calls, the groups already computed by group_ref (each group
    once), how many groups were computed, and the call's deadline."""

    build_hash: str | None
    current: Any
    commit: str
    seconds: float = SAME_SHAPE_SECONDS
    started: float = field(default_factory=time.monotonic)
    groups: dict[str, dict[str, Any]] = field(default_factory=dict)
    computed: int = 0
    reads: Any = None
    sides: dict[tuple[str, str], dict[str, list[Any]]] = field(default_factory=dict)

    def over(self) -> bool:
        return time.monotonic() - self.started >= self.seconds


def _read_with(diff_id: str, pair: str, ref: str) -> dict[str, str]:
    return {
        "one_diff": f"same_shape_siblings(diff_id={json.dumps(diff_id)}, evidence_ref="
        f"{json.dumps(ref)})",
        "run_pair": f"same_shape_siblings(diff_id={json.dumps(pair)}, evidence_ref="
        f"{json.dumps(ref)})",
    }


def _group_of(
    atlas: sqlite3.Connection, ss: SameShapePass, diff_id: str, ref: str, sink_class: str
) -> str | None:
    """The one-diff group_ref of the A-side call ``ref`` (of ``sink_class``) — read from the side's
    calls, cheaply, so a group already computed is not computed again — or None when the call is
    no single group's member (a function-level ref, no shape, several shapes)."""
    from treasure_map.lib.query import same_shape_siblings as sss

    meta = sss._meta(atlas, diff_id)
    if meta is None or not meta.sha["a"]:
        return None
    side = (meta.run["a"], meta.sha["a"])
    calls = ss.reads.side_calls(atlas, *side)
    if side not in ss.sides:
        ss.sides[side] = sss._groups(calls)
    keys = {
        c.key
        for c in calls
        if c.ref == ref
        and c.sink_class == sink_class
        and c.unkeyed is None
        and c.granularity in sss.MEMBER_GRANULARITIES
    }
    if len(keys) != 1:
        return None
    (key,) = keys
    members = ss.sides[side].get(key) or []
    return sss.group_ref(diff_id, key, "a", sss._fp_version(members))


def same_shape(
    atlas: sqlite3.Connection, diff_id: str, subject: dr.Subject | None, ss: SameShapePass
) -> dict[str, Any]:
    """The ``same_shape`` block of one judgement (see the module docstring): ``{"same_shape":
    {"groups": [...]}}``, with ``same_shape_deferred`` beside it when the call's time ran out, or
    ``{"same_shape_unavailable": why}``."""
    from treasure_map.lib.query import same_shape_siblings as sss

    if subject is None or subject.entry is None:
        return {"same_shape_unavailable": "the anchor names no entry of a binary diff"}
    if ss.reads is None:
        ss.reads = sss.SameShapeReads()
    run_a, run_b = diff_id.split("::")[:2]
    pair = dr.run_pair(run_a, run_b)
    e = subject.entry
    rows = list(zip(e.rows, e.row_views, strict=True))
    if subject.row_view is not None:  # a candidate subject: its own row only
        rows = [(r, v) for r, v in rows if v is subject.row_view]
    if not rows:
        return {"same_shape_unavailable": "the entry has no candidate row"}
    with_a = [(r, v) for r, v in rows if r.a_ref]
    if not with_a:
        return {"same_shape_unavailable": "no candidate row of the entry has an A-side ref"}
    groups: list[dict[str, Any]] = []
    deferred: list[dict[str, Any]] = []
    seen: set[str] = set()
    not_member = 0
    for r, _v in with_a:
        assert r.a_ref is not None
        gref = _group_of(atlas, ss, diff_id, r.a_ref, r.sink_class)
        if gref is None:
            not_member += 1
            continue
        if gref in seen:
            continue
        seen.add(gref)
        if gref not in ss.groups:
            if ss.over():
                deferred.append(
                    {"group_ref": gref, "read_with": _read_with(diff_id, pair, r.a_ref)}
                )
                continue
            ss.groups[gref] = _compute(atlas, ss, diff_id, pair, run_a, run_b, r)
            ss.computed += 1
        groups.append(ss.groups[gref])
    out: dict[str, Any] = {}
    if groups:
        out["same_shape"] = {"groups": groups}
    if deferred:
        out["same_shape_deferred"] = {
            "groups": deferred,
            "why": f"the write call's {ss.seconds:g} s for same-shape groups ran out",
        }
    if not out:
        out["same_shape_unavailable"] = (
            f"none of the entry's {not_member} candidate rows with an A-side ref is a same-shape "
            "group's member (a function-level ref, or no single shape): see same_shape_siblings' "
            "not_a_member"
        )
    return out


def _compute(
    atlas: sqlite3.Connection,
    ss: SameShapePass,
    diff_id: str,
    pair: str,
    run_a: str,
    run_b: str,
    r: Any,
) -> dict[str, Any]:
    """One group's entry in ``same_shape``: the one-diff group object's counts, and the run
    pair's members outside this diff."""
    from treasure_map.lib.query import same_shape_siblings as sss
    from treasure_map.lib.query.sink_overlay import _subject_key

    anchor = dr.candidate_anchor(run_a, run_b, _subject_key(r))
    stamps = {"build_hash": ss.build_hash, "current": ss.current, "commit": ss.commit}
    one = sss.same_shape_siblings(atlas, diff_id, candidate_anchor=anchor, reads=ss.reads, **stamps)
    entry: dict[str, Any] = {"read_with": _read_with(diff_id, pair, r.a_ref)}
    if "error" in one or one.get("not_a_member"):
        entry["unavailable"] = one.get("error") or "not_a_member"
        return entry
    entry.update(
        {
            "group_ref": one.get("group_ref"),
            "member_count": one.get("member_count"),
            "by_landing": one.get("by_landing"),
        }
    )
    whole = sss.same_shape_siblings(atlas, pair, candidate_anchor=anchor, **stamps)
    if "error" in whole:
        entry["members_outside_input_diff"] = None
        entry["run_pair_unavailable"] = whole["error"]
    else:
        entry["members_outside_input_diff"] = whole.get("members_outside_input_diff")
    return {k: entry[k] for k in _GROUP_KEYS if k in entry}


_GROUP_KEYS = (
    "group_ref",
    "member_count",
    "by_landing",
    "members_outside_input_diff",
    "run_pair_unavailable",
    "unavailable",
    "read_with",
)


def withhold_by_landing(block: dict[str, Any]) -> dict[str, Any]:
    """A ``same_shape`` block cut to what an answer near its byte budget keeps: each group's ref,
    member count and calls, ``by_landing_withheld``."""
    groups = [
        {k: g[k] for k in ("group_ref", "member_count", "read_with") if k in g}
        for g in block.get("groups", [])
    ]
    return {"groups": groups, "by_landing_withheld": True}
