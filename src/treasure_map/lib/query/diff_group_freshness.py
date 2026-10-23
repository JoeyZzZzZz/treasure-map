# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Group-level freshness for a diff judgement that rested on a same-shape group.

When a judgement on one diff entry reasoned about "the other calls of this shape — they did not
change", it can record the group it leaned on (``annotate_diff``'s ``group_ref``). This module is
what stores a snapshot of that group at write time and what re-derives it on every read, so that a
member joining or leaving the group, or any member's own landing moving, puts the judgement back in
``needs_recheck`` — the same way a move in the entry's own facts already does.

READ-ONLY and DERIVED. It rides the existing basis mechanism: the snapshot lives under the ``group``
key of the judgement's ``basis_state`` (beside ``facts``), the comparison runs inside the view read
path (patch_view.ViewReview), and a move folds into ``diff_review.judge``'s ``moved`` as
``moved["group"]``. It never touches ``verdict_basis``, promotion, or the source-staleness coupling.

THE SNAPSHOT (``group_snapshot``) is the group as same_shape_siblings would count it now, reduced to
what a later read can compare cheaply: the ``group_ref`` (which carries the fingerprint and recipe
versions), the shape, the member count, the landing counts (same ``_group_counts`` S5 prints), a
short hash per member of its evidence_ref and of its own landing facts, and one summary hash over
all of that. A member's facts are the five the view reads — ``landing``, ``subclass``, ``listed``,
``similarity``, ``unreadable`` — written for every member alike, ``unreadable`` null for a member
whose row was read, so the canonical string has one reading on every implementation.

THE COMPARISON (``group_moved``) re-derives the current snapshot and reports what moved, capped so
one report never grows with the group: the ``group_ref`` changing (a fingerprint-version bump lands
here) ends it at once; an equal summary ends it as unchanged; otherwise the counts of changed,
joined and left members, the first few changed/joined members with their current facts, and the
left members by count and stored hash only (their refs were never stored in the clear). It never
raises and never reads a failure as "unchanged": a group it cannot rebuild is ``group_unreadable``,
which is itself a move.

THE RELATION CHECK (``annotate_group``) refuses a ``group_ref`` that is not actually about the entry
being judged: the group must either contain a call of the judged entry (``own_call``) or be a shape
the judged function-level candidate has (``same_shape``). A group_ref that is well-formed but about
some other entry is refused, with the groups the judged subject does belong to.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any

from treasure_map.lib.errors import ConfigError
from treasure_map.lib.query import diff_review as dr
from treasure_map.lib.query import same_shape_siblings as sss
from treasure_map.lib.query.patch_view import (
    BuiltDiff,
    _atlas_identity,
    _BoundedCache,
    build_diff_view,
    split_subject_key,
)

# The first few changed/joined members a move names, and the first few left-member hashes: a report
# is capped here so a 4,000-member group that moves whole is still one small record.
_REPORT_CAP = 5

# evidence rows of one run's binary, by (atlas, run, binary content hash, the run's instance stamp).
# The stamp is the run's instance row count and greatest instance_id: a re-hunt deletes and
# re-inserts the run's instances with fresh ids, so either number moves and the stale list is
# dropped. Reading it is one indexed aggregate (by run), far cheaper than the call list it guards.
_CALLS_CACHE: _BoundedCache[tuple[Any, ...], list[sss._Call]] = _BoundedCache(8)


def _clear_cache() -> None:
    _CALLS_CACHE.clear()


def _run_stamp(atlas: sqlite3.Connection, run_id: str) -> tuple[int, int]:
    row = atlas.execute(
        "SELECT COUNT(*), COALESCE(MAX(instance_id), 0) FROM instance WHERE source_run_id = ?",
        (run_id,),
    ).fetchone()
    return (int(row[0]), int(row[1]))


def _calls_cached(atlas: sqlite3.Connection, run_id: str, sha: str) -> list[sss._Call]:
    """``same_shape_siblings._calls`` behind the module cache (see ``_CALLS_CACHE``)."""
    key = (_atlas_identity(atlas), run_id, sha, *_run_stamp(atlas, run_id))
    hit = _CALLS_CACHE.get(key)
    if hit is not None:
        return hit
    calls = sss._calls(atlas, run_id, sha)
    _CALLS_CACHE[key] = calls
    return calls


def _h(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def _member_fact(st: sss._State) -> dict[str, Any]:
    """The five landing facts a member's hash rests on, written the same for every member: a
    read-row member carries ``unreadable`` null, never a missing key, so the canonical string is
    read one way everywhere (mirrors same_shape_siblings._member_row's readable fields)."""
    if st.view is None:
        return {
            "landing": None,
            "subclass": None,
            "listed": None,
            "similarity": None,
            "unreadable": st.unreadable,
        }
    assert st.entry is not None
    return {
        "landing": st.view["landing"],
        "subclass": st.view["subclass"],
        "listed": bool(st.entry.bucket),
        "similarity": st.entry.pair.similarity if st.entry.pair is not None else None,
        "unreadable": None,
    }


def _current(
    atlas: sqlite3.Connection,
    built: BuiltDiff,
    side: str,
    f2_key: str,
    cache: dict[tuple[str, str], Any],
) -> tuple[dict[str, Any], dict[str, tuple[str, dict[str, Any]]]] | None:
    """The current snapshot of one group and, beside it, each member's (evidence_ref, facts) keyed
    by the same evidence_ref hash the snapshot uses — so a move can name a current member. None when
    this side has no group of that shape now. ``cache`` memoises this within one view read."""
    memo = cache.get((side, f2_key))
    if memo is not None:
        return memo  # type: ignore[no-any-return]
    diff = built.diff
    run = diff.run_a if side == "a" else diff.run_b
    sha = diff.sha_a if side == "a" else diff.sha_b
    if not sha:
        raise ConfigError(f"diff records no content hash for side {side!r}")
    calls = _calls_cached(atlas, run, sha)
    members = sss._groups(calls).get(f2_key, [])
    if not members:
        cache[(side, f2_key)] = None
        return None
    states = sss._states(built, side, members)
    counts = sss._group_counts(members, states)
    member_hashes: dict[str, str] = {}
    facts: dict[str, tuple[str, dict[str, Any]]] = {}
    for c in members:
        assert c.ref is not None
        fact = _member_fact(states[c.ref])
        ref_hash = _h(c.ref)
        member_hashes[ref_hash] = _h(json.dumps(fact, sort_keys=True))
        facts[ref_hash] = (c.ref, fact)
    first = members[0]
    snap = {
        "group_ref": sss.group_ref(diff.diff_id, f2_key, side, sss._fp_version(members)),
        "side": side,
        "shape": {
            "structural_fingerprint": first.fingerprint,
            "sink_anchor": first.sink,
            "kind": first.kind,
        },
        "member_count": len(members),
        "counts": counts,
        "members": member_hashes,
        "summary": _h(
            "|".join(
                (
                    str(len(members)),
                    json.dumps(counts, sort_keys=True),
                    json.dumps(member_hashes, sort_keys=True),
                )
            )
        ),
    }
    out = (snap, facts)
    cache[(side, f2_key)] = out
    return out


def group_snapshot(
    atlas: sqlite3.Connection, built: BuiltDiff, side: str, f2_key: str
) -> dict[str, Any] | None:
    """The snapshot a judgement stores for the group it leaned on, or None when this side has no
    group of that shape now (see the module docstring for the shape of it)."""
    current = _current(atlas, built, side, f2_key, {})
    return current[0] if current is not None else None


def _member_delta(
    stored: dict[str, Any], snap: dict[str, Any], facts: dict[str, tuple[str, dict[str, Any]]]
) -> dict[str, Any]:
    stored_members = stored.get("members") or {}
    current_members = snap["members"]
    joined = [h for h in current_members if h not in stored_members]
    left = [h for h in stored_members if h not in current_members]
    changed = [
        h
        for h in current_members
        if h in stored_members and current_members[h] != stored_members[h]
    ]
    named = []
    for ref_hash in sorted(set(changed) | set(joined))[:_REPORT_CAP]:
        ref, fact = facts[ref_hash]
        named.append(
            {
                "evidence_ref": ref,
                **{k: fact[k] for k in ("landing", "subclass", "listed", "similarity")},
            }
        )
    out: dict[str, Any] = {
        "changed": len(changed),
        "joined": len(joined),
        "left": len(left),
        "members": named,
    }
    if left:
        out["left_members"] = {"count": len(left), "stored_hashes": sorted(left)[:_REPORT_CAP]}
    any_ref = next((facts[h][0] for h in current_members), None)
    if any_ref is not None:
        out["page"] = {
            "evidence_ref": any_ref,
            "members_offset": 0,
            "see": "same_shape_siblings — the group as it stands now, a page at a time",
        }
    return out


def group_moved(
    atlas: sqlite3.Connection,
    built: BuiltDiff,
    stored: dict[str, Any],
    cache: dict[tuple[str, str], Any],
) -> dict[str, Any] | None:
    """What moved in the group ``stored`` recorded, or None when nothing did. A ``group_ref`` that
    changed (a fingerprint-version bump among it) ends it; an equal summary ends it as unchanged;
    otherwise the per-member delta. Never raises: a group it cannot rebuild is a move
    (``group_unreadable``), never silently "unchanged"."""
    try:
        stored_ref = stored.get("group_ref")
        side = stored.get("side")
        f2_key = _f2_from_ref(stored_ref)
        if f2_key is None or side not in ("a", "b"):
            return {"reason": "group_unreadable", "detail": f"unreadable group_ref {stored_ref!r}"}
        current = _current(atlas, built, side, f2_key, cache)
        current_ref = current[0]["group_ref"] if current is not None else None
        if current_ref != stored_ref:
            return {"reason": "group_ref_changed", "then": stored_ref, "now": current_ref}
        assert current is not None
        snap, facts = current
        if snap["summary"] == stored.get("summary"):
            return None
        return _member_delta(stored, snap, facts)
    except Exception as exc:  # noqa: BLE001 — a group that cannot be rebuilt is a move, never a throw
        return {"reason": "group_unreadable", "detail": f"{type(exc).__name__}: {exc}"}


# ── write-time: the group_ref must be about the entry being judged ──────────────────────────


def _f2_from_ref(group_ref: Any) -> str | None:
    """The shape key inside a group_ref (``...#f2:{key}:{side}@...``), None when it is not one."""
    if not isinstance(group_ref, str) or "#f2:" not in group_ref:
        return None
    key = group_ref.split("#f2:", 1)[1].split(":", 1)[0]
    return key or None


def _parse_ref(group_ref: str) -> tuple[str, str, str, str, str] | None:
    """``(diff_id, f2_key, side, fingerprint_version, recipe_version)`` of a group_ref, or None."""
    head, sep, tail = group_ref.partition("#f2:")
    if not sep:
        return None
    key, sep2, rest = tail.partition(":")
    side, sep3, versions = rest.partition("@")
    fpv, sep4, recipe = versions.partition("/")
    if not (sep2 and sep3 and sep4 and key and side and fpv and recipe):
        return None
    return head, key, side, fpv, recipe


def _subject_side_refs(built: BuiltDiff, anchor_ref: str, side: str) -> tuple[set[str], bool]:
    """The evidence_refs the judged subject has on ``side``, and whether the anchor is a candidate.
    For an entry it is the entry's rows' refs on that side; for a candidate row it is that row's ref
    on that side."""
    diff = built.diff
    parts = dr.split_anchor(anchor_ref, diff.run_a, diff.run_b)
    if parts is None:
        return set(), False
    kind, key = parts
    if kind == "candidate":
        split = split_subject_key(key, diff.run_a, diff.run_b)
        if split is None:
            return set(), True
        _gran, _cls, a_ref, b_ref = split
        ref = a_ref if side == "a" else b_ref
        return ({ref} if ref else set()), True
    subjects = dr.subjects_of(built.placed, diff.run_a, diff.run_b, diff.binary or "")
    subject = subjects.get(anchor_ref)
    if subject is None:
        return set(), False
    refs = {(r.a_ref if side == "a" else r.b_ref) for r in subject.entry.rows}
    return {r for r in refs if r}, False


def annotate_group(
    atlas: sqlite3.Connection, diff_id: str, anchor_ref: str, group_ref: str
) -> dict[str, Any]:
    """Validate a ``group_ref`` for a judgement on ``anchor_ref`` and return the ``group`` block to
    store (the snapshot plus the ``relation`` by which it is about this entry). Raises ConfigError,
    naming the one check that failed, when the ref is not this diff's, its versions are not current,
    its shape is no current group, or the group is about some other entry.

    A thin wrapper that builds the view and the side meta once; ``annotate_group_on`` holds the
    checks, so a batch write that has already built both can reuse them (M-2)."""
    built = build_diff_view(atlas, diff_id)
    if built is None:
        raise ConfigError(f"no diff {diff_id!r} in this atlas (see list_diffs)")
    side_meta = sss._meta(atlas, diff_id)
    assert side_meta is not None  # the diff view just built
    return annotate_group_on(atlas, built, side_meta, diff_id, anchor_ref, group_ref)


def annotate_group_on(
    atlas: sqlite3.Connection,
    built: BuiltDiff,
    side_meta: sss._Meta,
    diff_id: str,
    anchor_ref: str,
    group_ref: str,
) -> dict[str, Any]:
    """``annotate_group`` against an already-built view and side meta (``_meta`` — run / sha per
    side, NOT the ``_binary_diff`` dict). Same checks, same errors."""
    parsed = _parse_ref(group_ref)
    if parsed is None:
        raise ConfigError(
            f"group_ref {group_ref!r} is not well-formed "
            "({diff_id}#f2:{key}:{side}@{fingerprint_version}/{recipe}) — copy it from a "
            "same_shape_siblings result"
        )
    g_diff, f2_key, side, fpv, recipe = parsed
    if g_diff != diff_id:
        raise ConfigError(f"group_ref names diff {g_diff!r}, but this judgement is on {diff_id!r}")
    if side not in ("a", "b"):
        raise ConfigError(f"group_ref names side {side!r}; a group is on side 'a' or 'b'")
    if recipe != sss.F2_RECIPE_VERSION:
        raise ConfigError(
            f"group_ref is of recipe {recipe!r}, but this build groups by "
            f"{sss.F2_RECIPE_VERSION!r} — read the group again and annotate against it"
        )
    run, sha = side_meta.run[side], side_meta.sha[side]
    if not sha:
        raise ConfigError(f"diff {diff_id!r} records no content hash for side {side!r}")
    calls = _calls_cached(atlas, run, sha)
    groups = sss._groups(calls)
    members = groups.get(f2_key)
    if not members:
        raise ConfigError(
            f"shape {f2_key!r} is no group on side {side!r} of diff {diff_id!r} now — read the "
            "group again (a re-scan can retire a shape)"
        )
    current_fpv = sss._fp_version(members)
    if fpv != current_fpv:
        raise ConfigError(
            f"group_ref is of fingerprint version {fpv!r}, but this build records "
            f"{current_fpv!r} for the shape — read the group again and annotate against it"
        )
    relation = _relation(built, side, f2_key, members, calls, anchor_ref)
    if relation is None:
        shapes = _subject_shapes_listing(built, side_meta, side, calls, groups, anchor_ref)
        raise ConfigError(
            f"group {group_ref!r} is not about this entry: it holds no call of it, and the shape "
            f"is not one this subject has on side {side!r}. The shapes it does have on this side: "
            f"{shapes or 'none'}"
        )
    snapshot = group_snapshot(atlas, built, side, f2_key)
    assert snapshot is not None  # members were just found
    return {**snapshot, "relation": relation}


def group_in_diff(
    atlas: sqlite3.Connection, built: BuiltDiff, side_meta: sss._Meta, item: str
) -> bool:
    """Whether ``item`` is a group_ref that names a CURRENT group of this diff — well-formed, this
    diff's, current recipe + fingerprint version, a live shape on its side. The read-only slice of
    ``annotate_group_on`` up to (not including) the ``_relation`` "about this entry" check: a
    group_ref used as a ``checked`` anchor proves a group was read, it need not be this entry's
    group. Never raises — any mismatch is False (it answers ``is_diff_anchor``, not a write)."""
    parsed = _parse_ref(item)
    if parsed is None:
        return False
    g_diff, f2_key, side, fpv, recipe = parsed
    if g_diff != diff_id_of(side_meta) or side not in ("a", "b") or recipe != sss.F2_RECIPE_VERSION:
        return False
    run, sha = side_meta.run.get(side), side_meta.sha.get(side)
    if not sha or not run:
        return False
    members = sss._groups(_calls_cached(atlas, run, sha)).get(f2_key)
    if not members:
        return False
    return fpv == sss._fp_version(members)


def diff_id_of(side_meta: sss._Meta) -> str:
    """The diff_id a side meta carries (named so ``group_in_diff`` reads clearly)."""
    return side_meta.diff_id


def _relation(
    built: BuiltDiff,
    side: str,
    f2_key: str,
    members: list[sss._Call],
    calls: list[sss._Call],
    anchor_ref: str,
) -> str | None:
    """How the group is about the judged subject: ``own_call`` when the group holds a call of it,
    ``same_shape`` when the shape is one the subject (a function-level candidate) has, else None."""
    subject_refs, _is_candidate = _subject_side_refs(built, anchor_ref, side)
    if subject_refs & {c.ref for c in members if c.ref}:
        return "own_call"
    if f2_key in {c.key for c in calls if c.ref in subject_refs and c.unkeyed is None}:
        return "same_shape"
    return None


def _subject_shapes_listing(
    built: BuiltDiff,
    meta: sss._Meta,
    side: str,
    calls: list[sss._Call],
    groups: dict[str, list[sss._Call]],
    anchor_ref: str,
) -> list[dict[str, Any]]:
    subject_refs, _is_candidate = _subject_side_refs(built, anchor_ref, side)
    mine = [c for c in calls if c.ref in subject_refs and c.unkeyed is None]
    return sss._shape_keys(meta, side, mine, groups)
