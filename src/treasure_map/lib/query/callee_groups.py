# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Callee groups: the changed function pairs of one diff that newly call the same function.

A group is keyed by one B-side function X. Its members are the listed PAIRED entries (a function
in no pair has no A side to compare, so it is never a member) whose B function calls X while
their A function does not call X's counterpart — the A function the diff pairs X with (an
undetermined pairing too); an X in no pair has none, so every caller of it is a member. A member
whose A call list cannot be read is kept (its entry id is recorded in ``members_a_side_unread``,
and surfaced to the reader so "newly calls X" is not claimed for it): it cannot rule X
out, and a group is never dropped for it. X must be defined in the binary — one function of that
name on the B side, not a thunk — and is no key when its own entry is a function in no pair whose
counterpart may exist (``counterpart_suspected``): what looks new may be only unpaired.

A read of the facts only (callee lists by name, the alignment, the listed entries): nothing is
stored. ``members_possibly_incomplete`` marks every group of a B side where some function's callee
list was cut at its cap — a member may be missing. Used by the pair review (a group unit hands its
must-read members out together, X's two sides read once) and by the group freshness of a judgement
that leaned on one (``group_ref`` = ``{diff_id}#callee:{X}@callee-v1``).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field
from typing import Any

from treasure_map.lib.query import diff_review as dr

CALLEE_GROUP_VERSION = "callee-v1"
_SUSPECTED = "counterpart_suspected"


def group_ref(diff_id: str, callee_b: str) -> str:
    return f"{diff_id}#callee:{callee_b}@{CALLEE_GROUP_VERSION}"


def parse_ref(ref: Any) -> tuple[str, str, str] | None:
    """``(diff_id, callee_b, version)`` of a callee group_ref, or None when it is not one."""
    if not isinstance(ref, str) or "#callee:" not in ref:
        return None
    diff_id, _sep, tail = ref.partition("#callee:")
    callee, sep, version = tail.partition("@")
    if not (diff_id and callee and sep and version):
        return None
    return diff_id, callee, version


def is_callee_ref(ref: Any) -> bool:
    return parse_ref(ref) is not None


@dataclass
class CalleeGroup:
    diff_id: str
    callee_b: str
    callee_name: str
    callee_a: str | None  # X's aligned A-side function, when it has one
    members: list[str] = field(default_factory=list)  # entry ids, in listing order
    members_possibly_incomplete: bool = False
    # entry ids of members whose A call list could not be read, so "newly calls X" is UNCONFIRMED
    # for them (kept as members, never dropped). A list, not a count, so the reader can be shown
    # WHICH members carry the caveat — not merely how many.
    members_a_side_unread: list[str] = field(default_factory=list)

    @property
    def ref(self) -> str:
        return group_ref(self.diff_id, self.callee_b)


def _thunks(atlas: sqlite3.Connection, run_id: str, sha: str | None) -> frozenset[str]:
    from treasure_map.lib.diff.layer0 import _thunk_spans
    from treasure_map.lib.ro_db import ro_connect

    row = atlas.execute("SELECT analysis_db_path FROM run WHERE run_id = ?", (run_id,)).fetchone()
    if row is None or not row[0] or not sha:
        return frozenset()
    try:
        conn = ro_connect(row[0])
    except sqlite3.Error:
        return frozenset()
    try:
        if "thunk_spans" not in {r[1] for r in conn.execute("PRAGMA table_info(binaries)")}:
            return frozenset()
        got = conn.execute("SELECT thunk_spans FROM binaries WHERE sha256 = ?", (sha,)).fetchone()
        return frozenset(_thunk_spans(got[0] if got else None))
    except sqlite3.Error:
        return frozenset()
    finally:
        conn.close()


def callee_groups(
    atlas: sqlite3.Connection, built: Any, entries: list[Any]
) -> dict[str, CalleeGroup]:
    """Every callee group of one built diff with at least two members, keyed by X's B address.
    ``entries`` are the listed entries (patch_view.listed_view); their order is the members'."""
    builder = getattr(built, "builder", None)
    if builder is None or built.withheld is not None:
        return {}
    side_a, side_b = builder.sides["a"], builder.sides["b"]
    if side_a.error is not None or side_b.error is not None:
        return {}
    d = built.diff
    # X's counterpart: the A function the diff pairs it with (an undetermined pairing too —
    # if the A side calls that, X may well not be new).
    to_a = {p.addr_b: p.addr_a for p in d.pairs}
    thunks = _thunks(atlas, d.run_b, d.sha_b)
    cut = any(raw[2] for raw in side_b.raw.values() if len(raw) > 2)
    suspected = {
        e.unpaired.addr
        for e in entries
        if e.unpaired is not None
        and e.unpaired.side == "b"
        and e.unpaired.presence_state == _SUSPECTED
    }
    groups: dict[str, CalleeGroup] = {}
    for e in entries:
        p = e.pair
        if p is None:
            continue
        fb, fa = side_b.fn(p.addr_b), side_a.fn(p.addr_a)
        if fb is None or fb.callees is None:
            continue  # no B call list: nothing names X
        # An A side whose call list cannot be read cannot rule X out: the entry is a member, and
        # the group records it apart (members_a_side_unread) — never a drop, never a claim.
        a_unread = fa is None or fa.callees is None
        a_calls = set() if a_unread else set(fa.callees or ())
        for name in dict.fromkeys(fb.callees):
            addrs = side_b.by_name.get(name) or []
            if len(addrs) != 1:
                continue  # not defined here, or not one function: no key
            x = addrs[0]
            if x == p.addr_b or x in thunks or x in suspected:
                continue
            xa = to_a.get(x)
            if xa is not None and side_a.names.get(xa) in a_calls:
                continue  # the A side calls X's counterpart: not new
            g = groups.get(x)
            if g is None:
                g = groups[x] = CalleeGroup(d.diff_id, x, name, xa, members_possibly_incomplete=cut)
            if e.entry_id not in g.members:
                g.members.append(e.entry_id)
                if a_unread:
                    g.members_a_side_unread.append(e.entry_id)
    return {x: g for x, g in groups.items() if len(g.members) >= 2}


# ── the snapshot a judgement leaning on a group stores, and what moved since ────────────────


def _h(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def snapshot(group: CalleeGroup, entries: list[Any]) -> dict[str, Any]:
    """The group as a judgement stores it: its ref, X, each member's entry facts hashed, and one
    summary hash (S6's shape, for a callee group)."""
    by_id = {e.entry_id: e for e in entries}
    members = {
        _h(m): _h(json.dumps(dr.entry_facts(by_id[m]), sort_keys=True, default=str))
        for m in group.members
        if m in by_id
    }
    return {
        "group_ref": group.ref,
        "kind": "callee",
        "callee": {"b": group.callee_b, "a": group.callee_a, "name": group.callee_name},
        "member_count": len(members),
        "members": members,
        "members_possibly_incomplete": group.members_possibly_incomplete,
        "members_a_side_unread": group.members_a_side_unread,
        "summary": _h(json.dumps(members, sort_keys=True)),
    }


def moved(stored: dict[str, Any], current: dict[str, Any] | None) -> dict[str, Any] | None:
    """What moved in a callee group since ``stored``: None when nothing did; the group gone when
    it no longer stands; else the member counts that changed, joined and left."""
    if current is None:
        return {"reason": "group_gone", "then": stored.get("group_ref")}
    if current.get("summary") == stored.get("summary"):
        return None
    then, now = stored.get("members") or {}, current["members"]
    return {
        "changed": sum(1 for h in now if h in then and now[h] != then[h]),
        "joined": sum(1 for h in now if h not in then),
        "left": sum(1 for h in then if h not in now),
    }
