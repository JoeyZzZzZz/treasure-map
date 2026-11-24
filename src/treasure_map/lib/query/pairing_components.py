# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Pairing-correction components: where the published alternative pairings of one diff propose
pairs the diff did not make, read as pairs of their own.

The diff's pairs are never changed here (nor its storage, its sink overlay baseline, its buckets or
its significance order). An alternative pairing (lib/query/alt_pairings) on its own changes nothing
either; but one read on a PAIR entry whose target is the other side's function of ANOTHER pair entry
says those two entries were paired across each other: the entry's function belongs with the
target. That is a CLAIM (a, b): ``a`` the A-side function, ``b`` the B-side one, re-pairing the
entry ``a`` is in and the entry ``b`` is in. Either end reading it is enough; both ends reading it
are one claim (its vias and items merged).

A claim stands (``passes``) when a ``key`` or ``twin`` reading backs it; a ``string``-only claim
stands when the alternative's text ratio is above the lower of the two current pairings' ratios
(any of the three unreadable: it stands). Every pair entry the view placed takes part, listed or
not, aligned or not; an entry no longer listed can be a claim's end, never a unit's member.

The entries joined by standing claims make one COMPONENT per connected set (a shifted chain, a swap,
a cycle). A component with no conflict — no function in two claims with different counterparts —
SUPERSEDES each member entry whose two functions are both in claims a key or twin reading backs: it
stays listed and can be judged, but is no longer a must-read on its own. A string-only claim
supersedes nothing. Each standing claim is read as an ALTERNATIVE entry (``pair.state``
``alternative``, entry_id ``pair:{a}:{b}``, the usual pair anchor): its rows are the candidate rows
that fall on ``a`` (A side) or ``b`` (B side), each read ``presence_undetermined`` /
``proposed_pairing`` with the cross-side fields emptied; it is placed in no bucket and counted
nowhere, and a promotion from it is refused (the two functions are not established counterparts).

The claims and components are cached on the diff's readings key and the build's string / key
readings (they read the build's alternative pairings and the two sides' texts); the alternative
entries carry rows, which move with a re-hunt that key does not hold, so they are built afresh each
time.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

from treasure_map.lib.query import alt_pairings
from treasure_map.lib.query import diff_review as dr
from treasure_map.lib.query import patch_view as pv
from treasure_map.lib.query.sink_overlay import SinkOverlayRow, _func_entry_hex

if TYPE_CHECKING:
    from treasure_map.lib.query.patch_view import BuiltDiff, _Entry, _Readings

# The reason every row of an alternative entry carries (and its landing's subclass, R).
PROPOSED_PAIRING = pv.PROPOSED_PAIRING
ALTERNATIVE = pv.ALTERNATIVE
_STRONG = frozenset({alt_pairings.VIA_KEY, alt_pairings.VIA_TWIN})


@dataclass(frozen=True)
class Claim:
    addr_a: str
    addr_b: str
    # The two entries it re-pairs: the one ``addr_a`` is in, the one ``addr_b`` is in.
    re_pairs: tuple[str, str]
    vias: tuple[str, ...]  # both ends' vias, merged and sorted
    items: tuple[dict[str, Any], ...]  # the alternative pairings read, each with ``read_on``

    @property
    def entry_id(self) -> str:
        return f"pair:{self.addr_a}:{self.addr_b}"

    @property
    def strong(self) -> bool:
        return bool(_STRONG & set(self.vias))


@dataclass(frozen=True)
class Component:
    component_id: str  # "pc:" + sha1 of the sorted claim anchors, first 12 hex
    entries: tuple[str, ...]  # the member entries (listed or not), sorted
    claims: tuple[Claim, ...]  # the standing claims, by entry_id
    conflict: bool
    superseded: tuple[str, ...]  # empty when ``conflict``
    ends: tuple[tuple[str, str], ...]  # (side, addr) of a member's function no claim covers

    def summary(self) -> dict[str, Any]:
        """The fields a member entry carries (``pairing_correction``)."""
        return {
            "component_id": self.component_id,
            "claims": [c.entry_id for c in self.claims],
            "superseded": list(self.superseded),
            "conflict": self.conflict,
        }

    def detail(self) -> dict[str, Any]:
        """The fields an alternative entry carries: the summary, the members and the ends, and
        both ends' alternative pairings for each claim."""
        return {
            **self.summary(),
            "members": list(self.entries),
            "ends": [{"side": s, "addr": a} for s, a in self.ends],
            "claim_evidence": {c.entry_id: [dict(i) for i in c.items] for c in self.claims},
        }


# The claims and components of one diff, on its readings key, the build's callee block (which
# withholds every alternative pairing) and a digest of every placed entry's string / key readings:
# those come from the build (a re-hunt rewrites the dispatch keys), which the readings key does not
# hold.
# The bound is per diff, for the same reason as patch_view's (``_PER_DIFF``): a whole run pair is
# read diff by diff, and 32 of 126 evicted what the next pass wanted.
_PAIRING_CACHE: pv._BoundedCache[tuple[str, ...], tuple[Component, ...]] = pv._BoundedCache(
    pv._PER_DIFF
)


def clear_cache() -> None:
    _PAIRING_CACHE.clear()


def _pair_entries(built: BuiltDiff) -> list[_Entry]:
    return [e for e in built.placed if e.pair is not None]


def _claims(built: BuiltDiff, readings: _Readings) -> dict[tuple[str, str], dict[str, Any]]:
    """Every claim read on the placed pair entries, by (addr_a, addr_b), before the gate."""
    entries = _pair_entries(built)
    by_a = {e.pair.addr_a: e for e in entries if e.pair is not None}
    by_b = {e.pair.addr_b: e for e in entries if e.pair is not None}
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for e in entries:
        p = e.pair
        assert p is not None
        found = pv._alt_readings(built, readings, e)
        if found is None:
            continue
        for item in found[0]:
            target = item["target_addr"]
            if item["direction"] == "to_b":
                other = by_b.get(target)
                if other is None or other is e:
                    continue
                key, re_pairs = (p.addr_a, target), (e.entry_id, other.entry_id)
            else:
                other = by_a.get(target)
                if other is None or other is e:
                    continue
                key, re_pairs = (target, p.addr_b), (other.entry_id, e.entry_id)
            got = out.setdefault(key, {"re_pairs": re_pairs, "vias": set(), "items": []})
            got["vias"].add(str(item["via"]))
            got["items"].append({"read_on": e.entry_id, **item})
    return out


def _stands(
    built: BuiltDiff, readings: _Readings, key: tuple[str, str], claim: dict[str, Any]
) -> bool:
    """The gate: a key or twin reading, or a string-only claim whose text ratio is above the lower
    of the two current pairings' (any of the three unreadable: it stands)."""
    if _STRONG & claim["vias"]:
        return True
    by_id = {e.entry_id: e for e in _pair_entries(built)}
    x, y = (by_id[i].pair for i in claim["re_pairs"])
    assert x is not None and y is not None
    alt = pv._text_ratio(built, readings, *key)
    cur_x = pv._text_ratio(built, readings, x.addr_a, x.addr_b)
    cur_y = pv._text_ratio(built, readings, y.addr_a, y.addr_b)
    if alt is None or cur_x is None or cur_y is None:
        return True
    return alt > min(cur_x, cur_y)


def _component(built: BuiltDiff, claims: list[Claim]) -> Component:
    d = built.diff
    claims = sorted(claims, key=lambda c: c.entry_id)
    by_id = {e.entry_id: e for e in _pair_entries(built)}
    members = sorted({i for c in claims for i in c.re_pairs})
    of_a: dict[str, set[str]] = {}
    of_b: dict[str, set[str]] = {}
    for c in claims:
        of_a.setdefault(c.addr_a, set()).add(c.addr_b)
        of_b.setdefault(c.addr_b, set()).add(c.addr_a)
    conflict = any(len(v) > 1 for v in (*of_a.values(), *of_b.values()))
    strong_a = {c.addr_a for c in claims if c.strong}
    strong_b = {c.addr_b for c in claims if c.strong}
    superseded: list[str] = []
    ends: list[tuple[str, str]] = []
    for m in members:
        p = by_id[m].pair
        assert p is not None
        if not conflict and p.addr_a in strong_a and p.addr_b in strong_b:
            superseded.append(m)
        if p.addr_a not in of_a:
            ends.append(("a", p.addr_a))
        if p.addr_b not in of_b:
            ends.append(("b", p.addr_b))
    anchors = sorted(
        dr.pair_anchor(d.run_a, d.run_b, d.binary or "", c.addr_a, c.addr_b) for c in claims
    )
    digest = hashlib.sha1("\n".join(anchors).encode("utf-8"), usedforsecurity=False).hexdigest()
    return Component(
        component_id=f"pc:{digest[:12]}",
        entries=tuple(members),
        claims=tuple(claims),
        conflict=conflict,
        superseded=tuple(superseded),
        ends=tuple(sorted(ends)),
    )


def components_of(
    atlas: sqlite3.Connection, built: BuiltDiff, readings: _Readings | None = None
) -> tuple[Component, ...]:
    """The diff's pairing-correction components, ordered by their first claim. ``readings`` are
    the view's (``_pseudo_readings`` when not given). The build's pair evidence is attached first,
    as the view's reading attaches it. Empty for a withheld diff."""
    if built.withheld is not None or built.builder is None:
        return ()
    if readings is None:
        readings = pv._pseudo_readings(atlas, built)
    pv._attach_pair_evidence(atlas, built)
    anchors = sorted(
        f"{e.entry_id}|{i['via']}|{i['direction']}|{i['target_addr']}"
        for e in _pair_entries(built)
        for i in e.alt_anchor
    )
    digest = hashlib.sha256("\n".join(anchors).encode("utf-8")).hexdigest()
    key = (*readings.key, built.builder.callee_block or "", digest)
    hit = _PAIRING_CACHE.get(key)
    if hit is not None:
        return hit
    raw = _claims(built, readings)
    standing = [
        Claim(
            addr_a=a,
            addr_b=b,
            re_pairs=c["re_pairs"],
            vias=tuple(sorted(c["vias"])),
            items=tuple(
                sorted(c["items"], key=lambda i: (i["read_on"], *alt_pairings.order_key(i)))
            ),
        )
        for (a, b), c in sorted(raw.items())
        if _stands(built, readings, (a, b), c)
    ]
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        root = parent.setdefault(x, x)
        while root != parent[root]:
            root = parent[root]
        parent[x] = root
        return root

    for c in standing:
        ra, rb = find(c.re_pairs[0]), find(c.re_pairs[1])
        if ra != rb:
            parent[ra] = rb
    groups: dict[str, list[Claim]] = {}
    for c in standing:
        groups.setdefault(find(c.re_pairs[0]), []).append(c)
    comps = sorted(
        (_component(built, cl) for cl in groups.values()), key=lambda k: k.claims[0].entry_id
    )
    out = tuple(comps)
    _PAIRING_CACHE[key] = out
    return out


def _side_row(r: SinkOverlayRow, keep_a: bool, keep_b: bool) -> SinkOverlayRow:
    """The row as an alternative entry holds it: the side(s) of the claim kept, every cross-side
    field emptied, read presence_undetermined / proposed_pairing."""
    return replace(
        r,
        a_ref=r.a_ref if keep_a else None,
        b_ref=r.b_ref if keep_b else None,
        presence="presence_undetermined",
        presence_reason=PROPOSED_PAIRING,
        match_basis=None,
        counterpart_call=None,
        alignment_confidence=None,
        counterpart_callee=None,
        coclaimed_by=r.coclaimed_by if keep_a else None,
        a_n=r.a_n if keep_a else None,
        coclaimed_by_b=r.coclaimed_by_b if keep_b else None,
        b_n=r.b_n if keep_b else None,
    )


def _rows_of(built: BuiltDiff, a: str, b: str) -> list[SinkOverlayRow]:
    """The diff's candidate rows that fall on ``a`` (by their A-side ref) or on ``b`` (by their
    B-side ref) — by the function the ref names, wherever the row was placed — each with only the
    claim's side(s) kept."""
    out = []
    for r in built.overlay.rows:
        on_a = bool(r.a_ref) and _func_entry_hex(r.a_ref or "") == a
        on_b = bool(r.b_ref) and _func_entry_hex(r.b_ref or "") == b
        if on_a or on_b:
            out.append(_side_row(r, on_a, on_b))
    return out


def alternative_entries(
    atlas: sqlite3.Connection,
    built: BuiltDiff,
    components: tuple[Component, ...],
    readings: _Readings | None = None,
) -> tuple[_Entry, ...]:
    """One alternative entry per standing claim, built afresh (its rows move with a re-hunt): the
    names, export gaps and markup each side's function has in the pairing it is in now, no
    confidence / similarity / instruction count, the claim's rows, the callee lists and sink counts
    of the two functions read as a pair, and ``pairing_correction`` (the component's detail). Its
    text reading is read too (``_alternative_reads``), so it renders as an aligned pair's does."""
    bld = built.builder
    if not components or bld is None:
        return ()
    if readings is None:
        readings = pv._pseudo_readings(atlas, built)
    by_id = {e.entry_id: e for e in _pair_entries(built)}
    out: list[_Entry] = []
    for comp in components:
        detail = comp.detail()
        for c in comp.claims:
            x, y = by_id[c.re_pairs[0]].pair, by_id[c.re_pairs[1]].pair
            assert x is not None and y is not None
            p = pv._Pair(
                addr_a=c.addr_a,
                addr_b=c.addr_b,
                name_a=x.name_a,
                name_b=y.name_b,
                confidence=None,
                similarity=None,
                state=ALTERNATIVE,
                export_gap_a=x.export_gap_a,
                export_gap_b=y.export_gap_b,
                instructions=None,
                markup_a=x.markup_a,
                markup_b=y.markup_b,
            )
            e = pv._Entry(pair=p, unpaired=None, rows=_rows_of(built, c.addr_a, c.addr_b))
            e.row_views = [bld._row_view(r, e) for r in e.rows]
            if e.rows:
                e.tier = bld._tier(e.rows)
            e.callee_set = bld._callee_comparison(p)
            e.sink_candidate_counts = bld._sink_candidate_counts_for(
                p.addr_a, p.addr_b, ALTERNATIVE
            )
            e.sink_callsite_counts = bld._sink_callsite_counts_for(p.addr_a, p.addr_b, ALTERNATIVE)
            # A fixed rank: it orders a page of one; it takes part in no order.
            e.rank = {"pairing_correction": comp.component_id}
            e.pairing_correction = detail
            out.append(e)
    reads = pv._alternative_reads(readings, [e.pair for e in out if e.pair is not None])
    for e in out:
        assert e.pair is not None
        read = reads.get((e.pair.addr_a, e.pair.addr_b))
        if read is not None:
            e.body_status, e.sizes = read.bodies, read.sizes
    return tuple(out)


def mark_members(built: BuiltDiff, components: tuple[Component, ...]) -> None:
    """Set ``pairing_correction`` (the component's summary) on every placed member entry."""
    by_id = {e.entry_id: e for e in built.placed}
    for comp in components:
        summary = comp.summary()
        for m in comp.entries:
            if m in by_id:
                by_id[m].pairing_correction = summary


def corrections(
    atlas: sqlite3.Connection, built: BuiltDiff, readings: _Readings | None = None
) -> tuple[tuple[Component, ...], tuple[_Entry, ...]]:
    """The diff's components and alternative entries, its member entries marked."""
    if readings is None and built.withheld is None:
        readings = pv._pseudo_readings(atlas, built)
    comps = components_of(atlas, built, readings)
    mark_members(built, comps)
    return comps, alternative_entries(atlas, built, comps, readings)
