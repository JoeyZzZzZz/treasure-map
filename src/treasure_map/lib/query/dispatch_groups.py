# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Dispatch-table groups: a NAVIGATION grouping of a pair's must-read entries by the string-keyed
edge that names their function, moving nothing.

Two groupings, both read from the atlas ``string_keyed_edge`` table (an ENUMERATED EDGE, a stored
fact — never a reachability verdict; see ``atlas_schema.sql`` ★IRON LAW):

* ``static_string_table`` — an entry is a member when its function entry (on a side) is the stored
  handler of a key in a recovered ``{string_ptr, func_ptr}`` table of that side's binary. The two
  sides' tables are aligned by key-set overlap (>= 50% of the smaller key set), one table to one;
  the group is the aligned table (``table_addr`` on each side). A table stored as split by an
  undefined handler is one piece of a table: a piece left unaligned joins the group of the other
  side's table it overlaps by that same measure, even when that table is aligned to another piece,
  so a table cut into pieces on one side and whole on the other is one group (its pieces listed per
  side). The key is only a member label.
* ``strcmp_gate`` — an entry is a member when its function entry is the callee of a same-variable
  ``strcmp`` ladder; the group is the aligned dispatch FUNCTION (``from_func_addr``), the two sides'
  dispatch functions aligned by a function pairing whose state is ``aligned`` (an undetermined
  pairing joins nothing). The gating key is only a member label.

Each side is read on its own: a member's keys are given per side (``{"a": [...], "b": [...]}``, an
empty list = that side's enumeration names no key for it), and a group whose other side enumerates
nothing for it — no aligned table, or an aligned dispatch function with no stored gate edge — has
that side's anchor null and ``counterpart_enumerates`` false (with the aligned function, when there
is one, as ``counterpart``). One side enumerated is never shown as both.

This reads the STORED enumeration only; it never reads a call edge of the dispatch and never claims
the handler is routed to or reachable. An entry named by no recovered table or gate falls to an
explicit UNCOVERED bucket, counted per side by the static-table detector's ``detector_scan_status``
(the atlas row stored beside the edges), so "not enumerated" is never read as "not dispatched".

The static tables are read here from the hunt-flattened atlas ``string_keyed_edge`` rows (by run
and binary path, per table address). The patch view reads the same detector's output another way —
from that run's analysis.db ``string_tables`` by binary hash, a key over all the binary's tables,
kept only when it has exactly one handler — so the two readings can differ on a key; neither is
rewritten to match the other.

Only a grouping: the units, the must-read set, the unit ids and the order are untouched; an entry
that joins a group also stays in whatever unit held it (ENTRY / S_BATCH / SECOND_TIER / callee
GROUP). An entry can be in a callee group AND a dispatch group at once. It is read on demand
(``review_pair(..., navigation=True)``), not on every reading of a pair.
"""

from __future__ import annotations

import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from treasure_map.lib.diff.layer0 import norm_hex

DISPATCH_GROUP_VERSION = "dispatch-v1"
STATIC, GATE = "static_string_table", "strcmp_gate"
_SPLIT = "split_by_undefined_handler"
SIDES = ("a", "b")

# Code-authored wording, kept apart so the neutrality test can scan it (firmware key labels and
# addresses are DATA, never scanned). It describes the stored MECHANISM only — the enumerated edge —
# and carries no reachability or verdict word (see the ★IRON LAW in atlas_schema.sql).
MECHANISM_NOTE = (
    "A navigation grouping by the enumerated string-keyed edge that names each entry's function (a "
    "stored fact); an entry named by no recovered table or gate is simply not enumerated here."
)
NOTE_STATIC = "stored as the handler of a key in this table"
NOTE_GATE = "gated by a key in this function"
_UNCOVERED_NOTE = (
    "no recovered table or gate enumerates these entries; each side is counted by the static-table "
    "detector's scan status of that side's binary"
)
DETECTOR_NOTE = (
    "scanned_no_static_table_found holds only within supported_scope, never 'no table'; the "
    "strcmp-gate detector records no scan status"
)
# Rendered by the report file only (the MCP answer's tool description says the same).
COUNTERPART_NOTE = (
    "a null side: that side's stored enumeration names nothing for this group (counterpart is the "
    "aligned function there, if any)"
)
# The code-authored strings the neutrality test scans, and the words it forbids in them.
NEUTRAL_TEXTS = (
    MECHANISM_NOTE,
    NOTE_STATIC,
    NOTE_GATE,
    _UNCOVERED_NOTE,
    DETECTOR_NOTE,
    COUNTERPART_NOTE,
)
# The uncovered buckets, as named in the block (scanned by the neutrality test too).
BUCKETS = (
    "static_table_detector_did_not_run",
    "static_table_scan_capped",
    "binary_has_edges_entry_not_a_member",
    "scanned_no_static_table_found",
)


def group_ref(diff_id: str, mechanism: str, anchor: str) -> str:
    """A dispatch group's cross-call ref. ``anchor`` is the A-side table/dispatcher address when the
    group has an A side, else ``b:<addr>``."""
    return f"{diff_id}#dispatch:{mechanism}:{anchor}@{DISPATCH_GROUP_VERSION}"


@dataclass(frozen=True)
class MemberRef:
    """One must-read diff entry, with the per-side function addresses parsed from its entry_id."""

    diff_id: str
    entry_id: str
    anchor_ref: str
    unit_kind: str
    addr_a: str | None
    addr_b: str | None


def _no_keys() -> dict[str, list[str]]:
    return {"a": [], "b": []}


@dataclass
class DispatchGroup:
    mechanism: str
    diff_id: str
    binary: str | None
    a_anchor: str | None  # table_addr / dispatcher addr on the A side (None = nothing enumerated)
    b_anchor: str | None
    # a one-sided gate group: the aligned function on the side that enumerates nothing (or None)
    counterpart: str | None = None
    # entry_id -> per side, the sorted key labels by which this member is in the group
    members: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    member_anchors: dict[str, str] = field(default_factory=dict)
    completeness_reasons: set[str] = field(default_factory=set)
    # a static group: per side, every table of that side that joins it (more than one = the pieces
    # of a table split by an undefined handler); empty for a gate group
    pieces: dict[str, list[str]] = field(default_factory=_no_keys)

    @property
    def split_by_undefined_handler(self) -> bool:
        return _SPLIT in self.completeness_reasons

    @property
    def counterpart_enumerates(self) -> bool:
        """Whether both sides' stored enumerations name this group."""
        return self.a_anchor is not None and self.b_anchor is not None

    @property
    def ref(self) -> str:
        return group_ref(self.diff_id, self.mechanism, self.a_anchor or f"b:{self.b_anchor}")


@dataclass
class PairDispatch:
    """The dispatch groups of one pair, with every grouped member and the uncovered bucket."""

    run_a: str
    run_b: str
    groups: list[DispatchGroup]
    # entry_id (with diff) -> set of mechanisms it is grouped under
    member_mechanisms: dict[tuple[str, str], set[str]]
    grouped_members: int
    also_in_callee_group: int
    uncovered: list[MemberRef]
    # side -> bucket -> members (each uncovered member counted once on each side it has a function)
    uncovered_by_detector: dict[str, dict[str, int]]
    detector_statuses: dict[tuple[str, str], dict[str, Any] | None]


# ── parsing an entry_id into its per-side addresses ────────────────────────────────────────────


def _parse_entry_id(entry_id: str) -> tuple[str | None, str | None]:
    """``pair:<A>:<B>`` -> (A, B); ``a:<addr>`` / ``b:<addr>`` -> one side; both normalized hex."""
    parts = entry_id.split(":")
    if parts[0] == "pair" and len(parts) == 3:
        return norm_hex(parts[1]), norm_hex(parts[2])
    if parts[0] in ("a", "b") and len(parts) == 2:
        addr = norm_hex(parts[1])
        return (addr, None) if parts[0] == "a" else (None, addr)
    return None, None


def members_from_units(units: list[Any]) -> list[MemberRef]:
    """The must-read diff ENTRY members of a pair's units (each in exactly one unit), with the per
    side addresses and the kind of the unit holding them (``callee_group`` for a callee group)."""
    out: list[MemberRef] = []
    for u in units:
        for m in u.members:
            if m.kind != "entry" or not m.must_read or not m.entry_id:
                continue
            addr_a, addr_b = _parse_entry_id(m.entry_id)
            out.append(MemberRef(m.stream, m.entry_id, m.anchor_ref, u.kind, addr_a, addr_b))
    return out


# ── reading the enumerated edges and the detector status (both atlas) ──────────────────────────


def _reasons(reason: str | None) -> set[str]:
    """A stored ``completeness_reason``: a comma-joined set (the extractor joins its reasons)."""
    return {r.strip() for r in (reason or "").split(",") if r.strip()}


def _diff_meta(atlas: sqlite3.Connection, run_a: str, run_b: str) -> dict[str, dict[str, Any]]:
    cur = atlas.execute(
        "SELECT diff_id, binary_a, sha256_a, sha256_b, binary_path_a, binary_path_b "
        "FROM diff_meta WHERE run_a_id = ? AND run_b_id = ?",
        (run_a, run_b),
    )
    cols = [c[0] for c in cur.description]
    return {r[0]: dict(zip(cols, r, strict=True)) for r in cur.fetchall()}


def _static_tables(
    atlas: sqlite3.Connection, run_id: str, paths: set[str]
) -> dict[str, dict[str, dict[str, Any]]]:
    """``binary_path -> table_addr -> {"handlers": {callee_addr}, "keys": {callee_addr: [keys]},
    "reasons": {reason}}`` for the recovered static tables of this run's listed binaries."""
    out: dict[str, dict[str, dict[str, Any]]] = defaultdict(lambda: defaultdict(_new_table))
    if not paths:
        return out
    placeholders = ",".join("?" * len(paths))
    rows = atlas.execute(
        "SELECT binary_path, table_addr, key, callee_addr, completeness_reason "
        "FROM string_keyed_edge WHERE mechanism = ? AND source_run_id = ? "
        f"AND binary_path IN ({placeholders})",
        (STATIC, run_id, *sorted(paths)),
    )
    for path, table_addr, key, callee_addr, reason in rows:
        if key is None or not callee_addr:
            continue
        t = out[path][str(table_addr)]
        ca = norm_hex(callee_addr)
        t["handlers"].add(ca)
        t["keys"].setdefault(ca, []).append(key)
        t["reasons"] |= _reasons(reason)
    return out


def _new_table() -> dict[str, Any]:
    return {"handlers": set(), "keys": {}, "reasons": set()}


def _gates(
    atlas: sqlite3.Connection, run_id: str, paths: set[str]
) -> dict[str, dict[str, dict[str, dict[str, Any]]]]:
    """``binary_path -> callee_addr -> from_func_addr -> {"keys": [keys], "reasons": {reason}}``:
    the enumerated strcmp-gate edges (the callee is the gated function, the from-function the
    dispatch function)."""
    out: dict[str, dict[str, dict[str, dict[str, Any]]]] = defaultdict(
        lambda: defaultdict(lambda: defaultdict(_new_gate))
    )
    if not paths:
        return out
    placeholders = ",".join("?" * len(paths))
    rows = atlas.execute(
        "SELECT binary_path, callee_addr, from_func_addr, key, completeness_reason "
        "FROM string_keyed_edge WHERE mechanism = ? AND source_run_id = ? "
        f"AND binary_path IN ({placeholders})",
        (GATE, run_id, *sorted(paths)),
    )
    for path, callee_addr, from_func_addr, key, reason in rows:
        ca, ffa = norm_hex(callee_addr), norm_hex(from_func_addr)
        if ca is None or ffa is None:
            continue
        g = out[path][ca][ffa]
        if key is not None:
            g["keys"].append(key)
        g["reasons"] |= _reasons(reason)
    return out


def _new_gate() -> dict[str, Any]:
    return {"keys": [], "reasons": set()}


def _dispatchers(gates: dict[str, dict[str, dict[str, Any]]]) -> set[str]:
    """The dispatch functions of one binary's gate edges (every stored ``from_func_addr``)."""
    return {ffa for by_ffa in gates.values() for ffa in by_ffa}


def _alignment(
    atlas: sqlite3.Connection, diff_ids: set[str]
) -> dict[str, dict[str, dict[str, str]]]:
    """``diff_id -> {"a2b": {addr_a: addr_b}, "b2a": {addr_b: addr_a}}``: the function pairing whose
    state is ``aligned``, so a dispatch function on one side is aligned to its counterpart on the
    other. An undetermined pairing is no alignment and joins nothing."""
    out: dict[str, dict[str, dict[str, str]]] = {d: {"a2b": {}, "b2a": {}} for d in diff_ids}
    if not diff_ids:
        return out
    placeholders = ",".join("?" * len(diff_ids))
    rows = atlas.execute(
        "SELECT diff_id, addr_a, addr_b FROM function_alignment "
        f"WHERE alignment_state = 'aligned' AND diff_id IN ({placeholders})",
        tuple(sorted(diff_ids)),
    )
    for diff_id, addr_a, addr_b in rows:
        a, b = norm_hex(addr_a), norm_hex(addr_b)
        if diff_id in out and a and b:
            out[diff_id]["a2b"][a] = b
            out[diff_id]["b2a"][b] = a
    return out


def _detector_statuses(
    atlas: sqlite3.Connection, run_id: str, paths: set[str]
) -> dict[str, dict[str, Any] | None]:
    """``binary_path -> the static-table detector's status row (or None)``, read from the atlas
    ``detector_scan_status`` row the hunt stores beside the edges (by run and path) — the honesty
    row that tells "scanned, found none" from "not scanned" from "scan capped". No row, a
    pre-column row or two rows for one path -> None (no status: read as not run, never scanned)."""
    out: dict[str, dict[str, Any] | None] = {p: None for p in paths}
    if not paths:
        return out
    placeholders = ",".join("?" * len(paths))
    try:
        rows = atlas.execute(
            "SELECT binary_path, scanned, supported_scope, unsupported_note, cap_hit, found_count "
            "FROM detector_scan_status WHERE detector = 'string_tables' AND source_run_id = ? "
            f"AND binary_path IN ({placeholders})",
            (run_id, *sorted(paths)),
        ).fetchall()
    except sqlite3.OperationalError:
        return out  # a pre-feature atlas: no status recorded
    seen: dict[str, int] = defaultdict(int)
    for path, scanned, scope, note, cap_hit, found in rows:
        seen[path] += 1
        out[path] = {
            "scanned": bool(scanned),
            "supported_scope": scope,
            "unsupported_note": note,
            "cap_hit": bool(cap_hit),
            "found_count": found,
        }
    for path, n in seen.items():
        if n > 1:
            out[path] = None
    return out


# ── the grouping ───────────────────────────────────────────────────────────────────────────────


def _key_set(table: dict[str, Any]) -> set[str]:
    return {k for ks in table["keys"].values() for k in ks}


def _overlap(ka: set[str], kb: set[str]) -> int:
    """The keys two tables share when they are >= 50% of the smaller key set, else 0."""
    overlap = len(ka & kb)
    if overlap and overlap >= 0.5 * min(len(ka), len(kb)):
        return overlap
    return 0


def _align_tables(ta: dict[str, dict[str, Any]], tb: dict[str, dict[str, Any]]) -> dict[str, str]:
    """B table_addr -> A table_addr, aligned by key-set overlap >= 50% of the smaller key set
    (greedy, best overlap first, one A table per B table)."""
    scored: list[tuple[int, str, str]] = []
    for b, tbv in tb.items():
        kb = _key_set(tbv)
        for a, tav in ta.items():
            overlap = _overlap(_key_set(tav), kb)
            if overlap:
                scored.append((overlap, a, b))
    out: dict[str, str] = {}
    used_a: set[str] = set()
    for _ov, a, b in sorted(scored, reverse=True):
        if b not in out and a not in used_a:
            out[b] = a
            used_a.add(a)
    return out


def _table_groups(
    ta: dict[str, dict[str, Any]], tb: dict[str, dict[str, Any]]
) -> dict[str, dict[str, tuple[str, str]]]:
    """``side -> table_addr -> (A table, B table)``: the two-sided group each table of a side joins.

    Tables align one to one (``_align_tables``). A table left unaligned whose stored reasons say it
    was split by an undefined handler is a PIECE of a table: it joins the one-to-one group of the
    other side's table it overlaps most (by the same >= 50% measure), even though that table is
    already aligned to another piece — many pieces to one whole table, on either side. Any other
    unaligned table joins no two-sided group (its group is one-sided)."""
    paired: dict[str, dict[str, tuple[str, str]]] = {"a": {}, "b": {}}
    for b, a in _align_tables(ta, tb).items():
        paired["a"][a] = paired["b"][b] = (a, b)
    out = {s: dict(v) for s, v in paired.items()}
    for side, mine, theirs in (("a", ta, tb), ("b", tb, ta)):
        other = "b" if side == "a" else "a"
        for addr, table in mine.items():
            if addr in paired[side] or _SPLIT not in table["reasons"]:
                continue
            keys = _key_set(table)
            scored = [
                (ov, there)
                for there, tt in theirs.items()
                if there in paired[other] and (ov := _overlap(keys, _key_set(tt)))
            ]
            if scored:
                out[side][addr] = paired[other][max(scored)[1]]
    return out


def _pieces(
    tgroups: dict[str, dict[str, tuple[str, str]]], anchors: tuple[str | None, str | None]
) -> dict[str, list[str]]:
    """Per side, every table that joins the static group with these anchors (an unaligned table
    is a one-sided group of its own)."""
    out = {s: sorted(t for t, anc in tgroups[s].items() if anc == anchors) for s in SIDES}
    for s, anchor in zip(SIDES, anchors, strict=True):
        if anchor is not None and anchor not in out[s]:
            out[s].append(anchor)
    return out


def _detector_bucket(status: dict[str, Any] | None, binary_has_edges: bool) -> str:
    """Why an uncovered member's binary enumerates no table/gate naming it — honest three state."""
    if status is None or not status.get("scanned"):
        return "static_table_detector_did_not_run"
    if status.get("cap_hit"):
        return "static_table_scan_capped"
    if binary_has_edges:
        return "binary_has_edges_entry_not_a_member"
    return "scanned_no_static_table_found"


def compute_pair(
    atlas: sqlite3.Connection,
    run_a: str,
    run_b: str,
    members: list[MemberRef],
    *,
    align_dispatchers: bool = True,
) -> PairDispatch:
    """Group a pair's must-read entry members by the static tables and strcmp gates that enumerate
    their function. ``align_dispatchers`` merges a gate's two sides by function alignment (the spec
    grouping); False keeps each side's dispatch function a group of its own (the prototype)."""
    meta = _diff_meta(atlas, run_a, run_b)
    paths = {
        "a": {m["binary_path_a"] for m in meta.values() if m["binary_path_a"]},
        "b": {m["binary_path_b"] for m in meta.values() if m["binary_path_b"]},
    }
    runs = {"a": run_a, "b": run_b}
    tables = {s: _static_tables(atlas, runs[s], paths[s]) for s in SIDES}
    gates = {s: _gates(atlas, runs[s], paths[s]) for s in SIDES}
    det = {s: _detector_statuses(atlas, runs[s], paths[s]) for s in SIDES}
    dispatchers = {s: {p: _dispatchers(g) for p, g in gates[s].items()} for s in SIDES}
    align = _alignment(atlas, set(meta))
    # side -> table_addr -> (A table, B table) per diff, so a two-sided table is one group.
    tgroups: dict[str, dict[str, dict[str, tuple[str, str]]]] = {}
    for did, m in meta.items():
        tgroups[did] = _table_groups(
            tables["a"].get(m["binary_path_a"], {}), tables["b"].get(m["binary_path_b"], {})
        )

    groups: dict[tuple[str, str, str | None, str | None], DispatchGroup] = {}
    member_mechanisms: dict[tuple[str, str], set[str]] = defaultdict(set)
    uncovered: list[MemberRef] = []
    uncovered_by_detector: dict[str, dict[str, int]] = {s: defaultdict(int) for s in SIDES}
    detector_statuses: dict[tuple[str, str], dict[str, Any] | None] = {}

    def join(
        mechanism: str,
        mem: MemberRef,
        binary: str | None,
        anchors: tuple[str | None, str | None],
        side: str,
        keys: list[str],
        reasons: set[str],
        counterpart: str | None = None,
        pieces: dict[str, list[str]] | None = None,
    ) -> None:
        key = (mechanism, mem.diff_id, *anchors)
        g = groups.get(key)
        if g is None:
            g = groups[key] = DispatchGroup(mechanism, mem.diff_id, binary, *anchors)
            if pieces is not None:
                g.pieces = pieces
        if counterpart is not None:
            g.counterpart = counterpart
        per_side = g.members.setdefault(mem.entry_id, _no_keys())
        per_side[side] = sorted(set(per_side[side]) | set(keys))
        g.member_anchors[mem.entry_id] = mem.anchor_ref
        g.completeness_reasons |= reasons
        member_mechanisms[(mem.diff_id, mem.entry_id)].add(mechanism)

    for mem in members:
        did = mem.diff_id
        dm = meta.get(did)
        if dm is None:
            continue
        binary = dm["binary_a"]
        path = {"a": dm["binary_path_a"], "b": dm["binary_path_b"]}
        addr = {"a": mem.addr_a, "b": mem.addr_b}
        for s in SIDES:
            detector_statuses[(did, s)] = det[s].get(path[s])
        in_group = False
        anchors: tuple[str | None, str | None]

        # static tables: the member's per-side function is a stored handler in a table
        for s in SIDES:
            if addr[s] is None:
                continue
            for table_addr, tav in tables[s].get(path[s], {}).items():
                if addr[s] not in tav["handlers"]:
                    continue
                keys = sorted(set(tav["keys"].get(addr[s], [])))
                # The group is the aligned TABLE (``table_addr``), never a single key: a table's
                # handlers share one group, with the key(s) kept as each member's label (per side).
                # A table in no two-sided group is null on the other side.
                anchors = tgroups[did][s].get(table_addr) or (
                    (table_addr, None) if s == "a" else (None, table_addr)
                )
                pieces = _pieces(tgroups[did], anchors)
                join(STATIC, mem, binary, anchors, s, keys, tav["reasons"], pieces=pieces)
                in_group = True

        # strcmp gates: the member's per-side function is the callee of a dispatch function
        bin_gate = {s: gates[s].get(path[s], {}) for s in SIDES}
        for s in SIDES:
            fn = addr[s]
            if fn is None:
                continue
            other = "b" if s == "a" else "a"
            for ffa, gv in bin_gate[s].get(fn, {}).items():
                cp: str | None = None
                if align_dispatchers:
                    cp = align[did]["a2b" if s == "a" else "b2a"].get(ffa)
                # The other side's anchor only when that side's aligned function is itself a
                # stored dispatch function there; else null, with the aligned function as the
                # counterpart (one side enumerated is never shown as both).
                named = dispatchers[other].get(path[other], set())
                there = cp if cp is not None and cp in named else None
                anchors = (ffa, there) if s == "a" else (there, ffa)
                lone = cp if there is None else None
                join(GATE, mem, binary, anchors, s, gv["keys"], gv["reasons"], lone)
                in_group = True

        if not in_group:
            uncovered.append(mem)
            for s in SIDES:
                if addr[s] is None:
                    continue
                has_edges = bool(tables[s].get(path[s]) or bin_gate[s])
                uncovered_by_detector[s][_detector_bucket(det[s].get(path[s]), has_edges)] += 1

    grouped_ids = set(member_mechanisms)
    also_callee = sum(
        1
        for mem in members
        if (mem.diff_id, mem.entry_id) in grouped_ids and mem.unit_kind == "callee_group"
    )
    return PairDispatch(
        run_a=run_a,
        run_b=run_b,
        groups=sorted(
            groups.values(), key=lambda g: (-len(g.members), g.mechanism, g.diff_id, g.ref)
        ),
        member_mechanisms=dict(member_mechanisms),
        grouped_members=len(grouped_ids),
        also_in_callee_group=also_callee,
        uncovered=uncovered,
        uncovered_by_detector={s: dict(v) for s, v in uncovered_by_detector.items()},
        detector_statuses=detector_statuses,
    )


def from_review(
    atlas: sqlite3.Connection, facts: Any, units: list[Any], **kwargs: Any
) -> PairDispatch:
    """Compute the pair's dispatch groups from a review's facts and units."""
    return compute_pair(atlas, facts.run_a, facts.run_b, members_from_units(units), **kwargs)


# ── what is shown: the member label, the full group table, the compact report block ─────────────

MAX_KEYS_PER_MEMBER = 3  # key labels per side on a member label (the rest counted)
LARGEST_SHOWN = 3  # group refs named in the compact report block (the full table has them all)


def _where(g: DispatchGroup) -> dict[str, Any]:
    """A group's anchors per side, and why a side is null when one is."""
    name = "table" if g.mechanism == STATIC else "dispatch_function"
    out: dict[str, Any] = {name: {"a": g.a_anchor, "b": g.b_anchor}}
    if not g.counterpart_enumerates:
        out["counterpart_enumerates"] = False
        out["counterpart"] = g.counterpart
    return out


def member_labels(pd: PairDispatch) -> dict[tuple[str, str], list[dict[str, Any]]]:
    """``(diff_id, entry_id) -> the member's dispatch label``: each group it is in, with the
    group's ref, the keys naming it on each side (an empty side = that side names none) and how many
    must-read entries the group holds."""
    out: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for g in pd.groups:
        ref = g.ref
        for eid, keys in g.members.items():
            label: dict[str, Any] = {
                "mechanism": g.mechanism,
                "group_ref": ref,
                "keys": {s: keys[s][:MAX_KEYS_PER_MEMBER] for s in SIDES},
                "group_members": len(g.members),
            }
            cut = {s: len(keys[s]) - MAX_KEYS_PER_MEMBER for s in SIDES}
            if any(n > 0 for n in cut.values()):
                label["keys_omitted"] = {s: max(n, 0) for s, n in cut.items()}
            out[(g.diff_id, eid)].append(label)
    for labels in out.values():
        labels.sort(key=lambda lab: (lab["mechanism"], lab["group_ref"]))
    return dict(out)


def group_json(g: DispatchGroup) -> dict[str, Any]:
    """One group in full (the report file's table): its anchors per side, every member with its
    per-side keys, the tables of each side when a side has more than one (``table_pieces``: the
    pieces of a split table), and the stored completeness reasons of its table/gate edges."""
    out: dict[str, Any] = {
        "group_ref": g.ref,
        "mechanism": g.mechanism,
        "diff_id": g.diff_id,
        "binary": g.binary,
        **_where(g),
        "member_count": len(g.members),
        "members": [
            {"entry_id": eid, "anchor_ref": g.member_anchors.get(eid), "keys": g.members[eid]}
            for eid in sorted(g.members)
        ],
        "note": NOTE_STATIC if g.mechanism == STATIC else NOTE_GATE,
    }
    if any(len(g.pieces[s]) > 1 for s in SIDES):
        out["table_pieces"] = {s: list(g.pieces[s]) for s in SIDES}
    if g.completeness_reasons:
        out["completeness"] = {
            "reasons": sorted(g.completeness_reasons),
            "split_by_undefined_handler": g.split_by_undefined_handler,
        }
    return out


def _sizes(pd: PairDispatch, mechanism: str) -> dict[str, int]:
    gs = [g for g in pd.groups if g.mechanism == mechanism]
    sizes = sorted((len(g.members) for g in gs), reverse=True)
    return {
        "total": len(sizes),
        "with_2_or_more_members": sum(1 for s in sizes if s >= 2),
        "max_members": sizes[0] if sizes else 0,
        "one_sided": sum(1 for g in gs if not g.counterpart_enumerates),
    }


def _detector_scope(pd: PairDispatch) -> dict[str, list[str]]:
    """The static-table detector's recorded scope over the pair's read binaries (distinct)."""
    rows = [st for st in pd.detector_statuses.values() if st is not None]
    return {
        "supported_scope": sorted(
            {str(st["supported_scope"]) for st in rows if st["supported_scope"]}
        ),
        "unsupported_note": sorted(
            {str(st["unsupported_note"]) for st in rows if st["unsupported_note"]}
        ),
    }


def report_block(pd: PairDispatch) -> dict[str, Any]:
    """The compact ``dispatch_groups`` block of the pair review report: counts, the refs of the
    largest groups, the uncovered bucket counted per side by the static-table detector's status,
    and that detector's scope. The groups themselves ride on the members (``member_labels``) and in
    the report file (``group_json``). Only a navigation grouping — it moves nothing."""
    by_mechanism = {STATIC: 0, GATE: 0, "both": 0}
    for mechs in pd.member_mechanisms.values():
        if STATIC in mechs:
            by_mechanism[STATIC] += 1
        if GATE in mechs:
            by_mechanism[GATE] += 1
        if STATIC in mechs and GATE in mechs:
            by_mechanism["both"] += 1
    must_read_entries = pd.grouped_members + len(pd.uncovered)
    out: dict[str, Any] = {
        "mechanism_note": MECHANISM_NOTE,
        "grouped_members": pd.grouped_members,
        "grouped_pct": round(100.0 * pd.grouped_members / max(must_read_entries, 1), 1),
        "by_mechanism": by_mechanism,
        "also_in_callee_group": pd.also_in_callee_group,
        "table_groups": _sizes(pd, STATIC),
        "gate_groups": _sizes(pd, GATE),
        "largest": [
            {"group_ref": g.ref, "members": len(g.members)} for g in pd.groups[:LARGEST_SHOWN]
        ],
        "uncovered": {
            "count": len(pd.uncovered),
            "by_static_table_detector": pd.uncovered_by_detector,
            "note": _UNCOVERED_NOTE,
        },
        "static_table_detector": {**_detector_scope(pd), "note": DETECTOR_NOTE},
    }
    return out
