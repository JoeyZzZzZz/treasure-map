# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Dispatch-table groups: a NAVIGATION grouping of a pair's must-read entries by the string-keyed
edge that names their function, moving nothing.

Two groupings, both read from the atlas ``string_keyed_edge`` table (an ENUMERATED EDGE, a stored
fact — never a reachability verdict; see ``atlas_schema.sql`` ★IRON LAW):

* ``static_string_table`` — an entry is a member when its function entry (on a side) is the stored
  handler of a key in a recovered ``{string_ptr, func_ptr}`` table of that side's binary. The two
  sides' tables are aligned by key-set overlap (>= 50% of the smaller key set); the group is the
  aligned table (``table_addr`` on each side). The key is only a member label.
* ``strcmp_gate`` — an entry is a member when its function entry is the callee of a same-variable
  ``strcmp`` ladder; the group is the aligned dispatch FUNCTION (``from_func_addr``), the two sides'
  dispatch functions aligned by function alignment. The gating key is only a member label.

This reads the STORED enumeration only; it never reads a call edge of the dispatch and never claims
the handler is routed to or reachable. An entry named by no recovered table or gate falls to an
explicit UNCOVERED bucket carrying the per-binary ``detector_scan_status`` (the static-table
detector's honesty row), so "not enumerated" is never read as "not dispatched".

Only a grouping: the units, the must-read set, the unit ids and the order are untouched; an entry
that joins a group also stays in whatever unit held it (ENTRY / S_BATCH / SECOND_TIER / callee
GROUP). An entry can be in a callee group AND a dispatch group at once.
"""

from __future__ import annotations

import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from treasure_map.lib.diff.layer0 import norm_hex
from treasure_map.lib.ro_db import ro_connect

DISPATCH_GROUP_VERSION = "dispatch-v1"
STATIC, GATE = "static_string_table", "strcmp_gate"
_SPLIT = "split_by_undefined_handler"

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
    "no recovered table or gate enumerates these entries; read them with the static-table "
    "detector's scan status below"
)
# The code-authored strings the neutrality test scans, and the words it forbids in them.
NEUTRAL_TEXTS = (MECHANISM_NOTE, NOTE_STATIC, NOTE_GATE, _UNCOVERED_NOTE)


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


@dataclass
class DispatchGroup:
    mechanism: str
    diff_id: str
    binary: str | None
    a_anchor: str | None  # table_addr / dispatcher addr on the A side (None = B-only)
    b_anchor: str | None
    # entry_id -> the sorted key labels by which this member is in the group
    members: dict[str, list[str]] = field(default_factory=dict)
    member_anchors: dict[str, str] = field(default_factory=dict)
    completeness_reasons: set[str] = field(default_factory=set)

    @property
    def split_by_undefined_handler(self) -> bool:
        return _SPLIT in self.completeness_reasons

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
    uncovered_by_detector: dict[str, int]
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


# ── reading the enumerated edges (atlas) and the detector status (analysis.db) ──────────────────


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
        if reason:
            t["reasons"].add(reason)
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
        if reason:
            g["reasons"].add(reason)
    return out


def _new_gate() -> dict[str, Any]:
    return {"keys": [], "reasons": set()}


def _alignment(
    atlas: sqlite3.Connection, diff_ids: set[str]
) -> dict[str, dict[str, dict[str, str]]]:
    """``diff_id -> {"a2b": {addr_a: addr_b}, "b2a": {addr_b: addr_a}}``: the function pairing, so a
    dispatch function on one side is aligned to its counterpart on the other."""
    out: dict[str, dict[str, dict[str, str]]] = {d: {"a2b": {}, "b2a": {}} for d in diff_ids}
    if not diff_ids:
        return out
    placeholders = ",".join("?" * len(diff_ids))
    rows = atlas.execute(
        f"SELECT diff_id, addr_a, addr_b FROM function_alignment WHERE diff_id IN ({placeholders})",
        tuple(sorted(diff_ids)),
    )
    for diff_id, addr_a, addr_b in rows:
        a, b = norm_hex(addr_a), norm_hex(addr_b)
        if diff_id in out and a and b:
            out[diff_id]["a2b"][a] = b
            out[diff_id]["b2a"][b] = a
    return out


def _detector_statuses(
    atlas: sqlite3.Connection, run_id: str, shas: set[str]
) -> dict[str, dict[str, Any] | None]:
    """``sha256 -> the string_tables detector_scan_status row (or None)`` from this run's
    analysis.db — the honesty row that tells "scanned, found none" from "not scanned" from
    "scan capped"."""
    row = atlas.execute("SELECT analysis_db_path FROM run WHERE run_id = ?", (run_id,)).fetchone()
    out: dict[str, dict[str, Any] | None] = {sha: None for sha in shas}
    if row is None or not row[0] or not shas:
        return out
    try:
        conn = ro_connect(row[0])
    except sqlite3.Error:
        return out
    try:
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "detector_scan_status" not in names:
            return out
        placeholders = ",".join("?" * len(shas))
        rows = conn.execute(
            "SELECT b.sha256, d.scanned, d.supported_scope, d.unsupported_note, d.cap_hit, "
            "d.found_count FROM detector_scan_status d JOIN binaries b ON b.id = d.binary_id "
            f"WHERE d.detector = 'string_tables' AND b.sha256 IN ({placeholders})",
            tuple(sorted(shas)),
        )
        for sha, scanned, scope, note, cap_hit, found in rows:
            out[sha] = {
                "scanned": bool(scanned),
                "supported_scope": scope,
                "unsupported_note": note,
                "cap_hit": bool(cap_hit),
                "found_count": found,
            }
    except sqlite3.Error:
        return out
    finally:
        conn.close()
    return out


# ── the grouping ───────────────────────────────────────────────────────────────────────────────


def _align_tables(ta: dict[str, dict[str, Any]], tb: dict[str, dict[str, Any]]) -> dict[str, str]:
    """B table_addr -> A table_addr, aligned by key-set overlap >= 50% of the smaller key set
    (greedy, best overlap first, one A table per B table)."""
    scored: list[tuple[int, str, str]] = []
    for b, tbv in tb.items():
        kb = {k for ks in tbv["keys"].values() for k in ks}
        for a, tav in ta.items():
            ka = {k for ks in tav["keys"].values() for k in ks}
            overlap = len(ka & kb)
            if overlap and overlap >= 0.5 * min(len(ka), len(kb)):
                scored.append((overlap, a, b))
    out: dict[str, str] = {}
    used_a: set[str] = set()
    for _ov, a, b in sorted(scored, reverse=True):
        if b not in out and a not in used_a:
            out[b] = a
            used_a.add(a)
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
    paths_a = {m["binary_path_a"] for m in meta.values() if m["binary_path_a"]}
    paths_b = {m["binary_path_b"] for m in meta.values() if m["binary_path_b"]}
    shas_a = {m["sha256_a"] for m in meta.values() if m["sha256_a"]}
    shas_b = {m["sha256_b"] for m in meta.values() if m["sha256_b"]}
    tables_a = _static_tables(atlas, run_a, paths_a)
    tables_b = _static_tables(atlas, run_b, paths_b)
    gates_a = _gates(atlas, run_a, paths_a)
    gates_b = _gates(atlas, run_b, paths_b)
    align = _alignment(atlas, set(meta))
    det_a = _detector_statuses(atlas, run_a, shas_a)
    det_b = _detector_statuses(atlas, run_b, shas_b)
    # B table_addr -> A table_addr per diff, so a two-sided table is one group.
    tmaps: dict[str, dict[str, str]] = {}
    for did, m in meta.items():
        tmaps[did] = _align_tables(
            tables_a.get(m["binary_path_a"], {}), tables_b.get(m["binary_path_b"], {})
        )

    groups: dict[tuple[str, str, str | None, str | None], DispatchGroup] = {}
    member_mechanisms: dict[tuple[str, str], set[str]] = defaultdict(set)
    uncovered: list[MemberRef] = []
    uncovered_by_detector: dict[str, int] = defaultdict(int)
    detector_statuses: dict[tuple[str, str], dict[str, Any] | None] = {}

    def group_for(
        mechanism: str, diff_id: str, binary: str | None, a_anchor: str | None, b_anchor: str | None
    ) -> DispatchGroup:
        key = (mechanism, diff_id, a_anchor, b_anchor)
        g = groups.get(key)
        if g is None:
            g = groups[key] = DispatchGroup(mechanism, diff_id, binary, a_anchor, b_anchor)
        return g

    for mem in members:
        did = mem.diff_id
        dm = meta.get(did)
        if dm is None:
            continue
        binary = dm["binary_a"]
        detector_statuses[(did, "a")] = det_a.get(dm["sha256_a"])
        detector_statuses[(did, "b")] = det_b.get(dm["sha256_b"])
        in_group = False
        a_anchor: str | None
        b_anchor: str | None

        # static tables: the member's per-side function is a stored handler in a table
        for side, addr, tabs in (
            ("a", mem.addr_a, tables_a.get(dm["binary_path_a"], {})),
            ("b", mem.addr_b, tables_b.get(dm["binary_path_b"], {})),
        ):
            if addr is None:
                continue
            for table_addr, tav in tabs.items():
                if addr not in tav["handlers"]:
                    continue
                keys = sorted({k for ca, ks in tav["keys"].items() if ca == addr for k in ks})
                # The group is the aligned TABLE (``table_addr``), never a single key: a table's
                # handlers share one group, with the key(s) kept as each member's label below.
                if side == "a":
                    a_anchor, b_anchor = table_addr, _table_b_of(tmaps[did], table_addr)
                else:
                    a_anchor = tmaps[did].get(table_addr)
                    b_anchor = table_addr
                g = group_for(STATIC, did, binary, a_anchor, b_anchor)
                g.members.setdefault(mem.entry_id, [])
                g.members[mem.entry_id] = sorted(set(g.members[mem.entry_id]) | set(keys))
                g.member_anchors[mem.entry_id] = mem.anchor_ref
                g.completeness_reasons |= tav["reasons"]
                member_mechanisms[(did, mem.entry_id)].add(STATIC)
                in_group = True

        # strcmp gates: the member's per-side function is the callee of a dispatch function
        bin_gate_a = gates_a.get(dm["binary_path_a"], {})
        bin_gate_b = gates_b.get(dm["binary_path_b"], {})
        for side, addr, bin_gate in (("a", mem.addr_a, bin_gate_a), ("b", mem.addr_b, bin_gate_b)):
            if addr is None:
                continue
            for ffa, gv in bin_gate.get(addr, {}).items():
                if align_dispatchers:
                    if side == "a":
                        a_anchor, b_anchor = ffa, align[did]["a2b"].get(ffa)
                    else:
                        a_anchor, b_anchor = align[did]["b2a"].get(ffa), ffa
                else:
                    a_anchor, b_anchor = (ffa, None) if side == "a" else (None, ffa)
                g = group_for(GATE, did, binary, a_anchor, b_anchor)
                g.members.setdefault(mem.entry_id, [])
                g.members[mem.entry_id] = sorted(set(g.members[mem.entry_id]) | set(gv["keys"]))
                g.member_anchors[mem.entry_id] = mem.anchor_ref
                g.completeness_reasons |= gv["reasons"]
                member_mechanisms[(did, mem.entry_id)].add(GATE)
                in_group = True

        if not in_group:
            uncovered.append(mem)
            has_edges_a = bool(tables_a.get(dm["binary_path_a"]) or bin_gate_a)
            has_edges_b = bool(tables_b.get(dm["binary_path_b"]) or bin_gate_b)
            if mem.addr_a is not None:
                uncovered_by_detector[_detector_bucket(det_a.get(dm["sha256_a"]), has_edges_a)] += 1
            elif mem.addr_b is not None:
                uncovered_by_detector[_detector_bucket(det_b.get(dm["sha256_b"]), has_edges_b)] += 1

    grouped_ids = set(member_mechanisms)
    also_callee = sum(
        1
        for mem in members
        if (mem.diff_id, mem.entry_id) in grouped_ids and mem.unit_kind == "callee_group"
    )
    return PairDispatch(
        run_a=run_a,
        run_b=run_b,
        groups=sorted(groups.values(), key=lambda g: (-len(g.members), g.mechanism, g.diff_id)),
        member_mechanisms=dict(member_mechanisms),
        grouped_members=len(grouped_ids),
        also_in_callee_group=also_callee,
        uncovered=uncovered,
        uncovered_by_detector=dict(uncovered_by_detector),
        detector_statuses=detector_statuses,
    )


def _table_b_of(tmap: dict[str, str], table_a: str) -> str | None:
    """The B table aligned to an A table (invert the B->A alignment map)."""
    for b, a in tmap.items():
        if a == table_a:
            return b
    return None


def from_review(
    atlas: sqlite3.Connection, facts: Any, units: list[Any], **kwargs: Any
) -> PairDispatch:
    """Compute the pair's dispatch groups from a review's facts and units."""
    return compute_pair(atlas, facts.run_a, facts.run_b, members_from_units(units), **kwargs)


# ── the compact report block (bounded; caps groups and counts the rest) ─────────────────────────

MAX_GROUPS_SHOWN = 8
MAX_MEMBERS_PER_GROUP = 4
MAX_KEYS_PER_MEMBER = 2


def _group_json(g: DispatchGroup) -> dict[str, Any]:
    entry_ids = sorted(g.members)
    shown = entry_ids[:MAX_MEMBERS_PER_GROUP]
    members = [
        {
            "entry_id": eid,
            "anchor_ref": g.member_anchors.get(eid),
            "key_label": g.members[eid][:MAX_KEYS_PER_MEMBER],
        }
        for eid in shown
    ]
    where = (
        {"table": {"a": g.a_anchor, "b": g.b_anchor}}
        if g.mechanism == STATIC
        else {"dispatch_function": {"a": g.a_anchor, "b": g.b_anchor}}
    )
    out: dict[str, Any] = {
        "mechanism": g.mechanism,
        "diff_id": g.diff_id,
        "binary": g.binary,
        **where,
        "member_count": len(entry_ids),
        "members": members,
        "members_omitted": max(0, len(entry_ids) - len(shown)),
        "note": NOTE_STATIC if g.mechanism == STATIC else NOTE_GATE,
    }
    if g.completeness_reasons:
        out["completeness"] = {
            "reasons": sorted(g.completeness_reasons),
            "split_by_undefined_handler": g.split_by_undefined_handler,
        }
    return out


def report_block(pd: PairDispatch, *, max_groups: int = MAX_GROUPS_SHOWN) -> dict[str, Any]:
    """A bounded ``dispatch_groups`` block for the pair review report: counts, the largest groups
    (capped, the rest counted), and the explicit uncovered bucket with the detector's scan status.
    Only a navigation grouping — it moves nothing."""
    by_mechanism = {STATIC: 0, GATE: 0, "both": 0}
    for mechs in pd.member_mechanisms.values():
        if STATIC in mechs:
            by_mechanism[STATIC] += 1
        if GATE in mechs:
            by_mechanism[GATE] += 1
        if STATIC in mechs and GATE in mechs:
            by_mechanism["both"] += 1
    table_sizes = sorted((len(g.members) for g in pd.groups if g.mechanism == STATIC), reverse=True)
    gate_sizes = sorted((len(g.members) for g in pd.groups if g.mechanism == GATE), reverse=True)
    must_read_entries = pd.grouped_members + len(pd.uncovered)
    shown = pd.groups[:max_groups]
    return {
        "mechanism_note": MECHANISM_NOTE,
        "grouped_members": pd.grouped_members,
        "grouped_pct": round(100.0 * pd.grouped_members / max(must_read_entries, 1), 1),
        "by_mechanism": by_mechanism,
        "also_in_callee_group": pd.also_in_callee_group,
        "table_groups": {
            "total": len(table_sizes),
            "with_2_or_more_members": sum(1 for s in table_sizes if s >= 2),
            "max_members": table_sizes[0] if table_sizes else 0,
        },
        "gate_groups": {
            "total": len(gate_sizes),
            "with_2_or_more_members": sum(1 for s in gate_sizes if s >= 2),
            "max_members": gate_sizes[0] if gate_sizes else 0,
        },
        "groups": [_group_json(g) for g in shown],
        "groups_shown": len(shown),
        "groups_omitted": max(0, len(pd.groups) - len(shown)),
        "uncovered": {
            "count": len(pd.uncovered),
            "by_static_table_detector": pd.uncovered_by_detector,
            "note": _UNCOVERED_NOTE,
        },
    }
