# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The other calls of the same shape as one sink call, in the same binary, and where each of them
landed in one diff.

READ-ONLY and DERIVED, like the view it reads (lib/query/patch_view): it writes nothing and draws
no conclusion. Given one sink call of a diff, it names the calls of the same shape on the same side
of that diff — the same binary content, in the same run — and counts where each one landed in the
diff's view. A change that touched one call of a shape and left the others where they were shows
here as one landing among several; what that means is the reader's to decide.

THE SHAPE (``f2``) is the candidate pattern's ``structural_fingerprint`` (lib/pattern/fingerprint:
pattern kind, sink and source class, call-sequence shape), plus the called sink's name
(``sink_anchor``), plus a kind: the length kind (``size_kind``) for a copy or formatter call, the
source kind (``source_kind``) for any other class, ``unknown`` when it is not recorded.
``group_ref`` names one group on one side of one diff, with the fingerprint version the pattern
rows record and this recipe's version (``F2_RECIPE_VERSION``), so a later change to either names a
new group.

MEMBERS are the calls with an address of their own: ``callsite`` (a direct sink call) and
``wrapper_callsite`` (a call to a thin wrapper; its sink name is the sink the wrapper forwards to).
A function-level candidate (``wrapper``, ``function_fallback``, ``degraded_out_of_body``) has no
address of its own — several calls can share its ref — so it is not a member: it is counted beside
the group, and as an input it gets the shapes it has (``not_a_member``) instead of a group. A
member is counted once per evidence_ref. Only the side the input call is on is read: a B-side input
is grouped with B's calls and read by its B-side ref.

WHERE A MEMBER LANDED is read from the diff's view as get_diff_patch_view builds it, listed entries
and the similarity-1 pairs it does not list alike: the row's ``landing`` / ``subclass``
(patch_view.row_landing), whether its entry is listed, and its pair's similarity — nothing is read
a second way. A member whose row is in an entry that is not listed is in an aligned similarity-1
pair (``not_listed_sim1``). When the diff is undetermined as a whole the view places nothing:
every member is then counted under ``states_unreadable`` by the view's
``diff_undetermined:<reason>`` banners (each banner counts every member), never as not listed — a
state that could not be read is not a state that did not change.

WHAT CAN MAKE THE GROUP LOOK SMALLER (``sibling_set_bounds``):
  ``recall_gaps`` — the sinks the hunt does not recall that this binary's callee lists name, by
  family (patch_view.RECALL_GAP_SINKS). Such a call is never a candidate, so it is never a member of
  any group: this says the binary holds calls the hunt did not recall, not that this group is short
  of them. ``families`` is null when the lists could not be read (``state`` says why); with
  ``partial:<n>`` it holds what the readable lists name, n functions' lists being cut short or
  unreadable.
  ``undetermined_alignment_n`` — ``by_landing.R`` summed: members whose pair is undetermined. They
  are members all the same; only where they landed could not be read.
  ``binaries_not_diffed`` — calls with this sink name and kind, at the member granularities, in
  this run's binaries whose content no diff of this run pair covers, by why (a same-named binary
  with other content was diffed; the same content is on the other side; the other side holds a
  same-named binary with other content; this side only). Calls of OTHER binaries, never members of
  this group.
  ``excluded_non_callsite`` — this binary's function-level candidates with this sink name and kind,
  per granularity, counted once per evidence_ref.
  ``unkeyed`` — this binary's calls on this side that no shape could be given (no function address,
  no structural fingerprint, no sink name), once per evidence_ref: any of them may be of this
  shape.

HANDLES on a member row: ``evidence_ref`` (a candidate-level judgement, annotate); for a member in
a listed entry also ``entry_id`` + ``row_ref`` (what promote takes) and ``candidate_anchor`` (what
annotate_diff takes). promote itself decides whether it carries a judgement onto that row — a row
landing A, persisted, or P ``unmatched_analysis_complete``, in a determined pairing, on a diff whose
sources are current — and refuses the rest with its reasons; nothing here repeats that check.
"""

from __future__ import annotations

import hashlib
import sqlite3
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from treasure_map.lib import rescan_version
from treasure_map.lib.query import diff_review
from treasure_map.lib.query.diff_align import diff_source_staleness
from treasure_map.lib.query.patch_view import (
    RECALL_GAP_SINKS,
    BuiltDiff,
    _changed,
    _Entry,
    _read_side,
    _Side,
    build_diff_view,
    split_subject_key,
)
from treasure_map.lib.query.runs import get_run, run_staleness
from treasure_map.lib.query.sink_overlay import (
    SinkOverlayRow,
    _classify,
    _func_entry_hex,
    _parse_flow,
    _subject_key,
    _wrapper_callee,
)
from treasure_map.lib.query.triage import _CLASS_COPY, _CLASS_FORMAT, _source_kind_from_evidence

F2_RECIPE_VERSION = "f2-v1"
MEMBER_GRANULARITIES = ("callsite", "wrapper_callsite")
FUNCTION_LEVEL_GRANULARITIES = ("wrapper", "function_fallback", "degraded_out_of_body")
MEMBERS_PAGE_LIMIT = 200
MEMBERS_ORDER = "function_entry_then_call_address_then_evidence_ref"
NOT_DIFFED_REASONS = (
    "shadowed_by_name_collision",
    "identical_both_sides",
    "other_side_same_name_not_diffed",
    "binary_not_diffed",
)
UNKEYED_REASONS = ("no_function_address", "no_structural_fingerprint", "no_sink_name")
NO_ROW_IN_VIEW = "no_row_in_view"
SEVERAL_ROWS_IN_VIEW = "several_rows_in_view"
_UNKNOWN = "unknown"
_NO_SUBCLASS = "-"
_SIZE_KIND_CLASSES = (_CLASS_COPY, _CLASS_FORMAT)

_SELECT = (
    "SELECT i.evidence_ref, p.sink_class, i.sink_anchor, i.flow_evidence, "
    "p.structural_fingerprint, p.fingerprint_algo_version "
    "FROM instance i JOIN pattern p ON i.pattern_id = p.pattern_id "
)

_NOTE = (
    "Where each call of this shape on this side landed in this diff, as the diff's view states it. "
    "A count of landings is not a reading of the change: which of them matter is the reader's to "
    "decide."
)


# ── the shape of one call ───────────────────────────────────────────────────────────────────


def call_kind(sink_class: str, flow: Mapping[str, Any]) -> str:
    """The kind that goes into a call's shape: ``size_kind`` for a copy or formatter call,
    ``source_kind`` for any other class; ``unknown`` when it is not recorded."""
    if sink_class in _SIZE_KIND_CLASSES:
        value = flow.get("size_kind")
        return value if isinstance(value, str) and value else _UNKNOWN
    return _source_kind_from_evidence(flow)


def f2_key(structural_fingerprint: str, sink_anchor: str, kind: str) -> str:
    """The shape key: the fingerprint, the sink's name and the kind, hashed."""
    basis = "|".join((structural_fingerprint, sink_anchor, kind))
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def group_ref(diff_id: str, key: str, side: str, fingerprint_version: str) -> str:
    """``{diff_id}#f2:{key}:{side}@{fingerprint version}/{recipe version}``."""
    return f"{diff_id}#f2:{key}:{side}@{fingerprint_version}/{F2_RECIPE_VERSION}"


@dataclass(frozen=True)
class _Call:
    """One instance row of the side's binary, as far as its shape goes."""

    ref: str | None
    sink_class: str
    sink: str
    kind: str
    granularity: str
    call_addr: str | None
    func_entry: str | None
    fingerprint: str | None
    fingerprint_version: str
    wrapper: tuple[str | None, str | None]

    @property
    def unkeyed(self) -> str | None:
        """Why no shape can be given to this call; None when one can."""
        if self.func_entry is None:
            return "no_function_address"
        if not self.fingerprint:
            return "no_structural_fingerprint"
        if not self.sink:
            return "no_sink_name"
        return None

    @property
    def key(self) -> str:
        assert self.fingerprint
        return f2_key(self.fingerprint, self.sink, self.kind)


def _call(row: tuple[Any, ...]) -> _Call:
    ref, sink_class, sink, flow_raw, fingerprint, fp_version = row
    flow = _parse_flow(flow_raw)
    func_entry = _func_entry_hex(ref) if ref else None
    granularity, call_addr = _classify(ref, flow) if func_entry is not None else (_UNKNOWN, None)
    return _Call(
        ref=ref,
        sink_class=sink_class or "",
        sink=sink or "",
        kind=call_kind(sink_class or "", flow),
        granularity=granularity,
        call_addr=call_addr,
        func_entry=func_entry,
        fingerprint=fingerprint,
        fingerprint_version=fp_version or "",
        wrapper=(_wrapper_callee(flow) if granularity == "wrapper_callsite" else (None, None)),
    )


def _calls(atlas: sqlite3.Connection, run_id: str, sha: str) -> list[_Call]:
    """Every instance row of one run's binary (by content hash), in instance order."""
    rows = atlas.execute(
        _SELECT + "WHERE i.source_run_id = ? AND i.binary_content_hash = ? ORDER BY i.instance_id",
        (run_id, sha),
    ).fetchall()
    return [_call(tuple(r)) for r in rows]


# ── the diff, its sides, and the refusals ───────────────────────────────────────────────────


@dataclass(frozen=True)
class _Meta:
    diff_id: str
    run: dict[str, str]
    sha: dict[str, str | None]
    binary: dict[str, str | None]


def _meta(atlas: sqlite3.Connection, diff_id: str) -> _Meta | None:
    row = atlas.execute(
        "SELECT run_a_id, run_b_id, binary_a, binary_b, sha256_a, sha256_b FROM diff_meta "
        "WHERE diff_id = ?",
        (diff_id,),
    ).fetchone()
    if row is None:
        return None
    run_a, run_b, bin_a, bin_b, sha_a, sha_b = tuple(row)
    return _Meta(
        diff_id, {"a": run_a, "b": run_b}, {"a": sha_a, "b": sha_b}, {"a": bin_a, "b": bin_b}
    )


def refuse_stale_diff(
    atlas: sqlite3.Connection,
    diff_id: str,
    *,
    build_hash: str | None,
    current: rescan_version.CodeStamp,
    commit: str,
) -> dict[str, Any] | None:
    """The refusal for a diff whose A or B side is a PROVABLY stale run (lib/query/runs
    run_staleness, against the running extraction ``build_hash`` and code stamp ``current``), else
    None.

    The same refusal the MCP diff tools give, with the same keys, here in the read layer so the
    command line refuses what MCP refuses. An unknown diff_id passes: 'no such diff' is answered by
    the caller."""
    row = atlas.execute(
        "SELECT run_a_id, run_b_id FROM diff_meta WHERE diff_id = ?", (diff_id,)
    ).fetchone()
    if row is None:
        return None
    for side, run_id in (("a", row[0]), ("b", row[1])):
        run = get_run(atlas, run_id) if run_id else None
        if run is None:
            continue
        stale = run_staleness(run, build_hash=build_hash, current=current, commit=commit)
        if stale.stale:
            return {
                "diff_id": diff_id,
                "error": f"run '{run.run_id}' is a STALE scan ({stale.axis}): {stale.detail}",
                "stale_scan": {"axis": stale.axis, "detail": stale.detail, "diff_side": side},
                "remedy": stale.remedy,
            }
    return None


def _check_args(
    evidence_ref: Any, candidate_anchor: Any, members_offset: Any, members_limit: Any
) -> str | None:
    if (evidence_ref is None) == (candidate_anchor is None):
        return "pass exactly one of: evidence_ref, candidate_anchor"
    for name, value in (("evidence_ref", evidence_ref), ("candidate_anchor", candidate_anchor)):
        if value is not None and (not isinstance(value, str) or not value):
            return f"{name} must be a non-empty string, got {value!r}"
    if members_offset is not None and (
        isinstance(members_offset, bool)
        or not isinstance(members_offset, int)
        or members_offset < 0
    ):
        return f"members_offset must be an integer >= 0, got {members_offset!r}"
    if isinstance(members_limit, bool) or not isinstance(members_limit, int) or members_limit < 1:
        return f"members_limit must be an integer >= 1, got {members_limit!r}"
    return None


@dataclass(frozen=True)
class _Input:
    side: str
    ref: str
    sink_class: str | None  # the candidate anchor's, which narrows the ref's rows; None otherwise


def _resolve_input(
    meta: _Meta, evidence_ref: str | None, candidate_anchor: str | None
) -> _Input | str:
    """Which side's call the input names, or why it names none of this diff's. A candidate anchor
    names its A ref when it has one, else its B ref; an evidence_ref names the side of its run."""
    run_a, run_b = meta.run["a"], meta.run["b"]
    if candidate_anchor is not None:
        parts = diff_review.split_anchor(candidate_anchor, run_a, run_b)
        if parts is None:
            return (
                f"{candidate_anchor!r} is not an anchor of this diff's run pair "
                f"({diff_review.run_pair(run_a, run_b)}#candidate#<subject_key>) — copy it from a "
                "candidate row's anchor"
            )
        kind, key = parts
        if kind != "candidate":
            return (
                f"{candidate_anchor!r} is a {kind} anchor; same_shape_siblings takes a candidate "
                "anchor or an evidence_ref"
            )
        split = split_subject_key(key, run_a, run_b)
        if split is None:
            return f"{candidate_anchor!r} does not split into a candidate's two refs"
        _gran, sink_class, a_ref, b_ref = split
        if a_ref is not None:
            return _Input("a", a_ref, sink_class)
        assert b_ref is not None
        return _Input("b", b_ref, sink_class)
    assert evidence_ref is not None
    sides = [s for s in ("a", "b") if evidence_ref.startswith(f"{meta.run[s]}#")]
    if not sides:
        return (
            f"{evidence_ref!r} is not a ref of this diff's runs ({run_a!r}, {run_b!r}) — an "
            "evidence_ref starts with its run id and '#'"
        )
    return (
        _Input(sides[0], evidence_ref, None) if len(sides) == 1 else _Input("", evidence_ref, None)
    )


# ── one member's state, read from the view ──────────────────────────────────────────────────


@dataclass
class _State:
    entry: _Entry | None = None
    row: SinkOverlayRow | None = None
    view: dict[str, Any] | None = None
    unreadable: list[str] = field(default_factory=list)


def _row_index(
    built: BuiltDiff, side: str, refs: set[str]
) -> dict[str, list[tuple[_Entry, SinkOverlayRow, dict[str, Any]]]]:
    out: dict[str, list[tuple[_Entry, SinkOverlayRow, dict[str, Any]]]] = {}
    for e in built.placed:
        for r, v in zip(e.rows, e.row_views, strict=True):
            ref = r.a_ref if side == "a" else r.b_ref
            if ref in refs:
                out.setdefault(ref, []).append((e, r, v))
    return out


def _states(built: BuiltDiff, side: str, members: list[_Call]) -> dict[str, _State]:
    """Each member's row in the view, or why it has none. A diff withheld as a whole places no
    entry: every member is unreadable for each of its diff_undetermined banners. A call the hunt
    recorded more than once (one ref, several instance rows) has a row per record; they are read
    as one when they sit in one entry and land alike, else the member is unreadable."""
    refs = {m.ref for m in members if m.ref}
    if built.withheld is not None:
        banners = [b for b in built.banners if b.startswith("diff_undetermined:")]
        return {ref: _State(unreadable=list(banners)) for ref in refs}
    index = _row_index(built, side, refs)
    out: dict[str, _State] = {}
    for ref in refs:
        hits = index.get(ref, [])
        alike = {(e.entry_id, v["landing"], v["subclass"]) for e, _r, v in hits}
        if len(alike) == 1:
            e, r, v = hits[0]
            out[ref] = _State(entry=e, row=r, view=v)
        else:
            out[ref] = _State(unreadable=[NO_ROW_IN_VIEW if not hits else SEVERAL_ROWS_IN_VIEW])
    return out


# ── what can make the group look smaller ────────────────────────────────────────────────────


def _recall_gaps(side: _Side, source_stale: Any) -> dict[str, Any]:
    """The families of RECALL_GAP_SINKS this binary's callee lists name, read the way the view reads
    a pair's lists: a list cut short (``callees_truncated`` true, or not recorded) or unreadable
    makes the reading partial; sources not shown current, or no readable analysis.db, make it
    unreadable — and then ``families`` is null, never an empty list."""
    if source_stale is not False:
        return {"families": None, "state": "unreadable:source_stale"}
    if side.error is not None:
        return {"families": None, "state": "unreadable:analysis_db_unavailable"}
    names: set[str] = set()
    partial = 0
    for addr in side.raw:
        fn = side.fn(addr)
        if fn is None or fn.callees is None:
            partial += 1
            continue
        names.update(fn.callees)
        if fn.truncated is not False:
            partial += 1
    families = sorted(f for f, sinks in RECALL_GAP_SINKS.items() if names & set(sinks))
    return {"families": families, "state": f"partial:{partial}" if partial else "read"}


def _basename(path: str | None) -> str | None:
    return path.rsplit("/", 1)[-1] if path else None


def _not_diffed(
    atlas: sqlite3.Connection, meta: _Meta, side: str, sink: str, kind: str
) -> dict[str, dict[str, int]]:
    """Calls with this sink name and kind, at the member granularities, in this side's run, whose
    binary content no diff of this run pair covers — per reason, binaries counted by content hash
    and calls by evidence_ref. The reasons are decided in a fixed order: a same-named binary was
    diffed (as the run-pair overlay decides it), then the same content is on the other side, then
    the other side holds a same-named binary with other content, else this side only."""
    other = "b" if side == "a" else "a"
    sha_col, name_col = ("sha256_a", "binary_a") if side == "a" else ("sha256_b", "binary_b")
    diffs = atlas.execute(
        f"SELECT {sha_col}, {name_col} FROM diff_meta WHERE run_a_id = ? AND run_b_id = ?",
        (meta.run["a"], meta.run["b"]),
    ).fetchall()
    diffed_sha = {d[0] for d in diffs if d[0]}
    diffed_names = {d[1] for d in diffs if d[1]}
    other_sha: set[str] = set()
    other_names: set[str] = set()
    for sha, path in atlas.execute(
        "SELECT DISTINCT binary_content_hash, binary_path FROM instance WHERE source_run_id = ?",
        (meta.run[other],),
    ):
        if sha:
            other_sha.add(sha)
        name = _basename(path)
        if name:
            other_names.add(name)
    found: dict[str, tuple[set[str], set[str]]] = {r: (set(), set()) for r in NOT_DIFFED_REASONS}
    for ref, sink_class, flow_raw, sha, path in atlas.execute(
        "SELECT i.evidence_ref, p.sink_class, i.flow_evidence, i.binary_content_hash, "
        "i.binary_path FROM instance i JOIN pattern p ON i.pattern_id = p.pattern_id "
        "WHERE i.source_run_id = ? AND i.sink_anchor = ?",
        (meta.run[side], sink),
    ):
        if (sha and sha in diffed_sha) or not ref or _func_entry_hex(ref) is None:
            continue
        flow = _parse_flow(flow_raw)
        if _classify(ref, flow)[0] not in MEMBER_GRANULARITIES:
            continue
        if call_kind(sink_class or "", flow) != kind:
            continue
        name = _basename(path)
        if name in diffed_names:
            reason = "shadowed_by_name_collision"
        elif sha and sha in other_sha:
            reason = "identical_both_sides"
        elif name in other_names:
            reason = "other_side_same_name_not_diffed"
        else:
            reason = "binary_not_diffed"
        binaries, calls = found[reason]
        binaries.add(sha or f"path:{path}")
        calls.add(ref)
    return {r: {"binaries": len(b), "calls": len(c)} for r, (b, c) in found.items()}


def _excluded(calls: list[_Call], sink: str, kind: str) -> dict[str, int]:
    seen: dict[str, set[str]] = {g: set() for g in FUNCTION_LEVEL_GRANULARITIES}
    for c in calls:
        if c.ref and c.unkeyed is None and c.sink == sink and c.kind == kind:
            if c.granularity in seen:
                seen[c.granularity].add(c.ref)
    return {g: len(refs) for g, refs in seen.items()}


def _unkeyed(calls: list[_Call]) -> dict[str, int]:
    seen: dict[str, set[str]] = {r: set() for r in UNKEYED_REASONS}
    for i, c in enumerate(calls):
        why = c.unkeyed
        if why is not None:
            seen[why].add(c.ref or f"#row{i}")
    return {r: len(refs) for r, refs in seen.items()}


# ── the answer ──────────────────────────────────────────────────────────────────────────────


def _fp_version(members: list[_Call]) -> str:
    return "+".join(sorted({m.fingerprint_version for m in members})) or _UNKNOWN


def _groups(calls: list[_Call]) -> dict[str, list[_Call]]:
    """Members by shape key, once per evidence_ref, in instance order."""
    out: dict[str, dict[str, _Call]] = {}
    for c in calls:
        if c.ref and c.unkeyed is None and c.granularity in MEMBER_GRANULARITIES:
            out.setdefault(c.key, {}).setdefault(c.ref, c)
    return {k: list(v.values()) for k, v in out.items()}


def _member_row(
    meta: _Meta, side: str, c: _Call, st: _State, names: dict[str, str]
) -> dict[str, Any]:
    assert c.ref is not None and c.func_entry is not None
    row: dict[str, Any] = {
        "evidence_ref": c.ref,
        "key_granularity": c.granularity,
        "function_entry": c.func_entry,
        "function_name": names.get(c.func_entry),
        "call_addr": c.call_addr,
    }
    if st.view is None:
        row.update(
            {
                "landing": None,
                "subclass": None,
                "listed": None,
                "similarity": None,
                "unreadable": st.unreadable,
            }
        )
    else:
        assert st.entry is not None and st.row is not None
        e = st.entry
        listed = bool(e.bucket)
        row.update(
            {
                "landing": st.view["landing"],
                "subclass": st.view["subclass"],
                "listed": listed,
                "similarity": e.pair.similarity if e.pair is not None else None,
            }
        )
        if listed:
            row["entry_id"] = e.entry_id
            row["row_ref"] = c.ref
            row["candidate_anchor"] = diff_review.candidate_anchor(
                meta.run["a"], meta.run["b"], _subject_key(st.row)
            )
    if c.granularity == "wrapper_callsite":
        row["wrapper"] = {"name": c.wrapper[0], "entry": c.wrapper[1]}
    return row


def _order(c: _Call) -> tuple[str, str, str]:
    return (c.func_entry or "", c.call_addr or "", c.ref or "")


def _wrapper_key(c: _Call) -> str:
    name, entry = c.wrapper
    if entry:
        return entry
    return f"name:{name}" if name else "unrecorded"


def _group_object(
    atlas: sqlite3.Connection,
    meta: _Meta,
    built: BuiltDiff,
    side: str,
    key: str,
    members: list[_Call],
    states: dict[str, _State],
    calls: list[_Call],
    side_db: _Side,
    page_ref: dict[str, Any],
) -> dict[str, Any]:
    by_landing: dict[str, Counter[str]] = {}
    unreadable: Counter[str] = Counter()
    not_listed = below_1 = 0
    for m in members:
        assert m.ref is not None
        st = states[m.ref]
        if st.view is None:
            unreadable.update(st.unreadable)
            continue
        assert st.entry is not None
        sub = st.view["subclass"] or _NO_SUBCLASS
        by_landing.setdefault(st.view["landing"], Counter())[sub] += 1
        if not st.entry.bucket:
            not_listed += 1
        if st.entry.pair is not None and _changed(st.entry.pair):
            below_1 += 1
    landing_counts = {
        landing: dict(sorted(subs.items())) for landing, subs in sorted(by_landing.items())
    }
    first = members[0]
    out: dict[str, Any] = {
        "diff_id": meta.diff_id,
        "group_ref": group_ref(meta.diff_id, key, side, _fp_version(members)),
        "side": side,
        "binary": meta.binary[side],
        "shape": {
            "structural_fingerprint": first.fingerprint,
            "sink_anchor": first.sink,
            "kind": first.kind,
        },
        "member_count": len(members),
        "by_landing": landing_counts,
        "not_listed_sim1": not_listed,
        "similarity_below_1": below_1,
        "states_unreadable": dict(sorted(unreadable.items())),
    }
    wrappers = Counter(_wrapper_key(m) for m in members if m.granularity == "wrapper_callsite")
    if wrappers:
        out["by_wrapper"] = dict(sorted(wrappers.items()))
    out["sibling_set_bounds"] = {
        "recall_gaps": _recall_gaps(side_db, built.staleness.get("source_stale")),
        "undetermined_alignment_n": sum(landing_counts.get("R", {}).values()),
        "binaries_not_diffed": _not_diffed(atlas, meta, side, first.sink, first.kind),
        "excluded_non_callsite": _excluded(calls, first.sink, first.kind),
        "unkeyed": _unkeyed(calls),
    }
    out["members_page_ref"] = page_ref
    out["source_stale"] = built.staleness.get("source_stale")
    out["source_stale_reason"] = built.staleness.get("source_stale_reason")
    out["note"] = _NOTE
    return out


def _shape_keys(
    meta: _Meta, side: str, rows: list[_Call], groups: dict[str, list[_Call]]
) -> list[dict[str, Any]]:
    """Each shape ``rows`` have, with its group on this side — or a null group_ref and 0 members
    when this side has no member of that shape."""
    out: dict[str, dict[str, Any]] = {}
    for c in rows:
        members = groups.get(c.key, [])
        out.setdefault(
            c.key,
            {
                "f2_key": c.key,
                "sink_anchor": c.sink,
                "kind": c.kind,
                "group_ref": (
                    group_ref(meta.diff_id, c.key, side, _fp_version(members)) if members else None
                ),
                "member_count": len(members),
            },
        )
    return [out[k] for k in sorted(out)]


def same_shape_siblings(
    atlas: sqlite3.Connection,
    diff_id: str,
    *,
    evidence_ref: str | None = None,
    candidate_anchor: str | None = None,
    members_offset: int | None = None,
    members_limit: int = MEMBERS_PAGE_LIMIT,
    build_hash: str | None,
    current: rescan_version.CodeStamp,
    commit: str,
) -> dict[str, Any]:
    """The same-shape group of one sink call of a diff (see the module docstring).

    The call is named by ``evidence_ref`` or by its ``candidate_anchor``
    (``{run_a}::{run_b}#candidate#<subject_key>``, which names its A ref when it has one); it must
    be a candidate of the diffed binary on that side. A diff whose side is a provably stale run is
    refused (``refuse_stale_diff``, against ``build_hash`` / ``commit``).

    Without ``members_offset``: the group object — counts only, no member list. With it: one page
    of the members (``members_limit`` of them, in ``MEMBERS_ORDER``) and ``members_next_offset``
    (null on the last page). A function-level input returns ``not_a_member`` with the shapes it has
    instead."""
    meta = _meta(atlas, diff_id)
    if meta is None:
        return {"diff_id": diff_id, "error": f"no diff {diff_id!r} in this atlas (see list_diffs)"}
    refusal = refuse_stale_diff(
        atlas, diff_id, build_hash=build_hash, current=current, commit=commit
    )
    if refusal is not None:
        return refusal
    bad = _check_args(evidence_ref, candidate_anchor, members_offset, members_limit)
    if bad is not None:
        return {"diff_id": diff_id, "error": bad}
    inp = _resolve_input(meta, evidence_ref, candidate_anchor)
    if isinstance(inp, str):
        return {"diff_id": diff_id, "error": inp}

    # The input is checked against the side's candidates, not against the view: a diff the view
    # withholds as a whole still has its candidates, and its members are counted unreadable.
    side, calls, rows = "", [], []
    for s in (inp.side,) if inp.side else ("a", "b"):
        sha = meta.sha[s]
        if not sha:
            return {
                "diff_id": diff_id,
                "error": (
                    f"diff {diff_id!r} records no content hash for side {s}: the calls of the same "
                    "binary cannot be read"
                ),
            }
        side_calls = _calls(atlas, meta.run[s], sha)
        found = [c for c in side_calls if c.ref == inp.ref]
        if found:
            side, calls, rows = s, side_calls, found
            break
    if not rows:
        s = inp.side or "a"
        return {
            "diff_id": diff_id,
            "error": (
                f"{inp.ref!r} is not a candidate of {meta.binary[s]!r} on side {s} of this diff "
                f"(run {meta.run[s]!r})"
            ),
        }
    if inp.sink_class is not None:
        rows = [c for c in rows if c.sink_class == inp.sink_class]
        if not rows:
            return {
                "diff_id": diff_id,
                "error": (
                    f"the anchor's sink class {inp.sink_class!r} is not a class {inp.ref!r} is "
                    "recorded with"
                ),
            }
    keyed = [c for c in rows if c.unkeyed is None]
    if not keyed:
        return {
            "diff_id": diff_id,
            "error": f"{inp.ref!r} cannot be given a shape: {rows[0].unkeyed}",
        }
    groups = _groups(calls)
    mine = [c for c in keyed if c.granularity in MEMBER_GRANULARITIES]
    head: dict[str, Any] = {
        "diff_id": diff_id,
        "side": side,
        "binary": meta.binary[side],
        "input": {"evidence_ref": inp.ref, "key_granularity": keyed[0].granularity},
    }
    if not mine:
        if members_offset is not None:
            return {
                "diff_id": diff_id,
                "error": f"{inp.ref!r} is no group's member, so there are no members to page",
            }
        staleness = diff_source_staleness(atlas, diff_id)
        return {
            **head,
            "not_a_member": True,
            "key_granularity": keyed[0].granularity,
            "f2_keys": _shape_keys(meta, side, keyed, groups),
            "source_stale": staleness["source_stale"],
            "source_stale_reason": staleness["source_stale_reason"],
            "note": (
                "A function-level candidate has no call address of its own (several calls can "
                "share its ref), so it is no group's member. f2_keys are the shapes it has, each "
                "with this side's group of that shape, if there is one."
            ),
        }
    keys = sorted({c.key for c in mine})
    if len(keys) > 1:
        return {
            "diff_id": diff_id,
            "error": (
                f"{inp.ref!r} is recorded with {len(keys)} shapes, so it is a member of "
                f"{len(keys)} groups; name it by a candidate anchor, whose sink class narrows it"
            ),
            "f2_keys": _shape_keys(meta, side, mine, groups),
        }
    (key,) = keys
    members = groups[key]
    built = build_diff_view(atlas, diff_id)
    assert built is not None  # the diff_meta row was just read
    states = _states(built, side, members)
    side_db = _read_side(atlas, meta.run[side], meta.sha[side])
    if members_offset is None:
        page_ref: dict[str, Any] = {"diff_id": diff_id}
        page_ref["candidate_anchor" if candidate_anchor is not None else "evidence_ref"] = (
            candidate_anchor if candidate_anchor is not None else inp.ref
        )
        page_ref["members_offset"] = 0
        group = _group_object(
            atlas, meta, built, side, key, members, states, calls, side_db, page_ref
        )
        return {**head, **group}
    ordered = sorted(members, key=_order)
    total = len(ordered)
    if members_offset >= total and members_offset > 0:
        return {
            "diff_id": diff_id,
            "error": f"members_offset {members_offset} is past the group's {total} members",
            "member_count": total,
        }
    end = members_offset + members_limit
    page = ordered[members_offset:end]
    return {
        **head,
        "group_ref": group_ref(diff_id, key, side, _fp_version(members)),
        "member_count": total,
        "members_order": MEMBERS_ORDER,
        "members_offset": members_offset,
        "members": [_member_row(meta, side, c, states[c.ref or ""], side_db.names) for c in page],
        "members_next_offset": end if end < total else None,
        "source_stale": built.staleness.get("source_stale"),
        "source_stale_reason": built.staleness.get("source_stale_reason"),
    }
