# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The review of one run pair cut into work units: the must-read set, the order units are handed
out in, and how far the review has come — derived from the facts and the judgements, never stored.

The must-read set (predicate ``PREDICATE_VERSION``) is the read rule the review start already
states, made checkable, plus what it left out. An entry of a diff is must-read when it is

* a P entry (a function in no matched pair) — ``p_entry``;
* an entry carrying a ``lift_basis`` (whatever its page) — ``lift_basis``;
* an attention-0 entry — ``attention_0``;
* a bucket S entry — ``bucket_s`` (handed out per binary, as a batch);
* an R entry whose one side is not in that scan's function inventory (its candidate count there is
  unknown) while the other side names a sink candidate — ``side_not_in_inventory``;
* an aligned pair whose ``sink_callsite_counts`` shows fewer calls on the B side of a command sink
  (the command class, ``_eval`` or ``execvpe``) — ``command_calls_fewer`` (a side that cannot be
  counted is unknown, never fewer);
* among the first ``k`` entries of its diff in the default order — ``top_k``.

Besides the entries, every binary one run of the pair holds alone (``binary_presence``) and every
changed non-binary file of the pair is a must-read unit of its own. Every candidate row of a
must-read entry is read with it (its unit's material). The listed entries outside the set are the
second tier, handed out in batches per diff and bucket: the set orders what is read first and says
when the must-read part is done; it is not a part that may be skipped.

Order (dispatch): round robin by position. Each diff is a stream of its entries in its own default
(significance) order; the binary_presence binaries and the changed files are two more streams.
Round r hands out the r-th item of every stream before any (r+1)-th — no significance is compared
across diffs, so the order is computable and deterministic. A unit takes the position of its first
member.

A unit's id is a hash of its kind, its sorted member anchors and the predicate version; a shard
``worker`` of ``workers`` takes the units whose id's first eight hex digits, read as an integer,
are ``worker`` modulo ``workers``. A member is disposed when its judgement reads ``open``
(change_inconclusive) or ``concluded``; unjudged, needs_recheck and needs_relabel are not.

The structure (units and their members) depends on the facts and the predicate only, never on a
judgement, so it is cached by each diff's fact key and the predicate; progress re-reads only the
judgements against the cached facts.
"""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from typing import Any

from treasure_map.lib.pattern import classes
from treasure_map.lib.query import diff_review as dr
from treasure_map.lib.query.coverage import CONCLUDED, OPEN, UNSEEN

PREDICATE_VERSION = "v0"
DEFAULT_K = 4
MAX_K = 200
# A batch unit holds at most this many members: what one annotate_diff_batch call takes.
BATCH_MAX = 200

# The sinks whose fewer calls on the B side make an aligned pair must-read: the command class and
# the command-like families the hunt does not recall (argv_runner, exec_path_variant).
COMMAND_CALL_SINKS: frozenset[str] = frozenset(classes.CMD) | frozenset({"_eval", "execvpe"})

REASONS = (
    "p_entry",
    "lift_basis",
    "attention_0",
    "bucket_s",
    "side_not_in_inventory",
    "command_calls_fewer",
    "top_k",
    "binary_presence",
    "non_binary_file",
)

# Unit kinds.
ENTRY, S_BATCH, PRESENCE, FILE, SECOND_TIER = (
    "entry",
    "s_batch",
    "binary_presence",
    "non_binary_file",
    "second_tier_batch",
)
UNIT_KINDS = (ENTRY, S_BATCH, PRESENCE, FILE, SECOND_TIER)
DISPOSED_STATES = frozenset({OPEN, CONCLUDED})
PRESENCE_STREAM, FILE_STREAM = "binary_presence", "non_binary_file"

# What this view cannot see, stated with every report; a gap is closed only by a judgement.
NOT_SEEN = (
    "local_buffer_size_unread",
    "size_constant_outside_sink_arg",
    "multi_hop",
    "compile_equivalent_changes",
    "kernel_modules_information_only",
    "cross_binary_sink_chain",
    "indirect_calls_via_dispatch_tables",
)


@dataclass(frozen=True)
class Member:
    """One subject of a unit: a diff entry, a binary_presence binary or a changed file."""

    anchor_ref: str
    kind: str  # "entry" | "binary_presence" | "non_binary_file"
    stream: str  # its diff_id, or PRESENCE_STREAM / FILE_STREAM
    position: int  # its place in its stream
    entry_id: str | None = None
    bucket: str | None = None
    subclass: str | None = None
    attention: int | None = None
    lift_basis: str | None = None
    rows: int = 0  # its candidate rows
    reasons: tuple[str, ...] = ()

    @property
    def must_read(self) -> bool:
        return bool(self.reasons)


@dataclass(frozen=True)
class Unit:
    unit_id: str
    kind: str
    must_read: bool
    members: tuple[Member, ...]
    stream: str
    position: int  # its first member's place in its stream (the round it is handed out in)
    stream_index: int  # its stream's place among the streams

    @property
    def order(self) -> tuple[int, int, str]:
        return (self.position, self.stream_index, self.unit_id)


def unit_id(kind: str, anchors: Iterable[str], predicate_version: str = PREDICATE_VERSION) -> str:
    """A unit's id: its kind, its member anchors (sorted) and the predicate version, hashed."""
    blob = "\n".join([kind, predicate_version, *sorted(anchors)])
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def in_shard(uid: str, worker: int | None, workers: int | None) -> bool:
    """Whether unit ``uid`` belongs to shard ``worker`` of ``workers`` (every unit when unset)."""
    if worker is None or workers is None:
        return True
    return int(uid[:8], 16) % workers == worker


# ── the must-read predicate on one diff entry ───────────────────────────────────────────────


def _side_not_in_inventory(e: Any) -> bool:
    counts = e.sink_candidate_counts
    if e.shown_bucket != "R" or not counts:
        return False
    return any(
        u.get("reason") == "function_not_in_scan_inventory" and u.get("sink") is not None
        for u in counts.get("unknown") or []
    )


def _command_calls_fewer(e: Any) -> bool:
    counts = e.sink_callsite_counts
    if e.pair is None or not e.pair.aligned or not counts:
        return False
    return any(
        d.get("sink") in COMMAND_CALL_SINKS
        and isinstance(d.get("a"), int)
        and isinstance(d.get("b"), int)
        and d["b"] < d["a"]
        for d in counts.get("delta") or []
    )


def entry_reasons(
    e: Any, position: int, attention: int, lift_basis: str | None, k: int
) -> tuple[str, ...]:
    """Why one listed entry is must-read (``REASONS`` order); empty when it is second tier."""
    out = []
    bucket = e.shown_bucket
    if bucket == "P":
        out.append("p_entry")
    if lift_basis is not None:
        out.append("lift_basis")
    if attention == 0:
        out.append("attention_0")
    if bucket == "S":
        out.append("bucket_s")
    if _side_not_in_inventory(e):
        out.append("side_not_in_inventory")
    if _command_calls_fewer(e):
        out.append("command_calls_fewer")
    if position < k:
        out.append("top_k")
    return tuple(out)


# ── the facts of one diff, as the units read them ───────────────────────────────────────────


@dataclass
class DiffFacts:
    """One diff of the pair as its units read it: its listed entries in the default order (as
    members, with every predicate reason computed for ``k`` = MAX_K so any k reads from it), and
    the facts each judgement on it is read against (anchor -> subject)."""

    diff_id: str
    binary: str | None
    diff_ok: bool
    withheld: bool
    banners: list[str]
    entries: list[Member]
    subjects: dict[str, dr.Subject]
    run_a: str
    run_b: str


def diff_facts(atlas: sqlite3.Connection, diff_id: str, diff_ok: bool = True) -> DiffFacts | None:
    """Read one diff (its default-order listing) into ``DiffFacts``; None when there is no such
    diff."""
    from treasure_map.lib.query.patch_view import significance_listing

    listing = significance_listing(atlas, diff_id)
    if listing is None:
        return None
    d = listing.built.diff
    entries = []
    for o in listing.entries:
        e = o.entry
        entries.append(
            Member(
                anchor_ref=o.item.anchor_ref,
                kind="entry",
                stream=diff_id,
                position=o.position,
                entry_id=e.entry_id,
                bucket=e.shown_bucket,
                subclass=e.shown_subclass,
                attention=o.attention,
                lift_basis=o.lift_basis,
                rows=len(e.row_views),
                # Every reason but top_k: that one depends on k and is added when units are cut.
                reasons=tuple(
                    r
                    for r in entry_reasons(e, o.position, o.attention, o.lift_basis, 0)
                    if r != "top_k"
                ),
            )
        )
    subjects: dict[str, dr.Subject] = {}
    if d.binary and not listing.withheld:
        full = dr.subjects_of(listing.built.placed, d.run_a, d.run_b, d.binary)
        # Facts only: a judgement is read against its subject's facts (diff_review.judge).
        subjects = {a: dr.Subject(s.kind, s.facts) for a, s in full.items()}
    return DiffFacts(
        diff_id=diff_id,
        binary=d.binary,
        diff_ok=diff_ok,
        withheld=listing.withheld,
        banners=list(listing.built.banners),
        entries=entries,
        subjects=subjects,
        run_a=d.run_a,
        run_b=d.run_b,
    )


# ── the pair ────────────────────────────────────────────────────────────────────────────────


@dataclass
class PairFacts:
    """Everything the pair's units are cut from: each diff's facts, the binary_presence binaries
    and the changed files (as members), and what no unit can reach (failed / withheld diffs, the
    binaries no diff covers, files that could not be read)."""

    run_a: str
    run_b: str
    diffs: list[DiffFacts]
    presence: Any  # binary_presence.Presence
    presence_members: list[Member]
    pair_files: Any  # file_diff.PairFiles | None
    file_members: list[Member]
    files_unavailable: str | None
    failed_diffs: list[dict[str, Any]]
    not_diffed_binaries: dict[str, Any]
    identical_not_diffed: dict[str, Any]


def pair_facts(
    atlas: sqlite3.Connection,
    run_a: str,
    run_b: str,
    diff_reader: Callable[[sqlite3.Connection, str, bool], DiffFacts | None] = diff_facts,
) -> PairFacts:
    """Read the pair. ``diff_reader`` reads one diff (``diff_facts``, or a cached reader)."""
    from treasure_map.lib.query import binary_presence as bp
    from treasure_map.lib.query import file_diff as fd
    from treasure_map.lib.query.diff_align import (
        list_diff_blindspots,
        not_diffed_binaries,
        not_diffed_groups,
        split_not_diffed,
    )
    from treasure_map.lib.query.diff_annotations import _pair_diffs

    rows = _pair_diffs(atlas, dr.run_pair(run_a, run_b))
    diffs = []
    for r in rows:
        got = diff_reader(atlas, str(r["diff_id"]), bool(r["diff_ok"]))
        if got is not None:
            diffs.append(got)
    blind = list_diff_blindspots(atlas, run_a, run_b)
    failed = [
        {k: b[k] for k in ("diff_id", "binary", "diff_status_reason", "diff_attempts")}
        for b in blind["blindspots"]
    ]
    groups = not_diffed_groups(atlas, run_a, run_b)
    presence = bp.find_presence(atlas, run_a, run_b, groups)
    presence_members = [
        Member(
            anchor_ref=presence.anchor(b),
            kind="binary_presence",
            stream=PRESENCE_STREAM,
            position=i,
            bucket="binary_presence",
            subclass=b.tag,
            rows=b.candidates,
            reasons=("binary_presence",),
        )
        for i, b in enumerate(sorted(presence.items, key=lambda b: (b.tag, b.rel_path)))
    ]
    files_unavailable: str | None = None
    pf = None
    file_members: list[Member] = []
    try:
        pf = fd.read_pair(atlas, run_a, run_b)
        changed = [af for af in fd.aligned_files(pf) if af.status in fd.CHANGED_STATUSES]
        file_members = [
            Member(
                anchor_ref=dr.non_binary_anchor(run_a, run_b, af.path),
                kind="non_binary_file",
                stream=FILE_STREAM,
                position=i,
                bucket="non_binary_file",
                subclass=af.status,
                reasons=("non_binary_file",),
            )
            for i, af in enumerate(sorted(changed, key=lambda af: af.path))
        ]
    except fd.FileDiffError as exc:
        files_unavailable = str(exc)
    blind_not_diffed, identical = split_not_diffed(
        not_diffed_binaries(atlas, run_a, run_b, exclude=presence.excluded, groups=groups)
    )
    return PairFacts(
        run_a=run_a,
        run_b=run_b,
        diffs=diffs,
        presence=presence,
        presence_members=presence_members,
        pair_files=pf,
        file_members=file_members,
        files_unavailable=files_unavailable,
        failed_diffs=failed,
        not_diffed_binaries=blind_not_diffed,
        identical_not_diffed=identical,
    )


def _with_top_k(m: Member, k: int) -> Member:
    if m.kind != "entry" or m.position >= k or "top_k" in m.reasons:
        return m
    return replace(m, reasons=(*m.reasons, "top_k"))


def _chunks(members: list[Member]) -> list[list[Member]]:
    return [members[i : i + BATCH_MAX] for i in range(0, len(members), BATCH_MAX)]


def cut_units(facts: PairFacts, k: int = DEFAULT_K) -> list[Unit]:
    """Every unit of the pair, in the order they are handed out (``Unit.order``)."""
    units: list[Unit] = []
    streams = [d.diff_id for d in sorted(facts.diffs, key=lambda d: d.diff_id)]
    streams += [PRESENCE_STREAM, FILE_STREAM]
    index = {s: i for i, s in enumerate(streams)}

    def add(kind: str, members: list[Member], must_read: bool) -> None:
        first = min(members, key=lambda m: m.position)
        units.append(
            Unit(
                unit_id=unit_id(kind, (m.anchor_ref for m in members)),
                kind=kind,
                must_read=must_read,
                members=tuple(sorted(members, key=lambda m: m.position)),
                stream=first.stream,
                position=first.position,
                stream_index=index[first.stream],
            )
        )

    for d in facts.diffs:
        if d.withheld:
            continue
        s_members: list[Member] = []
        second: dict[str, list[Member]] = {}
        for raw in d.entries:
            m = _with_top_k(raw, k)
            if m.bucket == "S":
                s_members.append(m)
            elif m.must_read:
                add(ENTRY, [m], True)
            else:
                second.setdefault(m.bucket or "", []).append(m)
        for chunk in _chunks(s_members):
            add(S_BATCH, chunk, True)
        for bucket in sorted(second):
            for chunk in _chunks(second[bucket]):
                add(SECOND_TIER, chunk, False)
    for m in facts.presence_members:
        add(PRESENCE, [m], True)
    for m in facts.file_members:
        add(FILE, [m], True)
    units.sort(key=lambda u: u.order)
    return units


# ── progress: the judgements read against the cached facts ──────────────────────────────────


@dataclass
class Progress:
    """Each member anchor's review state, and what the pair-level completion reads."""

    states: dict[str, str] = field(default_factory=dict)
    dangling: list[str] = field(default_factory=list)


def read_progress(
    atlas: sqlite3.Connection,
    facts: PairFacts,
    *,
    pair_staleness: dict[str, Any],
    diff_staleness: Callable[[str], dict[str, Any]],
    group_review: Callable[[str, dict[str, Any]], dict[str, Any] | None] | None = None,
) -> Progress:
    """Every member's review state: the pair's judgements read against the cached facts, each
    diff's with its own staleness (``diff_staleness(diff_id)``), the binary_presence and file
    judgements with the pair's (``pair_staleness``). ``group_review(diff_id, stored_group)``
    re-reads a same-shape group a judgement leaned on (None: such a judgement is read on its own
    facts)."""
    from treasure_map.lib.query import binary_presence as bp
    from treasure_map.lib.query import file_diff as fd

    out = Progress()
    rows = dr.read_judgements(atlas, facts.run_a, facts.run_b)
    for d in facts.diffs:
        if d.withheld:
            continue
        diff_id = d.diff_id

        def _group(stored: dict[str, Any], diff_id: str = diff_id) -> dict[str, Any] | None:
            return group_review(diff_id, stored) if group_review is not None else None

        judged, dangling = dr.judgements_for(
            rows,
            diff_id=diff_id,
            run_a=d.run_a,
            run_b=d.run_b,
            binary=d.binary,
            subjects=d.subjects,
            withheld=False,
            staleness=diff_staleness(diff_id),
            group_review=_group if group_review is not None else None,
        )
        out.dangling += dangling
        for m in d.entries:
            out.states[m.anchor_ref] = dr.review_state(judged.get(m.anchor_ref))
    stale = pair_staleness.get("source_stale")
    reason = pair_staleness.get("source_stale_reason")
    presence_judged = bp.presence_review(
        atlas, facts.presence, source_stale=stale, source_stale_reason=reason
    )
    for m in facts.presence_members:
        out.states[m.anchor_ref] = dr.review_state(presence_judged.get(m.anchor_ref))
    if facts.pair_files is not None:
        file_judged = fd.file_review(
            atlas,
            facts.run_a,
            facts.run_b,
            source_stale=stale,
            source_stale_reason=reason,
            pf=facts.pair_files,
        )
        for m in facts.file_members:
            out.states[m.anchor_ref] = dr.review_state(file_judged.get(m.anchor_ref))
    return out


def disposed(state: str | None) -> bool:
    return state in DISPOSED_STATES


def unit_disposed(u: Unit, states: dict[str, str]) -> bool:
    return all(disposed(states.get(m.anchor_ref)) for m in u.members)


def next_unit(
    units: list[Unit],
    states: dict[str, str],
    worker: int | None = None,
    workers: int | None = None,
) -> Unit | None:
    """The first unit, in the order they are handed out, of this shard with a member not yet
    disposed."""
    for u in units:
        if in_shard(u.unit_id, worker, workers) and not unit_disposed(u, states):
            return u
    return None


# ── the report ──────────────────────────────────────────────────────────────────────────────


def report(
    facts: PairFacts,
    units: list[Unit],
    progress: Progress,
    *,
    k: int,
    server_commit: str | None,
) -> dict[str, Any]:
    """The pair's report: the must-read set by unit kind and by reason, how much of it and of every
    listed subject is disposed, ``must_read_complete`` beside the existing ``complete``, what no
    unit can reach, and the one-line ``coverage_statement``."""
    states = progress.states
    must = [u for u in units if u.must_read]
    must_members = [m for u in must for m in u.members]
    all_members = [m for u in units for m in u.members]
    by_kind: dict[str, dict[str, int]] = {}
    for u in units:
        row = by_kind.setdefault(u.kind, {"units": 0, "disposed": 0, "members": 0})
        row["units"] += 1
        row["members"] += len(u.members)
        row["disposed"] += unit_disposed(u, states)
    by_reason: dict[str, int] = dict.fromkeys(REASONS, 0)
    for m in must_members:
        for r in m.reasons:
            by_reason[r] += 1
    withheld = [
        {"diff_id": d.diff_id, "banners": d.banners}
        for d in facts.diffs
        if d.withheld and d.diff_ok
    ]
    must_done = sum(1 for m in must_members if disposed(states.get(m.anchor_ref)))
    all_done = sum(1 for m in all_members if disposed(states.get(m.anchor_ref)))
    unseen = sum(1 for m in all_members if states.get(m.anchor_ref, UNSEEN) == UNSEEN)
    must_read_complete = must_done == len(must_members) and not withheld and not facts.failed_diffs
    complete = (
        unseen == 0
        and not facts.failed_diffs
        and not withheld
        and not facts.not_diffed_binaries
        and facts.files_unavailable is None
    )
    server = server_commit or "unknown"
    statement = (
        f"must-read {len(must_members)} / disposed {must_done}; "
        f"all subjects {len(all_members)} / disposed {all_done}; "
        f"open audits 0; reduce not run; predicate {PREDICATE_VERSION} (k={k}); server {server}"
    )
    return {
        "run_pair": dr.run_pair(facts.run_a, facts.run_b),
        "predicate_version": PREDICATE_VERSION,
        "k": k,
        "coverage_statement": statement,
        "must_read": {
            "units": len(must),
            "units_disposed": sum(1 for u in must if unit_disposed(u, states)),
            "members": len(must_members),
            "members_disposed": must_done,
            "candidate_rows": sum(m.rows for m in must_members if m.kind == "entry"),
            "by_reason": by_reason,
        },
        "units_by_kind": by_kind,
        "all_listed": {"members": len(all_members), "disposed": all_done, "unjudged": unseen},
        "must_read_complete": must_read_complete,
        "complete": complete,
        "not_reachable": {
            "failed_diffs": facts.failed_diffs,
            "withheld_diffs": withheld,
            "not_diffed_binaries": facts.not_diffed_binaries,
            "non_binary_files_unavailable": facts.files_unavailable,
        },
        "not_seen": list(NOT_SEEN),
        "dangling_judgements": sorted(progress.dangling),
    }


# ── the cached reading of a pair ────────────────────────────────────────────────────────────

# Each diff's facts, by its fact key and the predicate version (a judgement never enters it). Long
# lived in the MCP server: the least recently used go first.
_DIFF_CACHE_MAX = 512


class _DiffCache:
    def __init__(self) -> None:
        from collections import OrderedDict

        self.data: OrderedDict[tuple[str, ...], DiffFacts] = OrderedDict()
        self.hits = 0
        self.misses = 0

    def read(self, atlas: sqlite3.Connection, diff_id: str, diff_ok: bool) -> DiffFacts | None:
        from treasure_map.lib.query.patch_view import diff_fact_key

        key = diff_fact_key(atlas, diff_id)
        if key is None:
            return None
        full = (*key, PREDICATE_VERSION, str(diff_ok))
        hit = self.data.get(full)
        if hit is not None:
            self.hits += 1
            self.data.move_to_end(full)
            return hit
        self.misses += 1
        got = diff_facts(atlas, diff_id, diff_ok)
        if got is not None:
            self.data[full] = got
            while len(self.data) > _DIFF_CACHE_MAX:
                self.data.popitem(last=False)
        return got

    def clear(self) -> None:
        self.data.clear()


DIFF_CACHE = _DiffCache()


def _group_reader(
    atlas: sqlite3.Connection,
) -> Callable[[str, dict[str, Any]], dict[str, Any] | None]:
    """Re-read a same-shape group a judgement leaned on, building its diff on first use (rare: only
    a judgement that recorded a group needs it)."""
    from treasure_map.lib.query.diff_group_freshness import group_moved
    from treasure_map.lib.query.patch_view import build_diff_view, listed_view

    built_by: dict[str, Any] = {}
    caches: dict[str, dict[tuple[str, str], Any]] = {}

    def read(diff_id: str, stored: dict[str, Any]) -> dict[str, Any] | None:
        if diff_id not in built_by:
            built = build_diff_view(atlas, diff_id)
            if built is not None:
                listed_view(atlas, built)
            built_by[diff_id] = built
        built = built_by[diff_id]
        if built is None:
            return {"group_unreadable": "the diff is gone"}
        return group_moved(atlas, built, stored, caches.setdefault(diff_id, {}))

    return read


@dataclass
class PairReview:
    """One reading of a pair: its facts, its units (for ``k``), every member's state, the report."""

    facts: PairFacts
    units: list[Unit]
    progress: Progress
    report: dict[str, Any]
    k: int

    def unit(self, uid: str) -> Unit | None:
        return next((u for u in self.units if u.unit_id == uid), None)

    def next_unit(self, worker: int | None = None, workers: int | None = None) -> Unit | None:
        return next_unit(self.units, self.progress.states, worker, workers)


def review_pair(
    atlas: sqlite3.Connection,
    run_a: str,
    run_b: str,
    *,
    k: int = DEFAULT_K,
    pair_staleness: dict[str, Any],
    server_commit: str | None,
    cache: _DiffCache | None = DIFF_CACHE,
) -> PairReview:
    """Read the pair's review: facts (each diff's through ``cache``), units, progress and report.
    ``pair_staleness`` is the caller's reading of the two runs (``source_stale`` /
    ``source_stale_reason``) for the binary_presence and file judgements; each diff's own
    staleness is read here."""
    # The staleness each diff's view reads (patch_view's own reference to it), so a judgement here
    # reads exactly as it does on the diff's page.
    from treasure_map.lib.query import patch_view as pv

    reader = cache.read if cache is not None else diff_facts
    facts = pair_facts(atlas, run_a, run_b, reader)
    units = cut_units(facts, k)
    progress = read_progress(
        atlas,
        facts,
        pair_staleness=pair_staleness,
        diff_staleness=lambda d: pv.view_staleness(atlas, d),
        group_review=_group_reader(atlas),
    )
    return PairReview(
        facts, units, progress, report(facts, units, progress, k=k, server_commit=server_commit), k
    )


def pair_staleness(
    atlas: sqlite3.Connection, run_a: str, run_b: str, config: Any = None
) -> dict[str, Any]:
    """The reading of the pair's two runs the binary_presence and file judgements are read with,
    for a caller with no stale-run gate of its own (the command line): ``source_stale`` true with
    the run named when either run was provably produced by other code than is running, else
    false. The MCP server refuses such a pair instead."""
    from treasure_map.lib import rescan_version
    from treasure_map.lib.analyze.ghidra_runner import current_pass_version
    from treasure_map.lib.config.config import load_config
    from treasure_map.lib.query.runs import get_run, run_staleness
    from treasure_map.version import installed_commit

    cfg = config if config is not None else load_config(None)
    current = rescan_version.current_code_stamp(cfg)
    for run_id in (run_a, run_b):
        run = get_run(atlas, run_id)
        if run is None:
            continue
        st = run_staleness(
            run, build_hash=current_pass_version(), current=current, commit=installed_commit()
        )
        if st.stale:
            return {"source_stale": True, "source_stale_reason": f"stale_scan:{run_id}"}
    return {"source_stale": False, "source_stale_reason": None}
