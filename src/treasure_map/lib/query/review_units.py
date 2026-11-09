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
* a bucket B entry of attention 0 or 1 whose subclass is ``sink_present_no_visible_delta`` or
  ``instruction_unmatched`` — ``aligned_b_sink``;
* among the first ``k`` entries of its diff in the default order — ``top_k``.

Besides the entries, every changed non-binary file of the pair is a must-read unit of its own, and
so are the binaries one run of the pair holds alone (``binary_presence``): each function of such a
binary holding a candidate is a must-read member (a binary holding none is one member on its own
anchor), handed out per binary in batches. Such a member is disposed only when its judgement, of
whatever verdict, cites every candidate of its subject (``presence_citations_short``). Every
candidate row of a must-read entry is read with it: its unit's material carries up to a page of
its rows (an entry alone, or each entry of a batch or group), the rest read on by entry_id and
rows_offset; a member whose rows were not all delivered is not read whole by the material, and a
judgement written having read only part of them is counted under ``basis_incomplete`` — as is one
written having read the subject itself only in part by a tool that pages it (a function's
pseudocode, disassembly or callees, a file's line difference: ``read_partial``). The listed
entries
outside the set are the second tier, handed out in batches per diff and bucket: the set orders
what is read first and says when the must-read part is done; it is not a part that may be skipped.

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
import json
import sqlite3
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from typing import Any

from treasure_map.lib.pattern import classes
from treasure_map.lib.query import diff_review as dr
from treasure_map.lib.query.coverage import CONCLUDED, NEEDS_RECHECK, OPEN, UNSEEN

PREDICATE_VERSION = "v2"
DEFAULT_K = 4
MAX_K = 200
# At most this many items in one annotate_diff_batch call.
BATCH_MAX = 200
# A batch unit (bucket S, second tier) holds at most this many members: about what one page's
# material shows (an entry's scan runs ~2 KB, ~3.5 KB at the 90th percentile), so a unit is read
# and judged from the page it is handed out on.
BATCH_UNIT_MAX = 16

# The sinks whose fewer calls on the B side make an aligned pair must-read: the command class (the
# exec-path variant among it) and the argv-array runner the hunt does not recall.
COMMAND_CALL_SINKS: frozenset[str] = frozenset(classes.CMD) | frozenset({"_eval", "execvpe"})
# The B subclasses whose attention-0/1 entries are must-read (``aligned_b_sink``): a sink candidate
# whose matched pair shows no visible delta at it, or whose sink instruction found no match on the
# other side — a fix to a sink call can read as either, ranked past the first k.
ALIGNED_B_SINK_SUBCLASSES: frozenset[str] = frozenset(
    {"sink_present_no_visible_delta", "instruction_unmatched"}
)

REASONS = (
    "p_entry",
    "lift_basis",
    "attention_0",
    "bucket_s",
    "side_not_in_inventory",
    "command_calls_fewer",
    "aligned_b_sink",
    "top_k",
    "binary_presence",
    "non_binary_file",
)

# Unit kinds.
ENTRY, S_BATCH, PRESENCE, FILE, SECOND_TIER, AUDIT, GROUP, REDUCE = (
    "entry",
    "s_batch",
    "binary_presence",
    "non_binary_file",
    "second_tier_batch",
    "audit",
    "callee_group",
    "reduce",
)
UNIT_KINDS = (ENTRY, S_BATCH, PRESENCE, FILE, SECOND_TIER, AUDIT, GROUP, REDUCE)
# Where a unit of a kind sorts among the units at the same place: a group first (its members read
# together), an audit after the unit its member came from.
_KIND_RANK = {GROUP: -1, AUDIT: 1}
# How many disagreements the report lists (the count is always exact).
DISAGREEMENTS_SHOWN = 20
# The judgements an audit reads blind: why one is opened. ``unread_before_verdict`` is NOT here any
# more — a subject judged before it was read is now a non-blind NEEDS_RECHECK (always on), not a
# blind audit unit (see ``read_audits`` and ``BLIND_AUDIT_ENABLED``).
AUDIT_SOURCES = ("change_inconclusive", "no_real_change")
# Blind auditing (the blind second reading of a no_real_change / change_inconclusive, and the shadow
# write it records) is SEALED off by default. Before flipping this back to True, all three must
# hold:
#   1. the blind launch keeps its prompt (A-4: the single-token --disallowedTools form);
#   2. a server-side audit mode: an audit session's replies carry no verdict / review_state;
#   3. an interactive session can close an audit unit (R-5). Today it cannot: the pair overview
#      start_diff_review(run_pair) is itself off the blind-read whitelist, so a session walking the
#      loop is handed the same audit unit round after round and every shadow it writes is
#      non-blind (``open audits`` never reaches 0). The fix then: the overview and a write's
#      next_unit skip AUDIT units; an audit unit is handed out only through ``unit=`` as a
#      session's FIRST call (the batch driver's); the report counts "audits pending (fresh
#      session)" apart.
# Until then a blind reading shares its parent's MCP connection and verdict context, so its record
# is not trustworthy. The "judged unread -> NEEDS_RECHECK" and "overwritten by another session"
# signals do NOT depend on this flag; they stay on so must_read_complete never goes green on an
# unread verdict.
BLIND_AUDIT_ENABLED = False
# The writes a person makes: never audited, and what settles a disagreement.
HUMAN = "human"
DISPOSED_STATES = frozenset({OPEN, CONCLUDED})
PRESENCE_STREAM, FILE_STREAM, REDUCE_STREAM = "binary_presence", "non_binary_file", "reduce"
# The reduce unit is handed out after every other unit.
_REDUCE_POSITION = 1 << 30

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
    """One subject of a unit: a diff entry, a binary_presence subject (a function of a one-sided
    binary, or such a binary) or a changed file."""

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
    group: dict[str, Any] | None = None  # a callee group unit's group (DiffFacts.groups)

    @property
    def order(self) -> tuple[int, int, int, str]:
        return (self.position, self.stream_index, _KIND_RANK.get(self.kind, 0), self.unit_id)


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
    if bucket == "B" and attention <= 1 and e.shown_subclass in ALIGNED_B_SINK_SUBCLASSES:
        out.append("aligned_b_sink")
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
    # The diff's callee groups (lib/query/callee_groups): ``{callee_b, callee_a, name, ref,
    # members (entry ids), members_possibly_incomplete}``, every member a listed paired entry.
    groups: list[dict[str, Any]] = field(default_factory=list)
    # The anchors of the listed entries and of their candidate rows: a judgement whose subject is
    # in ``subjects`` but not here reads subject_unlisted (diff_review.unlisted_judgements).
    listed_anchors: frozenset[str] = frozenset()


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
    listed_anchors: frozenset[str] = frozenset()
    if d.binary and not listing.withheld:
        full = dr.subjects_of(listing.built.placed, d.run_a, d.run_b, d.binary)
        # Facts only: a judgement is read against its subject's facts (diff_review.judge).
        subjects = {a: dr.Subject(s.kind, s.facts) for a, s in full.items()}
        listed_anchors = frozenset(
            dr.anchors_of([o.entry for o in listing.entries], d.run_a, d.run_b, d.binary)
        )
    groups: list[dict[str, Any]] = []
    if not listing.withheld:
        from treasure_map.lib.query.callee_groups import callee_groups

        listed = [o.entry for o in listing.entries]
        for g in callee_groups(atlas, listing.built, listed).values():
            groups.append(
                {
                    "callee_b": g.callee_b,
                    "callee_a": g.callee_a,
                    "name": g.callee_name,
                    "ref": g.ref,
                    "members": list(g.members),
                    "members_possibly_incomplete": g.members_possibly_incomplete,
                    "members_a_side_unread": g.members_a_side_unread,
                }
            )
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
        groups=groups,
        listed_anchors=listed_anchors,
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
            anchor_ref=s.anchor,
            kind="binary_presence",
            stream=PRESENCE_STREAM,
            position=i,
            bucket="binary_presence",
            subclass=s.binary.tag,
            rows=len(s.refs),
            reasons=("binary_presence",),
        )
        for i, s in enumerate(bp.review_subjects(presence))
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
    return [members[i : i + BATCH_UNIT_MAX] for i in range(0, len(members), BATCH_UNIT_MAX)]


def _assign_groups(d: DiffFacts, k: int) -> dict[str, tuple[dict[str, Any], list[Member]]]:
    """The callee groups of one diff that hold at least two must-read members, each with the
    must-read members it hands out: a member in several groups goes with the one whose first
    member comes first (it is read once; the others only name it). A group whose members all went
    to earlier groups hands out nothing."""
    by_id = {m.entry_id: _with_top_k(m, k) for m in d.entries}
    eligible = []
    for g in d.groups:
        must = [by_id[e] for e in g["members"] if e in by_id and by_id[e].must_read]
        if len(must) >= 2:
            eligible.append((min(m.position for m in must), g["callee_b"], g, must))
    out: dict[str, tuple[dict[str, Any], list[Member]]] = {}
    taken: set[str | None] = set()
    for _pos, _x, g, must in sorted(eligible, key=lambda t: (t[0], t[1])):
        mine = [m for m in must if m.entry_id not in taken]
        if not mine:
            continue
        taken |= {m.entry_id for m in mine}
        out[g["ref"]] = (g, mine)
    return out


def cut_units(facts: PairFacts, k: int = DEFAULT_K) -> list[Unit]:
    """Every unit of the pair, in the order they are handed out (``Unit.order``)."""
    units: list[Unit] = []
    streams = [d.diff_id for d in sorted(facts.diffs, key=lambda d: d.diff_id)]
    streams += [PRESENCE_STREAM, FILE_STREAM]
    index = {s: i for i, s in enumerate(streams)}

    def add(
        kind: str, members: list[Member], must_read: bool, group: dict[str, Any] | None = None
    ) -> None:
        first = min(members, key=lambda m: m.position)
        anchors = [m.anchor_ref for m in members]
        if group is not None:
            anchors.append(group["ref"])
        units.append(
            Unit(
                unit_id=unit_id(kind, anchors),
                kind=kind,
                must_read=must_read,
                members=tuple(sorted(members, key=lambda m: m.position)),
                stream=first.stream,
                position=first.position,
                stream_index=index[first.stream],
                group=group,
            )
        )

    for d in facts.diffs:
        if d.withheld:
            continue
        s_members: list[Member] = []
        second: dict[str, list[Member]] = {}
        grouped = _assign_groups(d, k)
        for g, members in grouped.values():
            add(GROUP, members, True, g)
        taken = {m.entry_id for _g, members in grouped.values() for m in members}
        for raw in d.entries:
            m = _with_top_k(raw, k)
            if m.entry_id in taken:
                continue
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
    # A one-sided binary's subjects (its functions) are handed out together, in batches.
    by_binary: dict[str, list[Member]] = {}
    for m in facts.presence_members:
        fn = dr.split_presence_function(m.anchor_ref)
        by_binary.setdefault(fn[0] if fn is not None else m.anchor_ref, []).append(m)
    for members in by_binary.values():
        for chunk in _chunks(members):
            add(PRESENCE, chunk, True)
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
    # The dangling judgements themselves (their subject no longer resolves), for their verdicts.
    dangling_judged: list[dr.DiffAnnotation] = field(default_factory=list)
    # The judgements read subject_unlisted: their subject resolves but is not listed.
    unlisted: list[dr.DiffAnnotation] = field(default_factory=list)


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
        out.dangling_judged += [judged[a] for a in dangling if a in judged]
        out.unlisted += dr.unlisted_judgements(judged, d.listed_anchors).values()
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


# ── the binary_presence subjects: their candidates, and whether a judgement cites them ───────


def presence_ranked(atlas: sqlite3.Connection, run_id: str, binary_path: str) -> list[Any]:
    """The binary's candidates in its run, in the default triage order (list_candidates')."""
    from treasure_map.lib.query import apply_view, triage

    ranked = [c for c in triage(atlas, run_id=run_id) if c.binary_path == binary_path]
    return list(apply_view(ranked, view=None, sort_by=None, dim_filters=[], only_filters=[]))


def presence_citations_short(
    atlas: sqlite3.Connection, facts: PairFacts, states: dict[str, str]
) -> dict[str, dict[str, Any]]:
    """The disposed binary_presence judgements whose ``checked`` / ``evidence`` do not cite every
    candidate of their subject (binary_presence.required_citations: a function's candidates) —
    anchor -> what is missing (``required`` / ``cited`` / ``missing_sample``). Every verdict is
    held to it, change_inconclusive included."""
    from treasure_map.lib.query import binary_presence as bp

    out: dict[str, dict[str, Any]] = {}
    pair = dr.run_pair(facts.run_a, facts.run_b)
    rows = {
        r[0]: r[1]
        for r in atlas.execute(
            "SELECT anchor_ref, verdict_basis FROM overlay "
            "WHERE anchor_kind = 'diff_subject' AND run_id = ?",
            (pair,),
        )
    }
    for m in facts.presence_members:
        if not disposed(states.get(m.anchor_ref)) or m.anchor_ref not in rows:
            continue
        gap = bp.citation_gap(facts.presence, m.anchor_ref, rows[m.anchor_ref])
        if gap is not None and gap["cited"] < gap["required"]:
            out[m.anchor_ref] = gap
    return out


# ── reduce: every callee group's members read as one group ──────────────────────────────────


def read_reduce(atlas: sqlite3.Connection, facts: PairFacts, units: list[Unit]) -> list[Member]:
    """The judgements a reduce still owes, as members: every member a callee group unit handed out
    must be judged leaning on that group (its ``group_ref``), and so must the group's own callee
    entry when the view lists it and no group took it as a member. Read from the judgements' stored
    group blocks; empty when the reduce is done (or there is no group)."""
    pair = dr.run_pair(facts.run_a, facts.run_b)
    leaned: dict[str, str | None] = {}
    for anchor, basis in atlas.execute(
        "SELECT anchor_ref, basis_state FROM overlay WHERE anchor_kind = 'diff_subject' "
        "AND run_id = ?",
        (pair,),
    ):
        group = _json(basis).get("group")
        leaned[anchor] = group.get("group_ref") if isinstance(group, dict) else None
    groups = [u for u in units if u.kind == GROUP and u.group is not None]
    in_a_group = {m.entry_id for u in groups for m in u.members}
    entries = {(d.diff_id, m.entry_id): m for d in facts.diffs for m in d.entries}
    owed: list[Member] = []
    for u in groups:
        assert u.group is not None
        ref = u.group["ref"]
        x = u.group["callee_b"]
        need = list(u.members)
        key = next(
            (
                m
                for (diff_id, eid), m in entries.items()
                if diff_id == u.stream
                and eid is not None
                and (eid == f"b:{x}" or (eid.startswith("pair:") and eid.endswith(f":{x}")))
            ),
            None,
        )
        if key is not None and key.entry_id not in in_a_group:
            need.append(key)
        for m in need:
            if leaned.get(m.anchor_ref) != ref:
                owed.append(replace(m, reasons=(f"group_ref:{ref}",)))
    return owed


# ── audits and disagreements, read from the overlay and its history ────────────────────────


@dataclass(frozen=True)
class Audit:
    """A judgement owed a blind second reading: why (``sources``), the write it reads (its history
    row and session; None for a write older than the history), and its unit."""

    member: Member
    sources: tuple[str, ...]
    write_id: int | None
    write_session: str | None
    unit: Unit


@dataclass
class Audits:
    open: list[Audit] = field(default_factory=list)
    disagreements: list[dict[str, Any]] = field(default_factory=list)
    # Subjects judged unread: a write flagged ``unread_before_verdict`` not followed by a write
    # whose basis is other than ``none``, or a latest write with basis ``none`` on a subject the
    # report's own k makes must-read. Always computed, independent of ``BLIND_AUDIT_ENABLED``; the
    # caller sets each to NEEDS_RECHECK (not disposed).
    needs_recheck: list[str] = field(default_factory=list)
    # Subjects whose current judgement reads disposed although its latest write read nothing of the
    # subject whole (basis ``none``: a member its unit's material did not show whole, or a material
    # cut and not read on) — not must-read at the report's k, so not judged unread — or read it with
    # only part of its candidate rows (``rows_partial``, at any k). Counted apart.
    basis_incomplete: list[str] = field(default_factory=list)


def _json(raw: Any) -> dict[str, Any]:
    try:
        data = json.loads(raw) if raw else {}
    except (TypeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def read_audits(atlas: sqlite3.Connection, facts: PairFacts, units: list[Unit]) -> Audits:
    """The open audits, disagreements, and needs-recheck subjects of the pair, from its judgements
    and their history. Three products, split by whether they depend on blind auditing:

    * ``open`` (blind audit units) — a judgement that is change_inconclusive or no_real_change,
      never a person's (``human``). GATED by ``BLIND_AUDIT_ENABLED``: none are produced while blind
      auditing is sealed. An audit closes when a blind shadow judgement follows the write (one whose
      session neither wrote it nor made any call off the blind-read whitelist first:
      ``non_blind`` is not counted).
    * ``needs_recheck`` (ALWAYS on) — a subject judged before anything of it was read. Walking its
      writes in order, one flagged ``unread_before_verdict`` sets it and only a newer write whose
      read basis is not ``none`` clears it (a basis-``none`` write that carries no flag — not
      must-read at its writer's k — changes nothing); and a subject whose latest write has basis
      ``none`` is set too when it is must-read at ``units``' own k, whatever k its writer worked
      at. The caller marks it NEEDS_RECHECK; it does not open a blind audit.
    * ``disagreements`` (ALWAYS on) — a blind shadow that reads otherwise than the current judgement
      (from history, even once the gate is off), or a judgement overwritten by another session with
      another verdict; a person's write settles it."""
    pair = dr.run_pair(facts.run_a, facts.run_b)
    current = {
        r[0]: {"verdict": r[1], "attributed_to": r[2]}
        for r in atlas.execute(
            "SELECT anchor_ref, verdict, attributed_to FROM overlay "
            "WHERE anchor_kind = 'diff_subject' AND run_id = ?",
            (pair,),
        )
    }
    history: dict[str, list[dict[str, Any]]] = {}
    for row in atlas.execute(
        "SELECT id, anchor_ref, event, before, after, attributed_to, read_basis, session "
        "FROM overlay_history WHERE anchor_kind = 'diff_subject' AND run_id = ? ORDER BY id",
        (pair,),
    ):
        history.setdefault(row[1], []).append(
            {
                "id": row[0],
                "event": row[2],
                "before": _json(row[3]),
                "after": _json(row[4]),
                "attributed_to": row[5],
                "read_basis": _json(row[6]),
                "session": row[7],
            }
        )
    out = Audits()
    index = {u.stream: u.stream_index for u in units}
    # The must-read set at the k these units were cut for (the report's k).
    must_now = {
        mm.anchor_ref
        for uu in units
        if uu.must_read and uu.kind not in (AUDIT, REDUCE)
        for mm in uu.members
    }
    seen: set[str] = set()
    for u in units:
        for m in u.members:
            if m.anchor_ref in seen or m.anchor_ref not in current:
                continue
            seen.add(m.anchor_ref)
            row = current[m.anchor_ref]
            if row["attributed_to"] == HUMAN:
                continue
            hist = history.get(m.anchor_ref, [])
            writes = [h for h in hist if h["event"] in ("insert", "update")]
            last = writes[-1] if writes else None
            after_id = last["id"] if last is not None else 0
            blind = [
                h
                for h in hist
                if h["event"] == "shadow"
                and h["id"] > after_id
                and not h["read_basis"].get("non_blind")
            ]
            differ = sorted({h["after"].get("verdict") for h in blind} - {row["verdict"]})
            if differ:
                out.disagreements.append(
                    {
                        "anchor_ref": m.anchor_ref,
                        "why": "audit_reads_otherwise",
                        "current": row["verdict"],
                        "shadow": differ,
                    }
                )
            if last is not None and last["event"] == "update" and len(writes) >= 2:
                prev = writes[-2]
                was = last["before"].get("verdict")
                if (
                    was != row["verdict"]
                    and last["session"]
                    and prev["session"]
                    and last["session"] != prev["session"]
                ):
                    out.disagreements.append(
                        {
                            "anchor_ref": m.anchor_ref,
                            "why": "overwritten_by_another_session",
                            "current": row["verdict"],
                            "before": was,
                        }
                    )
            # Always on, independent of the gate: a subject judged unread is re-read
            # (NEEDS_RECHECK), not audited blind. A flagged write sets it; only a newer write that
            # read something (basis not ``none``) clears it. A latest basis-``none`` write on a
            # subject must-read at this k sets it too (its writer may have worked at a smaller k).
            flagged = False
            for h in writes:
                hb = h["read_basis"]
                if hb.get("unread_before_verdict"):
                    flagged = True
                elif hb.get("basis") != "none":
                    flagged = False
            if flagged or (
                last is not None
                and last["read_basis"].get("basis") == "none"
                and m.anchor_ref in must_now
            ):
                out.needs_recheck.append(m.anchor_ref)
            elif last is not None and (
                last["read_basis"].get("basis") == "none"
                or last["read_basis"].get("rows_partial")
                or last["read_basis"].get("read_partial")
            ):
                out.basis_incomplete.append(m.anchor_ref)
            # Below: the blind audit unit. Sealed off by default (A-1); produced only when the
            # sealed section is satisfied and the flag is flipped back on.
            if not BLIND_AUDIT_ENABLED:
                continue
            sources = []
            if row["verdict"] in ("change_inconclusive", "no_real_change"):
                sources.append(row["verdict"])
            if not sources or blind:
                continue
            # The member an auditor reads names no source: a source is the verdict under audit, and
            # an audit is read blind (spec six.7). The sources stay on the Audit, counted only in
            # the report's ``audits.by_source``.
            audited = replace(m, reasons=(AUDIT,))
            wid = last["id"] if last is not None else None
            unit = Unit(
                unit_id=unit_id(AUDIT, [f"{m.anchor_ref}@{wid if wid is not None else 'legacy'}"]),
                kind=AUDIT,
                must_read=u.must_read,
                members=(audited,),
                stream=m.stream,
                position=m.position,
                stream_index=index.get(m.stream, u.stream_index),
            )
            out.open.append(
                Audit(audited, tuple(sources), wid, last["session"] if last else None, unit)
            )
    return out


def disposed(state: str | None) -> bool:
    return state in DISPOSED_STATES


def unit_disposed(u: Unit, states: dict[str, str]) -> bool:
    """Every member disposed. An audit or a reduce unit exists only while it is owed, so it never
    is."""
    if u.kind in (AUDIT, REDUCE):
        return False
    return all(disposed(states.get(m.anchor_ref)) for m in u.members)


def next_unit(
    units: list[Unit],
    states: dict[str, str],
    worker: int | None = None,
    workers: int | None = None,
    skip: frozenset[str] = frozenset(),
) -> Unit | None:
    """The first unit, in the order they are handed out, of this shard with a member not yet
    disposed — ``skip`` names units not to hand out here (the audits of the asking session's own
    judgements, which it cannot read blind)."""
    for u in units:
        if u.unit_id in skip:
            continue
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
    audits: Audits | None = None,
    presence_short: dict[str, dict[str, Any]] | None = None,
    reduce_owed: list[Member] | None = None,
) -> dict[str, Any]:
    """The pair's report: the must-read set by unit kind and by reason, how much of it and of every
    listed subject is disposed, ``must_read_complete`` beside the existing ``complete``, what no
    unit can reach, and the one-line ``coverage_statement``."""
    states = progress.states
    audits = audits or Audits()
    presence_short = presence_short or {}
    reduce_owed = reduce_owed or []
    # An audit re-reads a subject and a reduce re-judges one: neither is a subject of its own.
    subjects = [u for u in units if u.kind not in (AUDIT, REDUCE)]
    must = [u for u in subjects if u.must_read]
    must_members = [m for u in must for m in u.members]
    all_members = [m for u in subjects for m in u.members]
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
    must_read_complete = (
        must_done == len(must_members)
        and not withheld
        and not facts.failed_diffs
        and not audits.open
        and not audits.disagreements
        and not audits.needs_recheck
        and not reduce_owed
    )
    complete = (
        unseen == 0
        and not facts.failed_diffs
        and not withheld
        and not facts.not_diffed_binaries
        and facts.files_unavailable is None
    )
    server = server_commit or "unknown"
    # Blind auditing is sealed off by default: the report says ``audits off`` (not 0) so a reader
    # does not mistake the gate being closed for "audited, nothing open". The needs-recheck and
    # disagreement counts are always real.
    audits_off = not BLIND_AUDIT_ENABLED
    open_text = "off" if audits_off else str(len(audits.open))
    judged_unread = {
        "count": len(audits.needs_recheck),
        "subjects": sorted(audits.needs_recheck)[:DISAGREEMENTS_SHOWN],
        "why": "judged before anything of the subject was read",
        "cleared_by": "a later judgement written after reading the subject",
    }
    basis_incomplete = {
        "count": len(audits.basis_incomplete),
        "subjects": sorted(audits.basis_incomplete)[:DISAGREEMENTS_SHOWN],
        "why": (
            "disposed, but written before the subject was read whole: its unit's material did not "
            "show it whole (not listed, or a part withheld or cut) and it was not read on"
        ),
        "cleared_by": "a later judgement written after reading the subject in full",
    }
    dangling = dr.judged_not_listed(progress.dangling_judged)
    dangling["means"] = (
        "judgements whose subject no longer resolves in the current facts (anchor_unresolved: "
        "the pairing or the subject moved); they stay needs_recheck and no unit hands them out"
    )
    not_listed = dr.judged_not_listed(progress.unlisted)
    statement = (
        f"must-read {len(must_members)} / disposed {must_done}; "
        f"all subjects {len(all_members)} / disposed {all_done}; "
        f"open audits {open_text}; judged unread {judged_unread['count']}; "
        f"disagreements {len(audits.disagreements)}; "
        f"{'reduce done' if not reduce_owed else f'reduce owed {len(reduce_owed)}'}; "
        f"presence citations short {len(presence_short)}; "
        f"basis incomplete {basis_incomplete['count']}; "
        f"dangling {dangling['count']} (changed_real {dangling['changed_real']['count']}); "
        f"not listed {not_listed['count']}; "
        f"predicate {PREDICATE_VERSION} (k={k}); server {server}"
    )
    group_units = [u for u in units if u.kind == GROUP]
    by_source: dict[str, int] = dict.fromkeys(AUDIT_SOURCES, 0)
    for au in audits.open:
        for src in au.sources:
            by_source[src] += 1
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
        "audits": {
            "open": None if audits_off else len(audits.open),
            "status": "audits off" if audits_off else "on",
            "by_source": by_source,
        },
        # The coverage statement's "judged unread N": the same count, under the same name.
        "judged_unread": judged_unread,
        # Deprecated: the former name of ``judged_unread``, kept (same value) for readers of
        # older reports; it is dropped in a later release.
        "needs_recheck": {**judged_unread, "deprecated": "renamed judged_unread"},
        "disagreements": {
            "count": len(audits.disagreements),
            "items": audits.disagreements[:DISAGREEMENTS_SHOWN],
            "settled_by": "a judgement written by a person (tmap review judge / audit --apply)",
        },
        "presence_citations_short": presence_short,
        "groups": {
            "units": len(group_units),
            "members": sum(len(u.members) for u in group_units),
            "members_possibly_incomplete": sum(
                1 for u in group_units if (u.group or {}).get("members_possibly_incomplete")
            ),
            "groups_in_diffs": sum(len(d.groups) for d in facts.diffs),
        },
        "reduce": {
            "owed": len(reduce_owed),
            "rule": (
                "each member a callee group handed out is judged leaning on the group (its "
                "group_ref), and so is the group's own callee entry when listed"
            ),
        },
        "not_seen": list(NOT_SEEN),
        "dangling_judgements": sorted(progress.dangling),
        # The same judgements by verdict, changed_real apart: no unit hands them out.
        "dangling": dangling,
        # Apart from the dangling ones: the subject resolves but is no longer listed.
        "judged_not_listed": not_listed,
        "basis_incomplete": basis_incomplete,
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
    from treasure_map.lib.query.patch_view import (
        _attach_pair_evidence,
        build_diff_view,
        listed_view,
    )

    built_by: dict[str, Any] = {}
    caches: dict[str, dict[tuple[str, str], Any]] = {}

    def read(diff_id: str, stored: dict[str, Any]) -> dict[str, Any] | None:
        if diff_id not in built_by:
            built = build_diff_view(atlas, diff_id)
            if built is not None:
                # read as every judgement path reads it: the pair evidence attached, S decided
                _attach_pair_evidence(atlas, built)
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
    audits: Audits = field(default_factory=Audits)
    # The navigation facts (review_navigation.PairNavigation) when read with navigation=True.
    navigation: Any = None

    def unit(self, uid: str) -> Unit | None:
        return next((u for u in self.units if u.unit_id == uid), None)

    def audit_of(self, uid: str) -> Audit | None:
        return next((a for a in self.audits.open if a.unit.unit_id == uid), None)

    def next_unit(
        self,
        worker: int | None = None,
        workers: int | None = None,
        session: str | None = None,
    ) -> Unit | None:
        """The next unit of the shard; an audit of a judgement ``session`` wrote is not handed
        back to it (it cannot read it blind)."""
        skip = frozenset(
            a.unit.unit_id
            for a in self.audits.open
            if session is not None and a.write_session == session
        )
        return next_unit(self.units, self.progress.states, worker, workers, skip)


def review_pair(
    atlas: sqlite3.Connection,
    run_a: str,
    run_b: str,
    *,
    k: int = DEFAULT_K,
    pair_staleness: dict[str, Any],
    server_commit: str | None,
    cache: _DiffCache | None = DIFF_CACHE,
    navigation: bool = False,
) -> PairReview:
    """Read the pair's review: facts (each diff's through ``cache``), units, progress and report.
    ``pair_staleness`` is the caller's reading of the two runs (``source_stale`` /
    ``source_stale_reason``) for the binary_presence and file judgements; each diff's own
    staleness is read here. ``navigation`` also reads the navigation facts (dispatch and upstream
    groups, lib/query/review_navigation) into ``PairReview.navigation`` and the report's
    ``dispatch_groups`` / ``upstream_groups`` — only for a caller that shows them."""
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
    short = presence_citations_short(atlas, facts, progress.states)
    for anchor in short:
        # Judged without citing every candidate of its subject: read again, not disposed.
        progress.states[anchor] = NEEDS_RECHECK
    audits = read_audits(atlas, facts, units)
    for anchor in audits.needs_recheck:
        # Judged before anything of the subject was read (A-2(2)): re-read, not disposed. Always
        # on, independent of BLIND_AUDIT_ENABLED. Set like the presence citations above so the
        # reduce gate and must_read_complete below see it undisposed.
        progress.states[anchor] = NEEDS_RECHECK
    owed = read_reduce(atlas, facts, units)
    extra = [a.unit for a in audits.open]
    if owed and all(
        unit_disposed(u, progress.states) for u in units if u.kind not in (AUDIT, REDUCE)
    ):
        # Handed out once every other unit is disposed (the must-read set and the second tier).
        # Its id is the pair's (and the predicate's), not its owed members': judging one of them
        # leaves the same unit, so its other members — of any diff — are written with the id it
        # was handed out with.
        extra.append(
            Unit(
                unit_id=unit_id(REDUCE, [dr.run_pair(facts.run_a, facts.run_b)]),
                kind=REDUCE,
                must_read=True,
                members=tuple(owed),
                stream=REDUCE_STREAM,
                position=_REDUCE_POSITION,
                stream_index=len(facts.diffs) + 2,
            )
        )
    units = sorted([*units, *extra], key=lambda u: u.order)
    rep = report(
        facts,
        units,
        progress,
        k=k,
        server_commit=server_commit,
        audits=audits,
        presence_short=short,
        reduce_owed=owed,
    )
    nav = None
    if navigation:
        # F-3 / F-4: the dispatch groups (by the string-keyed edge that enumerates an entry's
        # function) and the upstream library groups. Moves nothing — units, ids and must_read are
        # already fixed above; this only annotates.
        from treasure_map.lib.query import review_navigation as _nav

        nav = _nav.read(atlas, facts, units, lambda u: unit_disposed(u, progress.states))
        rep.update(nav.report)
    return PairReview(facts, units, progress, rep, k, audits, nav)


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
