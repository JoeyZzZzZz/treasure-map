# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The scan review profile: one run's candidates cut into bands, two tiers and work units.

A scan of one firmware yields candidates in the tens of thousands, and until now the scan side
answered "which of these must I read?" with nothing at all: ``list_candidates`` RANKS them, and a
ranking says what to read first, never what may be left unread. The diff side has a bounded
must-read set because before/after frames the question for it. A scan carries no such frame, so
the only thing that can be taken out is what carries a PROVEN-SAFE fact. The must-read set here is
therefore large ON PURPOSE, and the job of this module is not to shrink it but to make what is NOT
read countable: a reader who stops partway can say exactly how far they got, and nobody may read
the remainder as "nothing found".

★ FACTS ONLY, NO PREDICTION. The coverage declaration is the scan counterpart of
``review_units.coverage_offer``, and it inherits that contract word for word: it states totals,
what is disposed, what is not, and the units the rest sits in — never how long the rest will take
or how many sessions it needs. Naming the batch driver is how a context too small for the set is
handled (``review_units.IF_THIS_CONTEXT_FILLS`` sets that precedent); a session estimate is not.

★ A READ LAYER, ABOVE ``triage``. Banding reads the dimension values triage already computed and
writes nothing back. No sort key, no sink vocabulary, no dimension and no rank moves because of
anything here, so no code stamp moves and nothing has to be re-scanned.

The four bands (every candidate is in exactly one):

* ``exec`` — a command / format-string / file-path sink with a dangerous source and no proven-safe
  fact: something an outside value could reach and have it interpreted.
* ``write`` — a memory-copy or formatter sink, same conditions: something an outside value could
  reach and overrun.
* ``unresolved`` — one of those sink families, not proven safe, with at least one dimension the
  analysis could not resolve. Not a weaker finding: an unread axis, which is why it is must-read.
* ``tail`` — everything else: a proven-safe fact, or neither a dangerous source nor an unresolved
  axis. Counted in the declaration, never handed out.

★ WHAT THIS IS NOT. This profile reads ONE run's candidates, which are the sinks of binaries that
are PRESENT. A binary a version diff removed has no candidates on the side it is gone from, and
what it took with it is characterised by the removal read layer the diff side owns and
``binary_presence`` consumes. Two profiles, one overlay and one verdict vocabulary; separate
coverage declarations and separate unit containers, because the scopes are not the same scope.

★ BAND MEMBERSHIP IS NOT THE IMPACT TIER. The sink families below are spelled out rather than
derived from ``sink_impact.DEFAULT_SINK_IMPACT``, and that is load-bearing twice over. That map is
an OVERRIDABLE ranking judgement (``--impact-order`` replaces it), so deriving membership from it
would let a reader's sort preference change what they are required to read. And ``format`` sits at
the LOWEST tier there while a formatter writing into a fixed buffer is exactly a memory-write lead:
entering a band asks only "could this be written to / executed", never "how much would it matter".
Grading stays where grading belongs — the ranking.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field, replace
from typing import Any

from treasure_map.lib.query import coverage as cov
from treasure_map.lib.query import review_units as ru
from treasure_map.lib.query.review_units import _chunks  # the shared unit-cutting primitive
from treasure_map.lib.query.sink_impact import DEFAULT_SINK_IMPACT
from treasure_map.lib.query.triage import (
    _UNRESOLVED_VALUES,
    TriageCandidate,
    _is_param_source,
    _is_proven_safe,
)

# ── the bands ───────────────────────────────────────────────────────────────────────────────

EXEC, WRITE, UNRESOLVED, TAIL = "exec", "write", "unresolved", "tail"
BANDS = (EXEC, WRITE, UNRESOLVED, TAIL)

# The sink families each band asks about. Named here, NOT derived from DEFAULT_SINK_IMPACT — see
# the module docstring for why an overridable ranking map must not decide what is must-read.
# ``log`` is in that map and in no band: it is mapped, carries no candidate in any corpus measured,
# and a logging call is not a write or an execution.
EXEC_SINKS: frozenset[str] = frozenset({"cmd", "fmt_string", "path_sink"})
WRITE_SINKS: frozenset[str] = frozenset({"copy", "format"})
BANDED_SINKS: frozenset[str] = EXEC_SINKS | WRITE_SINKS

# The source kinds that leave an analyzer-marked parameter unconstrained: a free string, or a
# charset the analysis could not read. ``charset_safe`` and ``charset_maybe`` are deliberately out
# — a converter-constrained value is the param-internal demotion iron law's case.
UNCONSTRAINED_SOURCE_KINDS: frozenset[str] = frozenset({"free_string", "unknown"})

# The dimensions an ``unresolved`` reading is looked for on. ``source`` is NOT among them: triage
# reads source attribution optimistically (unknown when unresolved, never a truth), so asking it
# this question would answer "unresolved" for every candidate in the corpus.
UNRESOLVED_DIMENSIONS: tuple[str, ...] = (
    "controllability",
    "source_writability",
    "reachability",
    "filtering",
    "sink_impact",
    "writer",
    "completeness",
)


def dangerous_source(c: TriageCandidate) -> bool:
    """Whether an outside value is read as reaching this candidate's sink.

    Two families, and both are needed. A ``controllable`` controllability comes from the nvram
    cross-reference (a key a web form writes), covering the value-store-mediated shape; the
    parameter branch covers a request parameter reaching a sink directly, which carries no nvram
    key to cross-reference and so reads ``likely`` at best. Dropping either loses a whole family of
    leads, and no single corpus exercises both: the value-store branch has no candidate at all in
    two of the three corpora measured.
    """
    if c.dim("controllability").value == "controllable":
        return True
    return _is_param_source(c) and c.source_kind in UNCONSTRAINED_SOURCE_KINDS


def has_unresolved_dimension(c: TriageCandidate) -> bool:
    """Whether any dimension of ``c`` reads unresolved — an unknown state, or a blank / ``?`` /
    ``unknown`` value. An unread axis, never a safe one."""
    for name in UNRESOLVED_DIMENSIONS:
        d = c.dim(name)
        if d.state == "unknown" or not d.value or d.value.lower() in _UNRESOLVED_VALUES:
            return True
    return False


def band(c: TriageCandidate) -> str:
    """Which band ``c`` is in (one of ``BANDS``).

    ★ An UNRECOGNISED sink_class reads ``unresolved``, not ``tail``. ``sink_class`` is an open
    value set — ``sink_impact`` states that an unmapped class is still ranked and never silently
    dropped — so a class a future extractor emits must not fall out of the must-read set on its
    way in. It lands in the weakest must-read band rather than in a band whose question it has not
    been shown to answer. Every class in every corpus measured is one of the five named above, so
    this branch changes no band count that exists today; it is what stops the next one from
    disappearing.
    """
    sink_class = (c.sink_class or "").lower()
    safe = _is_proven_safe(c)
    if sink_class in EXEC_SINKS and not safe and dangerous_source(c):
        return EXEC
    if sink_class in WRITE_SINKS and not safe and dangerous_source(c):
        return WRITE
    if not safe and has_unresolved_dimension(c):
        if sink_class in BANDED_SINKS or sink_class not in DEFAULT_SINK_IMPACT:
            return UNRESOLVED
    return TAIL


# ── the two tiers ───────────────────────────────────────────────────────────────────────────

TIER_1, TIER_2 = 1, 2

# One stream per Tier 1 band, and one for Tier 2: a unit belongs to exactly one, and the dispatch
# order rotates between them (``Unit.order`` sorts by position before stream), so a reader is not
# handed every command-sink unit of the whole run before seeing a memory-write one.
EXEC_STREAM = "scan_exec"
WRITE_STREAM = "scan_write"
UNRESOLVED_STREAM = "scan_unresolved_rce"
SECOND_TIER_STREAM = "scan_second_tier"
_STREAMS = (EXEC_STREAM, WRITE_STREAM, UNRESOLVED_STREAM, SECOND_TIER_STREAM)

# What one scan unit's member is, in ``Member.kind``. Not an anchor kind: the overlay still keys
# these on ``anchor_kind='evidence_ref'``, the candidate anchor it has always used.
MEMBER_KIND = "scan_candidate"

# Why a member is must-read, in ``Member.reasons`` (a Tier 2 member carries none, which is what
# makes ``Member.must_read`` false for it).
REASON_BY_BAND = {EXEC: "scan_exec", WRITE: "scan_write", UNRESOLVED: "scan_unresolved_rce"}


def tier(band_name: str, sink_class: str | None) -> int | None:
    """Which tier a banded candidate is read in, or None when it is not handed out at all.

    Tier 1 is "there is a reason to think this is dangerous": a dangerous source was read (the
    ``exec`` / ``write`` bands), or the sink is one of the command / format-string / file-path
    families and an axis is unread. Tier 2 is the weakest signal left — a memory-write family with
    an unread axis — and an unrecognised class, which has shown nothing yet either way.
    """
    if band_name in (EXEC, WRITE):
        return TIER_1
    if band_name == UNRESOLVED:
        return TIER_1 if (sink_class or "").lower() in EXEC_SINKS else TIER_2
    return None


# ── a banded candidate ──────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Banded:
    """One candidate with the band it reads in and where it sits in the default ranking."""

    evidence_ref: str
    binary: str
    sink_class: str
    source_kind: str
    band: str
    rank: int  # its place in the run's default triage order


def band_run(candidates: list[TriageCandidate]) -> list[Banded]:
    """Band a run's candidates, keeping the order ``triage`` handed them over (the default lens).

    A candidate with no ``evidence_ref`` is left out: the ref is the anchor every read and every
    write of it would use, so there is nothing a reader could be asked to do with it. The
    declaration counts it under ``unanchored`` rather than dropping it quietly.
    """
    out: list[Banded] = []
    for rank, c in enumerate(candidates):
        if not c.evidence_ref:
            continue
        out.append(
            Banded(
                evidence_ref=c.evidence_ref,
                binary=c.binary_path or "",
                sink_class=(c.sink_class or ""),
                source_kind=c.source_kind,
                band=band(c),
                rank=rank,
            )
        )
    return out


# ── the units ───────────────────────────────────────────────────────────────────────────────


def scan_units(banded: list[Banded]) -> list[ru.Unit]:
    """Cut the handed-out bands into work units: per stream, per binary, at most
    ``BATCH_UNIT_MAX`` members each, members in the run's ranking order.

    Per BINARY and never across one: a unit is read in one decompiler, and a unit whose members sit
    in two images is two context switches pretending to be one piece of work. The whole TIER is cut
    together inside a binary, not one cut per band: the members are rank-adjacent that way, which
    is how the reader meets them in ``list_candidates``.

    ★ The two tiers are cut SEPARATELY, so a binary with members in both yields a part-full unit in
    each. Cutting the whole must-read set in one pass per binary would give fewer units, and it
    cannot be done: a unit is must-read as a WHOLE (``dispatch_order`` reads one flag per unit), so
    a unit holding a tier-1 and a tier-2 member would either hand the second tier out with the
    first or hold the first back with the second. Fewer units is not worth either.

    ★ The STREAM a tier-1 unit belongs to is its strongest band (``exec`` over ``write`` over
    ``unresolved``), and its ``position`` is its place in THAT stream. ``Unit.order`` sorts by
    position before stream, so the dispatch rotates between the three — a reader is handed the
    leading command-sink unit, then the leading memory-write one, then the leading unread-axis one,
    rather than every unit of one band before the first of the next.

    Every unit's kind is ``review_units.SCAN_BAND``; Tier 1 units are must-read and Tier 2 units
    are not, which is what ``dispatch_order`` reads to keep the second tier behind the first.
    """
    tier1: dict[str, list[Banded]] = {}
    tier2: dict[str, list[Banded]] = {}
    for b in banded:
        where = tier(b.band, b.sink_class)
        if where == TIER_1:
            tier1.setdefault(b.binary, []).append(b)
        elif where == TIER_2:
            tier2.setdefault(b.binary, []).append(b)
    chunks: list[tuple[str, list[ru.Member]]] = []
    for by_binary, must in ((tier1, True), (tier2, False)):
        for binary in sorted(by_binary):
            rows = sorted(by_binary[binary], key=lambda b: b.rank)
            members = [
                ru.Member(
                    anchor_ref=b.evidence_ref,
                    kind=MEMBER_KIND,
                    stream="",  # filled in below, once the chunk's strongest band is known
                    position=b.rank,
                    bucket=b.band,
                    subclass=b.sink_class or None,
                    reasons=(REASON_BY_BAND[b.band],) if must else (),
                )
                for b in rows
            ]
            for chunk in _chunks(members):
                stream = (
                    _strongest_stream([m.bucket or TAIL for m in chunk])
                    if must
                    else SECOND_TIER_STREAM
                )
                chunks.append((stream, [replace(m, stream=stream) for m in chunk]))
    units: list[ru.Unit] = []
    counted: dict[str, int] = dict.fromkeys(_STREAMS, 0)
    for stream, members in chunks:
        stream_index = _STREAMS.index(stream)
        units.append(
            ru.Unit(
                unit_id=ru.unit_id(ru.SCAN_BAND, [m.anchor_ref for m in members]),
                kind=ru.SCAN_BAND,
                must_read=stream != SECOND_TIER_STREAM,
                members=tuple(members),
                stream=stream,
                position=counted[stream],
                stream_index=stream_index,
            )
        )
        counted[stream] += 1
    units.sort(key=lambda u: u.order)
    return units


def _strongest_stream(bands: list[str]) -> str:
    """The stream a tier-1 unit holding these bands belongs to: its strongest signal."""
    for name in (EXEC, WRITE, UNRESOLVED):
        if name in bands:
            return {EXEC: EXEC_STREAM, WRITE: WRITE_STREAM, UNRESOLVED: UNRESOLVED_STREAM}[name]
    return UNRESOLVED_STREAM


# ── what has been read, and what was read before it ─────────────────────────────────────────


def read_basis_of(lines: list[dict[str, Any]] | None, evidence_ref: str) -> dict[str, Any]:
    """The read basis of a write of one scan candidate — THE call shape, written once here.

    ★ ``unit_id`` IS NOT PASSED, and that is the whole point. ``read_basis.infer`` given a
    ``unit_id`` whose material was delivered reads ``_shown_whole``: the delivery log naming this
    anchor among the members it kept is enough, and the basis comes back ``unit_delivered``. A scan
    verdict is none of the two verdicts ``gated_short`` looks at, so nothing downstream would catch
    it either — between them, being HANDED a unit would satisfy the read gate and a ``safe`` could
    be written on a candidate nobody opened. Without the unit, ``infer`` falls through to its
    fetched test, whose three branches are each guarded by an anchor shape a scan ref does not have
    (a diff entry, a ``#non_binary#`` path, a ``#function_`` address), so the basis is exactly
    "explain_candidate was answered for this ref, or nothing was read".
    """
    from treasure_map.lib.query import read_basis as rb  # noqa: PLC0415 (cycle at import time)

    return rb.infer(lines, anchor_ref=evidence_ref, candidates=frozenset({evidence_ref}))


def must_read_candidate(atlas: sqlite3.Connection, evidence_ref: str) -> bool:
    """Whether ``evidence_ref`` is a candidate the scan profile selects as must-read (tier 1).

    Read at WRITE time, by the one caller that needs it: the dismissal threshold a write is held
    to. The run is resolved from the candidate's own instance row, and the banding then comes off
    the run's ``triage`` reading, which is cached per run — so the first write of a session pays
    for the reading the session's first ``list_candidates`` would have paid for anyway, and the
    rest pay nothing. A ref no instance names is not must-read: there is no candidate to band.
    """
    from treasure_map.lib.query.triage import triage  # noqa: PLC0415

    row = atlas.execute(
        "SELECT source_run_id FROM instance WHERE evidence_ref = ? LIMIT 1", (evidence_ref,)
    ).fetchone()
    run_id = row[0] if row else None
    if not run_id:
        return False
    for c in triage(atlas, run_id=run_id):
        if c.evidence_ref == evidence_ref:
            return tier(band(c), c.sink_class) == TIER_1
    return False


def _latest_write_bases(atlas: sqlite3.Connection, run_id: str) -> dict[str, dict[str, Any]]:
    """Each candidate anchor's LAST write and the basis it was written on, from overlay_history.

    The basis is read from HISTORY and not recomputed, because the question it answers is what the
    writer had read when they wrote — the current session's tool-call log cannot answer that for a
    judgement written in another one. Ordered by id and overwritten as it goes, so what is left is
    the last write, which is the one the overlay row holds.
    """
    out: dict[str, dict[str, Any]] = {}
    for ref, after, basis in atlas.execute(
        "SELECT anchor_ref, after, read_basis FROM overlay_history "
        "WHERE anchor_kind = 'evidence_ref' AND run_id = ? AND event IN ('insert', 'update') "
        "ORDER BY id",
        (run_id,),
    ):
        try:
            row = json.loads(after) if after else {}
            read = json.loads(basis) if basis else {}
        except (TypeError, ValueError):
            row, read = {}, {}
        out[ref] = {
            "verdict": row.get("verdict") if isinstance(row, dict) else None,
            "read_basis": read if isinstance(read, dict) else {},
        }
    return out


def scan_states(
    atlas: sqlite3.Connection, run_id: str, units: list[ru.Unit]
) -> tuple[dict[str, str], tuple[str, ...]]:
    """The disposition state of every unit member, and the members whose read gate could not be
    evaluated at all.

    Two layers, both of which must hold for a member to read disposed:

    * the overlay's own reading (``coverage``): a verdict in the current vocabulary whose stored
      facts have not moved. A retired word reads ``needs_relabel``, a moved basis
      ``needs_recheck`` — unchanged from how the candidate map has always read annotations.
    * the READ GATE: the last write's basis, through ``review_units.held_unread`` — THE shared
      predicate, not a second spelling of it. On a scan write it reduces to "the basis is
      ``none``", because its other half (``gated_short``) is defined over two verdicts a scan
      write never uses; reading it through the shared predicate is what keeps the two profiles
      from drifting the next time it changes, and the reduction is pinned by a test.

    ★ And the third state, which is NOT a disposition: a write made by a server that kept no
    tool-call log records basis ``unknown`` (``review_units.NO_SESSION_LOG``). ``held_unread`` is
    false for it — correctly, since nothing says the subject was unread — so the write disposes
    its member. That is the right call and a silent one: a whole run judged by such a server would
    read fully disposed with the read gate never having fired once. These members are returned
    separately so the declaration can state how much of its own disposed count rests on a gate it
    could not apply.
    """
    index = cov.load_coverage_index(atlas)
    writes = _latest_write_bases(atlas, run_id)
    states: dict[str, str] = {}
    unverifiable: list[str] = []
    for u in units:
        for m in u.members:
            ref = m.anchor_ref
            if ref in states:
                continue
            state = index.state_for(ref)
            last = writes.get(ref)
            if state != cov.UNSEEN and last is not None:
                if ru.held_unread(last["verdict"], last["read_basis"]):
                    state = cov.NEEDS_RECHECK
                elif last["read_basis"].get("why") == ru.NO_SESSION_LOG:
                    unverifiable.append(ref)
            states[ref] = state
    return states, tuple(unverifiable)


# ── the run-level container ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ScanReview:
    """One run's scan review, read fresh every time.

    Deliberately NOT a ``PairReview``: every field of that one is bound to a run pair (two runs,
    their diffs, their pairing components, the hand-off), and a scan has one run and no
    counterpart. What IS shared is everything that is not pair-shaped — the unit primitives, the
    read basis, the disposition states and the verdict vocabulary — so the two profiles cannot
    drift on the questions they both answer.
    """

    run_id: str
    banded: list[Banded]
    units: list[ru.Unit]
    states: dict[str, str]
    unanchored: int = 0
    by_band: dict[str, int] = field(default_factory=dict)
    # Members whose read gate could NOT be evaluated: the write was made by a server with no
    # tool-call log, so what had been read before it is not recorded either way. Kept and stated,
    # never folded into the disposed count — see ``unverifiable_read`` below.
    unverifiable_read: tuple[str, ...] = ()


def review_run(
    atlas: sqlite3.Connection, run_id: str, candidates: list[TriageCandidate] | None = None
) -> ScanReview:
    """Read one run's scan review. ``candidates`` lets a caller that already paid for
    ``triage(run_id=...)`` hand it over instead of reading it again."""
    if candidates is None:
        from treasure_map.lib.query.triage import triage  # noqa: PLC0415

        candidates = triage(atlas, run_id=run_id)
    banded = band_run(candidates)
    units = scan_units(banded)
    by_band = {name: 0 for name in BANDS}
    for b in banded:
        by_band[b.band] += 1
    states, unverifiable = scan_states(atlas, run_id, units)
    return ScanReview(
        run_id=run_id,
        banded=banded,
        units=units,
        states=states,
        unanchored=sum(1 for c in candidates if not c.evidence_ref),
        by_band=by_band,
        unverifiable_read=unverifiable,
    )


# ── the coverage declaration ────────────────────────────────────────────────────────────────

# How the second tier is grouped when it is stated: not one line per member (there are tens of
# thousands) and not one number (which says nothing about where they are). The triple is fixed
# here rather than chosen per call so two declarations of the same run group the same way.
SECOND_TIER_GROUP_KEY = ("sink_class", "source_kind", "binary")
# At most this many second-tier groups are printed; the rest are summed into one line. The total
# number of groups and the total number of members are always stated, printed or not.
GROUPS_SHOWN = 20

# The last line of every declaration, fixed. The one sentence that has to survive someone skimming
# the numbers above it.
UNREAD_NOT_UNFOUND = "What is not disposed above is UNREAD, not 'nothing found'."

# What the scan read layer cannot see. Stated, never counted: these are descriptions of a shape
# the analysis does not resolve, not labels any row carries, so every one of them matches zero rows
# in the fact tables by construction. A count would therefore read as "no such gap", which is the
# opposite of what they say.
BLIND_SPOTS_ARE_TEXT = (
    "named gaps, stated not counted: no row carries one of these as a label, so a count of them "
    "would read as 'none found' rather than 'not looked for'"
)


def _median(values: list[int]) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) // 2


def second_tier_groups(review: ScanReview) -> list[tuple[tuple[str, str, str], int]]:
    """The second tier grouped by ``SECOND_TIER_GROUP_KEY``, largest group first (ties by key, so
    the order is total and stable)."""
    counts: dict[tuple[str, str, str], int] = {}
    for b in review.banded:
        if tier(b.band, b.sink_class) != TIER_2:
            continue
        key = (b.sink_class, b.source_kind, b.binary)
        counts[key] = counts.get(key, 0) + 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))


def declaration(
    review: ScanReview,
    *,
    worker: int | None = None,
    workers: int | None = None,
    drive_with: str | None = None,
) -> dict[str, Any]:
    """What a scan review states every time it is read: the whole candidate set, the four bands,
    how far each tier has come, where the rest of the second tier sits, and the named gaps.

    ★ FACTS ONLY. There is no estimate here of how long the rest takes or how many sessions it
    needs — the same contract ``coverage_offer`` carries, for the same reason: a number like that
    would be the fact layer making a prediction, and the only honest divisor for it (how much one
    session disposes) has never been measured. What a context too small for the set gets instead is
    the batch driver's own command, named — the precedent ``IF_THIS_CONTEXT_FILLS`` sets.
    """
    in_shard = [u for u in review.units if ru.in_shard(u.unit_id, worker, workers)]
    tier1 = [u for u in in_shard if u.must_read]
    tier2 = [u for u in in_shard if not u.must_read]
    groups = second_tier_groups(review)
    sizes = [n for _, n in groups]

    def _members(units: list[ru.Unit]) -> list[ru.Member]:
        return [m for u in units for m in u.members]

    def _split(units: list[ru.Unit]) -> dict[str, Any]:
        members = _members(units)
        done = sum(1 for m in members if ru.disposed(review.states.get(m.anchor_ref)))
        undone = [m for m in members if not ru.disposed(review.states.get(m.anchor_ref))]
        by_band: dict[str, int] = {}
        for m in undone:
            by_band[m.bucket or "-"] = by_band.get(m.bucket or "-", 0) + 1
        return {
            "members": len(members),
            "disposed": done,
            "undisposed": len(undone),
            "undisposed_by_band": dict(sorted(by_band.items())),
            "units": len(units),
            "units_undisposed": sum(1 for u in units if not ru.unit_disposed(u, review.states)),
        }

    out: dict[str, Any] = {
        "run_id": review.run_id,
        "scope": "shard" if workers is not None else "run",
        "candidates": len(review.banded) + review.unanchored,
        "by_band": dict(review.by_band),
        "unanchored": review.unanchored,
        "tier_1": _split(tier1),
        "tier_2": {
            **_split(tier2),
            "handed_out": False,
            "group_key": list(SECOND_TIER_GROUP_KEY),
            "groups": len(groups),
            "group_size_median": _median(sizes),
            "group_size_max": max(sizes) if sizes else 0,
            "groups_shown": min(len(groups), GROUPS_SHOWN),
            "largest_groups": [
                {"sink_class": k[0], "source_kind": k[1], "binary": k[2], "members": n}
                for k, n in groups[:GROUPS_SHOWN]
            ],
            "groups_not_shown": max(len(groups) - GROUPS_SHOWN, 0),
            "members_not_shown": sum(sizes[GROUPS_SHOWN:]),
            "why": (
                "the weakest signal left: a memory-write sink family with an axis the analysis "
                "could not resolve, and any sink class this read layer does not recognise"
            ),
        },
        "tail": {
            "members": review.by_band.get(TAIL, 0),
            "why": (
                "a proven-safe fact, or neither a dangerous source nor an unresolved axis; "
                "counted, never handed out, and still readable and judgeable by hand"
            ),
        },
        "not_seen": list(ru.NOT_SEEN),
        "not_seen_note": BLIND_SPOTS_ARE_TEXT,
        # How much of the disposed count above rests on a read gate that could not be applied: a
        # write by a server keeping no tool-call log records no basis either way, so it disposes
        # its member and the gate never fires. Stated, because a whole run judged by such a server
        # would otherwise read fully disposed with nothing saying the gate was never applied.
        "read_gate_unverifiable": len(review.unverifiable_read),
        "read_gate_unverifiable_why": ru.NO_SESSION_LOG,
        "unread_not_unfound": UNREAD_NOT_UNFOUND,
    }
    if drive_with and out["tier_1"]["undisposed"]:
        out["if_this_context_fills"] = ru.IF_THIS_CONTEXT_FILLS.format(drive_with=drive_with)
    return out


def coverage_statement(dec: dict[str, Any]) -> str:
    """The one line a report leads with: the counts, and nothing that is not a count."""
    t1, t2 = dec["tier_1"], dec["tier_2"]
    bands = "; ".join(f"{name} {dec['by_band'].get(name, 0)}" for name in BANDS)
    return (
        f"scan {dec['run_id']}: {dec['candidates']} candidate(s) — {bands}. "
        f"tier 1 {t1['disposed']}/{t1['members']} disposed, {t1['units_undisposed']} unit(s) left; "
        f"tier 2 {t2['disposed']}/{t2['members']} disposed in {t2['groups']} group(s); "
        f"{len(dec['not_seen'])} named gap(s). {dec['unread_not_unfound']}"
    )


def declaration_text(dec: dict[str, Any]) -> str:
    """The declaration as the lines ``tmap review scan`` prints."""
    t1, t2 = dec["tier_1"], dec["tier_2"]
    lines = [
        coverage_statement(dec),
        "",
        f"candidates: {dec['candidates']} ({dec['scope']} scope)",
    ]
    for name in BANDS:
        lines.append(f"  band {name}: {dec['by_band'].get(name, 0)}")
    if dec["unanchored"]:
        lines.append(f"  no evidence_ref (nothing to anchor a read on): {dec['unanchored']}")
    lines += [
        "",
        f"tier 1 (must read): {t1['members']} member(s) in {t1['units']} unit(s) — "
        f"{t1['disposed']} disposed, {t1['undisposed']} not",
    ]
    for name, count in t1["undisposed_by_band"].items():
        lines.append(f"  not disposed, band {name}: {count}")
    lines.append(f"  units not disposed: {t1['units_undisposed']}")
    lines += [
        "",
        f"tier 2 (not handed out until tier 1 is done): {t2['members']} member(s) — "
        f"{t2['disposed']} disposed, {t2['undisposed']} not",
        f"  grouped by {' + '.join(t2['group_key'])}: {t2['groups']} group(s), "
        f"median {t2['group_size_median']}, largest {t2['group_size_max']}",
    ]
    for g in t2["largest_groups"]:
        # The key keeps the whole path (it is the group's identity); the LINE shows the last
        # segment, the way every other compact row of the tool names a binary.
        short = (g["binary"] or "").rsplit("/", 1)[-1] or g["binary"]
        lines.append(
            f"    {g['members']:6d}  {g['sink_class']} / source {g['source_kind']} / "
            f"{short or '(no path)'}"
        )
    if t2["groups_not_shown"]:
        lines.append(
            f"    ... and {t2['groups_not_shown']} further group(s), "
            f"{t2['members_not_shown']} member(s)"
        )
    if dec["read_gate_unverifiable"]:
        lines += [
            "",
            f"read gate not applicable to {dec['read_gate_unverifiable']} disposed member(s): "
            f"{dec['read_gate_unverifiable_why']}, so what was read before those verdicts is "
            "not recorded either way",
        ]
    lines += ["", f"tail: {dec['tail']['members']} — {dec['tail']['why']}", "", "not seen:"]
    lines += [f"  {name}" for name in dec["not_seen"]]
    lines.append(f"  ({dec['not_seen_note']})")
    if dec.get("if_this_context_fills"):
        lines += ["", dec["if_this_context_fills"]]
    lines += ["", dec["unread_not_unfound"]]
    return "\n".join(lines)
