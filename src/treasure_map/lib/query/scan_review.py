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
  axis. In every corpus measured the band is EXACTLY the proven-safe set, and every member of it
  still carries at least one unread axis — nothing reaches the tail by being plain, only by being
  lifted out of the set by the demotion iron law. The second branch is kept because the predicate
  admits it, not because anything has ever landed there. Counted in the declaration, never handed
  out.

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
# The two families together: what a DANGEROUS-SOURCE candidate is banded by. The unresolved
# band asks nothing about the class (see ``band``), so this is not "the classes the profile
# knows" — it is the classes a dangerous source can be banded at.
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


# The predicate that put a candidate in its band (``band_reason``): one per band, two for the tail.
PREDICATE_EXEC = "exec_sink_dangerous_source"
PREDICATE_WRITE = "write_sink_dangerous_source"
PREDICATE_UNRESOLVED = "unresolved_dimension"
PREDICATE_PROVEN_SAFE = "proven_safe"
PREDICATE_PLAIN = "no_dangerous_source_no_unread_axis"
# The tail's two predicates, in the order a count of them is stated.
TAIL_PREDICATES = (PREDICATE_PROVEN_SAFE, PREDICATE_PLAIN)


def band(c: TriageCandidate) -> str:
    """Which band ``c`` is in (one of ``BANDS``): ``band_reason``'s band, nothing else."""
    return band_reason(c)[0]


def band_reason(c: TriageCandidate) -> tuple[str, str]:
    """Which band ``c`` is in, and the predicate that put it there.

    The predicate is what a candidate outside the must-read set is counted under: a tail member is
    there because it carries a proven-safe fact (``proven_safe``) or because it shows neither a
    dangerous source nor an unread axis (``no_dangerous_source_no_unread_axis``). Naming which is
    what lets a reader of a count tell the two apart without re-deriving the band.

    ★ The ``unresolved`` band asks NOTHING about the sink class. Not proven safe, and an axis the
    analysis could not read: that is must-read whatever the sink is. This started out testing the
    class — the five banded ones, plus any class the impact map does not know — and the test was
    both unnecessary and subtly wrong. Unnecessary because ``sink_class`` is an open value set
    (``sink_impact`` states that an unmapped class is still ranked and never silently dropped), so
    a class a future extractor emits must not fall out of the must-read set on its way in. Wrong
    because it protected the classes the map does NOT know while letting a class it DOES know and
    that no band claims (``log``) fall through to the tail — the one shape with no protection was
    the one that had been thought about. Dropping the test removes the asymmetry and costs nothing
    measured: a census of the whole library, 288,224 candidates over 13 runs, holds exactly the
    five banded classes and no ``log`` candidate at all.
    """
    sink_class = (c.sink_class or "").lower()
    safe = _is_proven_safe(c)
    if sink_class in EXEC_SINKS and not safe and dangerous_source(c):
        return EXEC, PREDICATE_EXEC
    if sink_class in WRITE_SINKS and not safe and dangerous_source(c):
        return WRITE, PREDICATE_WRITE
    if not safe and has_unresolved_dimension(c):
        return UNRESOLVED, PREDICATE_UNRESOLVED
    return TAIL, PREDICATE_PROVEN_SAFE if safe else PREDICATE_PLAIN


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
# these on ``anchor_kind='evidence_ref'``, the candidate anchor it has always used. Spelled once, in
# review_units, beside the run pair's own candidate member kind: both are judged with ``annotate``
# (``review_units.write_tool``).
MEMBER_KIND = ru.SCAN_CANDIDATE

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
    # The predicate that put it in its band (``band_reason``).
    predicate: str = ""


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
        name, predicate = band_reason(c)
        out.append(
            Banded(
                evidence_ref=c.evidence_ref,
                binary=c.binary_path or "",
                sink_class=(c.sink_class or ""),
                source_kind=c.source_kind,
                band=name,
                rank=rank,
                predicate=predicate,
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

    Read at WRITE time, by the writers that need it: the dismissal threshold a write is held to.
    The run is resolved from the candidate's own instance row, and the banding then comes off the
    run's ``triage`` reading.

    COST, stated honestly: that reading is cached per process and per run, so the FIRST such write
    in a process pays for it and the rest pay nothing (measured: 5.5s cold, 2ms warm on a
    30,000-candidate run). A scan review's own loop does not call ``list_candidates`` — it calls
    ``explain_candidate`` and the fact tools — so nothing warms the cache for it, and under the
    batch driver each launch is its own process: one cold reading per launch that dismisses
    something. Called only for ``excluded``, so no other verdict pays it.

    A ref no instance names is not must-read: there is no candidate to band.
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

    ★ And the third state, which is NOT a disposition: a judgement whose read gate cannot be
    evaluated AT ALL. ``held_unread`` is false for it — correctly, since nothing says the subject
    was unread — so the write disposes its member. That is the right call and a silent one: a whole
    run judged this way would read fully disposed with the read gate never having fired once. These
    members are returned separately so the declaration can state how much of its own disposed count
    rests on a gate it could not apply.

    ★ ONLY the members that read DISPOSED, which is what that sentence claims of them. A member
    whose state is ``needs_relabel`` or ``needs_recheck`` is coming back to be judged again, and
    its basis is missing for the same reason every other one is; counting it here would print it
    as a disposed member whose gate could not be reached, when it is the opposite — a member
    nobody is being asked to take as settled. Measured on the live atlas, every single member in
    the count was of that shape (16 of 16 on one run, 3 of 3 on another, all ``needs_recheck`` on
    runs with nothing disposed at all), so the line read "the gate was not applicable to 16
    disposed members" of a run that had disposed none.

    TWO ways it happens, and the second is the whole of the stock today:

    * a server that kept no tool-call log records basis ``unknown``
      (``review_units.NO_SESSION_LOG``);
    * the write recorded NO basis — the history row's column is null, or there is no history row
      for the anchor at all. Every candidate judgement in the live atlas is of this shape (its
      history holds diff subjects only), and so is every write made by a path that passes no
      ``WriteContext``. Counting only the first kind therefore counted the rarer one and let the
      common one through, which is the failure this ★ exists to prevent.
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
            if state != cov.UNSEEN:
                basis = (last or {}).get("read_basis") or {}
                if last is not None and ru.held_unread(last["verdict"], basis):
                    state = cov.NEEDS_RECHECK
                elif ru.disposed(state) and ru.read_gate_unverifiable(basis):
                    # No basis recorded at all (no history row, or a null column), or one that
                    # says the writing server kept no log: either way the gate has nothing to
                    # apply, and saying so is the only honest thing left. The predicate is the
                    # shared one, which the run pair's completion reads too.
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
    # DISPOSED members whose read gate could not be evaluated: no basis was recorded with the
    # write, or the writing server kept no tool-call log, so what had been read before the verdict
    # is not recorded either way (``scan_states``). They stay in the disposed count — nothing says
    # they were unread — and the declaration states how much of that count they are.
    unverifiable_read: tuple[str, ...] = ()
    # The current verdict of every judged candidate of the run (evidence_ref -> verdict): what the
    # disposed members were judged, counted, and what the hand-off reads its blocks from.
    verdicts: dict[str, str] = field(default_factory=dict)

    def tier_members(self, which: int) -> list[ru.Member]:
        """Every member of the run's tier ``which`` (1 or 2), each once — the WHOLE RUN's, never a
        shard's."""
        must = which == TIER_1
        return [m for u in self.units if u.must_read == must for m in u.members]

    @property
    def must_read_complete(self) -> bool:
        """Whether tier 1 is done: every member disposed and none resting on a read gate that
        could not be applied (``review_units.must_read_set_done``, the predicate the run pair's
        completion shares). The whole run's, also in a shard."""
        return ru.must_read_set_done(
            self.tier_members(TIER_1), self.states, frozenset(self.unverifiable_read)
        )

    @property
    def tiers_complete(self) -> bool:
        """Whether both tiers are disposed. NOT called ``complete``: the tail is never handed out,
        so no reading of this profile is ever complete in the run pair's sense."""
        members = self.tier_members(TIER_1) + self.tier_members(TIER_2)
        return all(ru.disposed(self.states.get(m.anchor_ref)) for m in members)


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
        verdicts=current_verdicts(atlas, run_id),
    )


def current_verdicts(atlas: sqlite3.Connection, run_id: str) -> dict[str, str]:
    """The current verdict of every candidate of ``run_id`` the overlay holds one on."""
    return {
        str(ref): str(verdict)
        for ref, verdict in atlas.execute(
            "SELECT anchor_ref, verdict FROM overlay WHERE anchor_kind = 'evidence_ref' "
            "AND run_id = ?",
            (run_id,),
        )
    }


# The scan verdicts, in the order a count of them is stated.
SCAN_VERDICTS = ("inconclusive", "suspicious", "exploitable", "excluded", "safe")
# The verdicts that carry a lead forward (a hand-off's blocks), and the one that leaves it open.
LEAD_VERDICTS = ("suspicious", "exploitable")
OPEN_VERDICT = "inconclusive"


def disposed_by_verdict(
    members: list[ru.Member], states: dict[str, str], verdicts: dict[str, str]
) -> dict[str, int]:
    """How the disposed ``members`` were judged, by verdict (``SCAN_VERDICTS``; any other word
    under ``other``). A COUNT, never a ruling: it is what makes "read, and not concluded" visible —
    ``inconclusive`` disposes a member (``coverage.OPEN``), so a tier read through with nothing but
    inconclusive reads complete, and this is the line that says so."""
    out = dict.fromkeys(SCAN_VERDICTS, 0)
    seen: set[str] = set()
    for m in members:
        if m.anchor_ref in seen or not ru.disposed(states.get(m.anchor_ref)):
            continue
        seen.add(m.anchor_ref)
        v = verdicts.get(m.anchor_ref)
        key = v if v in out else "other"
        out[key] = out.get(key, 0) + 1
    return out


def open_items(review: ScanReview) -> list[str]:
    """The tier 1 members disposed as ``inconclusive``, by ref: read, and left open. The hand-off
    lists each, so a tier that reads complete on inconclusive judgements alone is not read as
    settled."""
    return sorted(
        {
            m.anchor_ref
            for m in review.tier_members(TIER_1)
            if ru.disposed(review.states.get(m.anchor_ref))
            and review.verdicts.get(m.anchor_ref) == OPEN_VERDICT
        }
    )


# ── the coverage declaration ────────────────────────────────────────────────────────────────

# How the second tier is grouped when it is stated: not one line per member (there are tens of
# thousands) and not one number (which says nothing about where they are). The triple is fixed
# here rather than chosen per call so two declarations of the same run group the same way.
SECOND_TIER_GROUP_KEY = ("sink_class", "source_kind", "binary")
# At most this many second-tier groups are printed; the rest are summed into one line. The total
# number of groups and the total number of members are always stated, printed or not.
GROUPS_SHOWN = 20

# The keys of a declaration that are the WHOLE RUN's even when the scope is one shard — named,
# the way ``coverage_offer`` names ``PAIR_WIDE_OFFER_KEYS`` and ``progress_block`` names
# ``PROGRESS_PAIR_WIDE_KEYS``, because a reader cannot tell by looking.
#
# ★ Why this is not cosmetic: a shard's declaration states the whole run's four band counts, its
# tail and its second-tier group distribution beside its OWN tier counts. Printed under a "shard
# scope" heading those read as the shard's, and at ``--workers 64`` they contradict it outright —
# the largest second-tier group (370 on one corpus) is twice that shard's entire second tier. The
# skill tells the agent to quote these numbers verbatim, so four workers would each report the
# same run-wide counts as theirs.
RUN_WIDE_KEYS = (
    "candidates",
    "by_band",
    "unanchored",
    "must_read_complete",
    "tiers_complete",
    "tail",
    "not_seen",
    "tier_2.groups",
    "tier_2.group_size_median",
    "tier_2.group_size_max",
    "tier_2.largest_groups",
    "tier_2.groups_shown",
    "tier_2.groups_not_shown",
    "tier_2.members_not_shown",
)

# What ``must_read_complete`` reads, said beside it.
MUST_READ_RULE = (
    "tier 1 done: every tier 1 member disposed, and none of them resting on a read gate that "
    "could not be applied; tiers_complete also needs tier 2 (the tail is never handed out)"
)

# The last line of every declaration, fixed. The one sentence that has to survive someone skimming
# the numbers above it.
UNREAD_NOT_UNFOUND = "What is not disposed above is UNREAD, not 'nothing found'."

# What the scan read layer cannot see. Stated, never counted: these are descriptions of a shape
# the analysis does not resolve, not labels any row carries, so every one of them matches zero rows
# in the fact tables by construction. A count would therefore read as "no such gap", which is the
# opposite of what they say.
# Why a disposed member's read gate could not be applied — BOTH shapes, because counting only one
# of them counted the rarer one (see ``scan_states``).
READ_GATE_UNVERIFIABLE_WHY = f"no basis recorded with the write, or {ru.NO_SESSION_LOG}"

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

    ★ WHERE, though, needs no prediction, and tier 1 states it: ``undisposed_by_binary``, the
    largest few images the unread part sits in. "How long" is the half of the question this layer
    must not answer; "where" is the half it can, and the second tier was already stated this way
    while the tier somebody has to READ was three band counts and nothing else. Measured, it is
    the difference between a flat 8,737 and knowing that 1,775 of them are in one binary and five
    binaries hold half: a reader can tell which decompiler session to open first without the tool
    ranking anything for them. A count by facet, exactly as the second tier's groups are — no
    rank moves, nothing is collapsed, and the tail and the second tier stay as queryable as before.
    """
    in_shard = [u for u in review.units if ru.in_shard(u.unit_id, worker, workers)]
    tier1 = [u for u in in_shard if u.must_read]
    tier2 = [u for u in in_shard if not u.must_read]
    groups = second_tier_groups(review)
    sizes = [n for _, n in groups]

    def _members(units: list[ru.Unit]) -> list[ru.Member]:
        return [m for u in units for m in u.members]

    binary_of = {b.evidence_ref: b.binary for b in review.banded}
    # ★ The read-gate count is THIS SCOPE's, because the sentence it prints ties it to the
    # disposed count ("of the members this scope reads disposed, how many rest on a gate that
    # could not be applied") and that count is the shard's. ``scan_states`` walks every unit of
    # the run, so a shard would otherwise state the whole run's number beside its own tier counts
    # — the mix no ``(whole run)`` tag can fix, since the two halves of one sentence would be at
    # different scopes. In run scope ``in_shard`` is every unit, so this filter is the identity.
    in_shard_refs = {m.anchor_ref for u in in_shard for m in u.members}
    unverifiable = [r for r in review.unverifiable_read if r in in_shard_refs]

    def _split(units: list[ru.Unit]) -> dict[str, Any]:
        members = _members(units)
        done = sum(1 for m in members if ru.disposed(review.states.get(m.anchor_ref)))
        undone = [m for m in members if not ru.disposed(review.states.get(m.anchor_ref))]
        by_band: dict[str, int] = {}
        by_binary: dict[str, int] = {}
        for m in undone:
            by_band[m.bucket or "-"] = by_band.get(m.bucket or "-", 0) + 1
            binary = binary_of.get(m.anchor_ref) or ""
            by_binary[binary] = by_binary.get(binary, 0) + 1
        largest = sorted(by_binary.items(), key=lambda kv: (-kv[1], kv[0]))
        return {
            "members": len(members),
            "disposed": done,
            "undisposed": len(undone),
            "undisposed_by_band": dict(sorted(by_band.items())),
            # WHERE the unread part sits — the shard's own count, like every other key of this
            # dict. The sum over ALL binaries is ``undisposed``; only the printed list is capped.
            "binaries": len(by_binary),
            "undisposed_by_binary": [
                {"binary": b, "members": n} for b, n in largest[:GROUPS_SHOWN]
            ],
            "binaries_not_shown": max(len(largest) - GROUPS_SHOWN, 0),
            "units": len(units),
            "units_undisposed": sum(1 for u in units if not ru.unit_disposed(u, review.states)),
            # How the disposed members of this scope were judged: counts, never a ruling.
            "disposed_by_verdict": disposed_by_verdict(members, review.states, review.verdicts),
        }

    tail_by: dict[str, int] = dict.fromkeys(TAIL_PREDICATES, 0)
    for b in review.banded:
        if b.band == TAIL:
            tail_by[b.predicate] = tail_by.get(b.predicate, 0) + 1
    out: dict[str, Any] = {
        "run_id": review.run_id,
        "scope": "shard" if workers is not None else "run",
        "candidates": len(review.banded) + review.unanchored,
        "by_band": dict(review.by_band),
        "unanchored": review.unanchored,
        # The WHOLE RUN's, also in a shard (``RUN_WIDE_KEYS``): a shard whose own units are all
        # disposed can still read false here. The shard's own progress is ``tier_1`` below.
        "must_read_complete": review.must_read_complete,
        "tiers_complete": review.tiers_complete,
        "complete_rule": MUST_READ_RULE,
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
            # Which predicate put each tail member there (``band_reason``).
            "by_predicate": tail_by,
            "why": (
                "a proven-safe fact (a compile-time-constant value at the sink) — measured, that "
                "is the whole of this band, and every member still carries an unread axis; "
                "counted, never handed out, and still readable and judgeable by hand"
            ),
        },
        "not_seen": list(ru.NOT_SEEN),
        "not_seen_note": BLIND_SPOTS_ARE_TEXT,
        "run_wide": list(RUN_WIDE_KEYS),
        # How much of the disposed count above rests on a read gate that could not be applied: a
        # write by a server keeping no tool-call log records no basis either way, so it disposes
        # its member and the gate never fires. Stated, because a whole run judged by such a server
        # would otherwise read fully disposed with nothing saying the gate was never applied.
        # This scope's, not the run's — see ``in_shard_refs`` above.
        "read_gate_unverifiable": len(unverifiable),
        "read_gate_unverifiable_why": READ_GATE_UNVERIFIABLE_WHY,
        "unread_not_unfound": UNREAD_NOT_UNFOUND,
    }
    if drive_with and out["tier_1"]["undisposed"]:
        out["if_this_context_fills"] = ru.IF_THIS_CONTEXT_FILLS.format(drive_with=drive_with)
    return out


def coverage_statement(dec: dict[str, Any]) -> str:
    """The one line a report leads with: the counts, and nothing that is not a count."""
    t1, t2 = dec["tier_1"], dec["tier_2"]
    bands = "; ".join(f"{name} {dec['by_band'].get(name, 0)}" for name in BANDS)
    # In a shard the band counts, the group count and the named gaps are the WHOLE RUN's while
    # the tier counts are this shard's (``RUN_WIDE_KEYS``). The skill tells an agent to quote this
    # line verbatim, so it says which is which rather than leaving four workers to report the same
    # run-wide numbers as four shards' own.
    scope = (
        " (bands and groups are the whole run's; the tier counts are this shard's)"
        if (dec["scope"] == "shard")
        else ""
    )
    return (
        f"scan {dec['run_id']}: {dec['candidates']} candidate(s) — {bands}. "
        f"tier 1 {t1['disposed']}/{t1['members']} disposed, {t1['units_undisposed']} unit(s) left; "
        f"tier 2 {t2['disposed']}/{t2['members']} disposed in {t2['groups']} group(s); "
        f"must_read_complete {str(dec['must_read_complete']).lower()}; "
        f"{len(dec['not_seen'])} named gap(s){scope}. {dec['unread_not_unfound']}"
    )


def declaration_text(dec: dict[str, Any]) -> str:
    """The declaration as the lines ``tmap review scan`` prints.

    ★ In a SHARD, every line whose numbers ``RUN_WIDE_KEYS`` names carries ``(whole run)``. The
    shard's own counts are the tier lines and nothing else, and a reader cannot tell which is
    which by looking — four workers each printing the same band counts under "shard" is how the
    same number gets reported four times as four different things."""
    t1, t2 = dec["tier_1"], dec["tier_2"]
    sharded = dec["scope"] == "shard"
    whole = " (whole run)" if sharded else ""
    lines = [
        coverage_statement(dec),
        "",
        f"candidates: {dec['candidates']}{whole or ''}"
        + (f" — this shard holds {t1['members'] + t2['members']} of them" if sharded else ""),
    ]
    for name in BANDS:
        lines.append(f"  band {name}: {dec['by_band'].get(name, 0)}{whole}")
    if dec["unanchored"]:
        lines.append(f"  no evidence_ref (nothing to anchor a read on): {dec['unanchored']}{whole}")
    lines += [
        "",
        f"tier 1 (must read{', this shard' if sharded else ''}): {t1['members']} member(s) in "
        f"{t1['units']} unit(s) — {t1['disposed']} disposed, {t1['undisposed']} not",
    ]
    for name, count in t1["undisposed_by_band"].items():
        lines.append(f"  not disposed, band {name}: {count}")
    judged = ", ".join(f"{v} {n}" for v, n in t1["disposed_by_verdict"].items() if n)
    lines.append(f"  disposed, by verdict: {judged or 'none'}")
    lines.append(f"  units not disposed: {t1['units_undisposed']}")
    if t1["undisposed_by_binary"]:
        lines.append(f"  not disposed, by binary ({t1['binaries']} in all):")
        for row in t1["undisposed_by_binary"]:
            short = (row["binary"] or "").rsplit("/", 1)[-1] or row["binary"]
            lines.append(f"    {row['members']:6d}  {short or '(no path)'}")
        if t1["binaries_not_shown"]:
            lines.append(f"    ... and {t1['binaries_not_shown']} further binary(ies)")
    lines += [
        "",
        f"tier 2 (not handed out until tier 1 is done{', this shard' if sharded else ''}): "
        f"{t2['members']} member(s) — {t2['disposed']} disposed, {t2['undisposed']} not",
        f"  grouped by {' + '.join(t2['group_key'])}: {t2['groups']} group(s), "
        f"median {t2['group_size_median']}, largest {t2['group_size_max']}{whole}",
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
    lines += [
        "",
        f"must_read_complete: {str(dec['must_read_complete']).lower()}{whole}; tiers_complete: "
        f"{str(dec['tiers_complete']).lower()}{whole} — {dec['complete_rule']}",
    ]
    by_pred = ", ".join(f"{p} {n}" for p, n in dec["tail"]["by_predicate"].items())
    lines += [
        "",
        f"tail: {dec['tail']['members']}{whole} ({by_pred}) — {dec['tail']['why']}",
        "",
        "not seen:",
    ]
    lines += [f"  {name}" for name in dec["not_seen"]]
    lines.append(f"  ({dec['not_seen_note']})")
    if dec.get("if_this_context_fills"):
        lines += ["", dec["if_this_context_fills"]]
    lines += ["", dec["unread_not_unfound"]]
    return "\n".join(lines)


# ── a unit's material: what a candidate unit hands out ─────────────────────────────────────

# How a candidate handed out in a unit is read and judged — said once, by every material that
# hands candidates out (a scan unit, and a run pair's one-sided candidate unit).
CANDIDATE_READ_RULE = (
    "read EVERY candidate with explain_candidate(evidence_ref=<anchor_ref>) before judging it — "
    "only that call answers the read gate, and being handed this unit does not; then judge it "
    "with the call its judge_with names (excluded on a tier 1 candidate needs exclusion_why)"
)


def candidate_material(
    members: list[ru.Member] | tuple[ru.Member, ...],
    states: dict[str, str],
    binary_of: dict[str, str],
    budget: int,
) -> dict[str, Any]:
    """The material of a unit of candidates: each candidate's ref, band, binary, sink class and
    ``judge_with`` — only the ones still owed while any is — fitted to ``budget`` bytes.

    ★ NO CANDIDATE FACT. The read gate is ``explain_candidate`` answered for the ref
    (``read_basis_of`` takes no unit, on purpose): were the material to carry the candidate's facts,
    a reader would have them without the gate ever seeing a read, and a verdict written from the
    material alone would read as unread for a reason the reader could not see. The material says
    WHAT to read; reading it is a call of its own.

    The same function for both profiles: a scan unit (``start_scan_review``) and a run pair's
    one-sided candidate unit (``start_diff_review``) hand out the same thing the same way."""
    owed = [m for m in members if not ru.disposed(states.get(m.anchor_ref))] or list(members)
    out: dict[str, Any] = {
        "candidates_total": len(members),
        "read_with": CANDIDATE_READ_RULE,
        "judge_with": ru.JUDGE_WITH_NOTE,
        "candidates": [],
        "candidates_truncated": False,
    }
    room = budget - len(json.dumps(out)) - 64
    for m in owed:
        item = {
            "anchor_ref": m.anchor_ref,
            "band": m.bucket,
            "binary": binary_of.get(m.anchor_ref),
            "sink_class": m.subclass,
            "judge_with": ru.judge_with(m),
        }
        size = len(json.dumps(item)) + 2
        if size > room and out["candidates"]:
            break
        out["candidates"].append(item)
        room -= size
    out["candidates_truncated"] = len(out["candidates"]) < len(owed)
    return out


# ── attribution: where a known issue sits, read off the mechanism ──────────────────────────

# Every class a known issue can fall in, exactly one each (``attribute``).
ATTRIBUTION_CLASSES = (
    "read",
    "unread",
    "tier2_undisposed",
    "tail",
    "ref_unresolved",
    "absent",
    "unanchored",
)
# A ``read`` issue's outcome, by the verdict it was given (the reader's, never the mechanism's).
READ_OUTCOMES = {
    "suspicious": "hit",
    "exploitable": "hit",
    "excluded": "missed",
    "safe": "missed",
    "inconclusive": "inconclusive",
}
# What each class is owed to, said with it.
ATTRIBUTION_OWNER = {
    "read": "the reader's verdict",
    "unread": "the mechanism: tier 1 not read through",
    "tier2_undisposed": (
        "the run mode: tier 2 is handed out only with until=complete — the reporter states the "
        "mode, this reading cannot see it"
    ),
    "tail": "the cut: the predicate that put it in the tail",
    "ref_unresolved": "the truth's anchor: no such function in this run",
    "absent": "sink-side recall: the function is there, no candidate at that sink",
    "unanchored": "the mechanism's edge: a candidate with no evidence_ref is never handed out",
}


def _split_ref(ref: str) -> dict[str, str] | None:
    """An evidence_ref's parts — ``{run}#{binary sha prefix}:{function address}@{class}@{site}``
    — or None when it is not of that shape."""
    run, sep, rest = ref.partition("#")
    if not sep or ":" not in rest:
        return None
    sha, _, tail = rest.partition(":")
    addr, _, more = tail.partition("@")
    sink_class, _, site = more.partition("@")
    if not run or not sha or not addr:
        return None
    return {"run": run, "sha": sha, "addr": addr, "sink_class": sink_class, "site": site}


def _function_row(
    atlas: sqlite3.Connection, run_id: str, sha: str, addr: str
) -> tuple[str | None, str | None, str | None]:
    """``(name, binary path, why)`` of the function at ``addr`` in the run's binary whose sha256
    starts with ``sha``, read from the run's function inventory; ``why`` names why it could not be
    read, and all three are None when it reads and holds no such function."""
    from treasure_map.lib.ro_db import ro_connect  # noqa: PLC0415

    row = atlas.execute("SELECT analysis_db_path FROM run WHERE run_id = ?", (run_id,)).fetchone()
    if row is None or not row[0]:
        return None, None, "the run records no function inventory"
    try:
        conn = ro_connect(row[0])
    except sqlite3.Error:
        return None, None, "the run's function inventory cannot be read"
    try:
        hit = conn.execute(
            "SELECT f.name, b.path FROM functions f JOIN current_binaries b ON b.id = f.binary_id "
            "WHERE b.sha256 LIKE ? AND lower(f.address) = lower(?) LIMIT 1",
            (f"{sha}%", addr),
        ).fetchone()
    except sqlite3.Error:
        return None, None, "the run's function inventory cannot be read"
    finally:
        conn.close()
    if hit is None:
        return None, None, None
    return (str(hit[0]) if hit[0] is not None else None), str(hit[1]), None


def attribute(
    atlas: sqlite3.Connection,
    review: ScanReview,
    candidates: list[TriageCandidate],
    evidence_ref: str,
) -> dict[str, Any]:
    """Which ``ATTRIBUTION_CLASSES`` class a known issue at ``evidence_ref`` falls in, read off the
    mechanism alone — the bands, the tiers, the states and the run's function inventory. No truth
    data is held here: the caller hands in the ref, and the answer says where it sits.

    * a candidate in a tier, disposed on a read gate that applies — ``read``, with the recorded
      verdict and its outcome (``READ_OUTCOMES``: hit / missed / inconclusive);
    * a tier 1 candidate otherwise (undisposed, needs_recheck, needs_relabel, or disposed on a gate
      that could not be applied) — ``unread``; the same in tier 2 — ``tier2_undisposed``;
    * a candidate of the tail — ``tail``, with the predicate that put it there;
    * no candidate under the ref: a ref-less candidate at that function and sink class —
      ``unanchored``; else the function in the run's inventory — ``absent`` (no candidate at that
      sink); else ``ref_unresolved`` (no such function, or the ref is not of this run).

    A candidate row carries its ``source_kind`` and whether its source reads dangerous, which is
    where a gap in source attribution shows — never as ``absent``."""
    by_ref = {b.evidence_ref: b for b in review.banded}
    cand_by_ref = {c.evidence_ref: c for c in candidates if c.evidence_ref}
    out: dict[str, Any] = {"evidence_ref": evidence_ref, "run_id": review.run_id}
    b = by_ref.get(evidence_ref)
    if b is not None:
        where = tier(b.band, b.sink_class)
        c = cand_by_ref.get(evidence_ref)
        out.update(
            band=b.band,
            predicate=b.predicate,
            tier=where,
            source_kind=b.source_kind,
            dangerous_source=dangerous_source(c) if c is not None else None,
        )
        if where is None:
            out["class"] = "tail"
        else:
            state = review.states.get(evidence_ref, cov.UNSEEN)
            unverifiable = evidence_ref in set(review.unverifiable_read)
            out["state"] = state
            if ru.disposed(state) and not unverifiable:
                verdict = review.verdicts.get(evidence_ref)
                out.update(
                    {
                        "class": "read",
                        "verdict": verdict,
                        "outcome": READ_OUTCOMES.get(verdict or ""),
                    }
                )
            else:
                out["class"] = "unread" if where == TIER_1 else "tier2_undisposed"
                if unverifiable:
                    out["read_gate"] = READ_GATE_UNVERIFIABLE_WHY
    else:
        parts = _split_ref(evidence_ref)
        if parts is None or parts["run"] != review.run_id:
            out.update(
                {"class": "ref_unresolved", "why": "the ref is not a candidate anchor of this run"}
            )
        else:
            name, path, why = _function_row(atlas, review.run_id, parts["sha"], parts["addr"])
            loose = [
                c
                for c in candidates
                if not c.evidence_ref
                and path is not None
                and c.binary_path == path
                and c.function == name
                and (c.sink_class or "") == parts["sink_class"]
            ]
            if loose:
                out["class"] = "unanchored"
            elif name is not None or path is not None:
                out.update({"class": "absent", "function": name, "binary": path})
            else:
                out.update({"class": "ref_unresolved", "why": why or "no such function"})
    out["owed_to"] = ATTRIBUTION_OWNER[out["class"]]
    return out
