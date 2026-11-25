# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The scan review profile (lib/query/scan_review): one run's candidates banded, tiered, cut into
work units, and declared.

Four groups of tests, in the order the module reads:

* the BAND predicate, over candidates built by hand — the four bands, the proven-safe clause that
  must sink a candidate, the formatter that is a memory-write lead whatever its impact tier, the
  source dimension the unresolved question must NOT ask, and the unrecognised sink class that must
  stay must-read rather than fall out of the set;
* the two TIERS and the UNITS they are cut into;
* the READ GATE — the one that is easy to implement wrongly: being HANDED a unit must not count as
  having read its candidates;
* the DECLARATION, whose job is that nothing unread reads as nothing found.

Zero real data: a synthetic atlas and hand-built candidates throughout.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from treasure_map.lib import overlay
from treasure_map.lib import tool_call_log as tcl
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import InstanceRow
from treasure_map.lib.atlas.writer import add_instance, upsert_pattern
from treasure_map.lib.errors import ConfigError
from treasure_map.lib.query import read_basis as rb
from treasure_map.lib.query import review_units as ru
from treasure_map.lib.query import scan_review as sr
from treasure_map.lib.query.sink_impact import DEFAULT_SINK_IMPACT, IMPACT_HIGH, IMPACT_LOW
from treasure_map.lib.query.triage import Dimension, TriageCandidate, clear_triage_cache, triage

RUN = "run_s"

# Every dimension the unresolved question asks about, with a RESOLVED reading — so a test turns
# exactly the one it is about to unresolved and nothing else drifts.
_RESOLVED = {
    "controllability": ("proven", "free"),
    "source_writability": ("proven", "web_settable"),
    "reachability": ("proven", "entry:web"),
    "filtering": ("proven", "none"),
    "sink_impact": ("proven", "high"),
    "writer": ("proven", "located"),
    "completeness": ("proven", "complete"),
}


def _cand(
    *,
    sink_class: str = "cmd",
    source_kind: str = "free_string",
    param_source: bool = True,
    controllability: tuple[str, str] | None = None,
    unresolved: tuple[str, ...] = (),
    ref: str = f"{RUN}#aa:00401000@cmd@0x10",
    binary: str = "/fw/bin/boa",
) -> TriageCandidate:
    """One candidate with exactly the readings a band test needs.

    ``unresolved`` names the dimensions to turn unresolved (state ``unknown``); every other one
    reads resolved, so a test about one axis cannot pass because of another.
    """
    dims = []
    for name, (state, value) in _RESOLVED.items():
        if name in unresolved:
            dims.append(Dimension(name, "unknown", "unknown", "not computed"))
        elif name == "controllability" and controllability is not None:
            dims.append(Dimension(name, controllability[0], controllability[1], ""))
        else:
            dims.append(Dimension(name, state, value, ""))
    dims.append(
        Dimension("source", "structural", "param", "")
        if param_source
        else Dimension("source", "unknown", "unknown", "")
    )
    return TriageCandidate(
        review_status="unknown",
        reachability_status="unknown",
        function="fn",
        sink_anchor="system",
        source_class="external_input" if param_source else "unknown",
        sink_class=sink_class,
        blocking_mechanism=None,
        origin="custom",
        source_run_id=RUN,
        evidence_ref=ref,
        binary_path=binary,
        source_kind=source_kind,
        dimensions=tuple(dims),
    )


# ── test 1 / 2: the band predicate ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("sink_class", "band"),
    [("cmd", sr.EXEC), ("fmt_string", sr.EXEC), ("path_sink", sr.EXEC)]
    + [("copy", sr.WRITE), ("format", sr.WRITE)],
)
def test_a_dangerous_source_puts_its_sink_family_in_its_band(sink_class: str, band: str) -> None:
    assert sr.band(_cand(sink_class=sink_class)) == band


def test_a_formatter_is_a_memory_write_lead_whatever_its_impact_tier() -> None:
    """``format`` is the LOWEST impact tier and still a ``write`` band member.

    The whole point of spelling the band families out instead of deriving them from the impact
    map: impact is an overridable RANKING judgement, and a formatter writing into a fixed buffer
    is a memory-write lead. If entering a band asked about impact, an unbounded sprintf would
    never be must-read.

    MUTATION (verified RED, ``1 failed``): derive WRITE_SINKS from the impact map's MEDIUM tier
    (dropping ``format``) -> this test fails, and so does the band-count parametrisation above.
    """
    assert DEFAULT_SINK_IMPACT["format"] == IMPACT_LOW
    assert DEFAULT_SINK_IMPACT["path_sink"] == IMPACT_HIGH
    assert sr.band(_cand(sink_class="format")) == sr.WRITE
    assert sr.band(_cand(sink_class="path_sink")) == sr.EXEC


def test_the_bands_name_only_sink_classes_the_impact_map_knows() -> None:
    # Not derived from that map (see above), but spelled from the same vocabulary: a class renamed
    # there and not here would silently stop matching, and this is what says so.
    assert sr.BANDED_SINKS <= set(DEFAULT_SINK_IMPACT)
    assert "log" not in sr.BANDED_SINKS  # mapped, and neither a write nor an execution


def test_a_proven_safe_candidate_sinks_to_the_tail() -> None:
    """The demotion iron law reaches the bands: a compile-time-constant value at the sink is the
    one fact that takes a candidate out of the must-read set.

    MUTATION (verified RED, ``1 failed``): drop the ``_is_proven_safe`` clause from the exec and
    write branches of ``band`` -> this candidate reads ``exec`` and the test fails. On the
    reference corpora that mutation also moves the band counts (exec 1615 -> 2915, write
    4636 -> 5817), which is what made it worth a test of its own.
    """
    safe = _cand(controllability=("proven", "constant"))
    assert sr.band(safe) == sr.TAIL
    assert sr.tier(sr.band(safe), safe.sink_class) is None
    # and the same candidate, with an unresolved axis as well, still sinks: proven-safe wins
    assert sr.band(_cand(controllability=("proven", "constant"), unresolved=("writer",))) == sr.TAIL


def test_a_candidate_with_no_dangerous_source_but_an_unread_axis_is_unresolved() -> None:
    cand = _cand(param_source=False, source_kind="charset_safe", unresolved=("writer",))
    assert sr.band(cand) == sr.UNRESOLVED


def test_a_charset_constrained_parameter_is_not_a_dangerous_source() -> None:
    # The param-internal demotion iron law: a converter-constrained value cannot inject, so it
    # does not make its sink a band member on the source axis alone.
    assert not sr.dangerous_source(_cand(source_kind="charset_safe"))
    assert not sr.dangerous_source(_cand(source_kind="charset_maybe"))
    assert sr.dangerous_source(_cand(source_kind="free_string"))
    assert sr.dangerous_source(_cand(source_kind="unknown"))


def test_a_value_store_controllable_candidate_is_dangerous_without_a_param_source() -> None:
    # The second family: an nvram key a web form writes. No corpus the profile was measured
    # against exercises it on two of three images, so nothing but this test holds the branch.
    cand = _cand(
        param_source=False, source_kind="charset_safe", controllability=("proven", "controllable")
    )
    assert sr.dangerous_source(cand)
    assert sr.band(cand) == sr.EXEC


def test_the_unresolved_question_never_asks_the_source_dimension() -> None:
    """``source`` is read optimistically by triage (unknown when unresolved, never a truth), so
    asking it this question would answer "unresolved" for every candidate in the atlas.

    MUTATION (verified RED, ``1 failed``): add ``source`` to UNRESOLVED_DIMENSIONS -> the
    non-param candidate below reads unresolved and this fails.
    """
    assert "source" not in sr.UNRESOLVED_DIMENSIONS
    cand = _cand(param_source=False, source_kind="charset_safe")
    assert not sr.has_unresolved_dimension(cand)
    assert sr.band(cand) == sr.TAIL


@pytest.mark.parametrize("dim", sorted(sr.UNRESOLVED_DIMENSIONS))
def test_any_one_unread_axis_is_enough_to_be_unresolved(dim: str) -> None:
    cand = _cand(param_source=False, source_kind="charset_safe", unresolved=(dim,))
    assert sr.has_unresolved_dimension(cand)
    assert sr.band(cand) == sr.UNRESOLVED


def test_an_unrecognised_sink_class_stays_must_read_rather_than_fall_out() -> None:
    """``sink_class`` is an OPEN value set — a class a future extractor emits must not drop out of
    the must-read set on its way in.

    It lands in the weakest must-read band (``unresolved``, tier 2), not in a band whose question
    it has not been shown to answer, and not in the tail. No corpus holds such a class today, so
    this changes no measured count; it is what stops the next one from disappearing.

    MUTATION (verified RED, ``1 failed``): require ``sink_class in BANDED_SINKS`` for the
    unresolved branch -> this reads ``tail`` and the test fails.
    """
    cand = _cand(sink_class="nvram_set", unresolved=("writer",))
    assert cand.sink_class not in DEFAULT_SINK_IMPACT
    assert sr.band(cand) == sr.UNRESOLVED
    assert sr.tier(sr.band(cand), cand.sink_class) == sr.TIER_2


# ── test 4: the two tiers ───────────────────────────────────────────────────────────────────


def test_an_unread_axis_on_an_rce_sink_is_tier_1_and_on_a_memory_write_sink_tier_2() -> None:
    """Why the split is at the sink and not at the band: for an ``unresolved`` candidate the sink
    IS the resolved axis, and an unread source on a command sink is a worse place to stop reading
    than an unread source on a memcpy."""
    for sink_class in sorted(sr.EXEC_SINKS):
        assert sr.tier(sr.UNRESOLVED, sink_class) == sr.TIER_1
    for sink_class in sorted(sr.WRITE_SINKS):
        assert sr.tier(sr.UNRESOLVED, sink_class) == sr.TIER_2
    # the two dangerous-source bands are tier 1 whatever their sink
    assert sr.tier(sr.EXEC, "cmd") == sr.TIER_1
    assert sr.tier(sr.WRITE, "copy") == sr.TIER_1
    assert sr.tier(sr.TAIL, "cmd") is None


# ── the synthetic atlas: units, the read gate, the declaration ──────────────────────────────


def _pattern(conn: sqlite3.Connection, fp: str, sink_class: str, source_class: str) -> int:
    return upsert_pattern(
        conn,
        source_class=source_class,
        sink_class=sink_class,
        call_sequence_shape="source->...->sink",
        structural_fingerprint=fp,
        fingerprint_algo_version="callseq-v1",
    )


_SEQ = [0]


def _inst(
    conn: sqlite3.Connection,
    pattern_id: int,
    *,
    binary: str,
    source_kind: str = "free_string",
    blocking: str | None = None,
    fn: str = "fn",
) -> str:
    _SEQ[0] += 1
    ref = f"{RUN}#b{_SEQ[0]:04d}:0040{_SEQ[0]:04x}@cmd@0x10"
    add_instance(
        conn,
        InstanceRow(
            pattern_id=pattern_id,
            pseudocode_hash=f"h{_SEQ[0]}",
            source_anchor=fn,
            sink_anchor="system",
            source_run_id=RUN,
            reachability_status="unknown",
            blocking_mechanism=blocking,
            provenance_level="L0",
            evidence_ref=ref,
            scope_origin="intra",
            origin="custom",
            binary_path=binary,
            flow_evidence=json.dumps({"source_kind": source_kind}),
        ),
    )
    return ref


def _world(
    tmp_path: Path, *, exec_n: int = 0, write_n: int = 0, second_n: int = 0, binary: str = "/fw/a"
) -> tuple[sqlite3.Connection, dict[str, list[str]]]:
    """An atlas holding the asked-for number of candidates per band, all in one binary.

    ``exec_n`` cmd sinks with a free-string param source (band exec, tier 1); ``write_n`` copy
    sinks likewise (band write, tier 1); ``second_n`` copy sinks with no dangerous source and an
    unread axis (band unresolved, tier 2).
    """
    clear_triage_cache()
    conn = open_atlas(tmp_path / "atlas.db")
    refs: dict[str, list[str]] = {sr.EXEC: [], sr.WRITE: [], "second": []}
    if exec_n:
        p = _pattern(conn, "fp_exec", "cmd", "external_input")
        refs[sr.EXEC] = [_inst(conn, p, binary=binary) for _ in range(exec_n)]
    if write_n:
        p = _pattern(conn, "fp_write", "copy", "external_input")
        refs[sr.WRITE] = [_inst(conn, p, binary=binary) for _ in range(write_n)]
    if second_n:
        p = _pattern(conn, "fp_second", "copy", "unknown")
        refs["second"] = [
            _inst(conn, p, binary=binary, source_kind="charset_safe") for _ in range(second_n)
        ]
    conn.commit()
    return conn, refs


def _review(conn: sqlite3.Connection) -> sr.ScanReview:
    clear_triage_cache()
    return sr.review_run(conn, RUN, triage(conn, run_id=RUN))


# ── test 3: the units ───────────────────────────────────────────────────────────────────────


def test_a_unit_never_holds_two_binaries(tmp_path: Path) -> None:
    clear_triage_cache()
    conn = open_atlas(tmp_path / "atlas.db")
    p = _pattern(conn, "fp_exec", "cmd", "external_input")
    for binary in ("/fw/a", "/fw/b"):
        for _ in range(3):
            _inst(conn, p, binary=binary)
    conn.commit()
    review = _review(conn)
    binary_of = {b.evidence_ref: b.binary for b in review.banded}
    assert len(review.units) == 2  # 3 + 3 members, one unit per binary, never merged
    for u in review.units:
        assert len({binary_of[m.anchor_ref] for m in u.members}) == 1
    assert {binary_of[u.members[0].anchor_ref] for u in review.units} == {"/fw/a", "/fw/b"}
    conn.close()


def test_a_unit_holds_at_most_batch_unit_max_members_in_ranking_order(tmp_path: Path) -> None:
    conn, _ = _world(tmp_path, exec_n=ru.BATCH_UNIT_MAX + 3)
    review = _review(conn)
    tier1 = [u for u in review.units if u.must_read]
    assert [len(u.members) for u in tier1] == [ru.BATCH_UNIT_MAX, 3]
    for u in tier1:
        positions = [m.position for m in u.members]
        assert positions == sorted(positions)  # the run's own ranking order, inside the unit
    conn.close()


def test_the_second_tier_is_its_own_unit_and_is_not_must_read(tmp_path: Path) -> None:
    conn, _ = _world(tmp_path, exec_n=2, second_n=2)
    review = _review(conn)
    must = [u for u in review.units if u.must_read]
    second = [u for u in review.units if not u.must_read]
    assert len(must) == 1 and len(second) == 1
    # A unit is must-read as a WHOLE, so the two tiers cannot share one: a mixed unit would either
    # hand the second tier out with the first or hold the first back with the second.
    assert {m.bucket for m in must[0].members} == {sr.EXEC}
    assert {m.bucket for m in second[0].members} == {sr.UNRESOLVED}
    assert all(m.must_read for m in must[0].members)
    assert not any(m.must_read for m in second[0].members)
    conn.close()


def test_the_second_tier_is_handed_out_only_after_the_first(tmp_path: Path) -> None:
    conn, _ = _world(tmp_path, exec_n=2, second_n=2)
    review = _review(conn)
    without = ru.dispatch_order(review.units, sweep=False)
    whole = ru.dispatch_order(review.units, sweep=True)
    assert [u.must_read for u in without] == [True]
    assert [u.must_read for u in whole] == [True, False]
    conn.close()


def test_the_three_tier_one_streams_are_handed_out_in_rotation(tmp_path: Path) -> None:
    # Two binaries, each with an exec and a write unit: the order alternates between the streams
    # rather than draining one of them first.
    clear_triage_cache()
    conn = open_atlas(tmp_path / "atlas.db")
    pe = _pattern(conn, "fp_exec", "cmd", "external_input")
    pw = _pattern(conn, "fp_write", "copy", "external_input")
    for binary in ("/fw/a", "/fw/b"):
        for _ in range(ru.BATCH_UNIT_MAX):
            _inst(conn, pe, binary=binary)
        for _ in range(ru.BATCH_UNIT_MAX):
            _inst(conn, pw, binary=binary)
    conn.commit()
    review = _review(conn)
    streams = [u.stream for u in ru.dispatch_order(review.units, sweep=False)]
    assert streams.count(sr.EXEC_STREAM) == 2 and streams.count(sr.WRITE_STREAM) == 2
    assert streams[0] != streams[1]  # rotation, not one stream drained first
    conn.close()


# ── test 3b: the kind, and the run pair it must stay out of ─────────────────────────────────


def test_a_scan_band_unit_pages_and_never_enters_a_run_pairs_cutting() -> None:
    from treasure_map import mcp_app

    assert ru.SCAN_BAND in mcp_app._PAGED_KINDS  # it is cut into members, so its material pages
    assert ru.SCAN_BAND not in ru._KIND_RANK  # no run-pair position to sort at
    # The pair predicate is untouched by this kind: it is not one of the kinds review_pair cuts,
    # so no pair's unit_id set moves and the version does not rise.
    pair_kinds = (
        ru.ENTRY,
        ru.S_BATCH,
        ru.PRESENCE,
        ru.FILE,
        ru.SECOND_TIER,
        ru.AUDIT,
        ru.GROUP,
        ru.REDUCE,
        ru.PAIRING,
    )
    assert ru.SCAN_BAND not in pair_kinds
    assert ru.PREDICATE_VERSION == "v5"


# ── test 5: the read gate — the one that is easy to get wrong ───────────────────────────────

_REF = f"{RUN}#aa:00401000@cmd@0x10"


def _explained(ref: str) -> dict[str, Any]:
    return {"tool": "explain_candidate", "params": {"evidence_ref": ref}}


def test_explaining_the_candidate_is_what_answers_the_read_gate() -> None:
    assert sr.read_basis_of([], _REF)["basis"] == "none"
    assert sr.read_basis_of([_explained(_REF)], _REF)["basis"] == "fetched"
    assert sr.read_basis_of([_explained("other#ref")], _REF)["basis"] == "none"


def test_reading_the_whole_function_is_not_reading_the_candidate() -> None:
    """``get_pseudocode`` / ``get_disassembly`` / ``get_callees`` answer the gate for a DIFF
    subject's ``#function_`` anchor. A scan candidate's anchor is not one, so reading its function
    says nothing about the candidate — the opposite of the habit the diff side builds, which is
    why the skill says it out loud."""
    lines = [
        {"tool": "get_pseudocode", "params": {"function": "0x00401000"}},
        {"tool": "get_disassembly", "params": {"function": "0x00401000"}},
        {"tool": "get_callees", "params": {"function": "0x00401000"}},
    ]
    assert sr.read_basis_of(lines, _REF)["basis"] == "none"


def test_being_handed_the_unit_does_not_count_as_having_read_its_candidates() -> None:
    """★ THE tooth. ``read_basis.infer`` given a ``unit_id`` whose material was delivered reads
    ``_shown_whole``: the delivery naming this anchor is enough and the basis comes back
    ``unit_delivered``. A scan verdict is neither of the two verdicts ``gated_short`` looks at, so
    nothing downstream would catch it either — a ``safe`` could be written on a candidate nobody
    opened. ``read_basis_of`` passes no unit, which is the whole reason it exists.

    The second half asserts the mutation's own outcome, so this test pins WHY the call shape is
    what it is and not merely that it is.

    MUTATION (verified RED, ``1 failed``): pass ``unit_id=`` through ``read_basis_of`` -> the
    first assertion reads ``unit_delivered`` and fails.
    """
    delivered = [{"tool": "start_scan_review", "unit": "u1", "unit_whole": [_REF], "params": {}}]
    assert sr.read_basis_of(delivered, _REF)["basis"] == "none"
    # what passing the unit would have said instead:
    with_unit = rb.infer(delivered, anchor_ref=_REF, unit_id="u1", candidates=frozenset({_REF}))
    assert with_unit["basis"] == "unit_delivered"


def _write(conn: sqlite3.Connection, ref: str, verdict: str, *, read: bool, **basis: Any) -> None:
    lines = [_explained(ref)] if read else []
    overlay.upsert_overlay(
        conn,
        evidence_ref=ref,
        verdict=verdict,
        rationale="because",
        verdict_basis=basis or None,
        ctx=overlay.WriteContext(
            channel="mcp", read_basis=sr.read_basis_of(lines, ref), session="s1"
        ),
    )


def test_a_verdict_written_before_the_candidate_was_read_reads_needs_recheck(
    tmp_path: Path,
) -> None:
    conn, refs = _world(tmp_path, exec_n=1)
    ref = refs[sr.EXEC][0]
    _write(conn, ref, "safe", read=False, block_source="p", block_point="q", block_why="r")
    assert _review(conn).states[ref] == "needs_recheck"
    # judged again, after reading it: disposed
    _write(conn, ref, "safe", read=True, block_source="p", block_point="q", block_why="r")
    review = _review(conn)
    assert review.states[ref] == "concluded"
    assert ru.disposed(review.states[ref])
    conn.close()


@pytest.mark.parametrize("verdict", sorted(overlay._VERDICTS))
def test_the_read_gate_holds_every_verdict_not_only_the_dismissals(
    tmp_path: Path, verdict: str
) -> None:
    """``gated_short`` — the diff side's "written without reading" check — is defined over
    ``no_real_change`` / ``change_inconclusive``, and a scan write is never either of those. So the
    basis-``none`` rule is stated on its own and holds for all five verdicts."""
    assert not set(overlay._VERDICTS) & set(ru.GATED_VERDICTS)
    # The reduction the scan side leans on, pinned rather than assumed: through the SHARED
    # predicate, a scan write is held exactly when its basis is ``none`` — ``gated_short``, the
    # other half, can never fire for one of these words. Reading it through ``held_unread`` is
    # what keeps the two profiles from drifting apart the next time that predicate changes.
    for basis in (
        {"basis": "none"},
        {"basis": "fetched"},
        {"basis": "fetched", "read_partial": "pages"},
        {"basis": "unit_delivered", "rows_partial": True},
    ):
        assert ru.held_unread(verdict, basis) == (basis["basis"] == "none")
    conn, refs = _world(tmp_path, exec_n=1)
    ref = refs[sr.EXEC][0]
    extra: dict[str, Any] = {}
    if verdict == "safe":
        extra = {"block_source": "p", "block_point": "q", "block_why": "r"}
    elif verdict == "excluded":
        extra = {"exclusion_why": "nothing reaches it"}
    _write(conn, ref, verdict, read=False, **extra)
    assert _review(conn).states[ref] == "needs_recheck"
    conn.close()


def test_reading_nine_of_sixteen_disposes_nine_and_leaves_seven(tmp_path: Path) -> None:
    conn, refs = _world(tmp_path, exec_n=ru.BATCH_UNIT_MAX)
    for i, ref in enumerate(refs[sr.EXEC]):
        _write(conn, ref, "inconclusive", read=i < 9)
    review = _review(conn)
    done = [r for r in refs[sr.EXEC] if ru.disposed(review.states[r])]
    assert len(done) == 9
    assert sum(1 for r in refs[sr.EXEC] if review.states[r] == "needs_recheck") == 7
    dec = sr.declaration(review)
    assert dec["tier_1"] == {
        **dec["tier_1"],
        "members": 16,
        "disposed": 9,
        "undisposed": 7,
    }
    conn.close()


# ── test 6: what a dismissal owes ───────────────────────────────────────────────────────────


def test_excluded_on_a_must_read_candidate_owes_a_reason(tmp_path: Path) -> None:
    """Both dismissal verdicts move a candidate out of the dangerous view by the same amount, so
    on a subject a review selected to be read, the cheaper word is not the cheaper way out of it.

    MUTATION (verified RED, ``1 failed``): drop the ``must_read_subject`` branch from
    ``_validate_verdict_basis`` -> the bare write below succeeds and this fails.
    """
    conn, refs = _world(tmp_path, exec_n=1)
    ref = refs[sr.EXEC][0]
    assert sr.must_read_candidate(conn, ref)
    with pytest.raises(ConfigError, match="requires exclusion_why"):
        overlay.upsert_overlay(
            conn,
            evidence_ref=ref,
            verdict="excluded",
            rationale="benign",
            must_read_subject=True,
        )
    overlay.upsert_overlay(
        conn,
        evidence_ref=ref,
        verdict="excluded",
        rationale="benign",
        verdict_basis={"exclusion_why": "the sink argument is a .rodata literal"},
        must_read_subject=True,
    )
    conn.close()


def test_excluded_off_the_must_read_set_owes_nothing_new(tmp_path: Path) -> None:
    # The old threshold stands where nobody was told to read it: a sentence of rationale. The
    # second tier is NOT must-read, so it is on this side of the line too.
    conn, refs = _world(tmp_path, second_n=1)
    ref = refs["second"][0]
    assert not sr.must_read_candidate(conn, ref)
    overlay.upsert_overlay(
        conn, evidence_ref=ref, verdict="excluded", rationale="noise", must_read_subject=False
    )
    conn.close()


def test_a_blank_or_foreign_exclusion_basis_is_refused(tmp_path: Path) -> None:
    conn, refs = _world(tmp_path, exec_n=1)
    ref = refs[sr.EXEC][0]
    with pytest.raises(ConfigError, match="must be non-blank"):
        overlay.upsert_overlay(
            conn,
            evidence_ref=ref,
            verdict="excluded",
            rationale="x",
            verdict_basis={"exclusion_why": "   "},
        )
    with pytest.raises(ConfigError, match="exclusion_why alone"):
        overlay.upsert_overlay(
            conn,
            evidence_ref=ref,
            verdict="excluded",
            rationale="x",
            verdict_basis={"exclusion_why": "ok", "block_why": "not this one"},
        )
    conn.close()


def test_the_exclusion_reason_is_stored_under_its_own_kind(tmp_path: Path) -> None:
    conn, refs = _world(tmp_path, exec_n=1)
    ref = refs[sr.EXEC][0]
    overlay.upsert_overlay(
        conn,
        evidence_ref=ref,
        verdict="excluded",
        rationale="x",
        verdict_basis={"exclusion_why": "the length is a sizeof"},
    )
    row = conn.execute("SELECT verdict_basis FROM overlay WHERE anchor_ref = ?", (ref,)).fetchone()
    assert json.loads(row[0]) == {"kind": "excluded", "exclusion_why": "the length is a sizeof"}
    conn.close()


# ── test 7 / 8: the declaration ─────────────────────────────────────────────────────────────


def test_the_declaration_states_every_band_both_tiers_the_tail_and_every_named_gap(
    tmp_path: Path,
) -> None:
    conn, _ = _world(tmp_path, exec_n=3, write_n=2, second_n=4)
    dec = sr.declaration(_review(conn))
    assert dec["by_band"] == {sr.EXEC: 3, sr.WRITE: 2, sr.UNRESOLVED: 4, sr.TAIL: 0}
    assert dec["candidates"] == 9
    assert dec["tier_1"]["members"] == 5 and dec["tier_1"]["disposed"] == 0
    assert dec["tier_2"]["members"] == 4 and dec["tier_2"]["handed_out"] is False
    assert dec["tail"]["members"] == 0
    assert tuple(dec["not_seen"]) == ru.NOT_SEEN and len(dec["not_seen"]) == 9
    text = sr.declaration_text(dec)
    for name in ru.NOT_SEEN:
        assert name in text
    assert text.rstrip().endswith(sr.UNREAD_NOT_UNFOUND)
    conn.close()


def test_the_second_tier_is_stated_by_group_and_the_rest_summed_in_one_line(
    tmp_path: Path,
) -> None:
    clear_triage_cache()
    conn = open_atlas(tmp_path / "atlas.db")
    p = _pattern(conn, "fp_second", "copy", "unknown")
    # one group per binary, sizes 1..GROUPS_SHOWN + 2, so the printed set is capped and the rest
    # is summed rather than dropped
    for i in range(sr.GROUPS_SHOWN + 2):
        for _ in range(i + 1):
            _inst(conn, p, binary=f"/fw/b{i:02d}", source_kind="charset_safe")
    conn.commit()
    review = _review(conn)
    dec = sr.declaration(review)
    t2 = dec["tier_2"]
    assert t2["group_key"] == ["sink_class", "source_kind", "binary"]
    assert t2["groups"] == sr.GROUPS_SHOWN + 2
    assert len(t2["largest_groups"]) == sr.GROUPS_SHOWN
    assert t2["groups_not_shown"] == 2
    assert t2["members_not_shown"] == 1 + 2  # the two smallest groups
    assert t2["group_size_max"] == sr.GROUPS_SHOWN + 2
    # totals are always stated, printed or not
    assert t2["members"] == sum(range(1, sr.GROUPS_SHOWN + 3))
    text = sr.declaration_text(dec)
    assert f"and {t2['groups_not_shown']} further group(s)" in text
    conn.close()


def test_the_declaration_names_the_driver_and_predicts_nothing(tmp_path: Path) -> None:
    """``coverage_offer`` and ``progress_block`` say "facts only … no prediction of when to stop",
    and this is the scan counterpart, so it may not say the one thing the diff side deliberately
    refuses to. What a context too small for the set gets instead is the driver's command, the
    precedent ``IF_THIS_CONTEXT_FILLS`` sets.

    MUTATION (verified RED, ``1 failed``): add a "sessions remaining" estimate to the declaration
    -> the forbidden-word assertion below fails.
    """
    conn, _ = _world(tmp_path, exec_n=3)
    review = _review(conn)
    dec = sr.declaration(review, drive_with="tmap review scan RUN --agent claude-code")
    assert "tmap review scan RUN --agent claude-code" in dec["if_this_context_fills"]
    blob = json.dumps(dec).lower() + sr.declaration_text(dec).lower()
    for word in ("session_estimate", "sessions_remaining", "estimated", "eta", "will take"):
        assert word not in blob
    # units left is a FACT and is stated
    assert dec["tier_1"]["units_undisposed"] == 1
    conn.close()


def test_nothing_undisposed_is_ever_stated_as_confirmed_safe(tmp_path: Path) -> None:
    conn, _ = _world(tmp_path, exec_n=2, second_n=2)
    dec = sr.declaration(_review(conn))
    text = sr.declaration_text(dec)
    low = text.lower()
    for claim in ("no issue", "nothing found", "clean", "confirmed safe", "all clear"):
        # the one place "nothing found" may appear is the closing line that denies it
        if claim in low:
            assert claim in sr.UNREAD_NOT_UNFOUND.lower()
    assert sr.UNREAD_NOT_UNFOUND in text
    assert "UNREAD" in text
    conn.close()


def test_the_coverage_statement_leads_with_the_counts(tmp_path: Path) -> None:
    conn, _ = _world(tmp_path, exec_n=3, second_n=1)
    dec = sr.declaration(_review(conn))
    line = sr.coverage_statement(dec)
    assert "3 candidate(s)" not in line  # 4 candidates, not just the must-read ones
    assert "4 candidate(s)" in line
    assert "tier 1 0/3 disposed" in line
    assert "9 named gap(s)" in line
    assert line.endswith(sr.UNREAD_NOT_UNFOUND)
    conn.close()


# ── the batch driver, and the CLI that runs it ──────────────────────────────────────────────

_PRESET = __import__("treasure_map.lib.review_driver", fromlist=["Preset"]).Preset(
    "test", ("agent", "{unit_id}", "{prompt}")
)


def _scan_agent(
    db: Path, *, read: bool = True, judge: str = "all", seen: list[str] | None = None
) -> Any:
    """A fake agent: reads the refs its prompt names out of the unit and judges them.

    ``read=False`` writes a verdict having explained nothing (the read gate must then hold it);
    ``judge="first"`` judges one ref a launch, which is how the loop's "a launch that disposed a
    new member gets the unit again, with no retry spent" branch is exercised.
    """
    import re as _re

    from treasure_map.lib.atlas.connection import open_atlas as _open

    def run(argv: Any, **_: Any) -> Any:
        from treasure_map.lib import review_driver as _rd

        prompt = argv[-1]
        refs = _re.findall(rf"({RUN}#\S+)", prompt)
        if seen is not None:
            seen.append(argv[1])
        conn = _open(db)
        try:
            if judge == "first":
                # the first ref it has not judged yet: one NEW member a launch, which is the
                # loop branch this exercises (the same unit again, no retry spent)
                done = {
                    r[0]
                    for r in conn.execute(
                        "SELECT anchor_ref FROM overlay WHERE anchor_kind = 'evidence_ref'"
                    )
                }
                refs = [r for r in refs if r not in done][:1]
            elif judge == "none":
                refs = []
            for ref in refs:
                _write(conn, ref, "inconclusive", read=read)
            conn.commit()
        finally:
            conn.close()
        return _rd.Launch(0, 0.01, False)

    return run


def test_the_driver_hands_out_every_scan_unit_and_reads_success_from_the_history(
    tmp_path: Path,
) -> None:
    """One launch per unit, the same loop the run pair uses: success is read from the overlay, not
    from the agent's exit code."""
    from treasure_map.lib import review_driver as rd

    conn, refs = _world(tmp_path, exec_n=ru.BATCH_UNIT_MAX + 1, second_n=2)
    conn.close()
    db = tmp_path / "atlas.db"
    seen: list[str] = []
    result = rd.scan_drive(
        db,
        RUN,
        _PRESET,
        workdir=tmp_path,
        runner=_scan_agent(db, seen=seen),
        echo=lambda s: None,
        until="complete",
    )
    assert result.failed == [] and result.stopped == "no unit left"
    assert result.units_done == result.units_tried == 3  # 16 + 1 tier-1 units, 1 second-tier
    assert len(set(seen)) == 3  # each unit's own id reached the agent
    assert result.offer is not None and result.offer["tier_1"]["undisposed"] == 0
    # What each launch WROTE is read by anchor, not by unit: a scan write names no unit, so the
    # unit-keyed reader the pair uses would log every launch as having written nothing.
    log = tcl.read_lines(tcl.log_path_for(db).with_name(rd.DRIVER_LOG))
    assert log is not None and [ln["members_written"] for ln in log] == [16, 1, 2]
    conn = open_atlas(db)
    assert all(ru.disposed(s) for s in _review(conn).states.values())
    conn.close()


def test_a_scan_unit_judged_without_reading_is_not_disposed_and_comes_back(
    tmp_path: Path,
) -> None:
    """The read gate reaches the driver: an agent that writes a verdict having explained nothing
    disposes no member, so the unit is retried and then reported failed — never counted done.

    MUTATION (verified RED, ``1 failed``): let the scan states ignore the stored basis -> this
    drive succeeds and the test fails."""
    from treasure_map.lib import review_driver as rd

    conn, _ = _world(tmp_path, exec_n=2)
    conn.close()
    db = tmp_path / "atlas.db"
    result = rd.scan_drive(
        db,
        RUN,
        _PRESET,
        workdir=tmp_path,
        runner=_scan_agent(db, read=False),
        retries=0,
        echo=lambda s: None,
    )
    assert result.units_done == 0
    assert result.stopped is not None  # the first unit wrote, but disposed nothing
    conn = open_atlas(db)
    assert set(_review(conn).states.values()) == {"needs_recheck"}
    conn.close()


def test_a_launch_that_disposes_one_member_gets_the_unit_again_with_no_retry_spent(
    tmp_path: Path,
) -> None:
    from treasure_map.lib import review_driver as rd

    conn, _ = _world(tmp_path, exec_n=3)
    conn.close()
    db = tmp_path / "atlas.db"
    result = rd.scan_drive(
        db,
        RUN,
        _PRESET,
        workdir=tmp_path,
        runner=_scan_agent(db, judge="first"),
        retries=0,  # three launches, and none of them a retry
        echo=lambda s: None,
    )
    assert result.units_tried == 1 and result.units_done == 1 and result.failed == []
    conn.close()


def test_the_shards_split_the_units_and_cover_them_all(tmp_path: Path) -> None:
    conn, _ = _world(tmp_path, exec_n=ru.BATCH_UNIT_MAX * 3)
    review = _review(conn)
    conn.close()
    ids = {u.unit_id for u in review.units}
    shards = [{u for u in ids if ru.in_shard(u, i, 3)} for i in range(3)]
    assert set().union(*shards) == ids  # every unit in exactly one shard
    assert sum(len(s) for s in shards) == len(ids)


def test_one_units_material_fits_the_page_budget(tmp_path: Path) -> None:
    """A tier-1 unit is at most BATCH_UNIT_MAX candidates and its prompt names each one, so one
    dispatch stays inside what a page shows."""
    from treasure_map.lib import review_driver as rd

    conn, _ = _world(tmp_path, exec_n=ru.BATCH_UNIT_MAX)
    review = _review(conn)
    unit = next(u for u in review.units if u.must_read)
    assert len(unit.members) == ru.BATCH_UNIT_MAX
    prompt = rd.scan_unit_prompt(RUN, unit)
    for m in unit.members:
        assert m.anchor_ref in prompt  # every ref it must read, named
    assert len(prompt.encode("utf-8")) < 8_000
    conn.close()


# ── the CLI ─────────────────────────────────────────────────────────────────────────────────


def test_the_cli_prints_the_declaration_and_writes_nothing(tmp_path: Path) -> None:
    from click.testing import CliRunner

    from treasure_map.cli.review_cli import review

    conn, _ = _world(tmp_path, exec_n=2, second_n=1)
    conn.close()
    db = tmp_path / "atlas.db"
    before = db.stat().st_mtime_ns
    res = CliRunner().invoke(review, ["scan", RUN, "--atlas", str(db)])
    assert res.exit_code == 0, res.output
    assert "band exec: 2" in res.output
    assert sr.UNREAD_NOT_UNFOUND in res.output
    assert "tmap review scan" in res.output  # the driver named, no session estimate
    assert db.stat().st_mtime_ns == before  # read-only
    bad = CliRunner().invoke(review, ["scan", "no_such_run", "--atlas", str(db)])
    assert bad.exit_code != 0 and "no candidate in this atlas" in bad.output


def test_the_cli_refuses_half_a_shard(tmp_path: Path) -> None:
    from click.testing import CliRunner

    from treasure_map.cli.review_cli import review

    conn, _ = _world(tmp_path, exec_n=1)
    conn.close()
    db = tmp_path / "atlas.db"
    for args in (["--worker", "0"], ["--workers", "2"], ["--worker", "2", "--workers", "2"]):
        res = CliRunner().invoke(review, ["scan", RUN, "--atlas", str(db), *args])
        assert res.exit_code != 0


def test_the_scan_skill_is_shipped_and_names_its_own_read_gate() -> None:
    from treasure_map.lib.query import scan_skill

    text = scan_skill.skill_text()
    assert text.startswith("---\nname: tmap-scan-review\n")
    # the four things the skill exists to say
    assert "explain_candidate" in text
    assert "exclusion_why" in text
    assert "--workers" in text and "EXPERIENCE value" in text
    assert "UNREAD" in text
    for band in (sr.EXEC, sr.WRITE, sr.UNRESOLVED, sr.TAIL):
        assert f"`{band}`" in text


def test_the_installer_refuses_to_claim_the_scan_skill() -> None:
    # The install ledger keeps ONE skill current; recording this one would claim upkeep it does
    # not do, so --install is refused rather than quietly writing an unmanaged file.
    from click.testing import CliRunner

    from treasure_map.cli.review_cli import review

    res = CliRunner().invoke(review, ["skill", "--scan", "--install", "/tmp/nowhere"])
    assert res.exit_code != 0 and "will not keep it current" in res.output


def test_a_write_whose_read_gate_could_not_be_applied_is_stated_not_hidden(
    tmp_path: Path,
) -> None:
    """A server keeping no tool-call log records basis ``unknown``: ``held_unread`` is false for it
    — correctly, nothing says the subject was unread — so the write disposes its member and the
    read gate never fires. A whole run judged that way would read fully disposed with nothing
    saying so, which is the shape this states instead.

    MUTATION (verified RED, ``1 failed``): drop ``read_gate_unverifiable`` from the declaration ->
    the count is gone and this fails.
    """
    conn, refs = _world(tmp_path, exec_n=2)
    ref = refs[sr.EXEC][0]
    overlay.upsert_overlay(
        conn,
        evidence_ref=ref,
        verdict="inconclusive",
        rationale="r",
        ctx=overlay.WriteContext(
            channel="mcp", read_basis=sr.read_basis_of(None, ref), session="s1"
        ),
    )
    review = _review(conn)
    assert review.unverifiable_read == (ref,)
    assert ru.disposed(review.states[ref])  # it IS disposed: nothing says it was unread
    dec = sr.declaration(review)
    assert dec["read_gate_unverifiable"] == 1
    assert dec["read_gate_unverifiable_why"] == ru.NO_SESSION_LOG
    assert "read gate not applicable to 1 disposed member(s)" in sr.declaration_text(dec)
    # a write WITH a log is not counted here
    other = refs[sr.EXEC][1]
    _write(conn, other, "inconclusive", read=True)
    assert _review(conn).unverifiable_read == (ref,)
    conn.close()
