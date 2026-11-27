# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""A binary only one run of a pair holds, read as its own run's scan reads it (review_units with
scan_review's tiers): which of its subjects are must-read, how they are cut into units, how each
is read and written, and the hand-off that carries its candidates.

The bands are set per candidate here (``scan_review.band_reason`` patched to a table), so a test
says which tier each candidate is in rather than depending on how triage reads a synthetic row.
Zero real data."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests.unit.lib.test_binary_presence import (  # noqa: F401 — the autouse servable fixture
    PAIR,
    World,
    _flow,
    _servable,
    _sha,
)
from treasure_map import mcp_app
from treasure_map.lib import overlay
from treasure_map.lib.query import binary_presence as bp
from treasure_map.lib.query import review_units as ru
from treasure_map.lib.query import scan_review as sr
from treasure_map.lib.query.triage import clear_triage_cache

WEB = "web/x.cgi"  # A only: the gate holds two of its function bodies (a web entry, cmd sinks)
TOOL = "bin/tool"  # B only: one tier 1 command candidate, no entry edge
WEAK = "bin/weak"  # A only: a tier 2 candidate and nothing else
EMPTY = "bin/empty"  # A only: no candidate at all (judged whole)
LOOSE = "bin/loose"  # A only: a tier 1 candidate naming no function (judged whole for it)

EXEC = (sr.EXEC, sr.PREDICATE_EXEC)
WRITE = (sr.WRITE, sr.PREDICATE_WRITE)
T2 = (sr.UNRESOLVED, sr.PREDICATE_UNRESOLVED)
TAIL = (sr.TAIL, sr.PREDICATE_PROVEN_SAFE)


class Tiered:
    """The world and the refs, by role."""

    def __init__(self, w: World, refs: dict[str, str], bands: dict[str, tuple[str, str]]) -> None:
        self.w = w
        self.refs = refs
        self.bands = bands

    def anchor(self, side_tag: str, rel: str, addr: str | None = None) -> str:
        base = f"{PAIR}#binary_presence#{side_tag}:{rel}"
        return base if addr is None else f"{base}::{addr}"


@pytest.fixture
def tiered(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Tiered:
    w = World(tmp_path)
    bands: dict[str, tuple[str, str]] = {}
    refs: dict[str, str] = {}

    def put(role: str, side: str, rel: str, sha: str, cls: str, band: tuple[str, str], **kw: Any):
        (ref,) = w.cand(side, rel, sha, cls, **kw)
        refs[role] = ref
        bands[ref] = band

    w.binary("a", WEB, _sha("3"))
    put("c1", "a", WEB, _sha("3"), "cmd", EXEC, addr="00401000", flow=_flow())
    put("c2", "a", WEB, _sha("3"), "cmd", TAIL, addr="00401000", flow=_flow())
    put("c3", "a", WEB, _sha("3"), "cmd", TAIL, addr="00402000", flow=_flow())
    put("c4", "a", WEB, _sha("3"), "copy", T2, addr="00403000")
    put("c5", "a", WEB, _sha("3"), "copy", WRITE, addr="00404000")
    w.binary("b", TOOL, _sha("4"))
    put("d1", "b", TOOL, _sha("4"), "cmd", EXEC, addr="00501000")
    put("d2", "b", TOOL, _sha("4"), "cmd", TAIL, addr="00501000")
    w.binary("a", WEAK, _sha("5"))
    put("e1", "a", WEAK, _sha("5"), "copy", T2, addr="00601000")
    w.binary("a", EMPTY, _sha("6"))
    w.binary("a", LOOSE, _sha("7"))
    put("f1", "a", LOOSE, _sha("7"), "cmd", EXEC, addr="main")
    w.commit()
    real = sr.band_reason
    monkeypatch.setattr(sr, "band_reason", lambda c: bands.get(c.evidence_ref) or real(c))
    clear_triage_cache()
    return Tiered(w, refs, bands)


def _review(t: Tiered, k: int = ru.DEFAULT_K) -> ru.PairReview:
    clear_triage_cache()
    return ru.review_pair(
        t.w.atlas,
        "runA",
        "runB",
        k=k,
        pair_staleness={"source_stale": False, "source_stale_reason": None},
        server_commit=None,
    )


def _units(r: ru.PairReview) -> list[ru.Unit]:
    """The units of the one-sided binaries (function bodies, whole binaries, candidates)."""
    return [u for u in r.units if u.stream in (ru.PRESENCE_STREAM, ru.PRESENCE_CANDIDATE_STREAM)]


def _must(r: ru.PairReview) -> set[str]:
    return {m.anchor_ref for u in _units(r) if u.must_read for m in u.members}


def _server(t: Tiered) -> Any:
    from tests.unit.test_tool_surface import _call

    server = mcp_app.build_server(t.w.path)
    return lambda name, args: _call(server, name, args)


def _annotate(t: Tiered, ref: str, verdict: str = "inconclusive", **kw: Any) -> None:
    """``ref`` judged after it was explained, as the annotate tool records it."""
    overlay.upsert_overlay(
        t.w.atlas,
        evidence_ref=ref,
        verdict=verdict,
        rationale="read it",
        verdict_basis=kw or None,
        ctx=overlay.WriteContext(
            channel="mcp",
            read_basis=sr.read_basis_of(
                [{"tool": "explain_candidate", "params": {"evidence_ref": ref}}], ref
            ),
            session="s",
        ),
    )
    t.w.atlas.commit()


# ── the must-read set ───────────────────────────────────────────────────────────────────────


def test_the_must_read_set_is_tier_1_candidates_gate_bodies_and_binaries_judged_whole(
    tiered: Tiered,
) -> None:
    """★ A one-sided binary's must-read set is the union of its scan tier 1 candidates (each a
    member of its own), the function bodies the characterisation gate holds, and the binary's own
    anchor when it is judged whole — on either side. The other function bodies and the tier 2
    candidates are second tier; the tail is in no unit at all.

    MUTATION (verified RED, 1 failed each): every function body must-read again (reasons always
    ``binary_presence``) -> RED; the tier 2 candidates must-read too -> RED."""
    t = tiered
    r = _review(t)
    a, b = "a_only", "b_only"
    want = {
        t.refs["c1"],
        t.refs["c5"],
        t.refs["d1"],
        t.refs["f1"],
        t.anchor(a, WEB, "00401000"),
        t.anchor(a, WEB, "00402000"),
        t.anchor(a, EMPTY),
        t.anchor(a, LOOSE),
    }
    assert _must(r) == want
    second = {m.anchor_ref for u in _units(r) if not u.must_read for m in u.members}
    assert second == {
        t.refs["c4"],
        t.refs["e1"],
        t.anchor(a, WEB, "00403000"),
        t.anchor(a, WEB, "00404000"),
        t.anchor(b, TOOL, "00501000"),
        t.anchor(a, WEAK, "00601000"),
    }
    every = {m.anchor_ref for u in r.units for m in u.members}
    assert not {t.refs[x] for x in ("c2", "c3", "d2")} & every
    assert r.report["must_read"]["by_reason"]["binary_presence"] == len(want)
    assert set(r.report["must_read"]["by_reason"]) == set(ru.REASONS)


def test_a_gate_body_whose_command_candidates_are_all_in_the_tail_stays_must_read(
    tiered: Tiered,
) -> None:
    """★ A function body the one-sided gate holds stays must-read even when none of its
    candidates is: its command candidate is in the tail, and an entry edge names its binary. Its
    changed_real without ``one_sided_characterized`` reads needs_recheck (the gate still holds
    it), so the must-read set is not done.

    MUTATION (verified RED, 1 failed): drop the gate from the presence members' reasons (only a
    binary judged whole must-read) -> the body is second tier -> RED."""
    t = tiered
    body = t.anchor("a_only", WEB, "00402000")
    assert body in _must(_review(t))
    overlay.annotate_diff(
        t.w.atlas,
        run_pair=PAIR,
        anchor_ref=body,
        verdict="changed_real",
        rationale="the binary is gone",
        verdict_basis={"evidence": [body, t.refs["c3"]]},
        ctx=overlay.WriteContext(channel="mcp", read_basis={"basis": "unit_delivered"}),
    )
    t.w.atlas.commit()
    r = _review(t)
    assert body in r.report["presence_characterization_short"]
    assert r.progress.states[body] == ru.NEEDS_RECHECK
    assert r.report["must_read_complete"] is False


def test_a_binary_judged_whole_stays_must_read_with_no_candidate_or_an_unplaced_one(
    tiered: Tiered,
) -> None:
    """★ A binary one run lacks is a fact the scan has no view on, so its own anchor stays
    must-read when it is judged whole: holding no candidate, or one naming no function (whose
    tier 1 candidate is a member of its own beside it).

    MUTATION (verified RED, 1 failed): leave the binary's own anchor out of the must-read
    reasons -> RED."""
    t = tiered
    must = _must(_review(t))
    assert t.anchor("a_only", EMPTY) in must
    assert t.anchor("a_only", LOOSE) in must and t.refs["f1"] in must
    (b,) = [x for x in bp.find_presence(t.w.atlas, "runA", "runB").items if x.rel_path == LOOSE]
    assert b.unplaced == (t.refs["f1"],) and b.judged_whole


def test_the_tail_is_counted_by_predicate_and_never_handed_out(tiered: Tiered) -> None:
    """★ A tail candidate is counted (with the predicate that put it there), never a member:
    not in the second tier either, so ``sweep`` hands none out and ``complete`` never waits on
    one.

    MUTATION (verified RED, 1 failed): make the tail tier 2 members -> counted as tier 2, and a
    sweep hands one out -> RED."""
    t = tiered
    r = _review(t)
    pc = r.report["presence_candidates"]
    assert (pc["tier_1"], pc["tier_2"], pc["tail"]) == (4, 2, 3)
    assert pc["tail_by_predicate"] == {sr.PREDICATE_PROVEN_SAFE: 3, sr.PREDICATE_PLAIN: 0}
    handed = {m.anchor_ref for u in ru.dispatch_order(r.units, sweep=True) for m in u.members}
    assert not {t.refs[x] for x in ("c2", "c3", "d2")} & handed
    assert "tail 3 counted (proven_safe 3" in r.report["coverage_statement"]


def test_a_binary_with_no_tier_1_candidate_is_named_apart(tiered: Tiered) -> None:
    """★ A one-sided binary holding candidates of which none is tier 1 leaves the must-read set
    except as counted: named under ``binaries_without_tier_1`` so its leaving is visible.

    MUTATION (verified RED, 1 failed): leave the binary unnamed -> RED."""
    pc = _review(tiered).report["presence_candidates"]
    assert pc["binaries_without_tier_1"] == 1
    assert pc["binaries_without_tier_1_named"] == [f"a_only:{WEAK}"]


# ── how a candidate member is read and judged ──────────────────────────────────────────────


def test_a_tier_1_candidate_judged_before_it_was_explained_is_not_disposed(
    tiered: Tiered,
) -> None:
    """★ The scan read gate holds the pair's candidate members: a verdict written before
    explain_candidate answered for the ref reads needs_recheck; written again after it, the
    member is disposed — in the pair and in the run's own scan review alike (one judgement).

    MUTATION (verified RED, 1 failed): drop the read gate from ``scan_states`` (the overlay's
    reading alone) -> the unread write disposes it -> RED."""
    t = tiered
    ref = t.refs["c1"]
    overlay.upsert_overlay(
        t.w.atlas,
        evidence_ref=ref,
        verdict="suspicious",
        rationale="r",
        ctx=overlay.WriteContext(channel="mcp", read_basis=sr.read_basis_of([], ref)),
    )
    t.w.atlas.commit()
    assert _review(t).progress.states[ref] == ru.NEEDS_RECHECK
    _annotate(t, ref, "suspicious")
    assert ru.disposed(_review(t).progress.states[ref])
    clear_triage_cache()
    assert ru.disposed(sr.review_run(t.w.atlas, "runA").states[ref])


def test_an_existence_reading_of_the_function_does_not_dispose_its_candidates(
    tiered: Tiered,
) -> None:
    """★ Citing every candidate of a function body ("the binary is gone") disposes the BODY; a
    tier 1 candidate of it is a member of its own and stays undisposed until judged itself.

    MUTATION (verified RED, 1 failed): read every candidate member as disposed (the body's
    existence reading standing for them) -> RED."""
    t = tiered
    body = t.anchor("a_only", WEB, "00403000")
    overlay.annotate_diff(
        t.w.atlas,
        run_pair=PAIR,
        anchor_ref=body,
        verdict="changed_real",
        rationale="the binary is gone",
        verdict_basis={"evidence": [body, t.refs["c4"]]},
        ctx=overlay.WriteContext(channel="mcp", read_basis={"basis": "unit_delivered"}),
    )
    t.w.atlas.commit()
    states = _review(t).progress.states
    assert ru.disposed(states[body])
    assert not ru.disposed(states[t.refs["c4"]])


def test_excluded_on_a_tier_1_one_sided_candidate_owes_its_reason(tiered: Tiered) -> None:
    """★ A one-sided binary's tier 1 candidate is that run's own tier 1 ref, so ``excluded``
    without ``exclusion_why`` is refused by the very write the scan profile holds it to.

    MUTATION (verified RED, 1 failed): never read the candidate as tier 1 at write time
    (``must_read_candidate`` false) -> the write goes through -> RED."""
    call = _server(tiered)
    out = call(
        "annotate", {"evidence_ref": tiered.refs["c1"], "verdict": "excluded", "rationale": "noise"}
    )
    assert out.get("written") is False and "exclusion_why" in out["error"], out


# ── the units ───────────────────────────────────────────────────────────────────────────────


def test_every_unit_holds_members_of_one_write_tool_and_the_four_kinds_are_cut(
    tiered: Tiered,
) -> None:
    """★ A one-sided binary's subjects are cut into units of one kind each — must-read bodies and
    whole binaries (PRESENCE), the other bodies (SECOND_TIER), and candidates tier 1 / tier 2
    (PRESENCE_CANDIDATES, must_read telling them apart) — so a unit's prompt and its write tool
    are one per unit, the second tier too.

    MUTATION (verified RED, 1 failed): cut the tier 1 candidates into PRESENCE units (the kind
    the bodies are judged in) -> RED."""
    r = _review(tiered)
    kinds = set()
    for u in _units(r):
        assert len({ru.write_tool(m) for m in u.members}) == 1, u
        kinds.add((u.kind, u.must_read))
    assert kinds == {
        (ru.PRESENCE, True),
        (ru.SECOND_TIER, False),
        (ru.PRESENCE_CANDIDATES, True),
        (ru.PRESENCE_CANDIDATES, False),
    }


def test_a_tier_2_candidate_unit_is_handed_out_on_sweep_with_the_scan_prompt(
    tiered: Tiered,
) -> None:
    """★ With the second tier asked for, a tier 2 candidate unit is handed out, and the batch
    driver gives it the scan prompt (explain_candidate, then annotate) for its own side's run;
    each member's judge_with names annotate.

    MUTATION (verified RED, 1 failed): give every pair unit unit_prompt -> it says annotate_diff
    with a unit_id -> RED."""
    from treasure_map.lib import review_driver as rd

    t = tiered
    r = _review(t)
    (u,) = [
        u
        for u in ru.dispatch_order(r.units, sweep=True)
        if u.kind == ru.PRESENCE_CANDIDATES
        and not u.must_read
        and u.members[0].run == "runA"
        and u.members[0].anchor_ref == t.refs["c4"]
    ]
    profile = rd._PairProfile(
        run_a="runA",
        run_b="runB",
        k=ru.DEFAULT_K,
        staleness={"source_stale": False, "source_stale_reason": None},
        sweep=True,
        worker=None,
        workers=None,
    )
    prompt = profile.prompt(u)
    assert "explain_candidate" in prompt and "annotate(evidence_ref" in prompt
    assert "firmware scan runA" in prompt and "annotate_diff" not in prompt
    assert all(ru.judge_with(m) == {"tool": "annotate"} for m in u.members)


def test_a_candidate_units_material_carries_no_candidate_fact(tiered: Tiered) -> None:
    """★ A candidate unit's material names each candidate — ref, band, binary, sink class,
    judge_with — and carries none of explain_candidate's facts: being handed it must not read
    as having read it.

    MUTATION (verified RED, 1 failed): drop the candidate unit's branch from _unit_material ->
    no candidates listed -> RED."""
    t = tiered
    r = _review(t)
    (u,) = [
        x
        for x in _units(r)
        if x.kind == ru.PRESENCE_CANDIDATES and x.must_read and x.members[0].run == "runB"
    ]
    out = _server(t)("start_diff_review", {"run_pair": PAIR, "unit": u.unit_id})
    mat = out["material"]
    assert "candidates" in mat, mat
    assert [c["anchor_ref"] for c in mat["candidates"]] == [t.refs["d1"]]
    (c,) = mat["candidates"]
    assert set(c) == {"anchor_ref", "band", "binary", "sink_class", "judge_with"}
    assert c["judge_with"] == {"tool": "annotate"} and c["band"] == sr.EXEC
    text = json.dumps(mat)
    for fact in ("dimensions", "sink_arg_provenance_summary", "controllability", "caveats"):
        assert fact not in text, fact
    assert [m["anchor_ref"] for m in out["members"]] == [t.refs["d1"]]


def test_what_a_launch_wrote_is_read_by_each_members_write_tool(tiered: Tiered) -> None:
    """★ The driver reads a launch's writes by each member's write tool: an annotate_diff write
    by its unit, an annotate write by its anchor — the union, so a unit holding both (none does
    today) still reads every write.

    MUTATION (verified RED, 1 failed each): read by unit alone -> the candidate is not seen;
    read by anchor alone -> the body is not seen."""
    from treasure_map.lib import review_driver as rd

    t = tiered
    r = _review(t)
    body = next(
        m
        for u in _units(r)
        if u.kind == ru.PRESENCE
        for m in u.members
        if m.anchor_ref == t.anchor("a_only", WEB, "00401000")
    )
    cand = next(m for u in _units(r) for m in u.members if m.anchor_ref == t.refs["c1"])
    mixed = ru.Unit("0" * 16, "x", True, (body, cand), "s", 0, 0)
    mark = rd.history_mark(t.w.atlas)
    overlay.annotate_diff(
        t.w.atlas,
        run_pair=PAIR,
        anchor_ref=body.anchor_ref,
        verdict="change_inconclusive",
        rationale="r",
        ctx=overlay.WriteContext(
            channel="mcp", unit_id=mixed.unit_id, read_basis={"basis": "unit_delivered"}
        ),
    )
    _annotate(t, cand.anchor_ref)
    profile = rd._PairProfile(
        run_a="runA",
        run_b="runB",
        k=ru.DEFAULT_K,
        staleness={"source_stale": False, "source_stale_reason": None},
        sweep=False,
        worker=None,
        workers=None,
    )
    assert profile.written(t.w.atlas, mixed, mark) == {body.anchor_ref, cand.anchor_ref}


def test_annotate_diff_on_a_candidate_is_refused_naming_annotate(tiered: Tiered) -> None:
    """★ annotate_diff naming a unit of candidates is refused, and so is annotate_diff on a
    candidate's evidence_ref with run_pair: each refusal names annotate (a one-sided candidate
    has no diff_id to pass).

    MUTATION (verified RED, 1 failed each): drop the candidate-unit refusal from _write_plan ->
    RED; put back the "pass diff_id" message for a candidate anchor -> RED."""
    t = tiered
    r = _review(t)
    (u,) = [
        x
        for x in _units(r)
        if x.kind == ru.PRESENCE_CANDIDATES and x.must_read and x.members[0].run == "runB"
    ]
    call = _server(t)
    out = call(
        "annotate_diff",
        {
            "anchor_ref": t.refs["d1"],
            "verdict": "changed_real",
            "rationale": "r",
            "run_pair": PAIR,
            "unit_id": u.unit_id,
        },
    )
    assert "holds candidates, judged with annotate" in str(out.get("error")), out
    assert "annotate(evidence_ref" in str(out.get("error"))
    out = call(
        "annotate_diff",
        {"anchor_ref": t.refs["d1"], "verdict": "changed_real", "rationale": "r", "run_pair": PAIR},
    )
    assert "judged with annotate" in str(out.get("error")), out
    assert "pass diff_id" not in str(out.get("error"))


def test_each_sides_candidates_are_read_from_their_own_run(tiered: Tiered) -> None:
    """★ The two sides' one-sided binaries are of two runs, and scan_states reads one: the
    candidates of each are read from their own run, so a judgement on a B-side candidate counts.

    MUTATION (verified RED, 1 failed): read every candidate from run A -> the B one's write is
    not found in its run's history, its read gate cannot be applied -> RED."""
    t = tiered
    _annotate(t, t.refs["c1"])
    _annotate(t, t.refs["d1"])
    r = _review(t)
    states = r.progress.states
    assert ru.disposed(states[t.refs["c1"]]) and ru.disposed(states[t.refs["d1"]])
    # Each read gate applied: the B one's basis was read from run B's own history.
    assert r.report["read_gate_unverifiable"]["count"] == 0


def test_a_unit_id_of_the_earlier_predicate_is_not_this_pairs(tiered: Tiered) -> None:
    """★ v6 moves every unit id: a v5 id of the same unit names no unit now, and a write naming
    it is refused (no silent match).

    MUTATION (verified RED, 1 failed): PREDICATE_VERSION left at v5 -> the old id resolves ->
    RED."""
    t = tiered
    r = _review(t)
    (u,) = [
        x
        for x in _units(r)
        if x.kind == ru.PRESENCE and t.anchor("a_only", EMPTY) in {m.anchor_ref for m in x.members}
    ]
    old = ru.unit_id(u.kind, [m.anchor_ref for m in u.members], "v5")
    assert r.unit(old) is None and r.unit(u.unit_id) is u
    out = _server(t)(
        "annotate_diff",
        {
            "anchor_ref": t.anchor("a_only", EMPTY),
            "verdict": "change_inconclusive",
            "rationale": "r",
            "run_pair": PAIR,
            "unit_id": old,
        },
    )
    assert "in this pair now" in str(out.get("error")), out


# ── the hand-off: a one-sided candidate's block on every face ───────────────────────────────


@pytest.fixture
def small(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Tiered:
    """One binary only B holds: one tier 1 command candidate (its only must-read subject) and a
    tail one — a pair whose must-read set one judgement completes."""
    w = World(tmp_path)
    w.binary("b", TOOL, _sha("4"))
    (d1,) = w.cand("b", TOOL, _sha("4"), "cmd", addr="00501000")
    (d2,) = w.cand("b", TOOL, _sha("4"), "cmd", addr="00501000")
    w.commit()
    bands = {d1: EXEC, d2: TAIL}
    real = sr.band_reason
    monkeypatch.setattr(sr, "band_reason", lambda c: bands.get(c.evidence_ref) or real(c))
    clear_triage_cache()
    return Tiered(w, {"d1": d1, "d2": d2}, bands)


def _judged_small(t: Tiered) -> None:
    """The small pair's must-read set done: its tier 1 candidate judged exploitable (read first),
    and its tail candidate judged suspicious by hand."""
    _annotate(
        t,
        t.refs["d1"],
        "exploitable",
        chain="read_cfg -> build_cmd (0x00501000) -> system",
        verification_gaps=["one", "two"],
    )
    _annotate(t, t.refs["d2"], "suspicious")
    assert _review(t).report["must_read_complete"] is True


# The three faces of a run pair's hand-off, each holding the one-sided candidates' blocks: the
# addition is made once, in review_report.handoff_findings, which all three read.
# MUTATION (verified RED, 3 failed): drop the candidates from handoff_findings -> no block on any
# face, and the driver refuses the agent's texts for an anchor it does not hold -> RED, each.


def test_the_mcp_hand_off_carries_a_one_sided_candidates_block(small: Tiered) -> None:
    """★ A one-sided candidate judged exploitable is a block of get_diff_handoff's pages, awaiting
    human verification; a tail candidate judged by hand is one too (its tier does not take it
    out)."""
    t = small
    _judged_small(t)
    page = _server(t)("get_diff_handoff", {"run_pair": PAIR})
    assert "refused" not in page, page
    text = page["text"]
    for ref in (t.refs["d1"], t.refs["d2"]):
        assert f"## `{ref}`" in text
    assert text.count("- status: awaiting human verification") == 2
    assert "build_cmd (0x00501000)" in text and "2 judged suspicious or exploitable" in text


def test_the_drivers_hand_off_takes_an_agents_texts_for_a_candidate_block(small: Tiered) -> None:
    """★ The driver's document holds the candidate blocks, so an agent's texts naming one are
    composed under it (never refused as an anchor the hand-off does not hold)."""
    from treasure_map.lib import review_driver as rd

    t = small
    _judged_small(t)
    composed = rd.compose_handoff(
        t.w.atlas, PAIR, [("agent", {t.refs["d1"]: {"hypotheses": "h", "device_checks": "d"}})]
    )
    assert isinstance(composed, rd.HandoffComposed), composed
    assert composed.nothing_written == [t.refs["d2"]]


def test_the_command_lines_hand_off_carries_a_candidate_block(
    small: Tiered, tmp_path: Path
) -> None:
    """★ ``tmap review report --handoff`` writes the candidate blocks for a person too."""
    from click.testing import CliRunner

    from treasure_map.cli import review_cli

    t = small
    _judged_small(t)
    out = tmp_path / "h.md"
    res = CliRunner().invoke(
        review_cli.review, ["report", PAIR, "--handoff", "-o", str(out), "--atlas", str(t.w.path)]
    )
    assert res.exit_code == 0, res.output
    assert f"## `{t.refs['d1']}`" in out.read_text()


def test_the_hand_off_digest_moves_when_a_candidate_is_judged_again(small: Tiered) -> None:
    """★ The MCP pages are cached by a digest of the findings: a candidate judged again (another
    rationale) reads differently, so the digest moves and the block is rebuilt.

    MUTATION (verified RED, 1 failed): digest the changed_real findings alone -> RED."""
    t = small
    _annotate(t, t.refs["d1"], "exploitable")
    call = _server(t)
    first = call("get_diff_handoff", {"run_pair": PAIR})
    overlay.upsert_overlay(
        t.w.atlas,
        evidence_ref=t.refs["d1"],
        verdict="exploitable",
        rationale="another reading",
        ctx=overlay.WriteContext(
            channel="mcp",
            read_basis=sr.read_basis_of(
                [{"tool": "explain_candidate", "params": {"evidence_ref": t.refs["d1"]}}],
                t.refs["d1"],
            ),
        ),
    )
    t.w.atlas.commit()
    second = call("get_diff_handoff", {"run_pair": PAIR})
    assert first["findings_digest"] != second["findings_digest"]
    assert "another reading" in second["text"]


# ── the scan review over MCP: its units, its gate and its hand-off ──────────────────────────


def test_start_scan_review_hands_out_tier_1_with_no_candidate_fact_and_the_gate_holds(
    tiered: Tiered,
) -> None:
    """★ start_scan_review hands out a tier 1 unit whose material names its candidates and
    carries no fact of them; a verdict written straight away (nothing explained) reads
    needs_recheck, so the unit comes back and must_read_complete stays false.

    MUTATION (verified RED, 1 failed): let the read gate read every write as fetched -> the write
    disposes the candidate -> RED."""
    t = tiered
    call = _server(t)
    out = call("start_scan_review", {"run_id": "runB"})
    nu = out["next_unit"]
    assert nu["kind"] == ru.SCAN_BAND and nu["must_read"] is True
    assert [c["anchor_ref"] for c in nu["material"]["candidates"]] == [t.refs["d1"]]
    assert "dimensions" not in json.dumps(nu["material"])
    assert out["must_read_complete"] is False
    wrote = call(
        "annotate", {"evidence_ref": t.refs["d1"], "verdict": "suspicious", "rationale": "r"}
    )
    assert wrote.get("written") is True, wrote
    again = call("start_scan_review", {"run_id": "runB"})
    assert again["next_unit"] is not None, again
    assert again["next_unit"]["unit_id"] == nu["unit_id"]
    assert again["must_read_complete"] is False


def test_the_scan_hand_off_is_refused_until_tier_1_is_done_then_carries_blocks_and_open_items(
    tiered: Tiered,
) -> None:
    """★ get_scan_handoff is refused (must_read_incomplete, saying what is left) until tier 1 is
    done; then it serves a header of counts, one block per candidate judged suspicious or
    exploitable, and the tier 1 candidates judged inconclusive as open items — and an inconclusive
    tier 1 still reads must_read_complete true, which disposed_by_verdict and the open items make
    visible.

    MUTATION (verified RED, 1 failed each): serve the hand-off ungated -> RED; leave the open
    items out -> RED."""
    t = tiered
    call = _server(t)
    refused = call("get_scan_handoff", {"run_id": "runA"})
    assert refused.get("refused") == "must_read_incomplete", refused
    assert refused["left"]["tier_1_undisposed"] == 3
    _annotate(t, t.refs["c1"], "inconclusive")
    _annotate(t, t.refs["c5"], "inconclusive")
    _annotate(t, t.refs["f1"], "exploitable")
    _annotate(t, t.refs["c3"], "suspicious")  # a tail candidate judged by hand
    head = call("start_scan_review", {"run_id": "runA"})
    assert head["must_read_complete"] is True and head["next_unit"] is None
    t1 = head["declaration"]["tier_1"]
    assert t1["disposed_by_verdict"]["inconclusive"] == 2
    page = call("get_scan_handoff", {"run_id": "runA"})
    assert "refused" not in page, page
    assert (page["findings"], page["open_items"]) == (2, 2)
    text = page["text"]
    assert f"## `{t.refs['f1']}`" in text and f"## `{t.refs['c3']}`" in text
    assert f"## open item: `{t.refs['c1']}`" in text
    assert text.count("- status: awaiting human verification") == 2
    assert "vulnerab" not in text.lower()
