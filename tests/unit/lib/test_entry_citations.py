# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The changed-row citation gate on a diff entry (lib/query/review_units
``entry_citations_short``): a ``changed_real`` on a must-read entry — function_pair or
function_presence — is disposed only when its ``evidence`` cites the rows the change LANDED on —
the rows whose landing is not ``persisted`` — up to ``MAX_CITED`` of them.

The gate's scope is ONE predicate (``entry_citation_applies``), read by the report that holds a
judgement back and by the MCP write that says what it owes; the last section here pins the two to
the same set of anchors.

Zero real data: test_diff_review's World (two diffs of one run pair), synthetic addresses and
candidate refs throughout.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tests.unit.lib.test_diff_review import DX, World, _pair_anchor, _ref, _row
from treasure_map.lib.query import diff_review as dr
from treasure_map.lib.query import review_units as ru

A1, B1 = "00001000", "00001100"
A2, B2 = "00002000", "00002100"


def _review(w: World) -> Any:
    return ru.review_pair(
        w.atlas,
        "runA",
        "runB",
        pair_staleness={"source_stale": False, "source_stale_reason": None},
        server_commit=None,
    )


def _landed(func_a: str, at: str) -> Any:
    """A row that LANDS (bucket A: the matched call now calls another callee)."""
    return _row(
        _ref("runA", func_a, at),
        None,
        reason="present_different_callee",
        call="present_different_callee",
        elsewhere=False,
    )


def _persisted(func_a: str, at: str) -> Any:
    """A row that landed nowhere: no change seen at that candidate."""
    return _row(_ref("runA", func_a, at), _ref("runB", func_a, at), presence="persisted")


def _world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rows: list[Any]) -> World:
    w = World(tmp_path, monkeypatch)
    w.pair(DX, A1, B1, conf=0.97, sim=0.8)
    w.rows[DX] = rows
    return w


def _judge(w: World, anchor: str, evidence: list[str] | None = None) -> None:
    basis = {"evidence": evidence} if evidence is not None else None
    w.judge(DX, anchor, "changed_real", verdict_basis=basis)


def _built(w: World) -> Any:
    from treasure_map.lib.query import patch_view as pv

    built = pv.build_diff_view(w.atlas, DX)
    assert built is not None
    return built


# ── rule E-1: the landed rows are the denominator ───────────────────────────────────────────


def test_a_changed_real_citing_none_of_its_landed_rows_reads_needs_recheck(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ E-1: a changed_real on a must-read entry whose two rows landed, citing neither of them,
    is written but reads needs_recheck and is named in ``entry_citations_short``; citing both
    disposes it.

    MUTATION (verified RED, ``1 failed``): never flip the state (drop the entry_citations_short
    loop in review_pair) -> RED; count the gate satisfied at zero citations -> RED."""
    r1, r2 = _landed(A1, "0x10"), _landed(A1, "0x20")
    w = _world(tmp_path, monkeypatch, [r1, r2])
    anchor = _pair_anchor(DX, A1, B1)
    _judge(w, anchor, [anchor, "the two call sites moved"])
    rev = _review(w)
    assert rev.progress.states.get(anchor) == "needs_recheck"
    gap = rev.report["entry_citations_short"].get(anchor)
    assert gap is not None
    assert (gap["required"], gap["cited"], gap["owed"], gap["uncited"]) == (2, 0, 2, 2)
    assert gap["missing_sample"] == [r1.a_ref, r2.a_ref] or gap["missing_sample"] == [
        r2.a_ref,
        r1.a_ref,
    ]
    _judge(w, anchor, [r1.a_ref, r2.a_ref])
    whole = _review(w)
    assert ru.disposed(whole.progress.states.get(anchor))
    assert anchor not in whole.report["entry_citations_short"]


def test_a_row_is_cited_by_either_of_its_refs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ E-1: a landed row counts as cited by either spelling a row_ref takes — its a_ref or its
    b_ref — so a judgement that cites the B side of the row satisfies the gate.

    MUTATION (verified RED, ``1 failed``): read the a_ref alone -> RED."""
    row = _row(
        _ref("runA", A1, "0x10"),
        _ref("runB", B1, "0x10"),
        reason="present_different_callee",
        call="present_different_callee",
        elsewhere=False,
    )
    w = _world(tmp_path, monkeypatch, [row])
    anchor = _pair_anchor(DX, A1, B1)
    _judge(w, anchor, [row.b_ref])
    assert ru.disposed(_review(w).progress.states.get(anchor))


def test_an_entry_whose_rows_all_persisted_owes_no_citation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ E-4: an entry all of whose rows are ``persisted`` — the change lands on no candidate row,
    which is legitimate — is not held to the gate: a changed_real with no citation at all is
    disposed, and the entry is named nowhere in the gate's report.

    MUTATION (verified RED, ``1 failed``): count every row, persisted ones included, as owed ->
    the entry owes 2 citations -> RED."""
    w = _world(tmp_path, monkeypatch, [_persisted(A1, "0x10"), _persisted(A1, "0x20")])
    w.atlas.execute(
        "UPDATE function_alignment SET similarity = 0.8 WHERE diff_id = ? AND addr_a = ?",
        (DX, A1),
    )
    w.atlas.commit()
    anchor = _pair_anchor(DX, A1, B1)
    _judge(w, anchor, [anchor, "the function body changed, at no candidate"])
    rev = _review(w)
    assert ru.disposed(rev.progress.states.get(anchor))
    assert anchor not in rev.report["entry_citations_short"]


def test_only_the_landed_rows_are_owed_not_the_persisted_ones_beside_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ E-1 (the denominator, with teeth): an entry holding one landed row and two persisted ones
    owes exactly the landed one — citing it alone disposes the judgement.

    MUTATION (verified RED, ``1 failed``): make the denominator every row of the entry -> the two
    persisted rows are owed too and the judgement reads needs_recheck -> RED; make it the rows of
    the entry's danger band -> RED."""
    landed = _landed(A1, "0x10")
    w = _world(tmp_path, monkeypatch, [landed, _persisted(A1, "0x20"), _persisted(A1, "0x30")])
    anchor = _pair_anchor(DX, A1, B1)
    # The fixture's premise: the entry really does hold three rows, two of them persisted.
    e = w.entry(f"pair:{A1}:{B1}")
    assert len(e["rows"]) == 3
    assert sum(1 for r in e["rows"] if r["landing"] == "persisted") == 2
    _judge(w, anchor, [landed.a_ref])
    rev = _review(w)
    assert ru.disposed(rev.progress.states.get(anchor))
    assert anchor not in rev.report["entry_citations_short"]


# ── rule E-5: the cap ───────────────────────────────────────────────────────────────────────


def test_over_the_cap_the_judgement_owes_max_cited_and_the_rest_is_counted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ E-5: an entry with more landed rows than ``MAX_CITED`` owes that many — citing 20 of its
    25 rows disposes it — and how many landed rows carry no citation is counted for the hand-off
    (``uncited`` per entry, ``entry_citations_uncited`` over the pair), never required.

    MUTATION (verified RED, ``1 failed``): owe every landed row (drop the MAX_CITED cap) -> citing
    20 of 25 reads needs_recheck -> RED."""
    rows = [_landed(A1, f"0x{i * 4:x}") for i in range(25)]
    w = _world(tmp_path, monkeypatch, rows)
    anchor = _pair_anchor(DX, A1, B1)
    _judge(w, anchor, [r.a_ref for r in rows[:19]])
    short = _review(w)
    assert short.progress.states.get(anchor) == "needs_recheck"
    assert short.report["entry_citations_short"][anchor]["owed"] == ru.MAX_CITED
    _judge(w, anchor, [r.a_ref for r in rows[: ru.MAX_CITED]])
    rev = _review(w)
    assert ru.disposed(rev.progress.states.get(anchor))
    assert anchor not in rev.report["entry_citations_short"]
    built = _review(w)
    e = next(x for x in _built(w).placed if x.entry_id == f"pair:{A1}:{B1}")
    gap = ru.entry_citation_gap(e, {"evidence": [r.a_ref for r in rows[: ru.MAX_CITED]]})
    assert gap is not None
    assert (gap["required"], gap["cited"], gap["uncited"]) == (25, ru.MAX_CITED, 5)
    assert built.report["entry_citations_uncited"] == 0  # it is disposed: nothing is owed


# ── rule E-4 / E-6: what the gate does not touch ────────────────────────────────────────────


def test_the_gate_holds_changed_real_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """★ E-4: only ``changed_real`` is held to this gate. A no_real_change on the same entry, whose
    ``checked`` cites none of the landed rows, is disposed by its own rules.

    MUTATION (verified RED, ``1 failed``): read every verdict here -> the no_real_change reads
    needs_recheck -> RED."""
    w = _world(tmp_path, monkeypatch, [_landed(A1, "0x10"), _landed(A1, "0x20")])
    anchor = _pair_anchor(DX, A1, B1)
    w.judge(
        DX,
        anchor,
        "no_real_change",
        verdict_basis={"checked": [anchor], "why_unchanged": "a renamed wrapper, same call"},
    )
    rev = _review(w)
    assert ru.disposed(rev.progress.states.get(anchor))
    assert rev.report["entry_citations_short"] == {}


# ── rule E-2: the stored rows keep their shape ──────────────────────────────────────────────


def test_the_stored_rows_keep_their_five_element_shape_with_presence_third(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ E-2: ``entry_facts.rows`` is unchanged by this gate — every element is the same five-part
    row with ``presence`` third, which is what lets the gate be read from a stored basis, and what
    keeps ``facts_delta`` quiet on an existing judgement (no mass needs_recheck on deployment).

    MUTATION (verified RED, ``1 failed``): store a row as a 3-tuple or a 6-tuple -> RED; move
    presence off index 2 -> RED."""
    from treasure_map.lib.query import patch_view as pv

    landed = _landed(A1, "0x10")
    w = _world(tmp_path, monkeypatch, [landed, _persisted(A1, "0x20")])
    built = pv.build_diff_view(w.atlas, DX)
    assert built is not None
    e = next(x for x in built.placed if x.entry_id == f"pair:{A1}:{B1}")
    facts = dr.entry_facts(e)
    assert all(len(r) == 5 for r in facts["rows"]), facts["rows"]
    assert {r[2] for r in facts["rows"]} == {"presence_undetermined", "persisted"}
    # landing == persisted is exactly presence == persisted (the gate's one assumption).
    for row, view in zip(e.rows, e.row_views, strict=True):
        assert (view["landing"] == "persisted") == (row.presence == "persisted")
    # An existing judgement's basis does not move: the facts read the same twice.
    anchor = _pair_anchor(DX, A1, B1)
    _judge(w, anchor, [landed.a_ref])
    again = pv.build_diff_view(w.atlas, DX)
    assert again is not None
    e2 = next(x for x in again.placed if x.entry_id == f"pair:{A1}:{B1}")
    assert dr.facts_delta(facts, dr.entry_facts(e2)) == {}


def test_the_coverage_statement_states_the_gate_and_the_uncited_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ E-5: the one-line coverage statement — the sentence a review quotes verbatim — carries how
    many judgements the gate holds and how many landed rows carry no citation at all, so an
    over-cap entry's unread rows are stated rather than silently forgiven.

    MUTATION (verified RED, ``1 failed``): leave the segment out of the statement -> RED."""
    rows = [_landed(A1, f"0x{i * 4:x}") for i in range(25)]
    w = _world(tmp_path, monkeypatch, rows)
    anchor = _pair_anchor(DX, A1, B1)
    _judge(w, anchor, [anchor, "the call sites moved"])
    rev = _review(w)
    assert "entry citations short 1 (landed rows uncited 25);" in rev.report["coverage_statement"]


def test_the_write_answers_with_what_it_still_has_to_cite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ E-1: a changed_real write that cites too few of its landed rows gets back what it owes
    (``row_citations`` with ``missing_sample``, and ``row_citations_short`` saying what it reads
    as), so the next write can name them — without this the gate would hand the unit back with
    nothing to act on, and the loop would never converge.

    MUTATION (verified RED, ``1 failed``): leave the fields off the write's answer -> RED."""
    from treasure_map import mcp_app

    r1, r2 = _landed(A1, "0x10"), _landed(A1, "0x20")
    w = _world(tmp_path, monkeypatch, [r1, r2])
    anchor = _pair_anchor(DX, A1, B1)
    tools = mcp_app.make_tools(w.path)
    short = tools["annotate_diff"](anchor, "changed_real", "read it", diff_id=DX, evidence=[anchor])
    assert short["written"] is True, short
    assert "row_citations" in short, sorted(short)
    assert short["row_citations"]["owed"] == 2
    assert short["row_citations"]["cited"] == 0
    assert sorted(short["row_citations"]["missing_sample"]) == sorted([r1.a_ref, r2.a_ref])
    assert "needs_recheck" in short["row_citations_short"]
    whole = tools["annotate_diff"](
        anchor, "changed_real", "read it", diff_id=DX, evidence=[anchor, r1.a_ref, r2.a_ref]
    )
    assert whole["row_citations"] == {
        "required": 2,
        "cited": 2,
        "owed": 2,
        "uncited": 0,
        "missing_sample": [],
    }
    assert "row_citations_short" not in whole


# ── the same gate on a function only one side holds ─────────────────────────────────────────

# A function the B side holds alone (added) and one the A side holds alone (removed): their rows
# all land, ``landing`` P, so a changed_real owes every one of them.
ADDED, REMOVED, BARE = "00003000", "00004000", "00006000"
# A pair the predicate does NOT hold: listed, with a landed row, and second tier (attention 1 on a
# same-callee B row, no lift_basis) — so ``must_read`` is False.
A3, B3 = "00005000", "00005100"


def _one_sided(side: str, func: str, at: str) -> Any:
    """A candidate row of a function with no counterpart, on that function's side only."""
    ref = _ref("runA" if side == "a" else "runB", func, at)
    return _row(
        ref if side == "a" else None,
        None if side == "a" else ref,
        reason="function_unmatched",
        conf=None,
    )


def _mixed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[World, dict[str, Any]]:
    """One diff holding, side by side, every entry the gate has to tell apart — a must-read pair
    with a landed row, a second-tier pair with one, a one-sided function on each side with landed
    rows, and a one-sided function with no candidate row at all. One fixture, so the report's
    scope and the write's are compared over the same five subjects.

    Returns the world and the rows by name, for citing them."""
    w = World(tmp_path, monkeypatch)
    w.pair(DX, A1, B1, conf=0.97, sim=0.8)  # bucket A -> attention 0 -> must-read
    w.pair(DX, A3, B3, conf=0.97, sim=0.5)
    for side, func in (("b", ADDED), ("a", REMOVED), ("b", BARE)):
        w.unpaired(DX, side, func, "unmatched_analysis_complete")
    rows = {
        "must_read_pair": _landed(A1, "0x10"),
        "second_tier_pair": _row(
            _ref("runA", A3, "0x10"), _ref("runB", B3, "0x10"), reason="counterpart_same_callee"
        ),
        "added_1": _one_sided("b", ADDED, "0x20"),
        "added_2": _one_sided("b", ADDED, "0x24"),
        "removed": _one_sided("a", REMOVED, "0x30"),
    }
    w.rows[DX] = list(rows.values())
    return w, rows


def _presence_anchor(side: str, func: str) -> str:
    return dr.presence_anchor("runA", "runB", "libx", side, func)


def _members(w: World) -> dict[str, Any]:
    return {m.entry_id: m for m in ru.diff_facts(w.atlas, DX).entries}


def test_a_changed_real_on_an_added_function_cites_every_row_it_landed_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ the extended scope: a function only the B side holds is a must-read entry (``p_entry``)
    whose rows all land, so a changed_real citing one of its two reads needs_recheck and is named
    in ``entry_citations_short`` with the uncited ref; citing both disposes it.

    The reason the gate skipped these — "a function_presence subject has no row list of this
    shape" — is not true of them: they have rows, and every one of them lands.

    MUTATION (verified RED, ``1 failed``): put the ``pair:`` prefix test back in the predicate ->
    the judgement reads disposed uncited -> RED."""
    w, rows = _mixed(tmp_path, monkeypatch)
    anchor = _presence_anchor("b", ADDED)
    m = _members(w)[f"b:{ADDED}"]
    assert (m.kind, m.must_read, m.reasons, m.rows) == ("entry", True, ("p_entry",), 2)
    assert ru.entry_citation_applies(m)

    _judge(w, anchor, [rows["added_1"].b_ref])
    rev = _review(w)
    assert rev.progress.states.get(anchor) == "needs_recheck"
    gap = rev.report["entry_citations_short"].get(anchor)
    assert gap is not None
    assert (gap["required"], gap["cited"], gap["owed"]) == (2, 1, 2)
    assert gap["missing_sample"] == [rows["added_2"].b_ref]

    _judge(w, anchor, [rows["added_1"].b_ref, rows["added_2"].b_ref])
    whole = _review(w)
    assert ru.disposed(whole.progress.states.get(anchor))
    assert anchor not in whole.report["entry_citations_short"]


def test_a_removed_functions_row_is_cited_by_its_a_ref(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ the other side of it: a function only the A side holds carries its rows on the A side, so
    the citation names the ``a_ref``. One gate, both directions — the row is cited by either of
    its refs and a one-sided row has only one.

    MUTATION (verified RED, ``1 failed``): read the b_ref alone -> RED."""
    w, rows = _mixed(tmp_path, monkeypatch)
    anchor = _presence_anchor("a", REMOVED)
    assert rows["removed"].b_ref is None  # fixture premise: there is no b_ref to cite
    _judge(w, anchor, [anchor, "the function is gone"])
    assert _review(w).report["entry_citations_short"].get(anchor) is not None
    _judge(w, anchor, [rows["removed"].a_ref])
    rev = _review(w)
    assert ru.disposed(rev.progress.states.get(anchor))
    assert anchor not in rev.report["entry_citations_short"]


def test_the_gate_on_a_one_sided_function_holds_changed_real_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ scope, not severity: the extended gate keeps the changed_real-only rule. A
    no_real_change and a change_inconclusive on a one-sided function, citing none of its rows, are
    disposed by their own rules.

    MUTATION (verified RED, ``1 failed``): hold every verdict -> both read needs_recheck -> RED."""
    w, _rows = _mixed(tmp_path, monkeypatch)
    anchor = _presence_anchor("b", ADDED)
    w.judge(
        DX,
        anchor,
        "no_real_change",
        verdict_basis={"checked": [anchor], "why_unchanged": "a renamed wrapper, same call"},
    )
    rev = _review(w)
    assert ru.disposed(rev.progress.states.get(anchor))
    assert anchor not in rev.report["entry_citations_short"]
    w.judge(DX, anchor, "change_inconclusive")
    again = _review(w)
    assert anchor not in again.report["entry_citations_short"]


def test_a_one_sided_function_with_no_candidate_row_owes_no_citation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ the denominator is the LANDED rows, so a one-sided function holding no candidate row at
    all owes nothing — a changed_real on it is disposed with no citation. The predicate holds it
    (it is must-read); the gap is what says nothing is owed.

    MUTATION (verified RED, ``1 failed``): owe a citation whenever the predicate holds -> RED."""
    w, _rows = _mixed(tmp_path, monkeypatch)
    anchor = _presence_anchor("b", BARE)
    assert _members(w)[f"b:{BARE}"].rows == 0  # fixture premise
    assert ru.entry_citation_applies(_members(w)[f"b:{BARE}"])
    _judge(w, anchor, [anchor, "a new function, at no candidate"])
    rev = _review(w)
    assert ru.disposed(rev.progress.states.get(anchor))
    assert anchor not in rev.report["entry_citations_short"]


def test_a_second_tier_entry_with_a_landed_row_is_not_held(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ ``must_read`` stays in the predicate: a listed pair that is second tier — nobody was asked
    to read it — owes no row citation even with a landed row, on either path. Dropping that test
    would hold back hundreds of judgements on entries the review never handed out.

    MUTATION (verified RED, ``1 failed``): drop ``must_read`` from the predicate -> RED."""
    w, _rows = _mixed(tmp_path, monkeypatch)
    anchor = _pair_anchor(DX, A3, B3)
    m = _members(w)[f"pair:{A3}:{B3}"]
    assert (m.must_read, m.reasons, m.rows) == (False, (), 1)  # fixture premise
    assert not ru.entry_citation_applies(m)
    _judge(w, anchor, [anchor, "read it, the call is the same"])
    rev = _review(w)
    assert ru.disposed(rev.progress.states.get(anchor))
    assert anchor not in rev.report["entry_citations_short"]


def test_the_write_answers_short_on_exactly_what_the_report_holds_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ ONE predicate, two paths: over a fixture holding all five entry shapes, the anchors the
    MCP write answers ``row_citations_short`` on are exactly the anchors the report holds back —
    a must-read pair and the two one-sided functions with rows, and neither the second-tier pair
    nor the one-sided function without rows. Two spellings of this question is how a write comes
    back claiming needs_recheck on an entry the review reads as disposed.

    The report is read first, off judgements written straight onto the overlay; the MCP writes
    follow, each carrying the same under-citing basis.

    MUTATION (verified RED, ``1 failed``): the write path not going through
    ``entry_citation_applies`` -> the second-tier pair answers short, the sets differ -> RED; the
    ``pair:`` prefix test back in the predicate -> the report holds neither one-sided entry -> RED.
    """
    from treasure_map import mcp_app

    w, _rows = _mixed(tmp_path, monkeypatch)
    anchors = {
        "must_read_pair": _pair_anchor(DX, A1, B1),
        "second_tier_pair": _pair_anchor(DX, A3, B3),
        "added": _presence_anchor("b", ADDED),
        "removed": _presence_anchor("a", REMOVED),
        "bare": _presence_anchor("b", BARE),
    }
    for anchor in anchors.values():
        _judge(w, anchor, [anchor, "read it"])  # cites the subject, none of its rows
    held = set(_review(w).report["entry_citations_short"])

    tools = mcp_app.make_tools(w.path)
    answered = set()
    for anchor in anchors.values():
        res = tools["annotate_diff"](
            anchor, "changed_real", "read it", diff_id=DX, evidence=[anchor]
        )
        assert res["written"] is True, res
        if "row_citations_short" in res:
            answered.add(anchor)

    assert held == answered
    assert held == {anchors["must_read_pair"], anchors["added"], anchors["removed"]}


def test_a_write_naming_its_unit_reads_the_gate_off_the_review_it_already_paid_for(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ the write reads the predicate's member from TWO sources — the pair review a unit-naming
    write already computed, and the one diff a write that names no unit reads on its own — and
    both have to answer the same. Here the first: a write naming the unit of a one-sided function
    answers the same ``row_citations`` as the write without one above.

    The two sources are EQUIVALENT by design, so swapping which one is read is not a red; what has
    teeth is a source that answers nothing (then the gate silently stops applying) — verified RED
    by making the review branch return None: the short goes missing: 1 failed."""
    from treasure_map import mcp_app

    w, rows = _mixed(tmp_path, monkeypatch)
    anchor = _presence_anchor("b", ADDED)
    unit = next(u for u in _review(w).units if any(m.anchor_ref == anchor for m in u.members))
    tools = mcp_app.make_tools(w.path)
    res = tools["annotate_diff"](
        anchor,
        "changed_real",
        "read it",
        diff_id=DX,
        evidence=[rows["added_1"].b_ref],
        unit_id=unit.unit_id,
    )
    assert res["written"] is True, res
    assert res["row_citations"]["owed"] == 2
    assert res["row_citations"]["cited"] == 1
    assert res["row_citations"]["missing_sample"] == [rows["added_2"].b_ref]
    assert "needs_recheck" in res["row_citations_short"]
