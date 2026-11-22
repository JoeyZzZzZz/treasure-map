# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The changed-row citation gate on a function_pair entry (lib/query/review_units
``entry_citations_short``): a ``changed_real`` on a must-read entry is disposed only when its
``evidence`` cites the rows the change LANDED on — the rows whose landing is not ``persisted`` —
up to ``MAX_CITED`` of them.

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
