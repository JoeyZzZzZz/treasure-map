# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Pairing-correction components (lib/query/pairing_components): the alternative pairings two
pair entries read on each other, read as alternative entries of their own and handed out as one
unit — the diff's pairs, buckets, counts and order unchanged.

Zero real data: test_patch_view's World (one diff of ``libx``); dispatch keys (one handler a side)
make the ``key`` claims, unique strings the ``string`` ones. A shifted chain, a 2-cycle and a
3-cycle; every address, name and body is synthetic.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tests.unit.lib.test_pair_evidence import _fresh, _key, _string  # noqa: F401 — autouse
from tests.unit.lib.test_patch_view import DIFF, World, _pair_id, _ref
from treasure_map import mcp_app
from treasure_map.lib import overlay
from treasure_map.lib.errors import ConfigError
from treasure_map.lib.query import diff_annotations as da
from treasure_map.lib.query import diff_review as dr
from treasure_map.lib.query import pairing_components as pc
from treasure_map.lib.query import patch_view as pv
from treasure_map.lib.query import review_report as rr
from treasure_map.lib.query import review_units as ru

PAIR = "runA::runB"
# Three aligned pairs (a_i, b_i), each low similarity (listed, bucket C).
A1, B1 = "00001000", "00001100"
A2, B2 = "00002000", "00002100"
A3, B3 = "00003000", "00003100"
P_B = "00009100"  # a function in no pair on B


@pytest.fixture(autouse=True)
def _clear_unit_cache() -> None:
    ru.DIFF_CACHE.clear()


def _body(addr: str, *stmts: str) -> str:
    lines = [f"void FUN_{addr}(int param_1)", "{", *(f"  {s};" for s in stmts), "  return;", "}"]
    return "\n".join(lines)


def _stmts(tag: str, n: int = 3) -> list[str]:
    return [f'puts("{tag} step {i}")' for i in range(n)]


def _world(tmp_path: Path, pairs: int = 3, *, texts: dict[str, list[str]] | None = None) -> World:
    """``pairs`` aligned pairs (a_i, b_i) at similarity 0.6, each function with a body of its own
    (``texts`` overrides one by address)."""
    w = World(tmp_path)
    texts = texts or {}
    for a, b in ((A1, B1), (A2, B2), (A3, B3))[:pairs]:
        w.pair(a, b, 0.97, 0.6)
        w.fn("a", a, [], pseudocode=_body(a, *texts.get(a, _stmts(f"a {a}"))))
        w.fn("b", b, [], pseudocode=_body(b, *texts.get(b, _stmts(f"b {b}"))))
    return w


def _claim(w: World, a: str, b: str, key: str | None = None) -> None:
    """A dispatch key with one handler on each side: ``a`` on A, ``b`` on B."""
    k = key or f"key_{a}_{b}"
    _key(w, "a", k, a)
    _key(w, "b", k, b)


def _corr(w: World) -> tuple[tuple[pc.Component, ...], tuple[Any, ...]]:
    w.commit()
    built = pv.build_diff_view(w.atlas, DIFF)
    assert built is not None
    return pc.corrections(w.atlas, built)


def _drill(w: World, entry_id: str) -> dict[str, Any]:
    w.commit()
    page = pv.get_diff_patch_view(w.atlas, DIFF, entry_id=entry_id)
    assert "error" not in page, page
    (entry,) = page["entries"]
    return dict(entry)


def _review(w: World, k: int = 0) -> ru.PairReview:
    w.commit()
    return ru.review_pair(
        w.atlas, "runA", "runB", k=k, pair_staleness={"source_stale": False}, server_commit="c0"
    )


def _anchor(a: str, b: str) -> str:
    return dr.pair_anchor("runA", "runB", "libx", a, b)


def _units(r: ru.PairReview, kind: str) -> list[ru.Unit]:
    return [u for u in r.units if u.kind == kind]


def _ids(u: ru.Unit) -> list[str | None]:
    return [m.entry_id for m in u.members]


# ── rule 1 / rule 2: claims and their gate ─────────────────────────────────────────────────


def test_a_key_between_two_pair_entries_is_one_claim_read_from_both_ends(tmp_path: Path) -> None:
    """★ rule 1: a key pairing a1 with b2 (another pair entry's B function) is the claim (a1, b2),
    re-pairing (a1, b1) and (a2, b2); read from both ends (a1's to_b, b2's to_a), it is ONE claim
    with both readings. A key pointing at a function in no pair claims nothing, and is still shown
    as the entry's alternative pairing.

    MUTATION (verified RED, ``1 failed``): keep only the first end's reading of a claim -> one
    item -> RED."""
    w = _world(tmp_path, 2)
    w.fn("b", P_B, [], pseudocode=_body(P_B, *_stmts("p")))
    w.unpaired("b", P_B, "absent")
    _claim(w, A1, B2)
    _claim(w, A2, P_B)
    comps, _alts = _corr(w)
    (comp,) = comps
    (claim,) = comp.claims
    assert (claim.addr_a, claim.addr_b) == (A1, B2)
    assert claim.re_pairs == (_pair_id(A1, B1), _pair_id(A2, B2))
    assert claim.vias == ("key",)
    assert sorted((i["read_on"], i["direction"]) for i in claim.items) == [
        (_pair_id(A1, B1), "to_b"),
        (_pair_id(A2, B2), "to_a"),
    ]
    shown = _drill(w, _pair_id(A2, B2)).get("alt_pairings") or []
    assert ("key", "to_b", P_B) in [(i["via"], i["direction"], i["target_addr"]) for i in shown]


def _string_claim_world(tmp_path: Path, alt_like_a1: bool) -> World:
    """a1's five unique strings are b2's (a string-only claim). The current pairings read
    alike (each pair's two bodies share most lines); the alternative (a1, b2) reads like them
    (``alt_like_a1``) or not at all."""
    shared1, shared2 = _stmts("one", 6), _stmts("two", 6)
    texts = {A1: shared1, B1: [*shared1, "sleep(1)"], A2: shared2, B2: [*shared2, "sleep(2)"]}
    if alt_like_a1:
        texts[B2] = [*shared1, "sleep(3)"]
        texts[A2] = [*shared1, "sleep(4)"]
    w = _world(tmp_path, 2, texts=texts)
    for i in range(5):
        _string(w, "a", f"shared value {i}", A1)
        _string(w, "b", f"shared value {i}", B2)
    return w


@pytest.mark.parametrize("alt_like_a1", [True, False])
def test_a_string_only_claim_stands_only_above_the_lower_current_ratio(
    tmp_path: Path, alt_like_a1: bool
) -> None:
    """★ rule 2: a string-only claim stands when the alternative's text ratio is above the lower of
    the two current pairings' ratios, and not otherwise.

    MUTATION (verified RED, ``1 failed`` each): let every string-only claim stand -> the False
    case -> RED; compare against the higher ratio -> the True case -> RED."""
    w = _string_claim_world(tmp_path, alt_like_a1)
    comps, _alts = _corr(w)
    built = pv.build_diff_view(w.atlas, DIFF)
    assert built is not None
    readings = pv._pseudo_readings(w.atlas, built)
    alt = pv._text_ratio(built, readings, A1, B2)
    lower = min(
        pv._text_ratio(built, readings, A1, B1) or 0, pv._text_ratio(built, readings, A2, B2) or 0
    )
    assert alt is not None and (alt > lower) is alt_like_a1  # the fixture splits the two cases
    assert bool(comps) is alt_like_a1


def test_a_key_claim_stands_whatever_the_texts_read(tmp_path: Path) -> None:
    """★ rule 2: a key reading needs no text: its alternative (a2, b1) reads less alike than both
    current pairings, every text readable, and it stands.

    MUTATION (verified RED, ``1 failed``): gate key claims on the ratio too -> RED."""
    w = _string_claim_world(tmp_path, alt_like_a1=False)
    _claim(w, A2, B1)
    comps, _alts = _corr(w)
    built = pv.build_diff_view(w.atlas, DIFF)
    assert built is not None
    readings = pv._pseudo_readings(w.atlas, built)
    alt = pv._text_ratio(built, readings, A2, B1)
    cur = [pv._text_ratio(built, readings, a, b) for a, b in ((A1, B1), (A2, B2))]
    assert alt is not None and None not in cur and alt < min(c for c in cur if c is not None)
    got = {(c.addr_a, c.addr_b): c.vias for comp in comps for c in comp.claims}
    assert got.get((A2, B1)) == ("key",)


def test_a_string_only_claim_with_an_unreadable_text_stands(tmp_path: Path) -> None:
    """★ rule 2: a string-only claim one of whose three texts cannot be read stands.

    MUTATION (verified RED, ``1 failed``): reject a string-only claim with an unreadable text ->
    RED."""
    w = _string_claim_world(tmp_path, alt_like_a1=False)
    w.adb["b"].execute("UPDATE functions SET pseudocode = NULL WHERE address = ?", (B2,))
    comps, _alts = _corr(w)
    got = {(c.addr_a, c.addr_b): c.vias for comp in comps for c in comp.claims}
    assert got.get((A1, B2)) == ("string",)


# ── rule 4 / rule 5: components, supersession, ends ─────────────────────────────────────────


def test_a_shifted_chain_supersedes_its_middle_and_names_its_two_ends(tmp_path: Path) -> None:
    """★ rule 4/5: claims (a1, b2) and (a2, b3) make one component of the three entries; the middle
    one (both functions covered by key claims) is superseded, the two ends are not, and the
    functions no claim covers are its ends.

    MUTATION (verified RED, ``1 failed``): supersede every member -> RED; leave the ends out ->
    RED."""
    w = _world(tmp_path)
    _claim(w, A1, B2)
    _claim(w, A2, B3)
    (comp,), alts = _corr(w)
    assert comp.entries == (_pair_id(A1, B1), _pair_id(A2, B2), _pair_id(A3, B3))
    assert [c.entry_id for c in comp.claims] == [_pair_id(A1, B2), _pair_id(A2, B3)]
    assert comp.superseded == (_pair_id(A2, B2),)
    assert comp.ends == (("a", A3), ("b", B1))
    assert not comp.conflict
    assert [e.entry_id for e in alts] == [_pair_id(A1, B2), _pair_id(A2, B3)]


@pytest.mark.parametrize("cycle", [2, 3])
def test_a_cycle_supersedes_every_member(tmp_path: Path, cycle: int) -> None:
    """★ rule 4/5: a 2-cycle (a1 <-> b2, a2 <-> b1) and a 3-cycle (a1 -> b2 -> ... -> b1) cover
    every member's two functions: every member superseded, no end.

    MUTATION (verified RED, ``1 failed`` each): require a member's two functions in ONE claim ->
    RED."""
    w = _world(tmp_path, cycle)
    a, b = [A1, A2, A3][:cycle], [B1, B2, B3][:cycle]
    for i in range(cycle):
        _claim(w, a[i], b[(i + 1) % cycle])
    (comp,), _alts = _corr(w)
    assert len(comp.claims) == cycle
    assert comp.superseded == comp.entries and len(comp.entries) == cycle
    assert comp.ends == ()


def test_a_conflict_supersedes_nothing(tmp_path: Path) -> None:
    """★ rule 5: a1 claimed with b2 AND with b3 (two keys): a conflict, and no member is
    superseded although some are covered.

    MUTATION (verified RED, ``1 failed``): ignore the conflict -> RED."""
    w = _world(tmp_path)
    _claim(w, A1, B2)
    _claim(w, A1, B3)
    _claim(w, A2, B1)
    _claim(w, A3, B1, key="key_three_one")
    (comp,), _alts = _corr(w)
    assert comp.conflict is True
    assert comp.superseded == ()


def test_an_entry_a_string_claim_alone_covers_is_not_superseded(tmp_path: Path) -> None:
    """★ rule 5: a 2-cycle whose one claim is string-only: neither member is superseded (a member
    is superseded only when key or twin claims cover both its functions).

    MUTATION (verified RED, ``1 failed``): count a string claim as cover -> RED."""
    w = _string_claim_world(tmp_path, alt_like_a1=True)
    _claim(w, A2, B1)
    (comp,), _alts = _corr(w)
    assert {c.vias for c in comp.claims} == {("string",), ("key",)}
    assert comp.superseded == ()


# ── rule 6 / rule 7: the alternative entry and its rows ─────────────────────────────────────


def _cycle_with_rows(tmp_path: Path) -> World:
    """A 2-cycle; a1 holds a command candidate, b2 two."""
    w = _world(tmp_path, 2)
    _claim(w, A1, B2)
    _claim(w, A2, B1)
    w.inst("a", _ref("runA", A1, "cmd", "0x10"), "cmd", "system")
    w.inst("b", _ref("runB", B2, "cmd", "0x10"), "cmd", "system")
    w.inst("b", _ref("runB", B2, "cmd", "0x20"), "cmd", "popen")
    w.commit()
    return w


def test_an_alternative_entry_reads_like_an_aligned_pair_without_the_alt_fields(
    tmp_path: Path,
) -> None:
    """★ rule 6: read by entry_id, an alternative entry is ``alignment_state`` alternative with a
    top-level pseudocode_sameness and pseudocode_delta, no similarity / confidence, and none of
    alt_pairings / significance / proposed_pair_reading; it is in no build's placed entries, and
    the listed page's counts are as without it.

    MUTATION (verified RED, ``1 failed``): carry the current pairing's similarity onto it ->
    RED."""
    w = _cycle_with_rows(tmp_path)
    comps, alts = _corr(w)
    e = _drill(w, _pair_id(A1, B2))
    assert e["alignment_state"] == "alternative"
    assert e.get("pseudocode_sameness") == "differs"
    assert isinstance(e.get("pseudocode_delta"), dict)
    assert (e["similarity"], e["alignment_confidence"]) == (None, None)
    for key in ("alt_pairings", "significance", "lift_basis", "proposed_pair_reading"):
        assert key not in e, key
    assert e["pairing_correction"]["component_id"] == comps[0].component_id
    built = pv.build_diff_view(w.atlas, DIFF)
    assert built is not None
    assert not {a.entry_id for a in alts} & {p.entry_id for p in built.placed}
    page = pv.get_diff_patch_view(w.atlas, DIFF)
    assert sum(page["counts"]["by_bucket"].values()) == 2 == page["total_entries"]
    assert page["pairing_components"] == {"count": 1, "claims": 2}
    assert {x["entry_id"] for x in page["entries"]} == {_pair_id(A1, B1), _pair_id(A2, B2)}


def test_every_row_of_an_alternative_entry_lands_r_proposed_pairing(tmp_path: Path) -> None:
    """★ rule 7: each row of an alternative entry lands R / proposed_pairing with no alignment
    confidence, and no ``unmapped_reason`` blind spot is counted for them; every candidate row of
    a superseded entry is on an alternative entry of its component.

    MUTATION (verified RED, ``1 failed``): drop row_landing's proposed_pairing branch -> RED."""
    w = _cycle_with_rows(tmp_path)
    (comp,), alts = _corr(w)
    rows = [v for e in alts for v in e.row_views]
    assert len(rows) == 3
    for v in rows:
        assert (v["landing"], v["subclass"]) == ("R", pv.PROPOSED_PAIRING)
        assert v["alignment_confidence"] is None and v["counterpart_call"] is None
    e = _drill(w, _pair_id(A1, B2))
    assert not any(str(s).startswith("unmapped_reason") for s in e.get("subclasses") or [])
    built = pv.build_diff_view(w.atlas, DIFF)
    assert built is not None
    pv.listed_view(w.atlas, built)
    by_id = {x.entry_id: x for x in built.placed}
    alt_refs = {ref for a in alts for r in a.rows for ref in (r.a_ref, r.b_ref) if ref}
    for sup in comp.superseded:
        for r in by_id[sup].rows:
            assert {ref for ref in (r.a_ref, r.b_ref) if ref} <= alt_refs, (sup, r)


def test_a_new_candidate_is_on_the_alternative_entry_at_once(tmp_path: Path) -> None:
    """★ The alternative entries are built afresh each read (their rows move with a re-hunt the
    readings key does not hold): a candidate added on a1 is on (a1, b2) at once, and the judgement
    written before it reads needs_recheck.

    MUTATION (verified RED, ``1 failed``): cache the alternative entries on the readings key ->
    the old row set is served -> RED."""
    w = _cycle_with_rows(tmp_path)
    before = _drill(w, _pair_id(A1, B2))
    w.judge(DIFF, _anchor(A1, B2), "changed_real")
    assert _drill(w, _pair_id(A1, B2))["review_state"] == "concluded"
    w.inst("a", _ref("runA", A1, "cmd", "0x30"), "cmd", "execv")
    w.commit()
    after = _drill(w, _pair_id(A1, B2))
    assert after["rows_total"] == before["rows_total"] + 1
    assert after["review_state"] == "needs_recheck"


# ── rule 8 and the subjects a write lands on ────────────────────────────────────────────────


def test_a_promotion_from_an_alternative_entry_is_refused(tmp_path: Path) -> None:
    """★ rule 8: promote from any row of an alternative entry is refused as such
    (``alignment_state`` alternative), before its rows' landings are read.

    MUTATION (verified RED, ``1 failed``): let it through to the landing check -> the refusal
    names the landing, not the alternative -> RED."""
    w = _cycle_with_rows(tmp_path)
    w.commit()
    ref = _ref("runA", A1, "cmd", "0x10")
    with pytest.raises(da.PromotionRefusedError) as exc:
        da.check_promotion(w.atlas, diff_id=DIFF, entry_id=_pair_id(A1, B2), row_ref=ref)
    assert exc.value.details.get("alignment_state") == "alternative", exc.value.details


def test_a_judgement_on_an_alternative_entry_is_read_everywhere_and_rewritten_in_place(
    tmp_path: Path,
) -> None:
    """★ A judgement on an alternative entry resolves (its subject is the diff's), reads concluded
    in list_overlays, in its members' ``pairing_correction`` and in the hand-off, whose block says
    it is an alternative pairing; written again it is an update, never refused.

    MUTATION (verified RED, ``1 failed``): leave the alternative entries out of ViewReview's
    subjects -> list_overlays reads it dangling -> RED."""
    w = _cycle_with_rows(tmp_path)
    w.commit()
    anchor = _anchor(A1, B2)
    w.judge(DIFF, anchor, "changed_real", verdict_basis={"change_kind": ["restructured"]})
    w.commit()
    rows = da.list_diff_overlays(w.atlas, run_id=PAIR, progress=False)["overlays"]
    assert [(r["anchor_ref"], r["review_state"]) for r in rows] == [(anchor, "concluded")]
    member = _drill(w, _pair_id(A1, B1))["pairing_correction"]
    assert member["claim_review_states"][_pair_id(A1, B2)] == "concluded"
    findings = rr.handoff_findings(w.atlas, PAIR)
    assert [(f["anchor_ref"], f["review_state"]) for f in findings] == [(anchor, "concluded")]
    block = rr.handoff_chunk(w.atlas, PAIR, findings[0])
    assert "alignment_state: alternative" in block
    again = w.judge(DIFF, anchor, "change_inconclusive")
    assert again.action == "updated"


def test_a_write_on_an_entry_placed_but_not_listed_is_still_refused(tmp_path: Path) -> None:
    """★ The write side takes the listed entries and the alternative ones only: an identical pair
    (placed, not listed) is refused as before.

    MUTATION (verified RED, ``1 failed``): resolve writes against every placed entry -> RED."""
    w = _cycle_with_rows(tmp_path)
    w.pair("00007000", "00007100", 0.97, 1.0)
    body = _body("00007000", *_stmts("same"))
    w.fn("a", "00007000", [], pseudocode=body)
    w.fn("b", "00007100", [], pseudocode=body.replace("00007000", "00007100"))
    w.commit()
    listed = {e["entry_id"] for e in pv.get_diff_patch_view(w.atlas, DIFF)["entries"]}
    assert _pair_id("00007000", "00007100") not in listed
    with pytest.raises(Exception, match="names nothing get_diff_patch_view lists"):
        w.judge(DIFF, _anchor("00007000", "00007100"), "changed_real")


def test_a_candidate_judgement_stays_on_its_own_entry(tmp_path: Path) -> None:
    """★ rule 7: no candidate subject is made for an alternative entry's rows: a judgement on a
    candidate row of a superseded entry is read against that entry. And ``checked`` naming an
    alternative entry's id resolves.

    MUTATION (verified RED, ``1 failed``): add the alternative rows' candidate subjects ->
    the subject's entry is the alternative -> RED; never read the alternative entries for a
    ``checked`` item -> the write is refused -> RED."""
    w = _cycle_with_rows(tmp_path)
    w.commit()
    built = pv.build_diff_view(w.atlas, DIFF)
    assert built is not None
    pv._attach_pair_evidence(w.atlas, built)
    entries = pv.listed_view(w.atlas, built).entries
    subjects = dr.subjects_for(w.atlas, built, entries)
    cands = {a: s for a, s in subjects.items() if s.kind == "candidate"}
    assert cands
    for s in cands.values():
        assert s.entry is not None and s.entry.pair is not None
        assert s.entry.pair.kind == "aligned"
    refused = None
    try:
        w.judge(
            DIFF,
            _anchor(A1, B1),
            "no_real_change",
            verdict_basis={"checked": [_pair_id(A1, B2)], "why_unchanged": "same calls"},
        )
    except ConfigError as exc:
        refused = str(exc)
    assert refused is None, refused  # checked naming an alternative entry resolves


# ── rule 9 / rule 10 / rule 11: the unit ────────────────────────────────────────────────────


def test_a_component_with_a_row_is_one_must_read_unit_and_its_superseded_entries_are_in_none(
    tmp_path: Path,
) -> None:
    """★ rule 9/10: a 2-cycle whose alternative has a candidate row is a must-read
    pairing_component unit of its alternative entries only (both members superseded), each
    member with ``pairing_component``; the superseded entries are in no unit, their own reasons
    kept on the component's unit.

    MUTATION (verified RED, ``1 failed``): leave superseded entries in the unit -> RED; drop their
    reasons from the unit -> RED."""
    w = _cycle_with_rows(tmp_path)
    r = _review(w)
    (u,) = _units(r, ru.PAIRING)
    assert u.must_read
    assert sorted(_ids(u)) == [_pair_id(A1, B2), _pair_id(A2, B1)]
    assert all(m.kind == "alternative" and "pairing_component" in m.reasons for m in u.members)
    anywhere = {m.entry_id for x in r.units for m in x.members}
    assert _pair_id(A1, B1) not in anywhere and _pair_id(A2, B2) not in anywhere
    assert u.component is not None
    assert set(u.component["superseded"]) == {_pair_id(A1, B1), _pair_id(A2, B2)}
    own = {m.entry_id: list(m.reasons) for d in r.facts.diffs for m in d.entries}
    assert own[_pair_id(A1, B1)]  # the fixture's premise: a superseded entry with reasons
    assert u.component["superseded_reasons"] == {
        x: own[x] for x in (_pair_id(A1, B1), _pair_id(A2, B2)) if own[x]
    }


def test_a_candidate_row_alone_makes_the_component_must_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ rule 9 condition 1, alone: no member must-read by its own reasons (each entry's reasons
    taken away here: an entry holding a candidate is attention 0 or lifted, so the two conditions
    cannot be told apart otherwise) and no function calling a sink — the alternative's candidate
    row makes the component must-read.

    MUTATION (verified RED, ``1 failed``): drop the rows condition -> not must-read -> RED."""
    monkeypatch.setattr(ru, "entry_reasons", lambda *_a, **_k: ())
    w = _cycle_with_rows(tmp_path)
    r = _review(w)
    assert all(m.reasons == () for d in r.facts.diffs for m in d.entries)
    (u,) = _units(r, ru.PAIRING)
    assert any(m.rows for m in u.members if m.kind == "alternative")
    assert u.must_read


def _quiet_cycle(tmp_path: Path, sizes: dict[str, int | None] | None = None) -> World:
    """A 2-cycle with no candidate and no sink call; ``sizes`` makes a function's text empty at
    that size (None: a real size, unreadable)."""
    w = _world(tmp_path, 2)
    _claim(w, A1, B2)
    _claim(w, A2, B1)
    for addr, size in (sizes or {}).items():
        side = "a" if addr in (A1, A2) else "b"
        w.adb[side].execute(
            "UPDATE functions SET pseudocode = '', size_bytes = ? WHERE address = ?",
            (size if size is not None else 4096, addr),
        )
    return w


@pytest.mark.parametrize(
    ("sizes", "must"),
    [({}, False), ({A1: None}, True), ({A1: 8, B2: 8}, False)],
    ids=["quiet", "one_side_unknown", "both_micro"],
)
def test_a_side_that_cannot_be_counted_makes_the_component_must_read_unless_micro(
    tmp_path: Path, sizes: dict[str, int | None], must: bool
) -> None:
    """★ rule 9: a component with no row and no sink call is not must-read (k=0); one side whose
    calls cannot be counted (text unavailable) makes it must-read; both sides design-skipped
    micro-stubs count as no call.

    MUTATION (verified RED, ``1 failed`` each): count unknown as no call -> one_side_unknown RED;
    count skipped_micro as a call -> both_micro RED."""
    w = _quiet_cycle(tmp_path, sizes)
    r = _review(w)
    (u,) = _units(r, ru.PAIRING)
    assert u.must_read is must


def test_a_quiet_component_is_second_tier_in_the_coverage_offer(tmp_path: Path) -> None:
    """★ A component that is not must-read is still one unit, and its members not disposed count
    in coverage_offer's second tier.

    MUTATION (verified RED, ``1 failed``): count only SECOND_TIER units there -> RED."""
    w = _quiet_cycle(tmp_path)
    r = _review(w)
    (u,) = _units(r, ru.PAIRING)
    assert not u.must_read
    offer = ru.coverage_offer(r, worker=None, workers=None, sweep=False)
    assert offer["second_tier"]["members"] >= len(u.members)
    assert offer["second_tier"]["units"] >= 1


def test_an_unlisted_member_is_no_unit_member(tmp_path: Path) -> None:
    """★ rule 3: an identical pair (placed, not listed) takes part as a claim's end, but is in no
    unit.

    MUTATION (verified RED, ``1 failed``): put the unlisted members in the unit -> RED."""
    w = _world(tmp_path, 2)
    w.pair(A3, B3, 0.97, 1.0)
    body = _body(A3, *_stmts("same"))
    w.fn("a", A3, [], pseudocode=body)
    w.fn("b", B3, [], pseudocode=body.replace(A3, B3))
    _claim(w, A1, B2)
    _claim(w, A2, B3)
    comps, _alts = _corr(w)
    (comp,) = comps
    assert _pair_id(A3, B3) in comp.entries
    r = _review(w)
    assert _pair_id(A3, B3) not in {m.entry_id for u in r.units for m in u.members}


def test_a_component_member_is_cut_out_of_its_callee_group_and_owed_no_group_ref(
    tmp_path: Path,
) -> None:
    """★ rule 11: two pair entries newly calling one function make a callee group; when one is a
    component member, the group is cut without it — no GROUP unit holds it and the reduce owes it
    nothing.

    MUTATION (verified RED, ``1 failed``): leave component members in the groups -> RED."""
    w = World(tmp_path)
    callee = "00008000"
    for a, b in ((A1, B1), (A2, B2), (A3, B3)):
        w.pair(a, b, 0.97, 0.6)
        w.fn("a", a, [], name=f"fn_{b}", pseudocode=_body(a, *_stmts(f"a {a}")))
        w.fn("b", b, ["new_helper"], name=f"fn_{b}", pseudocode=_body(b, *_stmts(f"b {b}")))
    w.pair(callee, "00008100", 0.97, 0.6)
    w.fn("a", callee, [], name="old_helper", pseudocode=_body(callee, *_stmts("callee a")))
    w.fn("b", "00008100", [], name="new_helper", pseudocode=_body("00008100", *_stmts("cb")))
    _claim(w, A1, B2)
    _claim(w, A2, B1)
    r = _review(w, k=ru.MAX_K)
    groups = [g for d in r.facts.diffs for g in d.groups]
    in_groups = {m for g in groups for m in g["members"]}
    assert _pair_id(A3, B3) in in_groups  # the fixture's group forms, with the one non-member
    comp_entries = {_pair_id(A1, B1), _pair_id(A2, B2)}
    assert not comp_entries & in_groups
    for u in _units(r, ru.GROUP):
        assert not comp_entries & set(_ids(u))
    owed = {m.anchor_ref for u in _units(r, ru.REDUCE) for m in u.members}
    assert not {_anchor(A1, B1), _anchor(A2, B2)} & owed


# ── rule 12 / rule 13: earlier judgements ───────────────────────────────────────────────────


def test_a_dangling_judgement_on_the_claimed_pair_reattaches_as_needs_recheck_and_goes_again(
    tmp_path: Path,
) -> None:
    """★ rule 13: a judgement on (a1, b2) written while that pair was the diff's: once re-paired
    it dangles; the claim makes the anchor resolve again — needs_recheck (its facts differ), and
    must-read; once the claim is gone it dangles again.

    MUTATION (verified RED, ``1 failed``): leave the alternative entries out of the review's
    subjects -> it stays dangling -> RED."""
    w = _world(tmp_path, 2)
    w.inst("a", _ref("runA", A1, "cmd", "0x10"), "cmd", "system")  # the component is must-read
    w.atlas.execute("UPDATE function_alignment SET addr_b = ? WHERE addr_a = ?", (B2, A1))
    w.atlas.execute("UPDATE function_alignment SET addr_b = ? WHERE addr_a = ?", (B1, A2))
    w.commit()
    anchor = _anchor(A1, B2)
    w.judge(DIFF, anchor, "changed_real")
    w.atlas.execute("UPDATE function_alignment SET addr_b = ? WHERE addr_a = ?", (B1, A1))
    w.atlas.execute("UPDATE function_alignment SET addr_b = ? WHERE addr_a = ?", (B2, A2))
    w.atlas.execute("UPDATE diff_meta SET created_at = '2099-01-01 00:00:00'")
    pv._clear_view_caches()
    ru.DIFF_CACHE.clear()
    assert anchor in _review(w).report["dangling_judgements"]
    _claim(w, A1, B2)
    _claim(w, A2, B1)
    pv._clear_view_caches()
    ru.DIFF_CACHE.clear()
    r = _review(w)
    assert anchor not in r.report["dangling_judgements"]
    assert r.progress.states[anchor] == "needs_recheck"
    assert anchor in {m.anchor_ref for u in r.units if u.must_read for m in u.members}
    assert r.report["must_read_complete"] is False
    w.atlas.execute("DELETE FROM string_keyed_edge")
    pv._clear_view_caches()
    ru.DIFF_CACHE.clear()
    assert anchor in _review(w).report["dangling_judgements"]


def test_an_earlier_changed_real_on_a_superseded_entry_is_read(tmp_path: Path) -> None:
    """★ R-H-2 on a subject no unit holds: a superseded entry (listed, in no unit) whose agent's
    changed_real is turned change_inconclusive reads earlier_changed_real.

    MUTATION (verified RED, ``1 failed``): read only the units' members -> RED."""
    w = _cycle_with_rows(tmp_path)
    anchor = _anchor(A1, B1)
    ctx = overlay.WriteContext(channel="mcp", session="s", read_basis={"basis": "fetched"})
    w.judge(DIFF, anchor, "changed_real", ctx=ctx, attributed_to="agent-via-mcp")
    w.judge(DIFF, anchor, "change_inconclusive", ctx=ctx, attributed_to="agent-via-mcp")
    r = _review(w)
    assert anchor not in {m.anchor_ref for u in r.units for m in u.members}
    assert anchor in {
        d["anchor_ref"] for d in r.audits.disagreements if d["why"] == "earlier_changed_real"
    }


def test_an_open_item_on_a_component_member_names_its_component(tmp_path: Path) -> None:
    """★ An open item on a component member says its component and each claim's review state.

    MUTATION (verified RED, ``1 failed``): read only the alternative pairings there -> RED."""
    w = _cycle_with_rows(tmp_path)
    anchor = _anchor(A1, B1)
    w.judge(DIFF, anchor, "change_inconclusive", attributed_to="human")
    w.commit()
    (item,) = rr.handoff_open_items(w.atlas, PAIR)
    block = rr.handoff_open_chunk(w.atlas, PAIR, item)
    comp_id = _drill(w, _pair_id(A1, B1))["pairing_correction"]["component_id"]
    assert f"- pairing component (tmap facts): {comp_id}" in block
    assert f"claim `{_pair_id(A1, B2)}`: {dr.review_state(None)}" in block


# ── the MCP unit material ───────────────────────────────────────────────────────────────────


def test_the_unit_material_gives_the_component_and_its_alternative_entries_first(
    tmp_path: Path,
) -> None:
    """★ A pairing_component unit's material: the component (claims, members, superseded, ends,
    conflict), then its members' views under ``entries``, the alternative entries first, each
    with its delta.

    MUTATION (verified RED, ``1 failed``): no material for the kind -> an error -> RED."""
    w = _world(tmp_path)
    _claim(w, A1, B2)
    _claim(w, A2, B3)
    w.inst("a", _ref("runA", A1, "cmd", "0x10"), "cmd", "system")
    w.commit()
    tools = mcp_app.make_tools(w.path)
    r = _review(w)
    (u,) = _units(r, ru.PAIRING)
    got = tools["start_diff_review"](run_pair=PAIR, unit=u.unit_id, k=0)
    mat = got.get("material") or {}
    assert "error" not in mat, got
    assert mat["component"]["superseded"] == [_pair_id(A2, B2)]
    ids = [e["entry_id"] for e in mat["entries"]]
    assert ids[:2] == [_pair_id(A1, B2), _pair_id(A2, B3)]
    assert {_pair_id(A1, B1), _pair_id(A3, B3)} <= set(ids)
    assert all("pseudocode_delta" in e for e in mat["entries"][:2])


# ── what was read before a judgement (the tool-call log) ────────────────────────────────────


def _code_world(tmp_path: Path, *, large: bool) -> World:
    """A 2-cycle whose alternative (a1, b2) has a candidate on a1 and texts that differ by many
    lines (``large``: over the inline hunk's gate) or by one."""
    many = 60 if large else 1
    texts = {
        A1: _stmts("shared", 4),
        B2: [*_stmts("shared", 4), *(f"sleep({i})" for i in range(many))],
    }
    w = _world(tmp_path, 2, texts=texts)
    _claim(w, A1, B2)
    _claim(w, A2, B1)
    for off in ("0x10", "0x20", "0x30"):
        w.inst("a", _ref("runA", A1, "cmd", off), "cmd", "system")
    w.commit()
    return w


class _Sess:
    """One server session with a tool-call log of its own, its reads recorded as the server
    records them."""

    def __init__(self, w: World) -> None:
        from treasure_map.lib import tool_call_log as tcl

        self.log = tcl.ToolCallLog(w.tmp / "calls.jsonl", tcl.Session(id="s1"))
        self.tools = mcp_app.make_tools(w.path, call_log=self.log)

    def start(self, k: int) -> None:
        """A start_diff_review(run_pair, k) answered without a unit's material: the k this
        session's writes are read at, nothing delivered."""
        self.log.record("start_diff_review", {"run_pair": PAIR, "k": k}, {"run_pair": PAIR})

    def call(self, name: str, **args: Any) -> dict[str, Any]:
        got: dict[str, Any] = self.tools[name](**args)
        self.log.record(name, args, got)
        return got

    def nrc(self, anchor: str, unit_id: str | None = None) -> dict[str, Any]:
        args: dict[str, Any] = {
            "anchor_ref": anchor,
            "verdict": "no_real_change",
            "rationale": "r",
            "diff_id": DIFF,
            "checked": [anchor],
            "why_unchanged": "the same calls",
        }
        if unit_id is not None:
            args["unit_id"] = unit_id
        got = self.call("annotate_diff", **args)
        assert got.get("written") is True, got
        return got


def _state(w: World, anchor: str) -> str | None:
    ru.DIFF_CACHE.clear()
    return _review(w).progress.states.get(anchor)


def test_an_alternative_entry_read_with_its_hunk_held_back_is_judged_unread(
    tmp_path: Path,
) -> None:
    """★ The read gate reads an alternative entry as an aligned one: its hunk held back (over the
    gate), a no_real_change written having read only its entry is unread_before_verdict ->
    needs_recheck; with the hunk whole, the same read and write concludes it.

    MUTATION (verified RED, ``1 failed``): render an alternative entry without its text reading
    (no pseudocode_delta) -> code_shown unknown, the write not held back -> RED."""
    for large, want in ((True, "needs_recheck"), (False, "concluded")):
        w = _code_world(tmp_path / str(large), large=large)
        s = _Sess(w)
        s.start(0)
        e = s.call("get_diff_patch_view", diff_id=DIFF, entry_id=_pair_id(A1, B2))["entries"][0]
        hunk = (e.get("pseudocode_delta") or {}).get("inline_hunk") or {}
        assert ("withheld" in hunk) is large, hunk  # the fixture's premise
        s.nrc(_anchor(A1, B2))
        assert _state(w, _anchor(A1, B2)) == want, large


def test_a_component_handed_out_and_judged_without_its_code_is_needs_recheck(
    tmp_path: Path,
) -> None:
    """★ The component unit handed out with its alternative's hunk held back: a no_real_change on
    it written with no read of its code is needs_recheck.

    MUTATION (verified RED, ``1 failed``): count every member of the material as read whole ->
    concluded -> RED."""
    w = _code_world(tmp_path, large=True)
    s = _Sess(w)
    (u,) = _units(_review(w), ru.PAIRING)
    got = s.call("start_diff_review", run_pair=PAIR, unit=u.unit_id, k=0)
    alt = next(e for e in got["material"]["entries"] if e["entry_id"] == _pair_id(A1, B2))
    assert "withheld" in alt["pseudocode_delta"]["inline_hunk"]
    s.nrc(_anchor(A1, B2), unit_id=u.unit_id)
    assert _state(w, _anchor(A1, B2)) == "needs_recheck"


def test_an_alternative_entry_judged_with_part_of_its_rows_read_is_needs_recheck(
    tmp_path: Path,
) -> None:
    """★ Only part of the alternative entry's rows read (rows_limit 1 of 3), its hunk whole: a
    no_real_change is needs_recheck.

    MUTATION (verified RED, ``1 failed``): read the rows window as whole -> concluded -> RED."""
    w = _code_world(tmp_path, large=False)
    s = _Sess(w)
    s.start(0)
    e = s.call("get_diff_patch_view", diff_id=DIFF, entry_id=_pair_id(A1, B2), rows_limit=1)
    assert e["entries"][0]["rows_total"] == 3 and len(e["entries"][0]["rows"]) == 1
    s.nrc(_anchor(A1, B2))
    assert _state(w, _anchor(A1, B2)) == "needs_recheck"
