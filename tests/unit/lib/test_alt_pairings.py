# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""alt_pairings (lib/query/patch_view, lib/query/alt_pairings): on every placed entry, where its
functions' counterparts may be other than where the diff pairs them — a function's unique strings
(at least five) or a single-handler dispatch key pointing elsewhere, or its body found exactly once
elsewhere on the other side (``via="twin"``, four gates). A fact beside the entry: nothing is
re-paired, re-bucketed, re-ordered or chosen between, and the pair evidence keeps its own rules.

Zero real data: test_patch_view's World (one diff of ``libx``, each run with its own analysis.db);
every address, name, string and body is synthetic.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests.unit.lib.test_pair_evidence import (  # noqa: F401 — the autouse fixture
    CONFLICT,
    _evidence_world,
    _fresh,
    _key,
    _staleness,
    _string,
)
from tests.unit.lib.test_patch_view import DIFF, World, _pair_id, _ref, _view
from treasure_map import mcp_app
from treasure_map.lib import overlay
from treasure_map.lib.query import alt_pairings as ap
from treasure_map.lib.query import diff_annotations as da
from treasure_map.lib.query import diff_review as dr
from treasure_map.lib.query import patch_view as pv
from treasure_map.lib.query import sameness

# ── the world ────────────────────────────────────────────────────────────────────────────────

A1, B2 = "00001000", "00002000"  # an aligned pair, low similarity (bucket C)
B1, A3 = "00002100", "00003000"  # where A1's anchors point, and B1's own partner
SHARED = ('puts("alpha step")', 'puts("beta step")', "sleep(3)")


def _body(addr: str, *stmts: str) -> str:
    """A function's text: its signature (naming it), each statement, a return — so its skeleton
    has ``len(stmts) + 4`` lines."""
    lines = [f"void FUN_{addr}(int param_1)", "{", *(f"  {s};" for s in stmts), "  return;", "}"]
    return "\n".join(lines)


def _fn(w: World, side: str, addr: str, *stmts: str, calls: list[str] | None = None) -> None:
    w.fn(side, addr, [], pseudocode=_body(addr, *stmts), calls=calls)


def _strings(w: World, a: str, b: str, n: int, tag: str = "shared message") -> None:
    """``n`` distinct strings, each referenced from ``a`` alone on A and ``b`` alone on B."""
    for i in range(n):
        _string(w, "a", f"{tag} {i}", a)
        _string(w, "b", f"{tag} {i}", b)


def _string_world(tmp_path: Path, n: int = 5, *, b1_paired: bool = True) -> World:
    """A1 <-> B2 aligned at similarity 0.6; A1's ``n`` unique strings are B1's. B1 is itself
    paired with A3 (``b1_paired``: every function in an aligned pair — no R, no P entry) or in
    no pair (a P entry)."""
    w = World(tmp_path)
    w.pair(A1, B2, 0.97, 0.6)
    _fn(w, "a", A1, *SHARED, calls=["system"])
    _fn(w, "b", B2, 'puts("unrelated text")', "exit(1)")
    _fn(w, "b", B1, *SHARED, "fflush(0)")  # A1's text, one line more: alike, not the same body
    if b1_paired:
        w.pair(A3, B1, 0.97, 0.6)
        _fn(w, "a", A3, 'puts("other side")', "sleep(9)")
    else:
        w.unpaired("b", B1, "absent")
    _strings(w, A1, B1, n)
    w.commit()
    return w


def _drill(w: World, entry_id: str) -> dict[str, Any]:
    page = pv.get_diff_patch_view(w.atlas, DIFF, entry_id=entry_id)
    assert "error" not in page, page
    (entry,) = page["entries"]
    return dict(entry)


def _one(entry: dict[str, Any]) -> dict[str, Any]:
    """The entry's single alternative (asserted, so a missing one fails as an assertion)."""
    items = entry.get("alt_pairings") or []
    assert len(items) == 1, entry
    return dict(items[0])


def _alts(entry: dict[str, Any]) -> list[tuple[str, str, str]]:
    return [(i["via"], i["direction"], i["target_addr"]) for i in entry.get("alt_pairings") or ()]


def _in(v: dict[str, Any], entry_id: str) -> dict[str, Any]:
    assert entry_id in v["by_id"], entry_id
    return dict(v["by_id"][entry_id])


# ── three sources, one each ────────────────────────────────────────────────────────────────


def test_five_unique_strings_point_an_aligned_entry_elsewhere(tmp_path: Path) -> None:
    """An aligned pair whose function's five unique strings belong to another function on
    the other side carries that function as a ``string`` alternative, and the alternative pairing
    reads its text closer than the current one does (one ratio rule for both).

    MUTATION (verified RED, 1 failed): compute alternatives on the undetermined R entries only ->
    no alt_pairings -> RED."""
    w = _string_world(tmp_path)
    e = _drill(w, _pair_id(A1, B2))
    assert _alts(e) == [("string", "to_b", B1)]
    item = _one(e)
    assert (item["target_pairing_state"], item["evidence_count"]) == ("aligned", 5)
    assert item["evidence"] == ["shared message 0", "shared message 1", "shared message 2"]
    assert item["alt_text_ratio"] > item["current_text_ratio"], item
    assert item.get("alt_delta_withheld") is None
    assert (e.get("alt_pairing_count"), e.get("alt_pairing_sources")) == (1, ["string"])


def test_a_single_handler_key_points_an_aligned_entry_elsewhere(tmp_path: Path) -> None:
    """One dispatch key whose single handler on the other side is another function is a
    ``key`` alternative.

    MUTATION (verified RED, 1 failed): compute alternatives on the undetermined R entries only ->
    RED."""
    w = _string_world(tmp_path, n=0)
    _key(w, "a", "do_reboot", A1)
    _key(w, "b", "do_reboot", B1)
    w.commit()
    assert _alts(_drill(w, _pair_id(A1, B2))) == [("key", "to_b", B1)]


X, Y = "00040000", "00050000"  # a function in no pair on each side
BODY = ('puts("unique work")', "memset(param_1,0,0x10)", "sleep(1)")


def _twin_world(
    tmp_path: Path, a_stmts: tuple[str, ...] = BODY, b_stmts: tuple[str, ...] = BODY
) -> World:
    """X on A and Y on B, each in no pair (P entries), with the given bodies."""
    w = World(tmp_path)
    w.unpaired("a", X, "absent")
    w.unpaired("b", Y, "absent")
    _fn(w, "a", X, *a_stmts)
    _fn(w, "b", Y, *b_stmts)
    return w


def test_a_unique_long_body_found_once_elsewhere_is_a_twin(tmp_path: Path) -> None:
    """A P entry whose body occurs exactly once on the other side (no short body, no callee
    refutation, literals read equal) carries that function as a ``twin`` alternative, and no
    ``twin_not_given``. Both directions: Y's entry points back at X.

    MUTATION (verified RED, 1 failed): read no same-body alternatives on P entries -> RED."""
    w = _twin_world(tmp_path)
    w.commit()
    e = _drill(w, f"a:{X}")
    assert _alts(e) == [("twin", "to_b", Y)]
    assert "twin_not_given" not in e
    item = _one(e)
    assert item["target_pairing_state"] == "unpaired"
    assert item["current_text_ratio"] is None  # a function in no pair has no current pairing
    assert item["alt_text_ratio"] == 1.0
    assert _alts(_drill(w, f"b:{Y}")) == [("twin", "to_a", X)]


# ── scope: every placed entry ──────────────────────────────────────────────────────────────


def test_an_aligned_entry_whose_strings_point_to_a_function_in_no_pair(tmp_path: Path) -> None:
    """An aligned low-similarity pair carries the alternative when the target is in no
    pair; the target state says so.

    MUTATION (verified RED, 1 failed): compute alternatives on the undetermined R entries only ->
    RED."""
    w = _string_world(tmp_path, b1_paired=False)
    item = _one(_drill(w, _pair_id(A1, B2)))
    assert (item["via"], item["target_addr"], item["target_pairing_state"]) == (
        "string",
        B1,
        "unpaired",
    )


A5, B5, B6 = "00005000", "00006000", "00006500"


def test_a_bucket_s_entry_carries_its_alternatives(tmp_path: Path) -> None:
    """An aligned similarity-1 pair whose text differs (bucket S, decided by the read face
    and never written to ``bucket``) carries its key alternative.

    MUTATION (verified RED, 1 failed): attach alternatives to ``built.entries`` instead of
    ``built.placed`` -> the S entry has none -> RED."""
    w = World(tmp_path)
    w.pair(A5, B5, 0.97, 1.0)
    _fn(w, "a", A5, 'puts("s side one")', "sleep(4)")
    _fn(w, "b", B5, 'puts("s side two")', "sleep(4)")
    _fn(w, "b", B6, 'puts("handler")', "sleep(5)")
    _key(w, "a", "do_restart", A5)
    _key(w, "b", "do_restart", B6)
    w.commit()
    e = _in(_view(w, bucket="S"), _pair_id(A5, B5))
    assert e["bucket"] == "S"
    assert (e.get("alt_pairing_count"), e.get("alt_pairing_sources")) == (1, ["key"])
    assert _alts(_drill(w, _pair_id(A5, B5))) == [("key", "to_b", B6)]


def test_a_diff_of_aligned_pairs_only_still_reads_its_alternatives(tmp_path: Path) -> None:
    """A diff with no R and no P entry at all (every function in an aligned pair) still
    reads its alternatives — the pair evidence's early return does not hold them back.

    MUTATION (verified RED, 1 failed): keep the ``if not targets and not one_sided: return``
    before the alternatives -> RED."""
    w = _string_world(tmp_path)
    v = _view(w)
    assert {e["bucket"] for e in v["entries"]} == {"C"}, [e["bucket"] for e in v["entries"]]
    e = _in(v, _pair_id(A1, B2))
    assert (e.get("alt_pairing_count"), e.get("alt_pairing_sources")) == (1, ["string"])
    # B1's own pairing (A3 <-> B1) points back: B1's strings are A1's
    e3 = _in(v, _pair_id(A3, B1))
    assert e3.get("alt_pairing_count") == 1


A7, B7, B8 = "00007000", "00007100", "00007200"


def _not_listed_world(tmp_path: Path) -> World:
    """A7 <-> B7: aligned, similarity 1, the same text — not listed; A7's key's handler on B is
    B8."""
    w = World(tmp_path)
    w.pair(A7, B7, 0.97, 1.0)
    _fn(w, "a", A7, 'puts("same both")', "sleep(6)")
    _fn(w, "b", B7, 'puts("same both")', "sleep(6)")
    _fn(w, "b", B8, 'puts("elsewhere")', "sleep(7)")
    _key(w, "a", "do_upgrade", A7)
    _key(w, "b", "do_upgrade", B8)
    w.commit()
    return w


def test_a_not_listed_pair_carries_its_alternatives_and_its_category_counts_them(
    tmp_path: Path,
) -> None:
    """A pair no entry lists carries its alternatives on its not-listed row (without a text
    reading: it is never read by entry_id), and its category counts ``with_alt_pairings``.

    MUTATION (verified RED, 1 failed): attach alternatives to listed entries only -> RED."""
    w = _not_listed_world(tmp_path)
    out = pv.get_diff_patch_view(w.atlas, DIFF)
    cats = {k: v for k, v in out["not_listed"].items() if v.get("count")}
    assert len(cats) == 1, out["not_listed"]
    ((name, counts),) = cats.items()
    assert counts.get("with_alt_pairings") == 1, counts
    page = pv.get_diff_patch_view(w.atlas, DIFF, not_listed_page=name)
    (row,) = page["entries"]
    assert row["entry_id"] == _pair_id(A7, B7)
    assert (row.get("alt_pairing_count"), row.get("alt_pairing_sources")) == (1, ["key"])
    item = _one(row)
    assert (item["via"], item["target_addr"]) == ("key", B8)
    assert item["alt_delta_withheld"] == pv.ALT_NOT_LISTED
    assert all(item[k] is None for k in pv._ALT_DRILL_FIELDS), item
    summary = pv.get_diff_patch_view(w.atlas, DIFF, not_listed_page=name, detail="summary")
    (srow,) = summary["entries"]
    assert (srow.get("alt_pairing_count"), srow.get("alt_pairing_sources")) == (1, ["key"])


def test_a_function_a_re_hunt_turns_into_an_entry_finds_its_twin(tmp_path: Path) -> None:
    """The same-body readings are read per function, so a function that is no entry when
    the readings are first read (no pair, no presence record) and becomes one later through a new
    candidate row — the diff unchanged, the readings served from their cache — finds its twin.

    MUTATION (verified RED, 1 failed): keep only the readings of functions placed at read time
    (per entry), under the readings' key -> the new entry has none -> RED."""
    w = World(tmp_path)
    w.unpaired("b", Y, "absent")
    _fn(w, "a", X, *BODY)
    _fn(w, "b", Y, *BODY)
    w.commit()
    first = _view(w)
    assert f"a:{X}" not in first["by_id"]
    w.inst("a", _ref("runA", X, "cmd", "0x30"), "cmd", "system")
    w.commit()
    e = _in(_view(w), f"a:{X}")
    assert (e.get("alt_pairing_count"), e.get("alt_pairing_sources")) == (1, ["twin"]), e
    assert _alts(_drill(w, f"a:{X}")) == [("twin", "to_b", Y)]


# ── the publish rules and the gates: their teeth are in the refusals ────────────────────────


@pytest.mark.parametrize("n", [1, 4])
def test_fewer_than_five_strings_publish_no_alternative(tmp_path: Path, n: int) -> None:
    """One string — or four — pointing elsewhere publishes nothing.

    MUTATION (verified RED, 2 failed): publish a string reading from one value -> RED."""
    w = _string_world(tmp_path, n=n)
    e = _drill(w, _pair_id(A1, B2))
    assert "alt_pairings" not in e and "alt_pairing_count" not in e, e


def test_the_publish_rule_moves_no_pair_evidence(tmp_path: Path) -> None:
    """★ One string pointing elsewhere on an undetermined pair whose caller corroborates it
    and which carries a lift_basis: the counterpart hint still reads the conflict, the pair
    evidence ``none``, and the entry does not float — the five-string rule is alt_pairings' own,
    never the pair evidence's.

    MUTATION (verified RED, 1 failed): apply the five-string rule inside _anchor_hints -> the
    conflict is gone -> supported -> attention 0 -> RED."""
    w = _evidence_world(tmp_path)
    e = _in(_view(w, sort_by="significance"), _pair_id(*CONFLICT))
    assert e["pair_evidence"]["state"] == "none", e["pair_evidence"]
    assert e["pair_evidence"]["caller_anchor"]["state"] == "corroborated"
    assert e["counterpart_hint"]["state"] == "conflict"
    assert e["lift_basis"] == "sink_callee_swap"
    assert e["significance"]["attention"] != 0, e["significance"]
    assert "alt_pairing_count" not in e  # one string: not published here either


P1, Q1, Q9 = "00011000", "00012000", "00019000"


def test_a_partner_with_the_same_body_gives_no_twin_reading(tmp_path: Path) -> None:
    """When the current partner has the same skeleton, the body's other copies are the
    pair's own reading: no twin, and no twin_not_given either.

    MUTATION (verified RED, 1 failed): drop the partner exclusion -> twin_not_given appears ->
    RED."""
    w = World(tmp_path)
    for side in ("a", "b"):
        w.block(side, "0x00400000", 0x1000)
    w.pair(P1, Q1, 0.97, 0.9)
    _fn(w, "a", P1, *BODY, "param_1 = 0x12345678")  # the same skeleton, a literal that differs
    _fn(w, "b", Q1, *BODY, "param_1 = 0x22345678")
    _fn(w, "b", Q9, *BODY, "param_1 = 0x32345678")  # the body once more on B, in no pair
    w.commit()
    e = _drill(w, _pair_id(P1, Q1))
    assert e["bucket"] == "C"
    assert "twin_not_given" not in e and "alt_pairings" not in e, e


def test_a_five_line_body_is_short(tmp_path: Path) -> None:
    """A unique body found once elsewhere whose skeleton has five lines gives no target,
    only ``short_body``.

    MUTATION (verified RED, 1 failed): drop gate 1 -> a target -> RED."""
    w = _twin_world(tmp_path, ("sleep(1)",), ("sleep(1)",))
    w.commit()
    e = _drill(w, f"a:{X}")
    assert "alt_pairings" not in e, e
    assert e.get("twin_not_given") == [{"direction": "to_b", "count": 1, "basis": "short_body"}]


CA, CB, CB2 = "00021000", "00022000", "00023000"


def _callee_world(tmp_path: Path, conf: float) -> World:
    """X calls CA, Y calls CB2, otherwise the same body. CA <-> CB is a pair at ``conf`` with the
    same body on both sides; CB2's body is another."""
    w = _twin_world(tmp_path, (f"FUN_{CA}(param_1)", *BODY), (f"FUN_{CB2}(param_1)", *BODY))
    w.pair(CA, CB, conf, 0.9)
    _fn(w, "a", CA, 'puts("helper")', "sleep(2)")
    _fn(w, "b", CB, 'puts("helper")', "sleep(2)")
    _fn(w, "b", CB2, 'puts("another helper")', "sleep(3)")
    w.commit()
    return w


def test_a_callee_aligned_to_its_own_body_elsewhere_refutes_the_twin(tmp_path: Path) -> None:
    """X and Y read the same skeleton, but X calls CA, aligned to CB with CA's own body,
    while Y calls CB2 there (another body): the twin is refused,
    ``callee_identity_elsewhere``. Its positions are the ``FUN_<addr>`` references themselves.

    MUTATION (verified RED, 1 failed): drop gate 3 -> a target -> RED. MUTATION (verified RED,
    1 failed): read the positions from sameness._calls (which names a blanked address
    ``unnamed``) -> never refutes -> RED."""
    w = _callee_world(tmp_path, 0.97)
    e = _drill(w, f"a:{X}")
    assert "alt_pairings" not in e, e
    assert e.get("twin_not_given") == [
        {"direction": "to_b", "count": 1, "basis": "callee_identity_elsewhere"}
    ]


def test_an_undetermined_callee_refutes_nothing(tmp_path: Path) -> None:
    """The same shape with CA <-> CB only an undetermined pair: it refutes nothing, the
    twin is given.

    MUTATION (verified RED, 1 failed): refuse whenever the two callees differ -> RED."""
    w = _callee_world(tmp_path, 0.5)
    e = _drill(w, f"a:{X}")
    assert _alts(e) == [("twin", "to_b", Y)]
    assert "twin_not_given" not in e


def test_literals_that_differ_hold_the_twin_back(tmp_path: Path) -> None:
    """The same skeleton, a large literal outside both images that differs:
    ``literal_values_differ``.

    MUTATION (verified RED, 1 failed): drop gate 4 -> a target -> RED."""
    w = _twin_world(tmp_path, (*BODY, "param_1 = 0x12345678"), (*BODY, "param_1 = 0x22345678"))
    for side in ("a", "b"):
        w.block(side, "0x00400000", 0x1000)
    w.commit()
    e = _drill(w, f"a:{X}")
    assert "alt_pairings" not in e, e
    assert e.get("twin_not_given") == [
        {"direction": "to_b", "count": 1, "basis": "literal_values_differ"}
    ]


def test_a_body_found_many_times_is_counted_not_given(tmp_path: Path) -> None:
    """A body found 80 times on the other side gives only its count, ``not_unique``.

    MUTATION (verified RED, 1 failed): drop gate 2 (take the first copy) -> a target -> RED."""
    w = _twin_world(tmp_path)
    for i in range(79):
        _fn(w, "b", f"{0x00060000 + 0x100 * i:08x}", *BODY)
    w.commit()
    e = _drill(w, f"a:{X}")
    assert "alt_pairings" not in e, e
    assert e.get("twin_not_given") == [{"direction": "to_b", "count": 80, "basis": "not_unique"}]


WARN = "/* WARNING: Could not recover jumptable at 0x00401000. Too many branches */"


def test_a_decompile_incomplete_body_gives_no_target(tmp_path: Path) -> None:
    """A body whose decompile says it is not whole gives no target,
    ``decompile_incomplete``, ahead of every other gate.

    MUTATION (verified RED, 1 failed): drop the decompile-incomplete exclusion -> a target ->
    RED."""
    w = _twin_world(tmp_path, (WARN, *BODY), (WARN, *BODY))
    w.commit()
    e = _drill(w, f"a:{X}")
    assert "alt_pairings" not in e, e
    assert e.get("twin_not_given") == [
        {"direction": "to_b", "count": 1, "basis": "decompile_incomplete"}
    ]


P2, Q2, Q3, Q4, P4 = "00031000", "00032000", "00033000", "00034000", "00035000"


def test_each_direction_of_a_pair_has_its_own_twin_reading(tmp_path: Path) -> None:
    """A pair's A body is found twice on B (``not_unique``) while its B body, a short one,
    is found once on A (``short_body``): one item per direction, in direction order.

    MUTATION (verified RED, 1 failed): keep one twin_not_given for the entry -> RED."""
    w = World(tmp_path)
    w.pair(P2, Q2, 0.97, 0.9)
    _fn(w, "a", P2, *BODY)
    _fn(w, "b", Q2, "sleep(8)")
    _fn(w, "b", Q3, *BODY)
    _fn(w, "b", Q4, *BODY)
    _fn(w, "a", P4, "sleep(8)")
    w.commit()
    assert _drill(w, _pair_id(P2, Q2)).get("twin_not_given") == [
        {"direction": "to_a", "count": 1, "basis": "short_body"},
        {"direction": "to_b", "count": 2, "basis": "not_unique"},
    ]


T6, T7, T8 = "00060000", "00070000", "00080000"


def test_every_alternative_is_given_in_a_fixed_order(tmp_path: Path) -> None:
    """An entry pointed to two functions by strings (five values to one, six to the other,
    whose text reads closer) and to a third by a key: all three, by (via, direction, target),
    never by evidence count or text ratio, and none chosen.

    MUTATION (verified RED, 1 failed): order by evidence count, most first -> RED. MUTATION
    (verified RED, 1 failed): order by alt_text_ratio, highest first -> RED."""
    w = _twin_world(tmp_path)
    _fn(w, "b", T6, 'puts("far away")', "exit(2)")
    _fn(w, "b", T7, *BODY, "fflush(0)")
    _fn(w, "b", T8, 'puts("handler two")', "exit(3)")
    _strings(w, X, T6, 5, "first set")
    _strings(w, X, T7, 6, "second set")
    _key(w, "a", "do_factory", X)
    _key(w, "b", "do_factory", T8)
    w.commit()
    e = _drill(w, f"a:{X}")
    assert _alts(e) == [
        ("key", "to_b", T8),
        ("string", "to_b", T6),
        ("string", "to_b", T7),
        ("twin", "to_b", Y),
    ]
    by = {i["target_addr"]: i for i in e.get("alt_pairings") or []}
    assert (by[T6]["evidence_count"], by[T7]["evidence_count"]) == (5, 6)
    assert by[T7]["alt_text_ratio"] > by[T6]["alt_text_ratio"], by


def test_a_stale_source_withholds_the_alternatives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On a diff whose sources are not shown current, none could be read:
    ``alt_pairings_withheld`` says why — never a count of 0 or an empty list.

    MUTATION (verified RED, 1 failed): treat a blocked diff as one with no alternative -> RED."""
    monkeypatch.setattr(pv, "diff_source_staleness", _staleness(True))
    w = _string_world(tmp_path)
    for e in _view(w)["entries"]:
        assert e.get("alt_pairings_withheld") == "source_stale", e
        assert "alt_pairing_count" not in e and "alt_pairings" not in e, e


def test_an_unreadable_analysis_db_withholds_the_alternatives(tmp_path: Path) -> None:
    """A side whose analysis.db cannot be read withholds them too, with that reason."""
    w = _string_world(tmp_path)
    w.atlas.execute("UPDATE run SET analysis_db_path = ? WHERE run_id = 'runB'", (str(tmp_path),))
    w.commit()
    for e in _view(w)["entries"]:
        assert e.get("alt_pairings_withheld") == "analysis_db_unavailable", e


def test_bodies_that_cannot_be_read_say_the_twins_were_not_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the bodies cannot be read while the anchors can, the string / key alternatives are
    given and the entry says the same-body readings were not read (``twin_unreadable``).

    MUTATION (verified RED, 1 failed): leave the unreadable twins unsaid -> RED."""
    w = _string_world(tmp_path)
    real = sameness.read_function_bodies
    monkeypatch.setattr(
        sameness,
        "read_function_bodies",
        lambda path, sha: None if path and path.endswith("analysis_b.db") else real(path, sha),
    )
    e = _in(_view(w), _pair_id(A1, B2))
    assert e.get("alt_pairing_count") == 1
    assert e.get("alt_pairings_withheld") == pv.ALT_TWIN_UNREADABLE


# ── where the readings ride, the budget, the order and the facts ──────────────────────────


def test_a_listed_page_counts_and_one_entry_reads_them_in_full(tmp_path: Path) -> None:
    """A listed page gives the count and sources only; a unit's members (entry_ids) give the
    readings without their text and sink reading (``read_with_entry_id``); one entry read by
    entry_id gives each alternative's delta summary, both sink counts (``pairing``
    ``alternative``) and both ratios.

    MUTATION (verified RED, 1 failed): give the full readings on a listed page -> RED."""
    w = _string_world(tmp_path)
    eid = _pair_id(A1, B2)
    listed = _in(_view(w), eid)
    assert listed.get("alt_pairing_count") == 1
    assert "alt_pairings" not in listed and "twin_not_given" not in listed, listed
    unit = pv.get_diff_patch_view(w.atlas, DIFF, entry_ids=frozenset({eid}))
    (member,) = [e for e in unit["entries"] if e["entry_id"] == eid]
    cheap = _one(member)
    assert cheap["alt_delta_withheld"] == pv.ALT_READ_WITH_ENTRY_ID
    assert all(cheap[k] is None for k in pv._ALT_DRILL_FIELDS), cheap
    item = _one(_drill(w, eid))
    assert all(item[k] is not None for k in pv._ALT_DRILL_FIELDS), item
    assert item["alt_delta_summary"]["kind"] in ("structural", "substitution_only"), item
    callsite = item["alt_sink_counts"]["callsite"]
    assert callsite is not None and callsite["pairing"] == "alternative", item
    assert callsite["delta"] == [{"sink": "system", "a": 1, "b": 0}]


def test_an_entry_over_the_budget_cuts_its_alternatives_and_says_so() -> None:
    """One entry whose alternatives alone would take it over the budget keeps as many as fit
    and says how many it holds (``alt_pairings_cut``); its count is unchanged.

    MUTATION (verified RED, 1 failed): do not cut the alternatives -> over the budget -> RED."""
    items = [
        {"via": "string", "direction": "to_b", "target_addr": f"{i:08x}", "evidence": ["v" * 80]}
        for i in range(400)
    ]
    entry = {"entry_id": "a:00001000", "alt_pairing_count": 400, "alt_pairings": items}
    out = mcp_app._entry_within_budget(entry, 1000, budget=20_000)
    assert 1000 + len(json.dumps(out)) <= 20_000
    kept = out.get("alt_pairings") or []
    assert 0 < len(kept) < 400
    assert out.get("alt_pairings_cut") == {"shown": len(kept), "of": 400}
    assert out["alt_pairing_count"] == 400
    assert entry["alt_pairings"] is items and len(items) == 400  # the input is not written


def test_a_summary_keeps_the_count_and_sources(tmp_path: Path) -> None:
    """``detail='summary'`` keeps ``alt_pairing_count`` and ``alt_pairing_sources``.

    MUTATION (verified RED, 1 failed): leave them out of the summary whitelist -> RED."""
    w = _string_world(tmp_path)
    e = _in(_view(w, detail="summary"), _pair_id(A1, B2))
    assert (e.get("alt_pairing_count"), e.get("alt_pairing_sources")) == (1, ["string"])


def _order_facts(w: World) -> dict[str, Any]:
    v = _view(w, sort_by="significance")
    return {
        "order": [e["entry_id"] for e in v["entries"]],
        "entries": {
            e["entry_id"]: (
                e["bucket"],
                e["subclass"],
                e["significance"],
                e["lift_basis"],
                e["review_state"],
                json.dumps(e["rank_key"], sort_keys=True),
            )
            for e in v["entries"]
        },
        "counts": v["counts"],
        "not_listed": {k: c["count"] for k, c in v["not_listed"].items()},
    }


KA, KB, KB1 = "00091000", "00092000", "00092100"  # beside the pair-evidence world's addresses


def test_alternatives_move_no_entry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """★ Alternatives are facts beside an entry — reading none at all leaves every entry's
    bucket, subclass, significance, lift_basis, rank and review state, the order and the counts
    exactly as they are with them.

    MUTATION (verified RED, 1 failed): lift an entry with an alternative to attention 0 -> RED."""
    w = _evidence_world(tmp_path)
    _strings(w, KA, KB1, 5)
    w.pair(KA, KB, 0.97, 0.6)
    _fn(w, "a", KA, *SHARED)
    _fn(w, "b", KB, 'puts("unrelated text")', "exit(1)")
    _fn(w, "b", KB1, *SHARED)
    w.unpaired("a", X, "absent")
    w.unpaired("b", Y, "absent")
    _fn(w, "a", X, *BODY)
    _fn(w, "b", Y, *BODY)
    w.commit()
    with_alts = _order_facts(w)
    assert _in(_view(w), _pair_id(KA, KB)).get("alt_pairing_count")
    assert _in(_view(w), f"a:{X}").get("alt_pairing_count")
    monkeypatch.setattr(pv._PairEvidence, "alt_anchor_items", lambda self, e: [])
    monkeypatch.setattr(ap, "twin_readings", lambda *a, **k: ap.TwinReadings({}))
    pv._clear_view_caches()
    without = _order_facts(w)
    assert "alt_pairing_count" not in _in(_view(w), _pair_id(KA, KB))
    assert with_alts == without


def _anchor_of(w: World, entry_id: str) -> str:
    return str(_drill(w, entry_id)["anchor_ref"])


def test_the_string_and_key_alternatives_are_a_fact_of_a_judgement(tmp_path: Path) -> None:
    """Entry_facts carries the published string / key alternatives as [via, direction,
    target], on a pair and on a function in no pair.

    MUTATION (verified RED, 1 failed): leave alt_pairings out of entry_facts -> RED."""
    w = _string_world(tmp_path, b1_paired=False)
    built = pv.build_diff_view(w.atlas, DIFF)
    assert built is not None
    pv._attach_pair_evidence(w.atlas, built)
    by = {e.entry_id: e for e in built.placed}
    assert _pair_id(A1, B2) in by and f"b:{B1}" in by
    assert dr.entry_facts(by[_pair_id(A1, B2)]).get("alt_pairings") == [["string", "to_b", B1]]
    assert dr.entry_facts(by[f"b:{B1}"]).get("alt_pairings") == [["string", "to_a", A1]]


def test_a_snapshot_without_the_alternatives_key_moves_nothing(tmp_path: Path) -> None:
    """A judgement stored before alternatives were a fact (its snapshot lacks the key)
    still reads concluded where the entry now has one: a snapshot is compared on its own keys.

    MUTATION (verified RED, 1 failed): compare every key of both snapshots -> RED."""
    w = _string_world(tmp_path)
    anchor = _anchor_of(w, _pair_id(A1, B2))
    overlay.annotate_diff(
        w.atlas, anchor_ref=anchor, verdict="changed_real", rationale="r", diff_id=DIFF
    )
    raw = w.atlas.execute("SELECT basis_state FROM overlay WHERE anchor_ref = ?", (anchor,))
    snap = json.loads(raw.fetchone()[0])
    assert snap["facts"].get("alt_pairings") == [["string", "to_b", B1]], snap["facts"]
    del snap["facts"]["alt_pairings"]
    w.atlas.execute(
        "UPDATE overlay SET basis_state = ? WHERE anchor_ref = ?", (json.dumps(snap), anchor)
    )
    w.atlas.commit()
    pv._clear_view_caches()
    built = pv.build_diff_view(w.atlas, DIFF)
    assert built is not None
    judged = pv.ViewReview(w.atlas, built).judged[anchor]
    assert (judged.state, dict(judged.moved)) == ("concluded", {})


def test_the_same_body_readings_are_no_fact_of_a_judgement(tmp_path: Path) -> None:
    """★ The facts a judgement on a P entry with a twin is checked against are the same
    whether or not this process has read the same-body readings: taken once with the S cache warm
    and the twin cache empty (no readings read), once after a full view read them.

    MUTATION (verified RED, 1 failed): put the twins (when cached) into alt_anchor -> RED."""
    w = _twin_world(tmp_path)
    w.commit()
    anchor = _anchor_of(w, f"a:{X}")
    pv._clear_view_caches()
    built = pv.build_diff_view(w.atlas, DIFF)
    assert built is not None
    pv.listed_view(w.atlas, built)  # the S cache, read from the pseudocode readings
    pv._TWIN_CACHE.clear()
    first = da.capture_diff_basis(w.atlas, DIFF, anchor)["facts"]
    assert len(pv._TWIN_CACHE) == 0  # the write path read no pseudocode
    assert _alts(_drill(w, f"a:{X}")) == [("twin", "to_b", Y)]
    assert len(pv._TWIN_CACHE) == 1
    second = da.capture_diff_basis(w.atlas, DIFF, anchor)["facts"]
    assert first == second
    assert "alt_pairings" in second and second["alt_pairings"] is None


def test_no_read_re_pairs_anything(tmp_path: Path) -> None:
    """Reading every entry's alternatives in full leaves the diff's pairing as it was: the
    build's pair maps and the stored alignment rows.

    MUTATION (verified RED, 1 failed): re-pair the entry's function with its alternative while
    reading it -> RED."""
    w = _string_world(tmp_path)
    rows = "SELECT * FROM function_alignment ORDER BY addr_a, addr_b"
    stored = [tuple(r) for r in w.atlas.execute(rows)]
    built = pv.build_diff_view(w.atlas, DIFF)
    assert built is not None
    before = (dict(built.diff.pair_of_a), dict(built.diff.pair_of_b), list(built.diff.pairs))
    readings = pv._pseudo_readings(w.atlas, built)
    pv._attach_pair_evidence(w.atlas, built)
    read = [pv._alt_fields(built, readings, e, "drill") for e in built.placed]
    assert any(r.get("alt_pairings") for r in read)
    assert (
        dict(built.diff.pair_of_a),
        dict(built.diff.pair_of_b),
        list(built.diff.pairs),
    ) == before
    assert [tuple(r) for r in w.atlas.execute(rows)] == stored


# ── the ratio rule ─────────────────────────────────────────────────────────────────────────


def test_the_ratio_blanks_the_try_addresses_by_the_pairs_own_offset() -> None:
    """delta_ratio reads the try/catch annotation's addresses under the offset of the pair it is
    given: moved by exactly that offset they read alike, else not.

    MUTATION (verified RED, 1 failed): never blank them -> RED."""
    a = (
        "void f(void)\n{\n"
        "  /* try { // try from 00401010 to 00401020 has its CatchHandler @ 00401030 */\n"
        "  g();\n}"
    )
    b = (
        a.replace("00401010", "00402010")
        .replace("00401020", "00402020")
        .replace("00401030", "00402030")
    )
    assert sameness.delta_ratio(a, b, None, None, "00401000", "00402000") == 1.0
    assert sameness.delta_ratio(a, b, None, None, "00401000", "00403000") < 1.0


def test_the_ratio_turns_the_junk_heuristic_off() -> None:
    """delta_ratio matches every line, however common: two long bodies that share only one line,
    repeated between their own lines, still read half alike; the junk heuristic would read them
    as nothing alike.

    MUTATION (verified RED, 1 failed): leave autojunk on -> RED."""
    a = "\n".join(f"}}\na_{i}();" for i in range(300))
    b = "\n".join(f"}}\nb_{i}();" for i in range(300))
    assert sameness.delta_ratio(a, b, None, None, "00001000", "00002000") == 0.5
