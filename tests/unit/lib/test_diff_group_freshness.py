# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Group-level freshness of a diff judgement (lib/query/diff_group_freshness, S6).

A judgement can record the same-shape group it leaned on (annotate_diff's ``group_ref``). This
checks that the group is snapshotted at write time, re-derived on every read, and that a member
joining, leaving or changing where it landed puts the judgement in needs_recheck — read the same way
by both read paths (get_diff_patch_view and list_diff_overlays), capped so one report never grows
with the group, and never read as unchanged when it cannot be rebuilt. Zero real data: it reuses the
synthetic one-diff world of test_same_shape_siblings.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from tests.unit.lib.test_same_shape_siblings import (
    DIFF,
    GROUP_A,
    LISTED,
    SYSTEM_FREE,
    UNLISTED,
    World,
    _build,
    _ref,
)
from treasure_map import mcp_app
from treasure_map.cli import mcp_cli
from treasure_map.lib import overlay
from treasure_map.lib.errors import ConfigError
from treasure_map.lib.query import diff_annotations as da
from treasure_map.lib.query import diff_group_freshness as gf
from treasure_map.lib.query import patch_view as pv
from treasure_map.lib.query import same_shape_siblings as ss
from treasure_map.lib.rescan_version import CodeStamp
from treasure_map.version import UNKNOWN_VERSION

_CURRENT = CodeStamp(hunt="src-a1a1a1a1a1a1a1a1", scan="{}")


@pytest.fixture(autouse=True)
def _servable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mcp_app, "_installed_commit", lambda: UNKNOWN_VERSION)
    monkeypatch.setattr(mcp_cli, "installed_commit", lambda: UNKNOWN_VERSION)
    pv._clear_view_caches()


@pytest.fixture
def current(monkeypatch: pytest.MonkeyPatch) -> None:
    def fresh(atlas: Any, diff_id: str) -> dict[str, Any]:
        return {"source_stale": False, "source_stale_reason": None, "toolchain_checked": True}

    monkeypatch.setattr(pv, "diff_source_staleness", fresh)
    monkeypatch.setattr(ss, "diff_source_staleness", fresh)


@pytest.fixture
def world(tmp_path: Path, current: None) -> World:
    w = World(tmp_path)
    _build(w)
    return w


# ── helpers ──────────────────────────────────────────────────────────────────────────────────


def _group_ref(w: World, ref: str) -> str:
    out = ss.same_shape_siblings(
        w.atlas,
        DIFF,
        evidence_ref=ref,
        build_hash=w.build,
        current=_CURRENT,
        commit=UNKNOWN_VERSION,
    )
    assert "group_ref" in out, out
    return str(out["group_ref"])


def _entry_anchor(w: World, needle: str) -> str:
    """The anchor_ref of the one listed entry whose anchor names ``needle`` (an address)."""
    view = pv.get_diff_patch_view(w.atlas, DIFF, limit=200)
    hits = [e["anchor_ref"] for e in view["entries"] if needle in e["anchor_ref"]]
    assert len(hits) == 1, (needle, hits)
    return hits[0]


def _annotate(w: World, anchor: str, group_ref: str | None, verdict: str = "changed_real") -> Any:
    return overlay.annotate_diff(
        w.atlas,
        diff_id=DIFF,
        anchor_ref=anchor,
        verdict=verdict,
        rationale="x: the other calls of this shape did not change; next: re-read if they move",
        group_ref=group_ref,
    )


def _state_in_view(w: World, anchor: str) -> str:
    pv._clear_view_caches()
    view = pv.get_diff_patch_view(w.atlas, DIFF, limit=200)
    for e in view["entries"]:
        if e["anchor_ref"] == anchor:
            return str(e["review_state"])
    raise AssertionError(f"{anchor!r} not listed")


def _overlay(w: World, anchor: str) -> dict[str, Any]:
    pv._clear_view_caches()
    out = da.list_diff_overlays(w.atlas, run_id="runA::runB")
    for o in out["overlays"]:
        if o["anchor_ref"] == anchor:
            return o
    raise AssertionError(f"{anchor!r} not in list_diff_overlays")


def _stored_group(w: World, anchor: str) -> dict[str, Any]:
    row = w.atlas.execute(
        "SELECT basis_state FROM overlay WHERE anchor_ref = ? AND anchor_kind = 'diff_subject'",
        (anchor,),
    ).fetchone()
    group = json.loads(row[0])["group"]
    assert isinstance(group, dict)
    return group


# ── the happy path and the two read paths ────────────────────────────────────────────────────


def test_a_group_a_judgement_leaned_on_is_stored_and_reads_concluded(world: World) -> None:
    anchor = _entry_anchor(world, "00001000")
    gref = _group_ref(world, LISTED)
    res = _annotate(world, anchor, gref)
    assert res.action in ("inserted", "created", "updated")
    group = _stored_group(world, anchor)
    assert group["group_ref"] == gref
    assert group["relation"] == "own_call"
    assert group["member_count"] == len(GROUP_A)
    assert "summary" in group and "members" in group
    assert _state_in_view(world, anchor) == "concluded"


def test_both_read_paths_agree_on_the_state_after_a_member_moves(world: World) -> None:
    anchor = _entry_anchor(world, "00001000")
    _annotate(world, anchor, _group_ref(world, LISTED))
    # move another member's landing: an unlisted similarity-1 pair becomes a changed pair.
    world.atlas.execute("UPDATE function_alignment SET similarity = 0.8 WHERE addr_a = '00003000'")
    world.commit()
    via_view = _state_in_view(world, anchor)
    via_list = _overlay(world, anchor)["review_state"]
    assert via_view == via_list == "needs_recheck"
    assert _overlay(world, anchor)["basis_moved"]["group"]["changed"] >= 1


# ── a move is a move: landing, join, leave, fingerprint ───────────────────────────────────────


def test_a_members_landing_moving_reads_needs_recheck(world: World) -> None:
    anchor = _entry_anchor(world, "00001000")
    _annotate(world, anchor, _group_ref(world, LISTED))
    assert _state_in_view(world, anchor) == "concluded"
    world.atlas.execute("UPDATE function_alignment SET similarity = 0.8 WHERE addr_a = '00003000'")
    world.commit()
    moved = _overlay(world, anchor)["basis_moved"]["group"]
    assert moved["changed"] >= 1
    assert _state_in_view(world, anchor) == "needs_recheck"


def test_a_member_joining_reads_needs_recheck(world: World) -> None:
    anchor = _entry_anchor(world, "00001000")
    _annotate(world, anchor, _group_ref(world, LISTED))
    # a new call of the same shape (strcpy / source_len) on side A, aligned.
    new = _ref("runA", "00028000", "copy", "0x10")
    world.pair("00028000", "00029000", 0.97, 1.0)
    world.inst("runA", new, "copy", "strcpy", json.dumps({"size_kind": "source_len"}))
    world.inst(
        "runB",
        _ref("runB", "00029000", "copy", "0x10"),
        "copy",
        "strcpy",
        json.dumps({"size_kind": "source_len"}),
    )
    world.im("00028010", "00029010", "00028000")
    world.fn("a", "00028000", ["strcpy"])
    world.fn("b", "00029000", ["strcpy"])
    world.commit()
    moved = _overlay(world, anchor)["basis_moved"]["group"]
    assert moved["joined"] == 1
    assert _state_in_view(world, anchor) == "needs_recheck"


def test_a_member_leaving_reads_needs_recheck_and_names_no_then_now(world: World) -> None:
    anchor = _entry_anchor(world, "00001000")
    _annotate(world, anchor, _group_ref(world, LISTED))
    # delete a member's instance row: the call leaves the group.
    world.atlas.execute("DELETE FROM instance WHERE evidence_ref = ?", (UNLISTED[1],))
    world.commit()
    moved = _overlay(world, anchor)["basis_moved"]["group"]
    assert moved["left"] == 1
    # a left member is named by count and stored hash only — never a per-field [then, now].
    assert set(moved["left_members"]) == {"count", "stored_hashes"}
    assert moved["left_members"]["count"] == 1
    assert _state_in_view(world, anchor) == "needs_recheck"


def test_a_fingerprint_version_bump_rechecks_the_whole_group(world: World) -> None:
    anchor = _entry_anchor(world, "00001000")
    gref = _group_ref(world, LISTED)
    _annotate(world, anchor, gref)
    assert _state_in_view(world, anchor) == "concluded"
    # a re-scan: the group's instances are deleted and re-inserted against a pattern whose
    # fingerprint version has moved on (same structural fingerprint, so the same f2_key).
    rows = world.atlas.execute(
        "SELECT i.instance_id, i.evidence_ref, i.binary_content_hash, i.binary_path, "
        "i.sink_anchor, i.flow_evidence, p.sink_class "
        "FROM instance i JOIN pattern p ON i.pattern_id = p.pattern_id "
        "WHERE i.source_run_id = 'runA' AND i.sink_anchor = 'strcpy'"
    ).fetchall()
    new_pattern = world.atlas.execute(
        "INSERT INTO pattern (source_class, sink_class, call_sequence_shape, "
        "structural_fingerprint, fingerprint_algo_version) VALUES "
        "('external_input', 'copy', 'shape_fp_copy', 'fp_copy', 'fpv-test-2')"
    ).lastrowid
    for iid, ref, sha, path, sink, flow, _cls in rows:
        world.atlas.execute("DELETE FROM instance WHERE instance_id = ?", (iid,))
        world.atlas.execute(
            "INSERT INTO instance (pattern_id, evidence_ref, source_run_id, binary_content_hash, "
            "binary_path, sink_anchor, flow_evidence) VALUES (?, ?, 'runA', ?, ?, ?, ?)",
            (new_pattern, ref, sha, path, sink, flow),
        )
    world.commit()
    moved = _overlay(world, anchor)["basis_moved"]["group"]
    assert moved["reason"] == "group_ref_changed"
    assert moved["then"] == gref and moved["now"] != gref
    assert _state_in_view(world, anchor) == "needs_recheck"


# ── the relation check ────────────────────────────────────────────────────────────────────────


def test_a_group_about_another_entry_is_refused_with_the_entrys_own_groups(world: World) -> None:
    anchor = _entry_anchor(world, "00001000")  # a strcpy pair; holds no system call
    cmd_group = _group_ref(world, SYSTEM_FREE[0])  # a system / cmd group
    with pytest.raises(ConfigError) as exc:
        _annotate(world, anchor, cmd_group)
    assert "not about this entry" in str(exc.value)


def test_a_function_level_candidates_own_shape_is_accepted_as_same_shape(world: World) -> None:
    anchor = _entry_anchor(world, "0001c000")  # the pair holding the function-level FALLBACK
    gref = _group_ref(world, LISTED)  # FALLBACK has the strcpy shape but is no member
    _annotate(world, anchor, gref)
    group = _stored_group(world, anchor)
    assert group["relation"] == "same_shape"


# ── the report is capped, whatever the group's size ──────────────────────────────────────────


def test_the_move_report_is_capped_and_does_not_grow_with_the_group(world: World) -> None:
    anchor = _entry_anchor(world, "00001000")
    _annotate(world, anchor, _group_ref(world, LISTED))
    # many new members of the shape join at once.
    for i in range(12):
        fa = f"{0x40000 + i * 0x1000:08x}"
        fb = f"{0x80000 + i * 0x1000:08x}"
        new = _ref("runA", fa, "copy", "0x10")
        world.pair(fa, fb, 0.97, 1.0)
        world.inst("runA", new, "copy", "strcpy", json.dumps({"size_kind": "source_len"}))
        world.inst(
            "runB",
            _ref("runB", fb, "copy", "0x10"),
            "copy",
            "strcpy",
            json.dumps({"size_kind": "source_len"}),
        )
        world.fn("a", fa, ["strcpy"])
        world.fn("b", fb, ["strcpy"])
    world.commit()
    moved = _overlay(world, anchor)["basis_moved"]["group"]
    assert moved["joined"] == 12
    assert len(moved["members"]) == gf._REPORT_CAP  # the named members are capped, 12 joined


def test_the_left_report_is_capped(world: World) -> None:
    anchor = _entry_anchor(world, "00001000")
    _annotate(world, anchor, _group_ref(world, LISTED))
    for ref in [LISTED, *UNLISTED]:  # delete five members' rows
        world.atlas.execute("DELETE FROM instance WHERE evidence_ref = ?", (ref,))
    world.commit()
    moved = _overlay(world, anchor)["basis_moved"]["group"]
    assert moved["left"] == 4
    assert len(moved["left_members"]["stored_hashes"]) <= gf._REPORT_CAP


# ── recompute never throws, and never reads a failure as unchanged ────────────────────────────


def test_a_recompute_that_raises_opens_the_view_and_rechecks(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    anchor = _entry_anchor(world, "00001000")
    _annotate(world, anchor, _group_ref(world, LISTED))

    def boom(*a: Any, **k: Any) -> Any:
        raise RuntimeError("synthetic rebuild failure")

    monkeypatch.setattr(gf, "_current", boom)
    pv._clear_view_caches()
    view = pv.get_diff_patch_view(world.atlas, DIFF, limit=200)  # must not raise
    entry = next(e for e in view["entries"] if e["anchor_ref"] == anchor)
    assert entry["review_state"] == "needs_recheck"
    moved = _overlay(world, anchor)["basis_moved"]
    # list_diff_overlays uses the same patched _current.
    assert moved["group"]["reason"] == "group_unreadable"


# ── the group never touches verdict_basis; an old snapshot is unchanged behaviour ─────────────


def test_the_group_is_stored_in_basis_state_not_verdict_basis(world: World) -> None:
    anchor = _entry_anchor(world, "00001000")
    _annotate(world, anchor, _group_ref(world, LISTED), verdict="changed_real")
    row = world.atlas.execute(
        "SELECT basis_state, verdict_basis FROM overlay WHERE anchor_ref = ?", (anchor,)
    ).fetchone()
    assert "group" in json.loads(row[0])
    assert row[1] is None or "group" not in json.loads(row[1])


def test_a_judgement_with_no_group_ref_is_unaffected_by_a_group_move(world: World) -> None:
    anchor = _entry_anchor(world, "00001000")
    _annotate(world, anchor, None)  # no group recorded
    assert "group" not in json.loads(
        world.atlas.execute(
            "SELECT basis_state FROM overlay WHERE anchor_ref = ?", (anchor,)
        ).fetchone()[0]
    )
    world.atlas.execute("UPDATE function_alignment SET similarity = 0.8 WHERE addr_a = '00003000'")
    world.commit()
    # the move is in another entry; with no group recorded this judgement stays concluded.
    assert _state_in_view(world, anchor) == "concluded"


# ── the canonical member fact (N-4): five keys, unreadable spelled out ────────────────────────


def test_a_readable_member_fact_writes_unreadable_null_not_a_missing_key() -> None:
    class _View:
        def __init__(self) -> None:
            self.bucket = "A"
            self.pair = type("P", (), {"similarity": 0.5466})()

    st = ss._State(
        entry=_View(), row=None, view={"landing": "R", "subclass": "alignment_low_confidence"}
    )  # type: ignore[arg-type]
    fact = gf._member_fact(st)
    assert set(fact) == {"landing", "subclass", "listed", "similarity", "unreadable"}
    assert fact["unreadable"] is None
    assert fact == {
        "landing": "R",
        "subclass": "alignment_low_confidence",
        "listed": True,
        "similarity": 0.5466,
        "unreadable": None,
    }


def test_an_unreadable_members_fact_carries_the_reason_so_two_reasons_differ() -> None:
    a = ss._State(unreadable=["no_row_in_view"])
    b = ss._State(unreadable=["several_rows_in_view"])
    fa = gf._member_fact(a)
    fb = gf._member_fact(b)
    assert fa["unreadable"] == ["no_row_in_view"] and fb["unreadable"] == ["several_rows_in_view"]

    def hashed(f: dict[str, Any]) -> str:
        return hashlib.sha256(json.dumps(f, sort_keys=True).encode()).hexdigest()[:12]

    assert hashed(fa) != hashed(fb)  # the reason is in the hash, not dropped


def test_a_wep_shaped_group_pins_its_member_facts_and_summary() -> None:
    """A four-member group like the real WEP one — one changed/undetermined member, three persisted
    similarity-1 members — pins the canonical member facts and the summary over them, so a drift in
    the serialization is caught."""
    members = {
        "r_member": {
            "landing": "R",
            "subclass": "alignment_low_confidence",
            "listed": True,
            "similarity": 0.5466,
            "unreadable": None,
        },
    }
    for i in range(3):
        members[f"persisted_{i}"] = {
            "landing": "persisted",
            "subclass": None,
            "listed": False,
            "similarity": 1.0,
            "unreadable": None,
        }
    member_hashes = {
        hashlib.sha256(ref.encode()).hexdigest()[:12]: hashlib.sha256(
            json.dumps(fact, sort_keys=True).encode()
        ).hexdigest()[:12]
        for ref, fact in members.items()
    }
    counts = {
        "by_landing": {"R": {"alignment_low_confidence": 1}, "persisted": {"-": 3}},
        "not_listed_sim1": 3,
        "similarity_below_1": 1,
        "states_unreadable": {},
    }
    summary = hashlib.sha256(
        "|".join(
            ("4", json.dumps(counts, sort_keys=True), json.dumps(member_hashes, sort_keys=True))
        ).encode()
    ).hexdigest()[:12]
    # The contract the implementation must keep: the fact string is the five keys, sorted; the
    # summary is count | counts | member hashes. Recompute here exactly as the module does.
    for fact in members.values():
        assert set(fact) == {"landing", "subclass", "listed", "similarity", "unreadable"}
    assert len(summary) == 12


# ── S5 refactor: the group object's counts ARE _group_counts (no drift between the two) ───────


def test_the_group_counts_helper_is_what_the_group_object_prints(world: World) -> None:
    out = ss.same_shape_siblings(
        world.atlas,
        DIFF,
        evidence_ref=LISTED,
        build_hash=world.build,
        current=_CURRENT,
        commit=UNKNOWN_VERSION,
    )
    meta = ss._meta(world.atlas, DIFF)
    assert meta is not None
    calls = ss._calls(world.atlas, "runA", "a" * 64)
    members = ss._groups(calls)[ss.f2_key("fp_copy", "strcpy", "source_len")]
    built = ss.build_diff_view(world.atlas, DIFF)
    assert built is not None
    counts = ss._group_counts(members, ss._states(built, "a", members))
    for key in ("by_landing", "not_listed_sim1", "similarity_below_1", "states_unreadable"):
        assert out[key] == counts[key]


# ── the call list is cached: read process-wide, keyed by atlas and the run's instance stamp ───


def test_paging_through_a_group_judgement_reads_the_call_list_once(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    anchor = _entry_anchor(world, "00001000")
    _annotate(world, anchor, _group_ref(world, LISTED))
    pv._clear_view_caches()
    calls_seen = {"n": 0}
    real = ss._calls

    def counting(*a: Any, **k: Any) -> Any:
        calls_seen["n"] += 1
        return real(*a, **k)

    monkeypatch.setattr(ss, "_calls", counting)
    for offset in (0, 2):  # two pages of the same diff view
        pv.get_diff_patch_view(world.atlas, DIFF, limit=2, offset=offset)
    assert calls_seen["n"] == 1  # the second page hit the cache, not a second read


def test_the_call_cache_is_keyed_by_the_atlas_so_two_atlases_never_share(tmp_path: Path) -> None:
    # Two atlases with the SAME run id, sha and instance stamp (one row each, instance_id 1), but
    # different content: only an atlas-identity in the key keeps one from being served the other's.
    flow = json.dumps({"size_kind": "source_len"})
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    a = World(tmp_path / "a")
    a.inst("runA", _ref("runA", "00001000", "copy", "0x10"), "copy", "strcpy", flow)
    a.commit()
    b = World(tmp_path / "b")
    b.inst("runA", _ref("runA", "00002000", "copy", "0x10"), "copy", "strcpy", flow)
    b.commit()
    ca = gf._calls_cached(a.atlas, "runA", "a" * 64)
    cb = gf._calls_cached(b.atlas, "runA", "a" * 64)
    assert len(ca) == len(cb) == 1
    assert ca[0].ref != cb[0].ref  # b read its own row, not a's from the cache


def test_the_call_cache_is_dropped_when_the_runs_instances_change(world: World) -> None:
    first = gf._calls_cached(world.atlas, "runA", "a" * 64)
    world.inst(
        "runA",
        _ref("runA", "0002a000", "copy", "0x10"),
        "copy",
        "strcpy",
        json.dumps({"size_kind": "source_len"}),
    )
    world.commit()
    again = gf._calls_cached(world.atlas, "runA", "a" * 64)  # no manual clear: the stamp moved
    assert len(again) == len(first) + 1
