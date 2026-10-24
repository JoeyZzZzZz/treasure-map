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


def _group_ref(w: World, ref: str, diff_id: str = DIFF) -> str:
    out = ss.same_shape_siblings(
        w.atlas,
        diff_id,
        evidence_ref=ref,
        build_hash=w.build,
        current=_CURRENT,
        commit=UNKNOWN_VERSION,
    )
    assert "group_ref" in out, out
    return str(out["group_ref"])


def _entry_anchor(w: World, needle: str, diff_id: str = DIFF) -> str:
    """The anchor_ref of the one listed entry whose anchor names ``needle`` (an address)."""
    view = pv.get_diff_patch_view(w.atlas, diff_id, limit=200)
    hits = [e["anchor_ref"] for e in view["entries"] if needle in e["anchor_ref"]]
    assert len(hits) == 1, (needle, hits)
    return hits[0]


def _annotate(
    w: World,
    anchor: str,
    group_ref: str | None,
    verdict: str = "changed_real",
    diff_id: str = DIFF,
) -> Any:
    return overlay.annotate_diff(
        w.atlas,
        diff_id=diff_id,
        anchor_ref=anchor,
        verdict=verdict,
        rationale="x: the other calls of this shape did not change; next: re-read if they move",
        group_ref=group_ref,
    )


def _refusal(w: World, anchor: str, group_ref: str) -> str:
    """The message a judgement leaning on ``group_ref`` is refused with — a ConfigError, never
    another exception and never an accepted write — after checking that nothing was written."""
    try:
        _annotate(w, anchor, group_ref)
    except Exception as exc:  # noqa: BLE001 — a refusal is a ConfigError; anything else is a bug
        assert isinstance(exc, ConfigError), f"{group_ref!r} raised {exc!r}, not a refusal"
        message = str(exc)
    else:
        raise AssertionError(f"a judgement leaning on {group_ref!r} was accepted")
    written = w.atlas.execute(
        "SELECT COUNT(*) FROM overlay WHERE anchor_ref = ?", (anchor,)
    ).fetchone()[0]
    assert written == 0
    return message


# libx's group shape: strcpy / source_len, of the fixture's ``fp_copy`` pattern.
_SRC = json.dumps({"size_kind": "source_len"})
_STRCPY_KEY = ss.f2_key("fp_copy", "strcpy", "source_len")

# A second binary of the same two runs, with its own diff (see _second_diff).
DIFF2 = "runA::runB::liby"
_SHA_Y = {"a": "5" * 64, "b": "6" * 64}


def _second_diff(w: World) -> list[str]:
    """A second diff of runA / runB, of another binary (liby), whose side A holds two calls of
    libx's group shape — the same f2_key, other calls: one in a changed pair (listed), one in an
    identical pair. Returns the two A refs."""
    w.atlas.execute(
        "INSERT INTO diff_meta (diff_id, run_a_id, run_b_id, binary_a, binary_b, sha256_a, "
        "sha256_b, diff_ok, version_skew, callsite_facts_a, callsite_facts_b, "
        "callsite_facts_hash_a, callsite_facts_hash_b, stub_state_a, stub_state_b) "
        "VALUES (?, 'runA', 'runB', 'liby', 'liby', ?, ?, 1, 0, 'read', 'read', ?, ?, "
        "'not_applicable', 'not_applicable')",
        (DIFF2, _SHA_Y["a"], _SHA_Y["b"], w.build, w.build),
    )
    binary_id = {
        side: w.adb[side]
        .execute("INSERT INTO binaries (name, sha256) VALUES ('liby', ?)", (_SHA_Y[side],))
        .lastrowid
        for side in ("a", "b")
    }
    refs = []
    for fa, fb, sim in (("00041000", "00042000", 0.8), ("00043000", "00044000", 1.0)):
        w.atlas.execute(
            "INSERT INTO function_alignment (diff_id, addr_a, addr_b, alignment_confidence, "
            "similarity, alignment_state) VALUES (?, ?, ?, 0.97, ?, 'aligned')",
            (DIFF2, fa, fb, sim),
        )
        w.atlas.execute(
            "INSERT INTO instruction_match (diff_id, func_addr_a, addr_a, addr_b) "
            "VALUES (?, ?, ?, ?)",
            (DIFF2, fa, f"{int(fa, 16) + 0x10:08x}", f"{int(fb, 16) + 0x10:08x}"),
        )
        for side, run, addr in (("a", "runA", fa), ("b", "runB", fb)):
            sha = _SHA_Y[side]
            ref = _ref(run, addr, "copy", "0x10", sha[:8])
            w.inst(run, ref, "copy", "strcpy", _SRC, sha=sha, path="/fw/lib/liby")
            w.adb[side].execute(
                "INSERT INTO functions (binary_id, name, address, callees, callees_truncated, "
                "unresolved_external_calls) VALUES (?, ?, ?, '[\"strcpy\"]', 0, '[]')",
                (binary_id[side], f"fn_{addr}", addr),
            )
            if side == "a":
                refs.append(ref)
    w.commit()
    return refs


def _rescan_strcpy_calls(w: World, *, fingerprint: str, fingerprint_version: str) -> None:
    """A re-scan of runA: its strcpy instances of the ``fp_copy`` pattern are deleted and
    re-inserted (fresh ids) against a pattern with this structural fingerprint and version."""
    rows = w.atlas.execute(
        "SELECT i.instance_id, i.evidence_ref, i.binary_content_hash, i.binary_path, "
        "i.sink_anchor, i.flow_evidence FROM instance i JOIN pattern p "
        "ON i.pattern_id = p.pattern_id WHERE i.source_run_id = 'runA' "
        "AND i.sink_anchor = 'strcpy' AND p.structural_fingerprint = 'fp_copy'"
    ).fetchall()
    assert rows
    pattern = w.atlas.execute(
        "INSERT INTO pattern (source_class, sink_class, call_sequence_shape, "
        "structural_fingerprint, fingerprint_algo_version) VALUES "
        "('external_input', 'copy', ?, ?, ?)",
        (f"shape_{fingerprint}_{fingerprint_version}", fingerprint, fingerprint_version),
    ).lastrowid
    for iid, ref, sha, path, sink, flow in rows:
        w.atlas.execute("DELETE FROM instance WHERE instance_id = ?", (iid,))
        w.atlas.execute(
            "INSERT INTO instance (pattern_id, evidence_ref, source_run_id, binary_content_hash, "
            "binary_path, sink_anchor, flow_evidence) VALUES (?, ?, 'runA', ?, ?, ?, ?)",
            (pattern, ref, sha, path, sink, flow),
        )
    w.commit()


def _review_state(w: World, anchor: str, diff_id: str = DIFF) -> str:
    """The entry's review_state, read through get_diff_patch_view with the caches as they are."""
    view = pv.get_diff_patch_view(w.atlas, diff_id, limit=200)
    for e in view["entries"]:
        if e["anchor_ref"] == anchor:
            return str(e["review_state"])
    raise AssertionError(f"{anchor!r} not listed")


def _state_in_view(w: World, anchor: str) -> str:
    pv._clear_view_caches()
    return _review_state(w, anchor)


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
    """A well-formed, current group_ref about some other entry is refused, and the refusal lists
    the groups the judged subject does belong to on that side — here the one strcpy shape of the
    entry's A call, by f2_key and group_ref — and not the group that was passed.

    MUTATION (verified RED, 1 failed): drop the relation check -> the cmd group is accepted.
    MUTATION (verified RED, 1 failed): list no groups in the refusal (``none``) -> the strcpy
    f2_key is not in it."""
    anchor = _entry_anchor(world, "00001000")  # a strcpy pair; holds no system call
    cmd_group = _group_ref(world, SYSTEM_FREE[0])  # a system / cmd group
    message = _refusal(world, anchor, cmd_group)
    assert "not about this entry" in message
    _head, sep, listing = message.partition("The shapes it does have on this side: ")
    assert sep, message
    assert _STRCPY_KEY in listing
    assert _group_ref(world, LISTED) in listing
    cmd_key = gf._f2_from_ref(cmd_group)
    assert cmd_key is not None and cmd_key not in listing


def test_a_group_ref_of_another_diff_is_refused(world: World) -> None:
    """A group_ref read on another diff of the same runs — even one of the same shape key, whose
    f2_key this diff also has a group of — is refused, naming the diff it is of.

    MUTATION (verified RED, 1 failed): skip the diff_id check -> the other diff's ref is accepted
    (this diff's group of the same key holds the entry's call)."""
    liby = _second_diff(world)
    other = _group_ref(world, liby[0], DIFF2)
    assert gf._f2_from_ref(other) == _STRCPY_KEY
    message = _refusal(world, _entry_anchor(world, "00001000"), other)
    assert f"group_ref names diff {DIFF2!r}, but this judgement is on {DIFF!r}" in message


def test_a_group_ref_of_another_recipe_version_is_refused(world: World) -> None:
    """A group_ref grouped by another recipe version (an older build's) is refused, naming the
    recipe it is of and the one this build groups by.

    MUTATION (verified RED, 1 failed): skip the recipe check -> it is accepted."""
    gref = _group_ref(world, LISTED)
    assert gref.endswith(f"/{ss.F2_RECIPE_VERSION}")
    older = gref.rsplit("/", 1)[0] + "/f2-v0"
    message = _refusal(world, _entry_anchor(world, "00001000"), older)
    assert f"group_ref is of recipe 'f2-v0', but this build groups by {ss.F2_RECIPE_VERSION!r}" in (
        message
    )


def test_a_group_ref_of_another_fingerprint_version_is_refused(world: World) -> None:
    """A group_ref read before a re-scan moved the shape's fingerprint version on (same structural
    fingerprint, so the same f2_key) is refused, naming both versions.

    MUTATION (verified RED, 1 failed): skip the fingerprint-version check -> the old ref is
    accepted."""
    gref = _group_ref(world, LISTED)
    assert "@fpv-test/" in gref
    _rescan_strcpy_calls(world, fingerprint="fp_copy", fingerprint_version="fpv-test-2")
    assert gf._f2_from_ref(_group_ref(world, LISTED)) == _STRCPY_KEY  # the shape key is unmoved
    message = _refusal(world, _entry_anchor(world, "00001000"), gref)
    assert (
        "group_ref is of fingerprint version 'fpv-test', but this build records 'fpv-test-2'"
        in message
    )


def test_a_group_ref_of_a_shape_that_is_no_group_now_is_refused(world: World) -> None:
    """A group_ref read before a re-scan gave its calls another structural fingerprint names a
    shape that is no group now: refused as such, naming the shape and side — never a crash.

    MUTATION (verified RED, 1 failed): skip the absent-shape check -> a TypeError, not a refusal
    (asserted as such)."""
    gref = _group_ref(world, LISTED)
    _rescan_strcpy_calls(world, fingerprint="fp_copy_b", fingerprint_version="fpv-test")
    assert gf._f2_from_ref(_group_ref(world, LISTED)) != _STRCPY_KEY  # the old shape is retired
    message = _refusal(world, _entry_anchor(world, "00001000"), gref)
    assert f"shape {_STRCPY_KEY!r} is no group on side 'a' of diff {DIFF!r} now" in message


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


# A four-member copy group on side A of a fresh diff: one call in a pair whose alignment could not
# be determined (R, listed, similarity 0.625), three in identical aligned pairs (persisted, not
# listed, similarity 1). The similarity is a binary-exact fraction, so its JSON is one string.
_PIN_R = _ref("runA", "00001000", "copy", "0x10")
_PIN_PERSISTED = [_ref("runA", f, "copy", "0x10") for f in ("00003000", "00005000", "00007000")]


def _four_member_copy_group(tmp_path: Path) -> World:
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.5, 0.625)
    w.inst("runA", _PIN_R, "copy", "strcpy", _SRC)
    for fa, fb in (("00003000", "00004000"), ("00005000", "00006000"), ("00007000", "00008000")):
        w.lined(fa, fb, 1.0)
    w.commit()
    return w


def test_a_four_member_copy_group_pins_its_member_facts_and_summary(
    tmp_path: Path, current: None
) -> None:
    """The stored snapshot of a four-member group, pinned whole as written by _member_fact and
    _current / group_snapshot, with every hash a literal. Every snapshot stored before an upgrade is
    compared against this serialisation: if it drifts, every judgement with a group reads
    needs_recheck at once. A deliberate change re-pins these values — and makes that mass recheck.

    MUTATION (verified RED, 1 failed): serialise a member's facts with compact separators -> its
    hashes and the summary differ. MUTATION (verified RED, 1 failed): add one character to the
    summary's basis (the member count) -> the summary differs. MUTATION (verified RED, 1 failed):
    count not_listed_sim1 one high -> the counts and the summary differ."""
    w = _four_member_copy_group(tmp_path)
    built = pv.build_diff_view(w.atlas, DIFF)
    assert built is not None
    members = ss._groups(ss._calls(w.atlas, "runA", "a" * 64)).get(_STRCPY_KEY, [])
    assert [m.ref for m in members] == [_PIN_R, *_PIN_PERSISTED]
    states = ss._states(built, "a", members)
    r_fact = {
        "landing": "R",
        "subclass": "alignment_low_confidence",
        "listed": True,
        "similarity": 0.625,
        "unreadable": None,
    }
    persisted_fact = {
        "landing": "persisted",
        "subclass": None,
        "listed": False,
        "similarity": 1.0,
        "unreadable": None,
    }
    assert gf._member_fact(states[_PIN_R]) == r_fact
    for ref in _PIN_PERSISTED:
        assert gf._member_fact(states[ref]) == persisted_fact

    # Each member's hash is over its facts' canonical JSON (sort_keys, default separators), e.g.
    # {"landing": "R", "listed": true, "similarity": 0.625, "subclass": "alignment_low_confidence",
    # "unreadable": null}; keyed by its evidence_ref's hash. The summary is over
    # "4|<counts JSON>|<member hashes JSON>". Recomputed by hand from those strings, not read back.
    pinned = {
        "group_ref": "runA::runB::libx#f2:f2acad237b9de471:a@fpv-test/f2-v1",
        "side": "a",
        "shape": {
            "structural_fingerprint": "fp_copy",
            "sink_anchor": "strcpy",
            "kind": "source_len",
        },
        "member_count": 4,
        "counts": {
            "by_landing": {"R": {"alignment_low_confidence": 1}, "persisted": {"-": 3}},
            "not_listed_sim1": 3,
            "similarity_below_1": 1,
            "states_unreadable": {},
        },
        "members": {
            "de08deba25a5": "2190d06a1fe5",  # _PIN_R: the R fact
            "6d36717c5621": "8642b32bf678",  # _PIN_PERSISTED[0]: the persisted fact
            "b60be1dc32f9": "8642b32bf678",  # _PIN_PERSISTED[1]
            "bb37ce115d43": "8642b32bf678",  # _PIN_PERSISTED[2]
        },
        "summary": "e6ea96799dca",
    }
    current_ = gf._current(w.atlas, built, "a", _STRCPY_KEY, {})
    assert current_ is not None
    snap, by_hash = current_
    assert snap == pinned
    assert {h: ref for h, (ref, _fact) in by_hash.items()} == {
        "de08deba25a5": _PIN_R,
        "6d36717c5621": _PIN_PERSISTED[0],
        "b60be1dc32f9": _PIN_PERSISTED[1],
        "bb37ce115d43": _PIN_PERSISTED[2],
    }
    assert gf.group_snapshot(w.atlas, built, "a", _STRCPY_KEY) == pinned
    assert gf.group_moved(w.atlas, built, pinned, {}) is None  # the pinned snapshot reads unmoved


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


def test_two_binaries_of_one_run_each_read_their_own_call_list(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The call-list cache is keyed by the binary's content hash too. Two diffs share runA, and on
    side A each binary has a group of the SAME shape key (strcpy / source_len) holding other calls.
    Each judgement is written by a process of its own; then one process reads both views, one after
    the other: both judgements read concluded, and each binary's call list is read once.

    MUTATION (verified RED, 1 failed): leave the content hash out of the cache key -> the second
    diff is served the first binary's call list and reads needs_recheck."""
    liby = _second_diff(world)
    anchors: dict[str, str] = {}
    for diff_id, needle, ref in ((DIFF, "00001000", LISTED), (DIFF2, "00041000", liby[0])):
        pv._clear_view_caches()  # a process of its own
        gref = _group_ref(world, ref, diff_id)
        assert gf._f2_from_ref(gref) == _STRCPY_KEY
        anchors[diff_id] = _entry_anchor(world, needle, diff_id)
        _annotate(world, anchors[diff_id], gref, diff_id=diff_id)
    libx_members = _stored_group(world, anchors[DIFF])["members"]
    liby_members = _stored_group(world, anchors[DIFF2])["members"]
    assert (len(libx_members), len(liby_members)) == (len(GROUP_A), 2)
    assert set(libx_members).isdisjoint(liby_members)  # one shape key, other calls

    pv._clear_view_caches()
    read: list[tuple[str, str]] = []
    real = ss._calls

    def counting(atlas: Any, run_id: str, sha: str) -> Any:
        read.append((run_id, sha))
        return real(atlas, run_id, sha)

    monkeypatch.setattr(ss, "_calls", counting)
    states = [_review_state(world, anchors[d], d) for d in (DIFF, DIFF2)]  # one process
    assert states == ["concluded", "concluded"]
    assert sorted(read) == [("runA", _SHA_Y["a"]), ("runA", "a" * 64)]


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


# ── annotate_diff_batch with a group_ref (T3 M-2): echo once, build the view once ─────────────


def test_batch_echoes_a_leaned_on_group_once_and_carries_the_ref(world: World) -> None:
    """Several entries of one batch leaning on the SAME group each carry only the group_ref string
    in their result; the group itself is echoed once under the top-level ``groups`` block.

    MUTATIONS (verified RED): inline the whole group echo on each result instead of a top-level
    block -> the result rows are no longer compact; key the top-level block per entry instead of
    per group_ref -> the one group is echoed three times."""
    tools = mcp_app.make_tools(world.path)
    gref = _group_ref(world, LISTED)
    anchors = [_entry_anchor(world, a) for a in _SHARING]
    out = tools["annotate_diff_batch"](
        [
            {
                "anchor_ref": a,
                "verdict": "changed_real",
                "rationale": "the shape held",
                "group_ref": gref,
            }
            for a in anchors
        ],
        diff_id=DIFF,
    )
    assert out["written"] is True, out
    for res in out["results"]:
        assert res["group_ref"] == gref and "group" not in res  # ref only on the row
    assert list(out["groups"]) == [gref]
    echoed = out["groups"][gref]
    assert echoed["group_ref"] == gref and echoed["relation"] == "own_call"
    assert echoed["member_count"] == len(GROUP_A)


def test_batch_builds_the_diff_view_once(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    """M-2: a whole batch builds the diff view once — a group-leaning item reuses the batch's built
    view, it does not rebuild it.

    MUTATION (verified RED): have the group path rebuild the view per item (annotate_group instead
    of annotate_group_on) -> build_diff_view runs more than once."""
    pv._clear_view_caches()
    calls = {"n": 0}
    real = pv.build_diff_view

    def counting(atlas: Any, diff_id: str, *a: Any, **k: Any) -> Any:
        calls["n"] += 1
        return real(atlas, diff_id, *a, **k)

    monkeypatch.setattr(pv, "build_diff_view", counting)
    monkeypatch.setattr(gf, "build_diff_view", counting)
    monkeypatch.setattr(da, "build_diff_view", counting)
    tools = mcp_app.make_tools(world.path)
    a1 = _entry_anchor(world, "00001000")
    a2 = _entry_anchor(world, "00009000")
    gref = _group_ref(world, LISTED)  # computed before counting matters (own build)
    calls["n"] = 0
    out = tools["annotate_diff_batch"](
        [
            {"anchor_ref": a1, "verdict": "changed_real", "rationale": "x", "group_ref": gref},
            {"anchor_ref": a2, "verdict": "changed_real", "rationale": "y"},
        ],
        diff_id=DIFF,
    )
    assert out["written"] is True
    assert calls["n"] == 1, calls["n"]


def test_a_group_ref_counts_as_a_checked_anchor_even_for_another_entry(world: World) -> None:
    """A group_ref used in ``checked`` proves a group was READ; it need not be about the judged
    entry (is_diff_anchor stops before the "about this entry" relation). The judged entry here is
    one the group is provably NOT about: leaning on it as a group_ref is refused.

    MUTATION (verified RED): hold a checked group_ref to the "about this entry" relation of the
    judged anchor -> the write is refused."""
    tools = mcp_app.make_tools(world.path)
    gref = _group_ref(world, LISTED)
    other = _entry_anchor(world, "00018000")  # a wrapper call's entry: no call or shape of GROUP_A
    with pytest.raises(ConfigError, match="not about this entry"):
        gf.annotate_group(world.atlas, DIFF, other, gref)
    out = tools["annotate_diff_batch"](
        [
            {
                "anchor_ref": other,
                "verdict": "no_real_change",
                "why_unchanged": "w",
                "checked": [gref],
            }
        ],
        diff_id=DIFF,
    )
    assert out["written"] is True, out


# Three entries the LISTED group is about, by both relations: two hold a call of it (own_call), one
# has its shape as a function-level candidate (same_shape).
_SHARING = ("00001000", "0000c000", "0001c000")
_SHARING_RELATION = {"00001000": "own_call", "0000c000": "own_call", "0001c000": "same_shape"}


def test_batch_rows_leaning_on_a_shared_group_equal_per_entry_writes(world: World) -> None:
    """A batch row that leaned on a group is field-for-field the row the single annotate_diff
    writes for the same inputs — the stored group snapshot included — and the group, snapshotted
    once for the batch, still carries each entry's own relation.

    MUTATION (verified RED): cache the relation with the group (per group_ref, not per entry) ->
    the same_shape entry stores own_call and differs from its single-write row."""
    tools = mcp_app.make_tools(world.path)
    gref = _group_ref(world, LISTED)
    anchors = {a: _entry_anchor(world, a) for a in _SHARING}
    cols = "verdict, rationale, attributed_to, basis_state, verdict_basis, promoted_from, run_id"

    def rows() -> dict[str, tuple[Any, ...]]:
        return {
            r[0]: tuple(r[1:])
            for r in world.atlas.execute(
                f"SELECT anchor_ref, {cols} FROM overlay WHERE anchor_kind = 'diff_subject'"  # noqa: S608
            ).fetchall()
        }

    def item(anchor: str) -> dict[str, Any]:
        return {
            "anchor_ref": anchor,
            "verdict": "changed_real",
            "rationale": "the other calls of this shape did not change",
            "group_ref": gref,
        }

    out = tools["annotate_diff_batch"]([item(a) for a in anchors.values()], diff_id=DIFF)
    assert out["written"] is True, out
    batched = rows()
    assert set(batched) == set(anchors.values())
    for addr, anchor in anchors.items():
        stored = json.loads(batched[anchor][3])
        assert stored["group"]["relation"] == _SHARING_RELATION[addr], addr
        assert tools["clear_overlay"](anchor_kind="diff_subject", anchor_ref=anchor)["cleared"] == 1
    for anchor in anchors.values():
        one = item(anchor)
        single = tools["annotate_diff"](**one, diff_id=DIFF)
        assert single["written"] is True, single
    assert rows() == batched


def test_batch_snapshots_a_shared_group_once(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    """Entries of one batch leaning on the same group_ref check and snapshot that group once; only
    the per-entry relation is worked out per entry.

    MUTATION (verified RED): give the batch no group cache -> the group is snapshotted once per
    entry."""
    tools = mcp_app.make_tools(world.path)
    gref = _group_ref(world, LISTED)
    anchors = [_entry_anchor(world, a) for a in _SHARING]
    snaps = {"n": 0}
    real = gf.group_snapshot

    def counting(*a: Any, **k: Any) -> Any:
        snaps["n"] += 1
        return real(*a, **k)

    monkeypatch.setattr(gf, "group_snapshot", counting)
    out = tools["annotate_diff_batch"](
        [
            {"anchor_ref": a, "verdict": "changed_real", "rationale": "x", "group_ref": gref}
            for a in anchors
        ],
        diff_id=DIFF,
    )
    assert out["written"] is True, out
    assert snaps["n"] == 1, snaps["n"]
