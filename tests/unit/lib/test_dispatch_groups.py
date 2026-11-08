# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""F-3 (D13) dispatch-table groups (lib/query/dispatch_groups): the navigation grouping of a pair's
must-read entries by the string-keyed edge that names their function, its member labels, its
compact report block and the report file's full table (read by lib/query/review_navigation).

Zero real data. The core tests build a tiny atlas by hand and call the grouping on hand-made member
refs; the end-to-end tests reuse the World of test_diff_review to drive ``review_pair``, the MCP
``start_diff_review`` / ``annotate_diff`` tools and ``tmap review report --md``.
"""

from __future__ import annotations

import inspect
import json
import re
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from treasure_map import mcp_app
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.query import dispatch_groups as dg
from treasure_map.lib.query import review_navigation as rn
from treasure_map.lib.query import review_report as rr
from treasure_map.lib.query import review_units as ru

# Addresses (8-hex, as the extractor normalizes them). F1/F2 are table handlers; H1 is gated by
# the dispatch function D1; U is in no table or gate.
F1A, F1B = "00001000", "00001001"
F2A, F2B = "00002000", "00002001"
H1A, H1B = "00003000", "00003001"
D1A, D1B = "00004000", "00004001"
UA, UB = "00005000", "00005001"
D2A = "00006000"  # a DIFFERENT dispatch function, in a same-short-name binary at another path
NA, NB = "00008000", "00008001"  # an app entry no table or gate names
T1, T1B = "0x7000", "0x7100"  # the table on each side (aligned by key overlap)

# diff -> (sha_a, sha_b). "app" is the diffed binary; "other" is diffed but never table-scanned.
D1 = "runA::runB::app"
DU = "runA::runB::other"
SHA = {(D1, "a"): "a" * 64, (D1, "b"): "b" * 64, (DU, "a"): "e" * 64, (DU, "b"): "f" * 64}
NAME = {D1: "app", DU: "other"}
DPATH = {D1: "/p1/app", DU: "/p3/other"}


class _Fixture:
    """Two runs, two diffs: ``app`` @/p1/app (a static table + a gate, scanned on both sides) and
    ``other`` @/p3/other (no edges, the detector never scanned it). A THIRD, non-diffed binary also
    named ``app`` sits at /p2/app with a gate on the same callee address — the short-name trap the
    path join must avoid. The detector status rows are the atlas's (as the hunt stores them beside
    the edges); no analysis.db is read."""

    def __init__(self, tmp: Path, *, scan_app: bool = True, with_sibling: bool = True) -> None:
        self.path = tmp / "atlas.db"
        self.atlas = open_atlas(self.path)
        self.atlas.execute("PRAGMA synchronous = OFF")
        for run in ("runA", "runB"):
            self.atlas.execute(
                "INSERT INTO run (run_id, hunt_commit, build_hash, hunt_instances) "
                "VALUES (?, 'c0', 'b0', 10)",
                (run,),
            )
            if scan_app:
                self.status(run, "app", "/p1/app")
        for did in (D1, DU):
            self.atlas.execute(
                "INSERT INTO diff_meta (diff_id, run_a_id, run_b_id, binary_a, binary_b, "
                "binary_path_a, binary_path_b, sha256_a, sha256_b, diff_ok, version_skew) "
                "VALUES (?, 'runA', 'runB', ?, ?, ?, ?, ?, ?, 1, 0)",
                (did, NAME[did], NAME[did], DPATH[did], DPATH[did], SHA[did, "a"], SHA[did, "b"]),
            )
        # app @/p1/app: a static table on each side (k1->F1, k2->F2, aligned by key overlap) and a
        # gate (dispatch function D1 gating H1 by k3), on both sides, D1 aligned across sides.
        self.static("runA", "app", "/p1/app", T1, [("k1", F1A), ("k2", F2A)])
        self.static("runB", "app", "/p1/app", T1B, [("k1", F1B), ("k2", F2B)])
        self.gate("runA", "app", "/p1/app", D1A, [("k3", H1A)])
        self.gate("runB", "app", "/p1/app", D1B, [("k3", H1B)])
        if with_sibling:
            # a NON-diffed binary also named 'app', at a different path, gating the SAME callee
            # address under a different dispatch function: the path join must not merge it in.
            self.gate("runA", "app", "/p2/app", D2A, [("k9", H1A)])
        # function alignment: the handlers, the gated function, and the dispatch function.
        for a, b in ((F1A, F1B), (F2A, F2B), (H1A, H1B), (D1A, D1B)):
            self.align(D1, a, b)
        self.atlas.commit()

    def status(
        self, run: str, binary: str, path: str, *, scanned: int = 1, cap_hit: int = 0
    ) -> None:
        self.atlas.execute(
            "INSERT INTO detector_scan_status (source_run_id, binary, binary_path, detector, "
            "scanned, supported_scope, unsupported_note, cap_hit, found_count) "
            "VALUES (?, ?, ?, 'string_tables', ?, 'scope_x', 'note_x', ?, 1)",
            (run, binary, path, scanned, cap_hit),
        )

    def static(
        self,
        run: str,
        binary: str,
        path: str,
        table_addr: str,
        entries: list[tuple[str, str]],
        reason: str | None = None,
    ) -> None:
        for key, callee in entries:
            self.atlas.execute(
                "INSERT INTO string_keyed_edge (source_run_id, binary, binary_path, key, "
                "mechanism, callee_addr, callee_kind, table_addr, completeness_status, "
                "completeness_reason) "
                "VALUES (?, ?, ?, ?, 'static_string_table', ?, 'direct', ?, 'incomplete', ?)",
                (run, binary, path, key, callee, table_addr, reason),
            )

    def gate(
        self, run: str, binary: str, path: str, ffa: str, entries: list[tuple[str, str]]
    ) -> None:
        for key, callee in entries:
            self.atlas.execute(
                "INSERT INTO string_keyed_edge (source_run_id, binary, binary_path, "
                "from_function, from_func_addr, key, mechanism, callee_addr, callee_kind, "
                "completeness_status) VALUES (?, ?, ?, ?, ?, ?, 'strcmp_gate', ?, 'direct', "
                "'complete')",
                (run, binary, path, f"FUN_{ffa}", ffa, key, callee),
            )

    def align(self, did: str, a: str, b: str, state: str = "aligned") -> None:
        self.atlas.execute(
            "INSERT INTO function_alignment (diff_id, addr_a, addr_b, alignment_confidence, "
            "similarity, alignment_state) VALUES (?, ?, ?, 0.97, 0.9, ?)",
            (did, a, b, state),
        )

    def sql(self, statement: str, *args: Any) -> None:
        self.atlas.execute(statement, args)
        self.atlas.commit()


def _members() -> list[dg.MemberRef]:
    return [
        dg.MemberRef(D1, f"pair:{F1A}:{F1B}", f"anc:{F1A}", "entry", F1A, F1B),
        dg.MemberRef(D1, f"pair:{F2A}:{F2B}", f"anc:{F2A}", "entry", F2A, F2B),
        dg.MemberRef(D1, f"pair:{H1A}:{H1B}", f"anc:{H1A}", "callee_group", H1A, H1B),
        dg.MemberRef(DU, f"pair:{UA}:{UB}", f"anc:{UA}", "entry", UA, UB),
    ]


H1 = dg.MemberRef(D1, f"pair:{H1A}:{H1B}", f"anc:{H1A}", "entry", H1A, H1B)
F1 = f"pair:{F1A}:{F1B}"


def _by_mech(pd: dg.PairDispatch, mech: str) -> list[dg.DispatchGroup]:
    return [g for g in pd.groups if g.mechanism == mech]


# ── the grouping ────────────────────────────────────────────────────────────────────────────────


def test_table_group_gate_group_and_uncovered_bucket(tmp_path: Path) -> None:
    """★ A table T {k1->F1, k2->F2} groups F1 and F2 (the table, not the key); a gate dispatch
    function D1 gating H1 groups H1 under D1 (the dispatch function, aligned across both sides); an
    entry whose binary the detector never scanned falls to the explicit uncovered bucket, counted
    on each side. H1's unit is a callee group, so it is counted co-grouped.

    MUTATION (verified RED, 3 failed): group static edges by key not table (the static
    ``join(STATIC, ...)`` anchors replaced by ``(keys[0] if keys else None, None)``) -> F1/F2
    split into two size-1 groups -> RED.
    MUTATION (verified RED, 2 failed): drop the uncovered bucket (``uncovered.append(mem)`` ->
    ``pass``) -> RED.
    MUTATION (verified RED, 7 failed): group gates by key (the gate ``anchors`` replaced by
    ``((gv["keys"] or [None])[0], None)``) -> the gate group's anchors are the key -> RED."""
    fx = _Fixture(tmp_path)
    pd = dg.compute_pair(fx.atlas, "runA", "runB", _members())

    tgroups = _by_mech(pd, dg.STATIC)
    assert len(tgroups) == 1
    tg = tgroups[0]
    assert set(tg.members) == {F1, f"pair:{F2A}:{F2B}"}
    assert (tg.a_anchor, tg.b_anchor) == (T1, T1B)
    # the key is a member label only, not the group key; given per side
    assert tg.members[F1] == {"a": ["k1"], "b": ["k1"]}

    ggroups = _by_mech(pd, dg.GATE)
    # exactly one gate group for H1 (app's D1), NOT the same-named sibling's D2 at another path
    # (see the short-name test); the two sides' dispatch functions are aligned into one group.
    h1_groups = [g for g in ggroups if H1.entry_id in g.members]
    assert len(h1_groups) == 1
    gg = h1_groups[0]
    assert set(gg.members) == {H1.entry_id}
    assert (gg.a_anchor, gg.b_anchor) == (D1A, D1B)
    assert gg.members[H1.entry_id] == {"a": ["k3"], "b": ["k3"]}

    assert pd.also_in_callee_group == 1  # H1's unit is a callee group
    assert pd.grouped_members == 3  # F1, F2, H1

    assert [m.entry_id for m in pd.uncovered] == [f"pair:{UA}:{UB}"]
    assert pd.uncovered_by_detector == {
        "a": {"static_table_detector_did_not_run": 1},
        "b": {"static_table_detector_did_not_run": 1},
    }


def test_gate_dispatch_functions_are_aligned_across_the_two_sides(tmp_path: Path) -> None:
    """★ A gate's two sides are one group when aligned by function alignment: with D1A<->D1B
    aligned, H1 (pair:H1A:H1B) is in ONE gate group; with alignment off it is two (one per side).

    MUTATION (verified RED, 7 failed): force the unaligned path by replacing
    ``if align_dispatchers:`` with ``if False:`` -> the aligned call makes one group per side ->
    the ``== 1`` assertion reddens."""
    fx = _Fixture(tmp_path, with_sibling=False)
    aligned = dg.compute_pair(fx.atlas, "runA", "runB", [H1], align_dispatchers=True)
    assert len([g for g in aligned.groups if g.mechanism == dg.GATE]) == 1

    unaligned = dg.compute_pair(fx.atlas, "runA", "runB", [H1], align_dispatchers=False)
    assert len([g for g in unaligned.groups if g.mechanism == dg.GATE]) == 2


def test_the_join_is_by_binary_path_not_the_short_name(tmp_path: Path) -> None:
    """★ The diffed ``app`` @/p1/app and a non-diffed binary also named ``app`` @/p2/app share the
    short name; the sibling gates the SAME callee address H1A under a different dispatch function,
    and holds a static table at the SAME address as T1 naming F1A by another key. Joining by path,
    H1 is in exactly one gate group (its own D1) and F1 is labelled by its own key only. Joining by
    short name would merge the two binaries' edges.

    MUTATION (verified RED, 6 failed): in ``_gates`` SELECT the short ``binary`` column, drop the
    ``AND binary_path IN (...)`` filter and index ``out[binary]``, and look it up by
    ``dm['binary_a']`` in compute_pair -> H1 picks up the sibling's dispatcher -> RED.
    MUTATION (verified RED, 1 failed): the same in ``_static_tables`` (SELECT ``binary``, no path
    filter, ``tables[s].get(dm["binary_a"])``) -> F1's A keys read ["k1", "k8"] -> RED."""
    fx = _Fixture(tmp_path, with_sibling=True)
    fx.static("runA", "app", "/p2/app", T1, [("k8", F1A)])
    fx.atlas.commit()
    members = [
        dg.MemberRef(D1, H1.entry_id, H1.anchor_ref, "callee_group", H1A, H1B),
        dg.MemberRef(D1, F1, f"anc:{F1A}", "entry", F1A, F1B),
    ]
    pd = dg.compute_pair(fx.atlas, "runA", "runB", members)
    gate = [g for g in pd.groups if g.mechanism == dg.GATE]
    assert len(gate) == 1
    assert (gate[0].a_anchor, gate[0].b_anchor) == (D1A, D1B)
    (table,) = _by_mech(pd, dg.STATIC)
    assert table.members[F1] == {"a": ["k1"], "b": ["k1"]}, table.members


# ── two sides, each read on its own (F3-2) ──────────────────────────────────────────────────────


def test_a_gate_enumerated_on_one_side_only_is_never_shown_as_both(tmp_path: Path) -> None:
    """★ D1A gates H1 on A; on B, D1A's aligned function D1B gates nothing (no stored edge): the
    group's B dispatch function is null, ``counterpart_enumerates`` false with D1B as the
    counterpart, and H1's B keys are empty — one side enumerated never reads as both.

    MUTATION (verified RED, 1 failed): take the aligned function as the other side's anchor
    whether or not it is a stored dispatch function there (``there = cp if cp is not None and cp
    in named else None`` -> ``there = cp``) -> the group names D1B -> RED."""
    fx = _Fixture(tmp_path, with_sibling=False)
    fx.sql("DELETE FROM string_keyed_edge WHERE source_run_id = 'runB' AND mechanism = ?", dg.GATE)
    pd = dg.compute_pair(fx.atlas, "runA", "runB", [H1])
    (g,) = _by_mech(pd, dg.GATE)
    assert (g.a_anchor, g.b_anchor) == (D1A, None)
    assert g.members[H1.entry_id] == {"a": ["k3"], "b": []}
    j = dg.group_json(g)
    assert j.get("dispatch_function") == {"a": D1A, "b": None}, j
    assert j.get("counterpart_enumerates") is False and j.get("counterpart") == D1B, j
    (label,) = dg.member_labels(pd)[(D1, H1.entry_id)]
    assert label.get("keys") == {"a": ["k3"], "b": []}, label


def test_an_undetermined_pairing_joins_no_two_sides(tmp_path: Path) -> None:
    """★ D1A and D1B paired only ``alignment_undetermined``: no alignment, so the two sides'
    dispatch functions are two one-sided groups, each null on the other side.

    MUTATION (verified RED, 1 failed): drop ``alignment_state = 'aligned'`` from ``_alignment``'s
    query -> the undetermined pairing merges the two -> one group -> RED."""
    fx = _Fixture(tmp_path, with_sibling=False)
    fx.sql(
        "UPDATE function_alignment SET alignment_state = 'alignment_undetermined' WHERE addr_a = ?",
        D1A,
    )
    pd = dg.compute_pair(fx.atlas, "runA", "runB", [H1])
    anchors = sorted(((g.a_anchor or "-"), (g.b_anchor or "-")) for g in _by_mech(pd, dg.GATE))
    assert anchors == [("-", D1B), (D1A, "-")], anchors
    assert all(not g.counterpart_enumerates for g in pd.groups)


def test_the_keys_of_a_member_are_given_per_side(tmp_path: Path) -> None:
    """★ H1 gated by k3 on A and by k4 on B (one aligned dispatch function): its label carries
    ``{"a": ["k3"], "b": ["k4"]}`` — a key that changed sides stays visible, and the label is the
    fixture's keys exactly.

    MUTATION (verified RED, 4 failed): the label's keys emptied (``"keys": {s: keys[s][:N] ...}``
    -> ``"keys": {"a": [], "b": []}``) -> RED.
    MUTATION (verified RED, 5 failed): one key list for both sides (``per_side[side]`` ->
    ``per_side["a"]`` in ``join``) -> RED."""
    fx = _Fixture(tmp_path, with_sibling=False)
    fx.sql("UPDATE string_keyed_edge SET key = 'k4' WHERE source_run_id = 'runB' AND key = 'k3'")
    pd = dg.compute_pair(fx.atlas, "runA", "runB", [H1])
    (label,) = dg.member_labels(pd)[(D1, H1.entry_id)]
    assert label.get("keys") == {"a": ["k3"], "b": ["k4"]}, label
    assert label.get("mechanism") == dg.GATE and label.get("group_members") == 1, label
    (g,) = pd.groups
    assert label.get("group_ref") == g.ref == dg.group_ref(D1, dg.GATE, D1A)


def test_two_tables_align_only_on_half_their_keys(tmp_path: Path) -> None:
    """Tables align when they share >= half the smaller key set: 2 of 3 keys align, 1 of 3 does
    not.

    MUTATION (verified RED, 1 failed): require every key of the larger set (``0.5 * min(...)`` ->
    ``1.0 * max(...)``) -> the 2/3 pair is not aligned -> RED.
    MUTATION (verified RED, 1 failed): align on any one shared key (``if overlap:``) -> the 1/3
    pair aligns -> RED."""

    def table(*keys: str) -> dict[str, dict[str, Any]]:
        return {"t": {"handlers": set(), "keys": {f"h{k}": [k] for k in keys}, "reasons": set()}}

    assert dg._align_tables(table("k1", "k2", "k3"), table("k1", "k2", "z")) == {"t": "t"}
    assert dg._align_tables(table("k1", "k2", "k3"), table("k1", "y", "z")) == {}


@pytest.mark.parametrize("side", ["a", "b"])
def test_a_table_with_no_aligned_counterpart_is_null_on_that_side(
    tmp_path: Path, side: str
) -> None:
    """★ A static table stored on one side only (the other side's table rows gone): the group is
    that side's table and null on the other, ``counterpart_enumerates`` false, the report table's
    other side null and F1's keys there empty — a table one side enumerates is never shown as both
    sides' table.

    MUTATION (verified RED, 2 failed): an unaligned A table takes itself as the B anchor too
    (``(table_addr, None) if s == "a"`` -> ``(table_addr, table_addr) if s == "a"``) -> RED.
    MUTATION (verified RED, 1 failed): the mirror on B (``else (None, table_addr)`` -> ``else
    (table_addr, table_addr)``) -> RED."""
    fx = _Fixture(tmp_path, with_sibling=False)
    fx.sql("DELETE FROM string_keyed_edge WHERE table_addr = ?", T1B if side == "a" else T1)
    member = dg.MemberRef(D1, F1, f"anc:{F1A}", "entry", F1A, F1B)
    pd = dg.compute_pair(fx.atlas, "runA", "runB", [member])
    (g,) = _by_mech(pd, dg.STATIC)
    want = (T1, None) if side == "a" else (None, T1B)
    assert (g.a_anchor, g.b_anchor) == want
    j = dg.group_json(g)
    assert j.get("table") == dict(zip(("a", "b"), want, strict=True)), j
    assert j.get("counterpart_enumerates") is False, j
    keys = {"a": ["k1"], "b": []} if side == "a" else {"a": [], "b": ["k1"]}
    assert g.members[F1] == keys, g.members


# ── a table split into pieces on one side, whole on the other ───────────────────────────────────

F2 = f"pair:{F2A}:{F2B}"
T1P = "0x7050"  # the second piece of the A table (or of the B table, mirrored)


def _split_members() -> list[dg.MemberRef]:
    return [
        dg.MemberRef(D1, F1, f"anc:{F1A}", "entry", F1A, F1B),
        dg.MemberRef(D1, F2, f"anc:{F2A}", "entry", F2A, F2B),
    ]


def _split_side(fx: _Fixture, side: str, *, split: bool = True) -> str:
    """Cut ``side``'s table {k1, k2} into two pieces {k1} and {k2} (the second at T1P), both stored
    as split by an undefined handler when ``split``; the other side keeps the whole table."""
    run, table, f2 = ("runA", T1, F2A) if side == "a" else ("runB", T1B, F2B)
    reason = "split_by_undefined_handler" if split else None
    fx.sql("DELETE FROM string_keyed_edge WHERE table_addr = ? AND key = 'k2'", table)
    fx.sql(
        "UPDATE string_keyed_edge SET completeness_reason = ? WHERE table_addr = ?", reason, table
    )
    fx.static(run, "app", "/p1/app", T1P, [("k2", f2)], reason)
    fx.atlas.commit()
    return table


@pytest.mark.parametrize("side", ["a", "b"])
def test_split_pieces_on_one_side_join_the_whole_table_of_the_other(
    tmp_path: Path, side: str
) -> None:
    """★ One side's table is split by an undefined handler into the pieces {k1->F1} and {k2->F2};
    the other side holds the whole table {k1, k2}. Every key of both pieces is enumerated by the
    whole table, so F1 and F2 are ONE two-sided group (its pieces listed on the split side), and
    neither reads 'the other side enumerates nothing' — on either side.

    MUTATION (verified RED, 2 failed): pieces aligned one to one only (the split-piece pass's
    ``if addr in paired[side] or _SPLIT not in table["reasons"]:`` -> ``if True:``) -> one piece is
    a one-sided group -> RED.
    MUTATION (verified RED, 1 failed): the split pass on the A side only (``(("a", ta, tb), ("b",
    tb, ta))`` -> ``(("a", ta, tb),)``) -> the B-split case reddens.
    MUTATION (verified RED, 2 failed): ``table_pieces`` never shown (``if any(len(g.pieces[s]) > 1
    ...)`` -> ``if False:``) -> RED."""
    fx = _Fixture(tmp_path, with_sibling=False)
    piece = _split_side(fx, side)
    pd = dg.compute_pair(fx.atlas, "runA", "runB", _split_members())
    groups = _by_mech(pd, dg.STATIC)
    assert [(g.counterpart_enumerates, sorted(g.members)) for g in groups] == [
        (True, sorted([F1, F2]))
    ], [(g.a_anchor, g.b_anchor, g.members) for g in groups]
    (g,) = groups
    assert g.members[F1] == {"a": ["k1"], "b": ["k1"]}, g.members
    assert g.members[F2] == {"a": ["k2"], "b": ["k2"]}, g.members
    whole = T1B if side == "a" else T1
    other = "b" if side == "a" else "a"
    j = dg.group_json(g)
    assert j.get("table_pieces") == {side: sorted([piece, T1P]), other: [whole]}, j
    assert (j.get("completeness") or {}).get("split_by_undefined_handler") is True, j
    assert pd.grouped_members == 2


def test_an_unaligned_table_not_stored_as_split_stays_one_to_one(tmp_path: Path) -> None:
    """★ The same two pieces on A, but neither stored as split by an undefined handler: they are
    two tables, aligned one to one, so only one of them joins B's table and the other is a
    one-sided group — only a stored split joins many tables to one.

    MUTATION (verified RED, 1 failed): any unaligned table joins (the split-piece pass's ``or _SPLIT
    not in table["reasons"]`` dropped) -> both pieces join B's table -> RED."""
    fx = _Fixture(tmp_path, with_sibling=False)
    _split_side(fx, "a", split=False)
    pd = dg.compute_pair(fx.atlas, "runA", "runB", _split_members())
    shape = sorted((g.b_anchor is not None, len(g.members)) for g in _by_mech(pd, dg.STATIC))
    assert shape == [(False, 1), (True, 2)], shape
    assert all("table_pieces" not in dg.group_json(g) for g in pd.groups)


# ── the stored completeness, read as a set (F3-1) ───────────────────────────────────────────────


def test_a_split_table_is_flagged_whatever_else_its_reason_holds(tmp_path: Path) -> None:
    """★ ``completeness_reason`` is a comma-joined set. A table whose reason is
    ``handler_undefined,split_by_undefined_handler`` and one whose reason is
    ``split_by_undefined_handler`` alone are both shown split, and the first names
    ``handler_undefined`` too.

    MUTATION (verified RED, 1 failed): keep the stored string whole (``_reasons`` -> ``{reason}``)
    -> the combined table reads not split -> RED.
    MUTATION (verified RED, 1 failed): ``"split_by_undefined_handler": False`` in group_json -> RED.
    MUTATION (verified RED, 1 failed): never show completeness (``if g.completeness_reasons:`` ->
    ``if False:``) -> RED."""
    fx = _Fixture(tmp_path)
    fx.sql(
        "UPDATE string_keyed_edge SET completeness_reason = ? WHERE table_addr = ?",
        "handler_undefined,split_by_undefined_handler",
        T1,
    )
    fx.sql("DELETE FROM string_keyed_edge WHERE table_addr = ?", T1B)
    fx.static("runA", "other", "/p3/other", "0x7200", [("k7", UA)], "split_by_undefined_handler")
    fx.atlas.commit()
    pd = dg.compute_pair(fx.atlas, "runA", "runB", _members())
    shown = {g.a_anchor: dg.group_json(g) for g in _by_mech(pd, dg.STATIC)}
    assert set(shown) == {T1, "0x7200"}, shown
    for j in shown.values():
        assert (j.get("completeness") or {}).get("split_by_undefined_handler") is True, j
    assert "handler_undefined" in shown[T1]["completeness"]["reasons"], shown[T1]


# ── the uncovered bucket, per side (MINOR-1/3) and its honest tiers (M4/M5/M6) ──────────────────


def test_an_entry_no_edge_names_in_a_scanned_binary_with_edges_is_said_so(tmp_path: Path) -> None:
    """N, an app entry no table or gate names: app was scanned (the atlas status row) and holds
    edges -> ``binary_has_edges_entry_not_a_member`` on each side, never 'none found'. With A's scan
    capped, side a reads ``static_table_scan_capped``.

    MUTATION (verified RED, 2 failed): the has-edges branch collapsed (``return
    "binary_has_edges_entry_not_a_member"`` -> ``return "scanned_no_static_table_found"``) -> RED.
    MUTATION (verified RED, 2 failed): the cap branch collapsed (``return
    "static_table_scan_capped"`` -> ``return "scanned_no_static_table_found"``) -> RED.
    MUTATION (verified RED, 3 failed): the atlas status rows not read (the query's ``detector =
    'string_tables'`` -> ``detector = 'none'``, as the old analysis.db-by-hash reader finds none
    here) -> did_not_run -> RED."""
    member = dg.MemberRef(D1, f"pair:{NA}:{NB}", f"anc:{NA}", "entry", NA, NB)
    fx = _Fixture(tmp_path)
    pd = dg.compute_pair(fx.atlas, "runA", "runB", [member])
    assert pd.uncovered_by_detector == {
        "a": {"binary_has_edges_entry_not_a_member": 1},
        "b": {"binary_has_edges_entry_not_a_member": 1},
    }
    fx.sql("UPDATE detector_scan_status SET cap_hit = 1 WHERE source_run_id = 'runA'")
    capped = dg.compute_pair(fx.atlas, "runA", "runB", [member])
    assert capped.uncovered_by_detector.get("a") == {"static_table_scan_capped": 1}


def test_the_uncovered_bucket_is_counted_on_each_side(tmp_path: Path) -> None:
    """★ U's A binary was scanned and found nothing; its B binary has no status: side a reads
    ``scanned_no_static_table_found``, side b ``static_table_detector_did_not_run`` — the B side's
    less certain tier is never hidden behind A's.

    MUTATION (verified RED, 3 failed): count the A side only (``for s in SIDES`` in the uncovered
    count -> ``for s in ("a",)``) -> side b missing -> RED.
    MUTATION (verified RED, 3 failed): an unscanned binary read as scanned (``return
    "static_table_detector_did_not_run"`` -> ``return "scanned_no_static_table_found"``) -> RED."""
    fx = _Fixture(tmp_path)
    fx.status("runA", "other", "/p3/other")
    fx.atlas.commit()
    pd = dg.compute_pair(fx.atlas, "runA", "runB", _members())
    assert pd.uncovered_by_detector == {
        "a": {"scanned_no_static_table_found": 1},
        "b": {"static_table_detector_did_not_run": 1},
    }


def test_two_status_rows_for_one_path_read_as_not_run(tmp_path: Path) -> None:
    """★ The atlas stores one detector status row per (run, binary); two rows for one path cannot
    say which scan is true, so that side reads ``static_table_detector_did_not_run`` (no status),
    never the scanned tier of either row; the other side keeps its own.

    MUTATION (verified RED, 1 failed): keep the last of the duplicate rows (``if n > 1:`` ->
    ``if False:`` in ``_detector_statuses``) -> side a reads the scanned tier -> RED."""
    member = dg.MemberRef(D1, f"pair:{NA}:{NB}", f"anc:{NA}", "entry", NA, NB)
    fx = _Fixture(tmp_path)
    fx.status("runA", "app", "/p1/app")
    fx.atlas.commit()
    pd = dg.compute_pair(fx.atlas, "runA", "runB", [member])
    assert pd.uncovered_by_detector == {
        "a": {"static_table_detector_did_not_run": 1},
        "b": {"binary_has_edges_entry_not_a_member": 1},
    }
    assert pd.detector_statuses.get((D1, "a"), "missing") is None


def test_a_member_label_counts_the_keys_it_leaves_out_per_side(tmp_path: Path) -> None:
    """★ A member label shows at most MAX_KEYS_PER_MEMBER keys a side and counts the rest per side:
    F1 named by four A keys and one B key reads three A keys and ``keys_omitted`` {"a": 1, "b": 0}.

    MUTATION (verified RED, 1 failed): never count the cut (``if any(n > 0 for n in
    cut.values()):`` -> ``if False:``) -> RED."""
    fx = _Fixture(tmp_path, with_sibling=False)
    extra = [f"k{i}" for i in range(5, 5 + dg.MAX_KEYS_PER_MEMBER)]
    fx.static("runA", "app", "/p1/app", T1, [(k, F1A) for k in extra])
    fx.atlas.commit()
    member = dg.MemberRef(D1, F1, f"anc:{F1A}", "entry", F1A, F1B)
    pd = dg.compute_pair(fx.atlas, "runA", "runB", [member])
    (label,) = dg.member_labels(pd)[(D1, F1)]
    shown = sorted(["k1", *extra])
    assert label.get("keys") == {"a": shown[: dg.MAX_KEYS_PER_MEMBER], "b": ["k1"]}, label
    assert label.get("keys_omitted") == {"a": len(shown) - dg.MAX_KEYS_PER_MEMBER, "b": 0}, label
    assert label.get("keys_omitted") == {"a": 1, "b": 0}, label


def test_the_members_are_taken_from_every_kind_of_unit() -> None:
    """★ A must-read entry is grouped whatever unit holds it — an entry unit, an S batch, a callee
    group — and only must-read entry members are taken.

    MUTATION (verified RED, 2 failed): take entry units only (``or u.kind != "entry"`` in
    members_from_units) -> the batch's and the group's members are lost -> RED."""

    def member(eid: str, must_read: bool = True, kind: str = "entry") -> Any:
        return SimpleNamespace(
            kind=kind, must_read=must_read, entry_id=eid, stream=D1, anchor_ref=f"anc:{eid}"
        )

    units = [
        SimpleNamespace(kind="entry", members=[member(f"pair:{F1A}:{F1B}")]),
        SimpleNamespace(
            kind="s_batch", members=[member(f"pair:{F2A}:{F2B}"), member("a:x", False)]
        ),
        SimpleNamespace(kind="callee_group", members=[member(f"pair:{H1A}:{H1B}")]),
        SimpleNamespace(kind="binary_presence", members=[member("p", kind="function")]),
    ]
    got = [(m.unit_kind, m.entry_id) for m in dg.members_from_units(units)]
    assert got == [
        ("entry", f"pair:{F1A}:{F1B}"),
        ("s_batch", f"pair:{F2A}:{F2B}"),
        ("callee_group", f"pair:{H1A}:{H1B}"),
    ]


# ── the compact block and the neutral wording ───────────────────────────────────────────────────


def test_the_report_block_is_counts_and_refs_only(tmp_path: Path) -> None:
    """★ The block carries counts, the refs of the largest groups (at most LARGEST_SHOWN), the
    uncovered counts per side and the detector's scope — no member list — and stays small.

    MUTATION (verified RED, 1 failed): drop the ``[:LARGEST_SHOWN]`` cut -> RED."""
    fx = _Fixture(tmp_path)
    # more groups than the cut: four one-entry gate groups
    members = []
    for i in range(4):
        callee, ffa = f"0000a{i}00", f"0000b{i}00"
        fx.gate("runA", "app", "/p1/app", ffa, [(f"g{i}", callee)])
        members.append(dg.MemberRef(D1, f"a:{callee}", f"anc:{callee}", "entry", callee, None))
    fx.atlas.commit()
    pd = dg.compute_pair(fx.atlas, "runA", "runB", [*_members(), *members])
    block = dg.report_block(pd)
    assert len(pd.groups) > dg.LARGEST_SHOWN
    assert [x["group_ref"] for x in block["largest"]] == [g.ref for g in pd.groups][:3]
    assert "groups" not in block and "entry_id" not in json.dumps(block)
    assert block["static_table_detector"]["supported_scope"] == ["scope_x"]
    assert block["gate_groups"]["one_sided"] == 4
    assert len(json.dumps(block)) <= 1_500, len(json.dumps(block))


# The words a dispatch group's authored text must never carry (a reachability / verdict claim).
# Kept in the test, not the shipped module: the module's own source stays neutral-scan clean.
_FORBIDDEN_WORDS = (
    "reachable",
    "reachability",
    "unreachable",
    "routed",
    "reaches",
    "dispatched to",
    "vulnerable",
    "exploitable",
    "malicious",
    "benign",
    "safe",
    "blocked",
    "patched",
)
_NEGATION = re.compile(r"\b(never|not|no|nor)\b")


def _hits(text: str) -> list[tuple[str, int]]:
    low = text.lower()
    return [
        (w, m.start()) for w in _FORBIDDEN_WORDS for m in re.finditer(rf"\b{re.escape(w)}\b", low)
    ]


def test_no_group_text_carries_a_reachability_or_verdict_word(tmp_path: Path) -> None:
    """★ The iron law: a string-keyed edge is an enumerated fact, never a reachability verdict. No
    code-authored note, block string or bucket name may contain a reachability or judgement word;
    the module's and the navigation reader's docstrings may name one only to deny it (a negation
    within the eight words before it).

    MUTATION (verified RED, 1 failed): put 'reachable' in NOTE_GATE -> RED.
    MUTATION (verified RED, 2 failed): rename the last bucket ``_detector_bucket`` returns to
    ``scanned_safe_no_table`` -> RED.
    MUTATION (verified RED, 1 failed): write 'the handler is routed to here' in a dispatch_groups
    function docstring -> RED."""
    fx = _Fixture(tmp_path)
    pd = dg.compute_pair(fx.atlas, "runA", "runB", _members())
    block = dg.report_block(pd)

    def strings(x: Any) -> list[str]:
        if isinstance(x, str):
            return [x]
        if isinstance(x, dict):
            return [s for k, v in x.items() for s in [k, *strings(v)]]
        if isinstance(x, list):
            return [s for v in x for s in strings(v)]
        return []

    shown = [s for s in strings(block) if "#dispatch:" not in s]  # refs carry firmware data
    shown += [dg.group_json(g)["note"] for g in pd.groups]
    # every bucket the classifier can name is a listed (scanned) bucket
    states = ({"scanned": True, "cap_hit": True}, {"scanned": True}, {"scanned": False}, None)
    named = {dg._detector_bucket(st, edges) for st in states for edges in (True, False)}
    assert named == set(dg.BUCKETS), named
    strict = [*shown, *dg.NEUTRAL_TEXTS, *dg.BUCKETS]
    for text in strict:
        assert not _hits(text), (text, _hits(text))
    docs = [inspect.getdoc(dg) or "", inspect.getdoc(rn) or ""]
    for mod in (dg, rn):
        for _n, obj in inspect.getmembers(
            mod, lambda o: inspect.isfunction(o) or inspect.isclass(o)
        ):
            if getattr(obj, "__module__", None) == mod.__name__:
                docs.append(inspect.getdoc(obj) or "")
    for doc in docs:
        for word, at in _hits(doc):
            before = " ".join(doc[:at].lower().split()[-8:])
            assert _NEGATION.search(before), (word, doc[max(0, at - 80) : at + 40])


# ── read on demand, never failing the review (MINOR-4/5) ────────────────────────────────────────


def _e2e_world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    from tests.unit.lib.test_diff_review import DX, World

    ru.DIFF_CACHE.clear()
    w = World(tmp_path, monkeypatch)
    for a, b in ((F1A, F1B), (F2A, F2B), (H1A, H1B), (D1A, D1B)):
        w.pair(DX, a, b)
    _edges(w, DX)
    return w


def _edges(w: Any, diff_id: str) -> None:
    """The table {k1->F1, k2->F2} and the gate D1 -> H1 on both sides of ``diff_id``'s binary."""
    w.atlas.execute(
        "UPDATE diff_meta SET binary_path_a='/p1/libx', binary_path_b='/p1/libx' WHERE diff_id=?",
        (diff_id,),
    )

    def static(run: str, table: str, entries: list[tuple[str, str]]) -> None:
        for key, callee in entries:
            w.atlas.execute(
                "INSERT INTO string_keyed_edge (source_run_id, binary, binary_path, key, "
                "mechanism, callee_addr, callee_kind, table_addr, completeness_status) VALUES "
                "(?, 'libx', '/p1/libx', ?, 'static_string_table', ?, 'direct', ?, 'incomplete')",
                (run, key, callee, table),
            )

    def gate(run: str, ffa: str, callee: str) -> None:
        w.atlas.execute(
            "INSERT INTO string_keyed_edge (source_run_id, binary, binary_path, from_function, "
            "from_func_addr, key, mechanism, callee_addr, callee_kind, completeness_status) VALUES "
            "(?, 'libx', '/p1/libx', ?, ?, 'k3', 'strcmp_gate', ?, 'direct', 'complete')",
            (run, f"FUN_{ffa}", ffa, callee),
        )

    static("runA", T1, [("k1", F1A), ("k2", F2A)])
    static("runB", T1B, [("k1", F1B), ("k2", F2B)])
    gate("runA", D1A, H1A)
    gate("runB", D1B, H1B)
    w.atlas.commit()


def _review(w: Any, k: int = 50, **kw: Any) -> ru.PairReview:
    return ru.review_pair(
        w.atlas,
        "runA",
        "runB",
        k=k,
        pair_staleness={"source_stale": False, "source_stale_reason": None},
        server_commit=None,
        **kw,
    )


def _entry_members(units: list[ru.Unit]) -> set[tuple[str, str]]:
    return {
        (m.stream, str(m.entry_id))
        for u in units
        for m in u.members
        if m.kind == "entry" and m.must_read and m.entry_id
    }


def test_grouping_moves_no_unit_id_or_must_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ The grouping is a view annotation: the unit list, the unit ids and the must-read set are
    byte-for-byte the same as units cut from the facts alone, read with or without navigation; the
    grouped and the uncovered members are exactly the must-read entry members of the units.

    MUTATION (verified RED, 2 failed): make the hook drop a unit (``units.pop()`` before
    ``_nav.read``) -> the unit list diverges from the facts-only cut -> RED."""
    w = _e2e_world(tmp_path, monkeypatch)
    facts = ru.pair_facts(w.atlas, "runA", "runB")

    def shape(units: list[ru.Unit]) -> set[tuple[Any, ...]]:
        return {
            (u.unit_id, u.kind, u.must_read, tuple(sorted(m.anchor_ref for m in u.members)))
            for u in units
        }

    review = _review(w, navigation=True)
    assert shape(review.units) == shape(ru.cut_units(facts, 50)) == shape(_review(w).units)
    pd = review.navigation.dispatch
    assert pd is not None
    grouped = set(pd.member_mechanisms)
    uncovered = {(m.diff_id, m.entry_id) for m in pd.uncovered}
    assert grouped | uncovered == _entry_members(review.units) and not grouped & uncovered
    assert {F1, f"pair:{F2A}:{F2B}", H1.entry_id} <= {eid for _d, eid in grouped}


def test_the_navigation_is_read_only_when_asked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MINOR-4: a reading of the pair without ``navigation`` computes no dispatch groups (the
    driver, the judge and the write planner read pairs often and show none); with it, the report
    carries both blocks.

    MUTATION (verified RED, 1 failed): ``navigation: bool = False`` -> ``True`` in review_pair ->
    the grouping runs on a plain reading -> RED."""
    w = _e2e_world(tmp_path, monkeypatch)
    calls: list[int] = []
    real = dg.from_review
    monkeypatch.setattr(dg, "from_review", lambda *a, **kw: calls.append(1) or real(*a, **kw))
    plain = _review(w)
    assert calls == [] and plain.navigation is None
    assert "dispatch_groups" not in plain.report and "upstream_groups" not in plain.report
    nav = _review(w, navigation=True)
    assert calls == [1] and {"dispatch_groups", "upstream_groups"} <= set(nav.report)


def test_an_unreadable_atlas_part_fails_neither_the_review_nor_a_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ MINOR-5: a sqlite error while reading the edges is ``{"unreadable": ...}`` in the block,
    labels nothing, and start_diff_review(run_pair) and a write naming its unit both answer.

    MUTATION (verified RED, 1 failed): drop the ``except sqlite3.Error`` around the dispatch read
    in review_navigation.read -> the tool raises -> RED."""
    from tests.unit.lib.test_diff_review import DX
    from tests.unit.test_tool_surface import _call

    w = _e2e_world(tmp_path, monkeypatch)

    def broken(*_a: Any, **_kw: Any) -> Any:
        raise sqlite3.OperationalError("no such table: string_keyed_edge")

    monkeypatch.setattr(dg, "from_review", broken)
    server = mcp_app.build_server(w.path)

    def call(name: str, args: dict[str, Any]) -> dict[str, Any]:
        try:
            return _call(server, name, args)
        except sqlite3.Error as exc:
            return {"raised": repr(exc)}

    out = call("start_diff_review", {"run_pair": "runA::runB", "k": 50})
    assert "raised" not in out and "error" not in out, out
    block = out["report"].get("dispatch_groups") or {}
    assert "no such table" in str(block.get("unreadable")), block
    nxt = out["next_unit"]
    assert all("dispatch" not in m for m in nxt["members"]), nxt["members"]
    wrote = call(
        "annotate_diff",
        {
            "anchor_ref": nxt["members"][0]["anchor_ref"],
            "verdict": "changed_real",
            "rationale": "r",
            "diff_id": DX,
            "unit_id": nxt["unit_id"],
        },
    )
    assert "raised" not in wrote and wrote.get("written") is True, wrote


# ── the member label: what reaches the reader (F3-3) ────────────────────────────────────────────


def _unit_of(review: ru.PairReview, entry_id: str) -> ru.Unit:
    return next(u for u in review.units if any(m.entry_id == entry_id for m in u.members))


def test_a_grouped_member_carries_its_group_ref_wherever_its_unit_is_handed_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ End to end through the MCP tools: start_diff_review(run_pair) carries the compact block
    (its ``largest`` names the table group's ref) within the byte budget; the unit of F1 read with
    ``unit=`` lists F1 with ``dispatch[0].group_ref`` equal to that ref, its keys per side and
    ``group_members`` 2; the next unit a write hands on is labelled the same way.

    MUTATION (verified RED, 2 failed): drop the label in ``_member_json`` (the ``out["dispatch"] =
    label`` line) -> RED.
    MUTATION (verified RED, 1 failed): the write's next unit read without navigation
    (``navigation=True`` dropped in _after_unit_write) -> its members carry no label -> RED.
    MUTATION (verified RED, 2 failed): ``"dispatch_groups"`` dropped from the report whitelist in
    _start_pair_review -> no block -> RED."""
    from tests.unit.lib.test_diff_review import DX
    from tests.unit.test_tool_surface import _call

    w = _e2e_world(tmp_path, monkeypatch)
    server = mcp_app.build_server(w.path)
    out = _call(server, "start_diff_review", {"run_pair": "runA::runB", "k": 50})
    assert len(json.dumps(out)) <= mcp_app._RESPONSE_BYTE_BUDGET
    block = out["report"].get("dispatch_groups") or {}
    assert block.get("largest") and len(json.dumps(block)) <= 1_500, block
    review = _review(w, navigation=True)
    table = next(g for g in review.navigation.dispatch.groups if g.mechanism == dg.STATIC)
    assert table.ref in [x["group_ref"] for x in block["largest"]], block["largest"]

    uid = _unit_of(review, F1).unit_id
    one = _call(server, "start_diff_review", {"run_pair": "runA::runB", "unit": uid, "k": 50})
    member = next(m for m in one.get("members") or [] if m.get("entry_id") == F1)
    labels = member.get("dispatch") or [{}]
    assert labels[0].get("group_ref") == table.ref, member
    assert labels[0].get("keys") == {"a": ["k1"], "b": ["k1"]}, labels
    assert labels[0].get("group_members") == 2, labels

    # A write naming its unit hands on the next unit, its grouped members labelled as above.
    expected = review.navigation.labels
    seen = 0
    nxt = out["next_unit"]
    for _ in range(len(review.units)):
        if nxt is None:
            break
        for m in nxt["members"]:
            want = expected.get((DX, m.get("entry_id")))
            assert m.get("dispatch") == want, (m, want)
            seen += want is not None
        wrote = _call(
            server,
            "annotate_diff",
            {
                "anchor_ref": nxt["members"][0]["anchor_ref"],
                "verdict": "changed_real",
                "rationale": "r",
                "diff_id": DX,
                "unit_id": nxt["unit_id"],
            },
        )
        nxt = wrote.get("next_unit")
    assert seen >= 3, seen  # F1, F2, H1 were each handed on labelled


def test_a_batch_handed_out_by_its_page_labels_its_grouped_members(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ Bucket S entries are handed out in an S batch (members listed by the material's page): a
    grouped member of the batch carries its ``dispatch`` label there too, and it counts among the
    grouped members of the pair.

    MUTATION (verified RED, 1 failed): ``_set_shown_members`` called without the navigation
    (``review.navigation`` -> ``None``) -> the batch's members carry no label -> RED."""
    from tests.unit.lib.test_diff_review import DX
    from tests.unit.lib.test_review_units import _s_world
    from tests.unit.test_tool_surface import _call

    w = _s_world(tmp_path, monkeypatch, 3)  # pairs 00000001..00000003, bucket S at k=0
    w.atlas.execute("UPDATE diff_meta SET binary_path_a='/p1/libx', binary_path_b='/p1/libx'")
    for run in ("runA", "runB"):
        w.atlas.execute(
            "INSERT INTO string_keyed_edge (source_run_id, binary, binary_path, from_function, "
            "from_func_addr, key, mechanism, callee_addr, callee_kind, completeness_status) "
            "VALUES (?, 'libx', '/p1/libx', 'FUN_d', '00000009', 'k5', 'strcmp_gate', "
            "'00000002', 'direct', 'complete')",
            (run,),
        )
    w.pair(DX, "00000009", "00000009", sim=1.0)
    review = _review(w, k=0, navigation=True)
    batch = _unit_of(review, "pair:00000002:00000002")
    assert batch.kind == ru.S_BATCH  # the precondition
    assert review.navigation.dispatch.grouped_members == 1
    server = mcp_app.build_server(w.path)
    one = _call(
        server, "start_diff_review", {"run_pair": "runA::runB", "unit": batch.unit_id, "k": 0}
    )
    listed = {m.get("entry_id"): m for m in one.get("members") or []}
    assert "pair:00000002:00000002" in listed, sorted(listed)
    (label,) = listed["pair:00000002:00000002"].get("dispatch") or [{}]
    assert label.get("keys") == {"a": ["k5"], "b": ["k5"]}, label
    assert all("dispatch" not in m for e, m in listed.items() if e != "pair:00000002:00000002")


def test_the_report_file_lists_every_group_with_its_members(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ ``tmap review report --md`` (and --html) renders the full table from the same reading:
    the table group's ref with F1 and F2 and their keys — F1's two sides in their own columns
    (``k1`` on A, ``k4`` on B) — the table's stored split, and the gate group's ref with H1, its B
    side enumerating nothing (``counterpart_enumerates: false``), in the report's dispatch section.

    MUTATION (verified RED, 1 failed): the CLI reads without navigation (``navigation=as_md or
    as_html`` dropped in review_cli.report) -> no dispatch section -> RED.
    MUTATION (verified RED, 1 failed): ``_dispatch_md`` returns ``[]`` -> RED.
    MUTATION (verified RED, 1 failed): the counterpart line dropped (``if
    j.get("counterpart_enumerates") is False:`` -> ``if False:`` in ``_dispatch_md``) -> RED.
    MUTATION (verified RED, 1 failed): the completeness line dropped (``if "completeness" in j:``
    -> ``if False:``) -> RED.
    MUTATION (verified RED, 1 failed): the B column shows the A keys (``{_keys(keys['b'])} |`` ->
    ``{_keys(keys['a'])} |``) -> RED."""
    from click.testing import CliRunner

    from treasure_map.cli import review_cli

    w = _e2e_world(tmp_path, monkeypatch)
    # F1 keyed k1 on A and k4 on B (the tables still align on k2), A's table stored as split, and
    # the gate enumerated on A only.
    w.atlas.execute(
        "UPDATE string_keyed_edge SET key = 'k4' WHERE source_run_id = 'runB' AND key = 'k1'"
    )
    w.atlas.execute(
        "UPDATE string_keyed_edge SET completeness_reason = 'split_by_undefined_handler' "
        "WHERE source_run_id = 'runA' AND table_addr = ?",
        (T1,),
    )
    w.atlas.execute(
        "DELETE FROM string_keyed_edge WHERE source_run_id = 'runB' AND mechanism = ?", (dg.GATE,)
    )
    w.atlas.commit()
    review = _review(w, navigation=True)
    refs = {g.mechanism: g.ref for g in review.navigation.dispatch.groups}
    md_file = tmp_path / "r.md"
    res = CliRunner().invoke(
        review_cli.review,
        ["report", "runA::runB", "--md", "-o", str(md_file), "--atlas", str(w.path), "--k", "50"],
    )
    assert res.exit_code == 0, res.output
    md = md_file.read_text(encoding="utf-8")
    assert "## Dispatch groups" in md, md[:2000]
    section = md.split("## Dispatch groups", 1)[1].split("\n## ", 1)[0]
    for text in (refs[dg.STATIC], F1, f"pair:{F2A}:{F2B}", refs[dg.GATE], H1.entry_id, "`k1`"):
        assert text in section, (text, section[:1500])
    rows = {
        cells[0].strip("` "): [c.strip() for c in cells[1:]]
        for line in section.splitlines()
        if line.startswith("| `")
        for cells in [line.strip("|").split("|")]
    }
    assert rows.get(F1) == ["`k1`", "`k4`"], rows
    gate_part = section.split(f"### `{refs[dg.GATE]}`", 1)[1].split("\n### ", 1)[0]
    assert "counterpart_enumerates: false" in gate_part, gate_part
    table_part = section.split(f"### `{refs[dg.STATIC]}`", 1)[1].split("\n### ", 1)[0]
    assert "split_by_undefined_handler: true" in table_part, table_part
    page = rr.html_page(review)
    assert "Dispatch groups" in page and refs[dg.STATIC] in page
