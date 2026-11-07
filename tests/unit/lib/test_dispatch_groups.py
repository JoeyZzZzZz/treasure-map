# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""F-3 (D13) dispatch-table groups (lib/query/dispatch_groups): the navigation grouping of a pair's
must-read entries by the string-keyed edge that names their function, and its surfacing in the pair
review report.

Zero real data. The core tests build a tiny atlas + two analysis.dbs by hand and call the grouping
on hand-made member refs; the end-to-end tests reuse the World of test_diff_review to drive
``review_pair`` and the MCP ``start_diff_review`` tool.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from treasure_map import mcp_app
from treasure_map.lib.analyze.ghidra_runner import current_pass_version
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.query import dispatch_groups as dg
from treasure_map.lib.query import review_units as ru
from treasure_map.lib.storage.connection import open_db

# Addresses (8-hex, as the extractor normalizes them). F1/F2 are table handlers; H1 is gated by
# the dispatch function D1; U is in no table or gate.
F1A, F1B = "00001000", "00001001"
F2A, F2B = "00002000", "00002001"
H1A, H1B = "00003000", "00003001"
D1A, D1B = "00004000", "00004001"
UA, UB = "00005000", "00005001"
D2A = "00006000"  # a DIFFERENT dispatch function, in a same-short-name binary at another path
T1, T1B = "0x7000", "0x7100"  # the table on each side (aligned by key overlap)

# diff -> (sha_a, sha_b). "app" is the diffed binary; "other" is diffed but never table-scanned.
D1 = "runA::runB::app"
DU = "runA::runB::other"
SHA = {(D1, "a"): "a" * 64, (D1, "b"): "b" * 64, (DU, "a"): "e" * 64, (DU, "b"): "f" * 64}
NAME = {D1: "app", DU: "other"}
DPATH = {D1: "/p1/app", DU: "/p3/other"}


class _Fixture:
    """Two runs, two diffs: ``app`` @/p1/app (a static table + a gate) and ``other`` @/p3/other (no
    edges, the detector never scanned it). A THIRD, non-diffed binary also named ``app`` sits at
    /p2/app with a gate on the same callee address — the short-name trap the path join must avoid.
    """

    def __init__(self, tmp: Path, *, scan_app: bool = True, with_sibling: bool = True) -> None:
        self.path = tmp / "atlas.db"
        self.atlas = open_atlas(self.path)
        self.atlas.execute("PRAGMA synchronous = OFF")
        build = current_pass_version()
        for side, run in (("a", "runA"), ("b", "runB")):
            db = tmp / f"analysis_{side}.db"
            conn = open_db(db)
            for did in (D1, DU):
                conn.execute(
                    "INSERT INTO binaries (name, sha256) VALUES (?, ?)",
                    (NAME[did], SHA[(did, side)]),
                )
            # detector scan status: app scanned; other NEVER scanned (no row at all).
            if scan_app:
                bid = conn.execute("SELECT id FROM binaries WHERE name='app'").fetchone()[0]
                conn.execute(
                    "INSERT INTO detector_scan_status (binary_id, detector, scanned, "
                    "supported_scope, cap_hit, found_count) VALUES (?, 'string_tables', 1, "
                    "'absolute_2field_only', 0, 1)",
                    (bid,),
                )
            conn.commit()
            conn.close()
            self.atlas.execute(
                "INSERT INTO run (run_id, hunt_commit, build_hash, hunt_instances, "
                "analysis_db_path) VALUES (?, 'c0', ?, 10, ?)",
                (run, build, str(db)),
            )
        for did in (D1, DU):
            self.atlas.execute(
                "INSERT INTO diff_meta (diff_id, run_a_id, run_b_id, binary_a, binary_b, "
                "binary_path_a, binary_path_b, sha256_a, sha256_b, diff_ok, version_skew) "
                "VALUES (?, 'runA', 'runB', ?, ?, ?, ?, ?, ?, 1, 0)",
                (did, NAME[did], NAME[did], DPATH[did], DPATH[did], SHA[did, "a"], SHA[did, "b"]),
            )
        # app @/p1/app: a static table on each side (k1->F1, k2->F2, aligned by key overlap) and a
        # gate (dispatch function D1 gating H1 by k3), on both sides, D1 aligned across sides.
        self._static("runA", "app", "/p1/app", T1, [("k1", F1A), ("k2", F2A)])
        self._static("runB", "app", "/p1/app", T1B, [("k1", F1B), ("k2", F2B)])
        self._gate("runA", "app", "/p1/app", D1A, [("k3", H1A)])
        self._gate("runB", "app", "/p1/app", D1B, [("k3", H1B)])
        if with_sibling:
            # a NON-diffed binary also named 'app', at a different path, gating the SAME callee
            # address under a different dispatch function: the path join must not merge it in.
            self._gate("runA", "app", "/p2/app", D2A, [("k9", H1A)])
        # function alignment: the handlers, the gated function, and the dispatch function.
        for a, b in ((F1A, F1B), (F2A, F2B), (H1A, H1B), (D1A, D1B)):
            self._align(D1, a, b)
        self.atlas.commit()

    def _static(
        self, run: str, binary: str, path: str, table_addr: str, entries: list[tuple[str, str]]
    ) -> None:
        for key, callee in entries:
            self.atlas.execute(
                "INSERT INTO string_keyed_edge (source_run_id, binary, binary_path, key, "
                "mechanism, callee_addr, callee_kind, table_addr, completeness_status) "
                "VALUES (?, ?, ?, ?, 'static_string_table', ?, 'direct', ?, 'incomplete')",
                (run, binary, path, key, callee, table_addr),
            )

    def _gate(
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

    def _align(self, did: str, a: str, b: str) -> None:
        self.atlas.execute(
            "INSERT INTO function_alignment (diff_id, addr_a, addr_b, alignment_confidence, "
            "similarity, alignment_state) VALUES (?, ?, ?, 0.97, 0.9, 'aligned')",
            (did, a, b),
        )


def _members() -> list[dg.MemberRef]:
    return [
        dg.MemberRef(D1, f"pair:{F1A}:{F1B}", f"anc:{F1A}", "entry", F1A, F1B),
        dg.MemberRef(D1, f"pair:{F2A}:{F2B}", f"anc:{F2A}", "entry", F2A, F2B),
        dg.MemberRef(D1, f"pair:{H1A}:{H1B}", f"anc:{H1A}", "callee_group", H1A, H1B),
        dg.MemberRef(DU, f"pair:{UA}:{UB}", f"anc:{UA}", "entry", UA, UB),
    ]


def _by_mech(pd: dg.PairDispatch, mech: str) -> list[dg.DispatchGroup]:
    return [g for g in pd.groups if g.mechanism == mech]


# ── the grouping ────────────────────────────────────────────────────────────────────────────────


def test_table_group_gate_group_and_uncovered_bucket(tmp_path: Path) -> None:
    """★ A table T {k1->F1, k2->F2} groups F1 and F2 (the table, not the key); a gate dispatch
    function D1 gating H1 groups H1 under D1 (the dispatch function, aligned across both sides); an
    entry whose binary the detector never scanned falls to the explicit uncovered bucket with its
    detector status. H1's unit is a callee group, so it is counted co-grouped.

    MUTATION (verified RED, 1 failed each):
      - group static edges by key not table: replace the static ``group_for(STATIC, did, binary,
        a_anchor, b_anchor)`` with ``group_for(STATIC, did, binary, keys[0] if keys else None,
        None)`` -> F1/F2 split into two size-1 groups, ``len(tgroups) == 1`` reddens;
      - drop the uncovered bucket: replace ``uncovered.append(mem)`` with ``pass`` -> the uncovered
        assertions redden.
    """
    fx = _Fixture(tmp_path)
    pd = dg.compute_pair(fx.atlas, "runA", "runB", _members())

    tgroups = _by_mech(pd, dg.STATIC)
    assert len(tgroups) == 1
    tg = tgroups[0]
    assert set(tg.members) == {f"pair:{F1A}:{F1B}", f"pair:{F2A}:{F2B}"}
    assert (tg.a_anchor, tg.b_anchor) == (T1, T1B)
    # the key is a member label only, not the group key
    assert tg.members[f"pair:{F1A}:{F1B}"] == ["k1"]

    ggroups = _by_mech(pd, dg.GATE)
    # exactly one gate group for H1 (app's D1), NOT the same-named sibling's D2 at another path
    # (see the short-name test); the two sides' dispatch functions are aligned into one group.
    h1_groups = [g for g in ggroups if f"pair:{H1A}:{H1B}" in g.members]
    assert len(h1_groups) == 1
    gg = h1_groups[0]
    assert set(gg.members) == {f"pair:{H1A}:{H1B}"}
    assert (gg.a_anchor, gg.b_anchor) == (D1A, D1B)
    assert gg.members[f"pair:{H1A}:{H1B}"] == ["k3"]

    assert pd.also_in_callee_group == 1  # H1's unit is a callee group
    assert pd.grouped_members == 3  # F1, F2, H1

    assert [m.entry_id for m in pd.uncovered] == [f"pair:{UA}:{UB}"]
    assert pd.uncovered_by_detector == {"static_table_detector_did_not_run": 1}


def test_gate_dispatch_functions_are_aligned_across_the_two_sides(tmp_path: Path) -> None:
    """★ A gate's two sides are one group when aligned by function alignment: with D1A<->D1B
    aligned, H1 (pair:H1A:H1B) is in ONE gate group; with alignment off it is two (one per side).

    MUTATION (verified RED, 1 failed): force the unaligned path by replacing
    ``if align_dispatchers:`` with ``if False:`` -> the aligned call makes one group per side ->
    the ``== 1`` assertion reddens."""
    fx = _Fixture(tmp_path, with_sibling=False)
    members = [dg.MemberRef(D1, f"pair:{H1A}:{H1B}", f"anc:{H1A}", "entry", H1A, H1B)]

    aligned = dg.compute_pair(fx.atlas, "runA", "runB", members, align_dispatchers=True)
    assert len([g for g in aligned.groups if g.mechanism == dg.GATE]) == 1

    unaligned = dg.compute_pair(fx.atlas, "runA", "runB", members, align_dispatchers=False)
    assert len([g for g in unaligned.groups if g.mechanism == dg.GATE]) == 2


def test_the_join_is_by_binary_path_not_the_short_name(tmp_path: Path) -> None:
    """★ The diffed ``app`` @/p1/app and a non-diffed binary also named ``app`` @/p2/app share the
    short name; the sibling gates the SAME callee address H1A under a different dispatch function.
    Joining by path, H1 (an app @/p1/app entry) is in exactly one gate group (its own D1). Joining
    by short name would merge the two binaries' edges.

    MUTATION (verified RED, 1 failed): in ``_gates`` SELECT the short ``binary`` column, drop the
    ``AND binary_path IN (...)`` filter and index ``out[binary]``, and look it up by
    ``dm['binary_a']`` in compute_pair -> H1 picks up the sibling's dispatcher -> two gate groups ->
    the ``== 1`` assertion reddens."""
    fx = _Fixture(tmp_path, with_sibling=True)
    members = [dg.MemberRef(D1, f"pair:{H1A}:{H1B}", f"anc:{H1A}", "callee_group", H1A, H1B)]
    pd = dg.compute_pair(fx.atlas, "runA", "runB", members)
    gate = [g for g in pd.groups if g.mechanism == dg.GATE]
    assert len(gate) == 1
    assert (gate[0].a_anchor, gate[0].b_anchor) == (D1A, D1B)


# ── neutrality: no reachability / verdict word in the code-authored strings ─────────────────────


def _code_strings(block: dict[str, Any]) -> list[str]:
    """The strings the code authored (notes), never the firmware DATA (keys, ids, addresses)."""
    out = [block["mechanism_note"], block["uncovered"]["note"]]
    out += [g["note"] for g in block["groups"]]
    return out


# The words a dispatch group's authored notes must never carry (a reachability / verdict claim).
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
)


def test_no_group_label_carries_a_reachability_or_verdict_word(tmp_path: Path) -> None:
    """★ The iron law: a string-keyed edge is an enumerated fact, never a reachability verdict. No
    code-authored note may contain a reachability or judgement word.

    MUTATION (verified RED, 1 failed): put 'reachable' in NOTE_GATE (e.g. 'reachable by a key in
    this function') -> the gate group's note trips the scan -> RED."""
    fx = _Fixture(tmp_path)
    pd = dg.compute_pair(fx.atlas, "runA", "runB", _members())
    block = dg.report_block(pd)
    texts = _code_strings(block) + list(dg.NEUTRAL_TEXTS)
    assert block["groups"], "precondition: at least one group so a group note is scanned"
    for text in texts:
        low = text.lower()
        for word in _FORBIDDEN_WORDS:
            assert word not in low, f"forbidden word {word!r} in: {text!r}"


def test_report_block_is_bounded_and_counts_the_rest(tmp_path: Path) -> None:
    """★ The report block caps the groups it shows and counts the rest, and stays small.

    MUTATION (verified RED, 1 failed): show every group (drop the ``[:max_groups]`` slice) and set
    groups_omitted to 0 -> ``groups_shown`` exceeds the cap -> RED."""
    fx = _Fixture(tmp_path)
    # many gate members so there are more groups than the cap
    members = [
        dg.MemberRef(D1, f"pair:{H1A}:{H1B}", f"anc:{H1A}", "entry", H1A, H1B),
        dg.MemberRef(D1, f"pair:{F1A}:{F1B}", f"anc:{F1A}", "entry", F1A, F1B),
        dg.MemberRef(D1, f"pair:{F2A}:{F2B}", f"anc:{F2A}", "entry", F2A, F2B),
    ]
    pd = dg.compute_pair(fx.atlas, "runA", "runB", members)
    block = dg.report_block(pd, max_groups=1)
    assert block["groups_shown"] == 1
    assert block["groups_omitted"] == len(pd.groups) - 1
    assert len(json.dumps(block)) < 8_000


# ── end to end: through review_pair and the MCP tool, moving nothing ────────────────────────────


def _e2e_world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    from tests.unit.lib.test_diff_review import DX, SHAS, World

    ru.DIFF_CACHE.clear()
    w = World(tmp_path, monkeypatch)
    for a, b in ((F1A, F1B), (F2A, F2B), (H1A, H1B), (D1A, D1B)):
        w.pair(DX, a, b)
    sha_a, sha_b = SHAS[DX]
    w.atlas.execute(
        "UPDATE diff_meta SET binary_path_a='/p1/libx', binary_path_b='/p1/libx' WHERE diff_id=?",
        (DX,),
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
    return w


def _review(w: Any, k: int = 50) -> ru.PairReview:
    return ru.review_pair(
        w.atlas,
        "runA",
        "runB",
        k=k,
        pair_staleness={"source_stale": False, "source_stale_reason": None},
        server_commit=None,
    )


def test_grouping_moves_no_unit_id_or_must_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ The grouping is a view annotation: the unit list, the unit ids and the must-read set are
    byte-for-byte the same as units cut from the facts alone, and the report still carries the
    dispatch groups (F1/F2 in a table group, H1 in a gate group).

    MUTATION (verified RED, 1 failed): make the report hook drop a unit (``units.pop()`` after the
    grouping in review_pair) -> the unit list diverges from the facts-only cut -> RED."""
    w = _e2e_world(tmp_path, monkeypatch)
    facts = ru.pair_facts(w.atlas, "runA", "runB")
    baseline = {
        (u.unit_id, u.kind, u.must_read, tuple(sorted(m.anchor_ref for m in u.members)))
        for u in ru.cut_units(facts, 50)
    }
    review = _review(w)
    got = {
        (u.unit_id, u.kind, u.must_read, tuple(sorted(m.anchor_ref for m in u.members)))
        for u in review.units
    }
    assert got == baseline

    block = review.report["dispatch_groups"]
    grouped = {eid for g in block["groups"] for eid in [mem["entry_id"] for mem in g["members"]]}
    assert {f"pair:{F1A}:{F1B}", f"pair:{F2A}:{F2B}"} <= grouped
    assert block["grouped_members"] >= 3
    assert any(g["mechanism"] == dg.STATIC for g in block["groups"])
    assert any(g["mechanism"] == dg.GATE for g in block["groups"])


def test_mcp_start_diff_review_carries_dispatch_groups_within_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ End to end through the MCP tool: start_diff_review(run_pair) forwards the report's
    ``dispatch_groups`` block, and the whole response stays within the byte budget.

    MUTATION (verified RED, 1 failed): drop 'dispatch_groups' from the report whitelist in
    mcp_app._start_pair_review -> the block is absent -> RED."""
    from tests.unit.test_tool_surface import _call

    w = _e2e_world(tmp_path, monkeypatch)
    server = mcp_app.build_server(w.path)
    out = _call(server, "start_diff_review", {"run_pair": "runA::runB", "k": 50})
    assert "dispatch_groups" in out["report"]
    block = out["report"]["dispatch_groups"]
    assert block["grouped_members"] >= 3
    assert any(g["mechanism"] == dg.STATIC for g in block["groups"])
    assert len(json.dumps(out)) <= mcp_app._RESPONSE_BYTE_BUDGET
