# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for layer-0 parse (.BinDiff -> atlas function_alignment / function_presence).

Fingerprint tests read the COMMITTED real fixture (tests/fixtures/layer0/*.BinDiff) so verification
is on real BinDiff runtime data, never a synthetic stub. Domain / orchestrator tests use a tiny
crafted .BinDiff + a synthetic analysis.db to exercise the presence + write logic hermetically (the
243MB real analysis.db is not in the repo).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import FunctionAlignmentRow, FunctionPresenceRow
from treasure_map.lib.atlas.writer import add_function_alignment, begin_run
from treasure_map.lib.diff import layer0
from treasure_map.lib.diff.layer0 import (
    BaselineDomain,
    alignment_state,
    compute_side_presence,
    load_baseline,
    norm_hex,
    parse_bindiff,
    run_layer0_parse,
)
from treasure_map.lib.errors import ConfigError
from treasure_map.lib.query.diff_align import align_by_a, align_by_b
from treasure_map.lib.storage.connection import open_db
from treasure_map.version import UNKNOWN_VERSION

FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "fixtures"
    / "layer0"
    / "libshared_before_vs_libshared_after.BinDiff"
)

# The 8 low-confidence pairs the spec names (address1, address2 in BIGINT decimal): each must parse
# to alignment_undetermined. They are the SAME batch under two totally different toolchains, so this
# is a structural fact of libshared (identical small wrappers), not toolchain noise.
_NAMED_UNDETERMINED = [
    (234452, 431136),
    (384720, 394188),
    (378832, 388300),
    (209576, 214624),
    (235264, 313944),
    (233248, 205944),
    (367384, 376852),
    (327648, 336772),
]


def _mk_bindiff(path: Path, rows: list[tuple], *, file_hashes=("sha_a", "sha_b")) -> Path:  # type: ignore[type-arg]
    """A tiny synthetic .BinDiff (only the columns layer-0 reads). rows = (a1,n1,a2,n2,sim,conf,
    bb,edges,instr). ``file_hashes`` = the (before, after) side hashes written to the ``file`` table
    for the binary-identity check; pass None to omit the file table (unverifiable)."""
    con = sqlite3.connect(path)
    con.execute(
        "CREATE TABLE function (id INTEGER PRIMARY KEY, address1 BIGINT, name1 TEXT, "
        "address2 BIGINT, name2 TEXT, similarity DOUBLE, confidence DOUBLE, "
        "basicblocks INTEGER, edges INTEGER, instructions INTEGER)"
    )
    con.executemany(
        "INSERT INTO function (address1,name1,address2,name2,similarity,confidence,"
        "basicblocks,edges,instructions) VALUES (?,?,?,?,?,?,?,?,?)",
        rows,
    )
    if file_hashes is not None:
        con.execute("CREATE TABLE file (id INT, filename TEXT, hash CHARACTER(40))")
        con.executemany(
            "INSERT INTO file (id, filename, hash) VALUES (?, ?, ?)",
            [(1, "before", file_hashes[0]), (2, "after", file_hashes[1])],
        )
    con.commit()
    con.close()
    return path


def _mk_analysis(path: Path, binary: str, sha: str, funcs: list[tuple]) -> Path:  # type: ignore[type-arg]
    """A synthetic analysis.db with one binary + funcs = (address, name, pseudocode, size_bytes).

    ``size_bytes`` is inserted EXPLICITLY (so None -> NULL and 0 stay distinct from a real size),
    since the decompile-status classifier turns on it (design-skip vs real failure vs unknown)."""
    con = open_db(path)
    con.execute(
        "INSERT INTO binaries (id, name, path, sha256) VALUES (1, ?, ?, ?)", (binary, binary, sha)
    )
    for addr, name, pc, size in funcs:
        con.execute(
            "INSERT INTO functions (binary_id, name, address, pseudocode, size_bytes) "
            "VALUES (1, ?, ?, ?, ?)",
            (name, addr, pc, size),
        )
    con.commit()
    con.close()
    return path


# ── alignment fingerprints on the real committed fixture ────────────────────────────────


def test_parse_real_fixture_matched_pair_count() -> None:
    p = parse_bindiff(FIXTURE, "d")
    assert len(p.rows) == 1848  # matched-pair count


def test_parse_real_fixture_confidence_split_at_0_9() -> None:
    p = parse_bindiff(FIXTURE, "d")
    aligned = sum(1 for r in p.rows if r.alignment_state == "aligned")
    undet = sum(1 for r in p.rows if r.alignment_state == "alignment_undetermined")
    assert (aligned, undet) == (1815, 33)  # 0.9 threshold split


def test_parse_real_fixture_named_low_conf_pairs_are_undetermined() -> None:
    p = parse_bindiff(FIXTURE, "d")
    by_pair = {(r.addr_a, r.addr_b): r for r in p.rows}
    for a, b in _NAMED_UNDETERMINED:
        row = by_pair[(norm_hex(a), norm_hex(b))]
        assert row.alignment_state == "alignment_undetermined"


def test_confidence_not_similarity_is_the_alignment_axis() -> None:
    # ★ the iron proof: (384720,394188) has similarity=1.0 (identical content) yet confidence ~0.02
    # (BinDiff can't trust the pairing among identical wrappers). Using similarity as the alignment
    # axis would call it a perfect align; confidence correctly calls it undetermined.
    p = parse_bindiff(FIXTURE, "d")
    row = next(r for r in p.rows if (r.addr_a, r.addr_b) == (norm_hex(384720), norm_hex(394188)))
    assert row.similarity == 1.0
    assert row.alignment_confidence < 0.9
    assert row.alignment_state == "alignment_undetermined"


def test_similarity_is_carried_first_class_not_dropped() -> None:
    # ★ similarity (change-magnitude) is a first-class fact next to confidence, never hidden — the
    # 'no change verdict' rule must not leak into 'hide the change magnitude'.
    p = parse_bindiff(FIXTURE, "d")
    assert all(r.similarity is not None for r in p.rows)


def test_bigint_decimal_address_normalized_to_tmap_hex() -> None:
    # ★ address contract: BinDiff address1 is BIGINT decimal; 234452 -> 0x393d4 -> "000393d4".
    assert norm_hex(234452) == "000393d4"
    p = parse_bindiff(FIXTURE, "d")
    assert any(r.addr_a == "000393d4" for r in p.rows)


# ── parse honesty: nothing dropped, no semantic verdict ─────────────────────────────────


def test_low_confidence_kept_not_dropped() -> None:
    assert alignment_state(0.89) == "alignment_undetermined"  # kept, explicit — not dropped
    assert alignment_state(0.9) == "aligned"


def test_alignment_row_has_no_change_verdict_field() -> None:
    # ★ iron law: no changed/unchanged/modified field escapes the parse (similarity is a raw fact).
    p = parse_bindiff(FIXTURE, "d")
    fields = set(vars(p.rows[0]))
    assert not (fields & {"changed", "unchanged", "modified", "change_verdict"})


# ── baseline domain + presence three-state (synthetic, hermetic) ────────────────────────


# ── presence: the ②③④ fixture + SET-level guards (each proven to have teeth in reverse below) ──
#
# The domain-swap bug (baseline := BinDiff set instead of tmap's inventory) and the operand-swap bug
# (unmatched := matched - baseline) are DIFFERENT bugs whose symptoms land in DIFFERENT buckets, so
# they need different guards. Categories injected (NOT ①, which layer-0 has no input channel for):
#   ② out-of-domain ∧ matched -> out_of_inventory ; ③ in-domain ∧ unmatched -> a presence row ;
# ④ in-domain ∧ matched -> matched_in_domain. ★ Fixture rule |②| != |③| (1 vs 2) so a count-level
# coincidence can never mask a set-level error; ★ ③ non-empty and covering BOTH presence_states.

# ④ two in-domain matched funcs ; ③ two in-domain UNMATCHED funcs (one analysis_complete via a
# skipped_micro size, one analysis_incomplete via a real-failure size) ; ② one out-of-domain match.
_CAT4 = frozenset({"00004000", "00004001"})
_CAT3 = frozenset({"00003000", "00003001"})
_CAT2 = frozenset({"00009999"})


def _presence_fixture(tmp_path: Path):  # type: ignore[no-untyped-def]
    # baseline (tmap functions inventory) = ③ ∪ ④ ; matched pairs (from the .BinDiff) = ② ∪ ④.
    funcs = [
        ("0x4000", "kept0", "int f(){}", 64),  # ④ ok
        ("0x4001", "kept1", "int f(){}", 64),  # ④ ok
        ("0x3000", "gone_micro", "", 4),  # ③ skipped_micro -> unmatched_analysis_complete
        ("0x3001", "gone_failed", "", 128),  # ③ failed -> unmatched_analysis_incomplete
    ]
    db = _mk_analysis(tmp_path / "a.db", "lib.so", "s", funcs)
    baseline = load_baseline(str(db), "lib.so")
    matched = _CAT2 | _CAT4
    return baseline, matched


def test_presence_guards_g1_g3_g4_g5_on_subset_fixture(tmp_path: Path) -> None:
    baseline, matched = _presence_fixture(tmp_path)
    pres = compute_side_presence("d", "a", matched, baseline)
    # ★ G1 (D1's core, cardinality-independent): baseline domain equals the TEST-SIDE independently
    # known functions set (③∪④) -- NOT the matched set. A domain swap corrupts baseline.addrs.
    assert baseline.addrs == _CAT3 | _CAT4
    # ★ G3 (D1 catcher, SET not count): out_of_inventory is exactly ② (out-of-domain matched)
    assert pres.out_of_inventory_addrs == _CAT2
    # ★ G4 (D2 catcher, SET): the unmatched presence rows are exactly ③ (in-domain unmatched)
    assert {r.addr for r in pres.rows} == _CAT3
    # ★ G5 (functional, axis D3): ③'s two presence_states are bucketed correctly
    by_addr = {r.addr: r.presence_state for r in pres.rows}
    assert by_addr["00003000"] == "unmatched_analysis_complete"  # skipped_micro
    assert by_addr["00003001"] == "unmatched_analysis_incomplete"  # real failure
    # structural identity -- a NON-GUARD (tautology for ANY baseline: (B∩M)⊎(B−M)≡B); no
    # interception, never relied on as a guard.
    assert pres.matched_in_domain + pres.unmatched == len(baseline.addrs)  # NON-GUARD (always true)


# ── reverse-validation: each guard PROVEN to go red under its degradation (per simulation) ──
# D1 domain-swap -> G1,G3,G4 red ; D2 operand-swap -> G4 red (G1,G3 GREEN, discriminating) ;
# D3 mapping-broken -> G5 red. (G5's red under D1/D2 would be collateral of ③ rows vanishing, so it
# is NOT tested there; the structural identity is a NON-GUARD, green under any degradation.)


def test_reverse_d1_domain_swap_reds_g1_g3_g4(tmp_path: Path) -> None:
    baseline, matched = _presence_fixture(tmp_path)
    # THE BUG: baseline := the BinDiff/matched set (the code can only see matched pairs), not tmap's
    # inventory. All of matched's addrs become 'in domain'.
    d1_baseline = BaselineDomain(functions={a: (None, "ok") for a in matched})
    pres = compute_side_presence("d", "a", matched, d1_baseline)
    assert d1_baseline.addrs != _CAT3 | _CAT4  # G1 RED (baseline corrupted)
    assert pres.out_of_inventory_addrs != _CAT2  # G3 RED (matched - matched = empty, not ②)
    assert {r.addr for r in pres.rows} != _CAT3  # G4 RED (baseline - matched = empty, not ③)
    # ★ the structural identity stays GREEN even here -> proves it is a NON-GUARD, not a catcher
    assert pres.matched_in_domain + pres.unmatched == len(d1_baseline.addrs)


def _compute_d2(matched, baseline):  # type: ignore[no-untyped-def]
    # THE BUG (operand swap): unmatched := matched - baseline (should be baseline - matched).
    unmatched = matched - baseline.addrs
    return [
        FunctionPresenceRow(
            diff_id="d",
            side="a",
            addr=a,
            name=None,
            presence_state="unmatched_analysis_complete",
            decompiled=1,
        )
        for a in sorted(unmatched)
    ]


def test_reverse_d2_operand_swap_reds_only_g4(tmp_path: Path) -> None:
    baseline, matched = _presence_fixture(tmp_path)
    d2_rows = _compute_d2(matched, baseline)
    assert {r.addr for r in d2_rows} != _CAT3  # G4 RED (unmatched became ②, not ③)
    # ★ G1 and G3 stay GREEN under D2 -> they DISCRIMINATE the kind (D2 not D1)
    assert baseline.addrs == _CAT3 | _CAT4  # G1 green
    assert (matched - baseline.addrs) == _CAT2  # G3 green (out_of_inventory still ②)


def test_reverse_d3_mapping_broken_reds_g5(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # THE BUG (_presence_state): mis-map skipped_micro -> analysis_incomplete (reverse of the
    # micro-function fix). G5 catches it; G1/G3/G4 (set-membership, not per-row status) stay green.
    real = layer0._presence_state
    monkeypatch.setattr(
        layer0,
        "_presence_state",
        lambda st: "unmatched_analysis_incomplete" if st == "skipped_micro" else real(st),
    )
    baseline, matched = _presence_fixture(tmp_path)
    pres = compute_side_presence("d", "a", matched, baseline)
    by_addr = {r.addr: r.presence_state for r in pres.rows}
    assert by_addr["00003000"] != "unmatched_analysis_complete"  # G5 RED (skipped_micro mis-mapped)
    # ★ the set-level guards are UNAFFECTED by a mapping bug -> they stay green (discriminate D3)
    assert baseline.addrs == _CAT3 | _CAT4  # G1 green
    assert pres.out_of_inventory_addrs == _CAT2  # G3 green
    assert {r.addr for r in pres.rows} == _CAT3  # G4 green


def test_skipped_micro_is_analysis_complete_not_a_gap(tmp_path: Path) -> None:
    # ★★ the reverse-pollution guard (this ticket's core): an empty-pseudocode function that is
    # UNDER the min size is DESIGN-SKIPPED (a thunk/stub the exporter never decompiles), so it is
    # known-benign and MUST read unmatched_analysis_complete — NOT _incomplete (which would invent
    # an analysis blind spot that does not exist). This test FAILS under the pre-fix behavior
    # (empty -> incomplete regardless of size), so it has teeth.
    db = _mk_analysis(tmp_path / "a.db", "lib.so", "s", [("0x2000", "micro_stub", "", 4)])
    base = load_baseline(str(db), "lib.so")
    assert base.skipped_micro_count == 1 and base.failed_count == 0
    pres = compute_side_presence("d", "a", frozenset(), base)
    assert pres.rows[0].presence_state == "unmatched_analysis_complete"


def test_real_decompile_failure_is_analysis_incomplete(tmp_path: Path) -> None:
    # ★ a genuine failure (empty pseudocode at/above the min size) is a real gap -> existence
    # UNDETERMINED -> unmatched_analysis_incomplete (never add/delete).
    db = _mk_analysis(tmp_path / "a.db", "lib.so", "s", [("0x3000", "big_failed", "", 128)])
    base = load_baseline(str(db), "lib.so")
    assert base.failed_count == 1 and base.skipped_micro_count == 0
    pres = compute_side_presence("d", "a", frozenset(), base)
    assert pres.rows[0].presence_state == "unmatched_analysis_incomplete"


def test_ok_function_is_analysis_complete(tmp_path: Path) -> None:
    db = _mk_analysis(tmp_path / "a.db", "lib.so", "s", [("0x1000", "fn", "int f(){}", 64)])
    base = load_baseline(str(db), "lib.so")
    pres = compute_side_presence("d", "a", frozenset(), base)
    assert pres.rows[0].presence_state == "unmatched_analysis_complete"


def test_both_size_sentinels_are_unknown_not_skipped_micro(tmp_path: Path) -> None:
    # ★ BOTH unrecorded-size sentinels (NULL and 0) -> unknown -> analysis_incomplete (conservative:
    # size unknown means 'no gap' cannot be asserted). ★ 0 is the trap: functions.size_bytes is
    # INTEGER DEFAULT 0, so a real 0-size function must NOT be swallowed into skipped_micro
    # (0 < MIN) — that would be the original bug wearing a new skin (hiding unknown as benign).
    db = _mk_analysis(
        tmp_path / "a.db",
        "lib.so",
        "s",
        [("0x1000", "size_null", "", None), ("0x2000", "size_zero", "", 0)],
    )
    base = load_baseline(str(db), "lib.so")
    assert (
        base.skipped_micro_count == 0 and base.failed_count == 0
    )  # neither is a determinate class
    pres = compute_side_presence("d", "a", frozenset(), base)
    by_addr = {r.addr: r for r in pres.rows}
    assert by_addr["00001000"].presence_state == "unmatched_analysis_incomplete"  # NULL sentinel
    assert by_addr["00002000"].presence_state == "unmatched_analysis_incomplete"  # 0 sentinel
    assert by_addr["00002000"].decompiled is None  # unknown -> honest NULL flag, not 0


# ── orchestrator + query face (synthetic atlas + analysis.db) ────────────────────────────


def _seed_two_runs(
    tmp_path: Path,
    *,
    tool_a: str = "0.0.1",
    tool_b: str = "0.0.1",
    ghidra_a: str = "11.4.3",
    ghidra_b: str = "11.4.3",
) -> Path:
    """Two runs (A/B) each resolving to a synthetic analysis.db, both carrying a 'lib.so' with the
    tiny .BinDiff's addresses. Returns the atlas path. The Ghidra versions are parameterized so the
    version-skew criterion (tmap tool_version AND Ghidra version) can be exercised independently."""
    dba = _mk_analysis(
        tmp_path / "a.db",
        "lib.so",
        "sha_a",
        [("0x1000", "keep", "int keep(){}", 64), ("0x2000", "gone_a", "int g(){}", 48)],
    )
    dbb = _mk_analysis(
        tmp_path / "b.db",
        "lib.so",
        "sha_b",
        [("0x1100", "keep", "int keep(){}", 64), ("0x3000", "new_b", "int n(){}", 48)],
    )
    atlas_path = tmp_path / "atlas.db"
    con = open_atlas(atlas_path)
    begin_run(con, "run_a", analysis_db_path=str(dba), tool_version=tool_a, ghidra_version=ghidra_a)
    begin_run(con, "run_b", analysis_db_path=str(dbb), tool_version=tool_b, ghidra_version=ghidra_b)
    con.close()
    return atlas_path


def _tiny_bindiff(tmp_path: Path) -> Path:
    # one high-conf matched pair (0x1000<->0x1100), aligned; addresses match the seeded analysis dbs
    return _mk_bindiff(
        tmp_path / "t.BinDiff",
        [(0x1000, "keep", 0x1100, "keep", 0.98, 0.97, 3, 2, 20)],
    )


def test_orchestrator_writes_all_three_tables_and_is_idempotent(tmp_path: Path) -> None:
    atlas_path = _seed_two_runs(tmp_path)
    bd = _tiny_bindiff(tmp_path)
    con = open_atlas(atlas_path)
    r1 = run_layer0_parse(
        con,
        bindiff_path=bd,
        run_a_id="run_a",
        run_b_id="run_b",
        binary_a="lib.so",
        binary_b="lib.so",
    )
    assert r1.matched_pairs == 1
    q = "SELECT COUNT(*) FROM function_alignment WHERE diff_id=?"
    n1 = con.execute(q, (r1.diff_id,)).fetchone()[0]
    # ★ idempotent: re-parse the same diff -> same row count, no duplicate insert
    run_layer0_parse(
        con,
        bindiff_path=bd,
        run_a_id="run_a",
        run_b_id="run_b",
        binary_a="lib.so",
        binary_b="lib.so",
    )
    n2 = con.execute(q, (r1.diff_id,)).fetchone()[0]
    assert n1 == n2 == 1
    meta_n = con.execute(
        "SELECT COUNT(*) FROM diff_meta WHERE diff_id=?", (r1.diff_id,)
    ).fetchone()[0]
    assert meta_n == 1
    con.close()


def test_diff_meta_functions_empty_is_failures_only_micro_skipped_separate(tmp_path: Path) -> None:
    # ★ diff_meta.functions_empty counts ONLY real failures (== run.functions_empty); design-skipped
    # micro-functions go in a SEPARATE micro_skipped column, never merged (same-name-diff-meaning
    # is exactly the confusion this ticket removes).
    dba = _mk_analysis(
        tmp_path / "a.db",
        "lib.so",
        "sha_a",
        [
            ("0x1000", "keep", "int keep(){}", 64),  # ok
            ("0x4000", "stub", "", 4),  # skipped_micro
            ("0x5000", "failed_fn", "", 200),  # real failure
        ],
    )
    dbb = _mk_analysis(
        tmp_path / "b.db", "lib.so", "sha_b", [("0x1100", "keep", "int keep(){}", 64)]
    )
    con = open_atlas(tmp_path / "atlas.db")
    begin_run(con, "run_a", analysis_db_path=str(dba), tool_version="0.0.1")
    begin_run(con, "run_b", analysis_db_path=str(dbb), tool_version="0.0.1")
    r = run_layer0_parse(
        con,
        bindiff_path=_tiny_bindiff(tmp_path),
        run_a_id="run_a",
        run_b_id="run_b",
        binary_a="lib.so",
        binary_b="lib.so",
    )
    row = con.execute(
        "SELECT functions_empty_a, micro_skipped_a FROM diff_meta WHERE diff_id=?", (r.diff_id,)
    ).fetchone()
    assert row[0] == 1  # only the one real failure
    assert row[1] == 1  # the micro stub, counted separately
    con.close()


def test_presence_rows_expose_unmatched_both_sides(tmp_path: Path) -> None:
    # ★ unmatched functions are EXPLICIT rows (never inferred from absence). A-side 0x2000 (gone_a)
    # and B-side 0x3000 (new_b) are unmatched -> one presence row each; diff_meta counts show it.
    atlas_path = _seed_two_runs(tmp_path)
    con = open_atlas(atlas_path)
    r = run_layer0_parse(
        con,
        bindiff_path=_tiny_bindiff(tmp_path),
        run_a_id="run_a",
        run_b_id="run_b",
        binary_a="lib.so",
        binary_b="lib.so",
    )
    pres = {
        (row[0], row[1]): row[2]
        for row in con.execute(
            "SELECT side, addr, presence_state FROM function_presence WHERE diff_id=?", (r.diff_id,)
        )
    }
    assert pres[("a", "00002000")] == "unmatched_analysis_complete"
    assert pres[("b", "00003000")] == "unmatched_analysis_complete"
    m = con.execute(
        "SELECT unmatched_a, unmatched_b, matched_pairs FROM diff_meta WHERE diff_id=?",
        (r.diff_id,),
    ).fetchone()
    assert (m[0], m[1], m[2]) == (1, 1, 1)
    con.close()


def test_unresolved_run_errors_not_silent_empty(tmp_path: Path) -> None:
    # ★ unresolved run: present but with no recorded analysis.db path -> explicit error, never a
    # guessed path or a silent empty alignment.
    _mk_analysis(tmp_path / "a.db", "lib.so", "s", [("0x1000", "f", "int f(){}", 64)])
    con = open_atlas(tmp_path / "atlas.db")
    begin_run(con, "run_a", analysis_db_path=str(tmp_path / "a.db"), tool_version="0.0.1")
    begin_run(con, "run_b", analysis_db_path=None, tool_version="0.0.1")  # unresolved B
    with pytest.raises(ConfigError, match="no recorded analysis.db"):
        run_layer0_parse(
            con,
            bindiff_path=_tiny_bindiff(tmp_path),
            run_a_id="run_a",
            run_b_id="run_b",
            binary_a="lib.so",
            binary_b="lib.so",
        )
    con.close()


def test_version_skew_uses_tool_version_not_firmware_hash(tmp_path: Path) -> None:
    # ★ version-skew source: A and B are different firmware (different sha by design) — skew comes
    # from the ANALYSIS-TOOL version, not the firmware hash. Same tool -> no skew; differ -> skew.
    con = open_atlas(_seed_two_runs(tmp_path, tool_a="0.0.1", tool_b="0.0.1"))
    r = run_layer0_parse(
        con,
        bindiff_path=_tiny_bindiff(tmp_path),
        run_a_id="run_a",
        run_b_id="run_b",
        binary_a="lib.so",
        binary_b="lib.so",
    )
    assert r.meta.version_skew == 0  # same tool_version despite different firmware sha
    con.close()

    con2 = open_atlas(_seed_two_runs(tmp_path / "skew", tool_a="0.0.1", tool_b="0.0.2"))
    r2 = run_layer0_parse(
        con2,
        bindiff_path=_tiny_bindiff(tmp_path / "skew"),
        run_a_id="run_a",
        run_b_id="run_b",
        binary_a="lib.so",
        binary_b="lib.so",
    )
    assert r2.meta.version_skew == 1  # differing tool_version -> exposed, non-blocking
    con2.close()


def test_query_face_bidirectional_carries_confidence_and_similarity(tmp_path: Path) -> None:
    # ★ single-side lookup both ways, each returning raw confidence + similarity + state.
    con = open_atlas(tmp_path / "atlas.db")
    add_function_alignment(
        con,
        [
            FunctionAlignmentRow(
                diff_id="d",
                addr_a="00001000",
                addr_b="00001100",
                name_a="keep",
                name_b="keep",
                alignment_confidence=0.97,
                similarity=0.6,
                alignment_state="aligned",
                basicblocks=3,
                edges=2,
                instructions=20,
            )
        ],
    )
    fwd = align_by_a(con, "d", "0x1000")  # accepts any address form
    assert fwd["found"] and fwd["pairs"][0]["addr_b"] == "00001100"
    assert fwd["pairs"][0]["alignment_confidence"] == 0.97
    assert fwd["pairs"][0]["similarity"] == 0.6  # change-magnitude carried, not only the state
    rev = align_by_b(con, "d", "00001100")
    assert rev["found"] and rev["pairs"][0]["addr_a"] == "00001000"
    # ★ MATCHED-PAIRS-ONLY: a miss is an honest 'not proof added/removed', not a delete verdict
    miss = align_by_a(con, "d", "0xdead")
    assert miss["found"] is False and "added/removed" in miss["note"]
    con.close()


def test_schema_declares_matched_pairs_only() -> None:
    # ★ the MATCHED-PAIRS-ONLY boundary is declared in the schema itself (not only prose).
    schema = (
        Path(__file__).resolve().parents[2].parent
        / "src"
        / "treasure_map"
        / "lib"
        / "storage"
        / "atlas_schema.sql"
    ).read_text()
    assert "MATCHED PAIRS ONLY" in schema
    assert '"function removed"' in schema  # absence of a row != removed


# ── binary-identity hash validation (a cross-firmware .BinDiff is refused, not silently run) ──


def test_bindiff_binary_hash_mismatch_is_refused(tmp_path: Path) -> None:
    # ★ a .BinDiff whose file-side hash does not match the resolved binary sha256 (the classic
    # cross-firmware misuse) -> explicit ConfigError, and NOT one alignment row written.
    atlas_path = _seed_two_runs(tmp_path)  # analysis dbs carry sha 'sha_a' / 'sha_b'
    bad = _mk_bindiff(
        tmp_path / "bad.BinDiff",
        [(0x1000, "keep", 0x1100, "keep", 0.98, 0.97, 3, 2, 20)],
        file_hashes=("WRONG_HASH", "sha_b"),  # A-side hash does not match binary_a
    )
    con = open_atlas(atlas_path)
    with pytest.raises(ConfigError, match="does not correspond"):
        run_layer0_parse(
            con,
            bindiff_path=bad,
            run_a_id="run_a",
            run_b_id="run_b",
            binary_a="lib.so",
            binary_b="lib.so",
        )
    assert con.execute("SELECT COUNT(*) FROM function_alignment").fetchone()[0] == 0
    con.close()


def test_bindiff_matching_hashes_proceed(tmp_path: Path) -> None:
    # ★ matching file-side hashes -> the parse runs normally (the guard is not a blanket block).
    atlas_path = _seed_two_runs(tmp_path)
    con = open_atlas(atlas_path)
    r = run_layer0_parse(
        con,
        bindiff_path=_tiny_bindiff(tmp_path),
        run_a_id="run_a",
        run_b_id="run_b",
        binary_a="lib.so",
        binary_b="lib.so",
    )
    assert r.matched_pairs == 1  # _tiny_bindiff writes matching ('sha_a','sha_b') hashes
    con.close()


# ── iron law 6: version_skew must carry a REAL tool+Ghidra version difference (not a constant) ──
#
# The consumer side (layer2) is already correct; these anchor
# the PRODUCER.  (tool_version drives skew, forward+reverse) are covered by
# test_version_skew_uses_tool_version_not_firmware_hash above and, on the consumer side, by
# test_diff_layer2.test_version_skew_degrades_every_edge_subject / _zero_restores. The tests here
# cover the Ghidra criterion , the both-unknown conservative direction , anchor
# independence (reverse), and the end-to-end visibility sanity .


def _parse_two_runs(tmp_path: Path, **seed_kw: str):  # type: ignore[no-untyped-def]
    """Seed two runs with the given tool/ghidra versions, run layer-0, return the Layer0Result."""
    con = open_atlas(_seed_two_runs(tmp_path, **seed_kw))
    try:
        return run_layer0_parse(
            con,
            bindiff_path=_tiny_bindiff(tmp_path),
            run_a_id="run_a",
            run_b_id="run_b",
            binary_a="lib.so",
            binary_b="lib.so",
        )
    finally:
        con.close()


def test_confirmed_same_version_contract() -> None:
    # ★ tight anchor +  unconfirmable: 'confirmed same' is True ONLY for two equal REAL
    # versions. A missing value (None) OR the explicit UNKNOWN_VERSION on EITHER side is
    # unconfirmable -> False (cannot-confirm-same != confirmed-same, the conservative direction).
    # ★ both-unknown is the case CC's review added: two failed detections most need skew, so it MUST
    # be False. Deleting layer0's `if a == UNKNOWN_VERSION or b == UNKNOWN_VERSION: return False`
    # line flips this one case to True -> this assertion goes red (its teeth). Anchors on the
    # UNKNOWN_VERSION constant (single source), never the literal "unknown".
    assert layer0._confirmed_same_version("11.0", "11.0") is True
    assert layer0._confirmed_same_version("11.0", "11.1") is False
    assert layer0._confirmed_same_version(UNKNOWN_VERSION, UNKNOWN_VERSION) is False  # both unknown
    assert layer0._confirmed_same_version("11.0", UNKNOWN_VERSION) is False  # one unknown
    assert layer0._confirmed_same_version(UNKNOWN_VERSION, "11.0") is False
    assert layer0._confirmed_same_version("11.0", None) is False  # one NULL (legacy/pre-column run)
    assert layer0._confirmed_same_version(None, None) is False


def test_version_skew_ghidra_criterion_is_live(tmp_path: Path) -> None:
    # ★ /  (regret guard): tool_version EQUAL, Ghidra versions differ -> skew=1. This is
    # the criterion the constant-None used to short-circuit; it proves the Ghidra leg is live and
    # cannot silently degrade to comparing only tool_version.
    r = _parse_two_runs(tmp_path, ghidra_a="11.0", ghidra_b="11.1")
    assert r.meta.version_skew == 1


def test_version_skew_ghidra_criterion_is_load_bearing(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # ★ reverse/independence: force _confirmed_same_version to always-confirm; the SAME
    # ghidra-differing fixture must then drop to skew=0 -> proves the Ghidra criterion (not
    # something else) produced the skew=1 above. If it stayed 1, the forward anchor is not reading
    # the criterion and must be rewritten.
    monkeypatch.setattr(layer0, "_confirmed_same_version", lambda a, b: True)
    r = _parse_two_runs(tmp_path, ghidra_a="11.0", ghidra_b="11.1")
    assert r.meta.version_skew == 0


def test_version_skew_both_unknown_is_conservative(tmp_path: Path) -> None:
    # ★ end-to-end: both sides recorded UNKNOWN_VERSION (two failed detections), tool_version
    # equal -> cannot confirm the same decompiler -> skew=1. The trap CC's audit named: a truthy
    # "unknown" == "unknown" must NOT read as confirmed-same. Deleting layer0's UNKNOWN_VERSION
    # guard line reddens this (both-unknown would fall through to a == b -> skew=0).
    r = _parse_two_runs(tmp_path, ghidra_a=UNKNOWN_VERSION, ghidra_b=UNKNOWN_VERSION)
    assert r.meta.version_skew == 1


def test_version_skew_forward_is_load_bearing(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # ★ anchor independence: break _version_skew (force False); a tool_version-differing diff
    # must then report version_skew=0 -> proves the forward skew assertions genuinely read
    # _version_skew's output, not a constant.
    monkeypatch.setattr(layer0, "_version_skew", lambda a, b: False)
    r = _parse_two_runs(tmp_path, tool_a="0.0.1", tool_b="0.0.2")
    assert r.meta.version_skew == 0


def test_diff_meta_records_ghidra_version_not_null(tmp_path: Path) -> None:
    # (INTEGRATION SANITY, not a mechanical anchor): a normal run stamps the recorded Ghidra
    # version onto diff_meta, visible (never NULL) so a consumer tells "unknown" (detection failed)
    # from NULL (field never implemented). ★ The "never NULL" invariant's TEETH live in the
    # per-layer anchors -- facts._run_ghidra_version and detect_ghidra_version --
    # because a single-point mutate does NOT redden THIS end-to-end assertion (the two sentinels
    # mask each other), so it is sanity only, deliberately not relied on as a guard.
    r = _parse_two_runs(tmp_path, ghidra_a="11.4.3", ghidra_b="11.4.3")
    assert r.meta.ghidra_version_a == "11.4.3"
    assert r.meta.ghidra_version_b == "11.4.3"


# ── Bug A: diff_meta records the diff's target binary short name ──


def test_diff_meta_binary_normalized_to_short_name(tmp_path: Path) -> None:
    # ★ Bug A: run_layer0_parse given a SHA256-form binary must STORE the short NAME in
    # diff_meta.binary_a/b -- layer-2 filters on string_keyed_edge.binary (short name), so a stored
    # sha would zero-match and silently drop every edge (over-filter). _seed_two_runs
    # gives lib.so the sha 'sha_a'/'sha_b'; passing those (the sha form) must still record 'lib.so'.
    con = open_atlas(_seed_two_runs(tmp_path))
    r = run_layer0_parse(
        con,
        bindiff_path=_tiny_bindiff(tmp_path),
        run_a_id="run_a",
        run_b_id="run_b",
        binary_a="sha_a",  # SHA256 form, not the short name
        binary_b="sha_b",
    )
    assert r.meta.binary_a == "lib.so"  # normalized to the short name, NOT the sha
    assert r.meta.binary_b == "lib.so"
    con.close()
