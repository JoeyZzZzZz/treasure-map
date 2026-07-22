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
from treasure_map.lib.atlas.models import FunctionAlignmentRow
from treasure_map.lib.atlas.writer import add_function_alignment, begin_run
from treasure_map.lib.diff.layer0 import (
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


def _mk_bindiff(path: Path, rows: list[tuple]) -> Path:  # type: ignore[type-arg]
    """A tiny synthetic .BinDiff (only the columns layer-0 reads). rows = (a1,n1,a2,n2,sim,conf,
    bb,edges,instr)."""
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
    con.commit()
    con.close()
    return path


def _mk_analysis(path: Path, binary: str, sha: str, funcs: list[tuple]) -> Path:  # type: ignore[type-arg]
    """A synthetic analysis.db with one binary + funcs = (address, name, pseudocode)."""
    con = open_db(path)
    con.execute(
        "INSERT INTO binaries (id, name, path, sha256) VALUES (1, ?, ?, ?)", (binary, binary, sha)
    )
    for addr, name, pc in funcs:
        con.execute(
            "INSERT INTO functions (binary_id, name, address, pseudocode) VALUES (1, ?, ?, ?)",
            (name, addr, pc),
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


def test_out_of_inventory_never_counts_as_unmatched(tmp_path: Path) -> None:
    # ★ the phantom guard (real fw: 737 out-of-inventory): a matched pair whose A addr is NOT in
    # tmap's inventory (a thunk BinDiff keeps but the exporter skips) is out_of_inventory — NEVER an
    # unmatched presence row.
    db = _mk_analysis(tmp_path / "a.db", "lib.so", "s", [("0x1000", "real_fn", "int f(){}")])
    base = load_baseline(str(db), "lib.so")
    # matched: one addr in inventory (0x1000) + one NOT in inventory (0x9999 = a thunk)
    pres = compute_side_presence("d", "a", frozenset({"00001000", "00009999"}), base)
    assert pres.out_of_inventory == 1  # 0x9999 matched but not in inventory
    assert pres.unmatched == 0  # 0x1000 matched; nothing left unmatched
    assert pres.matched_in_domain == 1
    assert pres.rows == []  # no phantom unmatched row


def test_decompile_gap_is_undetermined_not_add_delete(tmp_path: Path) -> None:
    # ★ decompile-gap honesty: an unmatched function that never decompiled (empty pseudocode) MUST
    # read unmatched_decompile_missing (existence undetermined), NEVER a possible add/delete.
    db = _mk_analysis(
        tmp_path / "a.db",
        "lib.so",
        "s",
        [("0x1000", "decompiled_fn", "int f(){}"), ("0x2000", "empty_fn", "")],
    )
    base = load_baseline(str(db), "lib.so")
    assert base.empty_count == 1
    pres = compute_side_presence("d", "a", frozenset(), base)  # nothing matched -> both unmatched
    by_addr = {r.addr: r for r in pres.rows}
    assert by_addr["00001000"].presence_state == "unmatched_both_decompiled"
    assert by_addr["00002000"].presence_state == "unmatched_decompile_missing"  # gap != add/delete


# ── orchestrator + query face (synthetic atlas + analysis.db) ────────────────────────────


def _seed_two_runs(tmp_path: Path, *, tool_a: str = "0.0.1", tool_b: str = "0.0.1") -> Path:
    """Two runs (A/B) each resolving to a synthetic analysis.db, both carrying a 'lib.so' with the
    tiny .BinDiff's addresses. Returns the atlas path."""
    dba = _mk_analysis(
        tmp_path / "a.db",
        "lib.so",
        "sha_a",
        [("0x1000", "keep", "int keep(){}"), ("0x2000", "gone_a", "int g(){}")],
    )
    dbb = _mk_analysis(
        tmp_path / "b.db",
        "lib.so",
        "sha_b",
        [("0x1100", "keep", "int keep(){}"), ("0x3000", "new_b", "int n(){}")],
    )
    atlas_path = tmp_path / "atlas.db"
    con = open_atlas(atlas_path)
    begin_run(con, "run_a", analysis_db_path=str(dba), tool_version=tool_a, ghidra_version="11.4.3")
    begin_run(con, "run_b", analysis_db_path=str(dbb), tool_version=tool_b, ghidra_version="11.4.3")
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
    assert pres[("a", "00002000")] == "unmatched_both_decompiled"
    assert pres[("b", "00003000")] == "unmatched_both_decompiled"
    m = con.execute(
        "SELECT unmatched_a, unmatched_b, matched_pairs FROM diff_meta WHERE diff_id=?",
        (r.diff_id,),
    ).fetchone()
    assert (m[0], m[1], m[2]) == (1, 1, 1)
    con.close()


def test_unresolved_run_errors_not_silent_empty(tmp_path: Path) -> None:
    # ★ unresolved run: present but with no recorded analysis.db path -> explicit error, never a
    # guessed path or a silent empty alignment.
    _mk_analysis(tmp_path / "a.db", "lib.so", "s", [("0x1000", "f", "int f(){}")])
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
