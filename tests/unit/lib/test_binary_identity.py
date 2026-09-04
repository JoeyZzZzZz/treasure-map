# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""A short name is a LABEL; the binary's identity is its row.

One firmware ships the same ``libshared.so.6`` under two roots, with different content, different
function tables and different data. Every read that selected a binary by name and took what came
back was answering about whichever row the database returned — silently, and not necessarily the
same row for two queries over the same firmware. This file pins the replacement: one resolver,
which refuses an ambiguous selector with its candidates and never picks; and callers that carry the
resolved identity onward instead of re-resolving a name they already turned into a row.

Three fixture shapes, because the ways this went wrong were not all the same:
  I   -- each binary has addresses the other lacks (the plain overlap case);
  II  -- one binary's addresses are a SUBSET of the other's, with different function names at the
         shared addresses (a merged domain looks complete and is wrong about every shared address);
  III -- three binaries under one name (a fix that only ever compares two would pass I and II).
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from treasure_map.lib import facts
from treasure_map.lib.binary_id import resolve_binary, resolve_binary_in_db
from treasure_map.lib.storage.connection import open_db

NAME = "libshared.so.6"
SHA = {"A": "a" * 64, "B": "b" * 64, "C": "c" * 64}
PATHS = {
    "A": "ftpclient/usr/lib/libshared.so.6",
    "B": "lib/libshared.so.6",
    "C": "opt/lib/libshared.so.6",
}
# Same short name, same address, different function name: the shape that makes a merged baseline
# domain wrong about the entries it does contain rather than merely short.
SHAPES: dict[str, dict[str, list[tuple[str, str, list[str]]]]] = {
    # side -> [(address, function name, callees)]
    "I": {
        "A": [
            ("0x1000", "only_a_fn", []),
            ("0x2000", "target", []),
            ("0x3000", "calls_b_only", ["b_only_fn"]),
            ("0xa000", "widen", ["target"]),
            ("0xa010", "widen", ["target"]),
            ("0xa020", "widen", ["target"]),
        ],
        "B": [
            ("0x9000", "only_b_fn", []),
            ("0x2000", "target", []),
            ("0x4000", "b_only_fn", []),
            # ★ 0xa000 is DELIBERATELY an address A also uses for a ``widen``. Two same-named
            # functions at the same address in two same-named binaries is what makes the binary
            # ID load-bearing in the caller dedup key — without it, one of them disappears.
            ("0xa000", "widen", ["target"]),
            ("0xb010", "widen", ["target"]),
        ],
    },
    "II": {
        "A": [
            ("0x1000", "real_init", []),
            ("0x1010", "parse", []),
            ("0x2000", "target", []),
            ("0x3000", "calls_b_only", ["b_only_fn"]),
            ("0xa000", "widen", ["target"]),
            ("0xa010", "widen", ["target"]),
            ("0xa020", "widen", ["target"]),
        ],
        # a strict SUBSET of A's addresses, different names where they meet
        "B": [
            ("0x1000", "_DT_INIT", []),
            ("0x1010", "FUN_1010", []),
            ("0x2000", "target", []),
            ("0xa000", "widen", ["target"]),
            ("0xa010", "widen", ["target"]),
        ],
    },
    "III": {
        "A": [
            ("0x1000", "only_a_fn", []),
            ("0x2000", "target", []),
            ("0x3000", "calls_b_only", ["b_only_fn"]),
            ("0xa000", "widen", ["target"]),
            ("0xa010", "widen", ["target"]),
            ("0xa020", "widen", ["target"]),
        ],
        "B": [
            ("0x9000", "only_b_fn", []),
            ("0x2000", "target", []),
            ("0x4000", "b_only_fn", []),
            ("0xa000", "widen", ["target"]),  # same address as one of A's widen — see shape I
            ("0xb010", "widen", ["target"]),
        ],
        "C": [("0x5000", "only_c_fn", []), ("0x2000", "target", [])],
    },
}


def _build(db_path: Path, shape: str) -> Path:
    """One analysis.db whose binaries all share NAME, differing in path, sha and content."""
    conn = open_db(db_path)
    sides = SHAPES[shape]
    for bid, side in enumerate(sorted(sides), start=1):
        conn.execute(
            # last_seen_at is LOAD-BEARING: current_binaries selects on MAX(last_seen_at) and
            # NULL never equals NULL, so omitting it empties the view and nothing resolves.
            "INSERT INTO binaries (id, name, path, sha256, last_seen_at, pass_version) "
            "VALUES (?, ?, ?, ?, '2026-01-01T00:00:00', 'pv')",
            (bid, NAME, PATHS[side], SHA[side]),
        )
        for addr, fname, callees in sides[side]:
            conn.execute(
                "INSERT INTO functions (binary_id, name, address, size_bytes, pseudocode, callees) "
                "VALUES (?, ?, ?, 64, ?, ?)",
                (bid, fname, addr, f"void {fname}(void){{ /* {side} */ }}", json.dumps(callees)),
            )
        conn.execute(
            "INSERT INTO strings (binary_id, value, address, category) VALUES (?, ?, '0x8000', ?)",
            (bid, f"only_in_{side}", "generic"),
        )
        conn.execute(
            "INSERT INTO imports (binary_id, func_name, lib_soname) VALUES (?, ?, 'libc.so.0')",
            (bid, f"imp_{side}"),
        )
        conn.execute(
            "INSERT INTO exports (binary_id, func_name, address) VALUES (?, ?, '0x2000')",
            (bid, f"exp_{side}"),
        )
        # Same block address on every side, different bytes: reading it by short name cannot be
        # right for more than one of them.
        conn.execute(
            "INSERT INTO data_blocks (binary_id, block_name, start_addr, size, bytes, "
            "initialized, executable, truncated) VALUES (?, '.rodata', '0x30000', 8, ?, 1, 0, 0)",
            (bid, side.encode() * 8),
        )
        conn.execute(
            "INSERT INTO string_refs (binary_id, string_addr, string_value, ref_at, ref_in_func, "
            "ref_in_func_addr, segment) VALUES (?, '0x8000', ?, '0x8100', ?, '0x2000', '.text')",
            (bid, f"only_in_{side}", f"target_{side}"),
        )
    # ★ A cross-binary xref edge: B's ``widen`` at the shared address calls A's ``target``. This
    # is what SEEDS the caller dedup set on the A-side query — and it is how the collision showed
    # up in production: the seed came from the OTHER same-named binary, and a name-keyed dedup then
    # suppressed every one of A's own callers. The edge must also survive in the answer.
    a_target = conn.execute(
        "SELECT f.id FROM functions f JOIN binaries b ON b.id = f.binary_id "
        "WHERE f.name = 'target' AND b.path = ?",
        (PATHS["A"],),
    ).fetchone()
    b_widen = conn.execute(
        "SELECT f.id, f.binary_id FROM functions f JOIN binaries b ON b.id = f.binary_id "
        "WHERE f.name = 'widen' AND f.address = '0xa000' AND b.path = ?",
        (PATHS["B"],),
    ).fetchone()
    if a_target and b_widen:
        conn.execute(
            "INSERT INTO xrefs (caller_binary_id, caller_func_id, callee_binary_id, "
            "callee_func_id, xref_type, confidence) VALUES (?, ?, ?, ?, 'import_export', 1.0)",
            (b_widen[1], b_widen[0], 1 if PATHS["A"] < PATHS["B"] else 2, a_target[0]),
        )
    conn.commit()
    conn.close()
    return db_path


@pytest.fixture(params=["I", "II", "III"])
def same_name_binaries_db(request: pytest.FixtureRequest, tmp_path: Path) -> Path:
    return _build(tmp_path / f"shape_{request.param}.db", request.param)


def _ro(db: Path) -> sqlite3.Connection:
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    return con


def _expected_paths(db: Path) -> set[str]:
    con = _ro(db)
    try:
        return {r["path"] for r in con.execute("SELECT path FROM current_binaries")}
    finally:
        con.close()


# ────────────────────────────────────────────────────────── the resolver itself


def test_the_fixture_really_is_ambiguous(same_name_binaries_db: Path) -> None:
    """Asserted first: every refusal test below passes vacuously on a one-binary fixture."""
    assert len(_expected_paths(same_name_binaries_db)) >= 2


def test_a_shared_short_name_is_refused_with_every_candidate(same_name_binaries_db: Path) -> None:
    """★ The rule. More than one row means the caller's request has more than one answer, so the
    answer is the list — never one of them.

    MUTATION: return ``rows[0]`` instead of the ambiguous refusal -> RED here and in every
    tool-level test below.
    """
    con = _ro(same_name_binaries_db)
    try:
        row, miss = resolve_binary(con, NAME)
    finally:
        con.close()
    assert row is None
    assert miss is not None and miss["reason"] == "ambiguous"
    assert {c["binary_path"] for c in miss["candidates"]} == _expected_paths(same_name_binaries_db)
    assert all(c["sha256"] for c in miss["candidates"])


@pytest.mark.parametrize("form", ["sha", "sha_prefix", "path"])
def test_an_identity_selector_resolves_to_exactly_one(
    same_name_binaries_db: Path, form: str
) -> None:
    """The three ways to name ONE binary: full sha, an >=8-hex prefix, the recorded path."""
    selector = {"sha": SHA["A"], "sha_prefix": SHA["A"][:8], "path": PATHS["A"]}[form]
    con = _ro(same_name_binaries_db)
    try:
        row, miss = resolve_binary(con, selector)
    finally:
        con.close()
    assert miss is None and row is not None
    assert row.sha256 == SHA["A"] and row.path == PATHS["A"]


def test_an_unknown_selector_is_not_found_not_ambiguous(same_name_binaries_db: Path) -> None:
    con = _ro(same_name_binaries_db)
    try:
        row, miss = resolve_binary(con, "no_such_binary_here")
    finally:
        con.close()
    assert row is None and miss is not None and miss["reason"] == "not_found"


def test_an_unreadable_db_is_a_miss_never_an_exception(tmp_path: Path) -> None:
    """``resolve_binary_in_db`` runs inside failure handlers, where raising would replace the error
    being reported with a different one."""
    row, miss = resolve_binary_in_db(str(tmp_path / "nope.db"), NAME)
    assert row is None and miss is not None and miss["reason"] == "db_error"


# ────────────────────────────────────────────────────────── the fact tools


def _tools(db: Path) -> Any:
    return facts


@pytest.mark.parametrize(
    "call",
    [
        "get_strings",
        "get_imports_exports",
        "get_data_bytes",
        "get_string_reference_anchors",
        "get_functions_referencing_string",
    ],
)
def test_a_by_name_tool_refuses_and_lists_the_candidates(
    same_name_binaries_db: Path, call: str
) -> None:
    """Every tool that takes a binary selector refuses the shared name the same way.

    MUTATION: restore a ``WHERE name = ? … LIMIT 1`` lookup in any of them -> that parameter RED.
    """
    con = _ro(same_name_binaries_db)
    try:
        res = {
            "get_strings": lambda: facts.get_strings(con, binary=NAME),
            "get_imports_exports": lambda: facts.get_imports_exports(con, binary=NAME),
            "get_data_bytes": lambda: facts.get_data_bytes(
                con, binary=NAME, address="0x30000", length=8
            ),
            "get_string_reference_anchors": lambda: facts.get_string_reference_anchors(
                con, text="only_in_A", binary=NAME
            ),
            "get_functions_referencing_string": lambda: facts.get_functions_referencing_string(
                con, text="void", binary=NAME
            ),
        }[call]()
    finally:
        con.close()
    if call == "get_functions_referencing_string":
        # This one filters rather than selects, so it does not refuse — but every hit must say
        # WHICH binary it came from, or the caller cannot tell the two apart.
        assert {f["binary_path"] for f in res["functions"]} == _expected_paths(
            same_name_binaries_db
        )
        return
    assert res["found"] is False
    assert res["reason"] == "ambiguous"
    assert {c["binary_path"] for c in res["candidates"]} == _expected_paths(same_name_binaries_db)


def test_an_identity_selector_returns_only_that_binarys_content(
    same_name_binaries_db: Path,
) -> None:
    """Resolved by sha, every read is scoped to that row — not merged with its namesakes."""
    con = _ro(same_name_binaries_db)
    try:
        strings = facts.get_strings(con, binary=SHA["A"])
        imports = facts.get_imports_exports(con, binary=SHA["A"])
        data = facts.get_data_bytes(con, binary=SHA["A"], address="0x30000", length=8)
    finally:
        con.close()
    assert [s["value"] for s in strings["strings"]] == ["only_in_A"]
    assert [i["func_name"] for i in imports["imports"]] == ["imp_A"]
    assert imports["binary_path"] == PATHS["A"]
    assert bytes.fromhex(data["bytes"]) == b"A" * 8


@pytest.mark.parametrize("call", ["get_pseudocode", "get_callees", "get_xrefs"])
def test_a_function_shared_by_both_binaries_is_ambiguous_until_qualified(
    same_name_binaries_db: Path, call: str
) -> None:
    """``target`` exists in every side, so naming it alone names several functions. The candidate
    anchors must differ by PATH — differing only by short name would leave the caller no way to
    pick one."""
    con = _ro(same_name_binaries_db)
    try:
        res = {
            "get_pseudocode": lambda: facts.get_pseudocode(con, func="target"),
            "get_callees": lambda: facts.get_callees(con, func="target"),
            "get_xrefs": lambda: facts.get_xrefs(con, func="target", direction="callers"),
        }[call]()
        qualified = facts.get_pseudocode(con, func="target", binary=PATHS["A"])
    finally:
        con.close()
    assert res["found"] is False and res["reason"] == "ambiguous"
    paths = [c["binary_path"] for c in res["candidates"]]
    assert len(paths) == len(set(paths)) >= 2
    assert qualified["found"] is True and qualified["anchor"]["binary_path"] == PATHS["A"]


def test_get_strings_with_func_uses_the_functions_own_binary(same_name_binaries_db: Path) -> None:
    """★ A function that resolved uniquely must not be dragged back into an ambiguity.

    ``only_a_fn`` exists in one binary only, so ``func`` alone resolves it. The search is then
    scoped to ITS binary — with or without a ``binary`` argument, and even when that argument is
    the shared short name.

    MUTATION: re-resolve ``binary`` and let it override ``frow["binary_id"]`` -> RED (the shared
    name refuses, and the call that had already identified one function fails).
    """
    if "only_a_fn" not in {f[1] for f in SHAPES["I"]["A"]}:  # pragma: no cover - fixture guard
        pytest.skip("shape has no A-only function")
    con = _ro(same_name_binaries_db)
    try:
        target = "only_a_fn" if _has(same_name_binaries_db, "only_a_fn") else "real_init"
        with_binary = facts.get_strings(con, binary=NAME, func=target, value="only_in")
        without = facts.get_strings(con, func=target, value="only_in")
    finally:
        con.close()
    for res in (with_binary, without):
        assert res.get("reason") != "ambiguous", res
        assert res["found"] is True
        assert {s["value"] for s in res["strings"]} <= {"only_in_A"}
        assert res["query"]["binary_path"] == PATHS["A"]


def _has(db: Path, fname: str) -> bool:
    con = _ro(db)
    try:
        return (
            con.execute("SELECT 1 FROM functions WHERE name = ? LIMIT 1", (fname,)).fetchone()
            is not None
        )
    finally:
        con.close()


def test_a_callee_that_lives_in_the_other_binary_is_not_resolved_in_this_one(
    same_name_binaries_db: Path,
) -> None:
    """★ ``resolved_in_binary`` says the call stays inside this file. Scoping the function set by
    short name pooled both binaries' functions, so a callee that exists ONLY in the namesake came
    back true — a claim that the call is local when it is not.

    MUTATION: scope the same-binary set by ``b.name = ?`` again -> RED.
    """
    if not _has(same_name_binaries_db, "calls_b_only"):  # shape II's B is a subset; still present
        pytest.skip("shape has no cross-binary callee")
    con = _ro(same_name_binaries_db)
    try:
        res = facts.get_callees(con, func="calls_b_only", binary=PATHS["A"])
    finally:
        con.close()
    by_name = {c["name"]: c["resolved_in_binary"] for c in res["callees"]}
    assert by_name["b_only_fn"] is False


def test_reverse_callers_are_not_collapsed_by_a_shared_short_name(
    same_name_binaries_db: Path,
) -> None:
    """★ THE SILENT LOSS. Same-binary callers are recovered by reverse-scanning callee lists and
    de-duplicated; keyed on (name, SHORT NAME), every ``widen`` in the second binary collided with
    the first one seen and was dropped. A caller set that comes back short reads exactly like a
    function with few callers.

    Addressed by PATH, each side must return its OWN ``widen`` addresses, in full.

    MUTATION: key the dedup on the short name again -> RED (the second binary's set empties).
    """
    con = _ro(same_name_binaries_db)
    try:
        expected = {
            side: {
                r["address"]
                for r in con.execute(
                    "SELECT f.address FROM functions f JOIN binaries b ON b.id = f.binary_id "
                    "WHERE f.name = 'widen' AND b.path = ?",
                    (PATHS[side],),
                )
            }
            for side in ("A", "B")
        }
        got = {
            side: facts.get_xrefs(con, func="target", binary=PATHS[side], direction="callers")
            for side in ("A", "B")
        }
    finally:
        con.close()
    for side in ("A", "B"):
        edges = got[side]["edges"]
        addrs = {
            e["anchor"]["address"]
            for e in edges
            if e["anchor"]["function"] == "widen" and e["anchor"]["binary_path"] == PATHS[side]
        }
        assert addrs == expected[side], side
        assert expected[side], "the fixture must give this side callers, or the test proves nothing"
    # ★ The cross-binary xref edge — B's widen calling A's target — is still in A's answer. It is
    # what seeds the dedup set, so a fix that simply stopped seeding would pass the sets above
    # while silently dropping a real edge.
    cross = {
        e["anchor"]["address"]
        for e in got["A"]["edges"]
        if e["anchor"]["binary_path"] == PATHS["B"] and e["anchor"]["function"] == "widen"
    }
    assert cross == {"0xa000"}


def test_every_anchor_carries_a_binary_path(same_name_binaries_db: Path) -> None:
    """A cross-tool anchor names the binary; with a repeated short name, the name alone does not
    identify one, so the path travels with it everywhere."""
    con = _ro(same_name_binaries_db)
    try:
        results = [
            facts.get_pseudocode(con, func="target", binary=PATHS["A"]),
            facts.get_callees(con, func="target", binary=PATHS["A"]),
            facts.get_xrefs(con, func="target", binary=PATHS["A"], direction="callers"),
            facts.get_disassembly(con, func="target", binary=PATHS["A"]),
        ]
        ambiguous = facts.get_pseudocode(con, func="target")
    finally:
        con.close()
    for res in results:
        assert "binary_path" in res["anchor"], res
    for edge in results[2]["edges"]:
        assert "binary_path" in edge["anchor"]
    for cand in ambiguous["candidates"]:
        assert "binary_path" in cand


# ────────────────────────────────────────────────────────── the diff side


def _two_runs(tmp_path: Path, shape: str) -> Path:
    """An atlas whose two runs both resolve to a same-name-binaries analysis.db."""
    from treasure_map.lib.atlas.connection import open_atlas
    from treasure_map.lib.atlas.writer import begin_run, finish_run

    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    for side in ("a", "b"):
        db = _build(tmp_path / f"{side}.db", shape)
        begin_run(
            conn,
            f"run_{side}",
            analysis_db_path=str(db),
            firmware_path=str(tmp_path),
            tool_version="0.0.1",
            ghidra_version="11.4.3",
        )
        finish_run(conn, f"run_{side}")
    conn.close()
    return atlas


def test_preflight_refuses_a_shared_short_name_naming_the_candidates(
    tmp_path: Path, same_name_binaries_db: Path
) -> None:
    """★ The refusal happens at the ENTRY, in its own words.

    Pushed any further, the ambiguity surfaced as ".BinDiff does not correspond to the two runs'
    binaries" — a cross-firmware message for a same-firmware problem — or as an assertion that
    vanishes under -O, letting a None name flow into the diff_id and the diff_meta scope columns.

    MUTATION: skip the resolution in preflight and pass the selector down -> RED (the error is
    raised somewhere else, with the wrong text, or not at all).
    """
    from treasure_map.lib.atlas.connection import open_atlas
    from treasure_map.lib.config.config import Config
    from treasure_map.lib.diff import driver

    shape = same_name_binaries_db.stem.split("_")[-1]
    atlas = open_atlas(_two_runs(tmp_path / f"d{shape}", shape))
    try:
        with pytest.raises(driver.AmbiguousBinarySelectorError) as exc:
            driver.preflight(atlas, "run_a", "run_b", NAME, config=Config(), force=False)
    finally:
        atlas.close()
    msg = str(exc.value)
    assert "MORE THAN ONE binary" in msg
    assert "does not correspond" not in msg
    # ★ Side A by name. Both sides are ambiguous here, so an implementation that skipped A and
    # tripped on B would raise an identical-looking error — the run id is what tells them apart,
    # and without it this assertion passes on a preflight that never checked side A at all.
    assert "run 'run_a'" in msg
    for path in _expected_paths(same_name_binaries_db):
        assert path in msg


def test_a_full_diff_records_the_refusal_as_that_binarys_blind_spot(tmp_path: Path) -> None:
    """A refusal that lives only in the console scrolls away. Recorded, it is queryable with a
    reason that names the fix — and it is a DIFFERENT reason from a toolchain failure, because a
    retry will not help.

    MUTATION: let the ambiguous error fall through to the generic outcome path without recording
    -> RED (no diff_meta row).
    """
    from treasure_map.lib.atlas.connection import open_atlas
    from treasure_map.lib.diff import driver

    atlas = open_atlas(_two_runs(tmp_path, "I"))
    try:
        driver._record_diff_failure(
            atlas,
            diff_id=driver.make_diff_id("run_a", "run_b", NAME),
            run_a_id="run_a",
            run_b_id="run_b",
            binary_short=NAME,
            exc=driver.AmbiguousBinarySelectorError("two of them"),
        )
        row = atlas.execute(
            "SELECT diff_ok, diff_status, diff_status_reason FROM diff_meta"
        ).fetchone()
    finally:
        atlas.close()
    assert row["diff_ok"] == 0
    assert row["diff_status"] == "failed"
    assert row["diff_status_reason"] == driver.AMBIGUOUS_SELECTOR_REASON


def test_load_baseline_is_the_resolved_binarys_whole_function_map(
    same_name_binaries_db: Path,
) -> None:
    """★ The baseline domain decides presence, so it must be exactly ONE binary's inventory.

    Selecting by ``name OR sha256`` merged every namesake's functions into one map — and because
    a later row overwrites an earlier one at the same address, shape II's subset binary silently
    renamed the entries it shared with the other. The domain then belonged to no binary at all.

    MUTATION: restore the ``WHERE b.name = ? OR b.sha256 = ?`` query (taking a selector) -> RED on
    shape II, where the shared addresses carry different names.
    """
    from treasure_map.lib.diff.layer0 import load_baseline

    con = _ro(same_name_binaries_db)
    try:
        rows = con.execute("SELECT id, path FROM current_binaries").fetchall()
        expected = {
            r["path"]: {
                f["address"].removeprefix("0x").lower().zfill(8): f["name"]
                for f in con.execute(
                    "SELECT address, name FROM functions WHERE binary_id = ?", (r["id"],)
                )
            }
            for r in rows
        }
    finally:
        con.close()
    for path, want in expected.items():
        row, miss = resolve_binary_in_db(str(same_name_binaries_db), path)
        assert row is not None, miss
        base = load_baseline(str(same_name_binaries_db), row)
        assert {addr: nm for addr, (nm, _st) in base.functions.items()} == want, path


def test_current_shas_returns_none_for_an_ambiguous_selector_and_never_raises(
    tmp_path: Path,
) -> None:
    """It runs inside an except handler. An exception here would replace the failure being
    reported with a different one, and a None sha is already the honest "cannot confirm".

    MUTATION: make it raise (or return one of the candidates) on ambiguity -> RED.
    """
    from treasure_map.lib.atlas.connection import open_atlas
    from treasure_map.lib.diff import driver

    atlas = open_atlas(_two_runs(tmp_path, "I"))
    try:
        assert driver._current_shas(atlas, "run_a", "run_b", NAME) == (None, None)
        # the counterpart: an identity selector still yields both shas
        assert driver._current_shas(atlas, "run_a", "run_b", SHA["A"]) == (SHA["A"], SHA["A"])
    finally:
        atlas.close()


def test_read_binaries_keeps_every_sha_and_the_plan_says_undecidable(tmp_path: Path) -> None:
    """★ Collapsing a name to one sha answered "did this binary change" about an arbitrary pick,
    and the answer could flip with nothing observable changing. Every sha is kept, and a name that
    carries more than one is reported as undecidable rather than compared.

    The partition is asserted as an equation: changed + unchanged + ambiguous == names in both.

    MUTATION: return ``{r[0]: r[1]}`` from _read_binaries -> RED (the name reads as decidable, and
    the partition no longer covers it).
    """
    from treasure_map.lib.atlas.connection import open_atlas
    from treasure_map.lib.diff import driver

    atlas_path = _two_runs(tmp_path, "I")
    # a second, unambiguous binary so the plan has something it CAN decide
    for side in ("a", "b"):
        con = sqlite3.connect(tmp_path / f"{side}.db")
        con.execute(
            "INSERT INTO binaries (id, name, path, sha256, last_seen_at) "
            "VALUES (99, 'solo', 'bin/solo', ?, '2026-01-01T00:00:00')",
            (("d" if side == "a" else "e") * 64,),
        )
        con.commit()
        con.close()

    inv = driver._read_binaries(str(tmp_path / "a.db"))
    assert inv[NAME] == tuple(sorted((SHA["A"], SHA["B"])))
    assert inv["solo"] == ("d" * 64,)

    atlas = open_atlas(atlas_path)
    try:
        plan = driver.plan_full_diff(atlas, "run_a", "run_b")
    finally:
        atlas.close()
    assert NAME in plan.ambiguous_by_name
    assert NAME not in plan.changed and NAME not in plan.unchanged
    assert "solo" in plan.changed  # different sha per side -> decidable and changed
    both = set(driver._read_binaries(str(tmp_path / "a.db"))) & set(
        driver._read_binaries(str(tmp_path / "b.db"))
    )
    assert len(plan.changed) + len(plan.unchanged) + len(plan.ambiguous_by_name) == len(both)


# ────────────────────────────────────────────── the write side: rows carry the path


def test_hunt_records_the_binary_path_beside_every_short_name(tmp_path: Path) -> None:
    """★ Each of these tables scoped a row to a binary by its SHORT NAME, which is a label: a
    per-binary filter on the name matches every file that answers to it. The path is written
    beside the name — the name stays what a caller types, the path is what says which file.

    MUTATION: drop ``binary_path=`` from any producer -> RED for that table.
    """
    from treasure_map.lib.hunt import run_analyzer2

    db = tmp_path / "analysis.db"
    conn = open_db(db)
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256, last_seen_at) "
        "VALUES (1, 'webd', 'usr/sbin/webd', ?, '2026-01-01T00:00:00')",
        ("a" * 64,),
    )
    conn.execute(
        "INSERT INTO functions (binary_id, name, address, pseudocode, callees, sink_provenance, "
        "nvram_ops) VALUES (1, 'handler', '00011000', ?, ?, ?, ?)",
        (
            'void handler(char *p){ nvram_get("wan_proto"); system("helper -d"); }',
            json.dumps(["nvram_get", "system"]),
            json.dumps(
                [
                    {
                        "sink_idx": 0,
                        "sink": "system",
                        "sink_addr": "0x11020",
                        "arg_idx": 0,
                        "provenance": {"kind": "constant", "resolved": True, "value": "helper -d"},
                    }
                ]
            ),
            json.dumps(
                [{"op": "read", "key": "wan_proto", "key_kind": "constant", "api": "nvram_get"}]
            ),
        ),
    )
    conn.commit()
    conn.close()

    atlas_path = tmp_path / "atlas.db"
    run_analyzer2(db, atlas_path, source_run_id="run1")

    from treasure_map.lib.atlas.connection import open_atlas

    atlas = open_atlas(atlas_path)
    try:
        for table, name_col, path_col in (
            ("exec_edge", "launcher_binary", "launcher_binary_path"),
            ("detector_scan_status", "binary", "binary_path"),
            ("nvram_key_flow", "binary", "binary_path"),
        ):
            rows = atlas.execute(
                f"SELECT {name_col}, {path_col} FROM {table}"  # noqa: S608 -- literal names
            ).fetchall()
            assert rows, f"{table} produced no rows, so the column proves nothing"
            for r in rows:
                assert r[0] == "webd"
                assert r[1] == "usr/sbin/webd", table
    finally:
        atlas.close()


def test_a_diff_records_which_file_it_aligned(tmp_path: Path) -> None:
    """diff_meta stores the short name for the per-binary filter; the path says which of the files
    under that name was actually diffed.

    ★ Driven through ``run_layer0_parse``, not through the writer: the writer only proves the
    column exists, while the claim is that the DIFF fills it in. A test that inserts the row itself
    passes just as well when layer 0 stops passing the paths.

    MUTATION: drop ``binary_path_a/_b`` from the layer-0 write -> RED. Measured RED at 1 failed.
    """
    from tests.unit.lib.test_diff_layer0 import _bins, _seed_two_runs, _tiny_bindiff
    from treasure_map.lib.atlas.connection import open_atlas
    from treasure_map.lib.diff.layer0 import run_layer0_parse

    atlas = open_atlas(_seed_two_runs(tmp_path))
    try:
        res = run_layer0_parse(
            atlas,
            bindiff_path=_tiny_bindiff(tmp_path),
            run_a_id="run_a",
            run_b_id="run_b",
            **_bins(atlas, "run_a", "run_b", "lib.so"),
        )
        row = atlas.execute(
            "SELECT binary_a, binary_path_a, binary_path_b FROM diff_meta WHERE diff_id = ?",
            (res.diff_id,),
        ).fetchone()
    finally:
        atlas.close()
    assert row["binary_a"] == "lib.so"  # the short name still scopes the per-binary filter
    assert row["binary_path_a"] == "lib.so"  # the fixture records path == name
    assert row["binary_path_b"] == "lib.so"


def test_a_key_lead_is_scoped_by_path_and_says_which_basis_it_matched(tmp_path: Path) -> None:
    """★ Two binaries share a short name and each holds a ``handle`` the other's key does not
    reach. Scoped by name, one binary's key lead annotated the other's candidate.

    The pre-column row is the second half: it carries no path, is still matched by name, and says
    so — a weaker scope reported as weaker, rather than presented as if it were a path match.

    MUTATION: drop the ``binary_path`` branch and scope by name again -> RED (each side sees both
    keys). Report ``scope_basis`` as "binary_path" unconditionally -> RED.
    """
    from treasure_map.lib.atlas.connection import open_atlas
    from treasure_map.lib.atlas.models import StringKeyedEdgeRow
    from treasure_map.lib.atlas.writer import add_string_keyed_edges
    from treasure_map.lib.query.string_edges import edges_reaching_callee

    atlas = open_atlas(tmp_path / "atlas.db")
    try:
        add_string_keyed_edges(
            atlas,
            [
                StringKeyedEdgeRow(
                    source_run_id="r",
                    binary=NAME,
                    binary_path=PATHS[side],
                    from_function="dispatch",
                    key=f"key_{side}",
                    mechanism="strcmp_gate",
                    callee_name="handle",
                )
                for side in ("A", "B")
            ]
            + [
                # a row from before the column existed: name only
                StringKeyedEdgeRow(
                    source_run_id="r",
                    binary=NAME,
                    binary_path=None,
                    from_function="dispatch",
                    key="key_legacy",
                    mechanism="strcmp_gate",
                    callee_name="handle",
                )
            ],
        )
        for side in ("A", "B"):
            edges = edges_reaching_callee(atlas, NAME, "handle", binary_path=PATHS[side])
            keys = {e["key"] for e in edges}
            assert keys == {f"key_{side}", "key_legacy"}, side
            basis = {e["key"]: e["scope_basis"] for e in edges}
            assert basis[f"key_{side}"] == "binary_path"
            assert basis["key_legacy"].startswith("short_name")
    finally:
        atlas.close()
