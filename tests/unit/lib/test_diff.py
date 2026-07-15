# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the cross-entity diff primitive (R-diff).

Synthetic, vendor-neutral fixtures, fully deterministic (no network, no LLM). Proves the
primitive's logic: exact/hash matching, added/removed/changed partitioning, the three-state
body handling (a missing body is never mistaken for a change), the stripped/renamed residue
degrading honestly to added/removed, read-only safety, and a boundary check that lib/diff/
carries no judgment vocabulary.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

import pytest

from treasure_map.lib.diff import run_diff
from treasure_map.lib.storage.connection import open_db

_DIFF_PKG = Path(__file__).resolve().parents[3] / "src" / "treasure_map" / "lib" / "diff"


# ── fixtures ──────────────────────────────────────────────────────────────────────


def _make_db(tmp_path: Path, name: str, funcs: list[dict[str, object]]) -> Path:
    """Build a tiny analysis.db with one neutral binary and the given functions."""
    db_path = tmp_path / name
    conn = open_db(db_path)
    # sha256 is per-file unique; a constant 64-char string is fine in a fresh DB.
    conn.execute(
        "INSERT INTO binaries (id, name, sha256) VALUES (1, 'appsvcd', ?)",
        ("a" * 64,),
    )
    for i, f in enumerate(funcs, start=1):
        conn.execute(
            "INSERT INTO functions (id, binary_id, name, pseudocode, pseudocode_hash) "
            "VALUES (?, 1, ?, ?, ?)",
            (i, f.get("name"), f.get("pseudocode"), f.get("hash")),
        )
    conn.commit()
    conn.close()
    return db_path


# ── exact + hash match => unchanged ─────────────────────────────────────────────────


def test_unchanged_matches(tmp_path: Path) -> None:
    funcs = [
        {"name": "parse_request", "pseudocode": "void parse_request(){a();}", "hash": "h1"},
        {"name": "FUN_00401000", "pseudocode": "int helper(){return 1;}", "hash": "h2"},
    ]
    db_a = _make_db(tmp_path, "a.db", funcs)
    db_b = _make_db(tmp_path, "b.db", funcs)

    res = run_diff(db_a, db_b, "version")

    assert res.stats.unchanged == 2  # one via exact symbol, one via hash
    assert res.stats.changed == 0
    assert res.stats.added == 0 and res.stats.removed == 0
    assert res.leads == ()  # unchanged are dropped, no leads


# ── added / removed ─────────────────────────────────────────────────────────────────


def test_added_and_removed(tmp_path: Path) -> None:
    db_a = _make_db(
        tmp_path, "a.db", [{"name": "only_in_a", "pseudocode": "void a(){}", "hash": "ha"}]
    )
    db_b = _make_db(
        tmp_path, "b.db", [{"name": "only_in_b", "pseudocode": "void b(){}", "hash": "hb"}]
    )

    res = run_diff(db_a, db_b, "sibling")

    assert res.stats.added == 1
    assert res.stats.removed == 1
    assert res.stats.changed == 0
    kinds = sorted(lead.change_kind for lead in res.leads)
    assert kinds == ["added", "removed"]
    # No verdict on one-sided leads.
    assert all(lead.change_description is None for lead in res.leads)


# ── changed (exact match, body differs) => deterministic diff, no description ────────


def test_changed_exact_match(tmp_path: Path) -> None:
    # Both bodies present and differ -> changed. The diff itself is the deterministic record;
    # the primitive does not ask an LLM to describe it, so the lead carries no change_description.
    db_a = _make_db(
        tmp_path,
        "a.db",
        [
            {
                "name": "copy_field",
                "pseudocode": "void copy_field(char*d,char*s){strcpy(d,s);}",
                "hash": "old",
            }
        ],
    )
    db_b = _make_db(
        tmp_path,
        "b.db",
        [
            {
                "name": "copy_field",
                "pseudocode": "void copy_field(char*d,char*s){if(strlen(s)<64)strcpy(d,s);}",
                "hash": "new",
            }
        ],
    )

    res = run_diff(db_a, db_b, "version")

    assert res.stats.changed == 1
    assert res.stats.matched == 1
    (lead,) = res.leads
    assert lead.change_kind == "changed"
    assert lead.scope_origin == "version"
    assert lead.change_description is None  # no LLM description step
    assert lead.pseudocode_hash_a == "old" and lead.pseudocode_hash_b == "new"


# ── three-state body handling: a missing body is never mistaken for a change ────────


def test_both_bodies_missing_is_skipped_not_changed(tmp_path: Path) -> None:
    # Same symbol on both sides, but BOTH decompilations are empty (e.g. both timed out).
    # No information => not a change. Must NOT inflate `changed`; counted as skipped_no_body
    # and dropped from leads (like unchanged).
    empty = {"name": "big_oss_fn", "pseudocode": "", "hash": None}
    db_a = _make_db(tmp_path, "a.db", [empty])
    db_b = _make_db(tmp_path, "b.db", [empty])

    res = run_diff(db_a, db_b, "version")

    assert res.stats.matched == 1  # symbol-aligned
    assert res.stats.changed == 0  # the bug this fixes: NOT counted as changed
    assert res.stats.changed_unverifiable == 0
    assert res.stats.skipped_no_body == 1
    assert res.leads == ()  # no information => no lead


def test_one_side_missing_body_is_changed_unverifiable(tmp_path: Path) -> None:
    # One version decompiled, the other timed out (empty). We cannot tell whether it changed,
    # so it is flagged changed_unverifiable — never silently unchanged, never mixed into the
    # main `changed` (no diff is possible).
    db_a = _make_db(
        tmp_path, "a.db", [{"name": "svc_init", "pseudocode": "void svc_init(){a();}", "hash": "h"}]
    )
    db_b = _make_db(tmp_path, "b.db", [{"name": "svc_init", "pseudocode": "", "hash": None}])

    res = run_diff(db_a, db_b, "version")

    assert res.stats.changed == 0  # not the describable main signal
    assert res.stats.changed_unverifiable == 1
    assert res.stats.skipped_no_body == 0
    (lead,) = res.leads
    assert lead.change_kind == "changed_unverifiable"


def test_one_side_truly_changed_other_empty_is_not_unchanged(tmp_path: Path) -> None:
    # Anti-false-negative: the present side is a substantively patched body, the other side is
    # empty (timed out). A one-side-empty pair must NOT be judged unchanged just because the
    # empty side gives nothing to compare — it stays changed_unverifiable so a real change is
    # never hidden.
    patched = "void rc(char*p){ if(validate(p)) run(p); }"  # clearly not a no-op
    db_a = _make_db(tmp_path, "a.db", [{"name": "rc", "pseudocode": patched, "hash": "h"}])
    db_b = _make_db(tmp_path, "b.db", [{"name": "rc", "pseudocode": "", "hash": None}])

    res = run_diff(db_a, db_b, "version")

    (lead,) = res.leads
    assert lead.change_kind == "changed_unverifiable"  # NOT unchanged — the guarded false neg


# ── stripped/renamed residue: neither exact nor hash matches => added/removed ────────


def test_stripped_residue_degrades_to_added_removed(tmp_path: Path) -> None:
    # Stripped names differ (excluded from name matching) and bodies/hashes differ, so neither
    # deterministic pass aligns them. With no LLM assist the residue is NOT force-matched — it
    # surfaces honestly as added + removed rather than a guessed pairing.
    db_a = _make_db(
        tmp_path,
        "a.db",
        [{"name": "FUN_00401100", "pseudocode": "int f(int x){return x+1;}", "hash": "ra"}],
    )
    db_b = _make_db(
        tmp_path,
        "b.db",
        [{"name": "FUN_00408200", "pseudocode": "int f(int x){return x+2;}", "hash": "rb"}],
    )

    res = run_diff(db_a, db_b, "mod")

    assert res.stats.matched == 0
    assert res.stats.added == 1 and res.stats.removed == 1  # residue surfaces, never dropped
    kinds = sorted(lead.change_kind for lead in res.leads)
    assert kinds == ["added", "removed"]


# ── read-only safety ────────────────────────────────────────────────────────────────


def test_run_diff_does_not_modify_inputs(tmp_path: Path) -> None:
    db_a = _make_db(
        tmp_path, "a.db", [{"name": "copy_field", "pseudocode": "void c(){x();}", "hash": "old"}]
    )
    db_b = _make_db(
        tmp_path, "b.db", [{"name": "copy_field", "pseudocode": "void c(){y();}", "hash": "new"}]
    )
    before_a, before_b = db_a.read_bytes(), db_b.read_bytes()

    run_diff(db_a, db_b, "version")

    assert db_a.read_bytes() == before_a  # read-only open never mutates the input
    assert db_b.read_bytes() == before_b


def test_load_functions_rejects_missing_db(tmp_path: Path) -> None:
    # Read-only mode does not create the file; a missing input surfaces, not masked.
    with pytest.raises(sqlite3.OperationalError):
        run_diff(tmp_path / "nope.db", tmp_path / "also_nope.db", "version")


# ── axis validation ─────────────────────────────────────────────────────────────────


def test_run_diff_rejects_unknown_axis(tmp_path: Path) -> None:
    db = _make_db(tmp_path, "a.db", [{"name": "f", "pseudocode": "void f(){}", "hash": "h"}])
    with pytest.raises(ValueError, match="axis must be one of"):
        run_diff(db, db, "bogus")  # type: ignore[arg-type]


# ── BOUNDARY: no judgment vocabulary, no section cites ──────────────────────────────


def test_diff_package_is_boundary_clean() -> None:
    judgment = re.compile(
        r"fix_quality|incomplete_patch|vulnerab|severity|exploit|\bsecurity\b",
        re.IGNORECASE,
    )
    section_ref = re.compile(r"§|PRD\s")
    for path in _DIFF_PKG.glob("*.py"):
        text = path.read_text()
        assert not judgment.search(text), f"judgment vocab in {path.name}"
        assert not section_ref.search(text), f"section/private-doc ref in {path.name}"
