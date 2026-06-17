# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the cross-entity diff primitive (R-diff).

Synthetic, vendor-neutral fixtures + a mock router (no network). Proves the primitive's
logic: exact/hash matching, added/removed/changed partitioning, one neutral verdict per
changed function, bounded M-assist with a degrade-and-flag overflow path, read-only
safety, and a boundary check that lib/diff/ carries no judgment vocabulary.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Callable
from pathlib import Path

import pytest

from treasure_map.lib.diff import run_diff
from treasure_map.lib.diff.differ import _run_diff_async
from treasure_map.lib.llm.types import LLMResponse, Tier
from treasure_map.lib.storage.connection import open_db

_DIFF_PKG = Path(__file__).resolve().parents[3] / "src" / "treasure_map" / "lib" / "diff"


# ── mock router ───────────────────────────────────────────────────────────────────


class FakeDiffRouter:
    """Async call() stub: canned match decisions + canned verdict text, all recorded."""

    def __init__(
        self,
        *,
        match_decider: Callable[[str], bool] = lambda _t: True,
        verdict_text: str = "adds a bounds check before the copy call",
    ) -> None:
        self._match_decider = match_decider
        self._verdict_text = verdict_text
        self.calls: list[tuple[str, str]] = []  # (task, input_text)

    async def call(
        self,
        task: str,
        input_text: str,
        prompt: str,
        prompt_version: str,
        max_tokens: int = 1500,
    ) -> LLMResponse:
        self.calls.append((task, input_text))
        if task == "function_match_assist":
            content = "yes" if self._match_decider(input_text) else "no"
            tier = Tier.M
        else:  # patch_verdict
            content = self._verdict_text
            tier = Tier.L
        return LLMResponse(content=content, model_id="fake", cost_usd=0.0, cached=False, tier=tier)

    def tasks(self) -> list[str]:
        return [t for t, _ in self.calls]


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


# ── exact + hash match => unchanged, no LLM ─────────────────────────────────────────


def test_unchanged_matches_use_no_llm(tmp_path: Path) -> None:
    funcs = [
        {"name": "parse_request", "pseudocode": "void parse_request(){a();}", "hash": "h1"},
        {"name": "FUN_00401000", "pseudocode": "int helper(){return 1;}", "hash": "h2"},
    ]
    db_a = _make_db(tmp_path, "a.db", funcs)
    db_b = _make_db(tmp_path, "b.db", funcs)
    router = FakeDiffRouter()

    res = run_diff(db_a, db_b, "version", router)

    assert res.stats.unchanged == 2  # one via exact symbol, one via hash
    assert res.stats.changed == 0
    assert res.stats.added == 0 and res.stats.removed == 0
    assert res.leads == ()  # unchanged are dropped, no leads
    assert router.calls == []  # no LLM consulted on the cheap paths


# ── added / removed ─────────────────────────────────────────────────────────────────


def test_added_and_removed(tmp_path: Path) -> None:
    db_a = _make_db(
        tmp_path, "a.db", [{"name": "only_in_a", "pseudocode": "void a(){}", "hash": "ha"}]
    )
    db_b = _make_db(
        tmp_path, "b.db", [{"name": "only_in_b", "pseudocode": "void b(){}", "hash": "hb"}]
    )
    router = FakeDiffRouter(match_decider=lambda _t: False)  # not the same function

    res = run_diff(db_a, db_b, "sibling", router)

    assert res.stats.added == 1
    assert res.stats.removed == 1
    assert res.stats.changed == 0
    kinds = sorted(lead.change_kind for lead in res.leads)
    assert kinds == ["added", "removed"]
    # No verdict on one-sided leads.
    assert all(lead.change_description is None for lead in res.leads)
    assert "patch_verdict" not in router.tasks()


# ── changed (exact match, body differs) => no LLM description ───────────────────────


def test_changed_makes_no_llm_call(tmp_path: Path) -> None:
    # Both bodies present and differ -> changed. The diff itself is the deterministic record;
    # the primitive no longer asks an LLM to describe it, so an exact-matched changed pair
    # makes NO LLM call at all and carries no change_description.
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
    router = FakeDiffRouter()

    res = run_diff(db_a, db_b, "version", router)

    assert res.stats.changed == 1
    assert res.stats.matched == 1
    (lead,) = res.leads
    assert lead.change_kind == "changed"
    assert lead.scope_origin == "version"
    assert lead.change_description is None  # no LLM description step
    assert lead.pseudocode_hash_a == "old" and lead.pseudocode_hash_b == "new"
    assert router.calls == []  # exact-matched + no description => zero LLM calls
    assert "patch_verdict" not in router.tasks()


# ── three-state body handling: a missing body is never mistaken for a change ────────


def test_both_bodies_missing_is_skipped_not_changed(tmp_path: Path) -> None:
    # Same symbol on both sides, but BOTH decompilations are empty (e.g. both timed out).
    # No information => not a change. Must NOT inflate `changed`; counted as skipped_no_body
    # and dropped from leads (like unchanged).
    empty = {"name": "big_oss_fn", "pseudocode": "", "hash": None}
    db_a = _make_db(tmp_path, "a.db", [empty])
    db_b = _make_db(tmp_path, "b.db", [empty])

    res = run_diff(db_a, db_b, "version", FakeDiffRouter())

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

    res = run_diff(db_a, db_b, "version", FakeDiffRouter())

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
    patched = "void rc(char*p){ if(validate(p)) system(p); }"  # clearly not a no-op
    db_a = _make_db(tmp_path, "a.db", [{"name": "rc", "pseudocode": patched, "hash": "h"}])
    db_b = _make_db(tmp_path, "b.db", [{"name": "rc", "pseudocode": "", "hash": None}])

    res = run_diff(db_a, db_b, "version", FakeDiffRouter())

    (lead,) = res.leads
    assert lead.change_kind == "changed_unverifiable"  # NOT unchanged — the guarded false neg


# ── max_assist 0 => pure static, no LLM call even for a changed pair ─────────────────


def test_max_assist_zero_makes_no_llm_call_even_for_changed(tmp_path: Path) -> None:
    # Pure static: a symbol-named function that changed body still aligns via exact match and is
    # classified "changed", but with max_assist 0 the L-tier description is skipped — no LLM call
    # of any kind, so a no-key run is possible. The lead is still emitted (just no description).
    db_a = _make_db(
        tmp_path,
        "a.db",
        [{"name": "notify_rc", "pseudocode": "void notify_rc(){a();}", "hash": "old"}],
    )
    db_b = _make_db(
        tmp_path,
        "b.db",
        [{"name": "notify_rc", "pseudocode": "void notify_rc(){a();b();}", "hash": "new"}],
    )
    router = FakeDiffRouter()

    res = run_diff(db_a, db_b, "version", router, max_assist=0)

    assert res.stats.changed == 1  # exact alignment + body differs
    assert router.calls == []  # NO LLM call of any kind (matching or description)
    (lead,) = res.leads
    assert lead.change_kind == "changed"
    assert lead.change_description is None  # consumer tolerates this (computes its own diff)


# ── residue: bounded M-assist + overflow degrade-and-flag ───────────────────────────


def _renamed_residue(tmp_path: Path) -> tuple[Path, Path]:
    # Stripped names differ and bodies differ slightly => neither exact nor hash matches;
    # only the assist pass can align them.
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
    return db_a, db_b


def test_residue_assist_matches(tmp_path: Path) -> None:
    db_a, db_b = _renamed_residue(tmp_path)
    router = FakeDiffRouter(match_decider=lambda _t: True)

    res = run_diff(db_a, db_b, "mod", router, max_assist=5)

    assert res.stats.m_assist_calls == 1  # one residue comparison, answered yes
    assert res.stats.matched == 1
    assert res.stats.changed == 1
    assert "function_match_assist" in router.tasks()
    assert "patch_verdict" not in router.tasks()  # no L-tier description step


def test_residue_assist_overflow_leaves_unmatched(tmp_path: Path) -> None:
    db_a, db_b = _renamed_residue(tmp_path)
    router = FakeDiffRouter(match_decider=lambda _t: True)

    res = run_diff(db_a, db_b, "mod", router, max_assist=0)  # budget exhausted immediately

    assert res.stats.m_assist_calls == 0
    assert res.stats.matched == 0
    assert res.stats.added == 1 and res.stats.removed == 1  # residue surfaces, never dropped
    assert "function_match_assist" not in router.tasks()


# ── read-only safety ────────────────────────────────────────────────────────────────


def test_run_diff_does_not_modify_inputs(tmp_path: Path) -> None:
    db_a = _make_db(
        tmp_path, "a.db", [{"name": "copy_field", "pseudocode": "void c(){x();}", "hash": "old"}]
    )
    db_b = _make_db(
        tmp_path, "b.db", [{"name": "copy_field", "pseudocode": "void c(){y();}", "hash": "new"}]
    )
    before_a, before_b = db_a.read_bytes(), db_b.read_bytes()

    run_diff(db_a, db_b, "version", FakeDiffRouter())

    assert db_a.read_bytes() == before_a  # read-only open never mutates the input
    assert db_b.read_bytes() == before_b


def test_load_functions_rejects_missing_db(tmp_path: Path) -> None:
    # Read-only mode does not create the file; a missing input surfaces, not masked.
    with pytest.raises(sqlite3.OperationalError):
        run_diff(tmp_path / "nope.db", tmp_path / "also_nope.db", "version", FakeDiffRouter())


# ── axis validation ─────────────────────────────────────────────────────────────────


def test_run_diff_rejects_unknown_axis(tmp_path: Path) -> None:
    db = _make_db(tmp_path, "a.db", [{"name": "f", "pseudocode": "void f(){}", "hash": "h"}])
    with pytest.raises(ValueError, match="axis must be one of"):
        run_diff(db, db, "bogus", FakeDiffRouter())  # type: ignore[arg-type]


# ── BOUNDARY: no judgment vocabulary, no section cites, mechanism-only prompt ───────


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


# ── async entry is awaitable for future async consumers ─────────────────────────────


def test_async_entry_matches_sync(tmp_path: Path) -> None:
    import asyncio

    db = _make_db(tmp_path, "a.db", [{"name": "f", "pseudocode": "void f(){}", "hash": "h"}])
    res = asyncio.run(_run_diff_async(db, db, "version", FakeDiffRouter(), max_assist=10))
    assert res.stats.unchanged == 1
