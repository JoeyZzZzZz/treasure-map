# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for lib/analyze/summarize — function summary filler (R1).

Uses a fake router (no network). Asserts selection, write-back, idempotency,
degrade-on-missing-pseudocode, limit, prompt-version pass-through, and per-item
failure handling.
"""

from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Callable
from pathlib import Path

from treasure_map.lib.analyze.summarize import (
    PROMPT_VERSION,
    SummaryStats,
    build_summary_prompt,
    summarize_functions,
)
from treasure_map.lib.llm.types import BatchItem, LLMResponse, Tier
from treasure_map.lib.storage.connection import open_db

# ── fake router ────────────────────────────────────────────────────────────────


class FakeRouter:
    """Records the prompt_version it was called with; returns canned responses.

    responder maps a BatchItem.input_text → str content, or None to simulate a
    per-item failure (router returns None for that item).
    """

    def __init__(self, responder: Callable[[str], str | None]) -> None:
        self._responder = responder
        self.seen_prompt_version: str | None = None
        self.seen_task: str | None = None
        self.call_count = 0
        self.progress_events: list[tuple[int, int]] = []

    async def call_batch(
        self,
        task: str,
        items: list[BatchItem],
        prompt_builder: Callable[[list[BatchItem]], str],
        prompt_version: str,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> list[LLMResponse | None]:
        self.call_count += 1
        self.seen_task = task
        self.seen_prompt_version = prompt_version
        # Exercise the prompt builder the way the real router does (single-item).
        _ = prompt_builder(items[:1])
        results: list[LLMResponse | None] = []
        done = 0
        for item in items:
            content = self._responder(item.input_text)
            if content is None:
                results.append(None)
            else:
                results.append(
                    LLMResponse(
                        content=content,
                        model_id="fake-model",
                        cost_usd=0.0,
                        cached=False,
                        tier=Tier.S,
                    )
                )
                done += 1
            # Mirror the real router: report (done-so-far, total) per completed item.
            if progress_callback is not None:
                progress_callback(done, len(items))
                self.progress_events.append((done, len(items)))
        return results


# ── fixtures ─────────────────────────────────────────────────────────────────


def _db(tmp_path: Path) -> sqlite3.Connection:
    conn = open_db(tmp_path / "analysis.db")
    conn.execute(
        "INSERT INTO binaries (id, name, sha256) VALUES (1, 'app', ?)",
        ("a" * 64,),
    )
    return conn


def _add_function(
    conn: sqlite3.Connection,
    func_id: int,
    *,
    pseudocode: str | None,
    summary: str | None = None,
) -> None:
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, pseudocode, summary) VALUES (?, 1, ?, ?, ?)",
        (func_id, f"func_{func_id}", pseudocode, summary),
    )
    conn.commit()


def _echo_responder(text: str) -> str:
    return f"summary of: {text[:20]}"


# ── build_summary_prompt ───────────────────────────────────────────────────────


def test_build_summary_prompt_is_neutral_and_static() -> None:
    item = BatchItem(id="1", input_text="int main(){}")
    prompt = build_summary_prompt([item])
    assert isinstance(prompt, str)
    assert "one sentence" in prompt.lower()
    # Static instruction: does not embed the function body.
    assert "int main" not in prompt


# ── selection + write-back ─────────────────────────────────────────────────────


def test_summarize_writes_back_and_returns_stats(tmp_path: Path) -> None:
    conn = _db(tmp_path)
    _add_function(conn, 10, pseudocode="void parse(char *s){...}")
    _add_function(conn, 11, pseudocode="int add(int a,int b){return a+b;}")
    router = FakeRouter(_echo_responder)

    stats = asyncio.run(summarize_functions(conn, router))

    assert stats == SummaryStats(selected=2, summarized=2, skipped_no_pseudocode=0, failed=0)
    rows = dict(conn.execute("SELECT id, summary FROM functions ORDER BY id").fetchall())
    assert rows[10] == "summary of: void parse(char *s){"
    assert rows[11] == "summary of: int add(int a,int b)"
    conn.close()


def test_summarize_selects_only_null_summary(tmp_path: Path) -> None:
    conn = _db(tmp_path)
    _add_function(conn, 10, pseudocode="void a(){}", summary="already done")
    _add_function(conn, 11, pseudocode="void b(){}")
    router = FakeRouter(_echo_responder)

    stats = asyncio.run(summarize_functions(conn, router))

    assert stats.selected == 1
    assert stats.summarized == 1
    # Pre-existing summary untouched.
    assert conn.execute("SELECT summary FROM functions WHERE id=10").fetchone()[0] == "already done"
    conn.close()


# ── idempotency ─────────────────────────────────────────────────────────────────


def test_summarize_is_idempotent(tmp_path: Path) -> None:
    conn = _db(tmp_path)
    _add_function(conn, 10, pseudocode="void a(){}")
    router = FakeRouter(_echo_responder)

    first = asyncio.run(summarize_functions(conn, router))
    second = asyncio.run(summarize_functions(conn, router))

    assert first.summarized == 1
    assert second == SummaryStats(selected=0, summarized=0, skipped_no_pseudocode=0, failed=0)
    conn.close()


# ── degrade: no pseudocode ──────────────────────────────────────────────────────


def test_summarize_skips_null_pseudocode(tmp_path: Path) -> None:
    conn = _db(tmp_path)
    _add_function(conn, 10, pseudocode=None)
    _add_function(conn, 11, pseudocode="   ")  # whitespace-only also skipped
    _add_function(conn, 12, pseudocode="void real(){}")
    router = FakeRouter(_echo_responder)

    stats = asyncio.run(summarize_functions(conn, router))

    assert stats.skipped_no_pseudocode == 2
    assert stats.selected == 1
    assert stats.summarized == 1
    # NULL-pseudocode rows remain NULL summary, no error.
    assert conn.execute("SELECT summary FROM functions WHERE id=10").fetchone()[0] is None
    conn.close()


def test_summarize_empty_db_returns_zeros(tmp_path: Path) -> None:
    conn = _db(tmp_path)
    router = FakeRouter(_echo_responder)
    stats = asyncio.run(summarize_functions(conn, router))
    assert stats == SummaryStats(selected=0, summarized=0, skipped_no_pseudocode=0, failed=0)
    assert router.call_count == 0  # nothing to summarize → router not called
    conn.close()


# ── limit ───────────────────────────────────────────────────────────────────────


def test_summarize_respects_limit(tmp_path: Path) -> None:
    conn = _db(tmp_path)
    for fid in range(10, 15):
        _add_function(conn, fid, pseudocode=f"void f{fid}(){{}}")
    router = FakeRouter(_echo_responder)

    stats = asyncio.run(summarize_functions(conn, router, limit=2))

    assert stats.selected == 2
    assert stats.summarized == 2
    remaining = conn.execute("SELECT COUNT(*) FROM functions WHERE summary IS NULL").fetchone()[0]
    assert remaining == 3
    conn.close()


# ── prompt version pass-through ──────────────────────────────────────────────────


def test_summarize_passes_prompt_version(tmp_path: Path) -> None:
    conn = _db(tmp_path)
    _add_function(conn, 10, pseudocode="void a(){}")
    router = FakeRouter(_echo_responder)

    asyncio.run(summarize_functions(conn, router))

    assert router.seen_prompt_version == PROMPT_VERSION
    assert router.seen_task == "function_summary"
    conn.close()


# ── progress callback forwarding ──────────────────────────────────────────────────


def test_summarize_forwards_progress_callback(tmp_path: Path) -> None:
    conn = _db(tmp_path)
    for fid in range(10, 13):
        _add_function(conn, fid, pseudocode=f"void f{fid}(){{}}")
    router = FakeRouter(_echo_responder)

    seen: list[tuple[int, int]] = []
    asyncio.run(summarize_functions(conn, router, progress=lambda d, t: seen.append((d, t))))

    # Invoked once per item, total constant, done monotonically increasing up to total.
    assert len(seen) == 3
    assert all(t == 3 for _, t in seen)
    assert [d for d, _ in seen] == [1, 2, 3]
    conn.close()


# ── per-item failure ──────────────────────────────────────────────────────────────


def test_summarize_failed_item_left_null(tmp_path: Path) -> None:
    conn = _db(tmp_path)
    _add_function(conn, 10, pseudocode="void good(){}")
    _add_function(conn, 11, pseudocode="void bad(){}")

    def responder(text: str) -> str | None:
        return None if "bad" in text else "ok summary"

    router = FakeRouter(responder)
    stats = asyncio.run(summarize_functions(conn, router))

    assert stats.selected == 2
    assert stats.summarized == 1
    assert stats.failed == 1
    rows = dict(conn.execute("SELECT id, summary FROM functions ORDER BY id").fetchall())
    assert rows[10] == "ok summary"
    assert rows[11] is None  # failed item left NULL, no half-write
    conn.close()


def test_summarize_failed_item_is_resumable(tmp_path: Path) -> None:
    """A failed item is re-selected on the next run (summary still NULL)."""
    conn = _db(tmp_path)
    _add_function(conn, 11, pseudocode="void bad(){}")

    flaky = {"fail": True}

    def responder(text: str) -> str | None:
        return None if flaky["fail"] else "recovered summary"

    router = FakeRouter(responder)
    first = asyncio.run(summarize_functions(conn, router))
    assert first.failed == 1

    flaky["fail"] = False
    second = asyncio.run(summarize_functions(conn, router))
    assert second.summarized == 1
    assert conn.execute("SELECT summary FROM functions WHERE id=11").fetchone()[0] == (
        "recovered summary"
    )
    conn.close()
