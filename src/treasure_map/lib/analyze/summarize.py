# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Function summary filler: populate functions.summary via the LLM router (S tier).

Idempotent and resumable: only rows with pseudocode present and summary still NULL
are processed, so a re-run skips already-summarized rows and a crashed run resumes
cleanly. A function with no pseudocode is skipped (no summary possible), never an
error. A failed item leaves its summary NULL (picked up on the next run) — no
half-written row.

The router keys its cache on (task, input_text, prompt_version); bump PROMPT_VERSION
on any change to the prompt text so changed inputs re-run instead of serving a stale
cached summary.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from treasure_map.lib.llm.types import BatchItem, LLMResponse

logger = logging.getLogger(__name__)

# Bump on ANY change to _SUMMARY_PROMPT (invalidates cache for changed inputs).
PROMPT_VERSION = "fnsum-v1"

# Neutral mechanism-only instruction: describe what the function does, not whether
# it is exploitable. No vendor names, no security judgment, no speculation.
_SUMMARY_PROMPT = (
    "In one sentence, describe what this C function does — its mechanism: the inputs "
    "it reads, the key operations it performs, and the outputs or side effects it "
    "produces. State only what the code does. No speculation, no security judgment, "
    "no remediation advice."
)

# Bound per-item cost: very long decompiled bodies are truncated before sending.
_MAX_PSEUDOCODE_CHARS = 6000


class _BatchRouter(Protocol):
    """Minimal router surface used here (the full LLMRouter satisfies it)."""

    async def call_batch(
        self,
        task: str,
        items: list[BatchItem],
        prompt_builder: Callable[[list[BatchItem]], str],
        prompt_version: str,
        progress_callback: Callable[[int, int], None] | None = ...,
    ) -> list[LLMResponse | None]: ...


@dataclass(frozen=True)
class SummaryStats:
    selected: int  # functions with pseudocode sent to the router
    summarized: int  # rows actually written
    skipped_no_pseudocode: int  # un-summarized rows with no pseudocode (skipped)
    failed: int  # selected items the router could not summarize (summary left NULL)


def build_summary_prompt(items: list[BatchItem]) -> str:
    """Return the system instruction for a summary call.

    The pseudocode travels as the router's input_text (the user message), so the
    prompt is the static, neutral instruction; items are accepted for interface
    symmetry with the router's prompt_builder contract.
    """
    return _SUMMARY_PROMPT


async def summarize_functions(
    conn: sqlite3.Connection,
    router: _BatchRouter,
    *,
    limit: int | None = None,
) -> SummaryStats:
    """Fill functions.summary for un-summarized functions that have pseudocode.

    Selects only rows where summary IS NULL, partitions out those lacking pseudocode
    (counted as skipped), summarizes the rest via the router, and writes results back
    in a single executemany + commit. Never raises on a per-item failure.
    """
    sql = "SELECT id, pseudocode FROM functions WHERE summary IS NULL ORDER BY id"
    params: tuple[int, ...] = ()
    if limit is not None:
        sql += " LIMIT ?"
        params = (limit,)
    rows = conn.execute(sql, params).fetchall()

    items: list[BatchItem] = []
    skipped_no_pseudocode = 0
    for func_id, pseudocode in rows:
        if pseudocode is None or not str(pseudocode).strip():
            skipped_no_pseudocode += 1
            continue
        items.append(
            BatchItem(
                id=str(func_id),
                input_text=str(pseudocode)[:_MAX_PSEUDOCODE_CHARS],
                metadata={"func_id": func_id},
            )
        )

    if not items:
        return SummaryStats(
            selected=0,
            summarized=0,
            skipped_no_pseudocode=skipped_no_pseudocode,
            failed=0,
        )

    results = await router.call_batch(
        "function_summary", items, build_summary_prompt, PROMPT_VERSION
    )

    updates: list[tuple[str, int]] = []
    failed = 0
    for item, result in zip(items, results, strict=True):
        if result is None or not result.content.strip():
            failed += 1
            continue
        updates.append((result.content.strip(), int(item.metadata["func_id"])))

    if updates:
        conn.executemany("UPDATE functions SET summary = ? WHERE id = ?", updates)
        conn.commit()

    return SummaryStats(
        selected=len(items),
        summarized=len(updates),
        skipped_no_pseudocode=skipped_no_pseudocode,
        failed=failed,
    )
