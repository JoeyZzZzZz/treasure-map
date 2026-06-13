# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Layered function matching: exact -> hash -> bounded M-tier assist on the residue.

Cost discipline: the LLM (function_match_assist, M tier) is consulted only on the
unmatched residue after the two cheap deterministic passes, and only up to max_assist
calls. On overflow the residue is left unmatched (it surfaces as added/removed) and the
call count is reported — degrade-and-flag, never a silent drop.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Protocol

from treasure_map.lib.diff.loader import FuncRow
from treasure_map.lib.llm.types import LLMResponse

logger = logging.getLogger(__name__)

# Bump on ANY change to _MATCH_PROMPT (invalidates the router cache for changed inputs).
MATCH_PROMPT_VERSION = "fnmatch-v1"

_MATCH_PROMPT = (
    "You are given two C functions, A and B, taken from two builds of related "
    "software. Decide whether they are the SAME function — the same role and the same "
    "core behavior — even if one was renamed or lightly edited. Answer with a single "
    "word: 'yes' or 'no'. No explanation."
)

# Stripped/auto-named functions (e.g. FUN_00401abc) carry no symbol identity, so they
# must not be matched by name — they fall through to the hash and assist passes.
_STRIPPED_NAME = re.compile(r"^(FUN|sub|loc)_[0-9a-fA-F]+$")

# Bound the per-function body fed to the assist prompt (token control).
_MAX_BODY_CHARS = 4000


class _DiffRouter(Protocol):
    """Minimal router surface used by the diff primitive (LLMRouter satisfies it)."""

    async def call(
        self,
        task: str,
        input_text: str,
        prompt: str,
        prompt_version: str,
    ) -> LLMResponse: ...


@dataclass(frozen=True)
class Pair:
    """A resolved alignment. One side is None for an unmatched (added/removed) row."""

    a: FuncRow | None
    b: FuncRow | None
    matched_via: str  # "exact" | "hash" | "assist" | "unmatched"


def _has_symbol(name: str | None) -> bool:
    return bool(name and name.strip() and not _STRIPPED_NAME.match(name.strip()))


def _assist_input(a: FuncRow, b: FuncRow) -> str:
    body_a = (a.pseudocode or "")[:_MAX_BODY_CHARS]
    body_b = (b.pseudocode or "")[:_MAX_BODY_CHARS]
    return f"Function A:\n{body_a}\n\nFunction B:\n{body_b}\n"


def _is_yes(response: LLMResponse | None) -> bool:
    if response is None:
        return False
    return response.content.strip().lower().startswith("yes")


async def match_functions(
    funcs_a: list[FuncRow],
    funcs_b: list[FuncRow],
    router: _DiffRouter,
    *,
    max_assist: int,
) -> tuple[list[Pair], int]:
    """Align functions across two entities. Returns (pairs, m_assist_calls).

    Pairs cover every input row exactly once: matched rows as (a, b); leftover rows as
    (a, None) or (None, b). m_assist_calls is the number of M-tier calls actually made
    (<= max_assist).
    """
    pairs: list[Pair] = []
    remaining_a = list(funcs_a)
    remaining_b = list(funcs_b)

    # Pass 1 — exact (binary_name, function_name) when both carry real symbols.
    by_key_b: dict[tuple[str, str], FuncRow] = {}
    for row in remaining_b:
        if _has_symbol(row.name):
            assert row.name is not None
            by_key_b.setdefault((row.binary_name, row.name), row)
    matched_b_ids: set[int] = set()
    leftover_a: list[FuncRow] = []
    for fa in remaining_a:
        match_b: FuncRow | None = None
        if _has_symbol(fa.name):
            assert fa.name is not None
            match_b = by_key_b.get((fa.binary_name, fa.name))
        if match_b is not None and match_b.func_id not in matched_b_ids:
            pairs.append(Pair(a=fa, b=match_b, matched_via="exact"))
            matched_b_ids.add(match_b.func_id)
        else:
            leftover_a.append(fa)
    remaining_a = leftover_a
    remaining_b = [fb for fb in remaining_b if fb.func_id not in matched_b_ids]

    # Pass 2 — identical pseudocode_hash => byte-identical function (no LLM).
    by_hash_b: dict[str, list[FuncRow]] = {}
    for fb in remaining_b:
        if fb.pseudocode_hash:
            by_hash_b.setdefault(fb.pseudocode_hash, []).append(fb)
    matched_b_ids = set()
    leftover_a = []
    for fa in remaining_a:
        bucket = by_hash_b.get(fa.pseudocode_hash) if fa.pseudocode_hash else None
        match = None
        if bucket:
            for cand in bucket:
                if cand.func_id not in matched_b_ids:
                    match = cand
                    break
        if match is not None:
            pairs.append(Pair(a=fa, b=match, matched_via="hash"))
            matched_b_ids.add(match.func_id)
        else:
            leftover_a.append(fa)
    remaining_a = leftover_a
    remaining_b = [fb for fb in remaining_b if fb.func_id not in matched_b_ids]

    # Pass 3 — bounded M-assist on the residue (renamed / stripped). Only functions
    # with pseudocode on both sides are eligible (no empty body to the LLM).
    m_assist_calls = 0
    matched_b_ids = set()
    leftover_a = []
    for fa in remaining_a:
        match = None
        if fa.pseudocode and fa.pseudocode.strip():
            for fb in remaining_b:
                if fb.func_id in matched_b_ids:
                    continue
                if not (fb.pseudocode and fb.pseudocode.strip()):
                    continue
                if m_assist_calls >= max_assist:
                    logger.warning(
                        "function_match_assist budget (%d) exhausted; leaving residue unmatched",
                        max_assist,
                    )
                    break
                m_assist_calls += 1
                resp = await router.call(
                    "function_match_assist",
                    _assist_input(fa, fb),
                    _MATCH_PROMPT,
                    MATCH_PROMPT_VERSION,
                )
                if _is_yes(resp):
                    match = fb
                    break
        if match is not None:
            pairs.append(Pair(a=fa, b=match, matched_via="assist"))
            matched_b_ids.add(match.func_id)
        else:
            leftover_a.append(fa)
    remaining_a = leftover_a
    remaining_b = [fb for fb in remaining_b if fb.func_id not in matched_b_ids]

    # Leftovers => removed (A-only) / added (B-only).
    pairs.extend(Pair(a=fa, b=None, matched_via="unmatched") for fa in remaining_a)
    pairs.extend(Pair(a=None, b=fb, matched_via="unmatched") for fb in remaining_b)
    return pairs, m_assist_calls
