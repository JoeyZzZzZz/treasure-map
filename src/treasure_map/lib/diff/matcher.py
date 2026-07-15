# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Layered function matching: exact -> hash on the residue.

Fully deterministic: an exact (binary_name, function_name) symbol match, then an identical
pseudocode_hash match. Whatever is left over is reported as added/removed — never guessed.
Symbol-complete builds align on the first pass; stripped/renamed residue that neither pass
resolves surfaces honestly as added/removed rather than being force-matched.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from treasure_map.lib.diff.loader import FuncRow

# Stripped/auto-named functions (e.g. FUN_00401abc) carry no symbol identity, so they
# must not be matched by name — they fall through to the hash pass.
_STRIPPED_NAME = re.compile(r"^(FUN|sub|loc)_[0-9a-fA-F]+$")


@dataclass(frozen=True)
class Pair:
    """A resolved alignment. One side is None for an unmatched (added/removed) row."""

    a: FuncRow | None
    b: FuncRow | None
    matched_via: str  # "exact" | "hash" | "unmatched"


def _has_symbol(name: str | None) -> bool:
    return bool(name and name.strip() and not _STRIPPED_NAME.match(name.strip()))


def match_functions(funcs_a: list[FuncRow], funcs_b: list[FuncRow]) -> list[Pair]:
    """Align functions across two entities.

    Pairs cover every input row exactly once: matched rows as (a, b); leftover rows as
    (a, None) or (None, b).
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

    # Pass 2 — identical pseudocode_hash => byte-identical function.
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

    # Leftovers => removed (A-only) / added (B-only).
    pairs.extend(Pair(a=fa, b=None, matched_via="unmatched") for fa in remaining_a)
    pairs.extend(Pair(a=None, b=fb, matched_via="unmatched") for fb in remaining_b)
    return pairs
