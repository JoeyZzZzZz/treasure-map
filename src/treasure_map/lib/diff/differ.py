# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Change classification and the public run_diff entry point.

run_diff opens both databases read-only, aligns functions (matcher), classifies each
alignment into a neutral change_kind, and for a genuinely changed function asks for a
neutral mechanism description (verdict). It returns in-memory results only — it never
writes to either input, and it knows nothing about any downstream store.
"""

from __future__ import annotations

import asyncio
import difflib
from dataclasses import replace
from pathlib import Path
from typing import get_args

from treasure_map.lib.diff.loader import FuncRow, load_functions
from treasure_map.lib.diff.matcher import Pair, _DiffRouter, match_functions
from treasure_map.lib.diff.models import Axis, ChangeLead, DiffResult, DiffStats, FuncRef
from treasure_map.lib.diff.verdict import describe_change

# Default ceiling on M-tier function_match_assist calls per run (degrade-and-flag above).
DEFAULT_MAX_ASSIST = 200


def _ref(row: FuncRow | None) -> FuncRef | None:
    if row is None:
        return None
    return FuncRef(binary_name=row.binary_name, func_name=row.name, func_id=row.func_id)


def _has_body(row: FuncRow) -> bool:
    return bool(row.pseudocode and row.pseudocode.strip())


def _unified_diff(a: str, b: str) -> str:
    return "\n".join(
        difflib.unified_diff(
            a.splitlines(), b.splitlines(), fromfile="a", tofile="b", lineterm="", n=3
        )
    )


def classify(pair: Pair, axis: Axis) -> tuple[ChangeLead, str | None]:
    """Classify one alignment into a ChangeLead plus the diff text (None if not diffable).

    A both-present pair with equal non-null hashes is unchanged; otherwise it is changed
    (with a unified diff when both bodies are present, else no verdict is possible). A
    one-sided pair is added/removed and never carries a verdict.
    """
    ref_a, ref_b = _ref(pair.a), _ref(pair.b)
    hash_a = pair.a.pseudocode_hash if pair.a else None
    hash_b = pair.b.pseudocode_hash if pair.b else None

    if pair.a is not None and pair.b is not None:
        if hash_a and hash_b and hash_a == hash_b:
            kind: str = "unchanged"
            diff_text = None
        elif _has_body(pair.a) and _has_body(pair.b):
            kind = "changed"
            assert pair.a.pseudocode is not None and pair.b.pseudocode is not None
            diff_text = _unified_diff(pair.a.pseudocode, pair.b.pseudocode)
        else:
            # Matched, but at least one body is missing: a change we cannot describe.
            kind = "changed"
            diff_text = None
    elif pair.a is not None:
        kind = "removed"
        diff_text = None
    else:
        kind = "added"
        diff_text = None

    lead = ChangeLead(
        change_kind=kind,  # type: ignore[arg-type]
        scope_origin=axis,
        func_ref_a=ref_a,
        func_ref_b=ref_b,
        pseudocode_hash_a=hash_a,
        pseudocode_hash_b=hash_b,
    )
    return lead, diff_text


async def _run_diff_async(
    db_a: Path | str,
    db_b: Path | str,
    axis: Axis,
    router: _DiffRouter,
    *,
    max_assist: int,
) -> DiffResult:
    funcs_a = load_functions(db_a)
    funcs_b = load_functions(db_b)
    pairs, m_assist_calls = await match_functions(funcs_a, funcs_b, router, max_assist=max_assist)

    leads: list[ChangeLead] = []
    matched = unchanged = added = removed = changed = verdict_calls = 0
    for pair in pairs:
        lead, diff_text = classify(pair, axis)
        if pair.a is not None and pair.b is not None:
            matched += 1
        kind = lead.change_kind
        if kind == "unchanged":
            unchanged += 1
            continue  # dropped: no lead, no LLM
        if kind == "added":
            added += 1
        elif kind == "removed":
            removed += 1
        else:  # changed
            changed += 1
            # The neutral L-tier description runs only when the LLM budget is on (max_assist > 0).
            # At max_assist 0 the run is pure-static and makes no LLM call of any kind, leaving
            # change_description None — a value the diff consumer already tolerates (it computes
            # its own deterministic unified diff). Alignment and classification are unaffected.
            if diff_text and max_assist > 0:
                description = await describe_change(diff_text, router)
                verdict_calls += 1
                lead = replace(lead, change_description=description)
        leads.append(lead)

    stats = DiffStats(
        matched=matched,
        unchanged=unchanged,
        added=added,
        removed=removed,
        changed=changed,
        m_assist_calls=m_assist_calls,
        verdict_calls=verdict_calls,
    )
    return DiffResult(leads=tuple(leads), stats=stats)


def run_diff(
    db_a: Path | str,
    db_b: Path | str,
    axis: Axis,
    router: _DiffRouter,
    *,
    max_assist: int = DEFAULT_MAX_ASSIST,
) -> DiffResult:
    """Locate and neutrally describe changes between two analysis databases.

    axis (version | mod | sibling) is recorded as each lead's scope_origin; the real
    pairing identity stays in the operator's external notes. Both DBs are read-only.
    """
    if axis not in get_args(Axis):
        raise ValueError(f"axis must be one of {get_args(Axis)} (got {axis!r})")
    return asyncio.run(_run_diff_async(db_a, db_b, axis, router, max_assist=max_assist))
