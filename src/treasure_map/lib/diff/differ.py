# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Change classification and the public run_diff entry point.

run_diff opens both databases read-only, aligns functions (matcher), and classifies each
alignment into a neutral change_kind. It returns in-memory results only — it never writes
to either input, and it knows nothing about any downstream store. The change itself is the
deterministic unified diff; the primitive does not ask an LLM to describe it.
"""

from __future__ import annotations

import difflib
from pathlib import Path
from typing import get_args

from treasure_map.lib.diff.loader import FuncRow, load_functions
from treasure_map.lib.diff.matcher import Pair, match_functions
from treasure_map.lib.diff.models import Axis, ChangeLead, DiffResult, DiffStats, FuncRef


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

    A both-present pair is decided in THREE states by whether each side has a body, so a
    missing body (a decompilation timeout) is never mistaken for a change:
      - both bodies present  -> compare hashes: equal = unchanged, else = changed + diff
      - neither body present  -> skipped_no_body (no information, not a change)
      - exactly one body      -> changed_unverifiable (cannot tell; flag, never guess)
    A one-sided pair is added/removed.
    """
    ref_a, ref_b = _ref(pair.a), _ref(pair.b)
    hash_a = pair.a.pseudocode_hash if pair.a else None
    hash_b = pair.b.pseudocode_hash if pair.b else None

    if pair.a is not None and pair.b is not None:
        a_body, b_body = _has_body(pair.a), _has_body(pair.b)
        if a_body and b_body:
            if hash_a and hash_b and hash_a == hash_b:
                kind: str = "unchanged"
                diff_text = None
            else:
                kind = "changed"
                assert pair.a.pseudocode is not None and pair.b.pseudocode is not None
                diff_text = _unified_diff(pair.a.pseudocode, pair.b.pseudocode)
        elif not a_body and not b_body:
            # Both decompilations are empty (e.g. both timed out): no information, not a
            # change. Treated like unchanged — counted, never a lead.
            kind = "skipped_no_body"
            diff_text = None
        else:
            # Exactly one side has a body: one version decompiled, the other did not. We
            # cannot tell whether the function changed, so we flag it (degrade-and-flag) —
            # never silently 'unchanged' (that would hide a real change) and never mixed into
            # the main 'changed' (we cannot describe it).
            kind = "changed_unverifiable"
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


def run_diff(
    db_a: Path | str,
    db_b: Path | str,
    axis: Axis,
) -> DiffResult:
    """Locate and neutrally describe changes between two analysis databases.

    axis (version | mod | sibling) is recorded as each lead's scope_origin; the real
    pairing identity stays in the operator's external notes. Both DBs are read-only.
    Fully deterministic: functions align by exact symbol then pseudocode hash, and the
    change itself is the deterministic unified diff.
    """
    if axis not in get_args(Axis):
        raise ValueError(f"axis must be one of {get_args(Axis)} (got {axis!r})")
    funcs_a = load_functions(db_a)
    funcs_b = load_functions(db_b)
    pairs = match_functions(funcs_a, funcs_b)

    leads: list[ChangeLead] = []
    matched = unchanged = added = removed = changed = 0
    changed_unverifiable = skipped_no_body = 0
    for pair in pairs:
        lead, _diff_text = classify(pair, axis)
        if pair.a is not None and pair.b is not None:
            matched += 1
        kind = lead.change_kind
        if kind == "unchanged":
            unchanged += 1
            continue  # dropped: no lead
        if kind == "skipped_no_body":
            skipped_no_body += 1
            continue  # no information, not a change — dropped like unchanged
        if kind == "added":
            added += 1
        elif kind == "removed":
            removed += 1
        elif kind == "changed_unverifiable":
            changed_unverifiable += 1
        else:  # changed
            changed += 1
        leads.append(lead)

    stats = DiffStats(
        matched=matched,
        unchanged=unchanged,
        added=added,
        removed=removed,
        changed=changed,
        changed_unverifiable=changed_unverifiable,
        skipped_no_body=skipped_no_body,
    )
    return DiffResult(leads=tuple(leads), stats=stats)
