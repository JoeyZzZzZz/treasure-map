# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Teeth for the re-scan stability of ``build_evidence_ref`` — the anchor every durable
judgement is keyed by.

The load-bearing invariant: scanning the SAME firmware again must yield the SAME ref for the
same function, or every stored judgement silently loses its anchor. The single trap is the
analysis DB's AUTOINCREMENT ``functions.id`` — delete-and-reingest per binary plus never-reused
ids means the id of one unchanged function drifts by the whole function count on every re-scan
(measured on real firmware: a 4x-scanned DB numbered its 88,178 functions 266,156..354,333). So
``func_id`` must NOT reach the ref while a real anchor (address, then name) exists.

The core test constructs the invariant by INVARIANCE, not by absence: it varies only ``func_id``
across two calls (real-magnitude drift 266,156 vs 354,333) and asserts the two full ref strings are
*equal*. Asserting merely "the func_id digits are not in the string" would be fooled by a func_id
whose digits coincidentally landed in the sha8/address; string equality cannot be so fooled.

Reverse mutation (break-the-code proof — run once, expect RED, then restore):
    In ``src/treasure_map/lib/hunt/refs.py`` change the ``fn_anchor`` line

        fn_anchor = _norm_addr(address) or (func_name or "").strip()

    to inject the drifting id into the anchor

        fn_anchor = f"{_norm_addr(address) or (func_name or '').strip()}-{func_id}"

    Expected: **2 failed**, both genuine assertion reds (not *error* / not a syntax blow-up) —
    ``test_rescan_id_drift_yields_identical_ref`` (the two refs now differ by their ``-266156`` /
    ``-354333`` tails) and ``test_id_fallback_reachable_only_without_address_or_name`` (the same
    injected id displaces the degenerate ``id<func_id>`` tail: ``-266156`` replaces ``id266156``).
    Restore the line to re-green.
"""

from __future__ import annotations

from treasure_map.lib.hunt.refs import build_evidence_ref

# Real-firmware AUTOINCREMENT drift: the SAME unchanged function is numbered differently on each
# re-scan of a delete-and-reingest analysis DB. These two ids bracket a measured real range.
_ID_SCAN_A = 266156
_ID_SCAN_B = 354333

# A function that carries a real anchor (both address and stripped name are present, as on real
# firmware). ``_ANCHORED`` is everything about the row EXCEPT the drifting func_id.
_ANCHORED = {
    "binary_sha256": "b32a0ffe1c4d7a90e5b6c8d2f0a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
    "address": "0x000b32a0",
    "func_name": "FUN_000b32a0",
    "suffix": "cmd",
}


def test_rescan_id_drift_yields_identical_ref() -> None:
    """Same run + binary + address + suffix, only func_id drifts -> byte-identical ref.

    This is the whole point of the anchor: a re-scan's AUTOINCREMENT churn must not move it.
    """
    ref_a = build_evidence_ref("run-x", func_id=_ID_SCAN_A, **_ANCHORED)
    ref_b = build_evidence_ref("run-x", func_id=_ID_SCAN_B, **_ANCHORED)
    assert ref_a == ref_b


def test_address_present_id_fallback_unreachable() -> None:
    """With an address in hand, the ``id<func_id>`` last-resort tail never appears in the ref."""
    ref = build_evidence_ref("run-x", func_id=_ID_SCAN_A, **_ANCHORED)
    assert f"id{_ID_SCAN_A}" not in ref


def test_id_fallback_reachable_only_without_address_or_name() -> None:
    """Positive control: func_id IS a live input, so the equality invariant above is non-vacuous.

    Only a degenerate row with neither address nor name falls back to the ``id<func_id>`` tail —
    which is exactly the case the anchored invariant proves the ref stays clear of.
    """
    ref = build_evidence_ref(
        "run-x",
        suffix="cmd",
        binary_sha256=_ANCHORED["binary_sha256"],
        func_id=_ID_SCAN_A,
    )
    assert f"id{_ID_SCAN_A}" in ref
