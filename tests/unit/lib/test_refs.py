# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
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
    injected id displaces the degenerate ``id<func_id>`` tail — ``-266156`` replaces the
    ``id``-prefixed form).
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


# ── D4: address-offset ref form ─────────────────────────────────────────────────────────────────

from treasure_map.lib.hunt.refs import (  # noqa: E402
    _norm_offset,
    callsite_offset_suffix,
)


def test_norm_offset_is_signed_and_zero_padded() -> None:
    """One offset, one spelling: signed, 0x, fixed-width zero pad. A negative in-body offset (an
    out-of-line block below the entry) keeps its sign so it never aliases onto a positive call.

    MUTATION (must go RED): drop the sign (``abs`` both sides), or drop the zero pad (``:x``)."""
    assert _norm_offset("0x409bc8", "0x409748") == "0x000480"
    assert _norm_offset("0x400", "0x440") == "-0x000040"
    assert _norm_offset("0x1000", "0x1000") == "0x000000"
    # the "0x1218" vs "0x001218" aliasing the pad exists to prevent
    assert _norm_offset("0x1218", "0x0") == _norm_offset("0x001218", "0x0") == "0x001218"
    # an offset wider than the pad still renders deterministically
    assert _norm_offset("0x1abcdef", "0x0") == "0x1abcdef"
    # unparseable either side -> None (caller falls back, never guesses)
    assert _norm_offset(None, "0x1") is None
    assert _norm_offset("zzz", "0x1") is None


def test_callsite_offset_suffix_three_forms_by_caller_contract() -> None:
    """Address offset when known; else the legacy ``#index`` ONLY if the caller passes one; else
    bare. The caller passes an index only for a pre-bridge DB, so a bridge-present hunt emits no
    ``#index`` at all — the invariant the rekey rests on. With the bridge present, an unaddressable
    call (index withheld) degrades to bare, not to a shifted ordinal a retired phantom could move.

    MUTATION (must go RED): return the bare class even when a callsite_index is given (which would
    collapse per-callsite candidates on a pre-bridge DB)."""
    assert callsite_offset_suffix("cmd", "0x001218") == "cmd@0x001218"
    assert callsite_offset_suffix("cmd", "0x001218", 3) == "cmd@0x001218"  # offset wins over index
    assert callsite_offset_suffix("copy", None, 2) == "copy#2"  # legacy: no bridge, index passed
    assert callsite_offset_suffix("copy", None) == "copy"  # bridge present, index withheld -> bare
    assert callsite_offset_suffix("copy", None, None) == "copy"


def test_offset_ref_splits_on_the_first_at_sign() -> None:
    """The full ref carries two ``@`` (``...@cmd@0x000480``); readers must split on the FIRST so the
    head stays ``<run>#<sha8>:<addr>`` and the suffix is ``<class>@<offset>``.

    This pins the wire contract the rekey executor relies on for parsing the new-form ref."""
    ref = build_evidence_ref(
        "runx",
        suffix=callsite_offset_suffix("cmd", _norm_offset("0x409bc8", "0x409748")),
        binary_sha256="a886defeaabbccdd",
        address="0x409748",
    )
    assert ref == "runx#a886defe:00409748@cmd@0x000480"
    head, suffix = ref.split("@", 1)
    assert head == "runx#a886defe:00409748"
    assert suffix.split("@") == ["cmd", "0x000480"]
