# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Reading the per-binary bridge facts (call_tokens + body_ranges) the extractor emits.

One source of truth for turning a callsite's TEXT position into its ADDRESS, shared by the two
places that must agree by construction: the hunt layer, which stamps a per-callsite candidate's
ref with its address offset, and the D4 rekey, which re-derives the same address to migrate an old
text-ordinal ref onto it. If these computed the address two different ways they would agree only by
luck, and a durable judgement would migrate onto the wrong call the first time they diverged.

The bridge facts (see analyze/ghidra ExportFunctions buildCallTokens / buildBodyRanges):
  * call_tokens: one record per function-name token in the decompiler's C markup — its own address
    (``op_addr`` = the call instruction's address) and the character offset where it prints
    (``text_off`` = the START of the name). ``opcode`` 7 is a real CALL; -1 is the function's own
    name and carries no address.
  * body_ranges: the function body's real address ranges; a call address outside them is out of the
    function body (an inlined copy landing in a neighbour), which the readers treat as not_traced.
"""

from __future__ import annotations

import json

from treasure_map.lib.hunt.refs import _addr_to_int, _norm_offset
from treasure_map.lib.pattern.classes import call_offsets


def addr_in_body(addr: str | None, body_ranges_json: str | None) -> bool:
    """Is ``addr`` inside one of the function's real body ranges?

    Fail-closed: no ranges recorded (a pre-bridge / un-migrated row) or an unparseable address
    reads as NOT in body, so a caller degrades the candidate to not_traced rather than forge an
    anchor at an address it could not place (fail-closed, never a guess)."""
    if not body_ranges_json:
        return False
    try:
        ranges = json.loads(body_ranges_json)
    except (ValueError, TypeError):
        return False
    i = _addr_to_int(addr)
    if i is None:
        return False
    for pair in ranges:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            continue
        lo, hi = _addr_to_int(pair[0]), _addr_to_int(pair[1])
        if lo is not None and hi is not None and lo <= i <= hi:
            return True
    return False


def op_addr_at(call_tokens_json: str | None, pseudocode: str, paren_off: int) -> str | None:
    """The call instruction address of the CALL token whose name ends at the call whose opening
    paren is ``paren_off``, or None when the bridge emitted no such token (register-indirect calls
    produce no ClangFuncNameToken, and a pre-bridge row has no tokens at all).

    The token's ``text_off`` marks the START of the name; ``call_offsets`` reports the paren. They
    are the same call when only whitespace separates the name's end from the paren — the decompiler
    wraps a long qualified C++ name across that gap, so an exact-equality match would miss it."""
    if not call_tokens_json:
        return None
    try:
        tokens = json.loads(call_tokens_json)
    except (ValueError, TypeError):
        return None
    for tok in tokens:
        if not isinstance(tok, dict) or tok.get("opcode") != 7:
            continue  # 7 = CALL; -1 is the function's own name token, no address
        text = tok.get("call_token") or ""
        start = tok.get("text_off")
        if not isinstance(start, int):
            continue
        name_end = start + len(text)
        if 0 <= name_end <= paren_off and pseudocode[name_end:paren_off].strip() == "":
            addr = tok.get("op_addr")
            return addr if isinstance(addr, str) and addr else None
    return None


# Why a callsite could not be pinned to an in-body address. One vocabulary, shared by the hunt
# (which records it on the candidate as ``anchor_degraded``) and the rekey (its not_traced reasons),
# so the same failure reads the same everywhere.
NO_BRIDGE_DATA = "no_bridge_data"  # the function carries no bridge tokens at all
NO_BRIDGE_TOKEN = "no_bridge_token"  # tokens exist, none ends at this call's paren
OUT_OF_BODY = "out_of_body"  # the call address is outside the function's body ranges
ENUMERATOR_OUT_OF_RANGE = "enumerator_out_of_range"  # the occurrence is past the text's calls
OFFSET_UNPARSEABLE = "offset_unparseable"  # an address that does not parse as hex
NO_FUNC_ENTRY = "no_func_entry"  # the function row has no entry address to measure from
NO_SINK_NAME = "no_sink_name"  # the candidate names no concrete sink to enumerate
ANCHOR_DEGRADED_REASONS: frozenset[str] = frozenset(
    {
        NO_BRIDGE_DATA,
        NO_BRIDGE_TOKEN,
        OUT_OF_BODY,
        ENUMERATOR_OUT_OF_RANGE,
        OFFSET_UNPARSEABLE,
        NO_FUNC_ENTRY,
        NO_SINK_NAME,
    }
)


def bridge_tokens_present(call_tokens_json: str | None) -> bool:
    """Did the extractor record ANY bridge token for this function?

    False for NULL, an empty string, unparseable JSON, or an empty list. The empty list matters:
    ``"[]"`` is a non-empty string (truthy), and it is exactly what the ingest stores for an export
    that carried no tokens, so a plain truthiness test would misreport "no bridge data" as "the
    bridge ran and found nothing at this call"."""
    if not call_tokens_json:
        return False
    try:
        tokens = json.loads(call_tokens_json)
    except (ValueError, TypeError):
        return False
    return isinstance(tokens, list) and len(tokens) > 0


def address_offset_at(
    call_tokens_json: str | None,
    body_ranges_json: str | None,
    pseudocode: str,
    paren_off: int,
    func_entry: str,
) -> tuple[str | None, str | None]:
    """``(offset, None)`` for the call whose opening paren is ``paren_off``, or ``(None, reason)``.

    The one place a text position becomes an address offset: the hunt reaches it through the
    occurrence it enumerated, the rekey through the text offset it recovered from an old ref."""
    if not bridge_tokens_present(call_tokens_json):
        return None, NO_BRIDGE_DATA
    addr = op_addr_at(call_tokens_json, pseudocode, paren_off)
    if addr is None:
        return None, NO_BRIDGE_TOKEN
    if not addr_in_body(addr, body_ranges_json):
        return None, OUT_OF_BODY
    offset = _norm_offset(addr, func_entry)
    if offset is None:
        return None, OFFSET_UNPARSEABLE
    return offset, None


def callsite_address_offset(
    pseudocode: str | None,
    sink_name: str | None,
    occurrence: int | None,
    call_tokens_json: str | None,
    body_ranges_json: str | None,
    func_entry: str | None,
    stub_names: dict[int, str] | None,
) -> tuple[str | None, str | None]:
    """``(offset, None)`` — the normalized ADDRESS offset of the ``occurrence``-th call to
    ``sink_name`` — or ``(None, reason)`` when it cannot be pinned to an in-body address.

    ``reason`` is one of ``ANCHOR_DEGRADED_REASONS``; the candidate is then not_traced and the hunt
    records the reason on it. ``(None, None)`` only when ``occurrence`` is None: a function-level
    candidate has no callsite to locate, so nothing degraded. Steps: locate the callsite's text
    position with the SAME enumerator the detector used (so the Nth call is the same call), find the
    bridge token whose name ends at that call's paren, take its call-instruction address, and
    require it to fall inside the body — never a guessed anchor."""
    if occurrence is None:
        return None, None
    if not sink_name:
        return None, NO_SINK_NAME
    if not func_entry:
        return None, NO_FUNC_ENTRY
    if not bridge_tokens_present(call_tokens_json):
        return None, NO_BRIDGE_DATA
    pc = pseudocode or ""
    offsets = call_offsets(pc, sink_name, stub_names)
    if occurrence >= len(offsets):
        return None, ENUMERATOR_OUT_OF_RANGE
    return address_offset_at(
        call_tokens_json, body_ranges_json, pc, offsets[occurrence], func_entry
    )


def callsite_addr_out_of_body(
    pseudocode: str | None,
    sink_name: str | None,
    occurrence: int | None,
    call_tokens_json: str | None,
    stub_names: dict[int, str] | None,
) -> str | None:
    """The ABSOLUTE call-instruction address of the ``occurrence``-th call to ``sink_name``, EVEN
    when it falls outside the function's body ranges.

    ``address_offset_at`` DROPS that address on the ``out_of_body`` degrade (returns only a reason),
    but C7's co-claim fold / cross-side address alignment need it back. Recovered WITHOUT changing
    any existing signature (``rekey_d4`` shares ``address_offset_at`` / ``op_addr_at`` and must keep
    seeing them unchanged). It reuses the SAME enumeration (``call_offsets`` + ``op_addr_at``) as
    ``callsite_address_offset``, so the address is the very same callsite the detector enumerated.
    None when no bridge token pins the call (register-indirect, no tokens, occurrence out of range)
    — the caller then records no address and the candidate stays function-level, never a guess."""
    if occurrence is None or not sink_name or not bridge_tokens_present(call_tokens_json):
        return None
    pc = pseudocode or ""
    offsets = call_offsets(pc, sink_name, stub_names)
    if occurrence >= len(offsets):
        return None
    return op_addr_at(call_tokens_json, pc, offsets[occurrence])
