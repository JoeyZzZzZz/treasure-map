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


def callsite_address_offset(
    pseudocode: str | None,
    sink_name: str | None,
    occurrence: int | None,
    call_tokens_json: str | None,
    body_ranges_json: str | None,
    func_entry: str | None,
    stub_names: dict[int, str] | None,
) -> str | None:
    """The normalized ADDRESS offset of the ``occurrence``-th call to ``sink_name``, from the bridge
    tokens, or None when it cannot be pinned to an in-body address.

    None makes the candidate not_traced. Steps: locate the callsite's text position with the SAME
    enumerator the detector used (so the Nth call is the same call), find the bridge token whose
    name ends at that call's paren, take its call-instruction address, and require it to fall inside
    the body — otherwise not_traced, never a guessed anchor."""
    if not call_tokens_json or occurrence is None or not func_entry or not sink_name:
        return None
    pc = pseudocode or ""
    offsets = call_offsets(pc, sink_name, stub_names)
    if occurrence >= len(offsets):
        return None
    addr = op_addr_at(call_tokens_json, pc, offsets[occurrence])
    if addr is None or not addr_in_body(addr, body_ranges_json):
        return None
    return _norm_offset(addr, func_entry)
