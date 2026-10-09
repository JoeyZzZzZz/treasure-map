# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The bridge reader: text position -> call address, and the reasons it can fail.

Synthetic token JSON in the shape the extractor emits (``text_off`` = start of the PRINTED name, in
Unicode code points; ``call_token`` = the printed name). No firmware needed."""

from __future__ import annotations

import json

from treasure_map.lib.hunt.bridge import (
    ENUMERATOR_OUT_OF_RANGE,
    NO_BRIDGE_DATA,
    NO_BRIDGE_TOKEN,
    NO_FUNC_ENTRY,
    NO_SINK_NAME,
    OFFSET_UNPARSEABLE,
    OUT_OF_BODY,
    bridge_tokens_present,
    callsite_addr_out_of_body,
    callsite_address_offset,
    op_addr_at,
)

_BODY = json.dumps([["0x1000", "0x1fff"]])


def _tok(text: str, off: int, addr: str, opcode: int = 7) -> dict[str, object]:
    return {"call_token": text, "text_off": off, "op_addr": addr, "opcode": opcode}


def test_offsets_are_code_points_past_a_supplementary_character() -> None:
    """A wide-char literal holding a character outside the BMP sits before the call. Counted in code
    points (what the extractor now emits, and how Python indexes the text) the token lands on the
    call; counted in 16-bit code units it would land one place late and miss it."""
    pc = "void f(void) {\n  g(L'\U00010000');\n  system(p);\n}\n"
    name_at = pc.index("system")  # Python index = code points
    good = json.dumps([_tok("system", name_at, "0x1010")])
    units16 = json.dumps([_tok("system", name_at + 1, "0x1010")])  # what 16-bit-unit counting gave
    paren = name_at + len("system")
    assert op_addr_at(good, pc, paren) == "0x1010"
    assert op_addr_at(units16, pc, paren) is None


def test_a_printed_name_is_matched_by_its_printed_length() -> None:
    """A name holding a supplementary character prints with it replaced by two underscores; the
    token carries that PRINTED text, whose length is what lines the name's end up with the paren.
    The raw name (one code point shorter) would not."""
    printed = "do__it"  # what a name "do<U+10000>it" prints as
    raw = "do\U00010000it"
    pc = f"void f(void) {{\n  {printed}(p);\n}}\n"
    at = pc.index(printed)
    paren = at + len(printed)
    assert op_addr_at(json.dumps([_tok(printed, at, "0x1020")]), pc, paren) == "0x1020"
    assert op_addr_at(json.dumps([_tok(raw, at, "0x1020")]), pc, paren) is None


def test_only_a_call_token_supplies_an_address() -> None:
    """The function's own name token (opcode -1) can sit where a call would; only opcode 7 (CALL)
    is a call. With both at one position, the CALL token's address is the answer.

    MUTATION (must go RED): drop the ``opcode != 7`` filter in op_addr_at."""
    pc = "void f(void) {\n  system(p);\n}\n"
    at = pc.index("system")
    tokens = json.dumps([_tok("system", at, "0x9999", opcode=-1), _tok("system", at, "0x1010")])
    assert op_addr_at(tokens, pc, at + len("system")) == "0x1010"


def test_an_empty_token_list_is_no_bridge_data() -> None:
    """``"[]"`` (what the ingest stores for a token-less export) is NO bridge data, not "the
    bridge ran and found nothing here"; likewise NULL, an empty string and unparseable JSON."""
    for raw in (None, "", "[]", "not json"):
        assert bridge_tokens_present(raw) is False
    assert bridge_tokens_present(json.dumps([_tok("x", 0, "0x1")])) is True


def test_each_failure_has_its_own_reason() -> None:
    """Every way a callsite can fail to get an address names itself; the success case names none."""
    pc = "void f(void) {\n  system(p);\n}\n"
    at = pc.index("system")
    tok = json.dumps([_tok("system", at, "0x1010")])

    def run(**kw: object) -> tuple[str | None, str | None]:
        args: dict[str, object] = {
            "pseudocode": pc,
            "sink_name": "system",
            "occurrence": 0,
            "call_tokens_json": tok,
            "body_ranges_json": _BODY,
            "func_entry": "0x1000",
            "stub_names": None,
        }
        args.update(kw)
        return callsite_address_offset(**args)  # type: ignore[arg-type]

    assert run() == ("0x000010", None)
    assert run(occurrence=None) == (None, None)  # function-level: nothing to locate
    assert run(sink_name=None) == (None, NO_SINK_NAME)
    assert run(func_entry=None) == (None, NO_FUNC_ENTRY)
    assert run(call_tokens_json="[]") == (None, NO_BRIDGE_DATA)
    assert run(occurrence=1) == (None, ENUMERATOR_OUT_OF_RANGE)
    other = json.dumps([_tok("system", 0, "0x1010")])  # a token that is not at this call
    assert run(call_tokens_json=other) == (None, NO_BRIDGE_TOKEN)
    assert run(body_ranges_json=json.dumps([["0x5000", "0x5fff"]])) == (None, OUT_OF_BODY)
    assert run(func_entry="zz") == (None, OFFSET_UNPARSEABLE)


def test_callsite_addr_out_of_body_recovers_dropped_address() -> None:
    """C7 (co-claim fold): out_of_body drops the computed call address (returns only a reason);
    callsite_addr_out_of_body recovers it via the SAME enumeration. None when no token pins it.

    MUTATION (must go RED): gate it on addr_in_body — then the out_of_body case returns None."""
    pc = "void f(void) {\n  system(p);\n}\n"
    at = pc.index("system")
    tok = json.dumps([_tok("system", at, "0x1010")])
    out_of_body = json.dumps([["0x5000", "0x5fff"]])  # 0x1010 is NOT in this body
    # offset path drops it (reason only); the recovery returns the address anyway
    assert callsite_address_offset(pc, "system", 0, tok, out_of_body, "0x1000", None) == (
        None,
        OUT_OF_BODY,
    )
    assert callsite_addr_out_of_body(pc, "system", 0, tok, None) == "0x1010"
    # function-level / no sink / no token pin -> None (never a guess)
    assert callsite_addr_out_of_body(pc, "system", None, tok, None) is None
    assert callsite_addr_out_of_body(pc, None, 0, tok, None) is None
    assert callsite_addr_out_of_body(pc, "system", 0, "[]", None) is None
    assert callsite_addr_out_of_body(pc, "system", 1, tok, None) is None  # occurrence out of range
