# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""A dispatch-table handler is kept only when the ELF itself fills the slot with it.

The detector reads ``{string, function}`` records out of the decompiler's memory view. A slot the
ELF fills with a vtable or typeinfo symbol plus an offset can land on a neighbouring function, and
a run of GOT entries alternates strings and functions: tables by accident. These pin the ELF-side
check (``elf_slots``) and what the ingest does with it (``checked_string_tables``): the record is
refused, its table is cut there, a piece shorter than the detector's minimum is no table, and each
table that remains says why it is not known complete. Every ELF here is synthetic and carries no
section headers, as most firmware binaries do.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tests.unit.lib.elf_builder import (
    DATA,
    EM_MIPS,
    R_ARM_ABS32,
    R_ARM_RELATIVE,
    dynamic_rel_binary,
)
from treasure_map.lib.analyze.elf_slots import (
    HANDLER_NOT_FUNCTION,
    HANDLER_UNVERIFIED,
    RECORD_IN_GOT,
    ElfSlots,
    SlotSymbol,
    handler_check,
    read_elf_slots,
)
from treasure_map.lib.analyze.ghidra_ingest import SCOPE_ONLY, checked_string_tables

LOADED = 0x10000 + DATA  # the data area where the decompiler loads it


def _arm(tmp_path: Path) -> ElfSlots:
    p = tmp_path / "lib.so"
    p.write_bytes(
        dynamic_rel_binary(
            symbols=[
                ("handler_fn", "FUNC", True),
                ("_ZTVfake", "OBJECT", False),
                ("imported", "FUNC", False),
                ("untyped", "NOTYPE", True),
            ],
            relocs=[
                (0x10, 1, R_ARM_ABS32, 0),
                (0x18, 2, R_ARM_ABS32, 8),  # a vtable symbol + 8, the addend in place
                (0x20, 3, R_ARM_ABS32, 0),
                (0x28, 0, R_ARM_RELATIVE, 0x200),
                (0x30, 4, R_ARM_ABS32, 0),
            ],
        )
    )
    slots = read_elf_slots(p)
    assert slots is not None
    return slots


def test_the_slot_facts_come_from_the_dynamic_segment_alone(tmp_path: Path) -> None:
    """★ With no section headers, the relocations, their symbols' ELF types, an in-place addend and
    a symbol-less RELATIVE slot are all read through the dynamic tags — at the decompiler's
    addresses (+0x10000 for a 32-bit object linked at 0)."""
    slots = _arm(tmp_path)
    assert slots.symbol(LOADED + 0x10) == SlotSymbol("handler_fn", "STT_FUNC", True, 0)
    assert slots.symbol(LOADED + 0x18) == SlotSymbol("_ZTVfake", "STT_OBJECT", False, 8)
    assert slots.relocated(LOADED + 0x28) and slots.symbol(LOADED + 0x28) is None
    assert not slots.relocated(LOADED + 0x40)
    assert not slots.relocated(DATA + 0x10)  # the link-time address is not the decompiler's


def test_a_handler_is_kept_only_when_the_elf_puts_that_function_in_the_slot(
    tmp_path: Path,
) -> None:
    """★ The ELF's own word decides. A defined FUNC symbol: kept, whatever the decompiler named the
    function it followed the pointer to (a thunk is followed). A symbol plus an offset: refused —
    the miss this exists for. An import: kept only under its own name. An untyped symbol: kept,
    marked unverified (dropping a real table loses an edge). A plain or RELATIVE slot: kept.

    MUTATION (verified RED): ignore the addend -> the vtable+8 slot passes on its type alone only if
    typed FUNC, so the untyped+offset case below is kept -> RED; skip the import-name check -> RED;
    keep any symbol type -> RED."""
    slots = _arm(tmp_path)

    def check(off: int, name: str) -> str | None:
        return handler_check(slots, LOADED + off - 4, LOADED + off, name)

    assert check(0x10, "the_thunk_target") is None
    assert check(0x18, "neighbour_fn") == HANDLER_NOT_FUNCTION
    assert check(0x20, "imported") is None
    assert check(0x20, "something_else") == HANDLER_NOT_FUNCTION
    assert check(0x30, "untyped") == HANDLER_UNVERIFIED
    assert check(0x28, "local_fn") is None
    assert check(0x40, "no_reloc") is None
    untyped_offset = ElfSlots(symbols={0x100: SlotSymbol("x", "STT_NOTYPE", False, 8)})
    assert handler_check(untyped_offset, 0xFC, 0x100, "x") == HANDLER_NOT_FUNCTION
    obj = ElfSlots(symbols={0x100: SlotSymbol("x", "STT_OBJECT", True, 0)})
    assert handler_check(obj, 0xFC, 0x100, "x") == HANDLER_NOT_FUNCTION


def test_a_record_in_the_got_is_no_table_record_even_without_section_headers(
    tmp_path: Path,
) -> None:
    """★ A MIPS GOT, found from DT_PLTGOT and the local/global entry counts when there are no
    section headers: a record lying in it is refused, whatever its words point at.

    MUTATION (verified RED): skip the GOT test -> RED."""
    p = tmp_path / "mips.so"
    p.write_bytes(
        dynamic_rel_binary(
            machine=EM_MIPS, symbols=[("a", "FUNC", True)], relocs=[], mips_got=(0x80, 2, 2, 1)
        )
    )
    slots = read_elf_slots(p)
    assert slots is not None
    assert slots.got == ((LOADED + 0x80, LOADED + 0x8C),)  # 2 local + 1 global entries
    assert handler_check(slots, LOADED + 0x80, LOADED + 0x84, "a") == RECORD_IN_GOT
    assert handler_check(slots, LOADED + 0x88, LOADED + 0x8C, "a") == RECORD_IN_GOT
    assert handler_check(slots, LOADED + 0x8C, LOADED + 0x90, "a") is None


# ── the ingest: refused records cut their table; each table says why it is not complete ──────


def _table(
    base: int, n: int, *, before: str = "not_a_record", after: str = "not_a_record", **entry: Any
) -> dict[str, Any]:
    return {
        "table_addr": f"0x{base:x}",
        "stride": 8,
        "count": n,
        "bounds": {"before": before, "after": after},
        "entries": [
            {
                "key": f"k{i}",
                "func_name": f"f{i}",
                "func_addr": "0x1",
                "func_kind": "direct",
                "key_terminated": True,
                **entry,
            }
            for i in range(n)
        ],
    }


def _bad_slots(*handler_slots: int) -> ElfSlots:
    return ElfSlots(
        symbols={a: SlotSymbol("_ZTIfake", "STT_OBJECT", False, 8) for a in handler_slots}
    )


def test_a_table_of_refused_records_is_gone_and_one_refused_record_cuts_a_table(
    tmp_path: Path,
) -> None:
    """★ Every record refused: no table. One refused record in nine: two tables of four, each
    saying a record was refused there. A piece shorter than four is no table.

    MUTATION (verified RED): keep a refused record -> RED; keep pieces shorter than the minimum
    -> the 3-record piece survives -> RED."""
    base = 0x20000
    all_bad = _bad_slots(*(base + i * 8 + 4 for i in range(5)))
    assert checked_string_tables([_table(base, 5)], all_bad) == []

    cut = checked_string_tables([_table(base, 9)], _bad_slots(base + 4 * 8 + 4))
    assert [(t.table_addr, len(t.entries), t.reason) for t in cut] == [
        (f"0x{base:x}", 4, "handler_not_function"),
        (f"0x{base + 5 * 8:x}", 4, "handler_not_function"),
    ]
    assert [e["func_name"] for e in cut[1].entries] == ["f5", "f6", "f7", "f8"]

    short = checked_string_tables([_table(base, 8)], _bad_slots(base + 3 * 8 + 4))
    assert [(t.table_addr, len(t.entries)) for t in short] == [(f"0x{base + 4 * 8:x}", 4)]


def test_each_table_names_its_own_reason(tmp_path: Path) -> None:
    """★ The reason is per table, from what bounds it and what it holds: one undefined handler
    between two tables -> both cut; a lone undefined handler at an end; a handler outside the
    image; the per-table record cap; a key that is not a C string; an untyped handler; and when
    nothing is seen, scope_only — never "complete".

    MUTATION (verified RED): read every table with one shared reason -> RED; drop the adjacency
    test -> the split reads as two plain handler_undefined ends -> RED."""
    none = ElfSlots()
    a, b = 0x30000, 0x30000 + 5 * 8  # one 8-byte record between a's 4 records and b
    split = checked_string_tables(
        [_table(a, 4, after="handler_undefined"), _table(b, 4, before="handler_undefined")], none
    )
    assert [t.reason for t in split] == ["split_by_undefined_handler"] * 2

    def reason(t: dict[str, Any], slots: ElfSlots | None = none) -> str:
        [out] = checked_string_tables([t], slots)
        return out.reason

    assert reason(_table(a, 4, after="handler_undefined")) == "handler_undefined"
    assert reason(_table(a, 4, before="handler_external")) == "got_relative_unresolved"
    assert reason(_table(a, 4, after="entry_cap")) == "truncated_at_probe_limit"
    assert reason(_table(a, 4, after="loose_key")) == "split_by_loose_key"
    assert reason(_table(a, 4, key_terminated=False)) == "key_not_terminated"
    assert reason(_table(a, 4)) == SCOPE_ONLY
    assert reason(_table(a, 4, before="block_edge")) == SCOPE_ONLY
    untyped = ElfSlots(symbols={a + 4: SlotSymbol("f0", "STT_NOTYPE", True, 0)})
    assert reason(_table(a, 4), untyped) == HANDLER_UNVERIFIED
    assert reason(_table(a, 4), None) == HANDLER_UNVERIFIED  # the ELF could not be read
    both = reason(_table(a, 4, after="handler_undefined", key_terminated=False))
    assert both == "handler_undefined,key_not_terminated"


def test_the_ingest_checks_the_tables_against_the_binarys_own_slots(tmp_path: Path) -> None:
    """★ Through the real ingest, on a real ELF: a table whose every handler slot the ELF fills with
    a vtable symbol plus an offset is not stored; two tables the ELF does not contradict are, each
    with its OWN completeness reason (one stops at an undefined handler, the other at a handler
    outside the image) — never the detector-level reason shared by both.

    MUTATION (verified RED, 1 failed): hand the ingest an empty ``ElfSlots()`` instead of
    ``read_elf_slots(rec.path)`` -> the refused table is stored. Store the detector-level reason in
    place of each table's ``t.reason`` -> the two reasons read the same."""
    import json
    import sqlite3

    from treasure_map.lib.analyze.elf_inventory import ElfRecord
    from treasure_map.lib.analyze.ghidra_ingest import ingest_ghidra_output
    from treasure_map.lib.storage.connection import open_db

    elf = tmp_path / "libsvc.so"
    elf.write_bytes(
        dynamic_rel_binary(
            symbols=[("_ZTVfake", "OBJECT", False)],
            relocs=[(0x44 + 8 * i, 1, R_ARM_ABS32, 8) for i in range(4)],
        )
    )
    assert read_elf_slots(elf) is not None  # premise: the ELF is readable, so the check is made
    refused, undef, ext = LOADED + 0x40, LOADED + 0x100, LOADED + 0x200
    sha = "c" * 64
    data = {
        "functions": [],
        "imports": [],
        "exports": [],
        "strings": [],
        "string_tables": {
            "tables": [
                _table(refused, 4),
                _table(undef, 4, after="handler_undefined"),
                _table(ext, 4, before="handler_external"),
            ],
            "completeness": {"status": "incomplete", "reason": "shared", "scope": "s"},
        },
    }
    out = tmp_path / "out"
    out.mkdir()
    (out / f"libsvc.so_{sha[:8]}_ghidra.json").write_text(json.dumps(data))
    conn: sqlite3.Connection = open_db(tmp_path / "analysis.db")
    try:
        conn.execute("INSERT INTO binaries (name, sha256) VALUES ('libsvc.so', ?)", (sha,))
        bid = conn.execute("SELECT id FROM binaries").fetchone()[0]
        rec = ElfRecord(path=elf, name="libsvc.so", arch="ARM:LE:32:v7", elf_type="shared",
                        sha256=sha, size=elf.stat().st_size)  # fmt: skip
        ingest_ghidra_output(conn, out, [rec], {sha: bid})
        stored = dict(
            conn.execute("SELECT DISTINCT table_addr, completeness_reason FROM string_tables")
        )
    finally:
        conn.close()
    assert set(stored) == {f"0x{undef:x}", f"0x{ext:x}"}
    assert stored[f"0x{undef:x}"] == "handler_undefined"
    assert stored[f"0x{ext:x}"] == "got_relative_unresolved"
