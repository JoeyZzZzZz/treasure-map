# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The ARM / AArch64 stub table: a PLT decoded entry by entry, never sized by layout arithmetic.

The decoder is a pure function of the PLT's bytes, its address and the binary's lazily bound GOT
slots, so it is checked here on hand-encoded instruction words; ``resolve_stubs`` is then driven on
synthetic ELFs that carry their facts only in the dynamic segment, the way a stripped firmware
binary does. The instruction words are encoded by ``elf_builder`` (or spelled out below), never by
the reader under test.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from tests.unit.lib.elf_builder import (
    EM_AARCH64,
    EM_ARM,
    GOT_AT,
    PLT_AT,
    STT,
    STT_GNU_IFUNC,
    Elf,
    aarch64_plt_entry,
    arm_plt_entry,
    plt_dynamic_binary,
)
from treasure_map.lib.analyze.stub_resolve import (
    PltEntry,
    decode_aarch64_plt_entry,
    decode_arm_plt_entry,
    decode_plt,
    ifunc_slot_names,
    resolve_stubs,
)

_PUSH_R4_LR = struct.pack("<I", 0xE92D4010)  # push {r4, lr}: the first word of an ordinary function
_FUNC = STT["FUNC"]


def _words(*ws: int) -> bytes:
    return b"".join(struct.pack("<I", w) for w in ws)


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


# ── one entry, decoded from its instruction words ────────────────────────────────────────────


def test_the_short_arm_entry_names_the_slot_its_pc_relative_adds_reach() -> None:
    code = arm_plt_entry(0x1014, 0x200C)
    assert decode_arm_plt_entry(code, 0, 0x1014) == PltEntry(0x1014, 0x200C, 12)


def test_the_long_arm_entry_adds_every_immediate() -> None:
    # add ip, pc, #0x10000000 ; add ip, ip, #0x100000 ; add ip, ip, #0x2000 ; ldr pc, [ip, #0x34]!
    code = _words(0xE28FC201, 0xE28CC601, 0xE28CCA02, 0xE5BCF034)
    got = decode_arm_plt_entry(code, 0, 0x1000)
    assert got == PltEntry(0x1000, 0x1000 + 8 + 0x10000000 + 0x100000 + 0x2000 + 0x34, 16)


def test_the_movw_movt_arm_entry_adds_the_third_instructions_pc() -> None:
    value = 0x00012345
    movw = 0xE300C000 | ((value & 0xF000) << 4) | (value & 0xFFF)
    movt = 0xE340C000 | (((value >> 16) & 0xF000) << 4) | ((value >> 16) & 0xFFF)
    code = _words(movw, movt, 0xE08CC00F, 0xE59CF004)  # add ip, ip, pc ; ldr pc, [ip, #4]
    got = decode_arm_plt_entry(code, 0, 0x1000)
    # `add ip, ip, pc` sits at 0x1008 and reads pc as 0x1010
    assert got == PltEntry(0x1000, value + 0x1010 + 4, 16)


def test_a_thumb_prefix_is_part_of_the_entry_and_moves_its_pc() -> None:
    code = b"\x78\x47\xc0\x46" + arm_plt_entry(0x1004, 0x2010)  # bx pc ; nop ; then the ARM entry
    assert decode_arm_plt_entry(code, 0, 0x1000) == PltEntry(0x1000, 0x2010, 16, True)


def test_bytes_that_are_no_arm_entry_decode_to_nothing() -> None:
    assert decode_arm_plt_entry(_PUSH_R4_LR * 4, 0, 0x1000) is None
    assert decode_arm_plt_entry(arm_plt_entry(0x1000, 0x2000)[:8], 0, 0x1000) is None  # cut short


def test_the_aarch64_entry_reads_its_page_and_offset_both_ways() -> None:
    up = aarch64_plt_entry(0x1020, 0x12018)
    assert decode_aarch64_plt_entry(up, 0, 0x1020) == PltEntry(0x1020, 0x12018, 16)
    down = aarch64_plt_entry(0x45030, 0x3FF8)  # a slot pages below the entry: a negative adrp
    assert decode_aarch64_plt_entry(down, 0, 0x45030) == PltEntry(0x45030, 0x3FF8, 16)


def test_an_aarch64_entry_whose_add_names_another_offset_is_no_entry() -> None:
    code = bytearray(aarch64_plt_entry(0x1020, 0x12018))
    code[8:12] = struct.pack("<I", 0x91000210 | (0x020 << 10))  # add x16, x16, #0x20, not #0x18
    assert decode_aarch64_plt_entry(bytes(code), 0, 0x1020) is None


# ── the table: where it ends is decoded, never computed ───────────────────────────────────────


def test_a_function_laid_out_after_the_plt_is_never_a_stub() -> None:
    """A-E4-14 (the layout-arithmetic tooth). Three lazily bound slots, but only two PLT entries:
    the third import is bound some other way, and the bytes after the second entry are an
    ordinary ``.text`` function. Sizing the table by its slots (header + 3 x 12 bytes) would make
    that function the third stub and name it after an import.

    Mutation: decode_plt reads ``len(slots)`` entries at a fixed 12-byte stride -> RED."""
    header = b"\0" * 20
    e0, e1 = 0x1000 + 20, 0x1000 + 32
    slots = {0x2000, 0x2004, 0x2008}
    code = header + arm_plt_entry(e0, 0x2000) + arm_plt_entry(e1, 0x2004) + _PUSH_R4_LR * 3
    # Precondition: the fixture has more slots than entries, so layout arithmetic would reach the
    # function at 0x102c.
    assert len(slots) * 12 + 20 > 0x102C - 0x1000
    entries = decode_plt(code, 0x1000, "arm", slots)
    assert [e.addr for e in entries] == [e0, e1]
    assert 0x102C not in {e.addr for e in entries}


def test_an_entry_shaped_word_run_through_a_slot_not_bound_lazily_ends_the_table() -> None:
    """Bytes that decode like an entry but jump through a slot this binary does not bind lazily are
    not an entry: the table ends before them.

    Mutation: drop the ``got_slot not in slots`` stop -> RED (a third entry)."""
    e0, e1, e2 = 0x1014, 0x1020, 0x102C
    code = b"\0" * 20 + arm_plt_entry(e0, 0x2000) + arm_plt_entry(e1, 0x2004)
    code += arm_plt_entry(e2, 0x2400)  # 0x2400 is no lazily bound slot
    entries = decode_plt(code, 0x1000, "arm", {0x2000, 0x2004, 0x2008})
    assert [e.got_slot for e in entries] == [0x2000, 0x2004]


def test_a_slot_taken_twice_ends_the_table() -> None:
    """Mutation: drop the ``got_slot in taken`` stop -> RED (the repeat is read as an entry)."""
    code = b"\0" * 20 + arm_plt_entry(0x1014, 0x2000) + arm_plt_entry(0x1020, 0x2000)
    entries = decode_plt(code, 0x1000, "arm", {0x2000, 0x2004})
    assert [e.addr for e in entries] == [0x1014]


def test_the_aarch64_table_starts_after_its_eight_word_header() -> None:
    header = b"\0" * 32
    code = header + aarch64_plt_entry(0x1020, 0x2018) + aarch64_plt_entry(0x1030, 0x2020)
    entries = decode_plt(code, 0x1000, "aarch64", {0x2018, 0x2020})
    assert [(e.addr, e.got_slot) for e in entries] == [(0x1020, 0x2018), (0x1030, 0x2020)]


# ── IRELATIVE: the one ifunc of that address, or no name ──────────────────────────────────────


def test_an_irelative_slot_is_named_only_by_exactly_one_ifunc() -> None:
    """A-E4-15. Named when the resolver address is the value of exactly one ``STT_GNU_IFUNC`` name
    (two symbols spelling the same name are one); unnamed when none has it, or when several
    different names share it.

    Mutation: ``len(names) >= 1`` (several also name) -> RED on the shared address.
    Mutation: fall back to the nearest ifunc below the address when none matches -> RED."""
    ifuncs = {0x7794C: {"memchr"}, 0x78388: {"memcpy"}, 0x79000: {"strlen", "__strlen_ifunc"}}
    initial = {0x40003C: 0x7794C, 0x400040: 0x78388, 0x400044: 0x79000, 0x400048: 0x78390}
    assert ifunc_slot_names(initial, ifuncs) == {0x40003C: "memchr", 0x400040: "memcpy"}


# ── resolve_stubs on a whole (synthetic) image ─────────────────────────────────────────────────

_SHIFT32 = 0x10000
_SHIFT64 = 0x100000


def _arm_image(*, extra_slot: bool = False, ifunc_names: tuple[str, ...] = ("memcpy",)) -> bytes:
    """An ARM ET_DYN at 0: a PLT0 header, entries for ``system`` and ``popen`` (JUMP_SLOT) and for
    one IRELATIVE slot whose resolver is at 0x2800, then an ordinary function. ``extra_slot`` adds
    a third JUMP_SLOT no entry jumps through; ``ifunc_names`` are the ifunc symbols at 0x2800."""
    e = [PLT_AT + 20, PLT_AT + 32, PLT_AT + 44]
    slots = [GOT_AT + 0xC, GOT_AT + 0x10, GOT_AT + 0x14]
    plt = b"\0" * 20 + b"".join(arm_plt_entry(a, s) for a, s in zip(e, slots, strict=True))
    plt += _PUSH_R4_LR * 4
    symbols = [("system", _FUNC, 0, False), ("popen", _FUNC, 0, False), ("exit", _FUNC, 0, False)]
    symbols += [(n, STT_GNU_IFUNC, 0x2800, True) for n in ifunc_names]
    jump = [(slots[0], 1), (slots[1], 2)] + ([(GOT_AT + 0x18, 3)] if extra_slot else [])
    got = {s: PLT_AT for s, _sym in jump}
    return plt_dynamic_binary(
        machine=EM_ARM,
        plt=plt,
        got=got,
        jump_slots=jump,
        irelative=((slots[2], 0x2800),),
        symbols=symbols,
    )


def test_an_arm_plt_is_named_through_its_jump_slots_and_its_one_ifunc(tmp_path: Path) -> None:
    """★ The positive control. Every name lands on the entry the decoder found, moved by the
    decompiler's load shift; the region runs from PLT0 to the end of the last entry; the
    function after it is no stub; the table is complete.

    Mutation: name the IRELATIVE entry by nothing (JUMP_SLOT only) -> RED (memcpy missing, and
    the table no longer complete)."""
    r = resolve_stubs(_write(tmp_path, "libc.so", _arm_image()))
    assert r is not None
    assert r.names == {
        PLT_AT + 20 + _SHIFT32: "system",
        PLT_AT + 32 + _SHIFT32: "popen",
        PLT_AT + 44 + _SHIFT32: "memcpy",
    }
    assert r.named_regions == ((".plt", PLT_AT + _SHIFT32, PLT_AT + 56 + _SHIFT32),)
    assert r.regions == ((PLT_AT + _SHIFT32, PLT_AT + 56 + _SHIFT32),)
    assert PLT_AT + 56 + _SHIFT32 not in r.names  # the function laid out next to the PLT
    assert r.complete is True


def test_a_jump_slot_no_entry_reaches_makes_the_table_incomplete(tmp_path: Path) -> None:
    """A lazily bound import whose entry is not among the decoded ones: nothing is guessed for it,
    and the table says it is not a full account.

    Mutation: ``complete`` ignores the slots no entry reached -> RED."""
    r = resolve_stubs(_write(tmp_path, "lib.so", _arm_image(extra_slot=True)))
    assert r is not None
    assert "exit" not in r.names.values()
    assert set(r.names.values()) == {"system", "popen", "memcpy"}
    assert r.complete is False


def test_an_irelative_entry_two_ifunc_names_share_stays_unnamed(tmp_path: Path) -> None:
    """A-E4-15 through the whole image: the IRELATIVE entry whose resolver address two different
    ifunc names share is left unnamed, and the table is then not complete.

    Mutation: ``complete`` ignores unnamed entries -> RED."""
    r = resolve_stubs(_write(tmp_path, "lib.so", _arm_image(ifunc_names=("memcpy", "memmove"))))
    assert r is not None
    assert PLT_AT + 44 + _SHIFT32 not in r.names
    assert set(r.names.values()) == {"system", "popen"}
    assert r.complete is False


def test_an_aarch64_plt_reads_its_rela_addends(tmp_path: Path) -> None:
    """AArch64: RELA relocations (the IRELATIVE resolver is the addend, not the word in place),
    an eight-word header, and the 64-bit load shift."""
    e = [PLT_AT + 32, PLT_AT + 48]
    slots = [GOT_AT + 0x18, GOT_AT + 0x20]
    plt = b"\0" * 32 + b"".join(aarch64_plt_entry(a, s) for a, s in zip(e, slots, strict=True))
    image = plt_dynamic_binary(
        machine=EM_AARCH64,
        plt=plt + _PUSH_R4_LR * 4,
        got={slots[0]: PLT_AT, slots[1]: 0},  # an IRELATIVE slot's word is not its resolver
        jump_slots=[(slots[0], 1)],
        irelative=((slots[1], 0x2840),),
        symbols=[("system", _FUNC, 0, False), ("memchr", STT_GNU_IFUNC, 0x2840, True)],
    )
    r = resolve_stubs(_write(tmp_path, "libc.so", image))
    assert r is not None
    assert r.names == {e[0] + _SHIFT64: "system", e[1] + _SHIFT64: "memchr"}
    assert r.complete is True


def test_a_tls_descriptor_slot_is_no_stub(tmp_path: Path) -> None:
    """A TLS descriptor relocation also sits in the PLT relocation table, but its slot is no import
    stub: it is neither named nor counted against the table's completeness."""
    image = plt_dynamic_binary(
        machine=EM_AARCH64,
        plt=b"\0" * 32 + aarch64_plt_entry(PLT_AT + 32, GOT_AT + 0x18),
        got={GOT_AT + 0x18: PLT_AT},
        jump_slots=[(GOT_AT + 0x18, 1)],
        other_plt_relocs=((GOT_AT + 0x28, 1031),),  # R_AARCH64_TLSDESC
        symbols=[("system", _FUNC, 0, False)],
    )
    r = resolve_stubs(_write(tmp_path, "lib.so", image))
    assert r is not None
    assert r.names == {PLT_AT + 32 + _SHIFT64: "system"}
    assert r.complete is True


def test_an_arm_elf_without_a_dynamic_segment_is_a_cannot_tell(tmp_path: Path) -> None:
    assert resolve_stubs(_write(tmp_path, "static", Elf(machine=EM_ARM).build())) is None


@pytest.mark.parametrize("machine", [EM_ARM, EM_AARCH64])
def test_an_image_with_no_lazy_binding_is_a_complete_empty_table(
    tmp_path: Path, machine: int
) -> None:
    """Read, and nothing to name: ``{}`` and complete — not the "cannot tell" of None."""
    image = plt_dynamic_binary(machine=machine, plt=b"", got={}, jump_slots=[], symbols=[])
    r = resolve_stubs(_write(tmp_path, "lib.so", image))
    assert r is not None
    assert r.names == {}
    assert r.complete is True


def test_a_thumb_prefixed_entry_is_named_at_both_of_its_entry_points(tmp_path: Path) -> None:
    """An entry behind a Thumb ``bx pc; nop`` pair is entered at its start by a Thumb caller and
    four bytes on by an ARM one: both addresses carry the import's name.

    Mutation: name only the prefix's address -> RED."""
    e0 = PLT_AT + 20
    slot = GOT_AT + 0xC
    plt = b"\0" * 20 + b"\x78\x47\xc0\x46" + arm_plt_entry(e0 + 4, slot) + _PUSH_R4_LR * 4
    image = plt_dynamic_binary(
        machine=EM_ARM,
        plt=plt,
        got={slot: PLT_AT},
        jump_slots=[(slot, 1)],
        symbols=[("system", _FUNC, 0, False)],
    )
    r = resolve_stubs(_write(tmp_path, "lib.so", image))
    assert r is not None
    assert r.names == {e0 + _SHIFT32: "system", e0 + 4 + _SHIFT32: "system"}
    assert r.complete is True
