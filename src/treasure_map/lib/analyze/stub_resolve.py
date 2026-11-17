# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Resolve a binary's lazy-binding stubs to their import names, from ELF structure alone (MIPS,
32-bit ARM and AArch64).

When a program calls a libc function like ``system``, the compiler emits a call to a small stub in
``.plt`` (or ``.MIPS.stubs``) that jumps through the GOT. If the decompiler does not stitch that
stub back to the import — which happens routinely, depending on its configuration and how the
binary was linked — the caller is left calling ``FUN_0041eb38`` instead of ``system``, and a real
command-execution sink drops out of every downstream reading. That is a false negative on a sink
that is objectively there.

This recovers the name WITHOUT the decompiler, from structures the ELF already carries, so the
answer does not depend on whether the decompiler happened to build a thunk.

On ARM and AArch64 the PLT is DECODED, entry by entry (``decode_plt``): each entry's instructions
compute the address of the GOT slot it jumps through — ``add ip, pc, #…`` / ``add ip, ip, #…`` /
``ldr pc, [ip, #…]!`` or its ``movw``/``movt`` form, behind an optional Thumb ``bx pc; nop``
prefix, on ARM; ``adrp x16`` / ``ldr x17, [x16, #…]`` / ``add x16, x16, #…`` / ``br x17`` on
AArch64 — and the relocation on that slot names the import: a ``JUMP_SLOT`` its symbol, an
``IRELATIVE`` the one ``STT_GNU_IFUNC`` symbol of this binary whose value its resolver address
equals (none, or several, leaves it unnamed). ★ The table's extent comes from decoding, never from
layout arithmetic: a range derived from section sizes or slot counts runs past the last entry into
the ``.text`` function laid out next to it, and naming that function after an import is a
fabricated stub. Decoding stops at the first bytes that are no entry, or whose slot is not one this
binary binds lazily or was already taken; an entry that cannot be decoded is never guessed, and the
table is then not complete. The slots come from the dynamic segment, so a binary without section
headers is read the same way.

On MIPS two paths are tried in order, both deterministic:

  * ``.rel.plt`` — a new-ABI PLT carries a ``JUMP_SLOT`` relocation per GOT entry, naming the
    symbol directly. The ``.plt`` stubs are in fixed 1:1 order with those relocations, so a stub
    address maps to a GOT slot maps to a name by arithmetic.
  * the classic global GOT — an older MIPS layout has no per-slot relocation; a GOT slot's position
    past ``DT_MIPS_LOCAL_GOTNO`` maps to a ``.dynsym`` index by the ABI formula. ★ The domain
    guards (index within the local/global boundary and within the symbol count) are not defensive
    padding: on a new-ABI binary this formula produces a NEGATIVE index for a ``.got.plt`` slot,
    and without the guard it would read an arbitrary symbol and write a wrong name — the one
    outcome worse than leaving the sink unresolved, because a wrong ``system`` is a fabricated
    candidate.

★ When the two paths would resolve one slot to DIFFERENT names (a corrupt or adversarial binary),
the slot is dropped, not guessed. Treating a false negative must never manufacture a false
positive.

★ SCOPE. This recovers the stub-mediated call — a direct call to a ``.plt`` stub, which the
decompiler renders as ``FUN_<stub-addr>`` so the address is recoverable from the name. It does NOT
recover an inline ``%call16`` GOT call (``lw t9, off(gp); jalr t9`` written straight into the
caller), which the decompiler renders as a nameless indirect call that carries no address to work
back from — finding those needs a disassembler this layer deliberately does not depend on. Such a
call, when it is left unresolved, is surfaced as an unclassified external call rather than named.
"""

from __future__ import annotations

import hashlib
import logging
from collections import Counter
from collections.abc import Callable, Mapping, Set
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Literal

from elftools.common.exceptions import ELFError
from elftools.elf.dynamic import DynamicSegment
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

logger = logging.getLogger(__name__)

# MIPS PLT layout: a 2-entry header (0x20 bytes) precedes the per-import stubs, each 16 bytes, and
# stub i uses .got.plt slot i+2 (slots 0 and 1 are reserved). These are the standard toolchain
# constants, named so the arithmetic below reads against them rather than against magic numbers.
_MIPS_PLT_HEADER = 0x20
_MIPS_PLT_ENTRY = 0x10
_GOT_PLT_RESERVED = 2
_GOT_ENTRY = 4  # o32 GOT entry size


@dataclass(frozen=True)
class StubResolution:
    """What a binary's stubs resolve to, and where its stub regions are.

    ``names`` maps a stub's entry address to the import it calls — only the stubs that resolved
    unambiguously. ``regions`` are the ``.plt`` / ``.MIPS.stubs`` address ranges, so a caller's
    ``FUN_<addr>`` callee can be recognised as a stub call even when its name did not resolve (then
    it is an unclassified external call, surfaced rather than dropped).

    ``complete`` says the ``names`` table covers EVERY stub this binary has. On MIPS: no non-empty
    ``.MIPS.stubs`` section, and every ``.plt`` table entry resolved a name — False when a
    ``.MIPS.stubs`` table carries stubs this path does not name (``_plt_stub_names`` only reads
    ``.plt``). On ARM / AArch64: every ``JUMP_SLOT`` slot is reached by a decoded entry and every
    decoded entry is named — False when an entry could not be decoded or an ``IRELATIVE`` one has no
    single ``STT_GNU_IFUNC`` name. Either way a reader never takes an empty-or-partial table for
    "these are all the stubs". ``named_regions`` is ``regions`` tagged with each range's section
    name, carried so a later reader can tell a ``.plt`` region from a ``.MIPS.stubs`` one (the
    decoded ARM / AArch64 table is tagged ``.plt``; it runs from the table's header to the end of
    its last decoded entry, an ``.iplt`` laid out right after it included)."""

    names: dict[int, str]
    regions: tuple[tuple[int, int], ...]
    complete: bool = False
    named_regions: tuple[tuple[str, int, int], ...] = ()

    def in_stub_region(self, addr: int) -> bool:
        return any(lo <= addr < hi for lo, hi in self.regions)


# Where the decompiler loads a shared object linked at address 0: it rebases the whole image, by
# 0x10000 on a 32-bit ELF and 0x100000 on a 64-bit one. An executable (ET_EXEC), or a shared object
# linked at a non-zero address, loads where it was linked. Checked over a whole corpus (every
# binary agreed) and cross-checked per binary at ingest against the image base the decompiler
# itself reports.
_LOAD_SHIFT_32 = 0x10000
_LOAD_SHIFT_64 = 0x100000


def ghidra_load_shift_of(elf: ELFFile) -> int:
    """How far the decompiler moves this ELF's addresses when it loads it: 0x10000 (32-bit) or
    0x100000 (64-bit) for an ET_DYN whose lowest PT_LOAD is at virtual address 0, else 0.

    Every address this module reads from the ELF (``sh_addr``) is a link-time address; the callee
    names and stub regions it hands on are compared with the decompiler's addresses, so they are
    moved by this amount first."""
    if elf.header.e_type != "ET_DYN":
        return 0
    loads = [seg["p_vaddr"] for seg in elf.iter_segments() if seg["p_type"] == "PT_LOAD"]
    if not loads or min(loads) != 0:
        return 0
    return _LOAD_SHIFT_64 if elf.elfclass == 64 else _LOAD_SHIFT_32


def ghidra_load_shift(elf_path: Path | str) -> int | None:
    """``ghidra_load_shift_of`` for a file; None when it is not a readable ELF."""
    try:
        with open(elf_path, "rb") as fh:
            return ghidra_load_shift_of(ELFFile(fh))
    except (OSError, ELFError, ValueError, KeyError, AttributeError) as exc:
        logger.debug("load shift unreadable for %s: %s", elf_path, exc)
        return None


def _dynamic_tags(elf: ELFFile) -> dict[str, int]:
    from elftools.elf.dynamic import DynamicSection

    dyn = elf.get_section_by_name(".dynamic")
    if not isinstance(dyn, DynamicSection):
        return {}
    return {tag.entry.d_tag: tag.entry.d_val for tag in dyn.iter_tags()}


def _rel_plt_slot_names(elf: ELFFile, dynsym: Any) -> dict[int, str]:
    """GOT slot address -> symbol name, from the PLT's JUMP_SLOT relocations (the new-ABI path)."""
    out: dict[int, str] = {}
    for sec_name in (".rel.plt", ".rela.plt"):
        sec = elf.get_section_by_name(sec_name)
        if not isinstance(sec, RelocationSection):
            continue
        for rel in sec.iter_relocations():
            sym = dynsym.get_symbol(rel["r_info_sym"])
            if sym is not None and sym.name:
                out[rel["r_offset"]] = sym.name
    return out


def global_got_slot_symbol_index(
    got_slot: int, pltgot: int, local_gotno: int, gotsym: int, symtabno: int
) -> int | None:
    """The .dynsym index a global GOT slot maps to, or None when the slot carries no symbol.

    The classic MIPS position formula, with BOTH domain guards, isolated so the boundary logic is
    checkable without a hand-built ELF. ★ Neither guard is padding. A slot below the local/global
    boundary (``got_index < local``) is a local relocation with no symbol; on a NEW-ABI binary the
    same formula applied to a ``.got.plt`` slot yields a NEGATIVE index. And an index at or past
    ``symtabno`` points past the symbol table. Either read produces a wrong name — and a wrong
    ``system`` is a fabricated candidate, the one outcome worse than an unresolved sink — so each
    returns None instead."""
    got_index = (got_slot - pltgot) // _GOT_ENTRY
    if got_index < local_gotno:
        return None
    dynsym_index = gotsym + (got_index - local_gotno)
    if dynsym_index >= symtabno or dynsym_index < 0:
        return None
    return dynsym_index


def _global_got_slot_names(elf: ELFFile, dynsym: Any, tags: dict[str, int]) -> dict[int, str]:
    """GOT slot address -> symbol name, by the classic global-GOT position formula (see the
    domain-guarded ``global_got_slot_symbol_index`` it delegates the boundary logic to)."""
    got = elf.get_section_by_name(".got")
    pltgot = tags.get("DT_PLTGOT")
    local = tags.get("DT_MIPS_LOCAL_GOTNO")
    gotsym = tags.get("DT_MIPS_GOTSYM")
    symtabno = tags.get("DT_MIPS_SYMTABNO")
    if got is None or pltgot is None or local is None or gotsym is None or symtabno is None:
        return {}
    out: dict[int, str] = {}
    start, size = got["sh_addr"], got["sh_size"]
    for slot in range(start, start + size, _GOT_ENTRY):
        dynsym_index = global_got_slot_symbol_index(slot, pltgot, local, gotsym, symtabno)
        if dynsym_index is None:
            continue
        sym = dynsym.get_symbol(dynsym_index)
        if sym is not None and sym.name:
            out[slot] = sym.name
    return out


def _merge_slot_names(a: dict[int, str], b: dict[int, str]) -> dict[int, str]:
    """Union of two slot->name maps; a slot the two disagree on is dropped, never guessed."""
    out = dict(a)
    for slot, name in b.items():
        if slot in out and out[slot] != name:
            del out[slot]  # two paths, two names -> undecidable, so no name at all
        else:
            out.setdefault(slot, name)
    return out


def _plt_stub_names(elf: ELFFile, slot_names: dict[int, str]) -> dict[int, str]:
    """Stub entry address -> import name, mapping each .plt stub to its .got.plt slot."""
    plt = elf.get_section_by_name(".plt")
    got_plt = elf.get_section_by_name(".got.plt")
    if plt is None or got_plt is None:
        return {}
    out: dict[int, str] = {}
    count = (plt["sh_size"] - _MIPS_PLT_HEADER) // _MIPS_PLT_ENTRY
    for i in range(count):
        stub_addr = plt["sh_addr"] + _MIPS_PLT_HEADER + i * _MIPS_PLT_ENTRY
        slot = got_plt["sh_addr"] + (i + _GOT_PLT_RESERVED) * _GOT_ENTRY
        name = slot_names.get(slot)
        if name:
            out[stub_addr] = name
    return out


def _named_stub_regions(elf: ELFFile) -> tuple[tuple[str, int, int], ...]:
    """The ``.plt`` / ``.MIPS.stubs`` regions, each tagged with its section name (non-empty)."""
    regions: list[tuple[str, int, int]] = []
    for sec_name in (".plt", ".MIPS.stubs"):
        sec = elf.get_section_by_name(sec_name)
        if sec is not None and sec["sh_size"]:
            regions.append((sec_name, sec["sh_addr"], sec["sh_addr"] + sec["sh_size"]))
    return tuple(regions)


def _plt_entry_count(elf: ELFFile) -> int:
    """How many per-import stubs the ``.plt`` holds, by the same arithmetic ``_plt_stub_names``
    uses (0 when there is no ``.plt``). A table is ``complete`` only when every one resolved."""
    plt = elf.get_section_by_name(".plt")
    if plt is None:
        return 0
    return max(0, (plt["sh_size"] - _MIPS_PLT_HEADER) // _MIPS_PLT_ENTRY)


def _has_nonempty_mips_stubs(elf: ELFFile) -> bool:
    """True when a non-empty ``.MIPS.stubs`` is present — stubs ``_plt_stub_names`` never reads, so
    a named table that leaves them out is NOT a full account of this binary's stubs."""
    sec = elf.get_section_by_name(".MIPS.stubs")
    return sec is not None and bool(sec["sh_size"])


# ── ARM / AArch64: the PLT decoded entry by entry ────────────────────────────────────────────

# Relocation types read here, as the ELF ABIs number them. pyelftools 0.33 lists R_ARM_IRELATIVE
# as 140 and has no R_AARCH64_IRELATIVE, so the numbers are written out rather than looked up.
_R_ARM_JUMP_SLOT = 22
_R_ARM_IRELATIVE = 160
_R_AARCH64_JUMP_SLOT = 1026
_R_AARCH64_IRELATIVE = 1032
# The symbol type of an indirect function (10); pyelftools names it by the range it starts.
_IFUNC_TYPES = frozenset({"STT_GNU_IFUNC", "STT_LOOS"})
# PLT0, the header every lazily bound GOT slot initially points at: five ARM words, eight AArch64
# ones. The per-import entries follow it.
_ARM_PLT_HEADER = 20
_AARCH64_PLT_HEADER = 32
_ARM_ENTRY_MAX = 20  # a Thumb prefix and the four-word long form
_AARCH64_ENTRY = 16

PltMachine = Literal["arm", "aarch64"]


@dataclass(frozen=True)
class PltEntry:
    """One decoded PLT entry: the address a call enters it at, the GOT slot it jumps through, and
    its length in bytes. ``thumb_prefix``: it starts with the Thumb ``bx pc; nop`` pair, so its ARM
    instructions — a second entry point — start four bytes on."""

    addr: int
    got_slot: int
    size: int
    thumb_prefix: bool = False


def _le_word(code: bytes, off: int, size: int) -> int | None:
    if off < 0 or off + size > len(code):
        return None
    return int.from_bytes(code[off : off + size], "little")


def _arm_rotated_imm(word: int) -> int:
    """The value of an ARM data-processing immediate: eight bits rotated right by twice the
    four-bit rotation field."""
    rot = 2 * ((word >> 8) & 0xF)
    imm = word & 0xFF
    return ((imm >> rot) | (imm << (32 - rot))) & 0xFFFFFFFF if rot else imm


def _arm_imm16(word: int) -> int:
    """The 16-bit immediate of ``movw`` / ``movt`` (imm4:imm12)."""
    return ((word >> 4) & 0xF000) | (word & 0xFFF)


_ARM_ADD_IP_PC = 0xE28FC000  # add ip, pc, #imm
_ARM_ADD_IP_IP = 0xE28CC000  # add ip, ip, #imm
_ARM_LDR_PC_IP_WB = 0xE5BCF000  # ldr pc, [ip, #imm]!
_ARM_MOVW_IP = 0xE300C000  # movw ip, #imm16
_ARM_MOVT_IP = 0xE340C000  # movt ip, #imm16
_ARM_ADD_IP_IP_PC = 0xE08CC00F  # add ip, ip, pc
_ARM_LDR_PC_IP = 0xE59CF000  # ldr pc, [ip, #imm]
_THUMB_BX_PC, _THUMB_NOP = 0x4778, 0x46C0


def decode_arm_plt_entry(code: bytes, off: int, addr: int) -> PltEntry | None:
    """The 32-bit ARM PLT entry at ``code[off:]`` (link-time address ``addr``), or None when the
    bytes there are no entry. Little-endian instructions.

    Read: ``add ip, pc, #i`` then at most two ``add ip, ip, #i`` then ``ldr pc, [ip, #i]!`` (slot =
    the first instruction's pc, which reads its own address + 8, plus every immediate); or
    ``movw ip`` / ``movt ip`` / ``add ip, ip, pc`` / ``ldr pc, [ip, #i]`` (slot = the 32-bit value
    plus the third instruction's pc plus the offset). Either may sit behind a Thumb ``bx pc; nop``
    pair."""
    thumb = _le_word(code, off, 2) == _THUMB_BX_PC and _le_word(code, off + 2, 2) == _THUMB_NOP
    start = off + 4 if thumb else off
    pc = addr + (start - off) + 8
    w0 = _le_word(code, start, 4)
    if w0 is None:
        return None
    if w0 & 0xFFFFF000 == _ARM_ADD_IP_PC:
        total = _arm_rotated_imm(w0)
        at = start + 4
        for _ in range(3):
            w = _le_word(code, at, 4)
            if w is None:
                return None
            if w & 0xFFFFF000 == _ARM_ADD_IP_IP:
                total += _arm_rotated_imm(w)
                at += 4
                continue
            if w & 0xFFFFF000 == _ARM_LDR_PC_IP_WB:
                slot = (pc + total + (w & 0xFFF)) & 0xFFFFFFFF
                return PltEntry(addr, slot, at + 4 - off, thumb)
            return None
        return None
    if w0 & 0xFFF0F000 == _ARM_MOVW_IP:
        w1, w2, w3 = (_le_word(code, start + 4 * k, 4) for k in (1, 2, 3))
        if (
            w1 is not None
            and w3 is not None
            and w1 & 0xFFF0F000 == _ARM_MOVT_IP
            and w2 == _ARM_ADD_IP_IP_PC
            and w3 & 0xFFFFF000 == _ARM_LDR_PC_IP
        ):
            value = (_arm_imm16(w1) << 16) | _arm_imm16(w0)
            slot = (value + pc + 8 + (w3 & 0xFFF)) & 0xFFFFFFFF
            return PltEntry(addr, slot, start + 16 - off, thumb)
    return None


_A64_ADRP_X16 = 0x90000010  # adrp x16, #page   (mask 0x9F00001F)
_A64_LDR_X17_X16 = 0xF9400211  # ldr x17, [x16, #imm12 * 8]   (mask 0xFFC003FF)
_A64_ADD_X16_X16 = 0x91000210  # add x16, x16, #imm12   (mask 0xFFC003FF)
_A64_BR_X17 = 0xD61F0220  # br x17


def decode_aarch64_plt_entry(code: bytes, off: int, addr: int) -> PltEntry | None:
    """The AArch64 PLT entry at ``code[off:]`` (link-time address ``addr``), or None when the
    bytes there are no entry: ``adrp x16`` / ``ldr x17, [x16, #o]`` / ``add x16, x16, #o`` /
    ``br x17``, the ``add`` naming the same offset as the load (slot = the ``adrp`` page + o)."""
    w0, w1, w2, w3 = (_le_word(code, off + 4 * k, 4) for k in range(4))
    if w0 is None or w1 is None or w2 is None or w3 is None:
        return None
    if w0 & 0x9F00001F != _A64_ADRP_X16 or w3 != _A64_BR_X17:
        return None
    if w1 & 0xFFC003FF != _A64_LDR_X17_X16 or w2 & 0xFFC003FF != _A64_ADD_X16_X16:
        return None
    offset = ((w1 >> 10) & 0xFFF) * 8
    if (w2 >> 10) & 0xFFF != offset:
        return None
    pages = (((w0 >> 5) & 0x7FFFF) << 2) | ((w0 >> 29) & 0x3)
    if pages & (1 << 20):
        pages -= 1 << 21
    page = (addr & ~0xFFF) + (pages << 12)
    return PltEntry(addr, (page + offset) & 0xFFFFFFFFFFFFFFFF, _AARCH64_ENTRY)


def decode_plt(
    code: bytes, base: int, machine: PltMachine, slots: Set[int]
) -> tuple[PltEntry, ...]:
    """Every entry of one PLT, decoded one after another — a pure function of the bytes.

    ``code`` holds the table's bytes from its header (PLT0) on, at link-time address ``base``;
    ``slots`` the GOT slots this binary binds lazily (its ``JUMP_SLOT`` and ``IRELATIVE`` slots).
    The entries start right after the header and end at the first bytes that are no entry, or
    whose slot is not in ``slots`` or was already taken by an earlier entry. Nothing past that point
    is an entry, however many slots are left: what follows a PLT is ordinary code, and a function
    there is never a stub."""
    header, decode = (
        (_ARM_PLT_HEADER, decode_arm_plt_entry)
        if machine == "arm"
        else (_AARCH64_PLT_HEADER, decode_aarch64_plt_entry)
    )
    out: list[PltEntry] = []
    taken: set[int] = set()
    off = header
    while True:
        entry = decode(code, off, base + off)
        if entry is None or entry.got_slot not in slots or entry.got_slot in taken:
            break
        taken.add(entry.got_slot)
        out.append(entry)
        off += entry.size
    return tuple(out)


def ifunc_slot_names(initial: Mapping[int, int], ifuncs: Mapping[int, Set[str]]) -> dict[int, str]:
    """The ``IRELATIVE`` slots that get a name: slot -> the one ``STT_GNU_IFUNC`` symbol name whose
    value equals the slot's resolver address (``initial``: the relocation's addend, or the word in
    place for REL). A resolver address no such symbol has, or that several differently named ones
    share, gives no name: which function the loader selects there is then not read from the ELF."""
    out: dict[int, str] = {}
    for slot, value in initial.items():
        names = ifuncs.get(value, frozenset())
        if len(names) == 1:
            out[slot] = next(iter(names))
    return out


def _load_reader(elf: ELFFile, fh: BinaryIO) -> Callable[[int, int], bytes]:
    """``read(vaddr, n)``: up to ``n`` file-backed bytes of the PT_LOAD segment holding ``vaddr``
    (fewer at the segment's end, none outside every segment)."""
    loads = [
        (s["p_vaddr"], s["p_filesz"], s["p_offset"])
        for s in elf.iter_segments()
        if s["p_type"] == "PT_LOAD"
    ]

    def read(vaddr: int, n: int) -> bytes:
        for start, size, offset in loads:
            if start <= vaddr < start + size:
                fh.seek(offset + vaddr - start)
                return fh.read(min(n, start + size - vaddr))
        return b""

    return read


def _arm_family_resolution(elf: ELFFile, fh: BinaryIO) -> StubResolution | None:
    """The decoded PLT of a 32-bit ARM or AArch64 ELF (see the module docstring). None when there
    is no dynamic segment, or for a big-endian 32-bit ARM ELF, whose instruction byte order (BE8 or
    BE32) is not read here."""
    machine: PltMachine = "aarch64" if elf.header.e_machine == "EM_AARCH64" else "arm"
    if machine == "arm" and not elf.little_endian:
        return None
    dyn = next((s for s in elf.iter_segments() if isinstance(s, DynamicSegment)), None)
    if dyn is None:
        return None
    jump_type, irel_type = (
        (_R_ARM_JUMP_SLOT, _R_ARM_IRELATIVE)
        if machine == "arm"
        else (_R_AARCH64_JUMP_SLOT, _R_AARCH64_IRELATIVE)
    )
    ptr = 8 if elf.elfclass == 64 else 4
    order: Literal["little", "big"] = "little" if elf.little_endian else "big"
    read = _load_reader(elf, fh)

    def word(vaddr: int) -> int | None:
        raw = read(vaddr, ptr)
        return int.from_bytes(raw, order) if len(raw) == ptr else None

    jump: dict[int, str | None] = {}  # JUMP_SLOT slot -> its symbol's name (None: unnamed)
    initial: dict[int, int] = {}  # IRELATIVE slot -> its resolver address
    tables: dict[str, Any] = dict(dyn.get_relocation_tables())
    for kind, table in tables.items():
        if kind == "RELR":
            continue  # relative relocations only: no slot is bound through them
        rela = table.is_RELA()
        for rel in table.iter_relocations():
            rtype, slot = rel["r_info_type"], rel["r_offset"]
            if rtype == jump_type:
                sym = dyn.get_symbol(rel["r_info_sym"]) if rel["r_info_sym"] else None
                jump[slot] = sym.name if sym is not None and sym.name else None
            elif rtype == irel_type:
                value = rel["r_addend"] if rela else word(slot)
                if value is not None:
                    initial[slot] = value
    ifuncs: dict[int, set[str]] = {}
    for sym in dyn.iter_symbols():
        if sym["st_info"]["type"] in _IFUNC_TYPES and sym["st_shndx"] != "SHN_UNDEF" and sym.name:
            ifuncs.setdefault(sym["st_value"], set()).add(sym.name)
    irel_names = ifunc_slot_names(initial, ifuncs)
    # PLT0: where the lazily bound slots point before the loader binds them.
    firsts = Counter(v for v in (word(s) for s in jump) if v)
    if not firsts:
        # No lazily bound import (complete: none to name), or slots whose table cannot be found.
        return StubResolution(names={}, regions=(), complete=not jump and not initial)
    plt0 = firsts.most_common(1)[0][0]
    header = _ARM_PLT_HEADER if machine == "arm" else _AARCH64_PLT_HEADER
    entry_max = _ARM_ENTRY_MAX if machine == "arm" else _AARCH64_ENTRY
    code = read(plt0, header + entry_max * (len(jump) + len(initial)))
    entries = decode_plt(code, plt0, machine, set(jump) | set(initial))
    shift = ghidra_load_shift_of(elf)
    names: dict[int, str] = {}
    unnamed = 0
    for e in entries:
        name = jump[e.got_slot] if e.got_slot in jump else irel_names.get(e.got_slot)
        if not name:
            unnamed += 1
            continue
        names[e.addr + shift] = name
        if e.thumb_prefix:
            names[e.addr + 4 + shift] = name
    reached = {e.got_slot for e in entries}
    complete = set(jump) <= reached and unnamed == 0
    named_regions: tuple[tuple[str, int, int], ...] = ()
    if entries:
        end = entries[-1].addr + entries[-1].size
        named_regions = ((".plt", plt0 + shift, end + shift),)
    return StubResolution(
        names=names,
        regions=tuple((lo, hi) for _n, lo, hi in named_regions),
        complete=complete,
        named_regions=named_regions,
    )


def resolve_stubs(elf_path: Path | str) -> StubResolution | None:
    """Every resolvable stub's import name + the stub regions, for one MIPS, 32-bit ARM or
    AArch64 ELF.

    Addresses are the decompiler's (``ghidra_load_shift_of`` applied), because every consumer
    compares them with the decompiler's: the extractor's stub lookup, the callee relabelling, the
    stored stub regions and the consistency check of the table the extractor echoes. Shifting here,
    once, keeps them all on one number; a shift applied only on the way into the extractor would
    make the ingest-time recomputation disagree with it on every rebased binary.

    None when the file is not a readable ELF of those machines with dynamic linking information (a
    MIPS ELF needs its ``.dynsym`` section; an ARM or AArch64 one its dynamic segment, and a 32-bit
    ARM one must be little-endian) — an honest "cannot tell", never an empty answer read as "no
    stubs". A best-effort read on MIPS: a malformed section makes that path contribute nothing
    rather than raising."""
    try:
        with open(elf_path, "rb") as fh:
            elf = ELFFile(fh)
            if elf.header.e_machine in ("EM_ARM", "EM_AARCH64"):
                return _arm_family_resolution(elf, fh)
            if elf.header.e_machine != "EM_MIPS":
                return None
            dynsym = elf.get_section_by_name(".dynsym")
            if dynsym is None:
                return None
            tags = _dynamic_tags(elf)
            slot_names = _merge_slot_names(
                _rel_plt_slot_names(elf, dynsym),
                _global_got_slot_names(elf, dynsym, tags),
            )
            shift = ghidra_load_shift_of(elf)
            names = {a + shift: n for a, n in _plt_stub_names(elf, slot_names).items()}
            named_regions = tuple(
                (sec, lo + shift, hi + shift) for sec, lo, hi in _named_stub_regions(elf)
            )
            complete = not _has_nonempty_mips_stubs(elf) and len(names) == _plt_entry_count(elf)
            return StubResolution(
                names=names,
                regions=tuple((lo, hi) for _n, lo, hi in named_regions),
                complete=complete,
                named_regions=named_regions,
            )
    except (OSError, ELFError, ValueError, KeyError, AttributeError) as exc:
        logger.debug("stub resolution skipped for %s: %s", elf_path, exc)
        return None


def _stub_addr_of(callee: str) -> int | None:
    """The address a ``FUN_<hex>`` callee names, or None when the callee is a real symbol.

    The decompiler names an unresolved stub call after the stub's address, so the address is
    recoverable from the name. A callee that is already a symbol (``system``, ``memcpy``) has no
    address to parse and is left alone."""
    if not callee.startswith("FUN_"):
        return None
    try:
        return int(callee[4:], 16)
    except ValueError:
        return None


@dataclass(frozen=True)
class RelabelResult:
    """A function's callees after stub relabelling, and the stub calls that stayed unresolved."""

    callees: list[str]
    unresolved_stub_addrs: list[str]


def relabel_callees(callees: list[str], resolution: StubResolution) -> RelabelResult:
    """Rewrite ``FUN_<stub-addr>`` callees to their import names, and collect the ones that did not.

    A callee whose address resolves becomes the import name in place — so the existing sink lexicon
    sees ``system`` and the caller becomes a candidate, with no downstream change. A callee in a
    stub region that did NOT resolve is returned as an unclassified external call: the hole stays
    visible rather than being read as an ordinary internal call. Everything else passes through."""
    out: list[str] = []
    unresolved: list[str] = []
    for callee in callees:
        addr = _stub_addr_of(callee)
        if addr is None:
            out.append(callee)
            continue
        name = resolution.names.get(addr)
        if name is not None:
            out.append(name)
        elif resolution.in_stub_region(addr):
            out.append(callee)  # keep it in the graph, but flag it as an unclassified external call
            unresolved.append(f"0x{addr:x}")
        else:
            out.append(callee)  # an ordinary internal function the map simply did not resolve
    return RelabelResult(callees=out, unresolved_stub_addrs=unresolved)


# The marker the extractor echoes when it was handed no stub table at all: "not injected", a value
# no content hash can take, so it is never confused with a table (or with a table that failed to
# load — the extractor throws on that instead of writing any output).
STUB_MARKER_NONE = "none"


def _stub_table_entries(names: Mapping[int, str]) -> list[tuple[int, str]]:
    """The entries a stub table carries, normalised: sorted by address, and only names that cannot
    break the one-entry-per-line, tab-separated form."""
    return sorted(
        (addr, name)
        for addr, name in names.items()
        if addr >= 0 and name and "\t" not in name and "\n" not in name and "\r" not in name
    )


def serialize_stub_table(names: Mapping[int, str]) -> str:
    """The stub table handed to the extractor (TMAP_STUB_NAMES): one ``<hex addr>\\t<name>`` line
    per resolved stub, sorted by address. The address is written the way ``_stub_addr_of`` reads a
    ``FUN_`` callee back (lowercase hex, int(hex, 16)), so both sides name a stub by one number."""
    return "".join(f"{addr:x}\t{name}\n" for addr, name in _stub_table_entries(names))


def stub_table_marker(names: Mapping[int, str] | None) -> str:
    """The marker the extractor must echo for this table: the sha256 of its normalised content
    (the extractor re-normalises the table it actually loaded and hashes that), or
    ``STUB_MARKER_NONE`` when no table is handed in. A count is never a marker — two different
    tables of the same size would pass."""
    if names is None:
        return STUB_MARKER_NONE
    return hashlib.sha256(serialize_stub_table(names).encode("utf-8")).hexdigest()
