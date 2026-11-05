# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""What an ELF says fills one pointer slot of its image, read from the ELF alone.

The static dispatch-table detector reads a run of ``{string pointer, function pointer}`` records out
of the decompiler's view of memory. The decompiler resolves each handler pointer to a function, but
it cannot say what the ELF meant to put in the slot: a ``.data`` slot filled at load time by a
relocation against a vtable or typeinfo symbol plus an offset can land on a neighbouring function,
and a run of GOT entries reads as alternating strings and functions. Both are tables only by
accident. This module reads, for a slot, the dynamic relocation that fills it (its symbol's name,
ELF type and definedness, and the addend) and whether the slot lies in the GOT, so the ingest can
tell a handler the ELF put there from one that merely lands there.

Addresses are the decompiler's (``ghidra_load_shift_of`` applied), so a slot address taken from
the extractor's output is looked up as it is.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from elftools.common.exceptions import ELFError
from elftools.elf.dynamic import DynamicSegment
from elftools.elf.elffile import ELFFile

from treasure_map.lib.analyze.stub_resolve import ghidra_load_shift_of

logger = logging.getLogger(__name__)

_MIPS_GOT_TAGS = ("DT_PLTGOT", "DT_MIPS_LOCAL_GOTNO", "DT_MIPS_SYMTABNO", "DT_MIPS_GOTSYM")


@dataclass(frozen=True)
class SlotSymbol:
    """The symbol a dynamic relocation names for a slot, as the dynamic symbol table types it."""

    name: str
    st_type: str  # STT_FUNC / STT_OBJECT / STT_NOTYPE / …
    defined: bool  # False for an import (SHN_UNDEF)
    addend: int  # explicit (RELA) or the word in place (REL)


@dataclass(frozen=True)
class ElfSlots:
    """Slot facts of one ELF: the symbol filling each relocated slot (None for a relocation that
    names no symbol, such as a RELATIVE one) and the GOT's address ranges."""

    symbols: dict[int, SlotSymbol | None] = field(default_factory=dict)
    got: tuple[tuple[int, int], ...] = ()

    def in_got(self, addr: int) -> bool:
        return any(lo <= addr < hi for lo, hi in self.got)

    def relocated(self, addr: int) -> bool:
        return addr in self.symbols

    def symbol(self, addr: int) -> SlotSymbol | None:
        return self.symbols.get(addr)


def _word_reader(elf: ELFFile, fh: Any, size: int) -> Any:
    loads = [s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]
    order = "little" if elf.little_endian else "big"

    def word_at(vaddr: int) -> int:
        for seg in loads:
            if seg["p_vaddr"] <= vaddr and vaddr + size <= seg["p_vaddr"] + seg["p_filesz"]:
                fh.seek(seg["p_offset"] + vaddr - seg["p_vaddr"])
                return int.from_bytes(fh.read(size), order)
        return 0

    return word_at


def _symbol(dyn: DynamicSegment, index: int, addend: int) -> SlotSymbol | None:
    sym = dyn.get_symbol(index)
    if sym is None or not sym.name:
        return None
    return SlotSymbol(
        name=sym.name,
        st_type=str(sym["st_info"]["type"]),
        defined=sym["st_shndx"] != "SHN_UNDEF",
        addend=addend,
    )


def _got_ranges(elf: ELFFile, tags: dict[str, int], ptr: int) -> list[tuple[int, int]]:
    """The GOT, from its sections when the ELF keeps section headers; on a MIPS ELF without them,
    from the dynamic tags (local entries, then one per global symbol)."""
    out: list[tuple[int, int]] = []
    for name in (".got", ".got.plt"):
        sec = elf.get_section_by_name(name)
        if sec is not None and sec["sh_size"]:
            out.append((sec["sh_addr"], sec["sh_addr"] + sec["sh_size"]))
    if not out and elf.header.e_machine == "EM_MIPS" and all(t in tags for t in _MIPS_GOT_TAGS):
        n = tags["DT_MIPS_LOCAL_GOTNO"] + tags["DT_MIPS_SYMTABNO"] - tags["DT_MIPS_GOTSYM"]
        if n > 0:
            out.append((tags["DT_PLTGOT"], tags["DT_PLTGOT"] + n * ptr))
    return out


def read_elf_slots(elf_path: Path | str) -> ElfSlots | None:
    """The slot facts of one ELF, or None when it cannot be read (an honest "cannot tell": the
    caller then has nothing to check a handler against, which is not the same as "checked")."""
    try:
        with open(elf_path, "rb") as fh:
            elf = ELFFile(fh)
            shift = ghidra_load_shift_of(elf)
            ptr = 8 if elf.elfclass == 64 else 4
            word_at = _word_reader(elf, fh, ptr)
            dyn = next((s for s in elf.iter_segments() if isinstance(s, DynamicSegment)), None)
            symbols: dict[int, SlotSymbol | None] = {}
            tags: dict[str, int] = {}
            if dyn is not None:
                tags = {t.entry.d_tag: t.entry.d_val for t in dyn.iter_tags()}
                for table in dyn.get_relocation_tables().values():
                    for rel in table.iter_relocations():
                        at = rel["r_offset"]
                        addend = rel["r_addend"] if rel.is_RELA() else word_at(at)
                        index = rel["r_info_sym"]
                        symbols[at + shift] = _symbol(dyn, index, addend) if index else None
            got = tuple((lo + shift, hi + shift) for lo, hi in _got_ranges(elf, tags, ptr))
            return ElfSlots(symbols=symbols, got=got)
    except (OSError, ELFError, ValueError, KeyError, AttributeError) as exc:
        logger.debug("slot facts unreadable for %s: %s", elf_path, exc)
        return None


# Why a dispatch-table record is refused (the handler is not one the ELF put in the slot), or kept
# without the check holding either way.
RECORD_IN_GOT = "record_in_got"
HANDLER_NOT_FUNCTION = "handler_not_function"
HANDLER_UNVERIFIED = "handler_unverified"


def handler_check(slots: ElfSlots, key_slot: int, handler_slot: int, handler: str) -> str | None:
    """None when the handler the decompiler resolved is the one the ELF fills the slot with (or the
    slot is a plain pointer no symbol names); else why not: ``RECORD_IN_GOT`` (a GOT entry is not a
    table record) or ``HANDLER_NOT_FUNCTION`` (the slot names a symbol plus an offset, a symbol
    other than the import the decompiler resolved, or a symbol that is not a function); or
    ``HANDLER_UNVERIFIED`` when the symbol is untyped — kept, since dropping a real table loses an
    edge, but marked.

    Only the ELF's own type decides: what the decompiler finds at the pointer is the question here,
    not the answer — a vtable symbol plus 8 lands exactly on a neighbouring function's slot."""
    if slots.in_got(key_slot) or slots.in_got(handler_slot):
        return RECORD_IN_GOT
    if not slots.relocated(handler_slot):
        return None
    sym = slots.symbol(handler_slot)
    if sym is None:
        return None  # a relocation naming no symbol (RELATIVE): the pointer is the image's own
    if sym.addend:
        return HANDLER_NOT_FUNCTION
    if not sym.defined and sym.name != handler:
        return HANDLER_NOT_FUNCTION
    if sym.st_type == "STT_FUNC":
        return None
    if sym.st_type == "STT_NOTYPE":
        return HANDLER_UNVERIFIED
    return HANDLER_NOT_FUNCTION
