# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Resolve a MIPS binary's lazy-binding stubs to their import names, from ELF structure alone.

When a program calls a libc function like ``system``, the compiler emits a call to a small stub in
``.plt`` (or ``.MIPS.stubs``) that jumps through the GOT. If the decompiler does not stitch that
stub back to the import — which happens routinely, depending on its configuration and how the
binary was linked — the caller is left calling ``FUN_004125b0`` instead of ``system``, and a real
command-execution sink drops out of every downstream reading. That is a false negative on a sink
that is objectively there.

This recovers the name WITHOUT the decompiler, from structures the ELF already carries, so the
answer does not depend on whether the decompiler happened to build a thunk. Two paths, tried in
order, both deterministic:

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

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from elftools.common.exceptions import ELFError
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
    it is an unclassified external call, surfaced rather than dropped)."""

    names: dict[int, str]
    regions: tuple[tuple[int, int], ...]

    def in_stub_region(self, addr: int) -> bool:
        return any(lo <= addr < hi for lo, hi in self.regions)


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


def _stub_regions(elf: ELFFile) -> tuple[tuple[int, int], ...]:
    regions: list[tuple[int, int]] = []
    for sec_name in (".plt", ".MIPS.stubs"):
        sec = elf.get_section_by_name(sec_name)
        if sec is not None and sec["sh_size"]:
            regions.append((sec["sh_addr"], sec["sh_addr"] + sec["sh_size"]))
    return tuple(regions)


def resolve_stubs(elf_path: Path | str) -> StubResolution | None:
    """Every resolvable stub's import name + the stub regions, for one MIPS ELF.

    None when the file is not a readable MIPS ELF with a dynamic symbol table — an honest "cannot
    tell", never an empty answer read as "no stubs". A best-effort read: a malformed section makes
    that path contribute nothing rather than raising."""
    try:
        with open(elf_path, "rb") as fh:
            elf = ELFFile(fh)
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
            return StubResolution(
                names=_plt_stub_names(elf, slot_names),
                regions=_stub_regions(elf),
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
