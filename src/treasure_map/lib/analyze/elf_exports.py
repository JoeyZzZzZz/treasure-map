# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The dynamic FUNCTION exports of one ELF, read from the DYNAMIC segment.

Which functions a binary EXPORTS is an entry-point fact: an exported function can be entered from
outside the binary, so its callers are not all visible in this binary's call graph. The decompiler
has no answer to this one — the "global" flag it offers is a property of the symbol's NAMESPACE,
not an ELF export — so the answer is read from the ELF itself, the same way the stub resolver reads
relocations rather than asking the decompiler.

★ The DYNAMIC SEGMENT, not the ``.dynsym`` SECTION. Section headers are optional at run time and
real firmware commonly ships shared objects without them, so ``get_section_by_name('.dynsym')``
answers None while the dynamic segment still carries every symbol. The segment is what the loader
itself follows, so it survives stripping. Where both are readable the two agree exactly, which is
why reading the weaker one costs nothing.

★ Matched by NAME, never by entry address. An ARM Thumb function carries the Thumb bit in bit 0 of
its ``st_value``, so its symbol address is one past the even address a decompiler reports, and an
address join would silently drop every Thumb export. The name is what both sides recover from the
same table, so it joins cleanly.

★ What the answer MEANS, stated because it is weaker than the word "exported": the defined STT_FUNC
dynamic symbols are an UPPER BOUND. Visibility (STV_HIDDEN) and binding (STB_LOCAL) are not
excluded here, so a symbol no other object could actually bind to may still be listed. The
direction is deliberate — over-listing keeps a possible entry point visible, under-listing would
quietly retire one — and it is why this is a lead rather than a proof.

``None`` means the exports could not be DETERMINED (unreadable file, not an ELF, no dynamic
segment); an empty set means the file was read and exports no functions. A caller must not collapse
the two: "not shown to be exported" is not "proven not exported".
"""

from __future__ import annotations

import logging
from pathlib import Path

from elftools.common.exceptions import ELFError
from elftools.elf.dynamic import DynamicSegment
from elftools.elf.elffile import ELFFile

logger = logging.getLogger(__name__)


def dynamic_function_exports(elf_path: Path | str) -> frozenset[str] | None:
    """Names of every DEFINED function symbol in this ELF's dynamic symbol table, or None.

    None is the honest "cannot tell" (see the module docstring): an unreadable file, a non-ELF, or
    an ELF with no dynamic segment. A best-effort read — a malformed table yields None rather than
    raising, so one damaged binary never stops an ingest.
    """
    try:
        with open(elf_path, "rb") as fh:
            elf = ELFFile(fh)
            segment = next((s for s in elf.iter_segments() if isinstance(s, DynamicSegment)), None)
            if segment is None:
                return None
            names: set[str] = set()
            for sym in segment.iter_symbols():
                entry = sym.entry
                if entry["st_info"]["type"] != "STT_FUNC":
                    continue
                # DEFINED only. The dynamic table holds this binary's IMPORTS too, as undefined
                # STT_FUNC entries — a function it CALLS, which is the opposite of one it offers.
                # Counting those would mark every caller of libc as exporting most of libc.
                if entry["st_shndx"] == "SHN_UNDEF":
                    continue
                if sym.name:
                    names.add(str(sym.name))
            return frozenset(names)
    except (OSError, ELFError, ValueError, KeyError, AttributeError) as exc:
        logger.debug("dynamic exports unreadable for %s: %s", elf_path, exc)
        return None


# The ELF shape the decompiler's loader reads WITHOUT building external symbols: an ARM executable
# (ET_EXEC) with no section headers whose dynamic segment carries a DT_HASH and no DT_GNU_HASH.
# Measured over a whole corpus: every binary of that shape had its imports recorded at under 1%
# (most at none), while every other shape was at or above 100%. Its PLT stubs become ordinary
# local functions, so the call graph and the sinks are unaffected — only the import list is empty.
_UNLOADED_IMPORT_SHAPE = ("EM_ARM", "ET_EXEC")


def unrecorded_dynamic_imports(
    elf_path: Path | str, recorded: frozenset[str] | set[str]
) -> tuple[str, ...] | None:
    """The undefined FUNC / NOTYPE dynamic symbols of an ELF the decompiler's loader leaves without
    external symbols (see ``_UNLOADED_IMPORT_SHAPE``) that ``recorded`` does not already name,
    sorted; () for every other ELF; None when the file cannot be read.

    Only that shape: elsewhere the decompiler's import list is complete but may name an import
    another way than the dynamic symbol table does (demangled C++ names), and filling by name
    there would list the same import twice. FUNC and NOTYPE because that is what the decompiler
    records as imports everywhere else."""
    try:
        with open(elf_path, "rb") as fh:
            elf = ELFFile(fh)
            if (elf.header.e_machine, elf.header.e_type) != _UNLOADED_IMPORT_SHAPE:
                return ()
            if elf.num_sections() != 0:
                return ()
            segment = next((s for s in elf.iter_segments() if isinstance(s, DynamicSegment)), None)
            if segment is None:
                return ()
            tags = {t.entry.d_tag for t in segment.iter_tags()}
            if "DT_HASH" not in tags or "DT_GNU_HASH" in tags:
                return ()
            names = {
                sym.name
                for sym in segment.iter_symbols()
                if sym.name
                and sym["st_shndx"] == "SHN_UNDEF"
                and sym["st_info"]["type"] in ("STT_FUNC", "STT_NOTYPE")
            }
            return tuple(sorted(names - set(recorded)))
    except (OSError, ELFError, ValueError, KeyError, AttributeError) as exc:
        logger.debug("dynamic imports unreadable for %s: %s", elf_path, exc)
        return None
