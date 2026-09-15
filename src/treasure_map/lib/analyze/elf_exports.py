# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The dynamic FUNCTION exports of one ELF, read from the DYNAMIC segment.

Which functions a binary EXPORTS is an entry-point fact: an exported function can be entered from
outside the binary, so its callers are not all visible in this binary's call graph. The decompiler
has no answer to this one — the "global" flag it offers is a property of the symbol's NAMESPACE,
not an ELF export — so the answer is read from the ELF itself, the same way the stub resolver reads
relocations rather than asking the decompiler.

★ The DYNAMIC SEGMENT, not the ``.dynsym`` SECTION. Section headers are optional at run time and
real firmware ships without them: of the shared objects sampled from one ARM firmware, 5 of 5
carried no section table at all, so ``get_section_by_name('.dynsym')`` answered None while the
dynamic segment still carried every symbol. The segment is what the loader itself follows, so it
survives stripping. Where both are readable the two agree exactly (measured on sampled MIPS
objects), which is why reading the weaker one costs nothing.

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
