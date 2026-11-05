# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""A minimal ELF writer for tests: just enough header, one PT_LOAD and the sections a reader under
test looks at. Every byte is synthetic; no toolchain is needed."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

EM_MIPS, EM_AARCH64, EM_ARM = 8, 183, 40
ET_EXEC, ET_DYN = 2, 3
SHT_PROGBITS, SHT_STRTAB, SHT_REL, SHT_DYNSYM = 1, 3, 9, 11
SHF_ALLOC, SHF_EXECINSTR = 0x2, 0x4
R_MIPS_JUMP_SLOT = 127


@dataclass
class Section:
    name: str
    sh_type: int
    addr: int = 0
    data: bytes = b""
    flags: int = SHF_ALLOC
    link: str | None = None  # name of the linked section
    info: int = 0
    entsize: int = 0
    size: int | None = None  # defaults to len(data)


@dataclass
class Elf:
    e_type: int = ET_DYN
    machine: int = EM_MIPS
    elfclass: int = 32
    load_vaddr: int = 0
    sections: list[Section] = field(default_factory=list)

    def build(self) -> bytes:
        """Little-endian ELF: header, one PT_LOAD, the section data, then the section headers."""
        is64 = self.elfclass == 64
        ehsize, phentsize, shentsize = (64, 56, 64) if is64 else (52, 32, 40)
        names = b"\0"
        name_off: dict[str, int] = {}
        for s in [*self.sections, Section(".shstrtab", SHT_STRTAB, flags=0)]:
            name_off[s.name] = len(names)
            names += s.name.encode() + b"\0"
        all_secs = [*self.sections, Section(".shstrtab", SHT_STRTAB, data=names, flags=0)]
        index = {s.name: i + 1 for i, s in enumerate(all_secs)}  # 0 is the null section
        body = b""
        offsets: list[int] = []
        base = ehsize + phentsize
        for s in all_secs:
            offsets.append(base + len(body))
            body += s.data
        shoff = base + len(body)
        out = bytearray()
        ident = b"\x7fELF" + bytes([2 if is64 else 1, 1, 1, 0]) + b"\0" * 8
        hdr_fmt = "<HHIQQQIHHHHHH" if is64 else "<HHIIIIIHHHHHH"
        out += ident + struct.pack(
            hdr_fmt,
            self.e_type,
            self.machine,
            1,
            self.load_vaddr,  # e_entry
            ehsize,  # e_phoff
            shoff,
            0,
            ehsize,
            phentsize,
            1,
            shentsize,
            len(all_secs) + 1,
            len(all_secs),  # e_shstrndx (the last one)
        )
        filesz = shoff
        if is64:
            out += struct.pack(
                "<IIQQQQQQ", 1, 5, 0, self.load_vaddr, self.load_vaddr, filesz, filesz, 0x1000
            )
        else:
            out += struct.pack(
                "<IIIIIIII", 1, 0, self.load_vaddr, self.load_vaddr, filesz, filesz, 5, 0x1000
            )
        out += body
        sh_fmt = "<IIQQQQIIQQ" if is64 else "<IIIIIIIIII"
        out += struct.pack(sh_fmt, *([0] * 10))
        for s, off in zip(all_secs, offsets, strict=True):
            size = len(s.data) if s.size is None else s.size
            link = index[s.link] if s.link else 0
            if is64:
                out += struct.pack(
                    sh_fmt,
                    name_off[s.name],
                    s.sh_type,
                    s.flags,
                    s.addr,
                    off,
                    size,
                    link,
                    s.info,
                    8,
                    s.entsize,
                )
            else:
                out += struct.pack(
                    sh_fmt,
                    name_off[s.name],
                    s.sh_type,
                    s.flags,
                    s.addr,
                    off,
                    size,
                    link,
                    s.info,
                    4,
                    s.entsize,
                )
        return bytes(out)


def mips_plt_binary(
    *,
    e_type: int = ET_DYN,
    load_vaddr: int = 0,
    plt_addr: int = 0x400,
    got_plt_addr: int = 0x800,
    stubs_addr: int = 0x600,
    import_name: str = "system",
) -> bytes:
    """A 32-bit MIPS ELF whose one ``.plt`` stub resolves, through ``.rel.plt``, to
    ``import_name``; plus a ``.MIPS.stubs`` region. Addresses are link-time (sh_addr)."""
    dynstr = b"\0" + import_name.encode() + b"\0"
    # Elf32_Sym: name, value, size, info, other, shndx — a null symbol, then the import.
    dynsym = struct.pack("<IIIBBH", 0, 0, 0, 0, 0, 0) + struct.pack("<IIIBBH", 1, 0, 0, 0x12, 0, 0)
    slot = got_plt_addr + 2 * 4  # stub 0 uses .got.plt slot 2
    rel = struct.pack("<II", slot, (1 << 8) | R_MIPS_JUMP_SLOT)
    secs = [
        Section(".dynstr", SHT_STRTAB, data=dynstr),
        Section(".dynsym", SHT_DYNSYM, data=dynsym, link=".dynstr", info=1, entsize=16),
        Section(".rel.plt", SHT_REL, data=rel, link=".dynsym", entsize=8),
        Section(".plt", SHT_PROGBITS, addr=plt_addr, data=b"\0" * 0x30, flags=6),
        Section(".MIPS.stubs", SHT_PROGBITS, addr=stubs_addr, data=b"\0" * 0x20, flags=6),
        Section(".got.plt", SHT_PROGBITS, addr=got_plt_addr, data=b"\0" * 12, flags=3),
    ]
    return Elf(e_type=e_type, machine=EM_MIPS, load_vaddr=load_vaddr, sections=secs).build()


DT = {
    "NULL": 0,
    "PLTGOT": 3,
    "HASH": 4,
    "STRTAB": 5,
    "SYMTAB": 6,
    "STRSZ": 10,
    "SYMENT": 11,
    "REL": 17,
    "RELSZ": 18,
    "RELENT": 19,
    "MIPS_LOCAL_GOTNO": 0x7000000A,
    "MIPS_SYMTABNO": 0x70000011,
    "MIPS_GOTSYM": 0x70000013,
    "GNU_HASH": 0x6FFFFEF5,
}
STT = {"NOTYPE": 0, "OBJECT": 1, "FUNC": 2}
R_ARM_ABS32 = 2
R_ARM_RELATIVE = 23


def dynamic_rel_binary(
    *,
    machine: int = EM_ARM,
    symbols: list[tuple[str, str, bool]],
    relocs: list[tuple[int, int, int, int]],
    mips_got: tuple[int, int, int, int] | None = None,
    e_type: int = ET_DYN,
    gnu_hash_tag: bool = False,
) -> bytes:
    """A 32-bit little-endian ET_DYN linked at 0 with NO section headers: one PT_LOAD over the
    whole file and a PT_DYNAMIC, so every fact is reachable only through the dynamic tags.

    ``symbols``: (name, STT type, defined); index 0 is the null symbol, these follow from 1.
    ``relocs``: (slot offset in the data area, symbol index or 0, relocation type, in-place word).
    ``mips_got``: (got offset in the data area, local entries, symbol count, first GOT symbol).
    Returns the image; the data area starts at ``DATA`` (a link-time address)."""
    ehsize, phentsize = 52, 32
    head = ehsize + 2 * phentsize
    dynstr = b"\0"
    name_at = []
    for name, _t, _d in symbols:
        name_at.append(len(dynstr))
        dynstr += name.encode() + b"\0"
    dynsym = struct.pack("<IIIBBH", 0, 0, 0, 0, 0, 0)
    for (_n, typ, defined), off in zip(symbols, name_at, strict=True):
        dynsym += struct.pack(
            "<IIIBBH", off, 0x100 if defined else 0, 0, (1 << 4) | STT[typ], 0, 1 if defined else 0
        )
    data = bytearray(0x100)
    rel = b""
    for slot, sym, rtype, word in relocs:
        data[slot : slot + 4] = struct.pack("<I", word)
        rel += struct.pack("<II", DATA + slot, (sym << 8) | rtype)
    nsym = len(symbols) + 1
    hashtab = struct.pack("<II", 1, nsym) + struct.pack("<I", 0) + b"\0" * (4 * nsym)
    o_dynstr = head
    o_dynsym = o_dynstr + len(dynstr)
    o_hash = o_dynsym + len(dynsym)
    o_rel = o_hash + len(hashtab)
    o_data = DATA
    assert o_rel + len(rel) <= o_data
    tags = [
        ("STRTAB", o_dynstr),
        ("STRSZ", len(dynstr)),
        ("SYMTAB", o_dynsym),
        ("SYMENT", 16),
        ("REL", o_rel),
        ("RELSZ", len(rel)),
        ("RELENT", 8),
        ("HASH", o_hash),
    ]
    if gnu_hash_tag:
        tags.append(("GNU_HASH", o_hash))  # only its presence matters to the reader under test
    if mips_got is not None:
        got_off, local, symtabno, gotsym = mips_got
        tags += [
            ("PLTGOT", DATA + got_off),
            ("MIPS_LOCAL_GOTNO", local),
            ("MIPS_SYMTABNO", symtabno),
            ("MIPS_GOTSYM", gotsym),
        ]
    dynamic = b"".join(struct.pack("<iI", DT[k], v) for k, v in tags) + struct.pack("<iI", 0, 0)
    o_dyn = o_data + len(data)
    total = o_dyn + len(dynamic)
    body = bytearray(total)
    body[o_dynstr : o_dynstr + len(dynstr)] = dynstr
    body[o_dynsym : o_dynsym + len(dynsym)] = dynsym
    body[o_hash : o_hash + len(hashtab)] = hashtab
    body[o_rel : o_rel + len(rel)] = rel
    body[o_data : o_data + len(data)] = data
    body[o_dyn : o_dyn + len(dynamic)] = dynamic
    ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\0" * 8
    hdr = ident + struct.pack(
        "<HHIIIIIHHHHHH", e_type, machine, 1, 0, ehsize, 0, 0, ehsize, phentsize, 2, 40, 0, 0
    )
    ph = struct.pack("<IIIIIIII", 1, 0, 0, 0, total, total, 6, 0x1000)
    ph += struct.pack("<IIIIIIII", 2, o_dyn, o_dyn, o_dyn, len(dynamic), len(dynamic), 6, 4)
    body[0 : len(hdr) + len(ph)] = hdr + ph
    return bytes(body)


DATA = 0x400  # where dynamic_rel_binary's data area starts (link-time; +0x10000 once loaded)


def extractor_image_fields(path: object) -> dict[str, str]:
    """The two image-base fields the extractor writes for this ELF, as the decompiler loads it:
    where it was linked (the lowest PT_LOAD) and that plus the load shift. What a stand-in for the
    extractor must echo for the ingest to accept its output. None for a file that is not a
    readable ELF (a stand-in binary that only carries the magic): no decompiler would load it, and
    an output without them is refused by the ingest."""
    from pathlib import Path

    from elftools.common.exceptions import ELFError
    from elftools.elf.elffile import ELFFile

    from treasure_map.lib.analyze.stub_resolve import ghidra_load_shift_of

    try:
        with Path(str(path)).open("rb") as fh:
            elf = ELFFile(fh)
            loads = [s["p_vaddr"] for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]
            if not loads:
                return {}
            linked = min(loads)
            loaded = linked + ghidra_load_shift_of(elf)
    except (OSError, ELFError, ValueError):
        return {}
    return {"image_base": f"0x{loaded:x}", "elf_original_image_base": f"0x{linked:x}"}
