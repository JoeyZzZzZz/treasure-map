# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The flow-graph edges the scan's BinExport builder writes (lib/diff/ghidra/
FallbackBinExport2Builder.java), on a hand-assembled MIPS program run through real Ghidra.

Two defects made BinDiff fall back to vertex 0 and misalign whole MIPS functions:

* a block ending in a delay slot carries its flow on the branch BEFORE the slot, and only flow
  from the block's last instruction was written — so such a block had no out-edge at all;
* an edge leaving the function's graph (a call, a tail branch into another function) has no
  target block in it, and was written without one — which reads as an edge to block 0.

The program: ``f1`` branches inside itself and then conditionally out to ``f2`` (a conditional
tail branch); ``f3`` jumps unconditionally to ``f2``. Every MIPS branch here has a delay slot.
Skipped without Ghidra or its BinExport extension (run with analyzeHeadless on PATH).
"""

from __future__ import annotations

import shutil
import struct
from pathlib import Path

import pytest

from tests.integration import binexport2_reader as be2
from treasure_map.lib.analyze.ghidra_runner import GhidraRunner
from treasure_map.lib.config.config import GhidraConfig, GhidraLocalConfig
from treasure_map.lib.export_stamp import scan_extension

_HEADLESS = shutil.which("analyzeHeadless")
_HOME = Path(_HEADLESS).resolve().parents[1] if _HEADLESS else None
_EXT = scan_extension(_HOME) if _HOME is not None else None
no_export = _EXT is None or _EXT.ext_dir is None

_LOAD = 0x00400000
_TEXT_OFF = 0x100
_T = _LOAD + _TEXT_OFF
F1, F3, F2 = _T, _T + 0x28, _T + 0x40
ZERO, V0, A0, A1, RA = 0, 2, 4, 5, 31
NOP = 0


def _beq(rs: int, rt: int, pc: int, target: int) -> int:
    return (4 << 26) | (rs << 21) | (rt << 16) | (((target - pc - 4) >> 2) & 0xFFFF)


def _bne(rs: int, rt: int, pc: int, target: int) -> int:
    return (5 << 26) | (rs << 21) | (rt << 16) | (((target - pc - 4) >> 2) & 0xFFFF)


def _addiu(rt: int, rs: int, imm: int) -> int:
    return (9 << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)


def _j(target: int) -> int:
    return (2 << 26) | ((target >> 2) & 0x3FFFFFF)


_JR_RA = (RA << 21) | 8

_CODE = [
    # f1
    _beq(A0, ZERO, F1 + 0x00, F1 + 0x14),  # 00: in-graph conditional branch ...
    NOP,  # 04: ... its delay slot ends block B0
    _addiu(V0, ZERO, 1),  # 08: B1
    _JR_RA,  # 0c
    NOP,  # 10
    _bne(A1, ZERO, F1 + 0x14, F2),  # 14: B2 — conditional branch OUT to f2 ...
    NOP,  # 18: ... delay slot
    _addiu(V0, ZERO, 2),  # 1c: B3 — its fall-through
    _JR_RA,  # 20
    NOP,  # 24
    # f3
    _addiu(V0, ZERO, 4),  # 28
    _j(F2),  # 2c: unconditional jump out to f2
    NOP,  # 30: delay slot
    NOP,  # 34
    NOP,  # 38
    NOP,  # 3c
    # f2
    _addiu(V0, ZERO, 3),  # 40
    _JR_RA,  # 44
    NOP,  # 48
]


def _mips_program() -> bytes:
    """A 32-bit little-endian MIPS ET_EXEC: one PT_LOAD over the file, .text at _TEXT_OFF, and a
    symbol table naming the three functions."""
    text = b"".join(struct.pack("<I", w) for w in _CODE)
    strtab = b"\0f1\0f3\0f2\0"
    sym = struct.pack("<IIIBBH", 0, 0, 0, 0, 0, 0)
    for name_off, addr in ((1, F1), (4, F3), (7, F2)):
        sym += struct.pack("<IIIBBH", name_off, addr, 0, 0x12, 0, 1)  # GLOBAL FUNC in .text
    shstr = b"\0.text\0.symtab\0.strtab\0.shstrtab\0"
    body = bytearray(_TEXT_OFF) + text
    sym_off = len(body)
    body += sym
    str_off = len(body)
    body += strtab
    shstr_off = len(body)
    body += shstr
    while len(body) % 4:
        body += b"\0"
    shoff = len(body)

    def sh(name: int, typ: int, flags: int, addr: int, off: int, size: int, **kw: int) -> bytes:
        return struct.pack(
            "<IIIIIIIIII",
            name, typ, flags, addr, off, size,
            kw.get("link", 0), kw.get("info", 0), kw.get("align", 4), kw.get("entsize", 0),
        )  # fmt: skip

    shdrs = sh(0, 0, 0, 0, 0, 0, align=0)
    shdrs += sh(1, 1, 0x6, _T, _TEXT_OFF, len(text))  # .text
    shdrs += sh(7, 2, 0, 0, sym_off, len(sym), link=3, info=1, entsize=16)  # .symtab
    shdrs += sh(15, 3, 0, 0, str_off, len(strtab), align=1)  # .strtab
    shdrs += sh(23, 3, 0, 0, shstr_off, len(shstr), align=1)  # .shstrtab
    filesz = len(body)
    ehdr = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\0" * 8
    ehdr += struct.pack("<HHIIIIIHHHHHH", 2, 8, 1, F1, 52, shoff, 0, 52, 32, 1, 40, 5, 4)
    phdr = struct.pack("<IIIIIIII", 1, 0, _LOAD, _LOAD, filesz, filesz, 5, 0x1000)
    out = bytearray(body)
    out[: len(ehdr) + len(phdr)] = ehdr + phdr
    return bytes(out) + shdrs


@pytest.fixture(scope="module")
def export(tmp_path_factory: pytest.TempPathFactory) -> be2.BinExport2:
    assert _HOME is not None
    work = tmp_path_factory.mktemp("be2")
    binary = work / "flow"
    binary.write_bytes(_mips_program())
    runner = GhidraRunner(GhidraConfig(local=GhidraLocalConfig(home=_HOME)), extension=_EXT)
    arch = "MIPS:LE:32:default"
    res = runner.run_ghidra(binary, work / "out", 300, arch, "f10wf10w", retry=False)
    assert res.success and res.export_file is not None, (res.reason, res.export_status)
    return be2.load(res.export_file)


def _edges(b: be2.BinExport2, entry: int) -> set[tuple[int, int | None, int]]:
    fg = b.graph_at(entry)
    return {
        (b.block_addr(e.source), None if e.target is None else b.block_addr(e.target), e.type)
        for e in fg.edges
    }


@pytest.mark.skipif(no_export, reason="no analyzeHeadless on PATH, or no BinExport extension")
def test_a_branch_whose_delay_slot_ends_the_block_writes_both_edges(export: be2.BinExport2) -> None:
    """★ B0 ends in the delay slot of an in-graph conditional branch: both edges are written, the
    taken one CONDITION_TRUE to B2, the fall-through CONDITION_FALSE to B1.

    MUTATION (verified RED): take only the block's last instruction as its flow instruction again
    -> B0 has no out-edge -> RED."""
    edges = _edges(export, F1)
    assert (F1, F1 + 0x14, be2.CONDITION_TRUE) in edges
    assert (F1, F1 + 0x08, be2.CONDITION_FALSE) in edges


@pytest.mark.skipif(no_export, reason="no analyzeHeadless on PATH, or no BinExport extension")
def test_an_edge_leaving_the_function_is_not_written(export: be2.BinExport2) -> None:
    """★ Every written edge has a target block in its own graph: the conditional branch from f1
    and the jump from f3 into f2 are not edges of their graphs (written without a target they read
    as edges to block 0).

    MUTATION (verified RED): write edges whose target is outside the graph again -> an edge with no
    target -> RED."""
    for fg in export.flow_graphs:
        for e in fg.edges:
            assert e.target is not None and e.target in fg.blocks, export.block_addr(fg.entry)
    assert not [t for _s, t, _ty in _edges(export, F3) if t != F3]  # f3: no edge out to f2


@pytest.mark.skipif(no_export, reason="no analyzeHeadless on PATH, or no BinExport extension")
def test_the_fall_through_of_a_branch_out_of_the_function_stays_its_false_edge(
    export: be2.BinExport2,
) -> None:
    """B2's conditional branch leaves f1 (not written); its fall-through to B3 is still that
    branch's false edge, as it was before the branch's own edge was dropped.

    MUTATION (verified RED): skip the branch without carrying its flow on -> the fall-through reads
    UNCONDITIONAL -> RED."""
    edges = _edges(export, F1)
    assert (F1 + 0x14, F1 + 0x1C, be2.CONDITION_FALSE) in edges
    assert not [e for e in edges if e[0] == F1 + 0x14 and e[1] != F1 + 0x1C]
