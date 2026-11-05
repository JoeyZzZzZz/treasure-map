# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Just enough of a BinExport2 reader for tests: instruction addresses, basic blocks and each
function's flow graph with its edges. Reads the protobuf wire format directly (no protobuf library);
field numbers follow the binexport2.proto the BinExport extension ships."""

from __future__ import annotations

import gzip
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

# FlowGraph.Edge.Type; an edge with no type set is UNCONDITIONAL (the proto's default).
CONDITION_TRUE, CONDITION_FALSE, UNCONDITIONAL, SWITCH = 1, 2, 3, 4


def _varint(b: bytes, p: int) -> tuple[int, int]:
    r = s = 0
    while True:
        c = b[p]
        p += 1
        r |= (c & 0x7F) << s
        if c < 0x80:
            return r, p
        s += 7


def _fields(b: bytes) -> Iterator[tuple[int, int | bytes]]:
    p = 0
    while p < len(b):
        key, p = _varint(b, p)
        f, wt = key >> 3, key & 7
        v: int | bytes
        if wt == 0:
            v, p = _varint(b, p)
        elif wt == 1:
            v, p = int.from_bytes(b[p : p + 8], "little"), p + 8
        elif wt == 2:
            n, p = _varint(b, p)
            v, p = b[p : p + n], p + n
        elif wt == 5:
            v, p = int.from_bytes(b[p : p + 4], "little"), p + 4
        else:
            raise ValueError(f"wire type {wt}")
        yield f, v


def _packed(v: int | bytes) -> list[int]:
    if isinstance(v, int):
        return [v]
    out, p = [], 0
    while p < len(v):
        x, p = _varint(v, p)
        out.append(x)
    return out


@dataclass
class Edge:
    source: int  # basic block index
    target: int | None  # basic block index; None when the export wrote no target
    type: int


@dataclass
class FlowGraph:
    blocks: list[int] = field(default_factory=list)
    entry: int = 0
    edges: list[Edge] = field(default_factory=list)


@dataclass
class BinExport2:
    insn_addr: list[int]
    blocks: list[list[tuple[int, int]]]  # per block: (begin, end) instruction index ranges
    flow_graphs: list[FlowGraph]

    def block_addr(self, index: int) -> int:
        return self.insn_addr[self.blocks[index][0][0]]

    def graph_at(self, entry_addr: int) -> FlowGraph:
        (fg,) = [g for g in self.flow_graphs if self.block_addr(g.entry) == entry_addr]
        return fg


def load(path: Path) -> BinExport2:
    data = path.read_bytes()
    if data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    addrs: list[int | None] = []
    sizes: list[int] = []
    blocks: list[list[tuple[int, int]]] = []
    graphs: list[FlowGraph] = []
    for f, v in _fields(data):
        if f == 5 and isinstance(v, bytes):  # instruction: address (1), raw bytes (5)
            fields = dict(_fields(v))
            addr = fields.get(1)
            addrs.append(addr if isinstance(addr, int) else None)
            raw = fields.get(5, b"")
            sizes.append(len(raw) if isinstance(raw, bytes) else 0)
        elif f == 6 and isinstance(v, bytes):  # basic block: instruction index ranges (1)
            ranges = []
            for ff, vv in _fields(v):
                if ff == 1 and isinstance(vv, bytes):
                    r = dict(_fields(vv))
                    begin = int(r.get(1, 0))
                    ranges.append((begin, int(r.get(2, begin + 1))))
            blocks.append(ranges)
        elif f == 7 and isinstance(v, bytes):  # flow graph: blocks (1), edges (2), entry (3)
            fg = FlowGraph()
            for ff, vv in _fields(v):
                if ff == 1:
                    fg.blocks.extend(_packed(vv))
                elif ff == 3 and isinstance(vv, int):
                    fg.entry = vv
                elif ff == 2 and isinstance(vv, bytes):
                    e = dict(_fields(vv))
                    target = e.get(2)
                    fg.edges.append(
                        Edge(
                            source=int(e.get(1, 0)),
                            target=target if isinstance(target, int) else None,
                            type=int(e.get(3, UNCONDITIONAL)),
                        )
                    )
            graphs.append(fg)
    # an instruction with no address follows the one before it
    insn_addr: list[int] = []
    prev = size = 0
    for a, s in zip(addrs, sizes, strict=True):
        prev = a if a is not None else prev + size
        insn_addr.append(prev)
        size = s
    return BinExport2(insn_addr, blocks, graphs)
