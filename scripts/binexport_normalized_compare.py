#!/usr/bin/env python3
# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Compare BinExport2 files by their normalized content.

Two exports of the same program are not byte-identical: the export records the wall-clock time it
was written, and three repeated lists come out in an order that varies between Ghidra sessions. A
raw sha256 therefore says "different" for two exports that hold the same program. This prints, per
file, a sha256 of the export with those differences taken out:

  * ``meta_information.timestamp`` (BinExport2 field 1, sub-field 4) removed;
  * ``call_graph.edge`` (field 8, sub-field 2) sorted — the vertices keep their order;
  * ``string_reference`` (field 11) and ``data_reference`` (field 15) sorted.

Everything else is compared byte for byte, in order. Also printed: a sha256 over only the fields an
operand-markup change can touch (expression 2, operand 3, instruction 5, string_table 9, comment
17), to tell a markup-only difference apart.

usage: binexport_normalized_compare.py FILE [FILE...]
       -> one line per file: normalized_sha  markup_sha  path
Exits 1 when more than one file is given and their normalized shas differ.

Standard library only (no protobuf): the wire format is walked directly.
"""

from __future__ import annotations

import collections
import hashlib
import sys
from collections.abc import Iterator
from pathlib import Path

_ORDER_FREE = frozenset({11, 15})  # string_reference, data_reference
_MARKUP = frozenset({2, 3, 5, 9, 17})
_META, _CALL_GRAPH = 1, 8
_TIMESTAMP, _EDGE = 4, 2


def _varint(b: bytes, p: int) -> tuple[int, int]:
    r = s = 0
    while True:
        c = b[p]
        p += 1
        r |= (c & 0x7F) << s
        s += 7
        if c < 0x80:
            return r, p


def _enc_varint(v: int) -> bytes:
    out = bytearray()
    while True:
        c = v & 0x7F
        v >>= 7
        if v:
            out.append(c | 0x80)
        else:
            out.append(c)
            return bytes(out)


def fields(
    b: bytes, p: int = 0, end: int | None = None
) -> Iterator[tuple[int, int, int, int, int]]:
    """Yield (field, wire type, tag start, payload start, field end) over a message's bytes. The
    payload start is where a length-delimited field's bytes begin (after its length)."""
    end = len(b) if end is None else end
    while p < end:
        tag_start = p
        key, p = _varint(b, p)
        field, wt = key >> 3, key & 7
        if wt == 0:
            _v, p = _varint(b, p)
            payload = p
        elif wt == 1:
            payload, p = p, p + 8
        elif wt == 2:
            n, p = _varint(b, p)
            payload, p = p, p + n
        elif wt == 5:
            payload, p = p, p + 4
        else:
            raise ValueError(f"unsupported wire type {wt} at offset {tag_start}")
        yield field, wt, tag_start, payload, p


def _rewrap(b: bytes, tag_start: int, payload: int, body: bytes) -> bytes:
    """A length-delimited field with a new body: its own tag bytes, then the new length."""
    tag_end = tag_start
    while b[tag_end] & 0x80:
        tag_end += 1
    return b[tag_start : tag_end + 1] + _enc_varint(len(body)) + body


def normalized(b: bytes) -> tuple[str, str]:
    """(normalized sha256, markup sha256) of one BinExport2's bytes."""
    groups: dict[int, list[bytes]] = collections.defaultdict(list)
    for field, wt, tag_start, payload, end in fields(b):
        raw = b[tag_start:end]
        if field == _META and wt == 2:
            body = b"".join(
                b[t:e]
                for f2, w2, t, _p, e in fields(b, payload, end)
                if not (f2 == _TIMESTAMP and w2 == 0)
            )
            raw = _rewrap(b, tag_start, payload, body)
        elif field == _CALL_GRAPH and wt == 2:
            kept: list[bytes] = []
            edges: list[bytes] = []
            for f2, _w2, t, _p, e in fields(b, payload, end):
                (edges if f2 == _EDGE else kept).append(b[t:e])
            raw = _rewrap(b, tag_start, payload, b"".join(kept + sorted(edges)))
        groups[field].append(raw)
    full = hashlib.sha256()
    markup = hashlib.sha256()
    for field in sorted(groups):
        items = sorted(groups[field]) if field in _ORDER_FREE else groups[field]
        for item in items:
            full.update(item)
            if field in _MARKUP:
                markup.update(item)
    return full.hexdigest(), markup.hexdigest()


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    seen: set[str] = set()
    for arg in argv:
        full, markup = normalized(Path(arg).read_bytes())
        seen.add(full)
        print(full[:16], markup[:16], arg)
    return 1 if len(seen) > 1 else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
