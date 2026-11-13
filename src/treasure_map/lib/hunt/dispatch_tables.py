# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Static ``{string key -> handler}`` dispatch tables, read at hunt time from the stored bytes.

A dispatch table is an array of records in read-only data, each holding a pointer to a key string
and one or more pointers to the functions that key dispatches to. The extractor's own table pass
reads one layout only (two-word records, key first); this module reads the stored image instead —
``data_blocks`` (the raw bytes of every loaded block, executable ones included), ``functions`` and
``binaries.thunk_spans`` of the analysis.db — so any stride from two to eight words and either
order of key and handler is seen, without re-running the decompiler.

★ IRON LAW: a row is an ENUMERATED fact — the bytes hold a key pointer and a function pointer in
one record — never a reachability verdict.

★ CONTENT IS A FACT, PAIRING IS EVIDENCE. Which words are key strings, which are function entries
and how wide a record is are read without ambiguity, and every table is written. WHICH function a
key is paired with is graded (``pairing_basis``): the code that reads the table, a registration
helper with a fixed record layout, or a terminating all-zero record. A column none of them settles
is written as one candidate row per reading (``pairing_basis = 'undetermined'``); no reading is
chosen for the person. Record length and block edges never decide a pairing.

The reading model, in words (the numbers are the record's words, ``s`` the stride):

* a KEY slot is a word pointing at the first byte of a NUL-terminated printable run of 1 to 511
  bytes (first byte 0x20-0x7e), not inside a function body when the block is executable. A table
  all of whose keys read as one character is read again as wide (4-byte) strings in the binary's
  byte order, when every key then reads as two or more printable units, every pointer is 4-aligned
  and
  no key starts inside another key's string; else it stays one-character keys.
* a HANDLER slot is a function entry (an odd pointer to an ARM function entry counts), a thunk
  entry, or NULL. Each record holds at least one non-NULL handler, each handler column holds a
  function somewhere in the run, and the run is at least ``MIN_RUN`` records long. A zero key
  slot, a handler slot into executable code that is no function (an undefined handler) or any
  other word ends the run; an undefined handler between two runs cuts one table in two.
* a READING is a stride, the key's word position and the handler offsets relative to the key
  (``{+1}`` key first, ``{-1}`` key last, ``{+1, +2}``, ...). The handler columns of a run are all
  the columns that qualify over it (the maximal set). Strides are tried from two up; a word a
  shorter stride already used is not offered to a wider one. Within a stride, overlapping
  readings are chosen by the keys they explain.
* the PAIRING of each handler column: a column the reading code names (``code_two_index``, or
  ``code_helper`` for a registration helper) is paired by the code; when the record has a single
  handler column, the one reading followed by an all-zero record (a key-only record counted into
  its end first) pairs it (``data_terminator``); every other column is ``undetermined``. A table
  outside the extractor's own tables whose keys are mostly not names is never paired.
* the extractor's tables are the floor: a table holding one of its key slots is never dropped by
  the noise filters (fewer than four distinct keys, or keys shaped like C++ type names).

The ELF's own relocations re-check every handler slot (``elf_slots.handler_check``) once the
file's sha256 is confirmed to be the scanned one; without that the handler stays unverified, and
the binary's status row says how many.
"""

from __future__ import annotations

import bisect
import hashlib
import itertools
import json
import logging
import os
import re
import sqlite3
import struct
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from treasure_map.lib.analyze.elf_slots import (
    HANDLER_NOT_FUNCTION,
    HANDLER_UNVERIFIED,
    RECORD_IN_GOT,
    ElfSlots,
    handler_check,
    read_elf_slots,
)
from treasure_map.lib.atlas.models import DetectorScanStatusRow, StringKeyedEdgeRow
from treasure_map.lib.ro_db import ro_uri

logger = logging.getLogger(__name__)

DETECTOR = "string_tables"  # the status row's detector name, which the readers select on
MECHANISM = "static_string_table"
MIN_RUN = 4  # the extractor's own minimum: a shorter run is no table
STRIDES = range(2, 9)  # record widths read, in words
STR_LIMIT = 511  # longest key read, in bytes or four-byte code units, before its terminator

# pairing_basis values. The first three emit a determined row; the last is a candidate row.
CODE_TWO_INDEX = "code_two_index"
CODE_HELPER = "code_helper"
DATA_TERMINATOR = "data_terminator"
UNDETERMINED = "undetermined"
PAIRING_BASES = (CODE_TWO_INDEX, CODE_HELPER, DATA_TERMINATOR, UNDETERMINED)
# column_evidence: what shows that a determined column is a column the table dispatches to.
EVIDENCE_CODE = "code"  # the reading code calls it
EVIDENCE_STRUCT = "struct"  # the record has this single handler column

# completeness_reason tokens this module adds (a comma-joined set, as the extractor's).
SCOPE_TOKEN = "scope_absolute_records_stride_2_to_8"
SPLIT = "split_by_undefined_handler"
UNDEFINED = "handler_undefined"
TRUNCATED = "data_blocks_truncated"

SUPPORTED_SCOPE = "absolute_records_stride_2_to_8_words"
UNSUPPORTED_NOTE = (
    "not read: GOT/PIC-relative records, records wider than 8 words, a handler Ghidra did not "
    "define as a function (it cuts the table there), an imported handler, two-byte wide keys and "
    "integer-keyed tables"
)

# Word classes of a handler slot.
_O, _F, _T, _X, _Z = 0, 1, 2, 3, 4
_PRINTABLE = bytes(range(0x20, 0x7F))

# A key list shaped like C++ type-info names (a number then a name), and a name-like key: the two
# noise filters a table outside the extractor's own tables is held to.
_RTTI = re.compile(r"^(?:N|St|S[a-z])?\d+[A-Za-z_]\w*E?$")
_NAME = re.compile(r"^[A-Za-z_./\-][A-Za-z0-9_ ./:+=\-\[\]]{1,47}$")


def namelike(key: str | None) -> bool:
    """A key that reads as a name: a letter, '_', '.', '/' or '-' first, then up to 47 name
    characters, at least one letter, at most two spaces."""
    return (
        bool(key)
        and bool(_NAME.match(key or ""))
        and any(ch.isalpha() for ch in key or "")
        and (key or "").count(" ") <= 2
    )


def _hx(text: Any) -> int | None:
    try:
        return int(str(text), 16)
    except (TypeError, ValueError):
        return None


# ── the binary's stored image ────────────────────────────────────────────────────────────────


@dataclass
class _Block:
    name: str
    start: int
    data: bytes
    executable: bool
    truncated: bool

    @property
    def end(self) -> int:
        return self.start + len(self.data)


@dataclass
class _Image:
    """One binary's stored memory image and the facts a word is classified against."""

    ps: int
    big_endian: bool
    arm: bool
    blocks: list[_Block]
    functions: dict[int, str]  # entry -> name
    thunks: set[int]
    bodies: list[tuple[int, int]]  # sorted, merged [lo, hi) function bodies (string bodies out)
    _starts: list[int] = field(default_factory=list)
    _str_cache: dict[int, str | None] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.blocks.sort(key=lambda b: b.start)
        self._starts = [b.start for b in self.blocks]
        self._body_lo = [lo for lo, _hi in self.bodies]

    def block_of(self, addr: int) -> _Block | None:
        i = bisect.bisect_right(self._starts, addr) - 1
        if i >= 0 and self.blocks[i].start <= addr < self.blocks[i].end:
            return self.blocks[i]
        return None

    def in_body(self, addr: int) -> bool:
        i = bisect.bisect_right(self._body_lo, addr) - 1
        return i >= 0 and self.bodies[i][0] <= addr < self.bodies[i][1]

    def raw_string_at(self, addr: int) -> str | None:
        """The NUL-terminated printable run starting at ``addr`` (1..511 bytes, first byte
        0x20-0x7e), read from the bytes alone, or None."""
        blk = self.block_of(addr)
        if blk is None:
            return None
        off = addr - blk.start
        end = blk.data.find(b"\0", off, off + STR_LIMIT + 1)
        if end <= off:
            return None
        run = blk.data[off:end]
        return None if run.translate(None, _PRINTABLE) else run.decode("ascii")

    def string_at(self, addr: int) -> str | None:
        """:meth:`raw_string_at`, except that in an executable block a run inside a function body
        is code, not a key."""
        hit = self._str_cache.get(addr, False)
        if hit is not False:
            return hit  # type: ignore[return-value]
        out = self.raw_string_at(addr)
        if out is not None and self.in_body(addr):
            blk = self.block_of(addr)
            if blk is not None and blk.executable:
                out = None
        self._str_cache[addr] = out
        return out

    def wide_at(self, addr: int) -> tuple[str, int] | None:
        """The wide (4-byte) string (this binary's byte order) at ``addr`` and its length in
        units: two or more units 0x20-0x7e ended by a zero unit within 511 units, or None."""
        if addr % 4:
            return None
        blk = self.block_of(addr)
        if blk is None:
            return None
        order: Literal["big", "little"] = "big" if self.big_endian else "little"
        off = addr - blk.start
        chars: list[str] = []
        for i in range(STR_LIMIT + 1):
            unit = blk.data[off + 4 * i : off + 4 * i + 4]
            if len(unit) < 4:
                return None
            v = int.from_bytes(unit, order)
            if v == 0:
                return ("".join(chars), len(chars)) if len(chars) >= 2 else None
            if not 0x20 <= v <= 0x7E:
                return None
            chars.append(chr(v))
        return None

    def word_at(self, addr: int) -> int | None:
        blk = self.block_of(addr)
        if blk is None or addr + self.ps > blk.end:
            return None
        off = addr - blk.start
        return int.from_bytes(blk.data[off : off + self.ps], "big" if self.big_endian else "little")

    def handler_of(self, value: int) -> tuple[int, str | None, str] | None:
        """``(entry, name, kind)`` of the function a handler pointer names: a function entry
        (``direct``; an odd pointer to an ARM function entry is a Thumb pointer to it), else a
        thunk entry (``thunk``, its target not recorded, so no name)."""
        name = self.functions.get(value)
        if name is not None:
            return value, name, "direct"
        if self.arm and value & 1:
            name = self.functions.get(value - 1)
            if name is not None:
                return value - 1, name, "direct"
        if value in self.thunks:
            return value, None, "thunk"
        return None


def _load_image(conn: sqlite3.Connection, bid: int, arch: str, bits: int | None) -> _Image:
    ps = 8 if bits == 64 else 4
    blocks: list[_Block] = []
    for name, start, data, ex, trunc in conn.execute(
        "SELECT block_name, start_addr, bytes, executable, truncated FROM data_blocks "
        "WHERE binary_id = ? AND initialized = 1 AND bytes IS NOT NULL",
        (bid,),
    ):
        st = _hx(start)
        if st is None:
            continue  # an overlay / non-loaded space ("name::addr"): no pointer reaches it
        blocks.append(_Block(str(name), st, bytes(data), bool(ex), bool(trunc)))
    functions: dict[int, str] = {}
    per_function: list[tuple[int, str | None, list[tuple[int, int]]]] = []
    for addr, name, ranges, origin in conn.execute(
        "SELECT address, name, body_ranges, origin FROM functions WHERE binary_id = ?", (bid,)
    ):
        entry = _hx(addr)
        if entry is None:
            continue
        functions[entry] = name or ""
        try:
            parsed = json.loads(ranges) if ranges else []
        except (TypeError, ValueError):
            parsed = []
        spans: list[tuple[int, int]] = []
        for rng in parsed if isinstance(parsed, list) else []:
            if isinstance(rng, list) and len(rng) == 2:
                lo, hi = _hx(rng[0]), _hx(rng[1])
                if lo is not None and hi is not None and hi >= lo:
                    spans.append((lo, hi + 1))
        per_function.append((entry, origin, spans))
    thunks: set[int] = set()
    row = conn.execute("SELECT thunk_spans FROM binaries WHERE id = ?", (bid,)).fetchone()
    try:
        parsed_thunks = json.loads(row[0]) if row and row[0] else []
    except (TypeError, ValueError):
        parsed_thunks = []
    for ent in parsed_thunks if isinstance(parsed_thunks, list) else []:
        entry = _hx(ent[0]) if isinstance(ent, list) and ent else None
        if entry is not None:
            thunks.add(entry)
    img = _Image(
        ps, ":BE:" in (arch or ""), (arch or "").startswith("ARM"), blocks, functions, thunks, []
    )
    # A promoted or recovered "function" whose entry bytes are a printable string is string bytes
    # the decompiler was made to disassemble: its body hides no code, so it masks no key. On ARM the
    # same holds one byte on: an odd pointer to a string reads as a Thumb pointer, and the code
    # recovery promotes the even address just before the string into a "function".
    kept: list[tuple[int, int]] = []
    for entry, origin, spans in per_function:
        if origin in ("promoted", "recovered") and any(
            len(img.raw_string_at(at) or "") >= 2
            for at in ((entry, entry + 1) if img.arm else (entry,))
        ):
            continue
        kept.extend(spans)
    img.bodies = _merge(kept)
    img.__post_init__()
    return img


def _merge(spans: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for lo, hi in sorted(spans):
        if out and lo <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return out


# ── one block's words ────────────────────────────────────────────────────────────────────────


@dataclass
class _Words:
    """The aligned words of one block, classified. ``key`` holds the word indices that are key
    slots; ``hcls`` each word's handler class; ``refused`` the indices the ELF refused as a handler
    slot (and why); ``unverified`` those it could not vouch for."""

    blk: _Block
    values: list[int]
    key: set[int]
    hcls: bytearray
    refused: dict[int, str]
    unverified: set[int]
    ps: int

    @property
    def n(self) -> int:
        return len(self.values)

    def addr(self, i: int) -> int:
        return self.blk.start + i * self.ps

    def hok(self, i: int) -> bool:
        """A handler slot that keeps the record: a function, a thunk or NULL."""
        return 0 <= i < len(self.values) and self.hcls[i] in (_F, _T, _Z)

    def hf(self, i: int) -> bool:
        """A handler slot holding a function or a thunk."""
        return 0 <= i < len(self.values) and self.hcls[i] in (_F, _T)

    def zero(self, i: int) -> bool:
        return 0 <= i < len(self.values) and self.values[i] == 0


def _words_of(img: _Image, blk: _Block) -> list[int]:
    n = len(blk.data) // img.ps
    fmt = (">" if img.big_endian else "<") + str(n) + ("I" if img.ps == 4 else "Q")
    return list(struct.unpack(fmt, blk.data[: n * img.ps]))


def _classify(img: _Image, blk: _Block) -> _Words:
    values = _words_of(img, blk)
    n = len(values)
    hcls = bytearray(n)
    key: set[int] = set()
    lo = img.blocks[0].start if img.blocks else 0
    hi = max((b.end for b in img.blocks), default=0)
    functions, thunks, arm = img.functions, img.thunks, img.arm
    for i, v in enumerate(values):
        if v == 0:
            hcls[i] = _Z
            continue
        if v < lo or v >= hi:
            if v in functions or v in thunks:  # an entry outside every stored block (defensive)
                hcls[i] = _F if v in functions else _T
            continue
        if v in functions or (arm and v & 1 and (v - 1) in functions):
            hcls[i] = _F
        elif v in thunks:
            hcls[i] = _T
        # The key test reads the raw pointer: an odd pointer is a string, never a Thumb function
        # pointer, on the key side.
        if img.string_at(v) is not None:
            key.add(i)
            continue
        if hcls[i] == _O:
            tb = img.block_of(v)
            if tb is not None and tb.executable and (v % 4 == 0 or (arm and v & 1)):
                hcls[i] = _X
    return _Words(blk, values, key, hcls, {}, set(), img.ps)


def _apply_slots(img: _Image, w: _Words, slots: ElfSlots | None) -> None:
    """The ELF's word on each slot: a key slot inside the GOT is no key; a handler slot the ELF
    fills with something other than that function (``handler_check``) is refused, which ends a
    run there; a handler it cannot vouch for is kept and counted unverified. With no slot facts
    every handler stays unverified."""
    handlers = [i for i, c in enumerate(w.hcls) if c in (_F, _T)]
    if slots is None:
        w.unverified.update(handlers)
        return
    for i in [i for i in w.key if slots.in_got(w.addr(i))]:
        w.key.discard(i)
    for i in handlers:
        a = w.addr(i)
        h = img.handler_of(w.values[i])
        verdict = handler_check(slots, a, a, (h[1] or "") if h else "")
        if verdict in (RECORD_IN_GOT, HANDLER_NOT_FUNCTION):
            w.hcls[i] = _O
            w.refused[i] = verdict
        elif verdict == HANDLER_UNVERIFIED:
            w.unverified.add(i)


# ── readings ─────────────────────────────────────────────────────────────────────────────────


@dataclass
class _Reading:
    """One reading of a run of records: the handler offsets relative to the key (``offsets``),
    the record rotations that give them (``rotations``: rotation ``t`` puts the record's words at
    key offsets ``t+1-s .. t``) and the key word indices it explains."""

    offsets: frozenset[int]
    rotations: list[int]
    keys: list[int]
    terminated: bool = False
    tail_sentinel: bool = False


@dataclass
class _Table:
    stride: int
    phase: int
    readings: list[_Reading]
    keyset: set[int]
    hset: set[int]

    @property
    def span(self) -> tuple[int, int]:
        ws = self.keyset | self.hset
        return min(ws), max(ws)


def _runs(flags: list[bool]) -> list[tuple[int, int]]:
    """``(start, length)`` of each run of True at least ``MIN_RUN`` long."""
    out: list[tuple[int, int]] = []
    i, n = 0, len(flags)
    while i < n:
        if not flags[i]:
            i += 1
            continue
        j = i
        while j < n and flags[j]:
            j += 1
        if j - i >= MIN_RUN:
            out.append((i, j - i))
        i = j
    return out


def _segment_readings(
    w: _Words, rows: list[int], s: int, blocked: set[int]
) -> list[tuple[frozenset[int], int, int, int]]:
    """The readings of one run of key slots at stride ``s``: ``(offsets, rotation, first row,
    last row)``. Per rotation, the record's handler columns are the qualifying columns of the
    longest run (records whose handler slots are all function / thunk / NULL with at least one
    non-NULL, every column holding a function somewhere in the run); the columns kept for a run are
    ALL the columns that qualify over it (the maximal set), never a subset."""
    n_rows = len(rows)
    out: list[tuple[frozenset[int], int, int, int]] = []
    for t in range(s):
        offs = {c: (c if c <= t else c - s) for c in range(1, s)}
        hok: dict[int, list[bool]] = {}
        hf: dict[int, list[bool]] = {}
        for c, o in offs.items():
            hok[c] = [w.hok(k + o) and (k + o) not in blocked for k in rows]
            hf[c] = [w.hf(k + o) and (k + o) not in blocked for k in rows]
        cols = [c for c in offs if any(hf[c])]
        if not cols:
            continue
        found: list[tuple[int, int, int, tuple[int, ...]]] = []
        for r in range(1, len(cols) + 1):
            for cc in itertools.combinations(cols, r):
                q = [
                    all(hok[c][i] for c in cc) and any(hf[c][i] for c in cc) for i in range(n_rows)
                ]
                for st, ln in _runs(q):
                    if all(any(hf[c][st : st + ln]) for c in cc):
                        found.append((ln, len(cc), st, cc))
        found.sort(key=lambda x: (-x[0], -x[1], x[2]))
        taken = [False] * n_rows
        for ln, _nc, st, _cc in found:
            if any(taken[st : st + ln]):
                continue
            for i in range(st, st + ln):
                taken[i] = True
            cmax = [c for c in cols if all(hok[c][st : st + ln]) and any(hf[c][st : st + ln])]
            out.append((frozenset(offs[c] for c in cmax), t, st, st + ln - 1))
    return out


def _stride_tables(w: _Words, s: int, blocked: set[int]) -> list[_Table]:
    """Every table one stride reads in a block, before the content choice: each maximal run of
    key slots at this stride, its readings clustered by the rows they cover."""
    keys = w.key - blocked
    out: list[_Table] = []
    for k in sorted(keys):
        if (k - s) in keys:
            continue  # not the start of a run
        rows = [k]
        while rows[-1] + s in keys:
            rows.append(rows[-1] + s)
        if len(rows) < MIN_RUN:
            continue
        readings = _segment_readings(w, rows, s, blocked)
        if not readings:
            continue
        readings.sort(key=lambda x: x[2])
        clusters: list[dict[str, Any]] = []
        for offsets, t, i0, i1 in readings:
            for cl in clusters:
                if not (i1 < cl["lo"] or i0 > cl["hi"]):
                    cl["alts"].append((offsets, t, i0, i1))
                    cl["lo"], cl["hi"] = min(cl["lo"], i0), max(cl["hi"], i1)
                    break
            else:
                clusters.append({"lo": i0, "hi": i1, "alts": [(offsets, t, i0, i1)]})
        for cl in clusters:
            by_offsets: dict[frozenset[int], dict[str, Any]] = {}
            for offsets, t, i0, i1 in cl["alts"]:
                e = by_offsets.setdefault(offsets, {"ts": [], "i0": i0, "i1": i1})
                e["ts"].append(t)
                if i1 - i0 > e["i1"] - e["i0"]:
                    e["i0"], e["i1"] = i0, i1
            tab_readings = [
                _Reading(offsets, sorted(e["ts"]), rows[e["i0"] : e["i1"] + 1])
                for offsets, e in by_offsets.items()
            ]
            keyset = {k2 for r in tab_readings for k2 in r.keys}
            hset = {
                k2 + o for r in tab_readings for k2 in r.keys for o in r.offsets if w.hf(k2 + o)
            }
            out.append(_Table(s, rows[0] % s, tab_readings, keyset, hset))
    return out


def _choose(tables: list[_Table]) -> list[_Table]:
    """The content choice within one stride: of the readings whose word spans overlap, the set
    that explains the most key slots (weighted interval scheduling over the spans)."""
    if not tables:
        return []
    order = sorted(range(len(tables)), key=lambda i: (tables[i].span[1], tables[i].span[0]))
    ends = [tables[i].span[1] for i in order]
    best = [0] * (len(order) + 1)
    take = [False] * (len(order) + 1)
    prev = [0] * (len(order) + 1)
    for j, i in enumerate(order, 1):
        lo = tables[i].span[0]
        pj = bisect.bisect_left(ends, lo, 0, j - 1)  # the tables that end before this one starts
        inc = best[pj] + len(tables[i].keyset)
        if inc > best[j - 1]:
            best[j], take[j], prev[j] = inc, True, pj
        else:
            best[j] = best[j - 1]
    chosen: list[_Table] = []
    j = len(order)
    while j > 0:
        if take[j]:
            chosen.append(tables[order[j - 1]])
            j = prev[j]
        else:
            j -= 1
    return sorted(chosen, key=lambda t: t.span[0])


def _find_tables(w: _Words) -> list[_Table]:
    """The tables of one block: strides from two up, each stride's content choice made on the
    words no shorter stride's table uses."""
    blocked: set[int] = set()
    out: list[_Table] = []
    for s in STRIDES:
        accepted = _choose(_stride_tables(w, s, blocked))
        for t in accepted:
            blocked |= t.keyset | t.hset
        out += accepted
    return sorted(out, key=lambda t: t.span[0])


def _terminate(w: _Words, s: int, r: _Reading) -> None:
    """Whether the reading's last record is followed by an all-zero record of this reading's
    framing (any of its rotations). A key-only record right after the last one (a key with every
    handler slot NULL: a sentinel) is counted into the end first. A block edge never counts."""
    last = r.keys[-1]
    nk = last + s
    if nk in w.key and all(w.zero(nk + o) for o in r.offsets):
        last = nk
        r.tail_sentinel = True
    for t in r.rotations:
        lo = last + s + (t + 1 - s)
        hi = lo + s
        if lo >= 0 and hi <= w.n and all(v == 0 for v in w.values[lo:hi]):
            r.terminated = True
            return


# ── the code that reads a table ──────────────────────────────────────────────────────────────
#
# Read from the decompiled TEXT of every function that names an address within one record before
# to two records past the table's first key. A frame is one pointer into the table and what is
# read through it:
#   walk     VAR = &SYM_<a>;  [VAR = VAR + N;]  with a call through VAR[k] / *VAR (a handler) and a
#            string compare whose argument is VAR[j] / *VAR (the key), directly or through a temp
#            loaded once from it
#   index    (&SYM_<a>)[i * N] | *(code **)(&SYM_<a> + i * N): a record width, no key
#   helper   luaL_register / luaL_newlib / luaL_setfuncs (L, ..., &SYM): a {name, func} record the
#            ABI fixes (key 0, handler 1)
# Only a frame with exactly one key index and at least one handler index pairs (two_index).

_SIZE: dict[str, int | None] = {
    "char": 1, "uchar": 1, "byte": 1, "bool": 1, "undefined": 1, "undefined1": 1, "short": 2,
    "ushort": 2, "undefined2": 2, "int": 4, "uint": 4, "undefined4": 4, "float": 4, "code": None,
    "undefined8": 8, "longlong": 8, "ulonglong": 8, "double": 8, "ulong": None, "long": None,
}  # fmt: skip
_DECL = re.compile(r"^\s+(?:const\s+)?(\w+)\s+(\*+)(\w+);", re.M)
_SYM = r"&[A-Za-z_]\w*?_([0-9a-f]{6,16})\b"
_ASSIGN = re.compile(r"\b(\w+) = (?:\([^()]*\))?" + _SYM)
_NUM = r"(0x[0-9a-f]+|\d+)"
_IDX1 = re.compile(r"\(" + _SYM + r"\)\[\w+ \* " + _NUM + r"\]")
_IDX2 = re.compile(r"\*\(code \*\*\)\s*\(" + _SYM + r" \+ \w+ \* " + _NUM + r"\)")
_CMP = re.compile(r"\b\w*(?:strcmp|strcasecmp|strncmp|strncasecmp|strstr)\(([^;]*?)\)")
_HELP = re.compile(r"\b(?:luaL_register|luaL_newlib|luaL_setfuncs)\s*\([^;]*?" + _SYM)
_HEX_SYM = re.compile(r"_([0-9a-f]{6,16})\b")


def _num(t: str) -> int:
    return int(t, 16) if t.startswith("0x") else int(t)


@dataclass(frozen=True)
class Frame:
    """One access to a table: the walk step in bytes (None: not a walking pointer), the key and
    handler word indices relative to the pointer, the form, and the address the pointer was set
    to."""

    step: int | None
    key_idx: frozenset[int]
    handler_idx: frozenset[int]
    form: str
    base: int


def frames(pc: str, lo: int, hi: int, ps: int) -> list[Frame]:
    """The access frames of one function's text over the addresses ``[lo, hi)``."""
    out: list[Frame] = []
    decls = {m.group(3): (m.group(1), m.group(2)) for m in _DECL.finditer(pc)}
    for m in _ASSIGN.finditer(pc):
        var, a = m.group(1), int(m.group(2), 16)
        if not lo <= a < hi:
            continue
        d = decls.get(var)
        es = None if d is None else (ps if len(d[1]) >= 2 else _SIZE.get(d[0]))
        steps = {_num(x) for x in re.findall(rf"\b{var} = {var} \+ {_NUM};", pc)}
        step: int | None
        if es and len(steps) == 1:
            step = steps.pop() * es
        elif es and not steps:
            step = None  # a pointer that does not walk (a matched-record form): handler only
        else:
            continue
        load: dict[str, set[int]] = {}
        for lm in re.finditer(rf"\b(\w+) = (?:\([^()]*\))?(?:{var}\[{_NUM}\]|(\*){var}\b)", pc):
            tmp, j, star = lm.group(1), lm.group(2), lm.group(3)
            load.setdefault(tmp, set()).add(0 if star else _num(j))

        def widx(expr: str, var: str = var, load: dict[str, set[int]] = load) -> set[int]:
            got = {_num(x) for x in re.findall(rf"\b{var}\[{_NUM}\]", expr)}
            if re.search(rf"\*{var}\b", expr):
                got.add(0)
            for tmp, js in load.items():
                if re.search(rf"\b{tmp}\b", expr):
                    got |= js
            return got

        hk = {_num(x) for x in re.findall(rf"\(code \*\)\s*{var}\[{_NUM}\]", pc)}
        hk |= {_num(x) // ps for x in re.findall(rf"\*\(code \*\*\)\s*\({var} \+ {_NUM}\)", pc)}
        if re.search(rf"\(code \*\)\s*\*{var}\b", pc):
            hk.add(0)
        for tmp, js in load.items():
            call = (
                rf"\(code \*\)\s*{tmp}\b|\(\*\(code \*\*\)\({tmp} \+ 0\)\)"
                rf"|\(\*\(code \*\)\s*{tmp}\)"
            )
            if re.search(call, pc):
                hk |= js
        kk: set[int] = set()
        for cm in _CMP.finditer(pc):
            kk |= widx(cm.group(1))
        if step is None and not hk:
            continue
        if step is None:
            step = ps * (max(hk | kk) + 1)  # a record at least this wide
        out.append(Frame(step, frozenset(kk), frozenset(hk), "walk", a))
    for m in _IDX1.finditer(pc):
        a, n = int(m.group(1), 16), _num(m.group(2))
        if lo <= a < hi and n:
            out.append(Frame(n * ps, frozenset(), frozenset({n - 1} if n >= 2 else ()), "index", a))
    for m in _IDX2.finditer(pc):
        a, n = int(m.group(1), 16), _num(m.group(2))
        if lo <= a < hi and n:
            out.append(Frame(n, frozenset(), frozenset(), "index", a))
    for m in _HELP.finditer(pc):
        a = int(m.group(1), 16)
        if lo <= a < hi:
            out.append(Frame(2 * ps, frozenset({0}), frozenset({1}), "helper", a))
    return out


class _CodeIndex:
    """A binary's decompiled functions, indexed by the addresses their symbols name."""

    def __init__(self, conn: sqlite3.Connection, bid: int) -> None:
        self.texts: list[str] = []
        self.by_addr: dict[int, set[int]] = defaultdict(set)
        for (pc,) in conn.execute(
            "SELECT pseudocode FROM functions WHERE binary_id = ? AND pseudocode IS NOT NULL",
            (bid,),
        ):
            i = len(self.texts)
            self.texts.append(pc)
            for m in _HEX_SYM.finditer(pc):
                self.by_addr[int(m.group(1), 16)].add(i)

    def frames_in(self, lo: int, hi: int, ps: int) -> list[Frame]:
        fns: set[int] = set()
        for a in range(lo, hi):
            fns |= self.by_addr.get(a, set())
        out: list[Frame] = []
        for i in sorted(fns):
            out += frames(self.texts[i], lo, hi, ps)
        return out


@dataclass(frozen=True)
class CodeEvidence:
    """What the reading code says about one table: ``status`` is ``none`` (no frame pairs),
    ``frame_only`` (frames give handler indices, no key: never a pairing), ``conflict`` (frames
    disagree on the key, or one slot is a key in one frame and a handler in another),
    ``inconsistent`` (the data's slots do not hold what the code reads) or ``ok``; ``offsets`` the
    handler offsets relative to the key (the union over the frames that agree on the key) and
    ``basis`` the pairing basis it gives."""

    status: str
    offsets: frozenset[int] = frozenset()
    basis: str | None = None
    why: str | None = None


def code_evidence(w: _Words, table: _Table, code_frames: list[Frame]) -> CodeEvidence:
    """The four preconditions of a code pairing, in order: a frame's handler index a record or
    more from its key is a prefetch of the next record and is dropped; frames that agree on the
    key column pool their handler offsets (two accessors reading one column each are one
    pairing); frames that disagree on it conflict; and the data's slots must hold what the code
    reads — the key column a key slot, each handler slot a function or NULL over the table's rows
    (at least one function per column, one non-NULL per row) — or the code is inconsistent."""
    s, ps = table.stride, w.ps
    keys = sorted(table.keyset)
    key0 = w.addr(keys[0])
    groups: dict[int, dict[str, Any]] = {}
    frame_only = 0
    for fr in code_frames:
        if not fr.handler_idx:
            continue
        if len(fr.key_idx) != 1:
            frame_only += 1
            continue
        k0 = next(iter(fr.key_idx))
        d = fr.base + k0 * ps - key0
        if d % ps:
            continue
        kcol = (d // ps) % s
        walk = (fr.step // ps) if fr.step else s
        offs = {h - k0 for h in fr.handler_idx if h != k0 and abs(h - k0) < walk}
        if not offs:
            continue
        g = groups.setdefault(kcol, {"offs": set(), "forms": set()})
        g["offs"] |= offs
        g["forms"].add(fr.form)
    if not groups:
        return CodeEvidence("frame_only" if frame_only else "none")
    if len(groups) > 1:
        return CodeEvidence("conflict", why="key_columns")
    kcol, g = next(iter(groups.items()))
    if kcol in {(kcol + o) % s for o in g["offs"]}:
        return CodeEvidence("conflict", why="slot_key_and_handler")
    basis = CODE_HELPER if g["forms"] == {"helper"} else CODE_TWO_INDEX
    offsets = frozenset(g["offs"])
    if kcol != 0:
        return CodeEvidence("inconsistent", offsets, basis, "key_not_data_key_column")
    if any(offsets <= r.offsets for r in table.readings):
        return CodeEvidence("ok", offsets, basis)
    any_fn = [False] * len(keys)
    for o in offsets:
        cls = [w.hcls[k + o] if 0 <= k + o < w.n else _O for k in keys]
        if any(c not in (_F, _T, _Z) for c in cls):
            return CodeEvidence("inconsistent", offsets, basis, "slot_not_fn_or_null")
        if not any(c in (_F, _T) for c in cls):
            return CodeEvidence("inconsistent", offsets, basis, "offset_never_fn")
        any_fn = [a or c in (_F, _T) for a, c in zip(any_fn, cls, strict=True)]
    if not all(any_fn):
        return CodeEvidence("inconsistent", offsets, basis, "row_all_null")
    return CodeEvidence("ok", offsets, basis)


# ── deciding the pairing, column by column ───────────────────────────────────────────────────


@dataclass(frozen=True)
class _Column:
    offset: int
    basis: str
    evidence: str


@dataclass(frozen=True)
class TableKeys:
    """A table's key text per key slot, and whether it was read as a wide (four-byte) string."""

    text: dict[int, str]
    wide: bool


def table_keys(img: _Image, w: _Words, keyset: Iterable[int]) -> TableKeys:
    """The key text of each key slot. When every key reads as one character, the keys are read
    as wide (4-byte) strings instead — only when all of them then read as two or more printable
    units, every pointer is 4-aligned and no key pointer falls inside another key's string;
    otherwise the one-character reading stands for the whole table (never a mix)."""
    slots = sorted(keyset)
    narrow = {k: img.string_at(w.values[k]) or "" for k in slots}
    if not narrow or any(len(t) != 1 for t in narrow.values()):
        return TableKeys(narrow, False)
    wide: dict[int, tuple[str, int]] = {}
    for k in slots:
        got = img.wide_at(w.values[k])
        if got is None:
            return TableKeys(narrow, False)
        wide[k] = got
    spans = sorted({(w.values[k], w.values[k] + 4 * (n + 1)) for k, (_t, n) in wide.items()})
    for k in slots:
        v = w.values[k]
        if any(lo < v < hi for lo, hi in spans):
            return TableKeys(narrow, False)
    return TableKeys({k: t for k, (t, _n) in wide.items()}, True)


def excluded_as_noise(keys: list[str]) -> bool:
    """A table of fewer than four distinct keys, or one whose keys are at least half shaped like
    C++ type-info names: noise (symbol records, type-info names beside a vtable)."""
    if len(set(keys)) < 4:
        return True
    return sum(bool(_RTTI.match(k)) for k in keys) * 2 >= max(1, len(keys))


def fails_content_gate(keys: list[str]) -> bool:
    """Fewer than three quarters of ALL the table's keys read as names: the table is not keyed by
    the strings it holds (an error-message table, mis-aligned symbol data) — no pairing is made,
    whatever the data or the code would say."""
    return bool(keys) and sum(namelike(k) for k in keys) * 4 < 3 * len(keys)


@dataclass(frozen=True)
class Decision:
    """Per handler column (offset mod stride): its pairing, or absent when undetermined."""

    columns: dict[int, _Column]
    conflict: str | None
    gated: bool
    code: CodeEvidence


def decide(table: _Table, code: CodeEvidence, gated: bool) -> Decision:
    """Q1 (is the column a handler the table dispatches to) and Q2 (which key it belongs to),
    column by column. A column the code names answers both from the code. With a single handler
    column over all the table's readings (Q1 holds by definition), the one reading followed by an
    all-zero record answers Q2. A
    terminator that disagrees with the code on a column it names is not used, and is recorded. Any
    other column, a table the content gate stops, and a table whose code conflicts or is
    inconsistent, stays undetermined."""
    s = table.stride
    columns: dict[int, _Column] = {}
    if gated:
        return Decision(columns, None, True, code)
    if code.status == "conflict":
        return Decision(columns, "code_frames_disagree", False, code)
    if code.status == "inconsistent":
        return Decision(columns, None, False, code)
    if code.status == "ok" and code.basis is not None:
        for o in code.offsets:
            columns[o % s] = _Column(o, code.basis, EVIDENCE_CODE)
    conflict: str | None = None
    # The record's handler columns are those of EVERY reading of the table (a column is its offset
    # mod the stride, so the rotations of one column are one column): a reading that lost a column
    # to one bad slot does not make the record single-column.
    table_columns = {o % s for r in table.readings for o in r.offsets}
    ended = [r for r in table.readings if r.terminated]
    if len(ended) == 1:
        by_col = {o % s: o for o in ended[0].offsets}
        if any(c in columns and columns[c].offset != o for c, o in by_col.items()):
            conflict = DATA_TERMINATOR
        elif len(table_columns) == 1:
            for c, o in by_col.items():
                columns.setdefault(c, _Column(o, DATA_TERMINATOR, EVIDENCE_STRUCT))
    return Decision(columns, conflict, False, code)


# ── the rows ─────────────────────────────────────────────────────────────────────────────────


@dataclass
class BinaryResult:
    """One binary's rows and the counts its status row carries."""

    edges: list[StringKeyedEdgeRow] = field(default_factory=list)
    key_slots: list[int] = field(default_factory=list)  # each edge's key slot address, in order
    tables: int = 0
    unverified: int = 0
    undetermined: int = 0
    truncated: bool = False


def _record_reasons(w: _Words, kpos: int, offsets: set[int]) -> set[str]:
    """What the record keyed at word ``kpos`` says about a table edge there: a handler slot the
    ELF refused, or one pointing into code Ghidra did not define (``handler_undefined``)."""
    why: set[str] = set()
    if 0 <= kpos < w.n and kpos in w.key:
        for o in offsets:
            slot = kpos + o
            if slot in w.refused:
                why.add(w.refused[slot])
            elif 0 <= slot < w.n and w.hcls[slot] == _X:
                why.add(UNDEFINED)
    return why


def _bound_reasons(w: _Words, table: _Table) -> tuple[set[str], set[str], set[str]]:
    """Why the table stops: the record before its first key, the record after its last, and any
    record keyed inside it, whose handler slot (under any of the table's readings) the ELF refused
    or that points into code Ghidra did not define."""
    s = table.stride
    offsets = {o for r in table.readings for o in r.offsets}
    keys = sorted(table.keyset)
    inner: set[str] = set()
    for k in keys:
        inner |= _record_reasons(w, k, offsets)
    return (
        _record_reasons(w, keys[0] - s, offsets),
        _record_reasons(w, keys[-1] + s, offsets),
        inner,
    )


def _table_rows(
    img: _Image,
    w: _Words,
    table: _Table,
    keys: TableKeys,
    dec: Decision,
    reasons: set[str],
    common: dict[str, Any],
    result: BinaryResult,
) -> None:
    s = table.stride
    edges: dict[tuple[int, int], int] = {}  # (key slot, offset) -> handler slot
    for r in table.readings:
        for k in r.keys:
            for o in r.offsets:
                if w.hf(k + o):
                    edges[(k, o)] = k + o
    determined: list[tuple[int, int, int]] = []
    candidates: dict[tuple[int, int], set[int]] = defaultdict(set)
    cand_slot: dict[tuple[int, int], int] = {}
    for (k, o), slot in sorted(edges.items()):
        col = dec.columns.get(o % s)
        if col is not None:
            if col.offset == o:
                determined.append((k, o, slot))
            continue  # another reading of a decided column: not this key's handler
        h = img.handler_of(w.values[slot])
        if h is None:
            continue
        candidates[(k, h[0])].add(o)
        cand_slot.setdefault((k, h[0]), slot)
    if any(slot in w.unverified for _k, _o, slot in determined) or any(
        slot in w.unverified for slot in cand_slot.values()
    ):
        reasons = reasons | {HANDLER_UNVERIFIED}
    reason = ",".join(sorted(reasons))
    table_addr = f"0x{w.addr(min(table.keyset)):x}"

    def row(k: int, slot: int, offset: int | None, basis: str, **extra: Any) -> None:
        h = img.handler_of(w.values[slot])
        if h is None:
            return
        entry, name, kind = h
        result.edges.append(
            StringKeyedEdgeRow(
                key=keys.text.get(k),
                callee_name=name or None,
                callee_addr=f"0x{entry:x}",
                callee_kind=kind,
                table_addr=table_addr,
                completeness_status="incomplete",
                completeness_reason=reason,
                completeness_scope=SUPPORTED_SCOPE,
                stride_words=s,
                key_phase=(w.addr(k) // w.ps) % s,
                handler_offset=offset,
                pairing_basis=basis,
                **extra,
                **common,
            )
        )
        result.key_slots.append(w.addr(k))
        if slot in w.unverified:
            result.unverified += 1

    for k, o, slot in determined:
        col = dec.columns[o % s]
        row(k, slot, o, col.basis, pairing_conflict=dec.conflict, column_evidence=col.evidence)
    for (k, _entry), offs in sorted(candidates.items()):
        row(
            k,
            cand_slot[(k, _entry)],
            next(iter(offs)) if len(offs) == 1 else None,
            UNDETERMINED,
            pairing_conflict=dec.conflict,
        )
        result.undetermined += 1


def detect_binary(
    conn: sqlite3.Connection,
    bid: int,
    *,
    arch: str,
    bits: int | None,
    java_key_slots: set[int],
    get_slots: Callable[[], ElfSlots | None],
    common: dict[str, Any],
) -> BinaryResult:
    """Every dispatch table of one binary, as string_keyed_edge rows (see the module docstring).
    ``get_slots`` gives the ELF's slot facts; it is called once, and only when some block may hold
    a table (the relocation read is the costly part)."""
    result = BinaryResult()
    slot_memo: list[ElfSlots | None] = []
    img = _load_image(conn, bid, arch, bits)
    result.truncated = any(b.truncated for b in img.blocks)
    code_index: _CodeIndex | None = None
    for blk in img.blocks:
        if len(blk.data) // img.ps < 2 * MIN_RUN:
            continue
        w = _classify(img, blk)
        if not _may_hold_a_table(w):
            continue
        if not slot_memo:
            slot_memo.append(get_slots())
        _apply_slots(img, w, slot_memo[0])
        tables = _find_tables(w)
        if not tables:
            continue
        starts = {(t.stride, min(t.keyset)): t for t in tables}
        bounds = {id(t): _bound_reasons(w, t) for t in tables}
        split: set[int] = set()
        for t in tables:
            after = bounds[id(t)][1]
            nxt = starts.get((t.stride, max(t.keyset) + 2 * t.stride))
            if UNDEFINED in after and nxt is not None and UNDEFINED in bounds[id(nxt)][0]:
                split |= {id(t), id(nxt)}
        for t in tables:
            for r in t.readings:
                _terminate(w, t.stride, r)
            keys = table_keys(img, w, t.keyset)
            texts = [keys.text[k] for k in sorted(t.keyset)]
            java = any(w.addr(k) in java_key_slots for k in t.keyset)
            if not java and excluded_as_noise(texts):
                continue
            gated = not java and fails_content_gate(texts)
            if code_index is None:
                code_index = _CodeIndex(conn, bid)
            key0 = w.addr(min(t.keyset))
            code = code_evidence(
                w,
                t,
                code_index.frames_in(key0 - t.stride * w.ps, key0 + 2 * t.stride * w.ps, w.ps),
            )
            reasons = {SCOPE_TOKEN} | bounds[id(t)][0] | bounds[id(t)][1] | bounds[id(t)][2]
            if id(t) in split:
                reasons.add(SPLIT)
            if blk.truncated and max(t.keyset) + 2 * t.stride > w.n:
                reasons.add(TRUNCATED)
            result.tables += 1
            _table_rows(img, w, t, keys, decide(t, code, gated), reasons, common, result)
    return result


def _may_hold_a_table(w: _Words) -> bool:
    """Cheap pre-test: some stride holds ``MIN_RUN`` key slots in a row."""
    keys = w.key
    for k in keys:
        for s in STRIDES:
            if all(k + s * j in keys for j in range(1, MIN_RUN)):
                return True
    return False


# ── the ELF on disk, and the run ─────────────────────────────────────────────────────────────

ELF_OK = "ok"
ELF_MISSING = "missing"
ELF_SHA_MISMATCH = "sha_mismatch"
ELF_UNREADABLE = "unreadable"

_SHA_CACHE: dict[tuple[str, int, int], str] = {}


def _file_sha256(path: str) -> str | None:
    """The file's sha256, cached by (path, size, mtime) within the process; None when unreadable."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    key = (path, st.st_size, st.st_mtime_ns)
    hit = _SHA_CACHE.get(key)
    if hit is not None:
        return hit
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return None
    _SHA_CACHE[key] = h.hexdigest()
    return _SHA_CACHE[key]


def elf_file_state(path: str | None, sha256: str | None) -> str:
    """Whether the ELF the slot check reads is the one that was scanned: ``ok`` (present, its
    sha256 equal to the recorded one), ``missing``, or ``sha_mismatch``. The hunt input
    fingerprint carries it, so an unpacked image deleted or replaced since re-hunts."""
    if not path or not os.path.isfile(path):
        return ELF_MISSING
    got = _file_sha256(path)
    if got is None:
        return ELF_MISSING
    return ELF_OK if sha256 and got == sha256 else ELF_SHA_MISMATCH


def _slots_for(path: str | None, sha256: str | None) -> tuple[str, ElfSlots | None]:
    state = elf_file_state(path, sha256)
    if state != ELF_OK or path is None:
        return state, None
    slots = read_elf_slots(Path(path))
    return (ELF_OK, slots) if slots is not None else (ELF_UNREADABLE, None)


@dataclass(frozen=True)
class RunTables:
    edges: list[StringKeyedEdgeRow]
    statuses: list[DetectorScanStatusRow]
    key_slots: list[int] = field(default_factory=list)  # each edge's key slot address, in order


def detect_run(db_path: Path | str, source_run_id: str) -> RunTables:
    """Every current binary's dispatch tables and its status row (``detector='string_tables'``).
    A binary the decompiler did not finish holds no image to read and gets no row; one whose
    analysis.db holds no stored bytes is recorded as not scanned, never as having none."""
    conn = sqlite3.connect(ro_uri(Path(db_path)), uri=True)
    edges: list[StringKeyedEdgeRow] = []
    key_slots: list[int] = []
    statuses: list[DetectorScanStatusRow] = []
    try:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {"binaries", "functions"} <= tables:
            return RunTables([], [], [])
        has_blocks = "data_blocks" in tables
        rows = conn.execute(
            "SELECT id, name, path, sha256, arch, bits FROM binaries WHERE ghidra_ok = 1 "
            "AND last_seen_at IS (SELECT MAX(last_seen_at) FROM binaries) ORDER BY id"
        ).fetchall()
        java: dict[int, set[int]] = defaultdict(set)
        if "string_tables" in tables:
            for b, ta, st, ei in conn.execute(
                "SELECT binary_id, table_addr, stride, entry_index FROM string_tables"
            ):
                base = _hx(ta)
                if base is not None and isinstance(st, int) and isinstance(ei, int):
                    java[b].add(base + ei * st)
        for bid, name, path, sha, arch, bits in rows:
            common = {
                "source_run_id": source_run_id,
                "binary": name,
                "binary_path": path,
                "from_function": None,
                "from_func_addr": None,
                "mechanism": MECHANISM,
                "ladder_size": None,
            }
            stored = (
                has_blocks
                and conn.execute(
                    "SELECT 1 FROM data_blocks WHERE binary_id = ? LIMIT 1", (bid,)
                ).fetchone()
                is not None
            )
            if not stored:
                statuses.append(
                    DetectorScanStatusRow(
                        source_run_id=source_run_id,
                        binary=name,
                        binary_path=path,
                        detector=DETECTOR,
                        scanned=0,
                        supported_scope=SUPPORTED_SCOPE,
                        unsupported_note=UNSUPPORTED_NOTE,
                    )
                )
                continue
            elf = {"state": "not_read"}

            def get_slots(
                path: str | None = path, sha: str | None = sha, elf: dict[str, str] = elf
            ) -> ElfSlots | None:
                elf["state"], slots = _slots_for(path, sha)
                return slots

            res = detect_binary(
                conn,
                bid,
                arch=arch or "",
                bits=bits,
                java_key_slots=java.get(bid, set()),
                get_slots=get_slots,
                common=common,
            )
            edges += res.edges
            key_slots += res.key_slots
            statuses.append(
                DetectorScanStatusRow(
                    source_run_id=source_run_id,
                    binary=name,
                    binary_path=path,
                    detector=DETECTOR,
                    scanned=1,
                    supported_scope=SUPPORTED_SCOPE,
                    unsupported_note=UNSUPPORTED_NOTE,
                    cap_hit=1 if res.truncated else 0,
                    found_count=res.tables,
                    handler_unverified=res.unverified,
                    pairing_undetermined=res.undetermined,
                )
            )
    finally:
        conn.close()
    return RunTables(edges, statuses, key_slots)
