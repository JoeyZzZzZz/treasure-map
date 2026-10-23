# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Stored data words whose value is a function's entry address — a byte fact, read on demand.

This reads a binary's stored segment bytes (``data_blocks``) and finds the word-aligned words whose
value equals some function's entry address (on ARM also ``entry|1``, the Thumb form). It says WHERE
such words are, in which block and block class, which recorded label is nearest, and whether the
word sits in an evenly spaced series of such words. It is NOT a reading that a word is a pointer,
that a function is called through it, or that a function is reached — those are the consumer's to
trace. Nothing here writes; nothing is stored.

Three readers share it: ``get_xrefs`` attaches the words that hold a function's entry value
(``xrefs_with_entry_words``), ``get_data_table`` decodes the records around one of them by the
spacing of the entry words, and the diff view sets the two sides' words side by side
(``side_reading`` / ``entry_delta``).

THE BLOCK CLASS (``block_class``) sorts a block by its name only, mechanically and without a
judgement: link and metadata structures (GOT / PLT / relocations / symbol and string tables /
unwind info) are kept apart from data segments, because a real dispatch table would otherwise be
buried under them. Every class is counted; only the comparable classes (``DELTA_CLASSES``: data,
unnamed, init_fini) feed the diff delta and a ``next`` step. A word whose bytes lie inside a stored
string (``inside_stored_string``, cross-checked against the ``strings`` table, never guessed from
the bytes) is counted but never compared and never offered as a ``next`` step.

THE SERIES (``run_around``) is an arrangement fact: the smallest stride at which at least
``MIN_RUN`` entry words follow one another, walked out to the first word that is not one. It is not
a reading that the series is a dispatch table.

Words are read only at word-aligned absolute addresses (``scope``), only for the functions the
analysis recorded, and labels only where the analysis recorded an address-taken site. A block whose
stored bytes fall short of its size makes the image incomplete: a search that finds nothing there
is ``undetermined``, never ``none_found``.
"""

from __future__ import annotations

import bisect
import json
import sqlite3
import sys
from array import array
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field, replace
from itertools import compress
from typing import Any, Literal

from treasure_map.lib.binary_id import resolve_binary
from treasure_map.lib.facts import (
    _RX_BYTES_WARNING,
    _hex_addr_int,
    _resolve_one,
    get_xrefs,
)

# The bounds of the series reading and of what one answer shows (owner decisions).
MAX_STRIDE = 0x400
MIN_RUN = 4
RUN_MAX_RECORDS = 4096
POINT_WORDS_SHOWN = 20
DIFF_WORDS_SHOWN = 5

# Every block class, in the order a listing shows them: the comparable ones first.
BLOCK_CLASSES = ("data", "unnamed", "init_fini", "linkage", "symbol_table", "unwind", "code")
# The classes the diff delta and a ``next`` step read; the rest are counted only.
DELTA_CLASSES = frozenset({"data", "unnamed", "init_fini"})

SCOPE = {
    "words": "aligned_words_only",
    "functions": "functions_table_only",
    "labels": "address_taken_sites_only",
}

_LINKAGE_PREFIXES = (".got", ".plt", ".rel", ".rela", ".gnu.")
_LINKAGE_NAMES = frozenset({".dynamic", ".hash"})
_SYMBOL_TABLE_NAMES = frozenset({".dynsym", ".symtab", ".dynstr", ".strtab", ".shstrtab"})
_UNWIND_NAMES = frozenset({".gcc_except_table", ".arm.exidx", ".arm.extab"})
_INIT_FINI_NAMES = frozenset({".init_array", ".fini_array", ".preinit_array", ".ctors", ".dtors"})


def block_class(name: str | None, executable: bool) -> str:
    """The class of a block, by its name (lower-cased) alone; an executable block is ``code``
    whatever its name. A sorting of link / metadata structures from data, not a judgement."""
    if executable:
        return "code"
    n = (name or "").lower()
    if n in _SYMBOL_TABLE_NAMES:
        return "symbol_table"
    if n in _LINKAGE_NAMES or n.startswith(_LINKAGE_PREFIXES):
        return "linkage"
    if n.startswith(".eh_frame") or n in _UNWIND_NAMES:
        return "unwind"
    if n in _INIT_FINI_NAMES:
        return "init_fini"
    if not n or n.startswith("segment_"):
        return "unnamed"
    return "data"


# ── the image: one binary's stored blocks, entries, labels and strings ─────────────────────────


@dataclass(frozen=True)
class Block:
    """One exported block. ``data`` is the stored bytes (empty for an uninitialized block)."""

    name: str
    start: int
    size: int
    data: bytes
    initialized: bool
    executable: bool
    truncated: bool  # the stored bytes cover less than ``size``
    block_class: str
    stored_end: int  # start + the stored bytes that lie inside the block
    end: int  # start + size

    def holds(self, addr: int) -> bool:
        return self.start <= addr < self.end


@dataclass
class Image:
    """One binary's view for this reading. ``unavailable`` names why words cannot be read at all
    (no blocks exported, an architecture that names no endianness / word size); ``entries`` is
    read either way, so whether a function is in the inventory is known even then."""

    binary_id: int
    sha256: str | None
    unavailable: str | None
    endian: str  # "LE" / "BE" ("" when unavailable)
    word_size: int  # 4 / 8 (0 when unavailable)
    thumb: bool
    entries: dict[int, tuple[str | None, str]]  # entry -> (name, the address as stored)
    targets: dict[int, int]  # a word value -> the entry it equals (entry, and entry|1 on ARM)
    blocks: tuple[Block, ...]  # every exported block, initialized or not, in address order
    labels: tuple[tuple[int, str], ...]  # (taken_at, nearby_symbol), sorted
    strings: dict[int, str]  # string start -> value
    string_ranges: tuple[tuple[int, int], ...]  # merged [start, end) of the stored strings
    complete: bool  # no initialized block's stored bytes fall short of its size
    # the word index (``word_index``) and the series memo, built on first use
    _index: dict[int, list[int]] | None = None
    _sorted_words: dict[int, list[int]] = field(default_factory=dict)  # block idx -> addresses
    _word_set: set[int] = field(default_factory=set)
    _block_of: dict[int, int] = field(default_factory=dict)  # word address -> block index
    _runs: dict[int, Run | None] = field(default_factory=dict)
    _chains: dict[tuple[int, int], _Full] = field(default_factory=dict)
    _readings: dict[str, SideReading] = field(default_factory=dict)  # by the address as given

    @property
    def initialized_blocks(self) -> list[tuple[int, Block]]:
        return [(i, b) for i, b in enumerate(self.blocks) if b.initialized and b.data]

    def block_at(self, addr: int) -> tuple[int, Block] | None:
        for i, b in enumerate(self.blocks):
            if b.holds(addr):
                return i, b
        return None

    def word_at(self, addr: int, block: Block) -> int | None:
        """The word stored at ``addr`` in ``block``, or None past its stored bytes."""
        off = addr - block.start
        if off < 0 or addr + self.word_size > block.stored_end:
            return None
        raw = block.data[off : off + self.word_size]
        return int.from_bytes(raw, "little" if self.endian == "LE" else "big")

    def is_entry_word(self, addr: int, block: Block) -> bool:
        value = self.word_at(addr, block)
        return value is not None and value in self.targets

    def inside_string(self, addr: int) -> bool:
        """Whether ``[addr, addr+word_size)`` meets a stored string's range
        ``[address, address+len+1)``."""
        ranges = self.string_ranges
        i = bisect.bisect_right(ranges, (addr, float("inf"))) - 1
        if i >= 0 and ranges[i][1] > addr:
            return True
        j = i + 1
        return j < len(ranges) and ranges[j][0] < addr + self.word_size

    def nearest_label(self, addr: int, block: Block) -> dict[str, Any] | None:
        """The recorded label at or before ``addr`` in the same block, with the distance to it."""
        i = bisect.bisect_right(self.labels, (addr, "\U0010ffff")) - 1
        if i < 0:
            return None
        at, name = self.labels[i]
        if at < block.start:
            return None
        return {"name": name, "address": _hex(at), "offset": addr - at}


def _hex(addr: int) -> str:
    return f"0x{addr:x}"


def _parse_arch(arch: str | None) -> tuple[str, int] | None:
    """(endianness, word size) from ``PROC:ENDIAN:BITS[:VARIANT]``, or None."""
    parts = (arch or "").split(":")
    if len(parts) < 3 or parts[1] not in ("LE", "BE"):
        return None
    try:
        bits = int(parts[2])
    except ValueError:
        return None
    if bits not in (32, 64):
        return None
    return parts[1], bits // 8


def _merged(ranges: Iterable[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    out: list[list[int]] = []
    for start, end in sorted(ranges):
        if out and start <= out[-1][1]:
            out[-1][1] = max(out[-1][1], end)
        else:
            out.append([start, end])
    return tuple((s, e) for s, e in out)


def _labels(conn: sqlite3.Connection, binary_id: int) -> tuple[tuple[int, str], ...]:
    """Every recorded address-taken site's ``nearby_symbol`` — the only place the analysis stores a
    name for a data location."""
    try:
        rows = conn.execute(
            "SELECT address_taken FROM functions WHERE binary_id = ? "
            "AND address_taken IS NOT NULL AND address_taken != ''",
            (binary_id,),
        ).fetchall()
    except sqlite3.OperationalError:
        return ()
    found: dict[int, str] = {}
    for (raw,) in rows:
        try:
            obj = json.loads(raw)
        except (ValueError, TypeError):
            continue
        edges = obj.get("edges") if isinstance(obj, dict) else None
        for e in edges if isinstance(edges, list) else ():
            if not isinstance(e, dict):
                continue
            name, at = e.get("nearby_symbol"), _hex_addr_int(e.get("taken_at"))
            if isinstance(name, str) and name and at is not None:
                found.setdefault(at, name)
    return tuple(sorted(found.items()))


def load_image(conn: sqlite3.Connection, binary_id: int) -> Image:
    """Read one binary's image (blocks, entries, labels, strings) from its analysis.db."""
    meta = conn.execute("SELECT arch, sha256 FROM binaries WHERE id = ?", (binary_id,)).fetchone()
    arch, sha = (meta[0], meta[1]) if meta is not None else (None, None)
    entries: dict[int, tuple[str | None, str]] = {}
    for name, address in conn.execute(
        "SELECT name, address FROM functions WHERE binary_id = ?", (binary_id,)
    ):
        value = _hex_addr_int(address)
        # An entry of 0 would equal every zeroed word: it is left out of the reading.
        if value:
            entries.setdefault(value, (name, address))
    try:
        rows = conn.execute(
            "SELECT block_name, start_addr, size, bytes, initialized, executable, truncated "
            "FROM data_blocks WHERE binary_id = ? ORDER BY id",
            (binary_id,),
        ).fetchall()
    except sqlite3.OperationalError:
        rows = []
    blocks: list[Block] = []
    for name, start_s, size, data, initialized, executable, truncated in rows:
        start = _hex_addr_int(start_s)
        if start is None:
            continue
        stored = bytes(data or b"") if initialized else b""
        size = int(size or 0)
        blocks.append(
            Block(
                name=name or "",
                start=start,
                size=size,
                data=stored,
                initialized=bool(initialized),
                executable=bool(executable),
                truncated=bool(truncated) or (bool(initialized) and len(stored) < size),
                block_class=block_class(name, bool(executable)),
                stored_end=start + min(len(stored), size),
                end=start + size,
            )
        )
    blocks.sort(key=lambda b: b.start)
    parsed = _parse_arch(arch)
    unavailable = None
    if not blocks:
        unavailable = "data_blocks_not_exported"
    elif parsed is None:
        unavailable = "arch_unparsed"
    endian, word_size = parsed if parsed is not None else ("", 0)
    thumb = (arch or "").startswith("ARM:")
    targets: dict[int, int] = {}
    for entry in entries:
        targets.setdefault(entry, entry)
    if thumb:
        for entry in entries:
            targets.setdefault(entry | 1, entry)
    strings: dict[int, str] = {}
    ranges: list[tuple[int, int]] = []
    try:
        for value, address in conn.execute(
            "SELECT value, address FROM strings WHERE binary_id = ?", (binary_id,)
        ):
            at = _hex_addr_int(address)
            if at is None or value is None:
                continue
            strings.setdefault(at, value)
            ranges.append((at, at + len(value) + 1))  # the terminating NUL included
    except sqlite3.OperationalError:
        pass
    return Image(
        binary_id=binary_id,
        sha256=sha,
        unavailable=unavailable,
        endian=endian,
        word_size=word_size,
        thumb=thumb,
        entries=entries,
        targets=targets,
        blocks=tuple(blocks),
        labels=_labels(conn, binary_id),
        strings=strings,
        string_ranges=_merged(ranges),
        complete=not any(b.truncated for b in blocks if b.initialized),
    )


# ── finding the words ──────────────────────────────────────────────────────────────────────


def _words_array(raw: bytes, word_size: int, swap: bool) -> array[int]:
    """``raw`` (a whole number of words) as an array of unsigned words in native order."""
    code = "I" if word_size == 4 else "Q"
    words = array(code)
    assert words.itemsize == word_size
    words.frombytes(raw)
    if swap:
        words.byteswap()
    return words


def _block_hits(image: Image, block: Block) -> list[int]:
    """The addresses of the aligned words in ``block`` whose value is an entry — ONE pass over the
    block: the words go into an array and one ``compress`` keeps the indexes whose value is a
    target. Never a per-value search back through the block."""
    ws = image.word_size
    first = (-block.start) % ws
    usable = (block.stored_end - block.start - first) // ws
    if usable <= 0:
        return []
    raw = block.data[first : first + usable * ws]
    swap = (image.endian == "LE") != (sys.byteorder == "little")
    words = _words_array(raw, ws, swap)
    base = block.start + first
    keep = compress(range(usable), map(image.targets.__contains__, words))
    return [base + i * ws for i in keep]


def word_index(image: Image) -> dict[int, list[int]]:
    """entry -> the aligned word addresses whose value equals it (all blocks, all classes), built
    once per image."""
    if image._index is not None:
        return image._index
    index: dict[int, list[int]] = {}
    if image.unavailable is None:
        for bi, block in image.initialized_blocks:
            hits = _block_hits(image, block)
            image._sorted_words[bi] = hits
            image._word_set.update(hits)
            for addr in hits:
                image._block_of[addr] = bi
                value = image.word_at(addr, block)
                assert value is not None
                index.setdefault(image.targets[value], []).append(addr)
    image._index = index
    return index


def words_holding(image: Image, entry: int) -> list[int]:
    """The aligned word addresses whose stored value is ``entry`` (or ``entry|1`` on ARM), read
    straight from the bytes — the point query. Same answer as ``word_index`` for that entry."""
    if image.unavailable is not None:
        return []
    ws = image.word_size
    order: Literal["little", "big"] = "little" if image.endian == "LE" else "big"
    values = [entry] + ([entry | 1] if image.thumb and entry | 1 != entry else [])
    found: list[int] = []
    for _bi, block in image.initialized_blocks:
        stored = block.data[: block.stored_end - block.start]
        for value in values:
            if value >= 1 << (8 * ws):
                continue
            needle = value.to_bytes(ws, order)
            at = stored.find(needle)
            while at != -1:
                if (block.start + at) % ws == 0:
                    found.append(block.start + at)
                at = stored.find(needle, at + 1)
    return sorted(found)


# ── the series around a word ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class End:
    """Why a series stops on one side: ``word_not_entry`` / ``block_start`` / ``block_end`` /
    ``stored_bytes_end`` / ``record_cap``, at the address that stopped it (its value, when that
    word is stored, is read where it is printed)."""

    reason: str
    at: int


@dataclass(frozen=True)
class Run:
    first_word: int
    stride: int
    records: int
    slot: int
    ended_before: End
    ended_after: End

    def json(self) -> dict[str, Any]:
        return {
            "first_word": _hex(self.first_word),
            "stride": self.stride,
            "records": self.records,
            "slot": self.slot,
        }

    def shape(self) -> tuple[int, int, int]:
        return self.stride, self.records, self.slot


@dataclass(frozen=True)
class _Full:
    """The whole series through a word at one stride, uncapped: its first and last word and why it
    stops on each side."""

    first: int
    last: int
    before: End
    after: End


_Memo = dict[tuple[int, int], _Full]


def _full_chain(
    image: Image,
    block: Block,
    addr: int,
    stride: int,
    is_entry: Callable[[int], bool],
    memo: _Memo,
) -> _Full:
    """The maximal series through ``addr`` at ``stride``: back to the first word that is not an
    entry word (or the block's start), forward to the first that is not one (or the block's end /
    its stored bytes' end). Memoized for every member, so a table is walked once per stride."""
    hit = memo.get((stride, addr))
    if hit is not None:
        return hit
    ws = image.word_size
    a = addr
    while True:
        prev = a - stride
        if prev < block.start:
            before = End("block_start", prev)
            break
        if not is_entry(prev):
            before = End("word_not_entry", prev)
            break
        a = prev
    first = a
    a = addr
    while True:
        nxt = a + stride
        if nxt + ws > block.end:
            after = End("block_end", nxt)
            break
        if nxt + ws > block.stored_end:
            after = End("stored_bytes_end", nxt)
            break
        if not is_entry(nxt):
            after = End("word_not_entry", nxt)
            break
        a = nxt
    full = _Full(first, a, before, after)
    for member in range(first, a + 1, stride):
        memo[(stride, member)] = full
    return full


def _window(image: Image, block: Block, full: _Full, addr: int, stride: int) -> Run:
    """The run ``addr`` reads in: the whole series, or — past ``RUN_MAX_RECORDS`` — the cap-sized
    segment of it that holds ``addr``, counted from the series' first word, so every member of a
    long series reads the same segment whichever word it is read from."""
    total = (full.last - full.first) // stride + 1
    index = (addr - full.first) // stride
    if total <= RUN_MAX_RECORDS:
        return Run(full.first, stride, total, index, full.before, full.after)
    seg = index // RUN_MAX_RECORDS
    first = full.first + seg * RUN_MAX_RECORDS * stride
    records = min(RUN_MAX_RECORDS, total - seg * RUN_MAX_RECORDS)
    last = first + (records - 1) * stride
    before = full.before if seg == 0 else End("record_cap", first - stride)
    after = full.after if last == full.last else End("record_cap", last + stride)
    return Run(first, stride, records, index - seg * RUN_MAX_RECORDS, before, after)


def _chain(
    image: Image,
    block: Block,
    addr: int,
    stride: int,
    is_entry: Callable[[int], bool],
    memo: _Memo | None = None,
) -> Run:
    """The run through ``addr`` at ``stride`` (see ``_full_chain`` and ``_window``)."""
    full = _full_chain(image, block, addr, stride, is_entry, {} if memo is None else memo)
    return _window(image, block, full, addr, stride)


def run_around(
    image: Image,
    block: Block,
    addr: int,
    is_entry: Callable[[int], bool],
    strides: Iterable[int] | None = None,
    memo: _Memo | None = None,
) -> Run | None:
    """The smallest stride ``s`` (a multiple of the word size, at most ``MAX_STRIDE``) at which the
    entry words through ``addr`` spaced ``s`` apart number at least ``MIN_RUN``, walked out on both
    sides; None when there is none. An arrangement fact, not a reading that it is a table.

    ``strides`` (ascending) narrows the strides tried to those at which ``addr ± s`` is an entry
    word (the diff side generates them from its index, nearest first); the answer is the same as
    trying them all, since a stride with no entry word next to ``addr`` cannot give a series of
    ``MIN_RUN``. ``memo`` shares the walked series between the words of one image."""
    ws = image.word_size
    tried = strides if strides is not None else range(ws, MAX_STRIDE + 1, ws)
    for s in tried:
        if s <= 0 or s % ws or s > MAX_STRIDE:
            continue
        # A cheap filter before the walk: at most MIN_RUN - 1 words each way. It can only let
        # through a stride the walk then turns down (``is_entry`` may not stop at the block's
        # edges), never drop one that would make a series.
        near = 0
        a = addr - s
        while near < MIN_RUN - 1 and is_entry(a):
            near += 1
            a -= s
        a = addr + s
        while near < MIN_RUN - 1 and is_entry(a):
            near += 1
            a += s
        if near + 1 < MIN_RUN:
            continue
        run = _chain(image, block, addr, s, is_entry, memo)
        if run.records >= MIN_RUN:
            return run
    return None


def _point_is_entry(image: Image, block: Block) -> Callable[[int], bool]:
    """Entry-word test read from the bytes (the point query's path)."""
    return lambda a: block.start <= a and image.is_entry_word(a, block)


def _neighbour_distances(hits: list[int], addr: int) -> Iterator[int]:
    """The distances from ``addr`` to the other entry words of its block (``hits``, sorted), nearest
    first and each once, up to ``MAX_STRIDE`` — generated lazily, so a word in a dense series stops
    at the first one."""
    pos = bisect.bisect_left(hits, addr)
    left, right = pos - 1, pos + (1 if pos < len(hits) and hits[pos] == addr else 0)
    last = 0
    while True:
        dl = addr - hits[left] if left >= 0 else None
        dr = hits[right] - addr if right < len(hits) else None
        if dl is None and dr is None:
            return
        if dr is None or (dl is not None and dl <= dr):
            d, left = dl, left - 1
        else:
            d, right = dr, right + 1
        assert d is not None
        if d > MAX_STRIDE:
            if (dl is None or dl > MAX_STRIDE) and (dr is None or dr > MAX_STRIDE):
                return
            continue
        if d != last:
            last = d
            yield d


def _indexed_run(image: Image, bi: int, addr: int) -> Run | None:
    """``run_around`` on the index's path: entry words looked up in the index, and the strides
    tried narrowed to the distances to the entry words within ``MAX_STRIDE`` of ``addr``. Memoized
    per word."""
    if addr in image._runs:
        return image._runs[addr]
    block = image.blocks[bi]
    words = image._word_set
    strides = _neighbour_distances(image._sorted_words.get(bi, []), addr)
    run = run_around(image, block, addr, lambda a: a in words, strides, image._chains)
    image._runs[addr] = run
    return run


# ── one word, described ────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Word:
    address: int
    block_index: int
    block: Block
    value: int
    inside_stored_string: bool
    run: Run | None

    @property
    def comparable(self) -> bool:
        return self.block.block_class in DELTA_CLASSES and not self.inside_stored_string


def _class_rank(word: Word) -> tuple[int, int, int]:
    return (
        0 if word.comparable else 1,
        BLOCK_CLASSES.index(word.block.block_class),
        word.address,
    )


def describe(image: Image, word: Word, entry: int) -> dict[str, Any]:
    out: dict[str, Any] = {
        "address": _hex(word.address),
        "block": word.block.name,
        "block_class": word.block.block_class,
        "block_executable": word.block.executable,
    }
    if word.value != entry:
        out["thumb_bit"] = True
    out["inside_stored_string"] = word.inside_stored_string
    out["nearest_recorded_label"] = image.nearest_label(word.address, word.block)
    out["run"] = word.run.json() if word.run is not None else None
    return out


def _counts(words: list[Word]) -> dict[str, Any]:
    by_class: dict[str, int] = {}
    for w in words:
        by_class[w.block.block_class] = by_class.get(w.block.block_class, 0) + 1
    return {
        "count": len(words),
        "count_by_class": {c: by_class[c] for c in BLOCK_CLASSES if by_class.get(c)},
        "count_in_executable": by_class.get("code", 0),
        "count_inside_string": sum(1 for w in words if w.inside_stored_string),
    }


def _state(image: Image, n: int) -> tuple[str, str | None]:
    """(state, reason): found / none_found, or undetermined with why."""
    if image.unavailable is not None:
        return "undetermined", image.unavailable
    if n:
        return "found", None
    if not image.complete:
        return "undetermined", "data_blocks_truncated"
    return "none_found", None


# ── piece one: the point query, attached to get_xrefs ───────────────────────────────────────


def point_words(image: Image, entry: int) -> list[Word]:
    """Every word holding ``entry``, read from the bytes, with its series (point-query path)."""
    out: list[Word] = []
    memo: _Memo = {}
    for addr in words_holding(image, entry):
        hit = image.block_at(addr)
        assert hit is not None
        bi, block = hit
        value = image.word_at(addr, block)
        assert value is not None
        run = run_around(image, block, addr, _point_is_entry(image, block), memo=memo)
        out.append(Word(addr, bi, block, value, image.inside_string(addr), run))
    return out


def entry_words_block(image: Image, entry: int) -> dict[str, Any]:
    """The ``entry_words`` block get_xrefs carries for one function (see the module docstring)."""
    words = sorted(point_words(image, entry), key=_class_rank)
    state, reason = _state(image, len(words))
    out: dict[str, Any] = {"state": state}
    if reason is not None:
        out["reason"] = reason
    out.update(_counts(words))
    shown = words[:POINT_WORDS_SHOWN]
    out["words"] = [describe(image, w, entry) for w in shown]
    out["words_shown"] = len(shown)
    if state == "found" and not image.complete:
        out["may_be_incomplete"] = True
    out["scope"] = dict(SCOPE)
    nxt = next((w for w in words if w.comparable and w.run is not None), None)
    out["next"] = (
        {
            "tool": "get_data_table",
            "args": {"address": _hex(nxt.address), "binary": image.sha256},
        }
        if nxt is not None
        else None
    )
    return out


def _entry_words_note(block: dict[str, Any]) -> str:
    if block["state"] == "found":
        comparable = sum(block["count_by_class"].get(c, 0) for c in DELTA_CLASSES)
        return (
            f"{block['count']} data words hold this entry value: {comparable} in comparable "
            "segments (data/unnamed/init_fini), the rest in other block classes (count_by_class). "
            "A word is a stored value, not proof of a call"
        )
    if block["state"] == "none_found":
        return (
            "no aligned data word holds this entry value in the stored blocks; not proof it is "
            "uncalled"
        )
    return (
        f"the stored data words could not be read in full ({block.get('reason')}); whether one "
        "holds this entry value is undetermined"
    )


def xrefs_with_entry_words(
    conn: sqlite3.Connection, *, func: str, direction: Any, binary: str | None
) -> dict[str, Any]:
    """``facts.get_xrefs``, unchanged, plus ``entry_words`` — the aligned data words whose value is
    the function's entry — when ``callers`` comes back empty, and always on ``address_taken``. The
    original note is kept and the entry-words sentence is appended after it."""
    result = get_xrefs(conn, func=func, direction=direction, binary=binary)
    if not result.get("found"):
        return result
    if not (direction == "address_taken" or (direction == "callers" and not result.get("edges"))):
        return result
    row, _miss = _resolve_one(conn, func, binary)
    if row is None:
        return result
    entry = _hex_addr_int(row["address"])
    if entry is None:
        return result
    image = load_image(conn, row["binary_id"])
    block = entry_words_block(image, entry)
    result["entry_words"] = block
    note = _entry_words_note(block)
    result["note"] = f"{result['note']} | {note}" if result.get("note") else note
    return result


# ── piece two: get_data_table ───────────────────────────────────────────────────────────────

_TABLE_CONTRACT = (
    "RECORDS BY ENTRY-WORD SPACING. A record is cut wherever a word equal to a function entry "
    "repeats at a fixed stride; the inferred stride is the spacing between entry words, not a "
    "declared record length — a record with two function pointers reads as two records unless you "
    "pass stride. `ascii_runs`/`words` are mechanical renderings, not field names or a reading of "
    "what the table does. Whether, when and with what the code uses a slot is yours to trace."
)
_RECORD_BYTES_SHOWN = 256
_STRING_TEXT_SHOWN = 128
_ASCII_MIN = 4


def ascii_runs(raw: bytes) -> list[dict[str, Any]]:
    """Printable runs of at least ``_ASCII_MIN`` bytes, rendered as they are."""
    out: list[dict[str, Any]] = []
    i, n = 0, len(raw)
    while i < n:
        if 0x20 <= raw[i] <= 0x7E:
            j = i
            while j < n and 0x20 <= raw[j] <= 0x7E:
                j += 1
            if j - i >= _ASCII_MIN:
                out.append(
                    {
                        "offset": i,
                        "text": raw[i:j].decode("ascii"),
                        "nul_terminated": j < n and raw[j] == 0,
                    }
                )
            i = j
        else:
            i += 1
    return out


def _parse_int(value: int | str | None) -> int | None:
    """An int as given, or a string read as hex (as an address is)."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return _hex_addr_int(str(value))


def _record_bytes(block: Block, start: int, length: int) -> bytes:
    lo = max(start, block.start)
    hi = min(start + length, block.stored_end)
    if hi <= lo:
        return b""
    return block.data[lo - block.start : hi - block.start]


def _word_holds(image: Image, value: int) -> dict[str, Any] | None:
    """What a word's value equals, mechanically: a function entry, a stored string's start, or an
    address inside an exported block. None for anything else (0 included)."""
    if not value:
        return None
    entry = image.targets.get(value)
    if entry is not None:
        return {"holds": "function_entry", "name": image.entries[entry][0]}
    text = image.strings.get(value)
    if text is not None:
        return {"holds": "stored_string", "text": text[:_STRING_TEXT_SHOWN]}
    hit = image.block_at(value)
    if hit is not None:
        return {"holds": "block_address", "block": hit[1].name}
    return None


def _record(
    image: Image, block: Block, index: int, entry_addr: int, stride: int, field_offset: int
) -> dict[str, Any]:
    ws = image.word_size
    start = entry_addr - field_offset
    raw = _record_bytes(block, start, stride)
    value = image.word_at(entry_addr, block)
    assert value is not None
    entry = image.targets[value]
    name, address = image.entries[entry]
    entry_word: dict[str, Any] = {
        "offset": field_offset,
        "value_hex": f"{value:0{ws * 2}x}",
        "function": {"name": name, "address": address},
    }
    if value != entry:
        entry_word["thumb_bit"] = True
    words: list[dict[str, Any]] = []
    first = start + (-start) % ws
    for a in range(first, start + stride - ws + 1, ws):
        if a == entry_addr:
            continue
        v = image.word_at(a, block) if block.start <= a else None
        if v is None:
            continue
        holds = _word_holds(image, v)
        if holds is not None:
            words.append({"offset": a - start, "value_hex": f"{v:0{ws * 2}x}", **holds})
    out: dict[str, Any] = {
        "index": index,
        "address": _hex(start),
        "entry_word": entry_word,
        "words": words,
        "ascii_runs": ascii_runs(raw),
        "bytes": raw[:_RECORD_BYTES_SHOWN].hex(),
    }
    if len(raw) > _RECORD_BYTES_SHOWN:
        out["bytes_truncated"] = True
    if len(raw) < stride:
        out["bytes_short"] = True  # the record runs past the block's stored bytes
    return out


def _end_json(
    image: Image, block: Block, end: End, stride: int, field_offset: int, *, after: bool
) -> dict[str, Any]:
    ws = image.word_size
    value = image.word_at(end.at, block) if block.start <= end.at else None
    out: dict[str, Any] = {
        "reason": end.reason,
        "at": _hex(end.at),
        "value_hex": f"{value:0{ws * 2}x}" if value is not None else None,
    }
    if after:
        raw = _record_bytes(block, end.at - field_offset, stride)
        out["record_hex"] = raw[:_RECORD_BYTES_SHOWN].hex()
    return out


def _miss(query: dict[str, Any], note: str, detail: str, **extra: Any) -> dict[str, Any]:
    return {
        "found": False,
        "query": query,
        "note": note,
        "detail": detail,
        **extra,
        "contract": _TABLE_CONTRACT,
    }


def get_data_table(
    conn: sqlite3.Connection,
    *,
    binary: str,
    address: str,
    stride: int | str | None = None,
    field_offset: int | str | None = None,
    offset: int = 0,
    limit: int = 64,
) -> dict[str, Any]:
    """The records around a data address, cut by the spacing of the words that hold a function's
    entry (see ``_TABLE_CONTRACT``). ``stride`` / ``field_offset`` may be ints or hex strings."""
    query = {
        "binary": binary,
        "address": address,
        "stride": stride,
        "field_offset": field_offset,
        "offset": offset,
        "limit": limit,
    }
    if not 1 <= limit <= 256 or offset < 0:
        return _miss(query, "invalid_page", "limit must be 1..256 and offset >= 0")
    brow, miss = resolve_binary(conn, binary)
    if brow is None:
        assert miss is not None
        return {**miss, "query": {**query, **miss["query"]}, "contract": _TABLE_CONTRACT}
    image = load_image(conn, brow.id)
    if image.unavailable == "data_blocks_not_exported":
        return _miss(
            query,
            "data_blocks_not_exported",
            "no data-segment blocks are stored for this binary (older analysis.db, or not "
            "re-scanned since the export existed) — UNKNOWN, not 'no data'",
        )
    if image.unavailable == "arch_unparsed":
        return _miss(
            query,
            "arch_unparsed",
            "the binary's architecture names no endianness / word size this reading knows",
        )
    ws = image.word_size
    addr = _hex_addr_int(address)
    if addr is None:
        return _miss(
            query,
            "unparsable_address",
            "address must be hex (0x-prefixed or bare, as Ghidra renders it)",
        )
    given_stride = _parse_int(stride)
    if stride is not None and (
        given_stride is None or given_stride <= 0 or given_stride % ws or given_stride > MAX_STRIDE
    ):
        return _miss(
            query,
            "invalid_stride",
            f"stride must be a positive multiple of the word size ({ws}) and at most "
            f"{MAX_STRIDE:#x}",
        )
    given_offset = _parse_int(field_offset)
    if field_offset is not None and (given_offset is None or given_offset < 0):
        return _miss(query, "invalid_field_offset", "field_offset must be >= 0")
    hit = image.block_at(addr)
    if hit is None:
        return _miss(
            query,
            "address_not_in_any_data_block",
            "the address is outside every exported data block — it may be code, or space the "
            "export did not cover; this is NOT 'the bytes are zero'",
        )
    bi, block = hit
    if not block.initialized:
        return _miss(
            query,
            "uninitialized_bss",
            "value is runtime-only",
            block_name=block.name,
            start=_hex(block.start),
        )
    is_entry = _point_is_entry(image, block)
    aligned = addr + (-addr) % ws
    anchor = next(
        (
            a
            for a in range(aligned, min(aligned + MAX_STRIDE, block.stored_end - ws) + 1, ws)
            if is_entry(a)
        ),
        None,
    )
    if anchor is None:
        return _miss(
            query,
            "no_entry_word_near_address",
            "no word holding a function entry within the scan range of this address",
            scanned={"from": _hex(aligned), "to": _hex(aligned + MAX_STRIDE)},
        )
    if given_stride is not None:
        run: Run | None = _chain(image, block, anchor, given_stride, is_entry)
        stride_source = "given"
    else:
        run = run_around(image, block, anchor, is_entry)
        stride_source = "entry_word_spacing"
    if run is None:
        near = [
            _hex(a)
            for a in range(
                max(block.start + (-block.start) % ws, anchor - MAX_STRIDE),
                min(anchor + MAX_STRIDE, block.stored_end - ws) + 1,
                ws,
            )
            if a != anchor and is_entry(a)
        ][:16]
        return _miss(
            query,
            "stride_not_inferred",
            f"fewer than {MIN_RUN} entry words follow one another at any stride up to "
            f"{MAX_STRIDE:#x} through the first entry word; pass stride to read records anyway",
            anchor_word=_hex(anchor),
            nearby_entry_words=near,
        )
    s = run.stride
    if given_offset is not None:
        fo, fo_source = given_offset, "given"
        if fo >= s:
            return _miss(
                query, "invalid_field_offset", f"field_offset must be below the stride {s}"
            )
    elif addr < anchor and anchor - addr < s:
        fo, fo_source = anchor - addr, "from_address"
    else:
        fo, fo_source = 0, "default"
    total = run.records
    page = range(offset, min(offset + limit, total))
    records = [_record(image, block, i, run.first_word + i * s, s, fo) for i in page]
    out: dict[str, Any] = {
        "found": True,
        "query": query,
        "table": {
            "first_record": _hex(run.first_word - fo),
            "records": total,
            "stride": s,
            "stride_source": stride_source,
            "field_offset": fo,
            "field_offset_source": fo_source,
            "ended_before": _end_json(image, block, run.ended_before, s, fo, after=False),
            "ended_after": _end_json(image, block, run.ended_after, s, fo, after=True),
        },
        "block": {
            "name": block.name,
            "start": _hex(block.start),
            "block_class": block.block_class,
            "executable": block.executable,
            "truncated": block.truncated,
        },
        "word_size": ws,
        "endian": image.endian,
        "records": records,
        "total_records": total,
        "contract": _TABLE_CONTRACT,
    }
    if block.executable:
        out["bytes_from_executable_segment"] = True
        out["warning"] = _RX_BYTES_WARNING
    if block.truncated:
        out["block_bytes_incomplete"] = True
    return out


# ── piece three: the two sides of a diff ────────────────────────────────────────────────────


def side_words(image: Image, entry: int) -> list[Word]:
    """Every word holding ``entry`` on the index's path, in listing order (``_class_rank``). The
    series is read for the words the diff uses — every comparable word (the delta compares them)
    and the first ``DIFF_WORDS_SHOWN`` (they are shown); the rest are counted only, and their
    ``run`` is left None unread."""
    index = word_index(image)
    bare: list[Word] = []
    for addr in index.get(entry, ()):
        bi = image._block_of[addr]
        block = image.blocks[bi]
        value = image.word_at(addr, block)
        assert value is not None
        bare.append(Word(addr, bi, block, value, image.inside_string(addr), None))
    bare.sort(key=_class_rank)
    return [
        replace(w, run=_indexed_run(image, w.block_index, w.address))
        if w.comparable or i < DIFF_WORDS_SHOWN
        else w
        for i, w in enumerate(bare)
    ]


@dataclass(frozen=True)
class SideReading:
    """One side of one diff entry: its state and its words (all classes)."""

    state: str  # found / none_found / undetermined / not_in_inventory
    reason: str | None
    words: tuple[Word, ...]
    may_be_incomplete: bool

    @property
    def comparable(self) -> list[Word]:
        return sorted((w for w in self.words if w.comparable), key=lambda w: w.address)


def side_reading(image: Image | None, addr: str | None, reason: str | None = None) -> SideReading:
    """The reading of one side for the function at ``addr`` (as the diff stores it). ``image`` None
    = that side could not be read at all (``reason``)."""
    if image is None:
        return SideReading("undetermined", reason or "side_unreadable", (), False)
    key = addr or ""
    hit = image._readings.get(key)
    if hit is not None:
        return hit
    entry = _hex_addr_int(addr)
    if entry is None or entry not in image.entries:
        out = SideReading("not_in_inventory", None, (), False)
    elif image.unavailable is not None:
        out = SideReading("undetermined", image.unavailable, (), False)
    else:
        words = tuple(side_words(image, entry))
        state, why = _state(image, len(words))
        out = SideReading(state, why, words, state == "found" and not image.complete)
    image._readings[key] = out
    return out


def undetermined_for_delta(side: SideReading) -> bool:
    """A side the delta cannot read: undetermined, or an incomplete image with no comparable word
    found (none found there is not none)."""
    return side.state == "undetermined" or (side.may_be_incomplete and not side.comparable)


def entry_delta(a: SideReading, b: SideReading) -> str | None:
    """The comparison of two sides' comparable words, in this order (each step decides):
    ``not_in_inventory`` on either side; ``undetermined`` on either side; nothing comparable on
    either side (None: not rendered); ``a_only`` / ``b_only``; ``count_differs``; and
    ``run_shape_differs`` or ``same_shape`` by the (stride, records, slot) of the words paired in
    address order."""
    if a.state == "not_in_inventory" or b.state == "not_in_inventory":
        return "not_in_inventory"
    if undetermined_for_delta(a) or undetermined_for_delta(b):
        return "undetermined"
    ca, cb = a.comparable, b.comparable
    if not ca and not cb:
        return None
    if ca and not cb:
        return "a_only"
    if cb and not ca:
        return "b_only"
    if len(ca) != len(cb):
        return "count_differs"
    for wa, wb in zip(ca, cb, strict=True):
        sa = wa.run.shape() if wa.run is not None else None
        sb = wb.run.shape() if wb.run is not None else None
        if sa != sb:
            return "run_shape_differs"
    return "same_shape"


def side_json(image: Image | None, side: SideReading, entry_addr: str | None) -> dict[str, Any]:
    """One side as the diff view renders it: state, counts and up to ``DIFF_WORDS_SHOWN`` words,
    each word with the printable runs of its record when it sits in a series."""
    out: dict[str, Any] = {"state": side.state}
    if side.reason is not None:
        out["reason"] = side.reason
    out.update(_counts(list(side.words)))
    if side.may_be_incomplete:
        out["may_be_incomplete"] = True
    shown = list(side.words[:DIFF_WORDS_SHOWN])
    entry = _hex_addr_int(entry_addr) or 0
    words: list[dict[str, Any]] = []
    for w in shown:
        assert image is not None
        one = describe(image, w, entry)
        if w.run is not None:
            raw = _record_bytes(w.block, w.address, w.run.stride)
            one["record_ascii_runs"] = [{**r, "text": r["text"][:64]} for r in ascii_runs(raw)[:3]]
        words.append(one)
    out["words"] = words
    out["words_shown"] = len(words)
    return out
