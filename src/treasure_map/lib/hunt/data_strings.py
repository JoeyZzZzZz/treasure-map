# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""NUL-terminated strings read out of a binary's loaded data blocks, by address.

Why this exists: a key passed as ``&DAT_<addr>`` has no row in the extracted ``strings`` table.
Ghidra spelling the operand ``DAT_`` is exactly the statement that it never typed those bytes as a
string, so the extractor had nothing to collect — the text is only in the loaded block's bytes. The
same read ``dispatch_tables`` does for handler tables, narrowed to one address and one string.

Boundaries, stated rather than approximated:
  * only an INITIALIZED block with recorded bytes can answer; a ``.bss`` address, an address in no
    loaded block, and an address in a block the extractor truncated all read as "not resolved"
    (None) — never as an empty key, which a reader would take for a key that IS empty;
  * the bytes are decoded as UTF-8 with replacement, and a run with no NUL before the block ends is
    taken to the block end. A "string" here is whatever bytes sit at an address a caller passed as
    a key: it is firmware DATA, never trusted, and a reader is told where it came from
    (``key_origin: data_ref``) so a byte run that is not really a key reads as one it can dismiss;
  * blocks are cached per binary, at most ``_CACHE_BINARIES`` of them, because the hunt pass walks
    a binary's functions together: a third binary evicts the least recently used rather than
    letting a whole image set accumulate.
"""

from __future__ import annotations

import sqlite3
from collections import OrderedDict

_CACHE_BINARIES = 2
# A binary whose initialized blocks total more than this is NOT cached: each lookup resolves the
# single block that holds the address instead (``_string_at_uncached``), so one unusually large
# image cannot pin tens of megabytes for the rest of the pass.
_MAX_CACHED_BYTES = 64 * 1024 * 1024

# The loaded, initialized, non-truncated blocks: a truncated block's stored bytes cover LESS than
# its extent, so a NUL found (or not found) inside them is not where the real string ends — such a
# block reads as "not resolved" (see the module docstring), so it is excluded everywhere here.
_BLOCK_WHERE = (
    "binary_id = ? AND initialized = 1 AND bytes IS NOT NULL AND COALESCE(truncated, 0) = 0"
)


class DataStrings:
    """Resolve a ``&DAT_<addr>`` key to its text, per binary, over an open analysis.db.

    The connection is the caller's: this neither opens nor closes one, so it is usable inside a
    pass that already holds the database open read-only."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._blocks: OrderedDict[int, list[tuple[int, bytes]]] = OrderedDict()
        self._uncacheable: set[int] = set()  # binaries too large to cache (resolved per lookup)
        self._has_table: bool | None = None

    def string_at(self, binary_id: int, address: int) -> str | None:
        """The NUL-terminated text at ``address`` in ``binary_id``, or None when no loaded block
        holds it (see the module docstring: None means NOT RESOLVED, never an empty key)."""
        blocks = self._blocks_for(binary_id)
        if blocks is None:  # too large to cache: resolve the single block that holds the address
            return self._string_at_uncached(binary_id, address)
        for start, data in blocks:
            if start <= address < start + len(data):
                return _slice_string(data, address - start)
        return None

    def _blocks_for(self, binary_id: int) -> list[tuple[int, bytes]] | None:
        """This binary's cached blocks, or None when it is too large to cache."""
        if binary_id in self._uncacheable:
            return None
        cached = self._blocks.get(binary_id)
        if cached is not None:
            self._blocks.move_to_end(binary_id)
            return cached
        blocks = self._load(binary_id)
        if blocks is None:
            self._uncacheable.add(binary_id)
            return None
        self._blocks[binary_id] = blocks
        while len(self._blocks) > _CACHE_BINARIES:
            self._blocks.popitem(last=False)
        return blocks

    def _table_present(self) -> bool:
        if self._has_table is None:
            self._has_table = bool(
                self._conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='data_blocks'"
                ).fetchone()
            )
        return self._has_table

    def _load(self, binary_id: int) -> list[tuple[int, bytes]] | None:
        """This binary's loaded blocks in a stable (``start_addr``) order, or None when their bytes
        total more than ``_MAX_CACHED_BYTES`` — then the caller resolves one block per lookup
        instead, so a single huge image is never pinned."""
        if not self._table_present():
            return []  # a database built before data_blocks: nothing resolves, nothing raises
        # Decide cacheability from sizes alone, no bytes pulled.
        total = self._conn.execute(
            f"SELECT COALESCE(SUM(length(bytes)), 0) FROM data_blocks WHERE {_BLOCK_WHERE}",
            (binary_id,),
        ).fetchone()[0]
        if total > _MAX_CACHED_BYTES:
            return None
        out: list[tuple[int, bytes]] = []
        for start, data in self._conn.execute(
            f"SELECT start_addr, bytes FROM data_blocks WHERE {_BLOCK_WHERE} ORDER BY start_addr",
            (binary_id,),
        ):
            addr = _hex_addr(start)
            if addr is None:
                continue  # an overlay / non-loaded space ("name::addr"): no key sits there
            out.append((addr, bytes(data)))
        return out

    def _string_at_uncached(self, binary_id: int, address: int) -> str | None:
        """Resolve one address in a binary too large to cache: the single block holding it, fetched
        on its own. Block extents are read from metadata (``length(bytes)``, no bytes pulled) to
        find the container, then that one block's bytes are read."""
        if not self._table_present():
            return None
        for block_id, start, nbytes in self._conn.execute(
            f"SELECT id, start_addr, length(bytes) FROM data_blocks WHERE {_BLOCK_WHERE}",
            (binary_id,),
        ):
            addr = _hex_addr(start)
            if addr is None or not (addr <= address < addr + nbytes):
                continue
            row = self._conn.execute(
                "SELECT bytes FROM data_blocks WHERE id = ?", (block_id,)
            ).fetchone()
            if row is None or row[0] is None:
                return None
            return _slice_string(bytes(row[0]), address - addr)
        return None


def _slice_string(raw: bytes, off: int) -> str:
    """The NUL-terminated run at ``off`` in ``raw``, to the block end if no NUL, UTF-8 with
    replacement. One decoder for both the cached and the per-lookup paths."""
    end = raw.find(b"\x00", off)
    return raw[off : end if end != -1 else len(raw)].decode("utf-8", "replace")


def _hex_addr(value: object) -> int | None:
    try:
        return int(str(value), 16)
    except (TypeError, ValueError):
        return None
