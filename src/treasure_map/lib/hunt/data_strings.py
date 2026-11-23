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
# A block is worth caching only up to this size; a larger one is read per lookup instead, so one
# unusually large segment cannot pin tens of megabytes for the rest of the pass.
_MAX_CACHED_BYTES = 64 * 1024 * 1024


class DataStrings:
    """Resolve a ``&DAT_<addr>`` key to its text, per binary, over an open analysis.db.

    The connection is the caller's: this neither opens nor closes one, so it is usable inside a
    pass that already holds the database open read-only."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._blocks: OrderedDict[int, list[tuple[int, bytes]]] = OrderedDict()
        self._has_table: bool | None = None

    def string_at(self, binary_id: int, address: int) -> str | None:
        """The NUL-terminated text at ``address`` in ``binary_id``, or None when no loaded block
        holds it (see the module docstring: None means NOT RESOLVED, never an empty key)."""
        for start, data in self._blocks_for(binary_id):
            if start <= address < start + len(data):
                off = address - start
                end = data.find(b"\x00", off)
                raw = data[off : end if end != -1 else len(data)]
                return raw.decode("utf-8", "replace")
        return None

    def _blocks_for(self, binary_id: int) -> list[tuple[int, bytes]]:
        cached = self._blocks.get(binary_id)
        if cached is not None:
            self._blocks.move_to_end(binary_id)
            return cached
        blocks = self._load(binary_id)
        self._blocks[binary_id] = blocks
        while len(self._blocks) > _CACHE_BINARIES:
            self._blocks.popitem(last=False)
        return blocks

    def _load(self, binary_id: int) -> list[tuple[int, bytes]]:
        if self._has_table is None:
            self._has_table = bool(
                self._conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='data_blocks'"
                ).fetchone()
            )
        if not self._has_table:
            return []  # a database built before data_blocks: nothing resolves, nothing raises
        out: list[tuple[int, bytes]] = []
        total = 0
        for start, data in self._conn.execute(
            "SELECT start_addr, bytes FROM data_blocks "
            "WHERE binary_id = ? AND initialized = 1 AND bytes IS NOT NULL",
            (binary_id,),
        ):
            addr = _hex_addr(start)
            if addr is None:
                continue  # an overlay / non-loaded space ("name::addr"): no key sits there
            raw = bytes(data)
            total += len(raw)
            if total > _MAX_CACHED_BYTES:
                break
            out.append((addr, raw))
        return out


def _hex_addr(value: object) -> int | None:
    try:
        return int(str(value), 16)
    except (TypeError, ValueError):
        return None
