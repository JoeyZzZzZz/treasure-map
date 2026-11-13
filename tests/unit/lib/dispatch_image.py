"""A synthetic stored image for the hunt-time dispatch-table reader's tests.

Lays out, for one binary of an analysis.db, three stored blocks the way the extractor records them
(``data_blocks``): an executable ``.text`` holding the functions (filled with a non-printable byte,
so no code reads as a string), a ``.rodata`` of NUL-terminated strings, and a ``.data`` of pointer
words — plus the ``functions`` rows and, optionally, the thunk spans and the extractor's own
``string_tables`` rows. No Ghidra, no ELF: the reader reads only these rows. Every name is
synthetic.
"""

from __future__ import annotations

import json
import sqlite3
import struct
from dataclasses import dataclass, field

TEXT_BASE = 0x10000
RODATA_BASE = 0x20000
DATA_BASE = 0x30000
FILL = 0xCC  # a code byte that is never printable


@dataclass
class Image:
    ps: int = 4
    big_endian: bool = False
    arch: str | None = None
    text: bytearray = field(default_factory=bytearray)
    rodata: bytearray = field(default_factory=bytearray)
    data: bytearray = field(default_factory=bytearray)
    functions: list[tuple[int, str, int, str]] = field(default_factory=list)
    thunks: list[int] = field(default_factory=list)
    pseudocode: dict[str, str] = field(default_factory=dict)
    truncated_data: bool = False

    # ── layout ──────────────────────────────────────────────────────────────────────────────
    def func(self, name: str, size: int = 16, origin: str = "analysis") -> int:
        addr = TEXT_BASE + len(self.text)
        self.text += bytes([FILL]) * size
        self.functions.append((addr, name, size, origin))
        return addr

    def thunk(self, size: int = 16) -> int:
        addr = TEXT_BASE + len(self.text)
        self.text += bytes([FILL]) * size
        self.thunks.append(addr)
        return addr

    def code(self, size: int = 16) -> int:
        """Executable bytes no function owns (an undefined handler target)."""
        addr = TEXT_BASE + len(self.text)
        self.text += bytes([FILL]) * size
        return addr

    def string(self, text: str | bytes) -> int:
        raw = text.encode() if isinstance(text, str) else text
        addr = RODATA_BASE + len(self.rodata)
        self.rodata += raw + b"\0"
        return addr

    def raw(self, blob: bytes, align: int = 1) -> int:
        """Raw ``.rodata`` bytes (aligned), returned at their first byte."""
        while len(self.rodata) % align:
            self.rodata += b"\0"
        addr = RODATA_BASE + len(self.rodata)
        self.rodata += blob
        return addr

    def wide(self, text: str) -> int:
        """A wide (4-byte) string in this image's byte order, 4-aligned, with its zero unit."""
        enc = "utf-32-be" if self.big_endian else "utf-32-le"
        return self.raw(text.encode(enc) + b"\0\0\0\0", align=4)

    def words(self, *values: int) -> int:
        """Pointer-sized words appended to ``.data``; the address of the first."""
        addr = DATA_BASE + len(self.data)
        fmt = (">" if self.big_endian else "<") + ("I" if self.ps == 4 else "Q")
        for v in values:
            self.data += struct.pack(fmt, v)
        return addr

    def word_at(self, i: int) -> int:
        return DATA_BASE + i * self.ps

    # ── into an analysis.db ─────────────────────────────────────────────────────────────────
    def write(
        self,
        conn: sqlite3.Connection,
        bid: int,
        *,
        name: str = "fx_bin",
        path: str | None = None,
        sha256: str | None = None,
        java: list[dict[str, object]] | None = None,
    ) -> None:
        conn.execute(
            "INSERT INTO binaries (id, name, path, sha256, ghidra_ok) VALUES (?, ?, ?, ?, 1)",
            (bid, name, path if path is not None else f"/fx/{name}", sha256 or f"{bid:064x}"),
        )
        self.write_contents(conn, bid, java=java)

    def write_contents(
        self, conn: sqlite3.Connection, bid: int, *, java: list[dict[str, object]] | None = None
    ) -> None:
        """The image of an existing binaries row: its arch, bits and thunk spans, the stored
        blocks, the functions and (optionally) the extractor's string_tables rows."""
        arch = self.arch or (
            ("x86:LE:64:default" if self.ps == 8 else "x86:LE:32:default")
            if not self.big_endian
            else "MIPS:BE:32:default"
        )
        conn.execute(
            "UPDATE binaries SET arch = ?, bits = ?, thunk_spans = ? WHERE id = ?",
            (
                arch,
                8 * self.ps,
                json.dumps([[f"0x{a:x}", [[f"0x{a:x}", f"0x{a + 15:x}"]]] for a in self.thunks]),
                bid,
            ),
        )
        for bname, base, blob, ex, trunc in (
            (".text", TEXT_BASE, self.text, 1, 0),
            (".rodata", RODATA_BASE, self.rodata, 0, 0),
            (".data", DATA_BASE, self.data, 0, int(self.truncated_data)),
        ):
            if not blob:
                continue
            conn.execute(
                "INSERT INTO data_blocks (binary_id, block_name, start_addr, size, bytes, "
                "initialized, executable, truncated) VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
                (
                    bid,
                    bname,
                    f"0x{base:x}",
                    len(blob) + (64 if trunc else 0),
                    bytes(blob),
                    ex,
                    trunc,
                ),
            )
        for addr, fname, size, origin in self.functions:
            conn.execute(
                "INSERT INTO functions (binary_id, name, address, pseudocode, callees, "
                "body_ranges, origin) VALUES (?, ?, ?, ?, '[]', ?, ?)",
                (
                    bid,
                    fname,
                    f"{addr:08x}",
                    self.pseudocode.get(fname, f"void {fname}(void) {{ }}"),
                    json.dumps([[f"0x{addr:x}", f"0x{addr + size - 1:x}"]]),
                    origin,
                ),
            )
        for row in java or []:
            conn.execute(
                "INSERT INTO string_tables (binary_id, table_addr, stride, entry_index, key, "
                "func_name, func_addr, func_kind, completeness_status, completeness_reason, "
                "completeness_scope) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'incomplete', 'scope_only', "
                "'absolute_2field_only')",
                (
                    bid,
                    row["table_addr"],
                    row.get("stride", 2 * self.ps),
                    row["entry_index"],
                    row.get("key"),
                    row.get("func_name"),
                    row.get("func_addr"),
                    row.get("func_kind", "direct"),
                ),
            )
