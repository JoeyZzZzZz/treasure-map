# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Stored data words whose value is a function's entry address (lib/query/entry_words).

Zero real data: every binary, address, block and function name is synthetic. Each image is a
hand-built analysis.db (``functions`` + ``data_blocks`` + ``strings``), so every case the reading
distinguishes — byte order, the ARM Thumb form, an executable or a truncated block, the block
classes, a word inside a stored string — is set out byte by byte. The diff side is read through
get_diff_patch_view on a small atlas of its own.
"""

from __future__ import annotations

import json
import re
import sqlite3
from array import array
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from treasure_map import mcp_app
from treasure_map.cli import mcp_cli
from treasure_map.lib import facts
from treasure_map.lib.analyze.ghidra_runner import current_pass_version
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.query import entry_words as ew
from treasure_map.lib.query import patch_view as pv
from treasure_map.lib.storage.connection import open_db
from treasure_map.version import UNKNOWN_VERSION

SHA = "5" * 64


class Bin:
    """One synthetic binary in its own analysis.db."""

    def __init__(self, path: Path, arch: str | None, *, sha: str = SHA, name: str = "libsyn"):
        self.path = path
        self.conn = open_db(path)
        self.conn.execute("PRAGMA synchronous = OFF")
        self.bid = int(
            self.conn.execute(
                "INSERT INTO binaries (name, path, sha256, arch) VALUES (?, ?, ?, ?)",
                (name, f"/fw/lib/{name}", sha, arch),
            ).lastrowid
            or 0
        )
        self.sha = sha
        self.be = arch is not None and ":BE:" in arch

    def fn(self, addr: int, name: str, taken: list[dict[str, Any]] | None = None) -> int:
        self.conn.execute(
            "INSERT INTO functions (binary_id, name, address, callees, address_taken) "
            "VALUES (?, ?, ?, '[]', ?)",
            (self.bid, name, f"{addr:08x}", json.dumps({"edges": taken or [], "truncated": False})),
        )
        return addr

    def block(
        self,
        name: str,
        start: int,
        data: bytes,
        *,
        size: int | None = None,
        executable: int = 0,
        truncated: int = 0,
        initialized: int = 1,
    ) -> None:
        self.conn.execute(
            "INSERT INTO data_blocks (binary_id, block_name, start_addr, size, bytes, initialized, "
            "executable, truncated) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                self.bid,
                name,
                f"0x{start:x}",
                len(data) if size is None else size,
                data if initialized else None,
                initialized,
                executable,
                truncated,
            ),
        )

    def string(self, addr: int, value: str) -> None:
        self.conn.execute(
            "INSERT INTO strings (binary_id, value, address, category) VALUES (?, ?, ?, 'misc')",
            (self.bid, value, f"{addr:08x}"),
        )

    def w(self, *values: int) -> bytes:
        return b"".join(v.to_bytes(4, "big" if self.be else "little") for v in values)

    def ro(self) -> sqlite3.Connection:
        self.conn.commit()
        return facts.open_analysis_ro(self.path)

    def image(self) -> ew.Image:
        conn = self.ro()
        try:
            return ew.load_image(conn, self.bid)
        finally:
            conn.close()


def _point(b: Bin, func: str, direction: str = "callers") -> dict[str, Any]:
    conn = b.ro()
    try:
        return ew.xrefs_with_entry_words(conn, func=func, direction=direction, binary=None)
    finally:
        conn.close()


def _table(b: Bin, address: str, **kw: Any) -> dict[str, Any]:
    conn = b.ro()
    try:
        return ew.get_data_table(conn, binary=b.sha, address=address, **kw)
    finally:
        conn.close()


def _addrs(block: dict[str, Any]) -> list[str]:
    return [w["address"] for w in block["words"]]


# ── tbl_be32: a big-endian table, stride 0x10, six records ───────────────────────────────────

BE_FNS = [0x00400100 + 0x40 * i for i in range(6)]
TBL = 0x10010  # the table's first record


def _be32(tmp_path: Path) -> Bin:
    """``.data`` at 0x10000: a zero word, then six 16-byte records (an entry word, then 12 bytes of
    ASCII with its NUL), then zeros. ``.rodata`` starts off the word grid (0x20002): it holds
    fn_0's entry at an aligned address and fn_1's at an unaligned one. fn_0 records a label at the
    table's base."""
    b = Bin(tmp_path / "be32.db", "MIPS:BE:32:default")
    b.fn(BE_FNS[0], "fn_0", [{"taken_at": f"{TBL:08x}", "nearby_symbol": "PTR_tbl_00010010"}])
    for i, a in enumerate(BE_FNS[1:], start=1):
        b.fn(a, f"fn_{i}")
    records = b"".join(b.w(a) + f"name_{i}_abc".encode() + b"\0\0" for i, a in enumerate(BE_FNS))
    assert len(records) == 6 * 16
    b.block(".data", 0x10000, b"\0" * 0x10 + records + b"\0" * 0x10)
    b.block(".rodata", 0x20002, b"\0\0" + b.w(BE_FNS[0]) + b"\0" + b.w(BE_FNS[1]) + b"\0" * 7)
    return b


def test_be32_words_are_aligned_and_in_both_byte_orders_of_reading(tmp_path: Path) -> None:
    """Only word-aligned words are read, in the binary's byte order; the point query (bytes) and
    the index (one pass per block) find the same words.

    MUTATIONS (verified RED): drop the alignment test in ``words_holding`` -> fn_1's unaligned copy
    is found; read the index from the block start instead of its first aligned word -> fn_0's
    .rodata word is missed; leave a big-endian block unswapped in ``_block_hits`` -> no hit."""
    b = _be32(tmp_path)
    image = b.image()
    index = ew.word_index(image)
    assert ew.words_holding(image, BE_FNS[0]) == [TBL, 0x20004]
    assert ew.words_holding(image, BE_FNS[1]) == [TBL + 0x10]
    assert sorted(index.get(BE_FNS[0], [])) == [TBL, 0x20004]
    assert sorted(index.get(BE_FNS[1], [])) == [TBL + 0x10]


def test_be32_series_and_label(tmp_path: Path) -> None:
    """The series is the smallest spacing with at least four entry words, walked to its ends; the
    nearest recorded label at or before a word is named with its distance."""
    b = _be32(tmp_path)
    out = _point(b, "fn_2")
    block = out["entry_words"]
    assert block["state"] == "found" and block["count"] == 1
    (word,) = block["words"]
    assert word["address"] == "0x10030" and word["block_class"] == "data"
    assert word["run"] == {"first_word": "0x10010", "stride": 16, "records": 6, "slot": 2}
    assert word["nearest_recorded_label"] == {
        "name": "PTR_tbl_00010010",
        "address": "0x10010",
        "offset": 0x20,
    }
    assert block["next"] == {
        "tool": "get_data_table",
        "surface": "mcp",
        "args": {"address": "0x10030", "binary": SHA},
    }
    # fn_0: the label sits on its own .data word; its .rodata word is in another block -> none
    words = _point(b, "fn_0")["entry_words"]["words"]
    labels = {w["block"]: w["nearest_recorded_label"] for w in words}
    assert labels[".data"] == {"name": "PTR_tbl_00010010", "address": "0x10010", "offset": 0}
    assert labels[".rodata"] is None


def test_be32_table_decodes_six_records(tmp_path: Path) -> None:
    b = _be32(tmp_path)
    t = _table(b, "0x10030")
    assert t["found"] is True and t["total_records"] == 6
    table = t["table"]
    assert table["stride"] == 16 and table["stride_source"] == "entry_word_spacing"
    assert table["field_offset"] == 0 and table["field_offset_source"] == "default"
    assert table["first_record"] == "0x10010"
    assert table["ended_before"] == {
        "reason": "word_not_entry",
        "at": "0x10000",
        "value_hex": "00000000",
    }
    after = table["ended_after"]
    assert after["reason"] == "word_not_entry" and after["at"] == "0x10070"
    assert after["record_hex"] == "00" * 16
    assert [r["entry_word"]["function"]["name"] for r in t["records"]] == [
        f"fn_{i}" for i in range(6)
    ]
    rec = t["records"][2]
    assert rec["address"] == "0x10030" and rec["entry_word"]["value_hex"] == f"{BE_FNS[2]:08x}"
    assert rec["ascii_runs"] == [{"offset": 4, "text": "name_2_abc", "nul_terminated": True}]
    assert (
        rec["bytes"]
        == (b"\0" * 0).hex() + bytes.fromhex(f"{BE_FNS[2]:08x}").hex() + (b"name_2_abc\0\0").hex()
    )
    assert t["word_size"] == 4 and t["endian"] == "BE" and t["block"]["block_class"] == "data"
    assert "bytes_from_executable_segment" not in t


def test_be32_table_field_offset_and_given_stride(tmp_path: Path) -> None:
    """``field_offset`` moves where a record starts (given, or the distance from ``address`` to
    the entry word); ``stride`` may be given as a hex string and then needs no four-word series."""
    b = _be32(tmp_path)
    t = _table(b, "0x1000c")  # 4 bytes before the first entry word
    assert t["table"]["field_offset"] == 4 and t["table"]["field_offset_source"] == "from_address"
    assert t["table"]["first_record"] == "0x1000c" and t["records"][0]["address"] == "0x1000c"
    assert t["records"][0]["entry_word"]["offset"] == 4
    t = _table(b, "0x10010", field_offset=8)
    assert t["table"]["first_record"] == "0x10008" and t["table"]["field_offset_source"] == "given"
    t = _table(b, "0x10010", stride="0x10")
    assert t.get("found") is True, t
    assert t["table"]["stride_source"] == "given" and t["total_records"] == 6
    t = _table(b, "0x10010", stride="0x20")
    assert t["total_records"] == 3  # fn_0, fn_2, fn_4
    assert _table(b, "0x10010", stride=6)["note"] == "invalid_stride"
    assert _table(b, "0x10010", stride="0x800")["note"] == "invalid_stride"


def test_be32_table_pages_by_record(tmp_path: Path) -> None:
    b = _be32(tmp_path)
    t = _table(b, "0x10010", offset=4, limit=2)
    assert [r["index"] for r in t["records"]] == [4, 5] and t["total_records"] == 6
    assert _table(b, "0x10010", limit=0)["note"] == "invalid_page"


def test_a_field_offset_at_or_past_the_stride_is_refused(tmp_path: Path) -> None:
    """A given field_offset must lie inside one record: at or past the stride it is
    ``invalid_field_offset``, not a table read from another record's bytes.

    MUTATION (verified RED): drop the ``fo >= s`` check -> a table comes back -> RED."""
    b = _be32(tmp_path)
    assert _table(b, "0x10010", field_offset=15).get("found") is True
    for fo in (16, 17):
        assert _table(b, "0x10010", field_offset=fo).get("note") == "invalid_field_offset", fo


def test_an_address_in_bss_is_uninitialized_as_get_data_bytes_says(tmp_path: Path) -> None:
    """An address inside a .bss extent (an uninitialized block, no bytes stored) is
    ``uninitialized_bss`` for get_data_table, the same name get_data_bytes gives it.

    MUTATION (verified RED): drop the ``initialized`` check -> the table reads on and names
    another reason -> RED."""
    b = _be32(tmp_path)
    b.block(".bss", 0x30000, b"", size=0x100, initialized=0)
    t = _table(b, "0x30010")
    conn = b.ro()
    try:
        raw = facts.get_data_bytes(conn, binary=SHA, address="0x30010", length=4)
    finally:
        conn.close()
    assert t.get("note") == "uninitialized_bss" == raw.get("note"), (t, raw)


def test_a_function_at_address_zero_is_not_read_in_a_diff(tmp_path: Path) -> None:
    """An entry of 0 would equal every zeroed word, so a diff side never reads it: the function
    at 0 is not_in_inventory there, beside a function whose one word is read as found.

    MUTATION (verified RED): keep an entry of 0 (``if value is not None``) -> the zero function
    reads found with every zero word -> RED."""
    b = Bin(tmp_path / "z.db", "MIPS:LE:32:default")
    b.fn(0, "zero_fn")
    b.fn(0x400100, "real_fn")
    b.block(".data", 0x10000, b"\0" * 0x40 + b.w(0x400100) + b"\0" * 0x40)
    image = b.image()
    zero = ew.side_reading(image, "00000000")
    assert (zero.state, zero.words) == ("not_in_inventory", ())
    assert ew.side_reading(image, "00400100").state == "found"


def test_a_point_query_shows_twenty_words_and_counts_them_all(tmp_path: Path) -> None:
    """A function whose entry is in 21 aligned words: the point query counts 21 and lists the
    first ``POINT_WORDS_SHOWN`` (20), words_shown saying so.

    MUTATION (verified RED): drop the ``[:POINT_WORDS_SHOWN]`` cut -> 21 words listed -> RED."""
    b = Bin(tmp_path / "many.db", "MIPS:LE:32:default")
    b.fn(0x400100, "many_fn")
    b.block(".data", 0x10000, b"".join(b.w(0x400100) + b"\0" * 0x3C for _ in range(21)))
    block = _point(b, "many_fn")["entry_words"]
    assert ew.POINT_WORDS_SHOWN == 20
    assert block["count"] == 21
    assert len(block["words"]) == block["words_shown"] == 20


# ── tbl_le32_thumb: ARM, entries stored as entry|1 ───────────────────────────────────────────

THUMB_FNS = [0x8000 + 0x20 * i for i in range(5)]


def _thumb(tmp_path: Path) -> Bin:
    b = Bin(tmp_path / "thumb.db", "ARM:LE:32:v7")
    for i, a in enumerate(THUMB_FNS):
        b.fn(a, f"th_{i}")
    b.block(".data", 0x30000, b"\0" * 4 + b.w(*(a | 1 for a in THUMB_FNS)) + b"\0" * 4)
    return b


def test_thumb_entry_words_are_read_and_flagged(tmp_path: Path) -> None:
    """On ARM a word equal to entry|1 holds that entry too, and says so (``thumb_bit``).

    MUTATION (verified RED): stop adding entry|1 to the ARM targets -> no word found."""
    b = _thumb(tmp_path)
    block = _point(b, "th_1")["entry_words"]
    assert block["state"] == "found"
    (word,) = block["words"]
    assert word["thumb_bit"] is True and word["address"] == "0x30008"
    assert word["run"] == {"first_word": "0x30004", "stride": 4, "records": 5, "slot": 1}
    t = _table(b, "0x30004")
    assert t["total_records"] == 5
    assert t["records"][1]["entry_word"]["thumb_bit"] is True
    assert t["records"][1]["entry_word"]["function"]["name"] == "th_1"
    assert sorted(ew.word_index(b.image())[THUMB_FNS[1]]) == [0x30008]


# ── tbl_rx: an executable block ──────────────────────────────────────────────────────────────


def test_rx_words_are_code_counted_and_never_next(tmp_path: Path) -> None:
    b = Bin(tmp_path / "rx.db", "MIPS:LE:32:default")
    fns = [b.fn(0x400000 + 0x10 * i, f"rx_{i}") for i in range(5)]
    b.block(".text", 0x400000, b.w(*fns) + b"\0" * 12, executable=1)
    block = _point(b, "rx_2")["entry_words"]
    assert block["count_by_class"] == {"code": 1} and block["count_in_executable"] == 1
    (word,) = block["words"]
    assert word["block_class"] == "code" and word["block_executable"] is True
    assert block["next"] is None
    t = _table(b, "0x400000")
    assert t["block"]["block_class"] == "code" and t["bytes_from_executable_segment"] is True
    assert t["warning"] == facts._RX_BYTES_WARNING


def test_get_data_bytes_and_the_table_share_one_rx_warning(tmp_path: Path) -> None:
    b = Bin(tmp_path / "rx.db", "MIPS:LE:32:default")
    b.fn(0x400000, "rx_0")
    b.block(".text", 0x400000, b"\0" * 16, executable=1)
    conn = b.ro()
    try:
        out = facts.get_data_bytes(conn, binary=SHA, address="0x400000", length=4)
    finally:
        conn.close()
    assert out["warning"] == facts._RX_BYTES_WARNING


# ── tbl_truncated: a block stored short of its size ──────────────────────────────────────────


def test_truncated_image_never_says_none_found(tmp_path: Path) -> None:
    """A word found in an incomplete image is given with ``may_be_incomplete``; nothing found there
    is ``undetermined`` (data_blocks_truncated), never none_found.

    MUTATION (verified RED): return none_found for 0 hits on an incomplete image -> RED."""
    b = Bin(tmp_path / "trunc.db", "MIPS:LE:32:default")
    fns = [b.fn(0x400000 + 0x10 * i, f"tr_{i}") for i in range(4)]
    later = b.fn(0x400100, "tr_later")  # its word would lie past the stored bytes
    b.block(".data", 0x10000, b.w(*fns) + b"\0" * 0x30, size=0x100, truncated=1)
    found = _point(b, "tr_0")["entry_words"]
    assert found["state"] == "found" and found["may_be_incomplete"] is True
    missing = _point(b, "tr_later")["entry_words"]
    assert missing["state"] == "undetermined" and missing["reason"] == "data_blocks_truncated"
    assert "not proof" not in _point(b, "tr_later")["note"].split(" | ")[-1]
    assert later and _table(b, "0x10000")["block_bytes_incomplete"] is True


# ── tbl_isolated / none / no blocks / bad arch ───────────────────────────────────────────────


def test_isolated_word_has_no_series_and_the_table_says_why(tmp_path: Path) -> None:
    b = Bin(tmp_path / "iso.db", "MIPS:LE:32:default")
    one = b.fn(0x400000, "iso_0")
    two = b.fn(0x400040, "iso_1")
    b.block(".data", 0x10000, b"\0" * 8 + b.w(one) + b"\0" * 0x3C + b.w(two) + b"\0" * 8)
    (word,) = _point(b, "iso_0")["entry_words"]["words"]
    assert word["run"] is None
    assert _point(b, "iso_0")["entry_words"]["next"] is None
    t = _table(b, "0x10008")
    assert t["note"] == "stride_not_inferred" and t["anchor_word"] == "0x10008"
    assert t["nearby_entry_words"] == ["0x10048"]


def test_none_found_no_blocks_and_bad_arch(tmp_path: Path) -> None:
    none = Bin(tmp_path / "none.db", "MIPS:LE:32:default")
    none.fn(0x400000, "lonely")
    none.block(".data", 0x10000, b"\0" * 32)
    out = _point(none, "lonely")
    assert out["entry_words"]["state"] == "none_found"
    assert out["note"].endswith("not proof it is uncalled")

    bare = Bin(tmp_path / "bare.db", "MIPS:LE:32:default")
    bare.fn(0x400000, "lonely")
    block = _point(bare, "lonely")["entry_words"]
    assert block["state"] == "undetermined" and block["reason"] == "data_blocks_not_exported"
    assert _table(bare, "0x10000")["note"] == "data_blocks_not_exported"

    odd = Bin(tmp_path / "odd.db", None)
    odd.fn(0x400000, "lonely")
    odd.block(".data", 0x10000, b"\0" * 32)
    block = _point(odd, "lonely")["entry_words"]
    assert block["state"] == "undetermined" and block["reason"] == "arch_unparsed"
    assert _table(odd, "0x10000")["note"] == "arch_unparsed"


# ── block classes ────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("name", "executable", "expected"),
    [
        (".got", 0, "linkage"),
        (".got.plt", 0, "linkage"),
        (".plt", 0, "linkage"),
        (".rel.dyn", 0, "linkage"),
        (".rela.plt", 0, "linkage"),
        (".dynamic", 0, "linkage"),
        (".hash", 0, "linkage"),
        (".gnu.hash", 0, "linkage"),
        (".gnu.version_r", 0, "linkage"),
        (".dynsym", 0, "symbol_table"),
        (".symtab", 0, "symbol_table"),
        (".dynstr", 0, "symbol_table"),
        (".strtab", 0, "symbol_table"),
        (".shstrtab", 0, "symbol_table"),
        (".eh_frame", 0, "unwind"),
        (".eh_frame_hdr", 0, "unwind"),
        (".gcc_except_table", 0, "unwind"),
        (".ARM.exidx", 0, "unwind"),
        (".ARM.extab", 0, "unwind"),
        (".init_array", 0, "init_fini"),
        (".fini_array", 0, "init_fini"),
        (".preinit_array", 0, "init_fini"),
        (".ctors", 0, "init_fini"),
        (".dtors", 0, "init_fini"),
        ("", 0, "unnamed"),
        ("segment_2", 0, "unnamed"),
        ("segment_2.1", 0, "unnamed"),
        (".data", 0, "data"),
        (".data.rel.ro", 0, "data"),
        (".rodata", 0, "data"),
        ("__libc_IO_vtables", 0, "data"),
        ("__cmd", 0, "data"),
        (".data", 1, "code"),
        (".got", 1, "code"),
    ],
)
def test_block_class_by_name(name: str, executable: int, expected: str) -> None:
    assert ew.block_class(name, bool(executable)) == expected


def _classes(tmp_path: Path) -> Bin:
    """fn_0..fn_4 in a .dynsym (16-byte symbols, the value at offset 4), a .got (one word each) and
    a .data table (8-byte records)."""
    b = Bin(tmp_path / "classes.db", "MIPS:LE:32:default")
    fns = [b.fn(0x400000 + 0x40 * i, f"cl_{i}") for i in range(5)]
    sym = b"".join(b.w(0x100 + i, a, 0x40, 0x12) for i, a in enumerate(fns))
    meta_only = [b.fn(0x500000 + 0x40 * i, f"mo_{i}") for i in range(4)]
    sym += b"".join(b.w(0x200 + i, a, 0x40, 0x12) for i, a in enumerate(meta_only))
    b.block(".dynsym", 0x1000, b"\0" * 16 + sym)
    b.block(".got", 0x2000, b.w(0, *fns, *meta_only, 0))
    b.block(".data", 0x3000, b.w(0, *(v for a in fns for v in (a, 0x77))) + b"\0" * 4)
    return b


def test_classes_are_counted_apart_and_only_data_is_next(tmp_path: Path) -> None:
    """Link and symbol-table words are counted per class and listed after the comparable ones;
    ``next`` names the data table, never the symbol table.

    MUTATION (verified RED): let a linkage / symbol_table word count as comparable -> ``next``
    points at .dynsym (it is listed first by address)."""
    b = _classes(tmp_path)
    block = _point(b, "cl_2")["entry_words"]
    assert block["count"] == 3
    assert block["count_by_class"] == {"data": 1, "linkage": 1, "symbol_table": 1}
    assert [w["block_class"] for w in block["words"]] == ["data", "linkage", "symbol_table"]
    assert block["next"]["args"]["address"] == block["words"][0]["address"]
    assert block["words"][0]["block"] == ".data"
    by_block = {w["block"]: w["run"] for w in block["words"]}
    assert by_block[".dynsym"]["stride"] == 16 and by_block[".got"]["stride"] == 4
    assert by_block[".data"]["stride"] == 8
    assert "1 in comparable segments" in _point(b, "cl_2")["note"]
    meta = _point(b, "mo_1")["entry_words"]
    assert meta["count_by_class"] == {"linkage": 1, "symbol_table": 1}
    assert all(w["run"] for w in meta["words"]) and meta["next"] is None


def _string_coincidence(tmp_path: Path) -> Bin:
    """A function at 0x41424344 ("ABCD" big-endian). ``.rodata`` holds a stored string whose
    aligned bytes 4..7 are "ABCD"; ``.dynstr`` holds the same bytes; a ``.data`` table also holds
    the entry. Function fn_s sits in no data word at all."""
    b = Bin(tmp_path / "strs.db", "MIPS:BE:32:default")
    target = b.fn(0x41424344, "ascii_fn")
    others = [b.fn(0x400000 + 0x40 * i, f"o_{i}") for i in range(3)]
    b.block(".rodata", 0x5000, b"xxxxABCDyyy\0")
    b.string(0x5000, "xxxxABCDyyy")
    b.block(".dynstr", 0x6000, b"\0\0\0\0ABCD\0\0\0\0")
    b.block(".data", 0x7000, b.w(0, target, *others, 0))
    return b


def test_a_word_inside_a_stored_string_is_counted_not_compared(tmp_path: Path) -> None:
    """A word whose bytes lie inside a stored string is flagged, counted, listed after the
    comparable words and never offered as ``next``; ``.dynstr`` is a symbol-table block.

    MUTATION (verified RED): do not exclude inside-string words from the comparable set -> the
    .rodata word (lowest address) is listed first and becomes ``next``."""
    b = _string_coincidence(tmp_path)
    block = _point(b, "ascii_fn")["entry_words"]
    assert block["count_by_class"] == {"data": 2, "symbol_table": 1}
    assert block["count_inside_string"] == 1
    first = block["words"][0]
    assert first["block"] == ".data" and first["inside_stored_string"] is False
    inside = next(w for w in block["words"] if w["block"] == ".rodata")
    assert inside["inside_stored_string"] is True and inside["block_class"] == "data"
    assert block["next"]["args"]["address"] == "0x7004"
    image = b.image()
    assert image.inside_string(0x5004) and image.inside_string(0x5008)  # the NUL counts
    assert not image.inside_string(0x500C)


def _init_fini(tmp_path: Path) -> Bin:
    b = Bin(tmp_path / "initfini.db", "ARM:LE:32:v7")
    fns = [b.fn(0x9000 + 0x20 * i, f"if_{i}") for i in range(4)]
    only = b.fn(0x9800, "if_only")
    b.block(".init_array", 0x4000, b.w(*fns, only))
    b.block(".data", 0x5000, b.w(0, *(v for a in fns for v in (a, 0)), 0))
    return b


def test_init_fini_is_comparable_and_after_data(tmp_path: Path) -> None:
    """init_fini words are comparable (they can be ``next``) and come after data / unnamed.

    MUTATION (verified RED): leave init_fini out of DELTA_CLASSES -> if_only has no ``next``."""
    b = _init_fini(tmp_path)
    block = _point(b, "if_1")["entry_words"]
    assert [w["block_class"] for w in block["words"]] == ["data", "init_fini"]
    assert block["next"]["args"]["address"] == block["words"][0]["address"]
    only = _point(b, "if_only")["entry_words"]
    assert only["words"][0]["block_class"] == "init_fini"
    assert only["next"] is not None and only["next"]["args"]["address"] == "0x4010"


def test_unnamed_segments_compare_and_executable_ones_count(tmp_path: Path) -> None:
    """On an only-segment-name binary the read/write segment is ``unnamed`` (comparable); the
    executable one is ``code``, counted, with no ``next``."""
    b = Bin(tmp_path / "segs.db", "MIPS:LE:32:default")
    fns = [b.fn(0x400000 + 0x40 * i, f"sg_{i}") for i in range(4)]
    rx_only = b.fn(0x400800, "sg_rx")
    b.block("segment_0", 0x400000, b.w(0, *fns, rx_only, rx_only, rx_only, 0), executable=1)
    b.block("segment_1", 0x480000, b.w(0, *fns, 0))
    block = _point(b, "sg_1")["entry_words"]
    assert [w["block_class"] for w in block["words"]] == ["unnamed", "code"]
    assert block["next"]["args"]["address"] == block["words"][0]["address"]
    rx = _point(b, "sg_rx")["entry_words"]
    assert rx["count_in_executable"] == 3 and rx["next"] is None
    assert "unnamed" in pv._CAVEATS["entry_words"] and "`code`" in pv._CAVEATS["entry_words"]


# ── the two paths agree; the index reads each block once ─────────────────────────────────────


def _all_fixtures(tmp_path: Path) -> list[Bin]:
    out = []
    for i, make in enumerate((_be32, _thumb, _classes, _string_coincidence, _init_fini)):
        d = tmp_path / f"f{i}"
        d.mkdir()
        out.append(make(d))
    return out


def test_point_query_equals_the_index(tmp_path: Path) -> None:
    """For every entry of every fixture, the point query (bytes) and the index give the same words,
    the same series, the same block class and the same inside-string flag."""
    checked = 0
    for b in _all_fixtures(tmp_path):
        image = b.image()
        index = ew.word_index(image)
        for entry, (_name, addr) in image.entries.items():
            point = {w.address: w for w in ew.point_words(image, entry)}
            assert sorted(point) == sorted(index.get(entry, []))
            side = {w.address: w for w in ew.side_words(image, entry)}
            assert sorted(side) == sorted(point)
            for a, w in point.items():
                s = side[a]
                if s.comparable or s.run is not None:
                    assert ew._indexed_run(image, s.block_index, a) == w.run, (b.path, a)
                assert (s.block.block_class, s.inside_stored_string) == (
                    w.block.block_class,
                    w.inside_stored_string,
                )
                checked += 1
            assert ew.side_reading(image, addr).state in ("found", "none_found")
    assert checked > 30


class _NoIndex(array):  # type: ignore[type-arg]
    """An array whose ``index`` may not be called: the index is one pass, never a search back."""

    def index(self, *args: Any, **kw: Any) -> int:  # noqa: ARG002
        raise AssertionError("word_index searched the block back by value")


def test_the_index_scans_each_block_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Structural, not timed: a big hit count is located in one pass per block — never by a
    per-value ``array.index`` back through the block.

    MUTATION (verified RED): locate each hit with ``words.index(value)`` -> the guard array
    raises."""
    b = Bin(tmp_path / "big.db", "MIPS:LE:32:default")
    fns = [b.fn(0x400000 + 0x10 * i, f"big_{i}") for i in range(3000)]
    b.block(".data", 0x10000, b.w(0, *fns, 0))
    b.block(".got", 0x40000, b.w(*fns[:500]))
    real = ew._words_array
    calls = {"n": 0}

    def guarded(raw: bytes, word_size: int, swap: bool) -> array[int]:
        calls["n"] += 1
        words = real(raw, word_size, swap)
        out = _NoIndex(words.typecode)
        out.frombytes(words.tobytes())
        return out

    monkeypatch.setattr(ew, "_words_array", guarded)
    index = ew.word_index(b.image())
    assert calls["n"] == 2  # one per initialized block
    assert len(index) == 3000 and sum(map(len, index.values())) == 3500


def test_a_long_series_is_cut_into_the_same_segment_from_any_member(tmp_path: Path) -> None:
    """Past RUN_MAX_RECORDS a series is read in cap-sized segments counted from its first word, so
    every member reads the same segment whichever path reads it."""
    b = Bin(tmp_path / "long.db", "MIPS:LE:32:default")
    n = ew.RUN_MAX_RECORDS + 10
    fns = [b.fn(0x400000 + 0x10 * i, f"lg_{i}") for i in range(n)]
    b.block(".data", 0x100000, b.w(0, *fns, 0))
    image = b.image()
    ew.word_index(image)
    last = fns[-1]
    (w,) = ew.side_words(image, last)
    assert w.run is not None
    assert w.run.records == 10 and w.run.slot == 9
    assert w.run.ended_before.reason == "record_cap"
    (p,) = ew.point_words(image, last)
    assert p.run == w.run


# ── get_xrefs: the original answer is untouched ──────────────────────────────────────────────


def test_xrefs_with_entry_words_only_adds(tmp_path: Path) -> None:
    """With the entry_words block and the appended note sentence taken away, the answer is
    facts.get_xrefs' own; ``callees`` and a ``callers`` answer with an edge carry no block."""
    b = _be32(tmp_path)
    b.conn.execute(
        "UPDATE functions SET callees = '[\"fn_3\"]' WHERE name = 'fn_4'"
    )  # fn_3 has a direct caller
    conn = b.ro()
    try:
        for func, direction in (
            ("fn_2", "callers"),
            ("fn_2", "address_taken"),
            ("fn_3", "callers"),
            ("fn_2", "callees"),
        ):
            got = ew.xrefs_with_entry_words(conn, func=func, direction=direction, binary=None)
            base = facts.get_xrefs(conn, func=func, direction=direction, binary=None)  # type: ignore[arg-type]
            attached = "entry_words" in got
            assert attached == (
                direction == "address_taken" or (func, direction) == ("fn_2", "callers")
            )
            if attached:
                got = dict(got)
                del got["entry_words"]
                note = got["note"].rsplit(" | ", 1)
                got["note"] = note[0]
                if "note" not in base:
                    assert len(note) == 1
                    del got["note"]
            assert got == base, (func, direction)
    finally:
        conn.close()


def test_cli_xrefs_matches_the_lib(tmp_path: Path) -> None:
    b = _be32(tmp_path)
    b.conn.commit()
    res = CliRunner().invoke(
        mcp_cli.fact, ["xrefs", "fn_2", "--analysis-db", str(b.path)], catch_exceptions=False
    )
    assert res.exit_code == 0, res.output
    out = json.loads(res.output)
    out.pop("stale_extract_warning", None)
    assert out == _point(b, "fn_2")


# ── the diff side ────────────────────────────────────────────────────────────────────────────

DIFF = "runA::runB::libsyn"
SHA_A, SHA_B = "a" * 64, "b" * 64


class DiffWorld:
    """One diff of ``libsyn`` between runA and runB, each side its own analysis.db with blocks."""

    def __init__(self, tmp: Path) -> None:
        self.atlas = open_atlas(tmp / "atlas.db")
        self.side: dict[str, Bin] = {}
        for s, run, sha in (("a", "runA", SHA_A), ("b", "runB", SHA_B)):
            self.side[s] = Bin(tmp / f"analysis_{s}.db", "MIPS:LE:32:default", sha=sha)
            self.atlas.execute(
                "INSERT INTO run (run_id, hunt_commit, build_hash, hunt_instances, "
                "analysis_db_path) VALUES (?, 'facade', ?, 10, ?)",
                (run, current_pass_version(), str(self.side[s].path)),
            )
        self.atlas.execute(
            "INSERT INTO diff_meta (diff_id, run_a_id, run_b_id, binary_a, binary_b, sha256_a, "
            "sha256_b, diff_ok, version_skew) VALUES (?, 'runA', 'runB', 'libsyn', 'libsyn', ?, ?, "
            "1, 0)",
            (DIFF, SHA_A, SHA_B),
        )

    def pair(self, a: int, b: int, sim: float) -> None:
        self.atlas.execute(
            "INSERT INTO function_alignment (diff_id, addr_a, addr_b, alignment_confidence, "
            "similarity, alignment_state) VALUES (?, ?, ?, 0.97, ?, 'aligned')",
            (DIFF, f"{a:08x}", f"{b:08x}", sim),
        )

    def view(self, **kw: Any) -> dict[str, Any]:
        for b in self.side.values():
            b.conn.commit()
        self.atlas.commit()
        return pv.get_diff_patch_view(self.atlas, DIFF, limit=200, **kw)


@pytest.fixture
def current(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        pv,
        "diff_source_staleness",
        lambda atlas, diff_id: {
            "source_stale": False,
            "source_stale_reason": None,
            "toolchain_checked": True,
        },
    )
    pv._clear_view_caches()


# Per side: a .data table of 8-byte records at 0x10000 (``table``), plus the other blocks the case
# names. Function addresses are the same on both sides; listed pairs have similarity 0.8.
_LISTED = 0.8
_SAME = 1.0


def _table_bytes(b: Bin, fns: list[int]) -> bytes:
    return b.w(0, *(v for a in fns for v in (a, 0x55))) + b"\0" * 4


def _diff_world(tmp_path: Path) -> tuple[DiffWorld, dict[str, int]]:
    """The cases, one function each (the same entry address on both sides):

    - ``same``: in the shared table at the same slot on both sides -> same_shape
    - ``shape``: in the table, at slot 1 on A and slot 2 on B -> run_shape_differs
    - ``count``: one word on A, two on B -> count_differs
    - ``a_only`` / ``b_only``: a comparable word on one side only
    - ``meta``: .dynsym / .got words that differ between the sides, one equal comparable word
      each -> same_shape (the metadata difference stays in each side's count_by_class)
    - ``strcoin``: a word inside a stored string, different on the two sides -> no delta
    - ``initf``: an .init_array word on A only -> a_only (init_fini is comparable)
    - ``inv``: not in B's functions table -> not_in_inventory (not rendered)
    - ``gotb``: a comparable word on A; on B only a .got word -> a_only (on an incomplete B
      image: undetermined, since nothing comparable found there is not none)
    Each also as a similarity-1 (not listed) pair, at +0x100000."""
    w = DiffWorld(tmp_path)
    names = ["same", "shape", "count", "a_only", "b_only", "meta", "strcoin", "initf", "inv"]
    names.append("gotb")
    fn: dict[str, int] = {}
    for i, n in enumerate(names):
        for shift, sim in ((0, _LISTED), (0x100000, _SAME)):
            addr = 0x400000 + shift + 0x100 * i
            key = n if not shift else f"{n}_nl"
            fn[key] = addr
            for side, b in w.side.items():
                if n == "inv" and side == "b":
                    continue
                b.fn(addr, key)
            w.pair(addr, addr, sim)
    filler = [0x480000 + 0x10 * i for i in range(4)]
    for b in w.side.values():
        for i, a in enumerate(filler):
            b.fn(a, f"fill_{i}")

    def table(side: str) -> list[int]:
        # same / same_nl keep slots 1 / 2 on both sides; shape / shape_nl sit one slot later on B
        head = [filler[0], fn["same"], fn["same_nl"]]
        if side == "a":
            return [*head, fn["shape"], fn["shape_nl"], filler[1], filler[2], filler[3]]
        return [*head, filler[1], fn["shape"], fn["shape_nl"], filler[2], filler[3]]

    for side, b in w.side.items():
        b.block(".data", 0x10000, _table_bytes(b, table(side)))
        extra = [fn["count"], fn["count_nl"]] * (1 if side == "a" else 2)
        if side == "a":
            extra += [fn["a_only"], fn["a_only_nl"], fn["gotb"], fn["gotb_nl"]]
        else:
            extra += [fn["b_only"], fn["b_only_nl"]]
        extra += [fn["meta"], fn["meta_nl"], fn["inv"], fn["inv_nl"]]
        # isolated words, 0x404 apart: farther than MAX_STRIDE, so no two make a series
        iso = b"".join(b.w(a) + b"\0" * 0x400 for a in extra)
        b.block(".sdata", 0x20000, iso)
        n_meta = 1 if side == "a" else 3
        b.block(
            ".dynsym",
            0x30000,
            b"".join(b.w(0, m, 0, 0) for m in [fn["meta"], fn["meta_nl"]] * n_meta),
        )
        got = [fn["meta"], fn["meta_nl"]] * n_meta
        if side == "b":
            got += [0, fn["gotb"], 0, fn["gotb_nl"]]
        b.block(".got", 0x31000, b.w(*got))
        # a stored string holding strcoin's entry bytes, on A once, on B twice
        payload = b"txt:" + b.w(fn["strcoin"]) + b.w(fn["strcoin_nl"])
        text = payload * (1 if side == "a" else 2)
        b.block(".rodata", 0x40000, text + b"\0")
        b.string(0x40000, text.decode("latin-1"))
        if side == "a":
            b.block(".init_array", 0x50000, b.w(fn["initf"], fn["initf_nl"]))
    return w, fn


def _by_addr(view: dict[str, Any], fn: dict[str, int]) -> dict[str, dict[str, Any]]:
    out = {}
    for name, addr in fn.items():
        eid = f"pair:{addr:08x}:{addr:08x}"
        hit = [e for e in view["entries"] if e["entry_id"] == eid]
        if hit:
            out[name] = hit[0]
    return out


def test_diff_entry_words_delta_per_case(tmp_path: Path, current: None) -> None:
    """Each listed pair's delta is read from the comparable words only: metadata classes and
    inside-string words never make one; init_fini does; a function missing from one side's
    inventory is counted apart, not as undetermined, and not rendered.

    MUTATIONS (verified RED): compare linkage / symbol_table words -> ``meta`` renders a delta;
    stop excluding inside-string words -> ``strcoin`` renders a delta; drop init_fini from the
    comparable classes -> ``initf`` is not rendered; fold not_in_inventory into undetermined -> the
    counts move."""
    w, fn = _diff_world(tmp_path)
    view = w.view()
    by = _by_addr(view, fn)
    assert {k for k in by if not k.endswith("_nl")} == set(fn) - {
        k for k in fn if k.endswith("_nl")
    }
    deltas = {k: (e.get("entry_words") or {}).get("delta") for k, e in by.items()}
    assert deltas == {
        "same": "same_shape",
        "shape": "run_shape_differs",
        "count": "count_differs",
        "a_only": "a_only",
        "b_only": "b_only",
        "meta": "same_shape",
        "strcoin": None,
        "initf": "a_only",
        "inv": None,
        "gotb": "a_only",
    }
    counts = view["entry_words_counts"]
    assert counts["listed"] == {
        "a_only": 3,
        "b_only": 1,
        "count_differs": 1,
        "run_shape_differs": 1,
        "same_shape": 2,
        "not_in_inventory": 1,
    }
    assert counts["not_listed"] == {
        "a_only": 3,
        "b_only": 1,
        "count_differs": 1,
        "run_shape_differs": 1,
        "not_in_inventory": 1,
    }
    meta = by["meta"]["entry_words"]
    assert meta["a"]["count_by_class"] == {"data": 1, "linkage": 1, "symbol_table": 1}
    assert meta["b"]["count_by_class"] == {"data": 1, "linkage": 3, "symbol_table": 3}
    assert "entry_words" not in by["strcoin"] and "entry_words" not in by["inv"]
    shape = by["shape"]["entry_words"]
    assert shape["a"]["words"][0]["run"]["slot"] != shape["b"]["words"][0]["run"]["slot"]
    assert shape["a"]["words"][0]["record_ascii_runs"] == []
    assert set(shape["a"]) >= {"state", "count", "count_by_class", "words", "words_shown"}


def test_diff_side_truncated_is_undetermined(tmp_path: Path, current: None) -> None:
    """A side whose image is stored short, with nothing comparable found, cannot say none: the pair
    is ``undetermined`` and rendered."""
    w, fn = _diff_world(tmp_path)
    w.side["b"].block(".bss_like", 0x90000, b"\0" * 8, size=0x100, truncated=1)
    view = w.view()
    by = _by_addr(view, fn)
    assert by["a_only"]["entry_words"]["delta"] == "undetermined"
    assert by["a_only"]["entry_words"]["b"]["state"] == "undetermined"
    assert by["a_only"]["entry_words"]["b"]["reason"] == "data_blocks_truncated"
    # B holds a .got word for gotb: found, but nothing comparable on an incomplete image
    gotb = by["gotb"]["entry_words"]
    assert gotb["delta"] == "undetermined" and gotb["b"]["state"] == "found"
    assert gotb["b"]["may_be_incomplete"] is True
    assert view["entry_words_counts"]["listed"]["undetermined"] >= 1


def test_diff_side_unreadable_is_said_once(tmp_path: Path, current: None) -> None:
    """A side with no exported blocks at all is named once on the envelope; its entries are counted
    as undetermined and not rendered one by one."""
    w, fn = _diff_world(tmp_path)
    w.side["b"].conn.execute("DELETE FROM data_blocks")
    view = w.view()
    assert view["entry_words_counts"]["unavailable"] == {"b": "data_blocks_not_exported"}
    assert not any("entry_words" in e for e in view["entries"])
    assert view["entry_words_counts"]["listed"]["undetermined"] == 9  # all but inv


def _set_arch(w: DiffWorld, arch: str | None) -> None:
    for b in w.side.values():
        b.conn.execute("UPDATE binaries SET arch = ?", (arch,))
        b.conn.commit()
    pv._clear_view_caches()


def test_diff_entry_words_change_nothing_else(tmp_path: Path, current: None) -> None:
    """Rendering entry_words moves no bucket, order, total or other field: with the side images
    unreadable (nothing rendered) and readable, every sort order gives the same entries but for the
    entry_words key, and its summary page the same entries, with the same envelope counts. A
    judgement written while nothing was
    rendered stays concluded once entry_words is: it is not part of what a judgement rests on.

    MUTATION (verified RED): put the entry's entry_words into its judgement facts
    (diff_review.entry_facts) -> the judged entry reads needs_recheck."""
    from treasure_map.lib import overlay

    w, fn = _diff_world(tmp_path)
    shape_anchor = f"runA::runB#function_pair#libsyn::{fn['shape']:08x}::{fn['shape']:08x}"
    _set_arch(w, None)
    w.view()
    overlay.annotate_diff(
        w.atlas,
        diff_id=DIFF,
        anchor_ref=shape_anchor,
        verdict="changed_real",
        rationale="read both sides",
    )
    for sort_by in (None, "candidate_tier", "address", "similarity"):
        kw = {} if sort_by is None else {"sort_by": sort_by}
        _set_arch(w, None)
        without = w.view(**kw)
        _set_arch(w, "MIPS:LE:32:default")
        with_words = w.view(**kw)
        summary = w.view(detail="summary", **kw)
        assert summary.get("entry_words_counts") == with_words["entry_words_counts"]
        assert [e["entry_id"] for e in summary["entries"]] == [
            e["entry_id"] for e in with_words["entries"]
        ]
        assert any("entry_words" in e for e in with_words["entries"])
        assert [e["entry_id"] for e in with_words["entries"]] == [
            e["entry_id"] for e in without["entries"]
        ]
        assert with_words["counts"] == without["counts"]
        assert with_words["total_entries"] == without["total_entries"]
        for a, b in zip(with_words["entries"], without["entries"], strict=True):
            assert {k: v for k, v in a.items() if k != "entry_words"} == b
    judged = _by_addr(w.view(), fn)["shape"]
    assert "entry_words" in judged and judged["review_state"] == "concluded"


def test_a_summary_page_carries_entry_words_as_counts(tmp_path: Path, current: None) -> None:
    """A summary entry carries entry_words wherever its full entry does, reduced to the delta and
    each side's state / reason / count / count_by_class / may_be_incomplete with no word listed
    (the field rules of test_patch_view, the whole entry compared); a function with no counterpart
    keeps its one side; the envelope's entry_words_counts is the full page's, on the summary too.

    MUTATIONS (verified RED): words only on a full page again -> no summary block or counts;
    copy the whole block -> words reach the summary; leave count_by_class out -> the meta pair's
    linkage words are lost; leave may_be_incomplete or reason out -> the truncated side loses it;
    leave delta out -> RED; drop the counts from a summary envelope -> RED."""
    from tests.unit.lib.test_patch_view import _S_ENTRY_KEYS, _S_NEVER, _deep_keys, _rules_summary

    w, fn = _diff_world(tmp_path)
    ponly = w.side["a"].fn(0x470000, "ponly")
    w.side["a"].block(".data.ponly", 0x60000, w.side["a"].w(ponly))
    w.atlas.execute(
        "INSERT INTO function_presence (diff_id, side, addr, presence_state) "
        "VALUES (?, 'a', ?, 'absent')",
        (DIFF, f"{ponly:08x}"),
    )

    def check() -> dict[str, dict[str, Any]]:
        full = w.view(rows_limit=0)
        summary = w.view(detail="summary")
        assert summary.get("entry_words_counts") == full["entry_words_counts"]
        assert full["entry_words_counts"]["listed"]
        f_by = {e["entry_id"]: e for e in full["entries"]}
        s_by = {e["entry_id"]: e for e in summary["entries"]}
        assert list(s_by) == list(f_by)
        for eid, s in s_by.items():
            assert s == _rules_summary(f_by[eid], False), eid
            assert set(s) <= _S_ENTRY_KEYS and not _deep_keys(s) & _S_NEVER, eid
            assert ("entry_words" in s) == ("entry_words" in f_by[eid]), eid
        assert sum("entry_words" in s for s in s_by.values()) >= 8
        return s_by

    s_by = check()
    by = {
        k: s_by[f"pair:{a:08x}:{a:08x}"] for k, a in fn.items() if f"pair:{a:08x}:{a:08x}" in s_by
    }
    assert by["shape"]["entry_words"] == {
        "delta": "run_shape_differs",
        "a": {"state": "found", "count": 1, "count_by_class": {"data": 1}},
        "b": {"state": "found", "count": 1, "count_by_class": {"data": 1}},
    }
    meta = by["meta"]["entry_words"]
    assert meta["delta"] == "same_shape"
    assert meta["b"]["count_by_class"] == {"data": 1, "linkage": 3, "symbol_table": 3}
    p_entry = s_by[f"a:{ponly:08x}"]
    assert p_entry["bucket"] == "P"
    assert p_entry["entry_words"] == {
        "a": {"state": "found", "count": 1, "count_by_class": {"data": 1}}
    }

    w.side["b"].block(".bss_like", 0x90000, b"\0" * 8, size=0x100, truncated=1)
    pv._clear_view_caches()
    s_by = check()
    gotb = s_by[f"pair:{fn['gotb']:08x}:{fn['gotb']:08x}"]["entry_words"]
    assert gotb["delta"] == "undetermined"
    assert gotb["b"].get("may_be_incomplete") is True
    a_only = s_by[f"pair:{fn['a_only']:08x}:{fn['a_only']:08x}"]["entry_words"]
    assert a_only["b"].get("reason") == "data_blocks_truncated"


def test_a_function_with_no_counterpart_renders_only_a_word_or_an_unknown(
    tmp_path: Path, current: None
) -> None:
    """A function with no counterpart renders its one side when that side holds a comparable word
    (or cannot say); one read in full with no comparable word renders nothing.

    MUTATION (verified RED): render every such side (``if True:``) -> the wordless one renders ->
    RED."""
    w, _fn = _diff_world(tmp_path)
    a = w.side["a"]
    with_word, without = a.fn(0x470000, "pword"), a.fn(0x470100, "pnone")
    a.block(".data.p", 0x60000, a.w(with_word))
    for addr in (with_word, without):
        w.atlas.execute(
            "INSERT INTO function_presence (diff_id, side, addr, presence_state) "
            "VALUES (?, 'a', ?, 'absent')",
            (DIFF, f"{addr:08x}"),
        )
    by_id = {e["entry_id"]: e for e in w.view()["entries"]}
    assert by_id[f"a:{with_word:08x}"]["entry_words"]["a"]["state"] == "found"
    assert by_id[f"a:{without:08x}"]["bucket"] == "P"
    assert "entry_words" not in by_id[f"a:{without:08x}"]


def test_not_in_inventory_is_named_before_an_unreadable_other_side() -> None:
    """A side missing from its inventory names the pair not_in_inventory even when the other side
    could not be read at all, whichever side is which: it is counted apart, never folded into
    undetermined.

    MUTATION (verified RED): decide undetermined before not_in_inventory -> RED."""
    missing = ew.SideReading("not_in_inventory", None, (), False)
    unreadable = ew.side_reading(None, "00400000", "side_unreadable")
    assert unreadable.state == "undetermined"
    assert ew.entry_delta(missing, unreadable) == "not_in_inventory"
    assert ew.entry_delta(unreadable, missing) == "not_in_inventory"


def test_an_unreadable_side_still_counts_a_missing_function_apart(
    tmp_path: Path, current: None
) -> None:
    """With the A side unreadable as a whole, the pair whose function B's inventory lacks is
    still counted not_in_inventory, the rest undetermined.

    MUTATION (verified RED): decide undetermined before not_in_inventory -> RED."""
    w, _fn = _diff_world(tmp_path)
    w.side["a"].conn.execute("DELETE FROM data_blocks")
    counts = w.view()["entry_words_counts"]
    assert counts["unavailable"] == {"a": "data_blocks_not_exported"}
    assert counts["listed"] == {"undetermined": 9, "not_in_inventory": 1}


def test_a_diff_side_shows_five_words_and_counts_them_all(tmp_path: Path, current: None) -> None:
    """A function whose entry is in six aligned words on each side: each side counts 6 and lists
    the first ``DIFF_WORDS_SHOWN`` (5).

    MUTATION (verified RED): drop the ``[:DIFF_WORDS_SHOWN]`` cut -> six words listed -> RED."""
    w, fn = _diff_world(tmp_path)
    for b in w.side.values():
        b.block(".data.many", 0x70000, b"".join(b.w(fn["same"]) + b"\0" * 0x3C for _ in range(5)))
    block = _by_addr(w.view(), fn)["same"]["entry_words"]
    assert ew.DIFF_WORDS_SHOWN == 5
    for side in ("a", "b"):
        assert block[side]["count"] == 6, side
        assert len(block[side]["words"]) == block[side]["words_shown"] == 5, side


def test_a_side_read_from_a_truncated_image_never_reads_same_shape(
    tmp_path: Path, current: None
) -> None:
    """Two sides whose comparable words agree in number and shape read same_shape — unless a side
    was read from an incomplete image, whose stored-short blocks could hide a word or cut a series:
    then undetermined. A difference read there is still given.

    MUTATION (verified RED): give same_shape whatever the images -> RED."""
    w, fn = _diff_world(tmp_path)
    by = _by_addr(w.view(), fn)
    assert by["same"]["entry_words"]["delta"] == "same_shape"
    w.side["b"].block(".bss_like", 0x90000, b"\0" * 8, size=0x100, truncated=1)
    pv._clear_view_caches()
    by = _by_addr(w.view(), fn)
    same = by["same"]["entry_words"]
    assert same["delta"] == "undetermined"
    assert same["b"]["may_be_incomplete"] is True and same["b"]["state"] == "found"
    assert by["shape"]["entry_words"]["delta"] == "run_shape_differs"
    assert by["count"]["entry_words"]["delta"] == "count_differs"


@pytest.mark.parametrize("view", ["string_edge", "candidate_flat"])
@pytest.mark.parametrize("detail", ["full", "summary"])
def test_the_other_views_carry_no_entry_words(
    tmp_path: Path, current: None, monkeypatch: pytest.MonkeyPatch, view: str, detail: str
) -> None:
    """entry_words belongs to the function-pair view: the string_edge and candidate_flat views, full
    or summary, carry neither the envelope's entry_words_counts nor an entry's block (and read no
    side image for it), on a diff whose sink_patch page carries both.

    MUTATION (verified RED, 4 failed): compute entry_words on every view -> RED."""
    w, _fn = _diff_world(tmp_path)
    assert "entry_words_counts" in w.view()
    calls: list[str] = []
    real = pv._entry_words_view

    def spy(atlas: Any, built: Any) -> Any:
        calls.append("read")
        return real(atlas, built)

    monkeypatch.setattr(pv, "_entry_words_view", spy)
    out = w.view(view=view, detail=detail)
    assert "error" not in out, out
    assert "entry_words_counts" not in out
    assert not any("entry_words" in e for e in out.get("entries") or ())
    assert calls == []


def test_entry_words_labels_say_nothing_of_what_a_change_means(
    tmp_path: Path, current: None
) -> None:
    """Every new key and value — the seven block classes, each delta, not_in_inventory, the side
    states and reasons — and the legend / caveat texts are free of words that say what a change
    means."""
    w, _fn = _diff_world(tmp_path)
    view = w.view()
    labels: set[str] = set(ew.BLOCK_CLASSES) | {"not_in_inventory"}
    labels |= set(view["entry_words_counts"]["listed"]) | set(
        view["entry_words_counts"]["not_listed"]
    )
    for e in view["entries"]:
        block = e.get("entry_words") or {}
        labels |= set(block) | {str(block.get("delta"))}
        for side in ("a", "b"):
            one = block.get(side) or {}
            labels |= set(one) | {str(one.get("state")), str(one.get("reason"))}
            labels |= set(one.get("count_by_class") or {})
            for word in one.get("words") or ():
                labels |= set(word) | set(word.get("run") or {})
    assert {"same_shape", "run_shape_differs", "a_only", "count_differs"} <= labels
    banned = {
        "removed",
        "added",
        "gone",
        "new",
        "reach",
        "reachable",
        "unreachable",
        "dead",
        "lost",
        "blocked",
        "safe",
        "fix",
        "patch",
        "regression",
    }
    for label in labels:
        parts = set(label.lower().replace("-", "_").split("_"))
        assert not parts & banned, label
    for text in (pv._LEGEND["entry_words"], pv._CAVEATS["entry_words"]):
        words = set(re.split(r"[^a-z0-9]+", text.lower()))
        assert not words & {"removed", "added", "unreachable", "dead", "lost", "blocked"}, text


# ── MCP: the tools, the next step's run, the page budget ─────────────────────────────────────


def _mcp_world(tmp_path: Path) -> Path:
    b = _be32(tmp_path)
    b.conn.execute("UPDATE binaries SET pass_version = ?", (current_pass_version(),))
    b.conn.commit()
    atlas = open_atlas(tmp_path / "atlas.db")
    atlas.execute(
        "INSERT INTO run (run_id, hunt_commit, build_hash, hunt_instances, analysis_db_path) "
        "VALUES ('run_t', 'facade', ?, 1, ?)",
        (current_pass_version(), str(b.path)),
    )
    atlas.commit()
    atlas.close()
    return tmp_path / "atlas.db"


def test_mcp_get_xrefs_next_names_the_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mcp_app, "_installed_commit", lambda: UNKNOWN_VERSION)
    tools = mcp_app.make_tools(_mcp_world(tmp_path))
    out = tools["get_xrefs"](function="fn_2", run_id="run_t")
    step = out["entry_words"]["next"]
    assert step["surface"] == "mcp"
    assert step["args"] == {"address": "0x10030", "binary": SHA, "run_id": "run_t"}
    table = tools[step["tool"]](**step["args"])
    assert table["total_records"] == 6 and table["resolved_run"] == "run_t"
    assert table["next_offset"] is None and table["truncated_by_bytes"] is False


def test_mcp_get_data_table_takes_hex_strings_and_fits_the_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``stride`` / ``field_offset`` as hex strings pass the tool's own schema; a page of large
    records stays within the response budget and resumes where it stopped."""
    import asyncio

    monkeypatch.setattr(mcp_app, "_installed_commit", lambda: UNKNOWN_VERSION)
    atlas = _mcp_world(tmp_path)
    server = mcp_app.build_server(atlas)
    res = asyncio.run(
        server.call_tool(
            "get_data_table",
            {"address": "0x10010", "binary": "libsyn", "run_id": "run_t", "stride": "0x10"},
        )
    )
    blocks = res[0] if isinstance(res, tuple) else res
    text = blocks[0].text if isinstance(blocks, list) else json.dumps(blocks)
    payload = json.loads(text)
    assert payload.get("found") is True, payload
    assert payload["table"]["stride_source"] == "given" and payload["total_records"] == 6

    big = tmp_path / "big"
    big.mkdir()
    b = Bin(big / "big.db", "MIPS:LE:32:default")
    fns = [b.fn(0x400000 + 0x10 * i, f"bg_{i}") for i in range(200)]
    rec = b"".join(
        b.w(a) + bytes(range(0x20, 0x7E)) * 4 + b"\0" * (0x400 - 4 - 0x5E * 4) for a in fns
    )
    b.block(".data", 0x100000, rec)
    b.conn.execute("UPDATE binaries SET pass_version = ?", (current_pass_version(),))
    b.conn.commit()
    a2 = open_atlas(big / "atlas.db")
    a2.execute(
        "INSERT INTO run (run_id, hunt_commit, build_hash, hunt_instances, analysis_db_path) "
        "VALUES ('run_big', 'facade', ?, 1, ?)",
        (current_pass_version(), str(b.path)),
    )
    a2.commit()
    a2.close()
    tools = mcp_app.make_tools(big / "atlas.db")
    page = tools["get_data_table"]("0x100000", binary=SHA, run_id="run_big", limit=256)
    assert page["total_records"] == 200 and page["table"]["stride"] == 0x400
    assert len(json.dumps(page)) <= mcp_app._RESPONSE_BYTE_BUDGET
    assert page["truncated_by_bytes"] is True and page["next_offset"] == len(page["records"])
    nxt = tools["get_data_table"](
        "0x100000", binary=SHA, run_id="run_big", limit=256, offset=page["next_offset"]
    )
    assert nxt["records"][0]["index"] == page["next_offset"]
