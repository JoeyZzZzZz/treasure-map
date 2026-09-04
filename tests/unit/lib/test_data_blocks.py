# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the raw data-segment byte substrate (A1): the Ghidra ``data_blocks`` export ->
analysis.db ingest -> ``facts.get_data_bytes`` read path.

The point of the feature is that the decompiler renders a data-segment constant as a bare
``DAT_000174e4`` and DROPS its content, so the bytes are unreachable from the pseudocode. The point
of these tests is the honesty around that substrate: every way of NOT having the bytes must stay a
distinguishable, non-empty answer. Four different misses must never collapse into one another or
into a confident "the bytes are zero":

  * a cap stored less than the block's extent  -> truncated, NOT "the data ends here"
  * a .bss extent (reserved, runtime-only)     -> uninitialized_bss, NOT b""
  * an address outside every exported block    -> address_not_in_any_data_block
  * a binary with no exported blocks at all    -> data_blocks_not_exported (UNKNOWN, not "no data")

Hermetic: a synthetic, vendor-neutral payload driven through the real ingest.
"""

from __future__ import annotations

import base64
import json
import sqlite3
from pathlib import Path
from typing import Any

from treasure_map.lib import facts
from treasure_map.lib.analyze.elf_inventory import ElfRecord
from treasure_map.lib.analyze.ghidra_ingest import ingest_ghidra_output
from treasure_map.lib.storage.connection import open_db

_SHA = "a" * 64
_OTHER_SHA = "b" * 64

# .rodata: fully stored.               .data: the exporter's cap stored 8 of 32 bytes.
# .bss:    reserved extent, no bytes.  .rodata2: big enough to hit the per-CALL cap on read.
_RODATA = b"ABCDEFGHIJKLMNOP"  # 16 bytes at 0x10000
_DATA_STORED = b"01234567"  # 8 bytes stored of a 32-byte block at 0x20000
_RODATA2 = bytes((i % 251) for i in range(8192))  # 8192 bytes at 0x40000
# an RX PT_LOAD at 0x50000: on a stripped ELF .rodata and .text share one block, so these bytes are
# deliberately half instruction-looking and half text -- the reader must not be told which is which.
_EXEC_SEG = bytes(range(0x20)) + b"exec-segment-literal"


def _payload(*, cap_hit: bool = True) -> dict[str, Any]:
    return {
        "functions": [],
        "imports": [],
        "exports": [],
        "strings": [],
        "data_blocks": {
            "cap_hit": cap_hit,
            "blocks": [
                {
                    "name": ".rodata",
                    "start": "0x10000",
                    "size": len(_RODATA),
                    "initialized": True,
                    "truncated": False,
                    "bytes": base64.b64encode(_RODATA).decode(),
                },
                {
                    "name": ".data",
                    "start": "0x20000",
                    "size": 32,
                    "initialized": True,
                    "truncated": True,
                    "bytes": base64.b64encode(_DATA_STORED).decode(),
                },
                {
                    "name": ".bss",
                    "start": "0x30000",
                    "size": 64,
                    "initialized": False,
                    "truncated": False,
                },
                {
                    # a section-header-stripped ELF's RX PT_LOAD: .rodata and .text share it
                    "name": "segment_2",
                    "start": "0x50000",
                    "size": len(_EXEC_SEG),
                    "executable": True,
                    "initialized": True,
                    "truncated": False,
                    "bytes": base64.b64encode(_EXEC_SEG).decode(),
                },
                {
                    "name": ".rodata2",
                    "start": "0x40000",
                    "size": len(_RODATA2),
                    "initialized": True,
                    "truncated": False,
                    "bytes": base64.b64encode(_RODATA2).decode(),
                },
            ],
        },
    }


def _ingest(tmp_path: Path, payload: dict[str, Any] | None) -> Path:
    """Build an analysis.db holding two binaries: 'test_bin' fed *payload*, and 'bare_bin' fed a
    payload with NO data_blocks key at all (the pre-feature export)."""
    db = tmp_path / "analysis.db"
    conn = open_db(db)
    conn.execute(
        # last_seen_at is LOAD-BEARING: current_binaries selects rows whose last_seen_at equals
        # the maximum, and NULL never equals NULL, so omitting it yields an EMPTY view and every
        # binary selector misses. Real scans always write it.
        "INSERT INTO binaries (name, path, sha256, last_seen_at) "
        "VALUES (?, ?, ?, '2026-01-01T00:00:00')",
        ("test_bin", "usr/sbin/test_bin", _SHA),
    )
    conn.execute(
        # last_seen_at is LOAD-BEARING: current_binaries selects rows whose last_seen_at equals
        # the maximum, and NULL never equals NULL, so omitting it yields an EMPTY view and every
        # binary selector misses. Real scans always write it.
        "INSERT INTO binaries (name, path, sha256, last_seen_at) "
        "VALUES (?, ?, ?, '2026-01-01T00:00:00')",
        ("bare_bin", "usr/sbin/bare_bin", _OTHER_SHA),
    )
    conn.commit()
    sha_to_id = {r["sha256"]: r["id"] for r in conn.execute("SELECT id, sha256 FROM binaries")}
    out = tmp_path / "ghidra_output"
    out.mkdir(parents=True, exist_ok=True)
    bare: dict[str, Any] = {"functions": [], "imports": [], "exports": [], "strings": []}
    for name, sha, data in (
        ("test_bin", _SHA, payload if payload is not None else bare),
        ("bare_bin", _OTHER_SHA, bare),
    ):
        (out / f"{name}_{sha[:8]}_ghidra.json").write_text(json.dumps(data))
    records = [
        ElfRecord(
            path=Path(f"/fake/{name}"),
            name=name,
            arch="MIPS:LE:32:default",
            elf_type="executable",
            sha256=sha,
            dt_needed=[],
            protections={},
            size=4096,
        )
        for name, sha in (("test_bin", _SHA), ("bare_bin", _OTHER_SHA))
    ]
    ingest_ghidra_output(conn, out, records, sha_to_id)
    conn.commit()
    conn.close()
    return db


def _ro(db: Path) -> sqlite3.Connection:
    return facts.open_analysis_ro(db)


# ── ingest: the rows land, and the two honesty columns survive the round trip ────────


def test_ingest_writes_one_row_per_block(tmp_path: Path) -> None:
    db = _ingest(tmp_path, _payload())
    conn = _ro(db)
    try:
        rows = conn.execute(
            "SELECT block_name, start_addr, size, bytes, initialized, executable, truncated "
            "FROM data_blocks ORDER BY start_addr"
        ).fetchall()
    finally:
        conn.close()
    by_name = {r["block_name"]: r for r in rows}
    assert set(by_name) == {".rodata", ".data", ".bss", ".rodata2", "segment_2"}
    assert bytes(by_name[".rodata"]["bytes"]) == _RODATA
    assert by_name[".rodata"]["truncated"] == 0
    assert by_name[".rodata"]["size"] == 16
    # ★ .bss stores NO bytes: the column is NULL, never b"" — an empty blob would read, to anyone
    # querying the table directly, as "we looked and there is nothing there".
    bss = by_name[".bss"]
    assert bss["initialized"] == 0
    assert bss["bytes"] is None
    assert bss["size"] == 64  # the extent is still recorded, so an address can land in it
    # an executable block carries its bytes AND its flag: the flag is what the read side turns into
    # the "may be instructions" warning, so losing it in transport loses the warning.
    ex = by_name["segment_2"]
    assert ex["executable"] == 1 and bytes(ex["bytes"]) == _EXEC_SEG


def test_ingest_writes_a_scan_status_row_even_though_it_is_not_a_detector(tmp_path: Path) -> None:
    # The honesty status is written on EVERY ingest, so a binary with zero exported blocks is
    # distinguishable from a binary nobody exported blocks for.
    db = _ingest(tmp_path, _payload())
    conn = _ro(db)
    try:
        rows = conn.execute(
            "SELECT b.name, d.scanned, d.cap_hit, d.found_count FROM detector_scan_status d "
            "JOIN binaries b ON b.id = d.binary_id WHERE d.detector = 'data_blocks' ORDER BY b.name"
        ).fetchall()
    finally:
        conn.close()
    status = {r["name"]: (r["scanned"], r["cap_hit"], r["found_count"]) for r in rows}
    assert status["test_bin"] == (1, 1, 5)
    # the pre-feature export claims NO scan rather than a clean zero
    assert status["bare_bin"] == (0, 0, 0)


# ── the four misses, each staying its own answer ─────────────────────────────────────


def test_data_blocks_truncated_not_silent(tmp_path: Path) -> None:
    """A block the exporter cut short must SAY so, at the row and at the read.

    MUTATION (must go RED): in ``ghidra_ingest._ingest_one_binary`` make the flag unconditional --
    ``truncated = 0`` instead of ``1 if b.get("truncated") else 0`` -- i.e. keep truncating but
    stop recording it. The stored row then claims to be the whole block and a read past the stored
    tail comes back as a clean short answer, which is the exact false "the data ends here" this
    guards. Second mutation: in ``facts.get_data_bytes`` drop the ``result["truncated"] = True``
    line, so the short read looks complete."""
    db = _ingest(tmp_path, _payload())
    conn = _ro(db)
    try:
        row = conn.execute(
            "SELECT size, bytes, truncated FROM data_blocks WHERE block_name = '.data'"
        ).fetchone()
        # a read inside the stored prefix, but asking past it
        partial = facts.get_data_bytes(conn, binary="test_bin", address="0x20000", length=32)
        # a read starting past the stored prefix but still inside the block's extent
        beyond = facts.get_data_bytes(conn, binary="test_bin", address="0x20010", length=4)
    finally:
        conn.close()
    assert row["truncated"] == 1
    assert row["size"] == 32 and len(bytes(row["bytes"])) == 8  # the row IS a prefix

    assert partial["found"] is True
    assert partial["truncated"] is True
    assert partial["note"] == "cap_truncated"
    assert bytes.fromhex(partial["bytes"]) == _DATA_STORED

    assert beyond["found"] is True
    assert beyond["truncated"] is True
    assert beyond["note"] == "cap_truncated"
    assert beyond["bytes"] == ""  # zero bytes AND flagged -- never a confident empty


def test_bss_not_read_as_zero(tmp_path: Path) -> None:
    """A .bss address is 'reserved, value is runtime-only' -- never zero bytes.

    MUTATION (must go RED): in ``facts.get_data_bytes`` treat the uninitialized block as empty
    content -- return ``{"found": True, "bytes": "", ...}`` instead of the ``uninitialized_bss``
    record. A caller then reads a runtime-only value as a proven-empty one."""
    db = _ingest(tmp_path, _payload())
    conn = _ro(db)
    try:
        res = facts.get_data_bytes(conn, binary="test_bin", address="0x30010", length=16)
    finally:
        conn.close()
    assert res["found"] is False
    assert res["note"] == "uninitialized_bss"
    assert res["detail"] == "value is runtime-only"
    assert "bytes" not in res  # no empty-string stand-in for the missing value
    assert res["block_name"] == ".bss"  # still anchored: the reader knows WHERE it landed


def test_address_not_found_is_not_safe(tmp_path: Path) -> None:
    """An address in no exported block is a NON-answer, not an empty successful read."""
    db = _ingest(tmp_path, _payload())
    conn = _ro(db)
    try:
        res = facts.get_data_bytes(conn, binary="test_bin", address="0x99999", length=8)
    finally:
        conn.close()
    assert res["found"] is False
    assert res["note"] == "address_not_in_any_data_block"
    assert "bytes" not in res


def test_no_rows_is_not_no_data(tmp_path: Path) -> None:
    """A binary nobody exported blocks for is UNKNOWN, never 'this binary has no data'."""
    db = _ingest(tmp_path, _payload())
    conn = _ro(db)
    try:
        res = facts.get_data_bytes(conn, binary="bare_bin", address="0x10000", length=8)
    finally:
        conn.close()
    assert res["found"] is False
    assert res["note"] == "data_blocks_not_exported"
    assert "bytes" not in res


def test_executable_segment_bytes_are_served_with_their_warning(tmp_path: Path) -> None:
    """RX blocks ARE readable -- and the answer can never arrive without saying the run may be code.

    Executable blocks are in scope on purpose: on an ELF stripped of section headers Ghidra builds
    one block per PT_LOAD and the read-only data sits inside the executable RX segment. Verified on
    this machine against Ghidra 12.1.2 -- a stripped firmware binary yields ``segment_2``
    (init=true, exec=true, holding its .rodata) plus ``segment_3`` (init=true, exec=false), whereas
    a binary that kept its section headers yields a separate non-executable ``.rodata`` block; and
    454/456, 455/455, 417/417 binaries of three real images are section-header-free. Excluding RX
    would therefore leave a .rodata address unanswerable on the vast majority of real binaries.

    The price is that .rodata and .text are indistinguishable there, so the caveat is mandatory.

    MUTATION (must go RED): drop the ``blk["executable"]`` branch in ``facts.get_data_bytes``, or
    stop carrying ``executable`` through ``ghidra_ingest``. The bytes then arrive looking exactly
    like data-segment bytes and an agent can read a run of ARM instructions as a charset table."""
    db = _ingest(tmp_path, _payload())
    conn = _ro(db)
    try:
        res = facts.get_data_bytes(conn, binary="test_bin", address="0x50020", length=20)
    finally:
        conn.close()
    assert res["found"] is True
    assert bytes.fromhex(res["bytes"]) == b"exec-segment-literal"
    assert res["block_name"] == "segment_2"
    # ★ the caveat, on its OWN keys -- not in `note`, which the truncation reason owns
    assert res["bytes_from_executable_segment"] is True
    assert "may be read-only DATA or may be INSTRUCTION" in res["warning"]


def test_executable_warning_survives_a_truncated_read(tmp_path: Path) -> None:
    """The RX caveat and a truncation reason must COEXIST. Sharing one `note` slot would let a
    short read out of an RX block silently lose the "may be instructions" warning -- the exact
    signal-collapse this codebase treats as a red line.

    MUTATION (must go RED): move the caveat into ``note`` (``result["note"] =
    "bytes_from_executable_segment"``) instead of its own key; the truncation reason then overwrites
    it, or it overwrites the truncation reason."""
    db = _ingest(tmp_path, _payload())
    conn = _ro(db)
    try:
        # start near the end of the RX block so the read is clamped AND lands in RX
        res = facts.get_data_bytes(conn, binary="test_bin", address="0x50028", length=64)
    finally:
        conn.close()
    assert res["found"] is True
    assert res["truncated"] is True and res["note"] == "clamped_to_block_end"
    assert res["bytes_from_executable_segment"] is True and res["warning"]


def test_bss_note_distinct_from_not_in_block(tmp_path: Path) -> None:
    """The three not-found reasons are three DIFFERENT strings; collapsing any two of them would
    let a caller answer a question the substrate never answered."""
    db = _ingest(tmp_path, _payload())
    conn = _ro(db)
    try:
        bss = facts.get_data_bytes(conn, binary="test_bin", address="0x30010", length=8)
        gone = facts.get_data_bytes(conn, binary="test_bin", address="0x99999", length=8)
        never = facts.get_data_bytes(conn, binary="bare_bin", address="0x10000", length=8)
    finally:
        conn.close()
    notes = {bss["note"], gone["note"], never["note"]}
    assert len(notes) == 3
    assert notes == {
        "uninitialized_bss",
        "address_not_in_any_data_block",
        "data_blocks_not_exported",
    }


# ── the ordinary read, and the two other bounds that stop it ─────────────────────────


def test_plain_read_returns_the_bytes_and_no_reading_of_them(tmp_path: Path) -> None:
    db = _ingest(tmp_path, _payload())
    conn = _ro(db)
    try:
        res = facts.get_data_bytes(conn, binary="test_bin", address="0x10004", length=4)
    finally:
        conn.close()
    assert res["found"] is True and res["truncated"] is False
    assert bytes.fromhex(res["bytes"]) == b"EFGH"
    assert res["ascii"] == "EFGH"
    assert res["offset_in_block"] == 4 and res["block_name"] == ".rodata"
    # the red line: bytes only. No verdict key of any kind rides along.
    assert "RAW BYTES ONLY" in res["contract"]
    # a data-block read carries NO executable caveat -- a flag that is always on says nothing
    assert "bytes_from_executable_segment" not in res
    assert "warning" not in res
    assert not {"is_text", "safe", "verdict", "looks_like"} & set(res)


def test_bare_hex_address_is_read_as_hex_not_decimal(tmp_path: Path) -> None:
    # An agent copies "00010004" straight out of a DAT_ symbol; reading it as decimal would land in
    # a different block (or nowhere) and answer a question about the wrong address.
    db = _ingest(tmp_path, _payload())
    conn = _ro(db)
    try:
        bare = facts.get_data_bytes(conn, binary="test_bin", address="00010004", length=4)
        prefixed = facts.get_data_bytes(conn, binary="test_bin", address="0x10004", length=4)
    finally:
        conn.close()
    assert bare["bytes"] == prefixed["bytes"] == b"EFGH".hex()


def test_read_past_block_end_says_which_limit_bit(tmp_path: Path) -> None:
    db = _ingest(tmp_path, _payload())
    conn = _ro(db)
    try:
        res = facts.get_data_bytes(conn, binary="test_bin", address="0x10008", length=64)
    finally:
        conn.close()
    assert res["truncated"] is True
    assert res["note"] == "clamped_to_block_end"  # NOT cap_truncated: this block is fully stored
    assert bytes.fromhex(res["bytes"]) == _RODATA[8:]


def test_per_call_length_cap_is_flagged_not_silent(tmp_path: Path) -> None:
    db = _ingest(tmp_path, _payload())
    conn = _ro(db)
    try:
        res = facts.get_data_bytes(conn, binary="test_bin", address="0x40000", length=8192)
    finally:
        conn.close()
    assert res["truncated"] is True
    assert res["note"] == "request_length_capped"
    assert res["length_returned"] == facts._DATA_BYTES_MAX_LENGTH
    assert bytes.fromhex(res["bytes"]) == _RODATA2[: facts._DATA_BYTES_MAX_LENGTH]


def test_binary_resolves_by_short_name_or_path(tmp_path: Path) -> None:
    db = _ingest(tmp_path, _payload())
    conn = _ro(db)
    try:
        by_name = facts.get_data_bytes(conn, binary="test_bin", address="0x10000", length=4)
        by_path = facts.get_data_bytes(
            conn, binary="usr/sbin/test_bin", address="0x10000", length=4
        )
        missing = facts.get_data_bytes(conn, binary="nope", address="0x10000", length=4)
    finally:
        conn.close()
    assert by_name["bytes"] == by_path["bytes"]
    # The selector resolver's own shape: a reason, and the query it could not satisfy.
    assert missing["found"] is False and missing["reason"] == "not_found"


def test_undecodable_transport_is_flagged_not_stored_as_empty(tmp_path: Path) -> None:
    """A block the exporter CALLS initialized whose base64 will not decode must be recorded as a
    zero-length PREFIX (truncated=1), not as a block that genuinely holds nothing."""
    payload = _payload()
    payload["data_blocks"]["blocks"][0]["bytes"] = "!!!not base64!!!"
    db = _ingest(tmp_path, payload)
    conn = _ro(db)
    try:
        row = conn.execute(
            "SELECT bytes, truncated, initialized FROM data_blocks WHERE block_name = '.rodata'"
        ).fetchone()
        res = facts.get_data_bytes(conn, binary="test_bin", address="0x10000", length=4)
    finally:
        conn.close()
    assert row["initialized"] == 1 and bytes(row["bytes"]) == b"" and row["truncated"] == 1
    assert res["found"] is True and res["truncated"] is True and res["note"] == "cap_truncated"


def test_absent_data_blocks_key_contributes_no_rows(tmp_path: Path) -> None:
    # "缺失 -> 贡献 0 行": a pre-feature export writes no placeholder row it could later be read as.
    db = _ingest(tmp_path, None)
    conn = _ro(db)
    try:
        count = conn.execute("SELECT COUNT(*) FROM data_blocks").fetchone()[0]
    finally:
        conn.close()
    assert count == 0


def test_reingest_wipes_and_rebuilds(tmp_path: Path) -> None:
    # Idempotent per binary: a second ingest must not double the block rows.
    db = _ingest(tmp_path, _payload())
    conn = open_db(db)
    sha_to_id = {r["sha256"]: r["id"] for r in conn.execute("SELECT id, sha256 FROM binaries")}
    rec = ElfRecord(
        path=Path("/fake/test_bin"),
        name="test_bin",
        arch="MIPS:LE:32:default",
        elf_type="executable",
        sha256=_SHA,
        dt_needed=[],
        protections={},
        size=4096,
    )
    ingest_ghidra_output(conn, tmp_path / "ghidra_output", [rec], sha_to_id)
    conn.commit()
    count = conn.execute(
        "SELECT COUNT(*) FROM data_blocks d JOIN binaries b ON b.id = d.binary_id "
        "WHERE b.name = 'test_bin'"
    ).fetchone()[0]
    conn.close()
    assert count == 5
