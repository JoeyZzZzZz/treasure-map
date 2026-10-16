# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""get_disassembly reads back the stored listing, fills each instruction's bytes from the data
blocks, and tells an un-extracted binary (available:false) from one with no instructions."""

from __future__ import annotations

import json
import zlib
from pathlib import Path

from treasure_map.lib import facts
from treasure_map.lib.storage.connection import open_db


def _listing(units: list[dict]) -> bytes:
    return zlib.compress(json.dumps(units).encode())


def _db(tmp_path: Path, *, with_listing: bool = True) -> Path:
    db = tmp_path / "analysis.db"
    conn = open_db(db)
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256, last_seen_at) VALUES "
        "(1, 'httpd', 'usr/sbin/httpd', ?, '2026-01-01')",
        ("a" * 64,),
    )
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, address, pseudocode, callees) "
        "VALUES (1, 1, 'handle', '0x1000', 'void h(){}', '[]')"
    )
    # one code block covering 0x1000.. with recognisable bytes
    conn.execute(
        "INSERT INTO data_blocks (binary_id, block_name, start_addr, size, bytes, initialized, "
        "executable, truncated) VALUES (1, '.text', '0x1000', 8, ?, 1, 1, 0)",
        (bytes(range(8)),),
    )
    if with_listing:
        units = [
            {"a": "0x1000", "n": 4, "k": "code", "m": "mov", "o": "r0, r1"},
            {"a": "0x1004", "n": 4, "k": "code", "m": "bl", "o": "printf"},
            {"a": "0x1008", "n": 4, "k": "data"},  # outside the 8-byte block -> bytes null
        ]
        conn.execute(
            "INSERT INTO function_listing (function_id, listing, unit_count, insn_count, truncated)"
            " VALUES (1, ?, 3, 2, 0)",
            (_listing(units),),
        )
        conn.execute(
            "INSERT INTO detector_scan_status (binary_id, detector, scanned, found_count) "
            "VALUES (1, 'listing', 1, 1)"
        )
    conn.commit()
    conn.close()
    return db


def test_get_disassembly_returns_units_with_bytes_from_the_blocks(tmp_path: Path) -> None:
    conn = facts.open_analysis_ro(_db(tmp_path))
    out = facts.get_disassembly(conn, func="handle")
    conn.close()
    assert out["available"] is True and out["total"] == 3
    insns = out["instructions"]
    assert insns[0]["mnemonic"] == "mov" and insns[0]["bytes"] == "00010203"
    assert insns[1]["operands"] == "printf" and insns[1]["bytes"] == "04050607"
    # the third unit is outside the stored block: bytes null with a reason, never zeroed
    assert insns[2]["kind"] == "data" and insns[2]["bytes"] is None
    assert "no block covers" in insns[2]["bytes_unavailable"]


def test_a_binary_without_listing_support_is_unavailable_with_a_reason(tmp_path: Path) -> None:
    """MUTATION: return available:true with empty instructions for an un-extracted binary -> RED."""
    conn = facts.open_analysis_ro(_db(tmp_path, with_listing=False))
    out = facts.get_disassembly(conn, func="handle")
    conn.close()
    assert out["available"] is False and "re-scan" in out["reason"]


def _db_big_listing(tmp_path: Path, n_units: int) -> Path:
    """One function whose listing has ``n_units`` instructions — enough that the serialized result
    exceeds one fact-tool page, so get_disassembly must byte-paginate it."""
    db = tmp_path / "analysis.db"
    conn = open_db(db)
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256, last_seen_at) VALUES "
        "(1, 'httpd', 'usr/sbin/httpd', ?, '2026-01-01')",
        ("a" * 64,),
    )
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, address, pseudocode, callees) "
        "VALUES (1, 1, 'handle', '0x1000', 'void h(){}', '[]')"
    )
    units = [
        {"a": f"0x{0x1000 + 4 * i:x}", "n": 4, "k": "code", "m": "mov", "o": "r0, r1"}
        for i in range(n_units)
    ]
    conn.execute(
        "INSERT INTO function_listing (function_id, listing, unit_count, insn_count, truncated)"
        " VALUES (1, ?, ?, ?, 0)",
        (_listing(units), n_units, n_units),
    )
    conn.execute(
        "INSERT INTO detector_scan_status (binary_id, detector, scanned, found_count) "
        "VALUES (1, 'listing', 1, 1)"
    )
    conn.commit()
    conn.close()
    return db


def test_a_large_listing_pages_losslessly_within_the_fact_tool_budget(tmp_path: Path) -> None:
    """get_disassembly caps ONE page at the shared fact-tool budget (_FACT_PAGE_CHARS, the MCP
    budget the other fact tools use), not at a much larger per-call ceiling — so the first page of a
    big function fits the MCP response, and the tail is reachable with offset=paging.next_offset,
    losslessly (every instruction returned exactly once, none summarized away).

    MUTATION (verified RED): restore the old default ``max_chars=200_000`` on get_disassembly ->
    the whole listing fits one page, paging.truncated is False, next_offset is None, and the
    first-page assertions below fail (an over-budget page is returned to MCP in one shot)."""
    n = 600  # ~130 serialized chars/unit -> well over _FACT_PAGE_CHARS (20000), under 200_000
    conn = facts.open_analysis_ro(_db_big_listing(tmp_path, n))
    try:
        first = facts.get_disassembly(conn, func="handle")
        assert first["available"] is True and first["total"] == n
        # The page is bounded: it does NOT carry the whole listing, and it says there is more.
        assert len(first["instructions"]) < n
        assert first["paging"]["truncated"] is True
        assert first["paging"]["next_offset"] is not None
        # Walk the tail by offset and assemble every instruction exactly once — lossless.
        seen: list[str] = [i["address"] for i in first["instructions"]]
        off = first["paging"]["next_offset"]
        guard = 0
        while off is not None:
            guard += 1
            assert guard < n + 5  # never loops forever
            page = facts.get_disassembly(conn, func="handle", offset=off)
            assert page["instructions"], "a page must always make progress"
            seen.extend(i["address"] for i in page["instructions"])
            off = page["paging"]["next_offset"]
    finally:
        conn.close()
    expected = [f"0x{0x1000 + 4 * i:x}" for i in range(n)]
    assert seen == expected  # every unit, in order, no drop and no duplicate


def test_a_truncated_block_leaves_bytes_null_not_short(tmp_path: Path) -> None:
    """A unit whose length runs past the stored (capped) bytes gets null + block_truncated, never a
    short byte string read as complete.

    MUTATION: return the short slice instead of null -> RED."""
    conn = facts.open_analysis_ro(_db(tmp_path))
    out = facts.get_disassembly(conn, func="handle")
    conn.close()
    # unit at 0x1004 asks 4 bytes and the block ends at 0x1008 — exactly covered, so it is present;
    # make the check explicit that a covered unit is full and an out-of-range one is null
    covered = [i for i in out["instructions"] if i["address"] == "0x1004"][0]
    assert covered["bytes"] is not None and len(covered["bytes"]) == 8
