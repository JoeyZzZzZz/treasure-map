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


def _db(tmp_path: Path, *, with_listing: bool = True, block_bytes: bytes = bytes(range(8))) -> Path:
    """``block_bytes`` is what the one 8-byte code block stores: fewer than 8 is a capped capture
    (``truncated=1``), the shape a block past the extractor's byte cap is stored in."""
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
        "executable, truncated) VALUES (1, '.text', '0x1000', 8, ?, 1, 1, ?)",
        (block_bytes, 1 if len(block_bytes) < 8 else 0),
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

    The block is 8 bytes long but stores only its first 6: the unit at 0x1000 is fully stored, the
    unit at 0x1004 asks for 4 bytes of which 2 were kept.

    MUTATION (verified RED): drop the ``len(chunk) < length`` check in facts._byte_reader -> the
    0x1004 unit comes back as the 2-byte "0405", read as if complete, and the null assertion
    below fails."""
    conn = facts.open_analysis_ro(_db(tmp_path, block_bytes=bytes(range(6))))
    out = facts.get_disassembly(conn, func="handle")
    conn.close()
    by_addr = {i["address"]: i for i in out["instructions"]}
    assert "0x1000" in by_addr and "0x1004" in by_addr
    # fully inside the stored prefix: present and whole
    assert by_addr["0x1000"]["bytes"] == "00010203"
    # runs past the stored prefix: null with the reason, not the 2 bytes that were kept
    assert by_addr["0x1004"]["bytes"] is None
    assert by_addr["0x1004"]["bytes_unavailable"] == "block_truncated"


def _db_listing_states(
    tmp_path: Path, *, row: bool, listing: bytes | None = None, errors: str = "[]"
) -> Path:
    """One function on a binary extracted WITH listing export (the per-binary 'listing' pass mark
    is present). ``row`` stores a function_listing row whose blob is ``listing`` (None is a NULL
    blob); without it there is no row at all. ``errors`` is the function's detector_errors JSON."""
    db = tmp_path / "analysis.db"
    conn = open_db(db)
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256, last_seen_at) VALUES "
        "(1, 'httpd', 'usr/sbin/httpd', ?, '2026-01-01')",
        ("a" * 64,),
    )
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, address, pseudocode, callees, "
        "detector_errors) VALUES (1, 1, 'handle', '0x1000', 'void h(){}', '[]', ?)",
        (errors,),
    )
    if row:
        conn.execute(
            "INSERT INTO function_listing (function_id, listing, unit_count, insn_count, "
            "truncated) VALUES (1, ?, 0, 0, 0)",
            (listing,),
        )
    conn.execute(
        "INSERT INTO detector_scan_status (binary_id, detector, scanned, found_count) "
        "VALUES (1, 'listing', 1, 0)"
    )
    conn.commit()
    conn.close()
    return db


def _disassemble(db: Path) -> dict:  # type: ignore[type-arg]
    conn = facts.open_analysis_ro(db)
    try:
        return facts.get_disassembly(conn, func="handle")
    finally:
        conn.close()


def test_a_function_with_no_instructions_is_available_and_empty(tmp_path: Path) -> None:
    """A function the listing pass DID cover, with no instructions, is an answer: available, zero
    instructions — never 'unavailable, re-scan', which would send a reader to re-scan for a listing
    that is already complete.

    Both stored shapes: a row whose listing is null, and a listing that decodes to no units.

    MUTATION (verified RED): ``if has_pass and lrow is not None:`` -> ``if False:`` in
    facts.get_disassembly -> the null-listing row is reported unavailable and the first
    ``available is True`` assertion fails."""
    (tmp_path / "null").mkdir()
    (tmp_path / "none").mkdir()
    for out in (
        _disassemble(_db_listing_states(tmp_path / "null", row=True, listing=None)),
        _disassemble(_db_listing_states(tmp_path / "none", row=True, listing=_listing([]))),
    ):
        assert out["available"] is True, out
        assert out["instructions"] == [] and out["total"] == 0
        assert "reason" not in out


def test_an_errored_listing_export_says_so_not_old_scan(tmp_path: Path) -> None:
    """The extractor names ``listing`` in detector_errors when the export raised on a function, and
    stores no listing for it. The reason must say that — not "analysed before tmap exported
    disassembly; re-scan", which is false for this binary (its listing pass ran) and sends the
    reader to a re-scan that reuses the cached extraction.

    MUTATION (verified RED): ``if "listing" in errored:`` -> ``if False:`` in facts.get_disassembly
    -> the reason no longer says the export raised, and the assertion on it fails."""
    out = _disassemble(_db_listing_states(tmp_path, row=False, errors='["listing"]'))
    assert out["available"] is False
    assert "listing export raised" in out["reason"]
    assert "analysed before" not in out["reason"]
    assert out["detector_errors"] == ["listing"]


def test_a_missing_listing_on_a_listing_pass_binary_is_not_called_an_old_scan(
    tmp_path: Path,
) -> None:
    """No listing row and no recorded error, on a binary whose listing pass DID run: the reason
    must not claim the binary predates listing export. Only the absence of the pass mark says
    that (test_a_binary_without_listing_support_is_unavailable_with_a_reason).

    MUTATION (verified RED): ``if has_pass:`` -> ``if False:`` (the branch after the empty-function
    one) in facts.get_disassembly -> the old-scan reason comes back and the assertion fails."""
    out = _disassemble(_db_listing_states(tmp_path, row=False))
    assert out["available"] is False
    assert "analysed before" not in out["reason"]
    assert "no listing was stored" in out["reason"]
