# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""get_disassembly reads back the stored listing, fills each instruction's bytes from the data
blocks, and tells an un-extracted binary (available:false) from one with no instructions."""

from __future__ import annotations

import json
import zlib
from pathlib import Path

from treasure_map.lib import facts
from treasure_map.lib.diff.layer0 import norm_hex
from treasure_map.lib.query import sameness
from treasure_map.lib.storage.connection import open_db

_UNITS = [
    {"a": "0x1000", "n": 4, "k": "code", "m": "mov", "o": "r0, r1"},
    {"a": "0x1004", "n": 4, "k": "code", "m": "bl", "o": "printf"},
    {"a": "0x1008", "n": 4, "k": "data"},  # outside the 8-byte block -> bytes null
]


def _listing(units: list[dict]) -> bytes:
    return zlib.compress(json.dumps(units).encode())


def _db(
    tmp_path: Path,
    *,
    with_listing: bool = True,
    block_bytes: bytes = bytes(range(8)),
    pseudocode: str | None = "void h(){}",
    units: list[dict] | None = None,
    size: int = 0,
) -> Path:
    """``block_bytes`` is what the one 8-byte code block stores: fewer than 8 is a capped capture
    (``truncated=1``), the shape a block past the extractor's byte cap is stored in. ``pseudocode``
    None is a function with no text (a micro-stub's shape); ``units`` replaces the stored
    listing. ``size`` is the function's size_bytes."""
    db = tmp_path / "analysis.db"
    conn = open_db(db)
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256, last_seen_at) VALUES "
        "(1, 'httpd', 'usr/sbin/httpd', ?, '2026-01-01')",
        ("a" * 64,),
    )
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, address, pseudocode, callees, size_bytes) "
        "VALUES (1, 1, 'handle', '0x1000', ?, '[]', ?)",
        (pseudocode, size),
    )
    # one code block covering 0x1000.. with recognisable bytes
    conn.execute(
        "INSERT INTO data_blocks (binary_id, block_name, start_addr, size, bytes, initialized, "
        "executable, truncated) VALUES (1, '.text', '0x1000', 8, ?, 1, 1, ?)",
        (block_bytes, 1 if len(block_bytes) < 8 else 0),
    )
    if with_listing:
        conn.execute(
            "INSERT INTO function_listing (function_id, listing, unit_count, insn_count, truncated)"
            " VALUES (1, ?, 3, 2, 0)",
            (_listing(_UNITS if units is None else units),),
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


def test_the_diff_view_inlines_the_items_get_disassembly_returns(tmp_path: Path) -> None:
    """The diff view's inline listing of a micro-stub (sameness.read_micro_listings),
    get_disassembly and get_pseudocode's inline ``disassembly`` of a micro-function decode a stored
    listing in one place (facts.listing_items): the items agree field for field, bytes aside — a
    unit stored without a length included, which reads 0 in all three — and get_pseudocode's
    items are get_disassembly's, bytes included.

    MUTATION (verified RED): give read_micro_listings its own decoder that passes the stored length
    through (the pre-fix sameness._listing_units) -> the length-less unit reads None there and 0 in
    get_disassembly -> RED.
    MUTATION (verified RED): leave the bytes out of get_pseudocode's inline items -> RED."""
    db = _db(tmp_path, pseudocode=None, units=[*_UNITS, {"a": "0x100c", "k": "data"}], size=6)
    conn = facts.open_analysis_ro(db)
    try:
        full = facts.get_disassembly(conn, func="handle")
        pseudo = facts.get_pseudocode(conn, func="handle")
    finally:
        conn.close()

    def bare(items: list[dict]) -> list[dict]:  # type: ignore[type-arg]
        return [
            {k: v for k, v in i.items() if k not in ("bytes", "bytes_unavailable")} for i in items
        ]

    assert len(bare(full["instructions"])) == 4 and bare(full["instructions"])[3]["length"] == 0
    inline = sameness.read_micro_listings(str(db), "a" * 64, {norm_hex("0x1000")})
    assert inline[norm_hex("0x1000")]["listing"] == bare(full["instructions"])
    assert pseudo["pseudocode_status"] == "skipped_micro"
    assert bare(pseudo.get("disassembly", [])) == bare(full["instructions"])
    assert pseudo["disassembly"] == full["instructions"]


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


# ── every outcome, against a recording made before the listing read was shared ─────────────────

_BRANCHES_GOLDEN = Path(__file__).resolve().parents[2] / "fixtures" / "disassembly_branches.json"


def _branch_outputs(tmp_path: Path) -> dict[str, dict]:  # type: ignore[type-arg]
    """get_disassembly over every way a listing can be stored or missing: a full listing (with a
    unit outside the block), one cut short by a capped block, two pages of a big listing, a NULL
    blob on a listing-pass binary and on an old one, a listing decoding to no unit, one that does
    not decode, an errored export, a missing row with no error, and an old scan."""
    out: dict[str, dict] = {}  # type: ignore[type-arg]

    def at(name: str) -> Path:
        d = tmp_path / name
        d.mkdir()
        return d

    out["full"] = _disassemble(_db(at("full")))
    out["capped_block"] = _disassemble(_db(at("capped"), block_bytes=bytes(range(6))))
    conn = facts.open_analysis_ro(_db_big_listing(at("big"), 200))
    try:
        first = facts.get_disassembly(conn, func="handle")
        out["big_first"] = first
        out["big_second"] = facts.get_disassembly(
            conn, func="handle", offset=first["paging"]["next_offset"]
        )
    finally:
        conn.close()
    out["null_blob"] = _disassemble(_db_listing_states(at("null"), row=True, listing=None))
    out["no_units"] = _disassemble(_db_listing_states(at("none"), row=True, listing=_listing([])))
    out["undecodable"] = _disassemble(
        _db_listing_states(at("bad"), row=True, listing=b"not a listing")
    )
    out["errored"] = _disassemble(_db_listing_states(at("err"), row=False, errors='["listing"]'))
    out["no_row"] = _disassemble(_db_listing_states(at("norow"), row=False))
    out["old_scan"] = _disassemble(_db(at("old"), with_listing=False))
    old_null = _db(at("oldnull"), with_listing=False)
    conn = open_db(old_null)
    conn.execute(
        "INSERT INTO function_listing (function_id, listing, unit_count, insn_count, truncated) "
        "VALUES (1, NULL, 0, 0, 0)"
    )
    conn.commit()
    conn.close()
    out["old_scan_null_blob"] = _disassemble(old_null)
    return out


def test_every_listing_outcome_is_what_it_was_before_the_read_was_shared(tmp_path: Path) -> None:
    """get_disassembly over every stored shape (:func:`_branch_outputs`) is, key order included,
    the recording made before its listing read was shared with get_pseudocode (facts._listing_for).

    MUTATIONS (verified RED): give the NULL-blob branch a listing's insn_count; drop
    detector_errors from the errored export; report an undecodable listing as empty."""
    golden = json.loads(_BRANCHES_GOLDEN.read_text())
    out = _branch_outputs(tmp_path)
    assert list(out) == list(golden)
    for name, value in out.items():
        assert json.dumps(value) == json.dumps(golden[name]), name


# ── get_pseudocode on a function with no text: its status, and a micro-function's listing ──────


def _fn_db(
    tmp_path: Path,
    *,
    pseudocode: str | None,
    size: int | None,
    listing: str = "units",
    truncated: int = 0,
) -> Path:
    """One function ``handle`` at 0x1000 with ``pseudocode`` and ``size`` bytes. ``listing``:
    ``units`` (a stored listing on a listing-pass binary), ``null`` (the pass ran, the row's blob is
    NULL), ``none`` (an old scan: no pass, no row). ``truncated`` is its callees_truncated."""
    db = tmp_path / "analysis.db"
    conn = open_db(db)
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256, last_seen_at) VALUES "
        "(1, 'httpd', 'usr/sbin/httpd', ?, '2026-01-01')",
        ("a" * 64,),
    )
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, address, pseudocode, callees, size_bytes, "
        "callees_truncated) VALUES (1, 1, 'handle', '0x1000', ?, '[]', ?, ?)",
        (pseudocode, size, truncated),
    )
    conn.execute(
        "INSERT INTO data_blocks (binary_id, block_name, start_addr, size, bytes, initialized, "
        "executable, truncated) VALUES (1, '.text', '0x1000', 8, ?, 1, 1, 0)",
        (bytes(range(8)),),
    )
    if listing != "none":
        conn.execute(
            "INSERT INTO function_listing (function_id, listing, unit_count, insn_count, truncated)"
            " VALUES (1, ?, 2, 2, 0)",
            (_listing(_UNITS[:2]) if listing == "units" else None,),
        )
        conn.execute(
            "INSERT INTO detector_scan_status (binary_id, detector, scanned, found_count) "
            "VALUES (1, 'listing', 1, 1)"
        )
    conn.commit()
    conn.close()
    return db


def _read(db: Path) -> tuple[dict, dict]:  # type: ignore[type-arg]
    """(get_pseudocode, get_disassembly) of ``handle``."""
    conn = facts.open_analysis_ro(db)
    try:
        return (
            facts.get_pseudocode(conn, func="handle"),
            facts.get_disassembly(conn, func="handle"),
        )
    finally:
        conn.close()


_PSEUDO_KEYS = [
    "found",
    "anchor",
    "binary_path",
    "size_bytes",
    "is_exported",
    "callees",
    "callees_truncated",
    "pseudocode",
]


def test_a_function_with_text_gets_no_status(tmp_path: Path) -> None:
    """A function with text — a micro-sized one included — carries exactly the keys it did before
    pseudocode_status existed.

    MUTATION (verified RED): give every function a pseudocode_status -> RED."""
    for size in (6, 40, 0):
        (tmp_path / str(size)).mkdir()
        out, _dis = _read(_fn_db(tmp_path / str(size), pseudocode="int f(void){}", size=size))
        assert list(out) == _PSEUDO_KEYS, size


def test_a_micro_function_with_no_text_is_skipped_micro_with_its_listing_inline(
    tmp_path: Path,
) -> None:
    """Under _DECOMPILE_MIN_SIZE with no text: ``skipped_micro``, its note, and the listing inline —
    get_disassembly's instructions item for item (bytes included); ``[]`` when the pass stored a
    NULL listing; ``disassembly_status`` with get_disassembly's own reason on an old scan. The
    stored text is kept as it was (``""`` stays ``""``, NULL stays None).

    MUTATION (verified RED): inline get_disassembly's whole result instead of its instructions ->
    RED; leave the micro listing out -> RED."""
    cases = {
        "units": ("", "units"),
        "null": (None, "null"),
        "old": ("", "none"),
        "blank": ("  \n", "units"),
    }
    for name, (text, listing) in cases.items():
        (tmp_path / name).mkdir()
        out, dis = _read(_fn_db(tmp_path / name, pseudocode=text, size=6, listing=listing))
        assert out["pseudocode"] == text, name
        assert out["pseudocode_status"] == "skipped_micro", name
        assert "not decompiled by design" in out.get("pseudocode_status_note", ""), name
        assert "note" not in out, name
        if dis["available"]:
            assert out.get("disassembly") == dis["instructions"], name
            assert "disassembly_status" not in out, name
        else:
            assert "disassembly" not in out, name
            assert out.get("disassembly_status") == {"available": False, "reason": dis["reason"]}
    out, _dis = _read(tmp_path / "units" / "analysis.db")
    assert [i["mnemonic"] for i in out.get("disassembly", ())] == ["mov", "bl"]
    assert out["disassembly"][0]["bytes"] == "00010203"
    null_out, _ = _read(tmp_path / "null" / "analysis.db")
    assert null_out.get("disassembly") == [] and "insn_count" not in null_out


def test_a_larger_or_unsized_function_with_no_text_says_why_without_a_listing(
    tmp_path: Path,
) -> None:
    """At or above _DECOMPILE_MIN_SIZE: ``decompile_empty``; size 0 or not recorded:
    ``size_unknown`` (checked first, so 0 is never a micro-function). Neither inlines a listing;
    each note points at get_disassembly.

    MUTATION (verified RED): classify by size before checking 0 -> size 0 reads skipped_micro ->
    RED."""
    for name, size, status in (
        ("big", 40, "decompile_empty"),
        ("floor", 10, "decompile_empty"),
        ("zero", 0, "size_unknown"),
        ("null", None, "size_unknown"),
    ):
        (tmp_path / name).mkdir()
        out, _dis = _read(_fn_db(tmp_path / name, pseudocode="", size=size))
        assert out["pseudocode_status"] == status, name
        assert "get_disassembly" in out.get("pseudocode_status_note", ""), name
        assert "disassembly" not in out and "disassembly_status" not in out, name


def test_the_status_note_and_the_truncation_note_are_two_keys(tmp_path: Path) -> None:
    """A micro-function with no text whose callee list is truncated carries both notes, each under
    its own key.

    MUTATION (verified RED): put the status note under ``note`` -> one overwrites the other ->
    RED."""
    out, _dis = _read(_fn_db(tmp_path, pseudocode="", size=6, truncated=1))
    assert out.get("note") == facts._CALLEES_TRUNC_NOTE
    assert out["pseudocode_status"] == "skipped_micro"
    assert "not decompiled by design" in out.get("pseudocode_status_note", "")


def test_the_status_splits_empty_text_as_the_diff_baseline_does() -> None:
    """facts.pseudocode_status and lib/diff/layer0._decompile_status read one empty text the same
    way over every text and size shape (the text check strips whitespace in both); a function with
    text gets no status, where layer0 says ok."""
    from treasure_map.lib.diff.layer0 import _decompile_status

    to_layer0 = {"skipped_micro": "skipped_micro", "decompile_empty": "failed"}
    to_layer0["size_unknown"] = "unknown"
    for text in (None, "", "  ", "x"):
        for size in (None, 0, 9, 10):
            expected = _decompile_status(text, size)
            if (text or "").strip():
                assert expected == "ok", (text, size)
                continue
            assert to_layer0[facts.pseudocode_status(size)] == expected, (text, size)
