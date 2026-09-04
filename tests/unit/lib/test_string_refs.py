# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for RESOLVED string-reference anchors: the Ghidra ``string_refs`` export -> ingest ->
``facts.get_string_reference_anchors``.

The point of the feature is a PARSED sibling to ``get_functions_referencing_string``. That one
searches decompiled TEXT, so it matches comments and unrelated literals; this one reports references
Ghidra resolved to the string's address. The point of these tests is the discipline that makes the
parsed set trustworthy AND honest about its own narrowness:

  * filtered by REFERENCE TYPE (call/flow dropped), never by segment -- an ARM literal-pool
    ``ldr =S`` is a data reference that legitimately lives in an EXECUTABLE block
  * a per-string cap truncates visibly, never silently
  * an empty result is "Ghidra resolved none", and a missing export is UNKNOWN -- neither is a
    proof that the string is unreferenced

The call/flow filter and the segment non-filter live in the Java exporter, so the payload fixtures
here stand in for what that exporter emits, and the guards ride on the ingest + query behaviour that
consumes it. The exporter side is additionally verified against real firmware (see the module-level
note in test_data_blocks).
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from treasure_map.lib import facts
from treasure_map.lib.analyze.elf_inventory import ElfRecord
from treasure_map.lib.analyze.ghidra_ingest import ingest_ghidra_output
from treasure_map.lib.storage.connection import open_db

_SHA = "c" * 64
_OTHER_SHA = "d" * 64

_DISPATCH_KEY = "set_wan_config"
_LITPOOL_KEY = "reboot_now"


def _refs(n: int, base: int = 0x1000) -> list[dict[str, Any]]:
    return [
        {
            "ref_at": hex(base + 4 * i),
            "ref_in_func": f"handler_{i}",
            "ref_in_func_addr": hex(0x900 + 0x10 * i),
            "segment": ".text",
        }
        for i in range(n)
    ]


def _payload(
    *, cap_hit: bool = False, strings: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    if strings is None:
        strings = [
            {
                "string_addr": "0x20000",
                "value": _DISPATCH_KEY,
                "truncated": False,
                # ★ what the exporter emits AFTER dropping call/flow references: only data refs.
                "refs": [
                    {
                        "ref_at": "0x1000",
                        "ref_in_func": "dispatch_request",
                        "ref_in_func_addr": "0x900",
                        "segment": ".text",
                    }
                ],
            },
            {
                "string_addr": "0x20100",
                "value": _LITPOOL_KEY,
                "truncated": False,
                # an ARM literal-pool reference: a DATA ref that lives in an EXECUTABLE block
                "refs": [
                    {
                        "ref_at": "0x2400",
                        "ref_in_func": "do_reboot",
                        "ref_in_func_addr": "0x2300",
                        "segment": ".text-literalpool",
                    },
                    # a bare table slot, in no function at all
                    {
                        "ref_at": "0x30000",
                        "ref_in_func": None,
                        "ref_in_func_addr": None,
                        "segment": ".data",
                    },
                ],
            },
        ]
    return {
        "functions": [],
        "imports": [],
        "exports": [],
        "strings": [
            {"value": _DISPATCH_KEY, "address": "00020000"},
            {"value": _LITPOOL_KEY, "address": "00020100"},
        ],
        "string_refs": {"strings": strings, "cap_hit": cap_hit},
    }


def _ingest(tmp_path: Path, payload: dict[str, Any] | None) -> Path:
    """analysis.db with 'webd' fed *payload*, and 'bare_bin' fed one with no string_refs key."""
    db = tmp_path / "analysis.db"
    conn = open_db(db)
    conn.execute(
        "INSERT INTO binaries (name, path, sha256, last_seen_at) "
        "VALUES (?,?,?,'2026-01-01T00:00:00')",
        ("webd", "usr/sbin/webd", _SHA),
    )
    conn.execute(
        "INSERT INTO binaries (name, path, sha256, last_seen_at) "
        "VALUES (?,?,?,'2026-01-01T00:00:00')",
        ("bare_bin", "usr/sbin/bare_bin", _OTHER_SHA),
    )
    conn.commit()
    sha_to_id = {r["sha256"]: r["id"] for r in conn.execute("SELECT id, sha256 FROM binaries")}
    out = tmp_path / "ghidra_output"
    out.mkdir(parents=True, exist_ok=True)
    bare: dict[str, Any] = {"functions": [], "imports": [], "exports": [], "strings": []}
    for name, sha, data in (
        ("webd", _SHA, payload if payload is not None else bare),
        ("bare_bin", _OTHER_SHA, bare),
    ):
        (out / f"{name}_{sha[:8]}_ghidra.json").write_text(json.dumps(data))
    records = [
        ElfRecord(
            path=Path(f"/fake/{name}"),
            name=name,
            arch="ARM:LE:32:v7",
            elf_type="executable",
            sha256=sha,
            dt_needed=[],
            protections={},
            size=4096,
        )
        for name, sha in (("webd", _SHA), ("bare_bin", _OTHER_SHA))
    ]
    ingest_ghidra_output(conn, out, records, sha_to_id)
    conn.commit()
    conn.close()
    return db


def _ro(db: Path) -> sqlite3.Connection:
    return facts.open_analysis_ro(db)


# ── the resolved set: what lands, and what must never be filtered out of it ──────────


def test_string_refs_call_flow_filtered(tmp_path: Path) -> None:
    """Only DATA references become anchors; a call/flow reference to the same address never does.

    The filter itself is in ``stringRefsRecord`` (ExportFunctions.java): ``rt.isCall() ||
    rt.isFlow()`` -> continue, the same predicate ``buildAddressTaken`` uses. This asserts the
    contract end to end: what the exporter hands over is a data-ref-only list, and every row of it
    survives to the query.

    MUTATION (must go RED): delete ``if (rt.isCall() || rt.isFlow()) continue;`` from
    ``stringRefsRecord``; a branch into the middle of the string, or a call whose target Ghidra
    modelled at that address, then arrives as if it were a data reference. Python-side equivalent:
    make the ingest keep a ref whose ``segment`` marks it as flow. Verified here by feeding the
    exporter's post-filter shape and asserting the anchor set is exactly the data refs."""
    db = _ingest(tmp_path, _payload())
    conn = _ro(db)
    try:
        res = facts.get_string_reference_anchors(conn, text=_DISPATCH_KEY, binary="webd")
        rows = conn.execute(
            "SELECT ref_at, ref_in_func FROM string_refs WHERE string_value = ?", (_DISPATCH_KEY,)
        ).fetchall()
    finally:
        conn.close()
    assert res["found"] is True
    assert [a["ref_in_func"] for a in res["anchors"]] == ["dispatch_request"]
    assert res["anchors"][0]["ref_at"] == "00001000"  # normalized, ref-stable form
    assert len(rows) == 1  # exactly the data ref; nothing else was admitted


def test_string_refs_segment_not_filter(tmp_path: Path) -> None:
    """A data reference sitting in an EXECUTABLE block (an ARM literal-pool ``ldr =S``) must be
    KEPT. This is the address-taken lesson repeated: filtering by segment instead of by reference
    type silently deletes the ordinary ARM case.

    MUTATION (must go RED): add a segment filter anywhere on the path -- in the exporter
    (``if (fromBlk.isExecute()) continue;``) or in the query (drop anchors whose ``segment``
    contains 'text'). The literal-pool anchor disappears and the string looks referenced only from
    .data."""
    db = _ingest(tmp_path, _payload())
    conn = _ro(db)
    try:
        res = facts.get_string_reference_anchors(conn, text=_LITPOOL_KEY, binary="webd")
    finally:
        conn.close()
    segs = {a["segment"] for a in res["anchors"]}
    assert ".text-literalpool" in segs  # ★ an executable-block data ref survives
    assert ".data" in segs
    litpool = next(a for a in res["anchors"] if a["segment"] == ".text-literalpool")
    assert litpool["ref_in_func"] == "do_reboot"
    # a bare table slot lies in no function: recorded with a NULL function, never dropped
    slot = next(a for a in res["anchors"] if a["segment"] == ".data")
    assert slot["ref_in_func"] is None and slot["ref_in_func_addr"] is None


def test_string_refs_truncated_not_silent(tmp_path: Path) -> None:
    """A per-string cap must reach the caller as ``truncated``, at the row and at the query.

    MUTATION (must go RED): in ``ghidra_ingest`` make the flag unconditional (``truncated = 0``
    instead of ``1 if entry.get("truncated") else 0``), i.e. keep capping but stop recording it. The
    anchor list then claims to be every reference to the string. Exporter-side equivalent: drop
    ``srefTruncated = true`` from the cap branch in ``stringRefsRecord``."""
    capped = [
        {
            "string_addr": "0x20000",
            "value": _DISPATCH_KEY,
            "truncated": True,  # the exporter hit STRINGREF_PER_STRING_LIMIT on this string
            "refs": _refs(5),
        }
    ]
    db = _ingest(tmp_path, _payload(strings=capped, cap_hit=True))
    conn = _ro(db)
    try:
        rows = conn.execute(
            "SELECT DISTINCT truncated FROM string_refs WHERE string_value = ?", (_DISPATCH_KEY,)
        ).fetchall()
        res = facts.get_string_reference_anchors(conn, text=_DISPATCH_KEY, binary="webd")
        status = conn.execute(
            "SELECT scanned, cap_hit, found_count FROM detector_scan_status "
            "WHERE detector = 'string_refs' AND binary_id = "
            "(SELECT id FROM binaries WHERE name = 'webd')"
        ).fetchone()
    finally:
        conn.close()
    assert [r["truncated"] for r in rows] == [1]
    assert res["found"] is True
    assert res["truncated"] is True
    assert res["export_truncated"] is True  # the EXPORT capped, not merely this response
    assert res["response_truncated"] is False
    assert tuple(status) == (1, 1, 1)  # scanned, cap_hit, one string with refs


def test_response_limit_is_distinct_from_export_truncation(tmp_path: Path) -> None:
    """Two independent shortfalls stay apart: the export capping a string's list, and this response
    capping its rows. Collapsing them would make a paging limit look like lost analysis."""
    many = [
        {"string_addr": "0x20000", "value": _DISPATCH_KEY, "truncated": False, "refs": _refs(10)}
    ]
    db = _ingest(tmp_path, _payload(strings=many))
    conn = _ro(db)
    try:
        res = facts.get_string_reference_anchors(conn, text=_DISPATCH_KEY, binary="webd", limit=3)
    finally:
        conn.close()
    assert res["returned"] == 3
    assert res["truncated"] is True
    assert res["response_truncated"] is True
    assert res["export_truncated"] is False  # nothing was lost by the exporter


# ── the two "no anchors" answers, neither of them a proof ────────────────────────────


def test_no_rows_is_not_no_reference(tmp_path: Path) -> None:
    """A binary with no string-reference export answers UNKNOWN, never an empty success.

    MUTATION (must go RED): have ``get_string_reference_anchors`` return the generic
    ``no_resolved_dataref`` for this case too, or return ``{found: True, anchors: []}``. Either way
    "nobody looked" becomes indistinguishable from "we looked and found nothing"."""
    db = _ingest(tmp_path, _payload())
    conn = _ro(db)
    try:
        res = facts.get_string_reference_anchors(conn, text=_DISPATCH_KEY, binary="bare_bin")
    finally:
        conn.close()
    assert res["found"] is False
    assert res["note"] == "string_refs_not_exported"
    assert "anchors" not in res


def test_unreferenced_string_is_not_proven_unreferenced(tmp_path: Path) -> None:
    """The export ran and resolved nothing: an honest empty, explicitly NOT a proof of absence --
    the same shape as an empty caller set."""
    db = _ingest(tmp_path, _payload())
    conn = _ro(db)
    try:
        res = facts.get_string_reference_anchors(conn, text="never_referenced_str", binary="webd")
    finally:
        conn.close()
    assert res["found"] is False
    assert res["note"] == "no_resolved_dataref"
    assert "NOT proof" in res["detail"]
    assert "indirect or computed reference" in res["detail"]


def test_two_empty_answers_are_distinct(tmp_path: Path) -> None:
    """'we resolved none' and 'nobody exported' must not be the same string."""
    db = _ingest(tmp_path, _payload())
    conn = _ro(db)
    try:
        resolved_none = facts.get_string_reference_anchors(conn, text="nope", binary="webd")
        never_ran = facts.get_string_reference_anchors(conn, text=_DISPATCH_KEY, binary="bare_bin")
    finally:
        conn.close()
    assert resolved_none["note"] != never_ran["note"]


# ── the parsed set vs the text set ───────────────────────────────────────────────────


def test_resolved_vs_text_distinct(tmp_path: Path) -> None:
    """The whole reason the parsed sibling exists: the TEXT search matches a mention in a COMMENT,
    the resolved one cannot.

    MUTATION (must go RED): make ``get_string_reference_anchors`` fall back to a pseudocode LIKE
    search when it has no rows -- the comment hit then reappears and the two tools stop differing,
    which is exactly the noise this feature removes."""
    db = _ingest(tmp_path, _payload())
    conn = open_db(db)
    # a function that only MENTIONS the key inside a comment -- no reference resolves to it
    conn.execute(
        "INSERT INTO functions (binary_id, name, address, pseudocode, callees, is_exported) "
        "VALUES ((SELECT id FROM binaries WHERE name='webd'), 'unrelated_helper', '0x7000', ?, "
        "'[]', 0)",
        (f"void unrelated_helper(void) {{ /* TODO: handle {_DISPATCH_KEY} later */ }}",),
    )
    conn.commit()
    conn.close()
    ro = _ro(db)
    try:
        text_hits = facts.get_functions_referencing_string(ro, text=_DISPATCH_KEY, binary="webd")
        parsed = facts.get_string_reference_anchors(ro, text=_DISPATCH_KEY, binary="webd")
    finally:
        ro.close()
    text_funcs = {f["function"] for f in text_hits["functions"]}
    parsed_funcs = {a["ref_in_func"] for a in parsed["anchors"]}
    assert "unrelated_helper" in text_funcs  # the TEXT search takes the comment bait
    assert "unrelated_helper" not in parsed_funcs  # the RESOLVED one does not
    assert text_funcs != parsed_funcs
    assert parsed_funcs == {"dispatch_request"}


# ── ingest mechanics ─────────────────────────────────────────────────────────────────


def test_absent_string_refs_key_contributes_no_rows(tmp_path: Path) -> None:
    db = _ingest(tmp_path, None)
    conn = _ro(db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM string_refs").fetchone()[0] == 0
        row = conn.execute(
            "SELECT scanned FROM detector_scan_status WHERE detector = 'string_refs' "
            "AND binary_id = (SELECT id FROM binaries WHERE name = 'webd')"
        ).fetchone()
    finally:
        conn.close()
    assert row["scanned"] == 0  # never claim an export that did not run


def test_reingest_wipes_and_rebuilds(tmp_path: Path) -> None:
    """★ WIPE-AND-REBUILD: binary_id survives a re-scan so ON DELETE CASCADE never fires; only the
    per-table DELETE clears the old rows. Without it a second analyze serves duplicated and stale
    anchors -- wrong facts, not merely extra ones.

    MUTATION (must go RED): remove ``"string_refs"`` from the DELETE tuple in
    ``ghidra_ingest._ingest_one_binary``."""
    db = _ingest(tmp_path, _payload())
    conn = open_db(db)
    sha_to_id = {r["sha256"]: r["id"] for r in conn.execute("SELECT id, sha256 FROM binaries")}
    rec = ElfRecord(
        path=Path("/fake/webd"),
        name="webd",
        arch="ARM:LE:32:v7",
        elf_type="executable",
        sha256=_SHA,
        dt_needed=[],
        protections={},
        size=4096,
    )
    ingest_ghidra_output(conn, tmp_path / "ghidra_output", [rec], sha_to_id)
    conn.commit()
    n = conn.execute(
        "SELECT COUNT(*) FROM string_refs r JOIN binaries b ON b.id = r.binary_id "
        "WHERE b.name = 'webd'"
    ).fetchone()[0]
    per_detector = conn.execute(
        "SELECT COUNT(*) FROM detector_scan_status d JOIN binaries b ON b.id = d.binary_id "
        "WHERE b.name = 'webd' AND d.detector = 'string_refs'"
    ).fetchone()[0]
    conn.close()
    assert n == 3  # 1 + 2 refs, not 6
    assert per_detector == 1
