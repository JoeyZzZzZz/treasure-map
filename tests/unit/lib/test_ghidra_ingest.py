# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for ghidra_ingest module."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from treasure_map.lib.analyze.elf_inventory import ElfRecord
from treasure_map.lib.analyze.ghidra_ingest import ingest_ghidra_output
from treasure_map.lib.storage.connection import open_db


def _make_record(name: str, sha256: str) -> ElfRecord:
    return ElfRecord(
        path=Path(f"/fake/{name}"),
        name=name,
        arch="MIPS:LE:32:default",
        elf_type="executable",
        sha256=sha256,
        dt_needed=[],
        protections={},
        size=4096,
    )


def _setup_db(tmp_path: Path) -> tuple[sqlite3.Connection, dict[str, int]]:
    """Create DB with one fake binary row, return conn and sha_to_id."""
    conn = open_db(tmp_path / "analysis.db")
    conn.execute(
        "INSERT INTO binaries (name, sha256) VALUES (?, ?)",
        ("test_bin", "a" * 64),
    )
    conn.commit()
    binary_id = conn.execute("SELECT id FROM binaries WHERE sha256 = ?", ("a" * 64,)).fetchone()[0]
    return conn, {"a" * 64: binary_id}


def _write_ghidra_json(output_dir: Path, name: str, sha256: str, data: dict) -> None:  # type: ignore[type-arg]
    output_dir.mkdir(parents=True, exist_ok=True)
    sha8 = sha256[:8]
    path = output_dir / f"{name}_{sha8}_ghidra.json"
    path.write_text(json.dumps(data))


def test_ingest_single_binary_writes_all_tables(tmp_path: Path) -> None:
    conn, sha_to_id = _setup_db(tmp_path)
    output_dir = tmp_path / "ghidra_output"
    _write_ghidra_json(
        output_dir,
        "test_bin",
        "a" * 64,
        {
            "functions": [
                {
                    "name": "main",
                    "address": "1000",
                    "size": 64,
                    "is_exported": 1,
                    "callees": ["puts"],
                    "pseudocode": "int main(){}",
                },
            ],
            "imports": [{"func_name": "puts", "lib_name": "libc.so.6"}],
            "exports": [{"func_name": "main", "address": "1000"}],
            "strings": [{"value": "hello", "address": "2000"}],
        },
    )

    rec = _make_record("test_bin", "a" * 64)
    stats = ingest_ghidra_output(conn, output_dir, [rec], sha_to_id)

    assert stats.functions_ingested == 1
    assert stats.imports_ingested == 1
    assert stats.exports_ingested == 1
    assert stats.strings_ingested == 1

    assert conn.execute("SELECT COUNT(*) FROM functions").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM imports").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM exports").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM strings").fetchone()[0] == 1
    conn.close()


def test_ingest_stores_string_truncation_flags(tmp_path: Path) -> None:
    """A truncated string export carries strings_total/strings_truncated onto the binaries row so
    get_strings can tell a consumer the stored list is only a prefix (the silent-drop red line)."""
    conn, sha_to_id = _setup_db(tmp_path)
    output_dir = tmp_path / "ghidra_output"
    _write_ghidra_json(
        output_dir,
        "test_bin",
        "a" * 64,
        {
            "functions": [],
            "imports": [],
            "exports": [],
            "strings": [{"value": "hello", "address": "2000"}],
            "strings_total": 5000,
            "strings_truncated": True,
        },
    )
    ingest_ghidra_output(conn, output_dir, [_make_record("test_bin", "a" * 64)], sha_to_id)
    row = conn.execute(
        "SELECT strings_total, strings_truncated FROM binaries WHERE id = ?",
        (sha_to_id["a" * 64],),
    ).fetchone()
    assert row[0] == 5000
    assert row[1] == 1
    conn.close()


def test_ingest_string_truncation_defaults_complete(tmp_path: Path) -> None:
    """An export WITHOUT the truncation fields (old pass) reads as complete: total = stored count,
    truncated = 0 — never a spurious 'incomplete' on a genuinely full list."""
    conn, sha_to_id = _setup_db(tmp_path)
    output_dir = tmp_path / "ghidra_output"
    _write_ghidra_json(
        output_dir,
        "test_bin",
        "a" * 64,
        {
            "functions": [],
            "imports": [],
            "exports": [],
            "strings": [
                {"value": "hello", "address": "2000"},
                {"value": "world", "address": "2008"},
            ],
        },
    )
    ingest_ghidra_output(conn, output_dir, [_make_record("test_bin", "a" * 64)], sha_to_id)
    row = conn.execute(
        "SELECT strings_total, strings_truncated FROM binaries WHERE id = ?",
        (sha_to_id["a" * 64],),
    ).fetchone()
    assert row[0] == 2
    assert row[1] == 0
    conn.close()


def test_ingest_parses_router_defaults_located(tmp_path: Path) -> None:
    """A located router_defaults table ingests its members (resolved -> key=name; unresolved ->
    key=NULL, recorded not dropped). An empty-string default stays "" (distinct from a null)."""
    conn, sha_to_id = _setup_db(tmp_path)
    output_dir = tmp_path / "ghidra_output"
    _write_ghidra_json(
        output_dir,
        "test_bin",
        "a" * 64,
        {
            "functions": [],
            "imports": [],
            "exports": [],
            "strings": [],
            "nvram_defaults": {
                "located": True,
                "symbol_addr": "0x884e4",
                "members": [
                    {"index": 0, "key": "sw_mode", "flags": 0, "default_value": "0"},
                    {"index": 894, "key": "oauth_auth_code", "flags": 128, "default_value": ""},
                ],
                "unresolved_members": [{"index": 900}],
                "truncated": False,
            },
        },
    )
    ingest_ghidra_output(conn, output_dir, [_make_record("test_bin", "a" * 64)], sha_to_id)
    rows = {
        r[0]: (r[1], r[2])
        for r in conn.execute("SELECT member_index, key, default_value FROM nvram_defaults")
    }
    assert rows[0] == ("sw_mode", "0")
    assert rows[894] == ("oauth_auth_code", "")  # empty-string default preserved, not null
    assert rows[900] == (None, None)  # unresolved member recorded as a key=NULL row
    conn.close()


def test_ingest_router_defaults_not_located_writes_nothing(tmp_path: Path) -> None:
    """A binary WITHOUT the symbol (located:false) contributes NO rows — absence reads as
    'not located' (unknown), never as 'no web-settable keys'."""
    conn, sha_to_id = _setup_db(tmp_path)
    output_dir = tmp_path / "ghidra_output"
    _write_ghidra_json(
        output_dir,
        "test_bin",
        "a" * 64,
        {
            "functions": [],
            "imports": [],
            "exports": [],
            "strings": [],
            "nvram_defaults": {"located": False},
        },
    )
    ingest_ghidra_output(conn, output_dir, [_make_record("test_bin", "a" * 64)], sha_to_id)
    assert conn.execute("SELECT COUNT(*) FROM nvram_defaults").fetchone()[0] == 0
    conn.close()


def test_ingest_parses_string_tables(tmp_path: Path) -> None:
    """Detector A: a top-level string_tables object ingests one row per entry, carrying the callee
    anchor and the detector-level completeness denormalized onto each row (neutral keys)."""
    conn, sha_to_id = _setup_db(tmp_path)
    output_dir = tmp_path / "ghidra_output"
    _write_ghidra_json(
        output_dir,
        "test_bin",
        "a" * 64,
        {
            "functions": [],
            "imports": [],
            "exports": [],
            "strings": [],
            "string_tables": {
                "tables": [
                    {
                        "table_addr": "0x74920",
                        "stride": 8,
                        "count": 2,
                        "entries": [
                            {
                                "key": "nvram_dump",
                                "func_name": "FUN_000561e4",
                                "func_addr": "0x000561e4",
                                "func_kind": "direct",
                            },
                            {
                                "key": "sys_reboot",
                                "func_name": "do_reboot",
                                "func_addr": "0x00011000",
                                "func_kind": "direct",
                            },
                        ],
                    }
                ],
                "completeness": {
                    "status": "incomplete",
                    "reason": "got_relative_and_three_field_and_mips_not_detected",
                    "scope": "absolute_2field_only",
                },
            },
        },
    )
    ingest_ghidra_output(conn, output_dir, [_make_record("test_bin", "a" * 64)], sha_to_id)
    rows = {
        r[0]: (r[1], r[2], r[3], r[4], r[5])
        for r in conn.execute(
            "SELECT key, func_name, func_addr, func_kind, entry_index, completeness_status, "
            "completeness_scope FROM string_tables"
        )
    }
    assert rows["nvram_dump"][:4] == ("FUN_000561e4", "0x000561e4", "direct", 0)
    assert rows["sys_reboot"][:4] == ("do_reboot", "0x00011000", "direct", 1)
    # the detector-level completeness rides on every row (incomplete by construction)
    st = conn.execute(
        "SELECT completeness_status, completeness_scope FROM string_tables WHERE key='nvram_dump'"
    ).fetchone()
    assert st[0] == "incomplete"
    assert st[1] == "absolute_2field_only"


def _ingest_string_tables(tmp_path: Path, st: object):  # type: ignore[no-untyped-def]
    """Ingest a payload whose string_tables value is ``st`` (a dict, or omit by passing None) and
    return the detector_scan_status rows for the binary."""
    conn, sha_to_id = _setup_db(tmp_path)
    output_dir = tmp_path / "ghidra_output"
    data: dict[str, object] = {"functions": [], "imports": [], "exports": [], "strings": []}
    if st is not None:
        data["string_tables"] = st
    _write_ghidra_json(output_dir, "test_bin", "a" * 64, data)
    ingest_ghidra_output(conn, output_dir, [_make_record("test_bin", "a" * 64)], sha_to_id)
    return conn.execute(
        "SELECT detector, scanned, supported_scope, unsupported_note, cap_hit, found_count "
        "FROM detector_scan_status"
    ).fetchall()


_COMP = {
    "status": "incomplete",
    "reason": "got_relative_and_three_field_and_mips_not_detected",
    "scope": "absolute_2field_only",
    "cap_hit": False,
}


def test_detector_status_written_even_at_zero_tables(tmp_path: Path) -> None:
    # ★ the whole point: at ZERO tables a detector_scan_status row is STILL written (scanned=1), so
    # an empty result is not read as a confident "none". The `if st_rows:` guard must not gate it.
    (row,) = _ingest_string_tables(tmp_path, {"tables": [], "completeness": _COMP})
    assert tuple(row) == ("string_tables", 1, "absolute_2field_only", _COMP["reason"], 0, 0)


def test_detector_status_cap_hit_propagates(tmp_path: Path) -> None:
    # ★ situation 3: a cap-truncated scan (cap_hit=true from the extractor) is recorded as cap_hit=1
    # -- a truncated walk never reads as a clean 0.
    (row,) = _ingest_string_tables(
        tmp_path, {"tables": [], "completeness": {**_COMP, "cap_hit": True}}
    )
    assert row[4] == 1  # cap_hit


def test_detector_status_found_count_is_tables_not_entries(tmp_path: Path) -> None:
    # found_count counts TABLES (1 here), not entries (2) -- a distinct honest count.
    table = {
        "table_addr": "0x1000",
        "stride": 8,
        "count": 2,
        "entries": [{"key": "a"}, {"key": "b"}],
    }
    (row,) = _ingest_string_tables(tmp_path, {"tables": [table], "completeness": _COMP})
    assert row[1] == 1 and row[5] == 1  # scanned=1, found_count=1 (one table)


def test_detector_status_absent_payload_is_scanned_zero(tmp_path: Path) -> None:
    # ★ old export with no detector object: record scanned=0 -- never claim a scan that did not run.
    (row,) = _ingest_string_tables(tmp_path, None)
    assert row[0] == "string_tables" and row[1] == 0  # scanned=0


def test_detector_status_idempotent_reingest_one_row(tmp_path: Path) -> None:
    # wipe-and-rebuild: re-ingesting the same binary leaves exactly one status row (DELETE loop).
    conn, sha_to_id = _setup_db(tmp_path)
    output_dir = tmp_path / "ghidra_output"
    _write_ghidra_json(
        output_dir,
        "test_bin",
        "a" * 64,
        {
            "functions": [],
            "imports": [],
            "exports": [],
            "strings": [],
            "string_tables": {"tables": [], "completeness": _COMP},
        },
    )
    rec = [_make_record("test_bin", "a" * 64)]
    ingest_ghidra_output(conn, output_dir, rec, sha_to_id)
    ingest_ghidra_output(conn, output_dir, rec, sha_to_id)  # re-ingest
    assert conn.execute("SELECT COUNT(*) FROM detector_scan_status").fetchone()[0] == 1
    conn.close()


def test_ingest_string_tables_empty_writes_nothing(tmp_path: Path) -> None:
    """An empty table list (the Java detector found no absolute-2-field table, or rejected noise)
    contributes NO rows — 'none of THIS form', never a spurious dispatch fact."""
    conn, sha_to_id = _setup_db(tmp_path)
    output_dir = tmp_path / "ghidra_output"
    _write_ghidra_json(
        output_dir,
        "test_bin",
        "a" * 64,
        {
            "functions": [],
            "imports": [],
            "exports": [],
            "strings": [],
            "string_tables": {
                "tables": [],
                "completeness": {"status": "incomplete", "scope": "absolute_2field_only"},
            },
        },
    )
    ingest_ghidra_output(conn, output_dir, [_make_record("test_bin", "a" * 64)], sha_to_id)
    assert conn.execute("SELECT COUNT(*) FROM string_tables").fetchone()[0] == 0
    conn.close()


def test_ingest_stores_a2_wrapper_fields(tmp_path: Path) -> None:
    """The A2 transport columns round-trip: a thin wrapper carries nvram_wrapper, a caller carries
    wrapper_call_args; a plain function defaults NULL/'[]' (no wrapper data until re-scan)."""
    conn, sha_to_id = _setup_db(tmp_path)
    output_dir = tmp_path / "ghidra_output"
    _write_ghidra_json(
        output_dir,
        "test_bin",
        "a" * 64,
        {
            "functions": [
                {
                    "name": "wget",
                    "address": "1000",
                    "callees": ["nvram_get"],
                    "pseudocode": "char* wget(void){}",
                    "nvram_wrapper": {"op": "read", "api": "nvram_get"},
                },
                {
                    "name": "biz",
                    "address": "2000",
                    "callees": ["wget"],
                    "pseudocode": "void biz(void){}",
                    "wrapper_call_args": [
                        {"callee": "wget", "key": "sw_mode", "key_kind": "constant"}
                    ],
                },
                {"name": "plain", "address": "3000", "callees": [], "pseudocode": "void p(){}"},
            ],
            "imports": [],
            "exports": [],
            "strings": [],
        },
    )
    ingest_ghidra_output(conn, output_dir, [_make_record("test_bin", "a" * 64)], sha_to_id)
    rows = {
        r[0]: (r[1], r[2])
        for r in conn.execute("SELECT name, nvram_wrapper, wrapper_call_args FROM functions")
    }
    assert json.loads(rows["wget"][0]) == {"op": "read", "api": "nvram_get"}
    assert json.loads(rows["biz"][1])[0]["key"] == "sw_mode"
    assert rows["plain"][0] is None and json.loads(rows["plain"][1]) == []
    conn.close()


def test_ingest_stores_address_taken_column(tmp_path: Path) -> None:
    """The address_taken transport column round-trips verbatim: a function carrying takes stores the
    {edges, truncated} object; a function without the field defaults to '{}' (no takes until a
    re-scan). get_xrefs(direction=address_taken) reads this column."""
    conn, sha_to_id = _setup_db(tmp_path)
    output_dir = tmp_path / "ghidra_output"
    take = {
        "taken_at": "0x9010",
        "taken_in_func": "register_handlers",
        "taken_in_func_addr": "0x8f00",
        "segment": ".text-literalpool",
        "nearby_symbol": None,
    }
    _write_ghidra_json(
        output_dir,
        "test_bin",
        "a" * 64,
        {
            "functions": [
                {
                    "name": "handler",
                    "address": "1000",
                    "callees": [],
                    "pseudocode": "void handler(){}",
                    "address_taken": {"edges": [take], "truncated": False},
                },
                {"name": "plain", "address": "2000", "callees": [], "pseudocode": "void p(){}"},
            ],
            "imports": [],
            "exports": [],
            "strings": [],
        },
    )
    ingest_ghidra_output(conn, output_dir, [_make_record("test_bin", "a" * 64)], sha_to_id)
    rows = {r[0]: r[1] for r in conn.execute("SELECT name, address_taken FROM functions")}
    assert json.loads(rows["handler"]) == {"edges": [take], "truncated": False}
    assert json.loads(rows["plain"]) == {}  # no field -> default '{}', never null
    conn.close()


def test_ingest_stores_callees_truncated_flag(tmp_path: Path) -> None:
    """A wide dispatcher whose callee list hit the cap carries callees_truncated=1 so the call
    graph is never read as complete; a normal function defaults to 0."""
    conn, sha_to_id = _setup_db(tmp_path)
    output_dir = tmp_path / "ghidra_output"
    _write_ghidra_json(
        output_dir,
        "test_bin",
        "a" * 64,
        {
            "functions": [
                {
                    "name": "dispatch",
                    "address": "1000",
                    "callees": ["h1", "h2"],
                    "callees_truncated": True,
                    "pseudocode": "void dispatch(){}",
                },
                {
                    "name": "small",
                    "address": "2000",
                    "callees": ["puts"],
                    "pseudocode": "void small(){}",
                },
            ],
            "imports": [],
            "exports": [],
            "strings": [],
        },
    )
    ingest_ghidra_output(conn, output_dir, [_make_record("test_bin", "a" * 64)], sha_to_id)
    rows = dict(
        conn.execute("SELECT name, callees_truncated FROM functions ORDER BY name").fetchall()
    )
    assert rows["dispatch"] == 1
    assert rows["small"] == 0
    conn.close()


def test_ingest_maps_lib_name_to_lib_soname(tmp_path: Path) -> None:
    """JSON has 'lib_name', DB column is 'lib_soname'."""
    conn, sha_to_id = _setup_db(tmp_path)
    output_dir = tmp_path / "ghidra_output"
    _write_ghidra_json(
        output_dir,
        "test_bin",
        "a" * 64,
        {
            "functions": [],
            "imports": [{"func_name": "puts", "lib_name": "libc.so.6"}],
            "exports": [],
            "strings": [],
        },
    )

    rec = _make_record("test_bin", "a" * 64)
    ingest_ghidra_output(conn, output_dir, [rec], sha_to_id)

    row = conn.execute("SELECT func_name, lib_soname FROM imports").fetchone()
    assert row["func_name"] == "puts"
    assert row["lib_soname"] == "libc.so.6"
    conn.close()


def test_ingest_computes_pseudocode_hash(tmp_path: Path) -> None:
    conn, sha_to_id = _setup_db(tmp_path)
    output_dir = tmp_path / "ghidra_output"
    pseudocode = "int main(){}"
    expected_hash = hashlib.md5(pseudocode.encode()).hexdigest()
    _write_ghidra_json(
        output_dir,
        "test_bin",
        "a" * 64,
        {
            "functions": [
                {
                    "name": "main",
                    "address": "1000",
                    "size": 64,
                    "is_exported": 1,
                    "callees": [],
                    "pseudocode": pseudocode,
                }
            ],
            "imports": [],
            "exports": [],
            "strings": [],
        },
    )

    rec = _make_record("test_bin", "a" * 64)
    ingest_ghidra_output(conn, output_dir, [rec], sha_to_id)

    row = conn.execute("SELECT pseudocode_hash FROM functions").fetchone()
    assert row["pseudocode_hash"] == expected_hash
    conn.close()


def test_ingest_handles_missing_json_file(tmp_path: Path) -> None:
    """Dirty record with no JSON file → log warning, no crash."""
    conn, sha_to_id = _setup_db(tmp_path)
    output_dir = tmp_path / "ghidra_output"
    output_dir.mkdir()

    rec = _make_record("test_bin", "a" * 64)
    stats = ingest_ghidra_output(conn, output_dir, [rec], sha_to_id)

    assert stats.binaries_missing_json == 1
    assert stats.functions_ingested == 0
    conn.close()


def test_ingest_handles_malformed_json(tmp_path: Path) -> None:
    conn, sha_to_id = _setup_db(tmp_path)
    output_dir = tmp_path / "ghidra_output"
    output_dir.mkdir()
    bad_path = output_dir / f"test_bin_{'a' * 8}_ghidra.json"
    bad_path.write_text("{ not valid json")

    rec = _make_record("test_bin", "a" * 64)
    stats = ingest_ghidra_output(conn, output_dir, [rec], sha_to_id)

    assert stats.binaries_malformed_json == 1
    assert stats.functions_ingested == 0
    conn.close()


def test_ingest_empty_pseudocode_hash_null(tmp_path: Path) -> None:
    conn, sha_to_id = _setup_db(tmp_path)
    output_dir = tmp_path / "ghidra_output"
    _write_ghidra_json(
        output_dir,
        "test_bin",
        "a" * 64,
        {
            "functions": [
                {
                    "name": "thunk",
                    "address": "1000",
                    "size": 8,
                    "is_exported": 0,
                    "callees": [],
                    "pseudocode": "",
                }
            ],
            "imports": [],
            "exports": [],
            "strings": [],
        },
    )

    rec = _make_record("test_bin", "a" * 64)
    ingest_ghidra_output(conn, output_dir, [rec], sha_to_id)

    row = conn.execute("SELECT pseudocode_hash FROM functions").fetchone()
    assert row["pseudocode_hash"] is None
    conn.close()


def test_ingest_skips_when_dirty_empty(tmp_path: Path) -> None:
    """dirty_records=[] → no DB writes, no errors."""
    conn, sha_to_id = _setup_db(tmp_path)
    output_dir = tmp_path / "ghidra_output"

    stats = ingest_ghidra_output(conn, output_dir, [], sha_to_id)

    assert stats.functions_ingested == 0
    assert stats.binaries_processed == 0
    conn.close()


def test_ingest_replaces_existing_rows(tmp_path: Path) -> None:
    """Re-ingest same binary → no duplicates (DELETE before INSERT)."""
    conn, sha_to_id = _setup_db(tmp_path)
    output_dir = tmp_path / "ghidra_output"
    _write_ghidra_json(
        output_dir,
        "test_bin",
        "a" * 64,
        {
            "functions": [
                {
                    "name": "main",
                    "address": "1000",
                    "size": 64,
                    "is_exported": 1,
                    "callees": [],
                    "pseudocode": "v1",
                }
            ],
            "imports": [],
            "exports": [],
            "strings": [],
        },
    )

    rec = _make_record("test_bin", "a" * 64)

    # First ingest
    ingest_ghidra_output(conn, output_dir, [rec], sha_to_id)
    assert conn.execute("SELECT COUNT(*) FROM functions").fetchone()[0] == 1

    # Second ingest (different pseudocode)
    _write_ghidra_json(
        output_dir,
        "test_bin",
        "a" * 64,
        {
            "functions": [
                {
                    "name": "main",
                    "address": "1000",
                    "size": 64,
                    "is_exported": 1,
                    "callees": [],
                    "pseudocode": "v2",
                }
            ],
            "imports": [],
            "exports": [],
            "strings": [],
        },
    )
    ingest_ghidra_output(conn, output_dir, [rec], sha_to_id)

    # Still exactly 1 row, with new pseudocode
    rows = conn.execute("SELECT pseudocode FROM functions").fetchall()
    assert len(rows) == 1
    assert rows[0]["pseudocode"] == "v2"
    conn.close()


def test_ingest_persists_nvram_ops(tmp_path: Path) -> None:
    """gap② transport: a function's nvram_ops array round-trips into the column verbatim."""
    conn, sha_to_id = _setup_db(tmp_path)
    output_dir = tmp_path / "ghidra_output"
    ops = [
        {
            "api": "nvram_set",
            "op": "write",
            "key": "sw_mode",
            "key_kind": "constant",
            "value_source": {"kind": "param", "name": "param_2"},
        },
        {"api": "nvram_commit", "op": "commit"},
    ]
    _write_ghidra_json(
        output_dir,
        "test_bin",
        "a" * 64,
        {
            "functions": [
                {
                    "name": "set_mode",
                    "address": "1000",
                    "size": 64,
                    "is_exported": 0,
                    "callees": [],
                    "pseudocode": "void set_mode(){}",
                    "nvram_ops": ops,
                }
            ],
            "imports": [],
            "exports": [],
            "strings": [],
        },
    )
    ingest_ghidra_output(conn, output_dir, [_make_record("test_bin", "a" * 64)], sha_to_id)

    stored = conn.execute("SELECT nvram_ops FROM functions").fetchone()["nvram_ops"]
    assert json.loads(stored) == ops
    conn.close()


def test_ingest_missing_nvram_ops_defaults_empty(tmp_path: Path) -> None:
    """A function exported before nvram_ops existed (key absent) ingests as '[]', never null."""
    conn, sha_to_id = _setup_db(tmp_path)
    output_dir = tmp_path / "ghidra_output"
    _write_ghidra_json(
        output_dir,
        "test_bin",
        "a" * 64,
        {
            "functions": [
                {
                    "name": "f",
                    "address": "1000",
                    "size": 8,
                    "is_exported": 0,
                    "callees": [],
                    "pseudocode": "x",
                }
            ],
            "imports": [],
            "exports": [],
            "strings": [],
        },
    )
    ingest_ghidra_output(conn, output_dir, [_make_record("test_bin", "a" * 64)], sha_to_id)
    assert conn.execute("SELECT nvram_ops FROM functions").fetchone()["nvram_ops"] == "[]"
    conn.close()
