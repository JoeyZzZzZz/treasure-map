# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
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
