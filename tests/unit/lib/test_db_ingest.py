# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

from pathlib import Path

from treasure_map.lib.analyze.db_ingest import ingest_elfs
from treasure_map.lib.analyze.elf_inventory import ElfRecord
from treasure_map.lib.storage.connection import open_db


def _make_record(name: str, sha: str, arch: str = "ARM:LE:32:v7") -> ElfRecord:
    return ElfRecord(
        path=Path(f"/fake/bin/{name}"),
        name=name,
        arch=arch,
        elf_type="executable",
        sha256=sha,
        dt_needed=["libc.so.0"],
        protections={"nx": True, "pie": False, "canary": False, "relro": "none", "fortify": False},
        size=4096,
    )


def test_ingest_elfs_round_trip(tmp_path):
    conn = open_db(tmp_path / "analysis.db")
    records = [
        _make_record("httpd", "aaa111"),
        _make_record("busybox", "bbb222"),
    ]
    sha_to_id = ingest_elfs(conn, records)
    assert len(sha_to_id) == 2
    assert "aaa111" in sha_to_id
    assert "bbb222" in sha_to_id

    rows = conn.execute("SELECT name, arch, sha256 FROM binaries ORDER BY name").fetchall()
    assert len(rows) == 2
    assert rows[0]["name"] == "busybox"
    assert rows[1]["arch"] == "ARM:LE:32:v7"
    conn.close()


def test_ingest_elfs_idempotent(tmp_path):
    """Re-ingesting the same records must not raise or duplicate rows."""
    conn = open_db(tmp_path / "analysis.db")
    rec = _make_record("dropbear", "ccc333")
    ingest_elfs(conn, [rec])
    ingest_elfs(conn, [rec])  # second call is a no-op
    count = conn.execute("SELECT COUNT(*) FROM binaries").fetchone()[0]
    assert count == 1
    conn.close()


def test_ingest_elfs_bits_extracted(tmp_path):
    """bits column should be parsed from the arch string."""
    conn = open_db(tmp_path / "analysis.db")
    ingest_elfs(conn, [_make_record("foo", "ddd444", arch="MIPS:BE:32:default")])
    row = conn.execute("SELECT bits FROM binaries WHERE sha256='ddd444'").fetchone()
    assert row["bits"] == 32
    conn.close()


def test_ingest_elfs_returns_existing_ids(tmp_path):
    """IDs for pre-existing rows are returned even when INSERT is a no-op."""
    conn = open_db(tmp_path / "analysis.db")
    rec = _make_record("boa", "eee555")
    ids_first = ingest_elfs(conn, [rec])
    ids_second = ingest_elfs(conn, [rec])
    assert ids_first["eee555"] == ids_second["eee555"]
    conn.close()


def test_ingest_empty_list(tmp_path):
    conn = open_db(tmp_path / "analysis.db")
    result = ingest_elfs(conn, [])
    assert result == {}
    conn.close()


def test_open_db_creates_schema(tmp_path):
    conn = open_db(tmp_path / "new.db")
    tables = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    assert "binaries" in tables
    assert "functions" in tables
    assert "xrefs" in tables
    conn.close()
