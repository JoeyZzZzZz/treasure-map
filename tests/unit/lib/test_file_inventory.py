# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The file inventory (lib/analyze/file_inventory): every file under the firmware root, with what
the scan took it in as, or why it did not.

Zero real data: every ELF here is a synthetic header built below.
"""

from __future__ import annotations

import dataclasses
import os
import sqlite3
import struct
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from treasure_map.lib.analyze import non_binary
from treasure_map.lib.analyze.elf_inventory import scan_filesystem
from treasure_map.lib.analyze.file_inventory import build_file_inventory, file_type_of
from treasure_map.lib.analyze.non_binary.orchestrator import _MAX_BYTES, run_all_ingesters
from treasure_map.lib.analyze.pipeline import run_analyze
from treasure_map.lib.analyze.symlinks import SymlinkCollector
from treasure_map.lib.config.config import Config
from treasure_map.lib.storage.connection import open_db
from treasure_map.lib.workspace.workspace import Workspace

EM_ARM = 40
ET_REL, ET_EXEC = 1, 2


def _elf(e_type: int, *, machine: int = EM_ARM, loadable: bool = False, tag: bytes = b"") -> bytes:
    """A little-endian ELF32 header, with one PT_LOAD program header covering the file when
    ``loadable`` (else no program header at all). ``tag`` is appended so two files can differ."""
    phnum = 1 if loadable else 0
    phoff = 52 if loadable else 0
    total = 52 + 32 * phnum + len(tag)
    ident = b"\x7fELF" + bytes([1, 1, 1]) + bytes(9)
    header = ident + struct.pack(
        "<HHIIIIIHHHHHH", e_type, machine, 1, 0, phoff, 0, 0, 52, 32, phnum, 40, 0, 0
    )
    phdr = struct.pack("<IIIIIIII", 1, 0, 0, 0, total, total, 5, 0x1000) if loadable else b""
    return header + phdr + tag


def _write(root: Path, rel: str, data: bytes) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


@pytest.fixture
def rootfs(tmp_path: Path) -> Path:
    root = tmp_path / "rootfs"
    _write(root, "bin/app", _elf(ET_EXEC, loadable=True, tag=b"app"))
    _write(root, "usr/bin/app_copy", _elf(ET_EXEC, loadable=True, tag=b"app"))  # same bytes
    _write(root, "lib/modules/x.ko", _elf(ET_REL))
    _write(root, "bin/split", _elf(ET_EXEC))  # an executable with no loadable segment
    _write(root, "bin/odd", _elf(ET_EXEC, machine=0x7777, loadable=True))
    _write(root, "bin/stub", b"\x7fELF\x01")  # a header cut short
    _write(root, "etc/init.sh", b"#!/bin/sh\necho hi\n")
    _write(root, "etc/version", b"1.2.3\n")
    _write(root, "etc/empty", b"")
    _write(root, "etc/blob", b"\x00\x01\x02payload")
    big = root / "opt/big.dat"
    big.parent.mkdir(parents=True)
    with big.open("wb") as fh:
        fh.truncate(_MAX_BYTES + 1)
    (root / "bin/sh").symlink_to("app")
    os.mkfifo(root / "dev_fifo")
    return root


def _scan(conn: sqlite3.Connection, root: Path) -> dict[str, tuple[str, str | None, str | None]]:
    records = scan_filesystem(root, symlink_collector=SymlinkCollector(root))
    stats = run_all_ingesters(conn, root)
    build_file_inventory(conn, root, records, ingest_failed=stats.ingest_failed)
    return {
        p: (t, i, r)
        for p, t, i, r in conn.execute(
            "SELECT path, file_type, inventoried_as, not_inventoried_reason FROM file_inventory"
        )
    }


def test_each_file_reads_what_the_scan_took_it_in_as_or_why_not(
    rootfs: Path, tmp_path: Path
) -> None:
    """★ Every regular and special file has one row: what the ELF walk or a non-binary ingester
    took it in as, or the reason neither did — a kernel module is et_rel, an extensionless text
    file is no_ingester, the second copy of an ELF is duplicate_content. A symlink is not a row
    (fs_symlinks holds it).

    MUTATION (verified RED, 1 failed each): drop the ET_REL branch (et_rel read as
    no_loadable_segments) -> RED; drop the duplicate check -> app_copy reads unreadable -> RED;
    drop the size limit -> big.dat reads no_ingester -> RED; drop the unknown-machine check ->
    RED; read a special file's content -> the test hangs on the FIFO (not run as a mutation)."""
    conn = open_db(tmp_path / "a.db")
    rows = _scan(conn, rootfs)
    assert rows == {
        "bin/app": ("elf_exec", "elf", None),
        "usr/bin/app_copy": ("elf_exec", None, "duplicate_content"),
        "lib/modules/x.ko": ("elf_rel", None, "et_rel"),
        "bin/split": ("elf_exec", None, "no_loadable_segments"),
        "bin/odd": ("elf_exec", None, "unsupported_arch"),
        "bin/stub": ("elf_other", None, "elf_unreadable"),
        "etc/init.sh": ("script", "non_binary:shell_script", None),
        "etc/version": ("text", None, "no_ingester"),
        "etc/empty": ("empty", None, "no_ingester"),
        "etc/blob": ("binary", None, "no_ingester"),
        "opt/big.dat": ("binary", None, "too_large"),
        "dev_fifo": ("special", None, "not_regular_file"),
    }


def test_two_scans_build_the_same_table(rootfs: Path, tmp_path: Path) -> None:
    """Rebuilt on every scan: a second scan of the same tree holds exactly the first's rows, with
    nothing left over or doubled.

    MUTATION (verified RED, 1 failed): drop the DELETE before the insert -> every row twice ->
    RED."""
    conn = open_db(tmp_path / "a.db")
    _scan(conn, rootfs)
    first = conn.execute(
        "SELECT path, sha256, size, file_type, inventoried_as, "
        "not_inventoried_reason FROM file_inventory ORDER BY path"
    ).fetchall()
    _scan(conn, rootfs)
    second = conn.execute(
        "SELECT path, sha256, size, file_type, inventoried_as, "
        "not_inventoried_reason FROM file_inventory ORDER BY path"
    ).fetchall()
    assert [tuple(r) for r in first] == [tuple(r) for r in second]
    assert len(first) == 12


def test_a_file_an_ingester_failed_on_reads_ingest_failed(
    rootfs: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file an ingester claimed and then failed on (its row rolled back) reads ingest_failed,
    not no_ingester.

    MUTATION (verified RED, 1 failed): stop the orchestrator recording the failure -> RED."""

    def boom(conn: sqlite3.Connection, file_id: int, f: object) -> int:
        raise RuntimeError("synthetic ingest failure")

    registry = [
        dataclasses.replace(i, ingest=boom) if i.kind == "shell_script" else i
        for i in non_binary.INGESTER_REGISTRY
    ]
    monkeypatch.setattr(non_binary, "INGESTER_REGISTRY", registry)
    rows = _scan(open_db(tmp_path / "a.db"), rootfs)
    assert rows["etc/init.sh"] == ("script", None, "ingest_failed")


def test_an_unreadable_file_reads_unreadable(tmp_path: Path) -> None:
    """A file that cannot be opened is still a row, with the reason, never dropped."""
    if os.geteuid() == 0:
        pytest.skip("root reads a mode-000 file")
    root = tmp_path / "rootfs"
    locked = _write(root, "etc/secret", b"x")
    locked.chmod(0)
    try:
        rows = _scan(open_db(tmp_path / "a.db"), root)
    finally:
        locked.chmod(0o600)
    assert rows == {"etc/secret": ("unreadable", None, "unreadable")}


@pytest.mark.parametrize(
    ("head", "size", "expected"),
    [
        (_elf(ET_REL), 52, "elf_rel"),
        (_elf(3), 52, "elf_dyn"),
        (_elf(4), 52, "elf_core"),
        (_elf(0x99), 52, "elf_other"),
        (b"#!/bin/sh\n", 10, "script"),
        (b"", 0, "empty"),
        ("café\n".encode(), 6, "text"),
        (b"\xff\xfe\x00", 3, "binary"),
        (b"\xff\xfeab", 4, "binary"),  # no NUL, but not UTF-8
        # a full sample cut through a multi-byte character is still text
        (b"a" * 8191 + "é".encode()[:1], 9000, "text"),
    ],
    ids=[
        "et_rel",
        "et_dyn",
        "et_core",
        "et_unknown",
        "shebang",
        "empty",
        "utf8_text",
        "nul",
        "not_utf8",
        "cut_multibyte",
    ],
)
def test_the_file_type_is_read_from_the_bytes(head: bytes, size: int, expected: str) -> None:
    """MUTATION (verified RED each): read e_type big-endian always -> RED; drop the tolerance for
    a sample cut through a multi-byte character -> cut_multibyte reads binary -> RED."""
    assert file_type_of(head, size) == expected


def test_the_scan_builds_the_inventory(tmp_path: Path) -> None:
    """run_analyze builds the table after the two inventories.

    MUTATION (verified RED, 1 failed): drop the call from run_analyze -> RED."""
    root = tmp_path / "fs"
    _write(root, "etc/version", b"1\n")
    runner = MagicMock()
    runner.get_headless.return_value = Path("/fake/headless")
    runner.run_all.return_value = []
    runner.pass_version.return_value = "testpass"
    runner.ghidra_version.return_value = "11.4.3"
    with patch("treasure_map.lib.analyze.pipeline.GhidraRunner", return_value=runner):
        with Workspace(tmp_path / "ws") as ws:
            run_analyze(root, ws, Config())
            db = ws.db_path
    conn = sqlite3.connect(db)
    assert conn.execute(
        "SELECT path, inventoried_as, not_inventoried_reason FROM file_inventory"
    ).fetchall() == [("etc/version", None, "no_ingester")]


def test_an_older_database_opens_with_an_empty_table(tmp_path: Path) -> None:
    """A database built before the table existed gains it, empty, on open."""
    db = tmp_path / "old.db"
    conn = open_db(db)
    conn.execute("DROP TABLE file_inventory")
    conn.commit()
    conn.close()
    conn = open_db(db)
    assert conn.execute("SELECT COUNT(*) FROM file_inventory").fetchone()[0] == 0


def test_a_row_holds_exactly_one_of_the_two_answers(tmp_path: Path) -> None:
    """The schema refuses a row with both inventoried_as and a reason, or with neither."""
    conn = open_db(tmp_path / "a.db")
    for inv, reason in (("elf", "et_rel"), (None, None)):
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO file_inventory (path, file_type, inventoried_as, "
                "not_inventoried_reason) VALUES ('x', 'text', ?, ?)",
                (inv, reason),
            )
