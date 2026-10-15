# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""A firmware file whose name is not UTF-8 is analysed like any other, not the end of the run."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from treasure_map.lib.analyze.db_ingest import ingest_elfs
from treasure_map.lib.analyze.elf_inventory import scan_filesystem
from treasure_map.lib.analyze.fs_names import db_text
from treasure_map.lib.analyze.non_binary.orchestrator import run_all_ingesters
from treasure_map.lib.analyze.symlinks import SymlinkCollector, write_symlinks
from treasure_map.lib.storage.connection import open_db

_GBK = "测试".encode("gbk")  # b'\xb2\xe2\xca\xd4' — not UTF-8
_ELF = Path(__file__).resolve().parents[2] / "fixtures" / "elfs" / "true_x86_64"


def _name(suffix: bytes) -> str:
    return os.fsdecode(_GBK + suffix)  # a str carrying surrogate escapes, as os.listdir gives it


def test_db_text_escapes_only_what_is_not_text() -> None:
    assert db_text("busybox") == "busybox"
    assert db_text("测试.conf") == "测试.conf"
    assert db_text(_name(b".conf")) == "\\xb2\\xe2\\xca\\xd4.conf"


def test_a_non_utf8_name_is_stored_on_every_path_and_stops_nothing(tmp_path: Path) -> None:
    """MUTATION: write the name as it comes (surrogates) on any of the three paths — binaries,
    non-binary files, links -> UnicodeEncodeError, the analysis stops -> RED."""
    root = tmp_path / "rootfs"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / _name(b".conf")).write_text("key=value\n")
    shutil.copy(_ELF, root / _name(b"_daemon"))
    (root / _name(b"_link")).symlink_to("etc")
    conn = open_db(tmp_path / "analysis.db")
    outcome = "ok"
    try:
        records = scan_filesystem(root)
        ingest_elfs(conn, records)
        collector = SymlinkCollector(root)
        for p in root.iterdir():
            collector.offer(p)
        write_symlinks(conn, collector.records)
        run_all_ingesters(conn, root)
    except UnicodeEncodeError as exc:
        outcome = repr(exc)
    names = {r[0] for r in conn.execute("SELECT name FROM binaries")}
    links = {r[0] for r in conn.execute("SELECT link_name FROM fs_symlinks")}
    files = {r[0] for r in conn.execute("SELECT name FROM non_binary_files")}
    conn.close()
    assert outcome == "ok"
    assert "\\xb2\\xe2\\xca\\xd4_daemon" in names
    assert "\\xb2\\xe2\\xca\\xd4_link" in links
    assert "\\xb2\\xe2\\xca\\xd4.conf" in files
