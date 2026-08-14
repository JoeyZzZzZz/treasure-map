# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

import pytest

from treasure_map.lib.analyze.elf_inventory import (
    ElfRecord,
    detect_arch,
    get_dt_needed,
    get_elf_type,
    get_protections,
    has_loadable_segments,
    has_substantial_text,
    scan_filesystem,
    sha256_file,
)

FIXTURES = Path(__file__).parent.parent.parent / "fixtures" / "elfs"
TRUE_ELF = FIXTURES / "true_x86_64"
LIBZ_ELF = FIXTURES / "libz_x86_64.so"


# ── helpers ────────────────────────────────────────────────────────────────────


def _skip_if_missing(path: Path) -> pytest.MarkDecorator:
    return pytest.mark.skipif(not path.exists(), reason=f"fixture missing: {path}")


# ── has_substantial_text (red-line: tell a failed empty from a code-free empty) ──────


@_skip_if_missing(LIBZ_ELF)
def test_has_substantial_text_true_on_code_binary() -> None:
    # A real shared library carries an executable .text section -> a 0-function result would be a
    # FAILED analysis, not "clean".
    assert has_substantial_text(LIBZ_ELF) is True


def test_has_substantial_text_false_on_non_elf(tmp_path: Path) -> None:
    # A non-ELF / unreadable file cannot be judged to have code -> conservatively False (never
    # manufacture a spurious "failed" that would re-analyze forever).
    garbage = tmp_path / "notelf"
    garbage.write_bytes(b"not an elf at all")
    assert has_substantial_text(garbage) is False


# ── detect_arch ────────────────────────────────────────────────────────────────


@_skip_if_missing(TRUE_ELF)
def test_detect_arch_x86_64(tmp_path):
    arch = detect_arch(TRUE_ELF)
    assert arch == "x86:LE:64:default"


def test_detect_arch_nonexistent(tmp_path):
    assert detect_arch(tmp_path / "ghost.elf") is None


def test_detect_arch_non_elf(tmp_path):
    f = tmp_path / "notelf.bin"
    f.write_bytes(b"\x00\x01\x02\x03" * 10)
    assert detect_arch(f) is None


# ── get_elf_type ───────────────────────────────────────────────────────────────


@_skip_if_missing(TRUE_ELF)
def test_get_elf_type_executable():
    # true_x86_64 is a PIE (ET_DYN with interpreter), but raw type check is ET_DYN
    result = get_elf_type(TRUE_ELF)
    assert result in ("executable", "shared_library")


@_skip_if_missing(LIBZ_ELF)
def test_get_elf_type_shared_library():
    assert get_elf_type(LIBZ_ELF) == "shared_library"


# ── has_loadable_segments ──────────────────────────────────────────────────────


@_skip_if_missing(TRUE_ELF)
def test_has_loadable_segments_real_elf():
    assert has_loadable_segments(TRUE_ELF) is True


def test_has_loadable_segments_empty_file(tmp_path):
    f = tmp_path / "empty.elf"
    f.write_bytes(b"")
    assert has_loadable_segments(f) is False


# ── sha256_file ────────────────────────────────────────────────────────────────


def test_sha256_file(tmp_path):
    f = tmp_path / "data.bin"
    f.write_bytes(b"hello world")
    expected = hashlib.sha256(b"hello world").hexdigest()
    assert sha256_file(f) == expected


# ── get_dt_needed ──────────────────────────────────────────────────────────────


@_skip_if_missing(TRUE_ELF)
def test_get_dt_needed_has_entries():
    deps = get_dt_needed(TRUE_ELF)
    assert isinstance(deps, list)
    # /usr/bin/true links against libc at minimum
    assert any("libc" in d for d in deps)


# ── get_protections ────────────────────────────────────────────────────────────


@_skip_if_missing(TRUE_ELF)
def test_get_protections_keys():
    prot = get_protections(TRUE_ELF)
    for key in ("nx", "pie", "canary", "relro", "fortify"):
        assert key in prot


@_skip_if_missing(TRUE_ELF)
def test_get_protections_true_has_pie():
    prot = get_protections(TRUE_ELF)
    assert prot["pie"] is True


# ── scan_filesystem ────────────────────────────────────────────────────────────


@_skip_if_missing(TRUE_ELF)
def test_scan_filesystem_finds_elfs(tmp_path):
    # Build a mini fs_root with the two fixtures
    fs = tmp_path / "rootfs"
    bin_dir = fs / "bin"
    lib_dir = fs / "lib"
    bin_dir.mkdir(parents=True)
    lib_dir.mkdir(parents=True)
    shutil.copy(TRUE_ELF, bin_dir / "true")
    shutil.copy(LIBZ_ELF, lib_dir / "libz.so")

    records = scan_filesystem(fs)
    assert len(records) == 2
    names = {r.name for r in records}
    assert "true" in names
    assert "libz.so" in names


def test_scan_filesystem_skips_non_elf(tmp_path):
    fs = tmp_path / "rootfs" / "bin"
    fs.mkdir(parents=True)
    (fs / "script.sh").write_bytes(b"#!/bin/sh\necho hello\n")
    (fs / "data.bin").write_bytes(b"\x00" * 100)
    records = scan_filesystem(tmp_path / "rootfs")
    assert records == []


def test_scan_filesystem_deduplicates(tmp_path):
    """Two files with the same content → only one ElfRecord."""
    if not TRUE_ELF.exists():
        pytest.skip("fixture missing")
    fs = tmp_path / "rootfs"
    (fs / "bin").mkdir(parents=True)
    (fs / "usr" / "bin").mkdir(parents=True)
    shutil.copy(TRUE_ELF, fs / "bin" / "true")
    shutil.copy(TRUE_ELF, fs / "usr" / "bin" / "true")  # identical content
    records = scan_filesystem(fs)
    assert len(records) == 1


def test_scan_filesystem_skips_symlinks(tmp_path):
    if not TRUE_ELF.exists():
        pytest.skip("fixture missing")
    fs = tmp_path / "rootfs" / "bin"
    fs.mkdir(parents=True)
    real = fs / "true"
    shutil.copy(TRUE_ELF, real)
    link = fs / "true_link"
    link.symlink_to(real)
    records = scan_filesystem(tmp_path / "rootfs")
    assert len(records) == 1  # symlink is skipped


# ── ElfRecord helpers ──────────────────────────────────────────────────────────


def test_elf_record_json_helpers():
    rec = ElfRecord(
        path=Path("/fake/bin/foo"),
        name="foo",
        arch="ARM:LE:32:v7",
        elf_type="executable",
        sha256="abc123",
        dt_needed=["libc.so.0", "libssl.so.1"],
        protections={
            "nx": True,
            "pie": False,
            "canary": True,
            "relro": "partial",
            "fortify": False,
        },
        size=12345,
    )
    assert '"libc.so.0"' in rec.dt_needed_json()
    assert '"nx": true' in rec.protections_json()
