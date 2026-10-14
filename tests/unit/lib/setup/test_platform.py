# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The platform gate and the Mach-O reader."""

from __future__ import annotations

import struct
from pathlib import Path

from treasure_map.lib.setup.platform import CPU_ARM64, CPU_X86_64, detect_platform, macho_cputypes


def _p(system: str, machine: str, **kw: object) -> str:
    return detect_platform(system=system, machine=machine, environ={}, glibc=None, **kw).support  # type: ignore[arg-type]


def test_the_support_table() -> None:
    assert _p("Linux", "x86_64") == "supported"
    assert _p("Darwin", "arm64") == "supported"
    assert _p("Darwin", "x86_64") == "unverified"
    assert _p("Linux", "aarch64") == "unsupported"
    assert _p("Windows", "AMD64") == "unsupported"
    p = detect_platform(system="Linux", machine="aarch64", environ={}, glibc=None)
    assert "linux_arm_64" in p.reason and "BinDiff" in p.reason
    w = detect_platform(system="Windows", machine="AMD64", environ={}, glibc=None)
    assert "WSL2" in w.reason


def test_wsl_is_detected(tmp_path: Path) -> None:
    osrelease = tmp_path / "osrelease"
    osrelease.write_text("6.6.87.2-microsoft-standard-WSL2\n")
    assert detect_platform(system="Linux", machine="x86_64", environ={}, osrelease=osrelease).is_wsl
    assert detect_platform(
        system="Linux", machine="x86_64", environ={"WSL_DISTRO_NAME": "U"}, osrelease=tmp_path / "x"
    ).is_wsl
    assert not detect_platform(
        system="Linux", machine="x86_64", environ={}, osrelease=tmp_path / "x"
    ).is_wsl


def test_macho_slices(tmp_path: Path) -> None:
    fat = tmp_path / "fat"
    fat.write_bytes(
        struct.pack(">II", 0xCAFEBABE, 2)
        + struct.pack(">IIIII", CPU_X86_64, 3, 0x4000, 10, 14)
        + struct.pack(">IIIII", CPU_ARM64, 0, 0x8000, 10, 14)
    )
    assert macho_cputypes(fat) == {CPU_X86_64, CPU_ARM64}
    thin = tmp_path / "thin"
    thin.write_bytes(struct.pack("<II", 0xFEEDFACF, CPU_X86_64) + b"\0" * 24)
    assert macho_cputypes(thin) == {CPU_X86_64}
    elf = tmp_path / "elf"
    elf.write_bytes(b"\x7fELF" + b"\0" * 20)
    assert macho_cputypes(elf) is None
    assert macho_cputypes(tmp_path / "absent") is None
