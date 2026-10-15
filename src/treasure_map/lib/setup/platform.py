# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Which platform tmap is running on, and whether its toolchain can run there.

The toolchain sets the bounds: Ghidra ships its native decompiler for linux_x86_64, mac_x86_64 and
mac_arm_64 only, and BinDiff has no arm64 Linux build. So ``linux-x86_64`` (WSL2 included) and
``darwin-arm64`` are supported, ``darwin-x86_64`` runs the same toolchain but has not been
acceptance-tested, and everything else is refused before ``tmap init`` writes anything.
"""

from __future__ import annotations

import os
import platform as _stdlib_platform
import struct
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

Support = Literal["supported", "unverified", "unsupported"]

SUPPORTED = ("linux-x86_64", "darwin-arm64")
UNVERIFIED = ("darwin-x86_64",)

_UNSUPPORTED_REASON = {
    "linux-aarch64": (
        "Ghidra ships no linux_arm_64 decompiler and BinDiff has no arm64 Linux build"
    ),
}


@dataclass(frozen=True)
class Platform:
    key: str  # "linux-x86_64" | "darwin-arm64" | "darwin-x86_64" | anything else, as read
    support: Support
    is_wsl: bool
    glibc: tuple[int, int] | None  # None off glibc (macOS, musl)
    reason: str

    @property
    def is_darwin(self) -> bool:
        return self.key.startswith("darwin-")

    @property
    def ghidra_native_dir(self) -> str | None:
        """Ghidra's ``os/<dir>`` name for this platform's native binaries."""
        return {
            "linux-x86_64": "linux_x86_64",
            "darwin-arm64": "mac_arm_64",
            "darwin-x86_64": "mac_x86_64",
        }.get(self.key)


def _arch(system: str, machine: str) -> str:
    m = machine.lower()
    if m in ("x86_64", "amd64"):
        return "x86_64"
    if m in ("arm64", "aarch64"):
        return "arm64" if system == "darwin" else "aarch64"
    return m


def _glibc_version() -> tuple[int, int] | None:
    try:
        value = os.confstr("CS_GNU_LIBC_VERSION")
    except (AttributeError, ValueError, OSError):
        return None
    if not value or not value.startswith("glibc "):
        return None
    parts = value.split()[1].split(".")
    try:
        return int(parts[0]), int(parts[1]) if len(parts) > 1 else 0
    except ValueError:
        return None


def _is_wsl(environ: Mapping[str, str], osrelease: Path) -> bool:
    if environ.get("WSL_DISTRO_NAME"):
        return True
    try:
        return "microsoft" in osrelease.read_text(errors="replace").lower()
    except OSError:
        return False


def _rosetta() -> bool:
    """Whether this process is translated by Rosetta — only ever asked on a real Mac."""
    if _stdlib_platform.system() != "Darwin":
        return False
    import subprocess

    try:
        out = subprocess.run(  # noqa: S603,S607 -- fixed argv, no shell
            ["sysctl", "-n", "sysctl.proc_translated"], capture_output=True, text=True, timeout=5
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    return out.strip() == "1"


def detect_platform(
    *,
    system: str | None = None,
    machine: str | None = None,
    environ: Mapping[str, str] | None = None,
    osrelease: Path = Path("/proc/sys/kernel/osrelease"),
    glibc: tuple[int, int] | None | Literal["detect"] = "detect",
    translated: bool | Literal["detect"] = "detect",
) -> Platform:
    """The running platform. Every input can be given, so a test can stand on any platform.

    An x86_64 Python under Rosetta on Apple Silicon reports x86_64; the machine is arm64, and the
    toolchain tmap starts (a JDK, Ghidra, BinDiff) runs natively — so it is read as darwin-arm64,
    with the translation named in ``reason``."""
    sys_name = (system if system is not None else _stdlib_platform.system()).lower()
    mach = machine if machine is not None else _stdlib_platform.machine()
    rosetta = (
        sys_name == "darwin"
        and _arch(sys_name, mach) == "x86_64"
        and (_rosetta() if translated == "detect" else translated)
    )
    if rosetta:
        mach = "arm64"
    env = os.environ if environ is None else environ
    key = f"{sys_name}-{_arch(sys_name, mach)}"
    wsl = sys_name == "linux" and _is_wsl(env, osrelease)
    libc = (_glibc_version() if sys_name == "linux" else None) if glibc == "detect" else glibc
    if key in SUPPORTED:
        note = "Python runs under Rosetta; the toolchain is arm64" if rosetta else ""
        return Platform(key, "supported", wsl, libc, note)
    if key in UNVERIFIED:
        return Platform(
            key, "unverified", wsl, libc, "Intel Mac: supported toolchain, not acceptance-tested"
        )
    if sys_name.startswith(("windows", "cygwin", "msys", "mingw")):
        reason = "native Windows is not supported: use WSL2"
    else:
        reason = _UNSUPPORTED_REASON.get(key, f"{key}: no supported toolchain for this platform")
    return Platform(key, "unsupported", wsl, libc, reason)


# ── Mach-O architecture (no `lipo` needed) ───────────────────────────────────────────────────

CPU_X86_64 = 0x01000007
CPU_ARM64 = 0x0100000C

_FAT_MAGICS = (0xCAFEBABE, 0xCAFEBABF)  # big-endian fat headers (32- and 64-bit arch tables)
_THIN_MAGIC_LE = 0xFEEDFACF  # a 64-bit Mach-O as it reads little-endian


def macho_cputypes(path: Path) -> set[int] | None:
    """The CPU types a Mach-O file carries (every slice of a universal binary), or None when the
    file cannot be read or is not a 64-bit Mach-O / fat Mach-O."""
    try:
        with path.open("rb") as fh:
            head = fh.read(8)
            if len(head) < 8:
                return None
            (magic_be,) = struct.unpack(">I", head[:4])
            if magic_be in _FAT_MAGICS:
                (count,) = struct.unpack(">I", head[4:8])
                if count == 0 or count > 64:
                    return None
                entry = 32 if magic_be == 0xCAFEBABF else 20
                table = fh.read(entry * count)
                if len(table) < entry * count:
                    return None
                return {
                    struct.unpack(">I", table[i * entry : i * entry + 4])[0] for i in range(count)
                }
            (magic_le,) = struct.unpack("<I", head[:4])
            if magic_le == _THIN_MAGIC_LE:
                (cputype,) = struct.unpack("<I", head[4:8])
                return {cputype}
            return None
    except OSError:
        return None
