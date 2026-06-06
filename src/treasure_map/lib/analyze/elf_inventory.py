# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
# Adapted from treasure-map-history scripts/01_find_elfs.py
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

from elftools.elf.elffile import ELFFile

logger = logging.getLogger(__name__)


@dataclass
class ElfRecord:
    path: Path
    name: str
    arch: str                          # Ghidra processor string, e.g. ARM:LE:32:v7
    elf_type: str                      # executable / shared_library / relocatable
    sha256: str
    dt_needed: list[str] = field(default_factory=list)
    protections: dict[str, object] = field(default_factory=dict)
    size: int = 0

    def dt_needed_json(self) -> str:
        return json.dumps(self.dt_needed)

    def protections_json(self) -> str:
        return json.dumps(self.protections)


def detect_arch(elf_path: Path) -> str | None:
    """Return a Ghidra-compatible processor string, or None on failure."""
    try:
        with elf_path.open("rb") as f:
            elf = ELFFile(f)
            mach = elf.header.e_machine
            ei_cls = elf.elfclass  # 32 or 64
            endian = "LE" if elf.little_endian else "BE"

            if mach == "EM_ARM":
                return f"ARM:{endian}:32:v7"
            if mach == "EM_AARCH64":
                return f"AARCH64:{endian}:64:v8A"
            if mach == "EM_MIPS":
                return f"MIPS:{endian}:{ei_cls}:default"
            if mach == "EM_386":
                return "x86:LE:32:default"
            if mach == "EM_X86_64":
                return "x86:LE:64:default"
            if mach == "EM_PPC":
                return f"PowerPC:{endian}:32:default"
            # Return UNKNOWN_ prefix so callers can decide whether to skip
            return f"UNKNOWN_{mach}:{endian}:{ei_cls}:default"
    except Exception:
        return None


def get_elf_type(elf_path: Path) -> str:
    try:
        with elf_path.open("rb") as f:
            elf = ELFFile(f)
            return {
                "ET_EXEC": "executable",
                "ET_DYN": "shared_library",
                "ET_REL": "relocatable",
            }.get(elf.header.e_type, "unknown")
    except Exception:
        return "unknown"


def has_loadable_segments(elf_path: Path) -> bool:
    """Return False for split/malformed ELFs with no valid PT_LOAD segment data."""
    try:
        file_size = elf_path.stat().st_size
        with elf_path.open("rb") as f:
            elf = ELFFile(f)
            has_load = False
            for seg in elf.iter_segments():
                if seg.header.p_type != "PT_LOAD" or seg.header.p_filesz == 0:
                    continue
                if seg.header.p_offset + seg.header.p_filesz > file_size:
                    return False  # segment data lives outside this file (Qualcomm PIL etc.)
                has_load = True
            return has_load
    except Exception:
        return False


def get_dt_needed(elf_path: Path) -> list[str]:
    """Extract DT_NEEDED entries from the .dynamic section."""
    deps: list[str] = []
    try:
        with elf_path.open("rb") as f:
            elf = ELFFile(f)
            dyn = elf.get_section_by_name(".dynamic")
            if dyn:
                for tag in dyn.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        deps.append(tag.needed)
    except Exception:
        pass
    return deps


def get_protections(elf_path: Path) -> dict[str, object]:
    """Detect ELF hardening: NX, PIE, stack canary, RELRO, fortify."""
    result: dict[str, object] = {
        "nx": True,
        "pie": False,
        "canary": False,
        "relro": "none",
        "fortify": False,
    }
    try:
        with elf_path.open("rb") as f:
            elf = ELFFile(f)
            segments = list(elf.iter_segments())

            # NX: PT_GNU_STACK present and PF_X not set
            for seg in segments:
                if seg.header.p_type == "PT_GNU_STACK":
                    result["nx"] = not bool(seg.header.p_flags & 0x1)
                    break

            # PIE: ET_DYN + PT_INTERP
            if elf.header.e_type == "ET_DYN":
                result["pie"] = any(s.header.p_type == "PT_INTERP" for s in segments)

            # RELRO: PT_GNU_RELRO = partial; DT_BIND_NOW or DT_FLAGS BIND_NOW = full
            if any(s.header.p_type == "PT_GNU_RELRO" for s in segments):
                result["relro"] = "partial"
                dyn = elf.get_section_by_name(".dynamic")
                if dyn:
                    for tag in dyn.iter_tags():
                        if tag.entry.d_tag == "DT_BIND_NOW":
                            result["relro"] = "full"
                            break
                        if tag.entry.d_tag == "DT_FLAGS" and (tag.entry.d_val & 0x8):
                            result["relro"] = "full"
                            break

            # Canary + Fortify: look for undefined dynamic symbols
            for section in elf.iter_sections():
                if section.header.sh_type == "SHT_DYNSYM":
                    for sym in section.iter_symbols():
                        if sym.entry.st_shndx == "SHN_UNDEF" and sym.name:
                            if sym.name in ("__stack_chk_fail", "__stack_chk_guard"):
                                result["canary"] = True
                            if sym.name.startswith("__") and sym.name.endswith("_chk"):
                                result["fortify"] = True
    except Exception:
        pass
    return result


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def scan_filesystem(
    fs_root: Path,
    progress_callback: object | None = None,
) -> list[ElfRecord]:
    """Walk *fs_root* and return one ElfRecord per unique ELF binary.

    Symlinks are skipped (Ghidra resolves them to the real file name, which
    causes output to be written under the wrong path).  Content-identical
    files (same sha256) are deduplicated — only the first occurrence is kept.
    """
    results: list[ElfRecord] = []
    seen_sha: set[str] = set()

    for fpath in sorted(fs_root.rglob("*")):
        if not fpath.is_file() or fpath.is_symlink():
            continue
        try:
            with fpath.open("rb") as f:
                magic = f.read(4)
            if magic != b"\x7fELF":
                continue

            arch = detect_arch(fpath)
            if not arch:
                continue
            if arch.startswith("UNKNOWN_"):
                logger.debug("skip unknown arch %s: %s", arch, fpath.name)
                continue
            if not has_loadable_segments(fpath):
                logger.debug("skip no PT_LOAD: %s", fpath.name)
                continue

            sha = sha256_file(fpath)
            if sha in seen_sha:
                logger.debug("skip dup sha256: %s", fpath.name)
                continue
            seen_sha.add(sha)

            record = ElfRecord(
                path=fpath,
                name=fpath.name,
                arch=arch,
                elf_type=get_elf_type(fpath),
                sha256=sha,
                dt_needed=get_dt_needed(fpath),
                protections=get_protections(fpath),
                size=fpath.stat().st_size,
            )
            results.append(record)
            logger.debug("found ELF: %s (%s)", fpath.name, arch)

        except (OSError, PermissionError):
            pass

    logger.info("ELF scan complete: %d unique binaries in %s", len(results), fs_root)
    return results
