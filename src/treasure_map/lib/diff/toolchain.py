# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The versions of the external diff toolchain: Ghidra, the BinExport extension, BinDiff.

A diff records them when it is computed, and both the full diff's plan and the readers compare
them with the toolchain installed now: an upgrade of any of the three makes a stored diff a
statement about other tools. All three are read from the installation itself — Ghidra's
``application.properties``, the extension's ``extension.properties``, ``bindiff --version`` — and
only when all three are read is there a toolchain to compare with; a machine that cannot read them
(no Ghidra configured, say) reports that it did not check, and never calls a diff stale or current
on that account.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from treasure_map.lib.config.config import Config, load_config


@dataclass(frozen=True)
class Toolchain:
    ghidra: str  # Ghidra's application.version
    binexport: str  # the BinExport extension's version
    bindiff: str  # the first line of ``bindiff --version``


def _properties_value(path: Path, key: str) -> str | None:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    for line in lines:
        k, sep, v = line.partition("=")
        if sep and k.strip() == key and v.strip():
            return v.strip()
    return None


def _ghidra_home(config: Config) -> Path | None:
    from treasure_map.lib.analyze.ghidra_runner import find_headless
    from treasure_map.lib.errors import GhidraNotFoundError

    try:
        headless = find_headless(config.ghidra)
    except GhidraNotFoundError:
        return None
    return Path(headless).resolve().parent.parent  # <home>/support/analyzeHeadless


def _binexport_version(home: Path, ghidra: str) -> str | None:
    """The installed BinExport extension's version: Ghidra's own Extensions directory, or the
    user's for this Ghidra version (the two places Ghidra loads an extension from)."""
    roots = [home / "Ghidra" / "Extensions"]
    user = Path.home() / ".ghidra"
    if user.is_dir():
        roots += sorted(p / "Extensions" for p in user.glob(f".ghidra_{ghidra}*"))
    for root in roots:
        value = _properties_value(root / "BinExport" / "extension.properties", "version")
        if value is not None:
            return value
    return None


def _bindiff_version() -> str | None:
    bindiff = shutil.which("bindiff")
    if bindiff is None:
        return None
    try:
        proc = subprocess.run(  # noqa: S603 -- fixed argv, no shell
            [bindiff, "--version"], capture_output=True, timeout=30
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    for line in (proc.stdout + proc.stderr).decode(errors="replace").splitlines():
        if line.strip():
            return line.strip()
    return None


def detect_toolchain(config: Config) -> Toolchain | None:
    """The toolchain installed for ``config``, or None when any of the three cannot be read."""
    home = _ghidra_home(config)
    if home is None:
        return None
    ghidra = _properties_value(home / "Ghidra" / "application.properties", "application.version")
    if ghidra is None:
        return None
    binexport = _binexport_version(home, ghidra)
    bindiff = _bindiff_version()
    if binexport is None or bindiff is None:
        return None
    return Toolchain(ghidra=ghidra, binexport=binexport, bindiff=bindiff)


# The toolchain the readers compare with, read once per process (a long-running reader must be
# restarted to see a toolchain upgraded under it). A list so a test can set it.
_current: list[Toolchain | None] = []


def current_toolchain() -> Toolchain | None:
    """The toolchain installed for the default configuration, read once per process."""
    if not _current:
        try:
            _current.append(detect_toolchain(load_config(None)))
        except Exception:  # an unreadable configuration is "not checked", never a failure
            _current.append(None)
    return _current[0]
