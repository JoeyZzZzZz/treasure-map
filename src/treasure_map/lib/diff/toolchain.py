# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The versions of the external diff toolchain: Ghidra, the BinExport extension, BinDiff.

A diff records them when it is computed, and both the full diff's plan and the readers compare
them with the toolchain installed now: an upgrade of any of the three makes a stored diff a
statement about other tools. All three are read from the installation itself — Ghidra's
``application.properties``, the extension's ``extension.properties`` and a digest of its jars (two
builds of one BinExport version stamp apart), ``bindiff --version`` — and only when all three are
read is there a toolchain to compare with; a machine that cannot read them (no Ghidra configured,
say) reports that it did not check, and never calls a diff stale or current on that account.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from treasure_map.lib.config.config import Config, load_config

# The extension locator lives with the export stamp (lib/export_stamp), which the scan imports
# without pulling this module in; its names are re-exported here for the setup and doctor code.
from treasure_map.lib.export_stamp import (
    binexport_dirs,
    binexport_lib_digest,
    binexport_stamp,
    ghidra_settings_dir,
)
from treasure_map.lib.export_stamp import properties_value as _properties_value

__all__ = [
    "Toolchain",
    "binexport_dirs",
    "binexport_lib_digest",
    "bindiff_version",
    "current_bindiff_version",
    "current_ghidra_version",
    "current_toolchain",
    "detect_toolchain",
    "ghidra_settings_dir",
]


@dataclass(frozen=True)
class Toolchain:
    ghidra: str  # Ghidra's application.version
    binexport: str  # the loaded BinExport's version + its jars' digest (11.4.3+lib:<12 hex>)
    bindiff: str  # the first line of ``bindiff --version``


def _ghidra_home(config: Config) -> Path | None:
    from treasure_map.lib.analyze.ghidra_runner import find_headless
    from treasure_map.lib.errors import GhidraNotFoundError

    try:
        headless = find_headless(config.ghidra)
    except GhidraNotFoundError:
        return None
    return Path(headless).resolve().parent.parent  # <home>/support/analyzeHeadless


def _binexport_version(home: Path) -> str | None:
    """The stamp of the one BinExport Ghidra at ``home`` loads: its version plus the digest of its
    jars (``11.4.3+lib:<12 hex>``), so two builds of one version stamp apart. None — not checked —
    when there is no loaded copy, two of them (Ghidra may load either), or the settings directory
    cannot be determined."""
    dirs = binexport_dirs(home)
    if dirs is None or len(dirs) != 1:
        return None
    return binexport_stamp(dirs[0])


def bindiff_version() -> str | None:
    """The first line of ``bindiff --version``, or None when BinDiff is not there."""
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
    binexport = _binexport_version(home)
    bindiff = bindiff_version()
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


# The Ghidra version installed for the default configuration, read once per process and on its
# own: a machine that only scans has no BinDiff, and detect_toolchain would then read nothing.
# A list so a test can set it.
_current_ghidra: list[str | None] = []


def current_ghidra_version() -> str | None:
    """The installed Ghidra's ``application.version``, or None when it cannot be read. Read once
    per process: a long-running reader started before an upgrade keeps the old value until it is
    restarted."""
    if not _current_ghidra:
        try:
            home = _ghidra_home(load_config(None))
            value = (
                _properties_value(home / "Ghidra" / "application.properties", "application.version")
                if home is not None
                else None
            )
        except Exception:  # an unreadable configuration is "not checked", never a failure
            value = None
        _current_ghidra.append(value)
    return _current_ghidra[0]


# The BinDiff installed, read once per process (a diff's only tool of its own). A list so a test
# can set it.
_current_bindiff: list[str | None] = []


def current_bindiff_version() -> str | None:
    """``bindiff --version``'s first line, read once per process (None: not installed)."""
    if not _current_bindiff:
        _current_bindiff.append(bindiff_version())
    return _current_bindiff[0]
