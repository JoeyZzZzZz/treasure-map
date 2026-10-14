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

import getpass
import hashlib
import os
import shutil
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from treasure_map.lib.config.config import Config, load_config


@dataclass(frozen=True)
class Toolchain:
    ghidra: str  # Ghidra's application.version
    binexport: str  # the loaded BinExport's version + its jars' digest (11.4.3+lib:<12 hex>)
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


def ghidra_settings_dir(
    ghidra_home: Path,
    *,
    environ: Mapping[str, str] | None = None,
    user_home: Path | None = None,
    platform: str | None = None,
    user_name: str | None = None,
) -> Path | None:
    """The user settings directory Ghidra at ``ghidra_home`` uses (where it keeps
    ``java_home.save`` and loads user extensions from), or None when it cannot be determined.

    Ghidra 11.4 puts it under ``$XDG_CONFIG_HOME`` when that is set, else ``~/.config`` (Linux) or
    ``~/Library`` (macOS), as ``ghidra/ghidra_<version>_<release name>``; when that base is not
    inside the home directory the ``ghidra`` part is prefixed with ``<user name>-``. None — never a
    guess — when ``launch.properties`` overrides the location (``-Dapplication.settingsdir``), when
    ``XDG_CONFIG_HOME`` is not an absolute path (Ghidra itself refuses it), or when the version or
    release name cannot be read. The older ``~/.ghidra/.ghidra_<version>`` directory is NOT this
    one, and Ghidra 11.4 does not load extensions from it."""
    env = os.environ if environ is None else environ
    home = Path.home() if user_home is None else user_home
    plat = sys.platform if platform is None else platform
    try:
        launch = (ghidra_home / "support" / "launch.properties").read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError:
        launch = ""
    for line in launch.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "-Dapplication.settingsdir" in stripped:
            return None
    props = ghidra_home / "Ghidra" / "application.properties"
    version = _properties_value(props, "application.version")
    release = _properties_value(props, "application.release.name")
    if version is None or release is None:
        return None
    xdg = env.get("XDG_CONFIG_HOME")
    if xdg:
        if not os.path.isabs(xdg):
            return None
        base = Path(xdg)
    else:
        base = home / ("Library" if plat == "darwin" else ".config")
    try:
        inside = Path(os.path.abspath(base)).is_relative_to(os.path.abspath(home))
    except ValueError:
        inside = False
    if inside:
        top = "ghidra"
    else:
        name = user_name if user_name is not None else getpass.getuser()
        top = f"{name}-ghidra"
    return base / top / f"ghidra_{version}_{release}"


def _loadable_binexport(ext_dir: Path) -> bool:
    """A BinExport directory Ghidra would load: it has its properties and its jar, and is not
    marked for removal."""
    if (ext_dir / "extension.properties.uninstalled").exists():
        return False
    if (ext_dir / "Module.manifest.uninstalled").exists():
        return False
    return (ext_dir / "extension.properties").is_file() and (
        ext_dir / "lib" / "BinExport.jar"
    ).is_file()


def binexport_dirs(
    ghidra_home: Path,
    *,
    environ: Mapping[str, str] | None = None,
    user_home: Path | None = None,
    platform: str | None = None,
    user_name: str | None = None,
) -> list[Path] | None:
    """The BinExport extension directories Ghidra at ``ghidra_home`` actually loads: its own
    ``Ghidra/Extensions/BinExport`` and the one under its user settings directory. The old
    ``~/.ghidra`` location is not counted (Ghidra 11.4 does not load it). None — unknown — when the
    settings directory cannot be determined, since a copy there could not be ruled out."""
    settings = ghidra_settings_dir(
        ghidra_home, environ=environ, user_home=user_home, platform=platform, user_name=user_name
    )
    if settings is None:
        return None
    found: list[Path] = []
    seen: set[str] = set()
    for ext in (
        ghidra_home / "Ghidra" / "Extensions" / "BinExport",
        settings / "Extensions" / "BinExport",
    ):
        if not _loadable_binexport(ext):
            continue
        key = os.path.realpath(ext)
        if key not in seen:
            seen.add(key)
            found.append(ext)
    return found


def binexport_lib_digest(ext_dir: Path) -> str:
    """A digest of the extension's code: every ``lib/*.jar`` by file name, sha256 of the
    concatenated ``name\\0`` + sha256(file) entries. Two builds of one version differ here."""
    outer = hashlib.sha256()
    for jar in sorted((ext_dir / "lib").glob("*.jar"), key=lambda p: p.name):
        inner = hashlib.sha256()
        with jar.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                inner.update(chunk)
        outer.update(jar.name.encode() + b"\0" + inner.hexdigest().encode())
    return outer.hexdigest()


def _binexport_version(home: Path) -> str | None:
    """The stamp of the one BinExport Ghidra at ``home`` loads: its version plus the digest of its
    jars (``11.4.3+lib:<12 hex>``), so two builds of one version stamp apart. None — not checked —
    when there is no loaded copy, two of them (Ghidra may load either), or the settings directory
    cannot be determined."""
    dirs = binexport_dirs(home)
    if dirs is None or len(dirs) != 1:
        return None
    value = _properties_value(dirs[0] / "extension.properties", "version")
    if value is None:
        return None
    return f"{value}+lib:{binexport_lib_digest(dirs[0])[:12]}"


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
    binexport = _binexport_version(home)
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
