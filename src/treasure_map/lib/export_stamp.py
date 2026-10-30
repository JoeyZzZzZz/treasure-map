# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""What a BinExport export was made by: the export scripts, and the BinExport extension.

A scan writes each binary's ``.BinExport`` in the same Ghidra session as its extraction (the export
scripts run after ``ExportFunctions``). The export reads the program the extraction read and changes
none of its facts, so neither the scripts nor the extension are part of the extraction pass
(``pass_version``) or the scan stamp: editing a script or upgrading the extension must not make a
run's facts read as stale. They are an axis of their own, the EXPORT HASH, recorded per binary with
its archived export (``binaries.binexport_scan_meta``): a binary whose export hash differs from the
one this install would produce is re-scanned, and a diff resting on its export reads stale.

  * ``export_code_hash(builder)`` — the export script files an export took, by name and bytes.
  * ``binexport_stamp(ext_dir)`` — the extension's version plus a digest of its jars.
  * ``export_hash(script_hash, binexport)`` — the two together, the value compared.

It also answers where Ghidra loads the extension from (its install directory, or the user settings
directory) and which copy a scan's JVM — run under a temporary user home — would load.

★ Standard library only, and listed in ``rescan_version.CLOSURE_EXCLUDED``: the scan pipeline
imports it, and anything it pulled in would enter the scan stamp.
"""

from __future__ import annotations

import getpass
import hashlib
import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from functools import cache
from pathlib import Path

# <package>/lib/diff/ghidra: the export scripts, beside the diff code that once ran them.
EXPORT_SCRIPT_DIR = Path(__file__).resolve().parent / "diff" / "ghidra"
EXPORT_SCRIPT = "ExportBinExport.java"
FALLBACK_BUILDER = "FallbackBinExport2Builder.java"
# The JDK-only decision of the one operand markup failure the builder renders around.
MARKUP_JUDGE = "StackVarnodeMarkup.java"
# The builder a scan's export always takes (ExportBinExport's scan mode).
SCAN_BUILDER = "fallback"


def export_files(builder: str | None) -> tuple[str, ...]:
    """The script files an export took, by its builder; an unknown builder (a failed attempt, an
    export recorded before the builder was) takes every file it could have used."""
    if builder == "extension":
        return (EXPORT_SCRIPT, MARKUP_JUDGE)
    return (EXPORT_SCRIPT, FALLBACK_BUILDER, MARKUP_JUDGE)


def export_code_hash_in(builder: str | None, script_dir: Path) -> str:
    """The hash of the export script files ``builder`` took, read from ``script_dir`` (by name and
    bytes, never by path, so an editable and an installed copy agree; a missing file counts as
    missing, it does not fail)."""
    h = hashlib.sha256()
    for name in export_files(builder):
        h.update(name.encode() + b"\0")
        try:
            h.update((script_dir / name).read_bytes())
        except OSError:
            h.update(b"\0missing\0")
        h.update(b"\0")
    return h.hexdigest()[:16]


@cache
def export_code_hash(builder: str | None) -> str:
    """``export_code_hash_in`` for the scripts this package ships."""
    return export_code_hash_in(builder, EXPORT_SCRIPT_DIR)


def export_hash(script_hash: str, binexport: str) -> str:
    """The export hash: the export scripts' hash and the extension's stamp, together."""
    blob = f"scripts={script_hash}\0binexport={binexport}".encode()
    return hashlib.sha256(blob).hexdigest()[:16]


# ── where Ghidra loads the extension from ─────────────────────────────────────────────────────


def properties_value(path: Path, key: str) -> str | None:
    """The value of ``key`` in a Java properties file, or None (no file, no key, empty value)."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    for line in lines:
        k, sep, v = line.partition("=")
        if sep and k.strip() == key and v.strip():
            return v.strip()
    return None


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
    version = properties_value(props, "application.version")
    release = properties_value(props, "application.release.name")
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


def loadable_binexport(ext_dir: Path) -> bool:
    """A BinExport directory Ghidra would load: it has its properties and its jar, and is not
    marked for removal."""
    if (ext_dir / "extension.properties.uninstalled").exists():
        return False
    if (ext_dir / "Module.manifest.uninstalled").exists():
        return False
    return (ext_dir / "extension.properties").is_file() and (
        ext_dir / "lib" / "BinExport.jar"
    ).is_file()


def install_binexport_dir(ghidra_home: Path) -> Path:
    """Where the extension sits inside a Ghidra installation."""
    return ghidra_home / "Ghidra" / "Extensions" / "BinExport"


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
    for ext in (install_binexport_dir(ghidra_home), settings / "Extensions" / "BinExport"):
        if not loadable_binexport(ext):
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


def binexport_stamp(ext_dir: Path) -> str | None:
    """The stamp of one extension copy: its version plus the digest of its jars
    (``11.4.3+lib:<12 hex>``), or None when its version cannot be read."""
    value = properties_value(ext_dir / "extension.properties", "version")
    if value is None:
        return None
    return f"{value}+lib:{binexport_lib_digest(ext_dir)[:12]}"


# ── the copy a scan loads ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ScanExtension:
    """The BinExport copy a scan's Ghidra JVM loads, decided before any JVM starts.

    ``ext_dir`` None = the extension is not available to the scan (``extension_missing``).
    ``link_from`` = a copy in the user settings directory the JVM would not see under its temporary
    user home: the scan links it into that home (a symbolic link, never a copy — two real paths of
    one module make Ghidra refuse to start). ``note`` says why a copy was or was not used."""

    ext_dir: Path | None
    stamp: str | None
    link_from: Path | None
    note: str | None


def scan_extension(
    ghidra_home: Path,
    *,
    environ: Mapping[str, str] | None = None,
    user_home: Path | None = None,
) -> ScanExtension:
    """Which BinExport a scan of ``ghidra_home`` loads.

    The installation's own copy when it has one — loaded whatever the user home, so nothing is
    linked; a second copy in the user settings directory is then only noted (the scan's JVM does
    not see it). Else the one copy in the user settings directory, linked into the scan's temporary
    home. Else none: the scan still runs, and its binaries are recorded ``extension_missing``.
    """
    install = install_binexport_dir(ghidra_home)
    settings = ghidra_settings_dir(ghidra_home, environ=environ, user_home=user_home)
    user_copy = settings / "Extensions" / "BinExport" if settings is not None else None
    user_ok = user_copy is not None and loadable_binexport(user_copy)
    if loadable_binexport(install):
        note = None
        if user_ok and user_copy is not None:
            if os.path.realpath(user_copy) != os.path.realpath(install):
                note = (
                    f"a second BinExport at {user_copy} is not loaded by the scan (it uses the "
                    f"one installed at {install}); tmap doctor reports the pair"
                )
        return ScanExtension(install, binexport_stamp(install), None, note)
    if user_ok and user_copy is not None:
        return ScanExtension(user_copy, binexport_stamp(user_copy), user_copy, None)
    where = f"{install}" + (f" or {user_copy}" if user_copy is not None else "")
    return ScanExtension(None, None, None, f"no BinExport extension at {where}")


def link_into_home(ext: ScanExtension, ghidra_home: Path, temp_home: Path) -> None:
    """Link a user-settings copy of the extension into ``temp_home``'s settings directory, where a
    JVM run with ``-Duser.home=<temp_home>`` (and no ``XDG_CONFIG_HOME``: the scan keeps every
    setting inside that home) looks for user extensions. Nothing is done for the installation's
    own copy, which every JVM loads."""
    if ext.link_from is None:
        return
    target_settings = ghidra_settings_dir(ghidra_home, environ={}, user_home=temp_home)
    if target_settings is None:
        return
    link = target_settings / "Extensions" / "BinExport"
    link.parent.mkdir(parents=True, exist_ok=True)
    if link.is_symlink() or link.exists():
        return
    link.symlink_to(ext.link_from, target_is_directory=True)
