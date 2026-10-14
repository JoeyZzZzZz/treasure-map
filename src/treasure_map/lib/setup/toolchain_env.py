# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Put the JDK and BinDiff named in config.yaml first in THIS process's environment.

Every tmap command calls this before doing anything, so the Ghidra and BinDiff it starts are the
ones ``tmap init`` chose — also when an MCP client starts ``tmap mcp`` with a bare PATH. Ghidra's
launcher prefers ``$JAVA_HOME`` (when it is a supported JDK) over the ``java`` it is started
with, and BinDiff is found on PATH, so setting the two is enough; no subprocess call changes.

Unset keys change nothing. A key that points at something unusable changes nothing either and
comes back as a note (the doctor shows it) — never an exception that would stop the command.
"""

from __future__ import annotations

import os
from collections.abc import MutableMapping
from pathlib import Path

from treasure_map.lib.config.config import Config
from treasure_map.lib.setup.discover import read_jdk


def _prepend_path(environ: MutableMapping[str, str], directory: Path) -> None:
    """``directory`` first on PATH, once: an earlier occurrence moves to the front, so applying
    the configuration again (init does, after writing it) never grows PATH."""
    current = environ.get("PATH", "")
    entry = str(directory)
    parts = [p for p in (current.split(os.pathsep) if current else []) if p != entry]
    environ["PATH"] = os.pathsep.join([entry, *parts])


def apply_toolchain_env(cfg: Config, environ: MutableMapping[str, str] | None = None) -> list[str]:
    """Inject ``cfg.toolchain`` into ``environ`` (default: this process). Returns notes."""
    env: MutableMapping[str, str] = os.environ if environ is None else environ
    notes: list[str] = []
    java_home = cfg.toolchain.java_home
    if java_home is not None:
        info = read_jdk(java_home)
        if info.java and info.javac and info.major == 21:
            env["JAVA_HOME"] = str(java_home)
            _prepend_path(env, java_home / "bin")
            notes.append(f"JAVA_HOME={java_home} (from config)")
        else:
            notes.append(
                f"toolchain.java_home {java_home} is not a JDK 21 (bin/java + bin/javac); not used"
            )
    bindiff = cfg.toolchain.bindiff
    if bindiff is not None:
        if bindiff.is_file() and os.access(bindiff, os.X_OK):
            _prepend_path(env, bindiff.parent)
            notes.append(f"bindiff {bindiff} first on PATH (from config)")
        else:
            notes.append(f"toolchain.bindiff {bindiff} is not an executable file; not used")
    return notes
