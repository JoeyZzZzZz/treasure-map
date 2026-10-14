# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Autouse guard: no unit test discovers the machine's own toolchain or agents.

``tmap init`` looks for a JDK, Ghidra and BinDiff on PATH, in system directories and in a few
environment variables, and for the ``claude`` / ``codex`` CLIs. On a developer's machine those
exist, so a test would pass or fail depending on what is installed there. Discovery is switched to
the throwaway home alone, and the variables it reads are cleared; a test that needs a toolchain
builds one under ``tmp_path`` and points at it.
"""

from __future__ import annotations

import pytest

import treasure_map.lib.setup.discover as _discover

_HOST_VARS = (
    "GHIDRA_HOME",
    "GHIDRA_INSTALL_DIR",
    "JAVA_HOME",
    "XDG_CONFIG_HOME",
    "CODEX_HOME",
    "DSH_HOME",
    "CLAUDE_CONFIG_DIR",
)


@pytest.fixture(autouse=True)
def _hermetic_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_discover, "SYSTEM_PROBES", False)
    for name in _HOST_VARS:
        monkeypatch.delenv(name, raising=False)
