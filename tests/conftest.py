# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Autouse guard: no test may touch the real ~/.treasure-map/.

Production code defaults several paths to the user's home directory. Some resolve ``Path.home()``
at CALL time (the config default_factory for atlas.db / workspaces, the ``.env`` lookup); others
FREEZE a home path at IMPORT time into a module constant. A test that calls
``write_last_run(...)`` without ``path=``, or uses the default config's ``atlas.db_path``, would
otherwise write into the user's real ~/.treasure-map/ — a pytest run has wiped a real atlas.db and
left last_run.json pointing at a deleted /tmp path, breaking a live MCP binding.

This fixture redirects every home path to a per-test throwaway home. Patching ``Path.home`` covers
the call-time users; the import-frozen constants (``last_run._POINTER_PATH`` and
``config._DEFAULT_CONFIG_PATH``) were bound before the patch, so each is reset explicitly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import treasure_map.lib.config.config as _config
import treasure_map.lib.last_run as _last_run


@pytest.fixture(autouse=True)
def _isolate_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_home = tmp_path / "home"
    (fake_home / ".treasure-map").mkdir(parents=True, exist_ok=True)
    # (1) call-time Path.home() users: config default_factory, the .env lookup, init, etc.
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))
    monkeypatch.setenv("HOME", str(fake_home))
    # (2) import-time frozen constants (bound before the patch above could take effect).
    tm = fake_home / ".treasure-map"
    monkeypatch.setattr(_last_run, "_POINTER_PATH", tm / "last_run.json")
    monkeypatch.setattr(_config, "_DEFAULT_CONFIG_PATH", tm / "config.yaml")
