# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
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

The environment is the other way a real path gets in: a ``TM_ATLAS__DB_PATH`` or
``TM_WORKSPACE_DIR`` exported in the developer's shell would point a test that deletes data at
the real atlas. Every ``TM_*`` variable is removed for the test, and whatever a test's ``.env``
sourcing put into ``os.environ`` is taken out again afterwards.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

import treasure_map.lib.config.config as _config
import treasure_map.lib.diff.toolchain as _toolchain
import treasure_map.lib.last_run as _last_run


@pytest.fixture(autouse=True)
def _isolate_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    fake_home = tmp_path / "home"
    (fake_home / ".treasure-map").mkdir(parents=True, exist_ok=True)
    # (1) call-time Path.home() users: config default_factory, the .env lookup, init, etc.
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))
    monkeypatch.setenv("HOME", str(fake_home))
    # (2) import-time frozen constants (bound before the patch above could take effect).
    tm = fake_home / ".treasure-map"
    monkeypatch.setattr(_last_run, "_POINTER_PATH", tm / "last_run.json")
    monkeypatch.setattr(_config, "_DEFAULT_CONFIG_PATH", tm / "config.yaml")
    # (3) no TM_* override from the developer's shell; .env sourcing does not outlive the test.
    for name in [n for n in os.environ if n.startswith("TM_")]:
        monkeypatch.delenv(name)
    saved = dict(os.environ)
    yield
    os.environ.clear()
    os.environ.update(saved)


@pytest.fixture(autouse=True)
def _no_external_toolchain(monkeypatch: pytest.MonkeyPatch) -> None:
    """No test reads the machine's Ghidra / BinExport / BinDiff versions: a GHIDRA_HOME in the
    environment or a bindiff on PATH would otherwise make a diff's toolchain stamps, and the
    readers' ``toolchain_checked``, depend on the machine. A test that needs a toolchain sets
    one."""
    monkeypatch.setattr(_toolchain, "_current", [None])
    monkeypatch.setattr(_toolchain, "detect_toolchain", lambda config: None)
    # A diff's own tool (BinDiff) and the scan's Ghidra, each read on its own.
    monkeypatch.setattr(_toolchain, "bindiff_version", lambda: None)
    monkeypatch.setattr(_toolchain, "_current_bindiff", [None])
    monkeypatch.setattr(_toolchain, "_current_ghidra", [None])
    # What a scan here would be made by (Ghidra version, export hash): not this machine's.
    from treasure_map.cli import hunt_cli

    monkeypatch.setattr(hunt_cli, "_scan_tools", lambda cfg: hunt_cli._ScanTools(None, None))


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """No test reaches the network: ``tmap init`` downloads the toolchain, and a test that forgot
    to inject a fake fetcher would otherwise pull hundreds of megabytes (or hang offline). A test
    that needs download semantics injects a ``Fetcher``."""
    import socket
    import urllib.request

    def _refuse(*_a: object, **_k: object) -> None:
        raise AssertionError("network in unit test")

    monkeypatch.setattr(urllib.request, "urlopen", _refuse)
    monkeypatch.setattr(socket, "create_connection", _refuse)
