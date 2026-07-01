# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Regression guard for the autouse home-isolation fixture (tests/conftest.py).

Proves a test can never resolve a default home path to the user's REAL ~/.treasure-map/ — the
hazard that let a pytest run wipe a real atlas.db and repoint last_run.json at a deleted path.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from treasure_map.lib import last_run
from treasure_map.lib.config.config import Config


def _real_home() -> Path:
    """The actual login home, independent of the (patched) HOME env var."""
    pwd = pytest.importorskip("pwd")
    return Path(pwd.getpwuid(os.getuid()).pw_dir)


def test_pointer_path_is_redirected_under_the_fake_home(tmp_path: Path) -> None:
    # The import-frozen _POINTER_PATH is reset by the autouse guard to the per-test fake home.
    p = last_run.pointer_path()
    assert str(p).startswith(str(tmp_path))
    assert p != _real_home() / ".treasure-map" / "last_run.json"


def test_default_write_last_run_never_touches_real_home(tmp_path: Path) -> None:
    # write_last_run WITHOUT path= must land in the fake home, never the real ~/.treasure-map.
    target = last_run.write_last_run("x.db", "y.db", "run_iso")
    assert str(target).startswith(str(tmp_path))
    assert last_run.read_last_run() is not None  # round-trips within the fake home
    assert Path(target).resolve() != (_real_home() / ".treasure-map" / "last_run.json").resolve()


def test_default_config_atlas_path_is_in_fake_home(tmp_path: Path) -> None:
    # The config default_factory resolves Path.home() at call time -> the fake home, so a default
    # atlas.db / workspace never points at the real ~/.treasure-map.
    cfg = Config()
    assert str(cfg.atlas.db_path).startswith(str(tmp_path))
    assert not str(cfg.atlas.db_path).startswith(str(_real_home() / ".treasure-map"))
