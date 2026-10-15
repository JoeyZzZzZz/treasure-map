# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
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


def test_a_tm_override_in_the_shell_never_reaches_a_test(tmp_path: Path) -> None:
    """A developer who exported TM_ATLAS__DB_PATH / TM_WORKSPACE_DIR must not have a test that
    deletes data (tmap uninstall --purge-data) aim at the atlas those name; nor may one test's
    .env sourcing carry into the next.

    MUTATION: drop the TM_* removal, or the os.environ restore, from the autouse fixture -> the
    child run's second test sees a TM_* variable -> RED."""
    import subprocess
    import sys

    real = tmp_path / "real"
    env = {
        **os.environ,
        "TM_ATLAS__DB_PATH": str(real / "atlas.db"),
        "TM_WORKSPACE_DIR": str(real / "ws"),
    }
    probe = Path(__file__).with_name("home_isolation_probe.py")
    res = subprocess.run(  # noqa: S603 -- this interpreter, fixed arguments
        [
            sys.executable,
            "-m",
            "pytest",
            f"{probe}::test_a_dotenv_is_sourced",
            f"{probe}::test_no_tm_variable_reaches_the_next_test",
            "-q",
            "-p",
            "no:cacheprovider",
        ],
        cwd=Path(__file__).resolve().parents[2],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert res.returncode == 0, res.stdout[-3000:]
    assert "2 passed" in res.stdout
