# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Run only by test_home_isolation.py, in a child pytest whose environment carries TM_*
overrides (the file name keeps it out of normal collection): the first test sources a .env, the
second must see neither that nor the shell's overrides."""

from __future__ import annotations

import os
from pathlib import Path

from treasure_map.lib.config.config import load_config


def test_a_dotenv_is_sourced() -> None:
    env = Path.home() / ".treasure-map" / ".env"
    env.write_text("TM_ISOLATION_PROBE=1\nISOLATION_PROBE=1\n")
    load_config()
    assert os.environ.get("TM_ISOLATION_PROBE") == "1"
    assert os.environ.get("ISOLATION_PROBE") == "1"


def test_no_tm_variable_reaches_the_next_test() -> None:
    assert [n for n in os.environ if n.startswith("TM_")] == []
    assert "ISOLATION_PROBE" not in os.environ
    cfg = load_config()
    assert str(cfg.atlas.db_path).startswith(str(Path.home()))
    assert str(cfg.workspace_dir).startswith(str(Path.home()))
