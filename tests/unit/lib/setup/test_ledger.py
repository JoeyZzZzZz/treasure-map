# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The install ledger round-trips and refuses a malformed file."""

from __future__ import annotations

from pathlib import Path

import pytest

from treasure_map.lib.errors import ConfigError
from treasure_map.lib.setup.ledger import Ledger


def test_round_trip(tmp_path: Path) -> None:
    tmp_path = tmp_path / "ledger"
    path = tmp_path / "installed.json"
    ledger = Ledger(path)
    ledger.add_pending("jdk", "dir", tmp_path / "jdk", source_sha256="ab")
    ledger.commit("jdk", java_home=str(tmp_path / "jdk"))
    again = Ledger.load(path)
    e = again.committed("jdk")
    assert e is not None and e.extra == {"source_sha256": "ab", "java_home": str(tmp_path / "jdk")}
    again.remove("jdk")
    assert Ledger.load(path).entries == []
    assert [p.name for p in tmp_path.iterdir()] == ["installed.json"]  # no temp files left


def test_a_malformed_ledger_is_an_error(tmp_path: Path) -> None:
    path = tmp_path / "installed.json"
    path.write_text('{"schema": 2, "entries": []}')
    with pytest.raises(ConfigError):
        Ledger.load(path)
