# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The Workspace provisions a run's directory and names its analysis.db — nothing more."""

from __future__ import annotations

from pathlib import Path

from treasure_map.lib.workspace.workspace import Workspace


def test_workspace_provisions_the_directory_and_names_its_db(tmp_path: Path) -> None:
    ws_path = tmp_path / "router_v1"
    with Workspace(ws_path) as ws:
        assert ws.path == ws_path and ws_path.is_dir()
        assert ws.db_path == ws_path / "analysis.db"


def test_workspace_keeps_no_checkpoint_database(tmp_path: Path) -> None:
    """The step-checkpoint state.db is gone: a scan resumes from analysis.db's per-binary
    pass_version, not a steps table that only its own tests ever read.

    MUTATION: recreate state.db in __init__ -> RED."""
    with Workspace(tmp_path / "w"):
        pass
    assert not (tmp_path / "w" / "state.db").exists()
