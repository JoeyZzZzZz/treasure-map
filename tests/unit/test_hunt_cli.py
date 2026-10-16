# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""`tmap hunt` on its own: it holds the workspace lock while it reads a workspace's analysis.db.

The hunt itself is stubbed (from the real stats dataclass); the lock is the real one, probed from
inside the hunt the way a second scan would try to take it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from treasure_map.cli.hunt_cli import hunt_pattern
from treasure_map.lib.config.config import Config
from treasure_map.lib.errors import WorkspaceError
from treasure_map.lib.hunt.analyzer2 import Analyzer2Stats
from treasure_map.lib.workspace.workspace import Workspace


def _try_workspace(path: Path) -> str:
    """Whether a scan of ``path`` could take the workspace now."""
    try:
        with Workspace(path):
            return "acquired"
    except WorkspaceError:
        return "refused"


def _stats() -> Analyzer2Stats:
    return Analyzer2Stats(
        scanned=0, matches=0, instances_written=0, by_status={"confirmed": 0, "unknown": 0}
    )


def _setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, db_dir: Path) -> dict[str, Any]:
    """Configure the workspace base, put an analysis.db in ``db_dir`` and stub the hunt so it
    records whether a lock file sat beside the database while it ran (read before the probe,
    which creates one) and whether the workspace was free."""
    monkeypatch.setattr(
        "treasure_map.lib.config.config.load_config",
        lambda _cfg=None: Config(llm=None, workspace_dir=tmp_path / "workspaces"),
    )
    db_dir.mkdir(parents=True, exist_ok=True)
    (db_dir / "analysis.db").touch()
    seen: dict[str, Any] = {}

    def _fake_hunt(db: Any, atlas: Any, *, source_run_id: str, rehunt: bool = False) -> Any:
        seen["lock_file"] = (Path(db).parent / Workspace._LOCK_NAME).exists()
        seen["hunt"] = _try_workspace(Path(db).parent)
        return _stats()

    monkeypatch.setattr("treasure_map.lib.hunt.run_analyzer2", _fake_hunt)
    return seen


def _hunt(tmp_path: Path, db: Path) -> Any:
    return CliRunner().invoke(
        hunt_pattern, [str(db), "--run-id", "r", "--atlas", str(tmp_path / "atlas.db")]
    )


def test_hunt_holds_the_workspace_lock_while_it_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A hunt of a workspace's analysis.db keeps a scan of that workspace out until it is done,
    and releases the workspace when it returns.

    MUTATION (verified RED): drop the ``held.enter_context(Workspace(ws_dir))`` line in
    hunt_pattern -> the probe inside the hunt acquires the workspace."""
    ws = tmp_path / "workspaces" / "router_v1"
    seen = _setup(tmp_path, monkeypatch, ws)
    result = _hunt(tmp_path, ws / "analysis.db")
    assert result.exit_code == 0, result.output
    assert seen == {"lock_file": True, "hunt": "refused"}
    assert _try_workspace(ws) == "acquired"


def test_hunt_is_refused_while_a_scan_holds_the_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """While a scan holds the workspace, a standalone hunt of its analysis.db is refused before it
    reads anything, with the lock's own message and exit 1.

    MUTATION (verified RED): drop the ``held.enter_context(Workspace(ws_dir))`` line -> the hunt
    runs under the scan and exits 0."""
    ws = tmp_path / "workspaces" / "router_v1"
    seen = _setup(tmp_path, monkeypatch, ws)
    with Workspace(ws):
        result = _hunt(tmp_path, ws / "analysis.db")
    assert result.exit_code == 1, result.output
    assert "another tmap process" in result.output
    assert seen == {}  # the hunt never started


def test_hunt_of_a_database_outside_any_workspace_takes_no_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An analysis.db that is no workspace's (a copy kept elsewhere) hunts as before: no lock is
    taken and no lock file is created beside it.

    MUTATION (verified RED): make workspace_of return the database's directory unconditionally ->
    the hunt locks the copy's directory and leaves a lock file there."""
    copies = tmp_path / "copies"
    seen = _setup(tmp_path, monkeypatch, copies)
    result = _hunt(tmp_path, copies / "analysis.db")
    assert result.exit_code == 0, result.output
    assert seen == {"lock_file": False, "hunt": "acquired"}


def test_hunt_help_says_it_rebuilds_nothing_in_the_database() -> None:
    """A standalone hunt reads the call edges the last scan built and does not rebuild them, so a
    workspace scanned by an older tmap keeps its older edges until it is scanned again. The help
    says so and names the command that refreshes everything.

    MUTATION (verified RED): drop the paragraph from hunt_pattern's docstring -> the help no longer
    mentions it and the assertion fails."""
    out = CliRunner().invoke(hunt_pattern, ["--help"]).output
    flat = " ".join(out.split())
    assert "rebuilds nothing in it" in flat
    assert "tmap rescan" in flat
