# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The Workspace provisions a run's directory and names its analysis.db — nothing more."""

from __future__ import annotations

from pathlib import Path

import pytest

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


def test_a_second_scan_of_the_same_workspace_is_refused(tmp_path: Path) -> None:
    """Two scans writing one analysis.db would interleave and re-key each other's rows.

    MUTATION: drop the flock in Workspace.__enter__ -> RED (the second enter succeeds)."""
    from treasure_map.lib.errors import WorkspaceError

    with Workspace(tmp_path / "ws"):
        with pytest.raises(WorkspaceError, match="another tmap process"):
            Workspace(tmp_path / "ws").__enter__()
    # released on exit: the next scan of the same workspace goes ahead
    with Workspace(tmp_path / "ws") as ws:
        assert ws.db_path == tmp_path / "ws" / "analysis.db"


def test_closing_a_workspace_releases_its_lock_there_and_then(tmp_path: Path) -> None:
    """``tmap rescan`` scans several runs in one process, so a workspace it has finished with must
    be free again at once — released by ``close()``, not whenever the file object is collected.

    MUTATION: make ``close()`` a no-op -> RED: the same process is refused its own workspace on
    the next entry. Drop the unlock and the close but still forget the handle (the form that
    survived before) -> RED: the lock file is left for the collector to close, which reports it
    as a ResourceWarning.
    """
    import gc
    import warnings

    from treasure_map.lib.errors import WorkspaceError

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        ws = Workspace(tmp_path / "ws")
        ws.__enter__()
        ws.close()
        gc.collect()
    try:
        with Workspace(tmp_path / "ws"):
            outcome = "re-entered"
    except WorkspaceError:
        outcome = "refused"
    assert outcome == "re-entered"
    leaked = [str(w.message) for w in caught if issubclass(w.category, ResourceWarning)]
    assert leaked == [], leaked


def test_workspace_of_names_only_a_workspaces_own_database(tmp_path: Path) -> None:
    """A hunt locks the workspace its analysis.db belongs to, and nothing else. A database sits in
    a workspace when its directory is directly under the configured base, or when a scan has
    already put its lock file there (a workspace made under an earlier base). A copy kept anywhere
    else is not one, and a file not named analysis.db is not a workspace's database.

    MUTATION (verified RED): drop the lock-file branch -> the workspace under the earlier base
    reads None. Make workspace_of return the parent unconditionally -> the stray copy is claimed."""
    from treasure_map.lib.workspace.workspace import workspace_of

    base = tmp_path / "workspaces"
    (base / "router_v1").mkdir(parents=True)
    assert workspace_of(base / "router_v1" / "analysis.db", base) == base / "router_v1"
    # under the base, but not the workspace's database file
    assert workspace_of(base / "router_v1" / "other.db", base) is None

    # a workspace a scan used under an earlier base still carries its lock file
    with Workspace(tmp_path / "old_base" / "router_v0"):
        pass
    old_db = tmp_path / "old_base" / "router_v0" / "analysis.db"
    assert workspace_of(old_db, base) == tmp_path / "old_base" / "router_v0"

    # a copy kept elsewhere: not under the base, no lock file
    (tmp_path / "copies").mkdir()
    assert workspace_of(tmp_path / "copies" / "analysis.db", base) is None
    assert not (tmp_path / "copies" / Workspace._LOCK_NAME).exists()
