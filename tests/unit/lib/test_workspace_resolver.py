# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for resolve_workspace — the pure name/path/auto resolver."""

from __future__ import annotations

from pathlib import Path

import pytest

from treasure_map.lib.errors import WorkspaceError
from treasure_map.lib.workspace.resolver import resolve_workspace

_BASE = Path("/home/u/.treasure-map/workspaces")


def test_bare_name_is_managed_under_base() -> None:
    r = resolve_workspace("router_v1", workspace_dir=_BASE, fs_root=Path("/fw"))
    assert r.kind == "name"
    assert r.path == _BASE / "router_v1"


@pytest.mark.parametrize("spec", ["./work", "a/b", "/abs/x", "../up", "~/scratch/ws"])
def test_path_specs_are_rejected(spec: str) -> None:
    # ★ Single semantics: -w is a NAME, never a path. A path-like spec is the exact mix-up that
    # used to split one run across two directories, so it is rejected loudly, not resolved.
    with pytest.raises(WorkspaceError):
        resolve_workspace(spec, workspace_dir=_BASE, fs_root=Path("/fw"))


def test_name_and_dotslash_name_do_not_split_into_two_dirs() -> None:
    # The regression the convergence fixes: `router` resolves under the base; `./router` no longer
    # resolves to a different (relative) directory — it is rejected, so a run cannot silently split.
    named = resolve_workspace("router", workspace_dir=_BASE, fs_root=Path("/fw"))
    assert named.path == _BASE / "router"
    with pytest.raises(WorkspaceError):
        resolve_workspace("./router", workspace_dir=_BASE, fs_root=Path("/fw"))


def test_path_rejection_message_suggests_the_bare_name() -> None:
    # The error must guide the user to the name form, not just refuse.
    with pytest.raises(WorkspaceError, match="my_ws"):
        resolve_workspace("/mnt/scratch/my_ws", workspace_dir=_BASE, fs_root=Path("/fw"))


def test_auto_name_is_deterministic_for_same_fs_root() -> None:
    a = resolve_workspace(None, workspace_dir=_BASE, fs_root=Path("/data/squashfs-root"))
    b = resolve_workspace(None, workspace_dir=_BASE, fs_root=Path("/data/squashfs-root"))
    assert a.kind == "auto"
    assert a.path == b.path  # path-stable -> re-runs resume
    assert a.path.parent == _BASE
    assert a.path.name.startswith("analyze_squashfs-root_")


def test_auto_name_differs_for_same_basename_different_path() -> None:
    # Two different firmware that share a basename must NOT collide into one workspace.
    a = resolve_workspace(None, workspace_dir=_BASE, fs_root=Path("/a/squashfs-root"))
    b = resolve_workspace(None, workspace_dir=_BASE, fs_root=Path("/b/squashfs-root"))
    assert a.path != b.path


@pytest.mark.parametrize("bad", ["a b", "weird*name", "name#1", "bad:name"])
def test_illegal_name_raises(bad: str) -> None:
    # A bare value with no path signal but illegal name characters: not a valid name.
    with pytest.raises(WorkspaceError):
        resolve_workspace(bad, workspace_dir=_BASE, fs_root=Path("/fw"))


def test_dotdot_is_rejected() -> None:
    # ".." has a leading dot -> a path-like spec -> rejected (no path mode any more).
    with pytest.raises(WorkspaceError):
        resolve_workspace("..", workspace_dir=_BASE, fs_root=Path("/fw"))


def test_list_workspace_names_returns_sorted_subdirs(tmp_path: Path) -> None:
    from treasure_map.lib.workspace.resolver import list_workspace_names

    base = tmp_path / "ws"
    base.mkdir()
    for name in ("charlie", "alpha", "bravo"):
        (base / name).mkdir()
    (base / "loose_file").write_text("not a workspace")  # a file is not a workspace
    assert list_workspace_names(base) == ["alpha", "bravo", "charlie"]


def test_list_workspace_names_absent_base_is_empty(tmp_path: Path) -> None:
    from treasure_map.lib.workspace.resolver import list_workspace_names

    assert list_workspace_names(tmp_path / "does_not_exist") == []  # never raises
