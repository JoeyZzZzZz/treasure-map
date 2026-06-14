# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
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


@pytest.mark.parametrize(
    "spec, expected",
    [
        ("./work", Path("./work")),
        ("a/b", Path("a/b")),
        ("/abs/x", Path("/abs/x")),
        ("../up", Path("../up")),
    ],
)
def test_path_specs_used_verbatim(spec: str, expected: Path) -> None:
    r = resolve_workspace(spec, workspace_dir=_BASE, fs_root=Path("/fw"))
    assert r.kind == "path"
    assert r.path == expected


def test_tilde_path_is_expanded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    r = resolve_workspace("~/scratch/ws", workspace_dir=_BASE, fs_root=Path("/fw"))
    assert r.kind == "path"
    assert r.path == tmp_path / "scratch" / "ws"


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
    # A bare value with no path signal but illegal name characters: not a name, not a path.
    with pytest.raises(WorkspaceError):
        resolve_workspace(bad, workspace_dir=_BASE, fs_root=Path("/fw"))


def test_dotdot_is_treated_as_path_not_name() -> None:
    # "." / ".." have a leading dot, so they are path specs (used verbatim), never bare names.
    r = resolve_workspace("..", workspace_dir=_BASE, fs_root=Path("/fw"))
    assert r.kind == "path"
    assert r.path == Path("..")
