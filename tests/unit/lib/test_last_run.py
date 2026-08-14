# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the last-run pointer (lib/last_run)."""

from __future__ import annotations

from pathlib import Path

from treasure_map.lib import last_run


def test_write_then_read_roundtrip(tmp_path: Path) -> None:
    ptr = tmp_path / "last_run.json"
    adb = tmp_path / "sub" / "analysis.db"
    adb.parent.mkdir()
    adb.touch()
    atlas = tmp_path / "atlas.db"
    atlas.touch()
    last_run.write_last_run(adb, atlas, "run_x", path=ptr)
    got = last_run.read_last_run(path=ptr)
    assert got is not None
    assert got.analysis_db == adb.resolve()  # stored absolute
    assert got.atlas_db == atlas.resolve()
    assert got.run_id == "run_x"
    assert got.recorded_at  # a timestamp was recorded


def test_read_missing_is_none(tmp_path: Path) -> None:
    assert last_run.read_last_run(path=tmp_path / "nope.json") is None


def test_read_corrupt_is_none(tmp_path: Path) -> None:
    ptr = tmp_path / "last_run.json"
    ptr.write_text("{ not json")
    assert last_run.read_last_run(path=ptr) is None


def test_write_failure_is_swallowed(tmp_path: Path) -> None:
    # A read-only / impossible target must not turn a successful scan into an error.
    target = tmp_path / "file_as_dir"
    target.touch()
    # writing "under" a regular file is an OSError; write_last_run must swallow it.
    last_run.write_last_run("a.db", "b.db", "r", path=target / "child.json")
