# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the scan -w and diff run-id shell-completion callbacks."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from treasure_map.cli.hunt_cli import _complete_run_id, _complete_workspace


def _fake_config(monkeypatch: pytest.MonkeyPatch, *, workspace_dir: Path, atlas: Path) -> None:
    monkeypatch.setattr(
        "treasure_map.lib.config.config.load_config",
        lambda _c=None: SimpleNamespace(
            workspace_dir=workspace_dir, atlas=SimpleNamespace(db_path=atlas)
        ),
    )


def test_scan_w_completion_suggests_existing_workspaces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wsdir = tmp_path / "ws"
    wsdir.mkdir()
    for n in ("rt_ax55_unpatched", "rt_ax55_patched", "miwifi_rn02"):
        (wsdir / n).mkdir()
    _fake_config(monkeypatch, workspace_dir=wsdir, atlas=tmp_path / "atlas.db")

    # a prefix narrows to matching existing names (helps re-scan without a typo)
    assert sorted(c.value for c in _complete_workspace(None, None, "rt")) == [  # type: ignore[arg-type]
        "rt_ax55_patched",
        "rt_ax55_unpatched",
    ]
    # empty prefix -> all workspaces
    assert len(_complete_workspace(None, None, "")) == 3  # type: ignore[arg-type]


def test_scan_w_completion_is_empty_when_base_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_config(monkeypatch, workspace_dir=tmp_path / "nope", atlas=tmp_path / "atlas.db")
    assert _complete_workspace(None, None, "") == []  # type: ignore[arg-type]


def test_run_id_completion_suggests_atlas_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from treasure_map.lib.atlas.connection import open_atlas
    from treasure_map.lib.atlas.models import InstanceRow
    from treasure_map.lib.atlas.writer import add_instance, upsert_pattern

    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    p = upsert_pattern(
        conn,
        source_class="unknown",
        sink_class="cmd",
        call_sequence_shape="s->x",
        structural_fingerprint="fp",
        fingerprint_algo_version="callseq-v1",
    )
    for rid in ("rt_ax55_unpatched", "miwifi_rn02"):
        add_instance(
            conn,
            InstanceRow(
                pattern_id=p,
                pseudocode_hash=f"h_{rid}",
                source_anchor="fn",
                sink_anchor="system",
                source_run_id=rid,
                reachability_status="unknown",
                provenance_level="L0",
                evidence_ref=f"{rid}#x",
                scope_origin="intra",
                origin="unknown",
            ),
        )
    conn.close()
    _fake_config(monkeypatch, workspace_dir=tmp_path / "ws", atlas=atlas)

    assert sorted(c.value for c in _complete_run_id(None, None, "")) == [  # type: ignore[arg-type]
        "miwifi_rn02",
        "rt_ax55_unpatched",
    ]
    assert [c.value for c in _complete_run_id(None, None, "rt")] == ["rt_ax55_unpatched"]  # type: ignore[arg-type]


def test_run_id_completion_is_empty_and_safe_without_atlas(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A completion helper must never crash the shell: an absent atlas yields no suggestions.
    _fake_config(monkeypatch, workspace_dir=tmp_path / "ws", atlas=tmp_path / "absent.db")
    assert _complete_run_id(None, None, "") == []  # type: ignore[arg-type]
