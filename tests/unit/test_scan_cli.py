# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the `tmap scan` orchestration command.

scan is a thin CLI spine: analyze -> hunt -> triage. These tests monkeypatch the three
reused entry points to assert ordering / argument wiring / short-circuit, and use the REAL
triage + shared renderer against a seeded atlas to prove the final segment is byte-identical
to `tmap triage` (single renderer, no drift).
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from click.testing import CliRunner

from treasure_map.cli.hunt_cli import scan
from treasure_map.cli.hunt_cli import triage as triage_cmd
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import InstanceRow
from treasure_map.lib.atlas.writer import add_instance, upsert_pattern
from treasure_map.lib.config.config import Config
from treasure_map.lib.errors import GhidraNotFoundError

_FID = [0]


class _DummyWorkspace:
    def __init__(self, path: Path, **_: Any) -> None:
        self.path = path
        self.db_path = path / "analysis.db"

    def __enter__(self) -> _DummyWorkspace:
        return self

    def __exit__(self, *_: object) -> None:
        return None


def _fake_analyze_result(db_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        db_path=db_path, binary_count=2, functions_ingested=9, incomplete_binaries=[]
    )


def _hunt_stats(written: int = 0) -> SimpleNamespace:
    return SimpleNamespace(
        instances_written=written,
        by_status={"confirmed": 0, "blocked": 0, "unknown": written},
        data_gap_skipped=0,
        nvram_flows_written=0,
        fmt_wrapper_unknown_source_skipped=0,
    )


def _base_patches(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub config + Workspace so scan runs hermetically (no real workspace/Ghidra)."""
    monkeypatch.setattr(
        "treasure_map.lib.config.config.load_config", lambda _cfg=None: Config(llm=None)
    )
    monkeypatch.setattr("treasure_map.lib.workspace.workspace.Workspace", _DummyWorkspace)


def _seed_atlas(tmp_path: Path, run_id: str, *, with_gated: bool = False) -> Path:
    conn = open_atlas(tmp_path / "atlas.db")
    p = upsert_pattern(
        conn,
        source_class="external_input",
        sink_class="cmd",
        call_sequence_shape="source->...->sink",
        structural_fingerprint="fp",
        fingerprint_algo_version="callseq-v1",
    )

    def _inst(status: str, fn: str, origin: str = "custom", blocking: str | None = None) -> None:
        _FID[0] += 1
        prov = "L1" if status in {"confirmed", "blocked"} else "L0"
        add_instance(
            conn,
            InstanceRow(
                pattern_id=p,
                pseudocode_hash=f"h{_FID[0]}",
                source_anchor=fn,
                sink_anchor="system",
                source_run_id=run_id,
                reachability_status=status,
                blocking_mechanism=blocking,
                provenance_level=prov,
                evidence_ref=f"{run_id}#fn{_FID[0]}",
                scope_origin="intra",
                origin=origin,
            ),
        )

    _inst("unknown", "tv_fn")
    _inst("confirmed", "rc_fn")
    if with_gated:
        _inst("blocked", "gt_fn", blocking="char_filter")
    conn.close()
    return tmp_path / "atlas.db"


def _mkfs(tmp_path: Path) -> Path:
    fs_root = tmp_path / "fs"
    fs_root.mkdir()
    return fs_root


# ── 1. three steps, in order; run_id default = workspace name ────────────────────────


def test_scan_runs_three_steps_in_order(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _base_patches(monkeypatch)
    calls: list[str] = []
    seen: dict[str, Any] = {}

    async def _fake_analyze(*_: Any, **__: Any) -> SimpleNamespace:
        calls.append("analyze")
        return _fake_analyze_result(tmp_path / "analysis.db")

    def _fake_hunt(db: Any, atlas: Any, *, source_run_id: str) -> Any:
        calls.append("hunt")
        seen["run_id"] = source_run_id
        return _hunt_stats()

    def _fake_triage(conn: Any, *, run_id: str | None = None) -> list[Any]:
        calls.append("triage")
        seen["triage_run_id"] = run_id
        return []

    monkeypatch.setattr("treasure_map.lib.analyze.pipeline.run_analyze", _fake_analyze)
    monkeypatch.setattr("treasure_map.lib.hunt.run_analyzer2", _fake_hunt)
    monkeypatch.setattr("treasure_map.lib.query.triage", _fake_triage)

    ws = tmp_path / "router_v1"
    result = CliRunner().invoke(
        scan,
        [
            str(_mkfs(tmp_path)),
            "-w",
            str(ws),
            "--atlas",
            str(tmp_path / "atlas.db"),
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls == ["analyze", "hunt", "triage"]
    assert seen["run_id"] == "router_v1"  # default run-id = workspace name
    assert seen["triage_run_id"] == "router_v1"


def test_scan_explicit_run_id_overrides_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _base_patches(monkeypatch)
    seen: dict[str, Any] = {}

    async def _fake_analyze(*_: Any, **__: Any) -> SimpleNamespace:
        return _fake_analyze_result(tmp_path / "analysis.db")

    def _fake_hunt(db: Any, atlas: Any, *, source_run_id: str) -> Any:
        seen["run_id"] = source_run_id
        return _hunt_stats()

    monkeypatch.setattr("treasure_map.lib.analyze.pipeline.run_analyze", _fake_analyze)
    monkeypatch.setattr("treasure_map.lib.hunt.run_analyzer2", _fake_hunt)
    monkeypatch.setattr("treasure_map.lib.query.triage", lambda conn, *, run_id=None: [])

    result = CliRunner().invoke(
        scan,
        [
            str(_mkfs(tmp_path)),
            "-w",
            str(tmp_path / "router_v1"),
            "--run-id",
            "device_x",
            "--atlas",
            str(tmp_path / "atlas.db"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert seen["run_id"] == "device_x"  # explicit --run-id wins over the workspace name


# ── 2. analyze failure short-circuits hunt + triage ─────────────────────────────────


def test_scan_analyze_failure_short_circuits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _base_patches(monkeypatch)
    downstream: list[str] = []

    async def _boom(*_: Any, **__: Any) -> SimpleNamespace:
        raise GhidraNotFoundError("ghidra missing")

    monkeypatch.setattr("treasure_map.lib.analyze.pipeline.run_analyze", _boom)
    monkeypatch.setattr(
        "treasure_map.lib.hunt.run_analyzer2",
        lambda *a, **k: downstream.append("hunt"),
    )
    monkeypatch.setattr(
        "treasure_map.lib.query.triage",
        lambda *a, **k: downstream.append("triage"),
    )

    result = CliRunner().invoke(
        scan, [str(_mkfs(tmp_path)), "-w", str(tmp_path / "ws"), "--atlas", str(tmp_path / "a.db")]
    )
    assert result.exit_code != 0
    assert downstream == []  # neither hunt nor triage ran


# ── 3. final segment is byte-identical to `tmap triage` (shared renderer, no drift) ──


def test_scan_triage_segment_matches_triage_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _base_patches(monkeypatch)
    atlas = _seed_atlas(tmp_path, "ws_x")

    async def _fake_analyze(*_: Any, **__: Any) -> SimpleNamespace:
        return _fake_analyze_result(tmp_path / "analysis.db")

    monkeypatch.setattr("treasure_map.lib.analyze.pipeline.run_analyze", _fake_analyze)
    monkeypatch.setattr("treasure_map.lib.hunt.run_analyzer2", lambda *a, **k: _hunt_stats(2))
    # triage + renderer are REAL here.

    scan_out = CliRunner().invoke(
        scan, [str(_mkfs(tmp_path)), "-w", str(tmp_path / "ws_x"), "--atlas", str(atlas)]
    )
    triage_out = CliRunner().invoke(triage_cmd, ["ws_x", "--atlas", str(atlas)])
    assert scan_out.exit_code == 0, scan_out.output
    assert triage_out.exit_code == 0, triage_out.output

    # scan's triage block (from the "triage: ..." header onward) must equal the triage command's
    # rendered list. Both commands prepend the same intended-use notice; the shared renderer's
    # output is what must not drift, so compare from the "triage: ..." header in both.
    block = scan_out.output[scan_out.output.index("triage: ") :]
    triage_block = triage_out.output[triage_out.output.index("triage: ") :]
    assert block == triage_block


# ── 4. triage presentation options pass through ─────────────────────────────────────


def test_scan_passes_through_triage_options(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _base_patches(monkeypatch)
    atlas = _seed_atlas(tmp_path, "ws_x", with_gated=True)

    async def _fake_analyze(*_: Any, **__: Any) -> SimpleNamespace:
        return _fake_analyze_result(tmp_path / "analysis.db")

    monkeypatch.setattr("treasure_map.lib.analyze.pipeline.run_analyze", _fake_analyze)
    monkeypatch.setattr("treasure_map.lib.hunt.run_analyzer2", lambda *a, **k: _hunt_stats(3))

    base = [str(_mkfs(tmp_path)), "-w", str(tmp_path / "ws_x"), "--atlas", str(atlas)]
    runner = CliRunner()

    default = runner.invoke(scan, base)
    assert default.exit_code == 0, default.output
    assert "gt_fn" not in default.output and "hidden" in default.output  # gated folded

    gated = runner.invoke(scan, [*base, "--include-gated"])
    assert gated.exit_code == 0, gated.output
    assert "gt_fn" in gated.output  # --include-gated passed through to the renderer

    as_json = runner.invoke(scan, [*base, "--json"])
    assert as_json.exit_code == 0, as_json.output
    tail = as_json.output.split("ranked candidates for manual review:\n", 1)[1].strip()
    parsed = json.loads(tail)  # the final segment is valid JSON
    assert isinstance(parsed, list) and parsed and "evidence_ref" in parsed[0]


# ── 5. empty candidate set is not an error ──────────────────────────────────────────


def test_scan_empty_candidates_is_ok(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _base_patches(monkeypatch)
    # an atlas with no instances for this run id -> triage returns nothing
    open_atlas(tmp_path / "atlas.db").close()

    async def _fake_analyze(*_: Any, **__: Any) -> SimpleNamespace:
        return _fake_analyze_result(tmp_path / "analysis.db")

    monkeypatch.setattr("treasure_map.lib.analyze.pipeline.run_analyze", _fake_analyze)
    monkeypatch.setattr("treasure_map.lib.hunt.run_analyzer2", lambda *a, **k: _hunt_stats(0))

    result = CliRunner().invoke(
        scan,
        [
            str(_mkfs(tmp_path)),
            "-w",
            str(tmp_path / "ws_empty"),
            "--atlas",
            str(tmp_path / "atlas.db"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "0 candidates" in result.output  # honest empty segment, no crash
