# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Two currency axes of Spec 2: the Ghidra that produced a run (a refusal: another decompiler
extracts differently) and the export a scan writes with each binary (not a refusal: the facts are
unchanged — the binaries are re-scanned for their export, and `tmap diff` does that first).

Zero real data: RunRow values and the diff-CLI test world.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from tests.unit.lib.binexport_seed import archive_exports, export_meta
from tests.unit.test_diff_cli import Env, env  # noqa: F401 -- the fixture
from treasure_map.cli import hunt_cli
from treasure_map.lib import rescan_version
from treasure_map.lib.atlas.models import RunRow
from treasure_map.lib.binexport_archive import archive_dir
from treasure_map.lib.config.config import Config
from treasure_map.lib.diff import toolchain
from treasure_map.lib.query.runs import run_staleness

# ── the Ghidra axis: proven stale, refused ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("stored", "installed", "stale"),
    [
        ("11.4.2", "11.4.3", True),
        ("11.4.3", "11.4.3", False),
        ("unknown", "11.4.3", False),  # mixed versions roll up to unknown: proves nothing
        ("11.4.2", None, False),  # no Ghidra readable here: proves nothing
        (None, "11.4.3", False),
    ],
)
def test_a_run_scanned_by_another_ghidra_is_refused(
    monkeypatch: pytest.MonkeyPatch, stored: str | None, installed: str | None, stale: bool
) -> None:
    """★ P-2=B: the decompiler that produced a run's facts is not the installed one -> provably
    stale on the toolchain axis (every tool refuses it until a re-scan); an unknown on either side
    is never a refusal.

    MUTATION (verified RED): drop the toolchain check from run_staleness -> served -> RED."""
    monkeypatch.setattr(toolchain, "_current_ghidra", [installed])
    run = RunRow(run_id="r", ghidra_version=stored)
    st = run_staleness(run, build_hash=None, current=rescan_version.CodeStamp("h", "s"), commit="c")
    assert st.stale is stale
    assert (st.axis == "toolchain") is stale


def test_an_export_script_change_never_refuses_a_run(monkeypatch: pytest.MonkeyPatch) -> None:
    """P-1=A: run_staleness reads no export: a run whose exports another export script made is
    served — only its binaries are re-scanned for their export."""
    monkeypatch.setattr(toolchain, "_current_ghidra", ["11.4.3"])
    run = RunRow(run_id="r", ghidra_version="11.4.3")
    st = run_staleness(run, build_hash=None, current=rescan_version.CodeStamp("h", "s"), commit="c")
    assert st.stale is False


# ── the rescan tiers ──────────────────────────────────────────────────────────────────────────


def _current_run(tmp_path: Path, statuses: list[tuple[str | None, str | None]]) -> RunRow:
    """A run every code stamp confirms current, its analysis.db holding one extracted binary per
    ``(binexport_status, export_hash)``."""
    from treasure_map.lib.storage.connection import open_db

    db = tmp_path / "analysis.db"
    conn = open_db(db)
    for i, (status, h) in enumerate(statuses):
        sha = f"{i}" * 64
        meta = export_meta(sha, "pv", export_hash=h) if h else None
        if meta is not None:  # an ok export has its archive on disk
            dest = archive_dir(db)
            dest.mkdir(parents=True, exist_ok=True)
            for name in (meta["archive"], meta["report_archive"]):
                (dest / name).write_bytes(b"x")
        conn.execute(
            "INSERT INTO binaries (name, sha256, ghidra_ok, binexport_status, binexport_scan_meta) "
            "VALUES (?, ?, 1, ?, ?)",
            (f"b{i}", sha, status, json.dumps(meta) if meta else None),
        )
    conn.commit()
    conn.close()
    cur = rescan_version.current_code_stamp(Config())
    return RunRow(
        run_id="r",
        resolved=True,
        scan_status="complete",
        analysis_db_path=str(db),
        ghidra_version="11.4.3",
        hunt_code_version=cur.hunt,
        scan_stamp=cur.scan,
        hunt_instances=0,
    )


def _reason(run: RunRow, tools: hunt_cli._ScanTools | None) -> tuple[str, str] | None:
    return hunt_cli._rescan_reason(
        run,
        current_build=None,
        current=rescan_version.current_code_stamp(Config()),
        live_instances=0,
        tools=tools,
    )


def test_the_tiers_name_an_upgraded_ghidra_and_out_of_date_exports(tmp_path: Path) -> None:
    """★ `tmap runs` / `rescan`: a run scanned by another Ghidra is the toolchain tier (every
    binary decompiled again); one whose exports another exporter made (or none recorded) is the
    export tier (those binaries decompiled again; the run stays served); a run whose exports match
    this install's is neither.

    MUTATION (verified RED): leave the export tier out of _rescan_reason -> None -> RED; order the
    export tier before the toolchain -> RED."""
    run = _current_run(tmp_path / "a", [("ok", "H"), ("ok", "OLD")])
    assert _reason(run, hunt_cli._ScanTools("11.4.3", "H")) == (
        "export",
        "BinExport exports out of date: 1 of 2 binaries' exports were made by other export "
        "scripts or another BinExport build, or not at all",
    )
    upgraded = hunt_cli._ScanTools("11.5.0", "H")
    axis, why = _reason(run, upgraded) or ("", "")
    assert axis == "toolchain" and "11.4.3" in why and "11.5.0" in why
    clean = _current_run(tmp_path / "b", [("ok", "H"), ("extension_missing", None)])
    assert _reason(clean, hunt_cli._ScanTools("11.4.3", None)) is None
    assert _reason(clean, hunt_cli._ScanTools("11.4.3", "H")) is not None  # extension now here
    assert {"toolchain", "export"} <= set(hunt_cli._TIER_ORDER)
    assert hunt_cli._TIER_ORDER.index("toolchain") < hunt_cli._TIER_ORDER.index("export")


# ── `tmap diff`: exports out of date are re-made first ────────────────────────────────────────


def _exported(env: Env, run_id: str, export_hash: str) -> None:  # noqa: F811
    db = env.ws_dir / run_id / "analysis.db"
    archive_exports(db, export_hash=export_hash)
    conn = sqlite3.connect(db)
    conn.execute("UPDATE binaries SET ghidra_ok = 1")
    conn.commit()
    conn.close()


def test_a_diff_rescans_a_run_whose_exports_are_out_of_date(env: Env) -> None:  # noqa: F811
    """★ U-2: the run's facts are current but its exports were made by another exporter: the diff
    says what the rescan costs, rescans it (only the binaries whose export is out of date are
    decompiled), then diffs; with --no-rescan it refuses instead. Without a BinExport here nothing
    can be re-made, and nothing is rescanned on that account.

    MUTATION (verified RED): skip the export check in the diff's rescan plan -> no rescan -> RED."""
    env.run("old")
    env.run("new")
    _exported(env, "old", "NEW")
    _exported(env, "new", "OLD")
    env.mp.setattr(hunt_cli, "_scan_tools", lambda cfg: hunt_cli._ScanTools(None, "NEW"))
    refused = env.diff("old", "new", "--no-rescan")
    assert refused.exit_code != 0 and "out of date (export)" in refused.output
    assert env.rescans == []
    res = env.diff()
    assert res.exit_code == 0, res.output
    assert [r["run_ids"] for r in env.rescans] == [("new",)]
    assert hunt_cli._TIER_LABEL["export"] in res.output
    assert hunt_cli._TIER_COST["export"] in res.output
    env.rescans.clear()
    env.mp.setattr(hunt_cli, "_scan_tools", lambda cfg: hunt_cli._ScanTools(None, None))
    _exported(env, "new", "OLD")
    assert env.diff().exit_code == 0
    assert env.rescans == []
