# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The MCP server's side of the code-stamp currency decision.

Three behaviours are unique to the server and cannot be read off the gate alone: it compares against
the config it was given (so a custom xref threshold makes a default-threshold run stale); it fixes
the running stamp at construction, not per call (a long-lived process does not drift as the code on
disk changes under it); and when it HAS drifted, a refusal says to restart it, because a rescan from
the command line uses the on-disk code and cannot make runs current for this already-started server.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from treasure_map import mcp_app
from treasure_map.lib import rescan_version
from treasure_map.lib.analyze.ghidra_runner import current_pass_version
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.writer import begin_run, finish_run
from treasure_map.lib.config.config import Config
from treasure_map.lib.rescan_version import CodeStamp
from treasure_map.lib.storage.connection import open_db


def _mk_analysis(tmp_path: Path) -> Path:
    db = tmp_path / "analysis.db"
    conn = open_db(db)
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256, pass_version, last_seen_at) "
        "VALUES (1, 'webd', 'usr/sbin/webd', ?, ?, '2026-01-01T00:00:00')",
        ("a" * 64, current_pass_version()),
    )
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, address, size_bytes, pseudocode, callees) "
        "VALUES (1, 1, 'handle_req', '0x6b90', 64, 'void handle_req(){ do_fwd(buf); }', ?)",
        (json.dumps(["do_fwd"]),),
    )
    conn.commit()
    conn.close()
    return db


def _atlas(tmp_path: Path, *, hunt_code: str | None, scan_stamp: str | None) -> Path:
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    begin_run(
        conn,
        "run_m",
        analysis_db_path=str((tmp_path / "analysis.db").resolve()),
        firmware_path=str(tmp_path / "fw"),
        build_hash=current_pass_version(),
    )
    finish_run(
        conn,
        "run_m",
        binaries=1,
        functions=1,
        hunt_commit="c" * 40,
        hunt_instances=0,
        hunt_code_version=hunt_code,
        scan_stamp=scan_stamp,
    )
    conn.close()
    return atlas


def test_a_run_scanned_under_a_different_config_is_refused(tmp_path: Path) -> None:
    """★ The server compares against the config IT was handed. A run whose scan stamp records the
    default xref threshold is stale to a server configured with another, and the refusal names the
    config key and both values.

    MUTATION: drop ``config`` from the scan stamp comparison (compare only code) -> RED (served)."""
    _mk_analysis(tmp_path)
    # The run carries the running hunt code and the DEFAULT-threshold scan stamp.
    atlas = _atlas(
        tmp_path,
        hunt_code=rescan_version.hunt_code_version(),
        scan_stamp=rescan_version.scan_stamp_for(Config()),
    )
    tools = mcp_app.make_tools(atlas, config=Config(xref_fold_edge_threshold=10_000))
    out = tools["get_pseudocode"]("handle_req", run_id="run_m")
    assert out.get("found") is False
    assert out["stale_scan"]["axis"] == "hunt"
    detail = out["stale_scan"]["detail"]
    assert "config.xref_fold_edge_threshold" in detail
    assert "25000" in detail and "10000" in detail


def test_a_run_scanned_under_the_same_config_is_served(tmp_path: Path) -> None:
    """The counterweight: same code, same config -> current -> served (not every run is refused)."""
    _mk_analysis(tmp_path)
    atlas = _atlas(
        tmp_path,
        hunt_code=rescan_version.hunt_code_version(),
        scan_stamp=rescan_version.scan_stamp_for(Config()),
    )
    tools = mcp_app.make_tools(atlas, config=Config())
    out = tools["get_pseudocode"]("handle_req", run_id="run_m")
    assert out.get("found") is not False, out


def test_the_server_stamp_is_fixed_at_construction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ The server grades against the code it STARTED with. Build the tools over a current run,
    then change the hunt code the module would report — the server must still serve the run, because
    it holds the stamp from construction and does not re-read it per call.

    MUTATION: compute the stamp inside the tool instead of once in make_tools -> RED (the run would
    read as stale after the patch)."""
    _mk_analysis(tmp_path)
    atlas = _atlas(
        tmp_path,
        hunt_code=rescan_version.hunt_code_version(),
        scan_stamp=rescan_version.scan_stamp_for(Config()),
    )
    tools = mcp_app.make_tools(atlas, config=Config())
    monkeypatch.setattr(rescan_version, "hunt_code_version", lambda: "src-f6f6f6f6f6f6f6f6")
    out = tools["get_pseudocode"]("handle_req", run_id="run_m")
    assert out.get("found") is not False, "the server must use its construction-time stamp"


def test_a_refusal_names_a_restart_when_the_on_disk_code_moved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ When the server's stamp no longer matches the code on disk, a refusal says to restart it:
    a rescan from the command line runs the on-disk code and cannot make the run current for a
    server still grading against its older, started-with code.

    MUTATION: drop the ``_server_code_moved`` suffix from the remedy -> RED."""
    _mk_analysis(tmp_path)
    # A run stale on the hunt code, so there is always a refusal to carry the hint.
    atlas = _atlas(
        tmp_path,
        hunt_code="src-b2b2b2b2b2b2b2b2",
        scan_stamp=rescan_version.scan_stamp_for(Config()),
    )
    tools = mcp_app.make_tools(atlas, config=Config())

    moved = CodeStamp(hunt="src-f6f6f6f6f6f6f6f6", scan=rescan_version.scan_stamp_for(Config()))
    monkeypatch.setattr(rescan_version, "on_disk_code_stamp", lambda _cfg: moved)
    refused = tools["get_pseudocode"]("handle_req", run_id="run_m")
    assert refused.get("found") is False
    assert "Restart the MCP server" in refused["remedy"]


def test_a_refusal_omits_the_restart_when_the_on_disk_code_matches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The counterweight: when on-disk code equals the server's stamp, the refusal carries only its
    own remedy — the restart hint would be noise, and worse, a false lead."""
    _mk_analysis(tmp_path)
    atlas = _atlas(
        tmp_path,
        hunt_code="src-b2b2b2b2b2b2b2b2",
        scan_stamp=rescan_version.scan_stamp_for(Config()),
    )
    tools = mcp_app.make_tools(atlas, config=Config())

    same = rescan_version.current_code_stamp(Config())
    monkeypatch.setattr(rescan_version, "on_disk_code_stamp", lambda _cfg: same)
    refused = tools["get_pseudocode"]("handle_req", run_id="run_m")
    assert refused.get("found") is False
    assert "Restart the MCP server" not in refused["remedy"]


def test_the_restart_hint_is_recomputed_on_every_refusal_not_cached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ The hint is recomputed each refusal, not cached in the server closure: the code can be
    edited (then restored) under a long-lived server between two calls, and each refusal must report
    the on-disk state AT THAT MOMENT. One ``make_tools``, two refusals: on-disk matches first (no
    hint), then has moved (hint must appear).

    MUTATION (audit G04): cache the first ``_server_code_moved`` result in the closure -> the second
    refusal keeps the first "no hint" answer and this goes RED.
    """
    _mk_analysis(tmp_path)
    atlas = _atlas(
        tmp_path,
        hunt_code="src-b2b2b2b2b2b2b2b2",
        scan_stamp=rescan_version.scan_stamp_for(Config()),
    )
    tools = mcp_app.make_tools(atlas, config=Config())

    same = rescan_version.current_code_stamp(Config())
    monkeypatch.setattr(rescan_version, "on_disk_code_stamp", lambda _cfg: same)
    first = tools["get_pseudocode"]("handle_req", run_id="run_m")
    assert first.get("found") is False and "Restart the MCP server" not in first["remedy"]

    moved = CodeStamp(hunt="src-f6f6f6f6f6f6f6f6", scan=rescan_version.scan_stamp_for(Config()))
    monkeypatch.setattr(rescan_version, "on_disk_code_stamp", lambda _cfg: moved)
    second = tools["get_pseudocode"]("handle_req", run_id="run_m")
    assert second.get("found") is False and "Restart the MCP server" in second["remedy"]


def test_on_disk_code_stamp_is_computed_fresh_not_from_the_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``on_disk_code_stamp`` reads the tree RIGHT NOW (uncached) so the restart hint can see the
    code move under a long-lived server; ``current_code_stamp`` is the cached construction-time
    value. This pins that the on-disk stamp follows the uncached ``code_version_of``, not the cache.

    MUTATION (audit G10): make ``on_disk_code_stamp`` return the cached ``current_code_stamp`` -> it
    stops reflecting an on-disk change and this goes RED.
    """
    cfg = Config()
    on_disk_hunt = "src-0d0d0d0d0d0d0d0d"
    cached = rescan_version.hunt_code_version()  # lock the cached value before patching
    monkeypatch.setattr(rescan_version, "code_version_of", lambda _pkg, _root: on_disk_hunt)
    on_disk = rescan_version.on_disk_code_stamp(cfg)
    assert on_disk.hunt == on_disk_hunt, "on_disk reads the tree now, via code_version_of"
    assert rescan_version.hunt_code_version() == cached, "the cached stamp is untouched"


def test_a_cross_run_refusal_also_carries_the_restart_hint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ COVERAGE, not a rule: the cross-run readers (cross_firmware_patterns, pattern_density) name
    a stale run under ``stale_runs_refused`` instead of a single refusal, and that entry's remedy
    carries the SAME restart hint as the single-run gate — a hint on one entry point and not the
    other would be a weaker gate beside a stronger one (audit G11).

    MUTATION: in ``_stale_run_index`` drop the ``_server_code_moved`` suffix from the remedy -> RED.
    """
    _mk_analysis(tmp_path)
    atlas = _atlas(
        tmp_path,
        hunt_code="src-b2b2b2b2b2b2b2b2",
        scan_stamp=rescan_version.scan_stamp_for(Config()),
    )
    tools = mcp_app.make_tools(atlas, config=Config())
    moved = CodeStamp(hunt="src-f6f6f6f6f6f6f6f6", scan=rescan_version.scan_stamp_for(Config()))
    monkeypatch.setattr(rescan_version, "on_disk_code_stamp", lambda _cfg: moved)
    out = tools["cross_firmware_patterns"]()
    refused = [e for e in out["stale_runs_refused"] if e["run_id"] == "run_m"]
    assert refused, out["stale_runs_refused"]
    assert all("Restart the MCP server" in e["remedy"] for e in refused)
