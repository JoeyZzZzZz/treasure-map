# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""D33: list_runs / start_diff_review / get_diff_meta report a ``server`` block — the running
server's own build. Every version field is the IN-PROCESS value, fixed at startup; only
``code_moved_on_disk`` is compared against the disk, and the disk is probed at most ONCE per
response (head and any refusal share the one probe). Zero real data: the test world of
test_patch_view.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.unit.lib.test_patch_view import DIFF, World
from treasure_map.lib import rescan_version
from treasure_map.mcp_app import make_tools

_FIELDS = {
    "commit",
    "version",
    "hunt_code",
    "scan_code",
    "pass_version",
    "diff_code_version",
    "code_moved_on_disk",
}


def _world(tmp_path: Path) -> World:
    w = World(tmp_path)
    w.commit()
    return w


def test_list_runs_reports_the_whole_server_block(tmp_path: Path) -> None:
    """Every field present; scan_code is the full stamp JSON (not just its ``code``); an editable
    install's commit is the unknown sentinel, never an error."""
    s = make_tools(_world(tmp_path).path)["list_runs"]()["server"]
    assert set(s) == _FIELDS
    parsed = json.loads(s["scan_code"])  # a full JSON stamp, config + deps and all
    assert "code" in parsed and "config" in parsed
    assert s["commit"] == "unknown" or len(s["commit"]) == 40
    assert s["code_moved_on_disk"] is False


def test_all_three_tools_share_one_assembler(tmp_path: Path) -> None:
    t = make_tools(_world(tmp_path).path)
    blocks = [
        t["list_runs"]()["server"],
        t["start_diff_review"](DIFF)["server"],
        t["get_diff_meta"](DIFF)["server"],
    ]
    assert blocks[0] == blocks[1] == blocks[2]


def test_code_moved_on_disk_tracks_the_disk_but_fields_do_not(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``code_moved_on_disk`` follows the disk; the version fields stay the loaded values."""
    t = make_tools(_world(tmp_path).path)  # pins _server_base at startup
    before = t["list_runs"]()["server"]
    assert before["code_moved_on_disk"] is False
    monkeypatch.setattr(
        rescan_version, "on_disk_code_stamp", lambda cfg: rescan_version.CodeStamp("src-X", "{}")
    )
    after = t["list_runs"]()["server"]
    assert after["code_moved_on_disk"] is True
    for k in ("commit", "version", "hunt_code", "scan_code", "pass_version", "diff_code_version"):
        assert after[k] == before[k]  # in-process loaded value, never re-read from disk
    assert after["hunt_code"] != "src-X"


def test_diff_code_version_is_fixed_at_startup(tmp_path: Path) -> None:
    """Read twice, the diff_code_version is the same — bound once at startup, not recomputed."""
    t = make_tools(_world(tmp_path).path)
    assert (
        t["list_runs"]()["server"]["diff_code_version"]
        == (t["get_diff_meta"](DIFF)["server"]["diff_code_version"])
    )


def test_the_disk_is_probed_at_most_once_per_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """get_diff_meta on a servable diff probes on_disk_code_stamp once (the head).

    MUTATION (verified RED): make the refusal path compute its own probe -> a stale diff probes
    twice; here, a servable one still shows the single head probe."""
    calls = {"n": 0}
    real = rescan_version.on_disk_code_stamp
    monkeypatch.setattr(
        rescan_version,
        "on_disk_code_stamp",
        lambda cfg: (calls.__setitem__("n", calls["n"] + 1), real(cfg))[1],
    )
    t = make_tools(_world(tmp_path).path)
    calls["n"] = 0
    t["get_diff_meta"](DIFF)
    assert calls["n"] <= 1


def test_a_stale_diff_refusal_carries_server_and_probes_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A proven-stale side refuses the diff, the refusal carries the server block, and the disk is
    still probed only once — the head's probe is reused for the refusal's remedy.

    MUTATION (verified RED): a refusal that computes its own _server_code_moved -> two probes."""
    w = World(tmp_path)
    w.atlas.execute("UPDATE run SET build_hash = 'OLDpipelineHASH' WHERE run_id = 'runA'")
    w.commit()
    calls = {"n": 0}
    real = rescan_version.on_disk_code_stamp
    monkeypatch.setattr(
        rescan_version,
        "on_disk_code_stamp",
        lambda cfg: (calls.__setitem__("n", calls["n"] + 1), real(cfg))[1],
    )
    t = make_tools(w.path)
    calls["n"] = 0
    out = t["get_diff_meta"](DIFF)
    assert "server" in out  # the refusal carries the server block
    assert "stale_scan" in out or "STALE" in str(out.get("error", ""))  # it IS a refusal
    assert calls["n"] <= 1  # head + refusal share one probe
