# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The MCP tool-call log (lib/tool_call_log): every call through the server is recorded in a local
file outside the atlas, best effort — key parameters only, never the response or free text, and a
failure to record never fails the tool."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from tests.unit.test_tool_surface import _call, _world
from treasure_map import mcp_app
from treasure_map.lib import tool_call_log as tcl


def _lines(atlas: Path) -> list[dict[str, Any]]:
    got = tcl.read_lines(tcl.log_path_for(atlas))
    return [] if got is None else list(got)


def test_a_call_through_the_server_is_recorded_outside_the_atlas(tmp_path: Path) -> None:
    """★ One line per call, next to (not in) the atlas: the tool, the session, the key parameters
    and the response size; a second server is another session.

    MUTATION (verified RED): drop the record call from _with_usage_hint -> no line -> RED."""
    atlas = _world(tmp_path)
    server = mcp_app.build_server(atlas)
    _call(server, "list_runs", {})
    _call(server, "list_runs", {})
    lines = _lines(atlas)
    assert [ln.get("tool") for ln in lines] == ["list_runs", "list_runs"]
    first = lines[0]
    assert tcl.log_path_for(atlas).parent.parent == atlas.resolve().parent
    assert first.get("response_bytes", 0) > 0 and first.get("error") is None
    assert first.get("session") == lines[1].get("session") and first.get("pid")
    _call(mcp_app.build_server(atlas), "list_runs", {})
    assert _lines(atlas)[-1].get("session") != first.get("session")


def test_only_the_key_parameters_are_recorded_never_free_text(tmp_path: Path) -> None:
    """★ A write call keeps its anchor and verdict in the log; its rationale is never written.

    MUTATION (verified RED): record every argument (drop the KEY_PARAMS filter) -> the rationale
    is in the log -> RED."""
    atlas = _world(tmp_path)
    server = mcp_app.build_server(atlas)
    secret = "zz-free-text-never-logged"
    _call(
        server,
        "annotate_diff",
        {
            "anchor_ref": "no-such-anchor",
            "verdict": "changed_real",
            "rationale": secret,
            "diff_id": "d-none",
        },
    )
    (line,) = _lines(atlas)
    assert line.get("params", {}).get("anchor_ref") == "no-such-anchor"
    assert line.get("params", {}).get("diff_id") == "d-none"
    assert "rationale" not in line.get("params", {})
    assert secret not in tcl.log_path_for(atlas).read_text()


def test_a_refused_unknown_parameter_and_a_raised_error_are_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The unknown-parameter refusal (before the tool runs) and an exception the tool raises are
    each one line with its error; the exception still reaches the caller.

    MUTATION (verified RED): drop the record in _CheckedFastMCP.call_tool -> RED; drop the record
    in the wrapper's except -> RED."""
    atlas = _world(tmp_path)
    real = mcp_app.make_tools

    def failing(*a: Any, **k: Any) -> dict[str, Any]:
        tools = real(*a, **k)

        def boom() -> dict[str, Any]:
            raise RuntimeError("zz-boom")

        tools["legal_notice"] = boom
        return tools

    monkeypatch.setattr(mcp_app, "make_tools", failing)
    server = mcp_app.build_server(atlas)
    with pytest.raises(ToolError):
        _call(server, "list_runs", {"zz_unknown": 1})
    with pytest.raises(ToolError, match="zz-boom"):
        _call(server, "legal_notice", {})
    lines = _lines(atlas)
    assert [ln.get("tool") for ln in lines] == ["list_runs", "legal_notice"]
    assert "zz_unknown" in (lines[0].get("error") or "")
    assert "zz-boom" in (lines[1].get("error") or "")


def test_a_log_that_cannot_be_written_never_fails_the_tool(tmp_path: Path) -> None:
    """★ The log's path is a directory: the call answers as it would, nothing is raised.

    MUTATION (verified RED): let append raise -> the tool call fails -> RED."""
    atlas = _world(tmp_path)
    tcl.log_path_for(atlas).mkdir(parents=True)
    try:
        out: dict[str, Any] | None = _call(mcp_app.build_server(atlas), "list_runs", {})
    except ToolError:
        out = None
    assert out is not None and ("runs" in out or "server" in out)


@pytest.mark.parametrize(
    ("result", "cut"),
    [
        ({"next_offset": 5}, True),
        ({"next_offset": None}, False),
        ({"paging": {"next_hunk_offset": 2}}, True),
        ({"truncated": True}, True),
        ({"truncated": False, "entries": []}, False),
        ({"a": {"b": {"next_offset": 1}}}, False),  # two levels down is a member's, not the page's
    ],
)
def test_a_cut_page_is_marked(result: dict[str, Any], cut: bool) -> None:
    """MUTATION (verified RED): read the top level only -> the paging case -> RED."""
    assert tcl.build_line(tcl.Session(), "t", {}, result).get("truncated") is cut


def test_reading_tells_a_missing_log_from_an_empty_one(tmp_path: Path) -> None:
    """No log is None (unknown), not an empty trail; a bad line is skipped; the moved-aside
    generation is read first.

    MUTATION (verified RED): return an empty iterator for a missing log -> RED."""
    path = tmp_path / "logs" / tcl.LOG_FILENAME
    assert tcl.read_lines(path) is None
    path.parent.mkdir()
    path.with_name(path.name + ".1").write_text(json.dumps({"tool": "old"}) + "\n")
    path.write_text("not json\n" + json.dumps({"tool": "new"}) + "\n[1]\n")
    got = tcl.read_lines(path)
    assert got is not None and [x.get("tool") for x in got] == ["old", "new"]


def test_a_long_log_is_moved_aside_before_a_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MUTATION (verified RED): never rotate -> one file holds both -> RED."""
    monkeypatch.setattr(tcl, "MAX_LOG_BYTES", 10)
    log = tcl.ToolCallLog(tmp_path / "logs" / tcl.LOG_FILENAME)
    log.record("first", {})
    log.record("second", {})
    aside = log.path.with_name(log.path.name + ".1")
    assert aside.is_file() and "first" in aside.read_text()
    assert "first" not in log.path.read_text() and "second" in log.path.read_text()


@pytest.mark.parametrize(
    ("result", "recorded"),
    [
        ({"next_unit": {"unit_id": "u1", "material": {"entry": {}}}}, True),
        # a write's answer naming the next unit without its material: not handed out
        ({"next_unit": {"unit_id": "u1", "read_with": "start_diff_review(...)"}}, False),
        # a material that is only an error carries nothing to read
        ({"next_unit": {"unit_id": "u1", "material": {"error": "gone"}}}, False),
        # start_diff_review(run_pair, unit=...): the unit's head, its material beside it
        ({"unit": {"unit_id": "u1"}, "material": {"entry": {}}}, True),
        ({"unit": {"unit_id": "u1"}}, False),
    ],
    ids=["with_material", "head_only", "error_material", "unit_read", "unit_head_only"],
)
def test_a_unit_counts_as_handed_out_only_with_its_material(
    result: dict[str, Any], recorded: bool
) -> None:
    """★ C-2: the log records a unit as handed out (what a later write's ``unit_delivered`` is
    read from) only when the answer carried its material — a unit named without it was not read.

    MUTATION (verified RED, 3 failed): record any answer naming a unit (the old rule) -> head_only,
    error_material and unit_head_only RED."""
    from treasure_map.lib.query import read_basis as rb

    line = tcl.build_line(tcl.Session(), "annotate_diff", {}, result)
    assert ("unit" in line) is recorded
    basis = rb.infer([line], anchor_ref="x", unit_id="u1")["basis"]
    assert (basis == "unit_delivered") is recorded
