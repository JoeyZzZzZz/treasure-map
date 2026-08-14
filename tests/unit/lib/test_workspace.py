# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from treasure_map.lib.workspace import Workspace


def test_mark_and_check(tmp_path):
    ws = Workspace(tmp_path / "ws")
    assert not ws.is_done("step1")
    ws.mark_done("step1")
    assert ws.is_done("step1")
    ws.close()


def test_persistence_across_reopen(tmp_path):
    ws_path = tmp_path / "ws"
    ws = Workspace(ws_path)
    ws.mark_done("parse")
    ws.close()

    ws2 = Workspace(ws_path)
    assert ws2.is_done("parse")
    ws2.close()


def test_clear_downstream(tmp_path):
    ws = Workspace(tmp_path / "ws")
    ws.mark_done("a")
    ws.mark_done("b")
    ws.mark_done("c")
    ws.clear_downstream("a", ["b", "c"])
    assert ws.is_done("a")
    assert not ws.is_done("b")
    assert not ws.is_done("c")
    ws.close()


def test_list_done(tmp_path):
    ws = Workspace(tmp_path / "ws")
    ws.mark_done("x")
    ws.mark_done("y")
    done = ws.list_done()
    assert "x" in done
    assert "y" in done
    ws.close()


def test_progress_callback(tmp_path):
    events: list[tuple[str, dict]] = []

    def cb(step, meta):
        events.append((step, meta))

    ws = Workspace(tmp_path / "ws", progress_callback=cb)
    ws.mark_done("elf_scan", {"count": 12})
    ws.close()

    assert events == [("elf_scan", {"count": 12})]


def test_reset(tmp_path):
    ws = Workspace(tmp_path / "ws")
    ws.mark_done("step1")
    ws.mark_done("step2")
    ws.reset()
    assert ws.list_done() == []
    ws.close()


def test_context_manager(tmp_path):
    with Workspace(tmp_path / "ws") as ws:
        ws.mark_done("init")
        assert ws.is_done("init")


def test_idempotent_mark_done(tmp_path):
    ws = Workspace(tmp_path / "ws")
    ws.mark_done("step")
    ws.mark_done("step")  # should not raise
    assert ws.is_done("step")
    ws.close()
