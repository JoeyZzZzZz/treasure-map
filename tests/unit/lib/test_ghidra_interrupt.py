# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Behavioral tests for Ghidra subprocess-group teardown on interrupt/timeout.

Uses real child process groups (sleep) — no Ghidra needed. Proves terminate_all
kills a registered group, that an empty registry is an instant no-op, that a
timed-out subprocess leaves no live group, and that an interrupt mid-flight kills
the group and re-raises KeyboardInterrupt without leaking a JVM.
"""

from __future__ import annotations

import os
import subprocess
import time

import pytest

from treasure_map.lib.analyze import ghidra_runner
from treasure_map.lib.analyze.ghidra_runner import (
    _active_pgids,
    _register_pgid,
    _run_subprocess,
    terminate_all,
)


def _group_alive(pgid: int) -> bool:
    """True if the process group still exists (signal 0 probes without killing)."""
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def test_terminate_all_kills_registered_group() -> None:
    proc = subprocess.Popen(["sleep", "600"], start_new_session=True)
    pgid = proc.pid
    _register_pgid(pgid)
    try:
        assert _group_alive(pgid)
        terminate_all(grace=0.2)
        assert proc.wait(timeout=5) != 0  # killed by signal -> non-zero
        assert pgid not in _active_pgids  # registry cleared
        assert not _group_alive(pgid)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)


def test_terminate_all_empty_registry_is_instant_noop() -> None:
    assert not _active_pgids  # nothing registered
    t0 = time.monotonic()
    terminate_all(grace=2.0)
    assert time.monotonic() - t0 < 0.05  # never hit the grace sleep


def test_run_subprocess_timeout_kills_group() -> None:
    captured: dict[str, int] = {}
    real_register = ghidra_runner._register_pgid

    def _spy(pgid: int) -> None:
        captured["pgid"] = pgid
        real_register(pgid)

    ghidra_runner._register_pgid = _spy  # type: ignore[assignment]
    try:
        rc, tail = _run_subprocess(["sleep", "30"], dict(os.environ), timeout=1)
    finally:
        ghidra_runner._register_pgid = real_register  # type: ignore[assignment]

    assert rc == -1
    assert tail == "timeout"
    pgid = captured["pgid"]
    assert not _group_alive(pgid)  # the sleep group is gone after return
    assert pgid not in _active_pgids  # finally-unregistered


def test_run_subprocess_interrupt_kills_group_and_reraises(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, int] = {}
    real_register = ghidra_runner._register_pgid

    def _spy(pgid: int) -> None:
        captured["pgid"] = pgid
        real_register(pgid)

    monkeypatch.setattr(ghidra_runner, "_register_pgid", _spy)

    real_communicate = subprocess.Popen.communicate
    calls = {"n": 0}

    def _fake_communicate(self: subprocess.Popen, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        # First call (the blocking wait) raises KeyboardInterrupt; the teardown
        # reap call (second) is allowed through so the child is actually reaped.
        calls["n"] += 1
        if calls["n"] == 1:
            raise KeyboardInterrupt
        return real_communicate(self, *args, **kwargs)

    monkeypatch.setattr(subprocess.Popen, "communicate", _fake_communicate)

    with pytest.raises(KeyboardInterrupt):
        _run_subprocess(["sleep", "30"], dict(os.environ), timeout=30)

    pgid = captured["pgid"]
    assert not _group_alive(pgid)  # group killed on the interrupt path
    assert pgid not in _active_pgids  # finally-unregistered, no leak
