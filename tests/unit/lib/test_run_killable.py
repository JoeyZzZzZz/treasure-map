# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""A timed-out or interrupted BinExport subprocess takes its whole process group — the orphaned-JVM
leak — and it does so AT ONCE, not by waiting the orphan out."""

from __future__ import annotations

import os
import signal
import subprocess
import time

import pytest

from treasure_map.lib.diff import driver
from treasure_map.lib.diff.driver import _kill_running_groups, _run_killable


def _reap(marker: str) -> list[str]:
    """Find, kill and return any surviving sleeper PIDs for ``marker`` (never leave a real leak)."""
    out = subprocess.run(["pgrep", "-f", marker], capture_output=True, text=True)  # noqa: S603,S607
    pids = [p for p in out.stdout.split() if p]
    for p in pids:
        try:
            os.kill(int(p), signal.SIGKILL)
        except (OSError, ValueError):
            pass
    return pids


def test_a_timeout_kills_the_whole_group_at_once_not_just_the_wrapper() -> None:
    """A shell that backgrounds a long child and waits (the analyzeHeadless->JVM shape): run's own
    timeout reaps the shell and leaves the child; _run_killable kills the whole group, and does it
    at once rather than letting communicate() block until the orphan exits on its own.

    The child sleeps 60s; the group kill must end this in a couple of seconds. The elapsed bound is
    what gives the test teeth the old version lacked: a version that dropped the killpg but kept
    communicate() stayed GREEN because, by the time communicate() returned (~60s later), the orphan
    had finished and pgrep found nothing. Here that version blows the time bound instead.

    MUTATIONS (each must go RED):
      * ``subprocess.run(..., timeout=)`` or ``os.kill(proc.pid, ...)`` (only the wrapper) ->
        the child survives -> the pgrep assertion fails.
      * drop the killpg and only re-raise -> communicate() waits ~60s -> the elapsed bound fails.
      * drop ``start_new_session=True`` -> killpg targets a non-group-leader -> child survives."""
    marker = "tmap_test_sleeper_rk1"
    script = f'python3 -c "import time; time.sleep(60)  # {marker}" & wait'
    start = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        _run_killable(["sh", "-c", script], dict(os.environ), 1)
    elapsed = time.monotonic() - start
    time.sleep(0.5)  # let SIGKILL propagate before we look
    leaked = _reap(marker)
    assert leaked == [], f"orphaned child survived the group kill: {leaked}"
    assert elapsed < 15, f"took {elapsed:.1f}s -> the orphan was waited on, not killed at once"


def test_run_killable_registers_its_group_only_while_running() -> None:
    """The running subprocess's group is in the registry during the call and gone after it, so an
    interrupt on another thread can reap it and a finished one is never signalled by mistake.

    MUTATION (RED): drop the ``_unregister_pgid`` in the finally -> the set keeps the dead group."""
    before = set(driver._RUNNING_PGIDS)
    cp = _run_killable(["true"], dict(os.environ), 30)
    assert cp.returncode == 0
    assert set(driver._RUNNING_PGIDS) == before  # registered during the run, removed after it


def test_kill_running_groups_reaps_a_registered_group() -> None:
    """``_kill_running_groups`` SIGKILLs every registered group — the main-thread path that takes
    the in-flight JVMs down when a full sweep is interrupted, without waiting each one out.

    MUTATION (RED): make ``_kill_running_groups`` a no-op (or ``os.kill`` instead of ``os.killpg``)
    -> the detached child outlives the call -> the time-bounded pgrep assertion fails."""
    marker = "tmap_test_sleeper_rk2"
    # A child in its OWN session (as _run_killable starts them), backgrounded under a shell that
    # exits immediately, so ONLY a group-level kill — not reaping its parent — can stop it.
    proc = subprocess.Popen(  # noqa: S603
        ["sh", "-c", f'python3 -c "import time; time.sleep(60)  # {marker}" & disown; exit 0'],
        start_new_session=True,
    )
    pgid = proc.pid
    driver._register_pgid(pgid)
    try:
        time.sleep(0.3)  # let the child spawn
        start = time.monotonic()
        _kill_running_groups()
        time.sleep(0.5)
        elapsed = time.monotonic() - start
        leaked = _reap(marker)
        assert leaked == [], f"registered group was not reaped: {leaked}"
        assert elapsed < 15
    finally:
        driver._unregister_pgid(pgid)
        _reap(marker)
        try:
            os.killpg(pgid, signal.SIGKILL)
        except OSError:
            pass
