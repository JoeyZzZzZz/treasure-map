# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""A timed-out BinExport subprocess takes its whole process group — the orphaned-JVM leak."""

from __future__ import annotations

import os
import signal
import subprocess
import time

import pytest

from treasure_map.lib.diff.driver import _run_killable


def test_a_timeout_kills_the_whole_group_not_just_the_wrapper() -> None:
    """A shell that backgrounds a long child (the analyzeHeadless->JVM shape) and waits: run's own
    timeout reaps the shell and can leave the child; _run_killable kills the group.

    MUTATION: use subprocess.run(..., timeout=) instead of the process-group kill -> RED."""
    marker = "tmap_test_sleeper_rk"
    script = f'python3 -c "import time; time.sleep(60)  # {marker}" & wait'
    with pytest.raises(subprocess.TimeoutExpired):
        _run_killable(["sh", "-c", script], dict(os.environ), 1)
    time.sleep(0.5)
    out = subprocess.run(["pgrep", "-f", marker], capture_output=True, text=True)  # noqa: S603,S607
    leaked = [p for p in out.stdout.split() if p]
    for p in leaked:  # never leave a real leak behind, even on failure
        try:
            os.kill(int(p), signal.SIGKILL)
        except (OSError, ValueError):
            pass
    assert leaked == []
