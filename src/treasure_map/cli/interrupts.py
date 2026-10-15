# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Termination signals handled the way Ctrl-C is.

Every long-running command already cleans up on ``KeyboardInterrupt``: the Ghidra and BinExport
process groups are killed, temporary directories are removed, ``finally`` blocks run. A ``kill``,
a CI timeout or a closed terminal sends SIGTERM or SIGHUP instead, whose default action ends the
process on the spot — none of that cleanup runs, and each JVM it started (they live in their own
session, out of the terminal's reach) keeps running on its own. Turning those two signals into the
same ``KeyboardInterrupt`` routes them through the cleanup that already exists.

The exit code follows the shell convention, 128 + the signal number: 130 for Ctrl-C, 143 for
SIGTERM, 129 for SIGHUP.
"""

from __future__ import annotations

import signal
from types import FrameType

_HANDLED: tuple[int, ...] = tuple(
    s for s in (getattr(signal, "SIGTERM", None), getattr(signal, "SIGHUP", None)) if s is not None
)
_INTERRUPT_EXITS = frozenset(128 + s for s in (signal.SIGINT, *_HANDLED))
_received: int | None = None


def _to_interrupt(signum: int, frame: FrameType | None) -> None:
    global _received
    _received = signum
    raise KeyboardInterrupt


def install_termination_handlers() -> None:
    """Route SIGTERM / SIGHUP into ``KeyboardInterrupt`` for the rest of this process."""
    for sig in _HANDLED:
        try:
            signal.signal(sig, _to_interrupt)
        except (ValueError, OSError):  # not the main thread, or the platform refuses it
            pass


def restore_default_termination() -> None:
    """Give SIGTERM / SIGHUP back their default action (for a server its client stops)."""
    for sig in _HANDLED:
        try:
            signal.signal(sig, signal.SIG_DFL)
        except (ValueError, OSError):
            pass


def interrupt_exit_code() -> int:
    """The exit code for the interrupt being handled: 128 + the signal that caused it."""
    return 128 + (_received if _received is not None else signal.SIGINT)


def is_interrupt_exit(code: object) -> bool:
    """Whether a ``SystemExit`` code is one of the interrupt exits above."""
    return code in _INTERRUPT_EXITS
