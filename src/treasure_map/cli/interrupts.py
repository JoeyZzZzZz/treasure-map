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

import click

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


class InterruptCommand(click.Command):
    """A click command that exits 128 + signal on an interrupt, like the scan/hunt commands do by
    hand. Without it click's default turns a Ctrl-C (or a SIGTERM/SIGHUP routed to one) into an
    ``Abort`` that exits 1 — indistinguishable from an ordinary error for a read command that has
    no other cleanup to run. ``invoke`` is where the callback runs, so catching here covers the
    whole command body."""

    def invoke(self, ctx: click.Context) -> object:
        try:
            return super().invoke(ctx)
        except KeyboardInterrupt:
            raise SystemExit(interrupt_exit_code()) from None


class InterruptGroup(click.Group):
    """The same, for a command GROUP: a KeyboardInterrupt raised inside any subcommand propagates
    through the group's ``invoke`` and becomes the 128 + signal exit, so every subcommand of the
    group follows the interrupt contract without repeating the handler on each one."""

    def invoke(self, ctx: click.Context) -> object:
        try:
            return super().invoke(ctx)
        except KeyboardInterrupt:
            raise SystemExit(interrupt_exit_code()) from None
