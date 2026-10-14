# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""A checkbox list on the terminal, with no dependency beyond the standard library.

↑/↓ (and Tab / Shift-Tab) move, Space toggles, ``a`` selects all, ``n`` none, Enter submits —
and Enter never toggles. Ctrl-C aborts. The terminal is restored on every way out. Off a
terminal (or with ``TERM=dumb``) the same choice is a numbered list read with one prompt.

The key handling is a pure function (``apply_key``) so its rules are tested without a terminal.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace

TITLE = (
    "Register treasure-map with these agents (detected ones are pre-selected — Space to unselect):"
)
FOOTER = "↑↓ / Tab move · Space toggle · a all · n none · Enter confirm"


class SelectionAbortedError(Exception):
    """Ctrl-C in the selector: nothing is changed."""


@dataclass(frozen=True)
class SelectState:
    checked: tuple[bool, ...]
    cursor: int = 0
    done: bool = False


UP, DOWN, TAB, BACKTAB, SPACE, ENTER, ALL, NONE, ABORT = (
    "up",
    "down",
    "tab",
    "backtab",
    "space",
    "enter",
    "all",
    "none",
    "abort",
)


def apply_key(state: SelectState, key: str) -> SelectState:
    n = len(state.checked)
    if key == ABORT:
        raise SelectionAbortedError
    if key == ENTER:
        return replace(state, done=True)  # submits; never toggles
    if n == 0:
        return state
    if key in (DOWN, TAB):
        return replace(state, cursor=(state.cursor + 1) % n)
    if key in (UP, BACKTAB):
        return replace(state, cursor=(state.cursor - 1) % n)
    if key == SPACE:
        flipped = list(state.checked)
        flipped[state.cursor] = not flipped[state.cursor]
        return replace(state, checked=tuple(flipped))
    if key == ALL:
        return replace(state, checked=(True,) * n)
    if key == NONE:
        return replace(state, checked=(False,) * n)
    return state


def decode_key(seq: bytes) -> str | None:
    """A raw keypress (or escape sequence) as a key name."""
    table = {
        b"\x1b[A": UP,
        b"\x1bOA": UP,
        b"\x1b[B": DOWN,
        b"\x1bOB": DOWN,
        b"\t": TAB,
        b"\x1b[Z": BACKTAB,
        b" ": SPACE,
        b"\r": ENTER,
        b"\n": ENTER,
        b"a": ALL,
        b"n": NONE,
        b"\x03": ABORT,
    }
    return table.get(seq)


def _render(labels: Sequence[str], state: SelectState) -> str:
    lines = [TITLE]
    for i, label in enumerate(labels):
        mark = "x" if state.checked[i] else " "
        pointer = ">" if i == state.cursor else " "
        lines.append(f" {pointer} [{mark}] {label}")
    lines.append(FOOTER)
    return "\r\n".join(lines) + "\r\n"


def _read_key(fd: int) -> bytes:
    first = os.read(fd, 1)
    if first != b"\x1b":
        return first
    seq = first + os.read(fd, 1)
    if seq[-1:] in (b"[", b"O"):
        seq += os.read(fd, 1)
    return seq


def _tty_select(labels: Sequence[str], preselected: Sequence[bool]) -> list[bool]:
    import termios
    import tty

    fd = sys.stdin.fileno()
    saved = termios.tcgetattr(fd)
    state = SelectState(tuple(preselected))
    out = sys.stderr
    drawn = 0
    try:
        tty.setraw(fd)
        while True:
            if drawn:
                out.write(f"\x1b[{drawn}A\x1b[J")
            text = _render(labels, state)
            out.write(text)
            out.flush()
            drawn = text.count("\r\n")
            key = decode_key(_read_key(fd))
            if key is None:
                continue
            state = apply_key(state, key)
            if state.done:
                return list(state.checked)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)


def parse_toggles(answer: str, n: int) -> list[int] | None:
    """``"1,3"`` -> [0, 2]; None when the answer is not a list of numbers in range."""
    picks: list[int] = []
    for part in answer.replace(" ", ",").split(","):
        if not part:
            continue
        if not part.isdigit() or not 1 <= int(part) <= n:
            return None
        picks.append(int(part) - 1)
    return picks


def _fallback_select(
    labels: Sequence[str],
    preselected: Sequence[bool],
    prompt: Callable[[str], str],
    echo: Callable[[str], None],
) -> list[bool]:
    checked = list(preselected)
    echo(TITLE)
    for i, label in enumerate(labels, 1):
        echo(f"  {i}. [{'x' if checked[i - 1] else ' '}] {label}")
    for _ in range(2):
        picks = parse_toggles(
            prompt("Toggle by number (e.g. 1,3), Enter to confirm").strip(), len(labels)
        )
        if picks is not None:
            for i in picks:
                checked[i] = not checked[i]
            return checked
        echo("  Numbers from the list, separated by commas.")
    return checked


def can_use_tty() -> bool:
    return sys.stdin.isatty() and sys.stderr.isatty() and os.environ.get("TERM", "dumb") != "dumb"


def select(
    labels: Sequence[str],
    preselected: Sequence[bool],
    *,
    prompt: Callable[[str], str],
    echo: Callable[[str], None],
    use_tty: bool | None = None,
) -> list[bool]:
    """The user's choice, one bool per label. Raises SelectionAbortedError on Ctrl-C."""
    if not labels:
        return []
    if use_tty if use_tty is not None else can_use_tty():
        return _tty_select(labels, preselected)
    return _fallback_select(labels, preselected, prompt, echo)
