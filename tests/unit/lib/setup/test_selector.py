# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The agent checkbox list: detected agents pre-selected, Space toggles, Enter submits and never
toggles."""

from __future__ import annotations

import pytest

from treasure_map.lib.setup import selector as sel


def _run(pre: tuple[bool, ...], keys: list[str]) -> sel.SelectState:
    state = sel.SelectState(pre)
    for k in keys:
        state = sel.apply_key(state, k)
    return state


def test_enter_submits_without_toggling() -> None:
    """★ MUTATION: let Enter toggle the item under the cursor -> RED."""
    state = _run((True, False, True), [sel.ENTER])
    assert state.done and state.checked == (True, False, True)


def test_space_toggles_and_tab_moves_like_down() -> None:
    state = _run((True, False, False), [sel.SPACE, sel.TAB, sel.SPACE, sel.DOWN, sel.UP, sel.ENTER])
    assert state.checked == (False, True, False) and state.cursor == 1
    assert _run((False,) * 3, [sel.TAB]).cursor == _run((False,) * 3, [sel.DOWN]).cursor == 1
    assert _run((False,) * 3, [sel.BACKTAB]).cursor == 2
    assert _run((False, True), [sel.ALL]).checked == (True, True)
    assert _run((False, True), [sel.NONE]).checked == (False, False)


def test_keys_decode() -> None:
    assert sel.decode_key(b"\x1b[A") == sel.UP
    assert sel.decode_key(b"\x1b[Z") == sel.BACKTAB
    assert sel.decode_key(b"\r") == sel.ENTER
    assert sel.decode_key(b" ") == sel.SPACE
    assert sel.decode_key(b"\x03") == sel.ABORT


def test_ctrl_c_aborts() -> None:
    with pytest.raises(sel.SelectionAbortedError):
        _run((True,), [sel.ABORT])


def test_the_fallback_keeps_the_preselection_on_enter() -> None:
    picks = sel.select(
        ["A", "B", "C"],
        [True, False, True],
        prompt=lambda _m: "",
        echo=lambda _m: None,
        use_tty=False,
    )
    assert picks == [True, False, True]
    picks = sel.select(
        ["A", "B", "C"],
        [True, False, True],
        prompt=lambda _m: "1,2",
        echo=lambda _m: None,
        use_tty=False,
    )
    assert picks == [False, True, True]
