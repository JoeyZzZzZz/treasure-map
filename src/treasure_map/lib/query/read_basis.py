# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""What was read before a judgement was written, inferred from the tool-call log (lib/tool_call_log)
of the writing server's session — recorded with the write in overlay_history as ``read_basis``.

``basis`` is one of:

* ``unit_delivered`` — the write names its work unit, and this session was handed that unit's
  material (by start_diff_review) before it; when that material was cut, something of the unit was
  also fetched after it.
* ``fetched`` — this session read the subject itself before the write: the entry in full
  (get_diff_patch_view with its entry_id), a side's pseudocode, disassembly or callees, a file's
  difference (get_file_diff with its path).
* ``none`` — the log holds nothing of the kind. On a must-read subject the caller marks it
  ``unread_before_verdict``, which opens an audit.
* ``unknown`` — there is no log, or no session to read it by: nothing can be said either way.

LIMIT, stated wherever this is reported: a subagent shares its parent's MCP connection, so in
serial use "the same session" is the same window, not the same context — there ``unit_delivered``
is a floor, not proof the deciding context read it. Only where each unit runs in a process of its
own (the batch driver) does it stand for that context. A person's channels are not inferred from
the log at all (``basis`` ``human``).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from treasure_map.lib import tool_call_log as tcl

# Tools whose answer carries the judgements themselves: having called one makes a shadow
# judgement not blind.
VERDICT_READERS = frozenset({"list_overlays"})
_FETCH_BY_FUNCTION = frozenset({"get_pseudocode", "get_disassembly", "get_callees"})
_HEX = re.compile(r"(?<![0-9A-Za-z])(?:0x)?([0-9a-fA-F]{4,})(?![0-9A-Za-z])")


def session_lines(log: tcl.ToolCallLog | None) -> list[dict[str, Any]] | None:
    """This server session's lines of its log, oldest first; None when there is no log."""
    if log is None:
        return None
    lines = tcl.read_lines(log.path)
    if lines is None:
        return None
    return [ln for ln in lines if ln.get("session") == log.session.id]


def _addrs(anchor_ref: str) -> set[str]:
    key = anchor_ref.split("#", 2)[-1]
    return {m.group(1).lower().lstrip("0") or "0" for m in _HEX.finditer(key.split("::", 1)[-1])}


def _norm_addr(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    m = _HEX.fullmatch(value.strip())
    return (m.group(1).lower().lstrip("0") or "0") if m else None


def _fetched(line: dict[str, Any], anchor_ref: str, entry_id: str | None) -> bool:
    tool, params = line.get("tool"), line.get("params") or {}
    if line.get("error"):
        return False
    if tool == "get_diff_patch_view":
        return params.get("entry_id") in {anchor_ref, entry_id} - {None}
    if tool == "get_file_diff" and "#non_binary#" in anchor_ref:
        return params.get("path") == anchor_ref.split("#non_binary#", 1)[1]
    if tool in _FETCH_BY_FUNCTION and "#function_" in anchor_ref:
        fn = _norm_addr(params.get("function"))
        return fn is not None and fn in _addrs(anchor_ref)
    return False


def infer(
    lines: list[dict[str, Any]] | None,
    *,
    anchor_ref: str,
    entry_id: str | None = None,
    unit_id: str | None = None,
    unit_anchors: Iterable[tuple[str, str | None]] = (),
) -> dict[str, Any]:
    """The read basis of one write (see the module docstring). ``unit_anchors`` are the unit's
    members (anchor, entry_id): after a cut delivery, a fetch of any of them counts as reading
    on."""
    if lines is None:
        return {"basis": "unknown", "why": "no tool-call log for this session"}
    members = list(unit_anchors) or [(anchor_ref, entry_id)]
    if unit_id is not None:
        delivered = [i for i, ln in enumerate(lines) if ln.get("unit") == unit_id]
        if delivered:
            # Every delivery cut (none whole): it counts once something of the unit was fetched
            # after the first of them.
            always_cut = all(lines[i].get("unit_material_cut") for i in delivered)
            read_on = any(
                _fetched(ln, a, e) for ln in lines[delivered[0] + 1 :] for a, e in members
            )
            if not always_cut or read_on:
                return {"basis": "unit_delivered", "material_cut": always_cut}
    if any(_fetched(ln, anchor_ref, entry_id) for ln in lines):
        return {"basis": "fetched"}
    return {"basis": "none"}


def blind(
    lines: list[dict[str, Any]] | None, write_session: str | None, session: str | None
) -> bool:
    """Whether a shadow judgement written now is blind: its session wrote neither the judgement it
    audits nor read the overlay's verdicts before. Without a log it cannot be shown blind."""
    if lines is None or session is None:
        return False
    if write_session is not None and write_session == session:
        return False
    return not any(ln.get("tool") in VERDICT_READERS for ln in lines)
