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

# Blind-read whitelist (G): the ONLY tools whose answer is proven free of any judgement — no
# verdict, review_state, verdict_shape or annotation block — so having called one keeps a shadow
# judgement blind. FAIL-CLOSED: every other tool, including list_overlays, the verdict-carrying
# views (get_diff_patch_view, get_diff_sink_overlay, list_diffs), start_diff_review's pair overview,
# and any tool not listed here (new ones included), makes a shadow NOT blind. A blocklist could not
# say this and could not tell apart the two calls below, which turn on a parameter. The members are
# proven leak-free by tests/unit/lib/test_read_basis.py; adding one without that proof is a bug.
BLIND_SAFE_TOOLS = frozenset(
    {
        "get_pseudocode",
        "get_disassembly",
        "get_callees",
        "get_xrefs",
        "get_strings",
        "get_data_bytes",
        "get_data_table",
        "get_sink_provenance",
        "get_imports_exports",
        "get_function_alignment",
        "get_functions_referencing_string",
        "get_string_reference_anchors",
        "get_string_keyed_edges",
        "get_nvram_key_flow",
        "get_script_callsites",
        "launched_by",
        "pattern_density",
        "cross_firmware_patterns",
        "same_shape_siblings",
        "get_diff_meta",
        "get_diff_deltas",
        "get_diff_string_delta",
        "list_runs",
        "legal_notice",
        "get_tool_reference",
    }
)
# Kept for callers that still name it (the blocklist is now the whitelist's complement).
VERDICT_READERS = frozenset({"list_overlays"})


def _blind_safe(line: dict[str, Any]) -> bool:
    """Whether one logged call keeps a shadow blind. Two tools turn on a parameter:
    start_diff_review is safe only when it names a ``unit`` (that unit's material, the verdict
    hidden) and not for the pair overview (which carries review_state and the annotation block);
    list_candidates is never safe with ``overlay`` true (it then shows the scan's own verdicts)."""
    tool = line.get("tool")
    params = line.get("params") or {}
    if tool == "start_diff_review":
        return params.get("unit") is not None
    if tool == "list_candidates":
        return not params.get("overlay")
    return tool in BLIND_SAFE_TOOLS


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
    audits nor read anything that carries a verdict before. Without a log it cannot be shown blind.
    FAIL-CLOSED: blind only when EVERY call the session made is on the blind-read whitelist
    (:func:`_blind_safe`); one call to anything else — list_overlays, a verdict-carrying view, or
    any unlisted tool — makes it not blind."""
    if lines is None or session is None:
        return False
    if write_session is not None and write_session == session:
        return False
    return all(_blind_safe(ln) for ln in lines)
