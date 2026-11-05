# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""What was read before a judgement was written, inferred from the tool-call log (lib/tool_call_log)
of the writing server's session — recorded with the write in overlay_history as ``read_basis``.

``basis`` is one of:

* ``unit_delivered`` — this session was handed the unit's material before the write (by
  start_diff_review, or a write's answer naming the next unit with it; a unit named without its
  material is not handed out) and that material showed the written subject whole: a material that
  lists members (a batch, a callee group, a reduce) shows only the members it kept, a one-subject
  material (an entry, a binary's first candidates, a file) shows its subject unless it was cut.
  Otherwise the delivery counts only once the subject ITSELF was fetched after it (then
  ``material_cut``); fetching another member does not read this one. The unit is the one the write
  names; a write that names none is read against the units this session was handed that hold its
  subject, and then carries ``unit_inferred``.
* ``fetched`` — this session read the subject itself before the write: the entry in full
  (get_diff_patch_view with its entry_id), a side's pseudocode, disassembly or callees, a file's
  difference (get_file_diff with its path).
* ``none`` — the log holds nothing of the kind. On a must-read subject the caller marks it
  ``unread_before_verdict``: the subject reads needs_recheck (not disposed) until a judgement
  written after reading it.
* ``unknown`` — there is no log, or no session to read it by: nothing can be said either way.

LIMIT, stated wherever this is reported: a subagent shares its parent's MCP connection, so in
serial use "the same session" is the same window, not the same context — there ``unit_delivered``
is a floor, not proof the deciding context read it. Only where each unit runs in a process of its
own (the batch driver) does it stand for that context. A person's channels are not inferred from
the log at all (``basis`` ``human``).
"""

from __future__ import annotations

import re
from typing import Any

from treasure_map.lib import tool_call_log as tcl

# Blind-read whitelist (G): the ONLY tools whose answer does not change with the verdicts recorded
# — no verdict, review_state, verdict_shape or annotation block; a count of what is judged or not
# is allowed — so having called one keeps a shadow judgement blind. FAIL-CLOSED: every other tool,
# including list_overlays, list_candidates (even with overlay off it carries coverage,
# in_exploit_ledger and verdict_shape), the verdict-carrying views (get_diff_patch_view,
# get_diff_sink_overlay, list_diffs), start_diff_review except reading the audit unit itself, and
# any tool not listed here (new ones included), makes a shadow NOT blind. The members are proven
# by tests/unit/lib/test_blind_whitelist.py: each one's answer is the same, byte for byte, in two
# worlds that differ only in the verdicts; adding one without a call there fails that test.
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


def _blind_safe(line: dict[str, Any], audit_unit: str | None) -> bool:
    """Whether one logged call keeps a shadow blind. start_diff_review turns on what it read: only
    a call naming ``audit_unit`` itself (that unit's material, the verdict hidden), whose answer
    handed that same unit out, is safe — any other unit, or the pair overview, carries
    review_state and the annotation block."""
    tool = line.get("tool")
    if tool == "start_diff_review":
        params = line.get("params") or {}
        return (
            audit_unit is not None
            and params.get("unit") == audit_unit
            and line.get("unit") == audit_unit
        )
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


def _shown_whole(line: dict[str, Any], anchor_ref: str, entry_id: str | None) -> bool:
    """Whether one delivery of a unit showed this subject whole: listed among the members its
    material kept, or — a one-subject material, which logs no member list — not cut."""
    whole = line.get("unit_whole")
    if isinstance(whole, list):
        return anchor_ref in whole or (entry_id is not None and entry_id in whole)
    return not line.get("unit_material_cut")


def infer(
    lines: list[dict[str, Any]] | None,
    *,
    anchor_ref: str,
    entry_id: str | None = None,
    unit_id: str | None = None,
) -> dict[str, Any]:
    """The read basis of one write of ``anchor_ref`` (see the module docstring)."""
    if lines is None:
        return {"basis": "unknown", "why": "no tool-call log for this session"}
    if unit_id is not None:
        delivered = [i for i, ln in enumerate(lines) if ln.get("unit") == unit_id]
        if delivered:
            whole = any(_shown_whole(lines[i], anchor_ref, entry_id) for i in delivered)
            # Not shown whole by any delivery: it counts once the subject itself was fetched
            # after the first of them.
            if whole or any(_fetched(ln, anchor_ref, entry_id) for ln in lines[delivered[0] + 1 :]):
                return {"basis": "unit_delivered", "material_cut": not whole}
    if any(_fetched(ln, anchor_ref, entry_id) for ln in lines):
        return {"basis": "fetched"}
    return {"basis": "none"}


def blind(
    lines: list[dict[str, Any]] | None,
    write_session: str | None,
    session: str | None,
    audit_unit: str | None,
) -> bool:
    """Whether a shadow judgement on ``audit_unit`` written now is blind: its session wrote
    neither the judgement it audits nor read anything that carries a verdict before. Without a log
    it cannot be shown blind, nor when the log holds no delivery of ``audit_unit`` (the shadow
    then rests on nothing read blind). FAIL-CLOSED: blind only when EVERY call the session made is
    on the blind-read whitelist (:func:`_blind_safe`); one call to anything else — list_overlays,
    a verdict-carrying view, another unit, or any unlisted tool — makes it not blind."""
    if lines is None or session is None or audit_unit is None:
        return False
    if write_session is not None and write_session == session:
        return False
    if not any(
        ln.get("tool") == "start_diff_review" and ln.get("unit") == audit_unit for ln in lines
    ):
        return False
    return all(_blind_safe(ln, audit_unit) for ln in lines)
