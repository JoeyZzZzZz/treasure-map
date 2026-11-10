# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""What was read before a judgement was written, inferred from the tool-call log (lib/tool_call_log)
of the writing server's session — recorded with the write in overlay_history as ``read_basis``.

``basis`` is one of:

* ``unit_delivered`` — this session was handed the unit's material before the write (by
  start_diff_review, or a write's answer naming the next unit with it; a unit named without its
  material is not handed out) and that material showed the written subject whole: a material that
  lists members (a batch, a callee group, a reduce, a one-sided binary's functions) shows only the
  members it kept, a one-subject material (an entry, a file) shows its subject unless it was cut.
  Otherwise the delivery counts only once the subject ITSELF was fetched after it (then
  ``material_cut``); fetching another member does not read this one. The unit is the one the write
  names; a write that names none is read against the units this session was handed that hold its
  subject, and then carries ``unit_inferred``.
* ``fetched`` — this session read the subject itself before the write: the entry in full
  (get_diff_patch_view with its entry_id), a side's pseudocode, disassembly or callees, a file's
  difference (get_file_diff with its path).
  A one-sided binary's function is read by explain_candidate on every one of its candidates
  (``candidates``, the evidence_refs it must cite).
* ``none`` — the log holds nothing of the kind. On a must-read subject the caller marks it
  ``unread_before_verdict``: the subject reads needs_recheck (not disposed) until a judgement
  written after reading it.
* ``unknown`` — there is no log, or no session to read it by: nothing can be said either way.

``rows_partial`` (with ``unit_delivered`` or ``fetched``): the subject is an entry whose candidate
rows this session read only part of — the windows its unit's material and its own reads held
(``unit_rows`` / ``rows_read`` in the log) leave some of its ``rows_total`` out, or it was read by
entry id with no window logged at all (fail-closed). The judgement still counts as disposed; the
report counts it under ``basis_incomplete``.

``read_partial`` (with ``unit_delivered`` or ``fetched``, when the read that made it count was of
the subject itself — a function's pseudocode, disassembly or callees, a file's line difference,
an entry by its entry_id): ``"pages"`` — no one read of its code (one tool, one function or file,
one run) was read whole: the windows its pages held (``page_rows`` in the log) leave part of its
total unread, read by coverage, not by which page came last (the last page alone is not the
whole), and a read of it that logged no window at all counts as partial (FAIL-CLOSED, as
``rows_partial``). The code is a function's pseudocode or disassembly (or a file's difference):
where any of those was read, a callee list read whole does not make it whole (every pseudocode
page carries the callees already). An entry read by its entry_id reads the code whole only when
it showed the code difference whole (``code_shown`` true in the log: its inline hunk not held
back, a layout-only delta, two texts that match — an undetermined pair's read from its
``proposed_pair_reading``); otherwise the code's own reads decide. With no
read of the code at all, an entry that held its hunk back (``code_shown`` false) is ``"pages"``,
and one that carried no hunk either way is read as the entry it is (no flag).
``"extraction_cap"`` — only a callee list was read, whole as the scan stored it but cut short
there (``callees_truncated``): reading on cannot complete it; a whole read of the code does.
Like ``rows_partial``, the judgement still counts as disposed and the report counts it under
``basis_incomplete``; a later judgement written after a whole read clears it. ``rows_partial``
stays about an entry's candidate rows only; the two can stand together (an entry whose rows and
whose code were both read in part).

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
from treasure_map.lib.tool_call_log import PAGE_PARAMS

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
# A read of the callee list alone: no part of the code itself.
_CALLEES = "get_callees"
_HEX = re.compile(r"(?<![0-9A-Za-z])(?:0x)?([0-9a-fA-F]{4,})(?![0-9A-Za-z])")


def session_lines(log: tcl.ToolCallLog | None) -> list[dict[str, Any]] | None:
    """This server session's lines of its log, oldest first; None when there is no log."""
    if log is None:
        return None
    lines = tcl.read_lines(log.path)
    if lines is None:
        return None
    return [ln for ln in lines if ln.get("session") == log.session.id]


def session_tally(lines: list[dict[str, Any]] | None) -> dict[str, int] | None:
    """What this session has been handed so far, from its log lines (``session_lines``; a call's
    line is written once it has answered, so the answer being put together is not in them): the
    distinct work units handed out with their material, and the bytes of every answer. None when
    there is no log."""
    if lines is None:
        return None
    units = {ln["unit"] for ln in lines if isinstance(ln.get("unit"), str)}
    sent = sum(n for ln in lines if isinstance(n := ln.get("response_bytes"), int))
    return {"units_handed": len(units), "response_bytes": sent}


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


def _stream(line: dict[str, Any]) -> tuple[Any, ...]:
    """What one paged read is a page OF: the tool, the function (normalised) or file, and the run /
    binary it was asked in — pages of the same stream add up, other streams do not."""
    params = line.get("params") or {}
    subject = (
        params.get("path")
        if line.get("tool") == "get_file_diff"
        else _norm_addr(params.get("function"))
    )
    return (line.get("tool"), subject, params.get("run_id"), params.get("binary"))


def _read_partial(lines: list[dict[str, Any]], anchor_ref: str, entry_id: str | None) -> str | None:
    """Whether the reads of the subject itself in ``lines`` read its code only in part (see
    ``read_partial`` in the module docstring): None when an entry read showed its code difference
    whole, or one read of the code — one stream of pages — covers its whole total (with no read of
    the code, one whole callee list not cut by the scan); ``"extraction_cap"`` when only callee
    lists were read and the whole one is cut short by the scan; else ``"pages"`` (FAIL-CLOSED: a
    stream with no window logged covers nothing; an entry that held its hunk back read none of the
    code)."""
    hits = [ln for ln in lines if _fetched(ln, anchor_ref, entry_id)]
    if not hits:
        return None
    entries = [ln for ln in hits if ln.get("tool") == "get_diff_patch_view"]
    if any(ln.get("code_shown") is True for ln in entries):
        return None
    held_back = any(ln.get("code_shown") is False for ln in entries)
    windows: dict[tuple[Any, ...], list[list[int]]] = {}
    capped: set[tuple[Any, ...]] = set()
    for ln in hits:
        if ln.get("tool") == "get_diff_patch_view":
            continue
        key = _stream(ln)
        ws = windows.setdefault(key, [])
        if _is_window(ln.get("page_rows")):
            ws.append(ln["page_rows"])
        if ln.get("extraction_cap"):
            capped.add(key)
    code = [key for key in windows if key[0] != _CALLEES]
    if code or held_back:
        # The code was read, or an entry held it back: only a whole read of the code is whole.
        return None if any(windows[k] and _covers(windows[k]) for k in code) else "pages"
    if not windows:
        return None  # read as an entry only, which carried no hunk either way
    whole = [key for key, ws in windows.items() if ws and _covers(ws)]
    if any(key not in capped for key in whole):
        return None
    return "extraction_cap" if whole else "pages"


def _covers(windows: list[list[int]]) -> bool:
    """Whether ``[start, end, total]`` windows, together, hold every item from 0 to the total."""
    total = max(w[2] for w in windows)
    reach = 0
    for start, end, _ in sorted(windows):
        if start > reach:
            break
        reach = max(reach, end)
    return reach >= total


def _explained_all(lines: list[dict[str, Any]], candidates: frozenset[str] | None) -> bool:
    """Whether ``lines`` hold an answered explain_candidate for every one of ``candidates`` (a
    one-sided binary's function: its candidates' evidence_refs); never for an empty or absent
    set."""
    if not candidates:
        return False
    read = {
        (ln.get("params") or {}).get("evidence_ref")
        for ln in lines
        if ln.get("tool") == "explain_candidate" and not ln.get("error")
    }
    return candidates <= read


def _rows_partial(
    lines: list[dict[str, Any]], anchor_ref: str, entry_id: str | None, delivered: list[int]
) -> bool:
    """Whether the row windows this session read of the entry (``unit_rows`` of the deliveries
    in ``delivered``, ``rows_read`` of its own reads) leave part of its candidate rows unread.
    False when nothing of it was read by entry id (nothing to say) or one window holds them all.
    FAIL-CLOSED: a read of it by entry id that logged no window says nothing of the rows it held,
    so with no window logged at all it counts as partial."""
    keys = {anchor_ref, entry_id} - {None}
    windows: list[list[int]] = []
    unlogged = False
    for i in delivered:
        rows = lines[i].get("unit_rows")
        if isinstance(rows, dict):
            windows.extend(w for k, w in rows.items() if k in keys and _is_window(w))
    for ln in lines:
        if ln.get("tool") != "get_diff_patch_view" or ln.get("error"):
            continue
        if (ln.get("params") or {}).get("entry_id") in keys:
            if _is_window(ln.get("rows_read")):
                windows.append(ln["rows_read"])
            else:
                unlogged = True
    if not windows:
        return unlogged
    return not _covers(windows)


def _is_window(value: Any) -> bool:
    return (
        isinstance(value, list)
        and len(value) == 3
        and all(isinstance(x, int) and not isinstance(x, bool) for x in value)
    )


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
    candidates: frozenset[str] | None = None,
) -> dict[str, Any]:
    """The read basis of one write of ``anchor_ref`` (see the module docstring). ``candidates``:
    the evidence_refs of a one-sided binary's function, read by explain_candidate on each."""
    if lines is None:
        return {"basis": "unknown", "why": "no tool-call log for this session"}
    if unit_id is not None:
        delivered = [i for i, ln in enumerate(lines) if ln.get("unit") == unit_id]
        if delivered:
            whole = any(_shown_whole(lines[i], anchor_ref, entry_id) for i in delivered)
            # Not shown whole by any delivery: it counts once the subject itself was fetched
            # after the first of them.
            after = lines[delivered[0] + 1 :]
            if (
                whole
                or any(_fetched(ln, anchor_ref, entry_id) for ln in after)
                or _explained_all(after, candidates)
            ):
                out: dict[str, Any] = {"basis": "unit_delivered", "material_cut": not whole}
                if not whole and _rows_partial(lines, anchor_ref, entry_id, delivered):
                    out["rows_partial"] = True
                if not whole and not _explained_all(after, candidates):
                    partial = _read_partial(after, anchor_ref, entry_id)
                    if partial is not None:
                        out["read_partial"] = partial
                return out
    if any(_fetched(ln, anchor_ref, entry_id) for ln in lines) or _explained_all(lines, candidates):
        got: dict[str, Any] = {"basis": "fetched"}
        if _rows_partial(lines, anchor_ref, entry_id, []):
            got["rows_partial"] = True
        if not _explained_all(lines, candidates):
            partial = _read_partial(lines, anchor_ref, entry_id)
            if partial is not None:
                got["read_partial"] = partial
        return got
    return {"basis": "none"}


# The evidence reads ``evidence_reads_cut`` counts: the fact tools about a subject that page their
# answer (not the reads of a subject itself, which the read basis weighs), and the diff's row
# overlay. A tool that takes no page parameter has no page to be left on; tests/unit/lib/
# test_read_basis_pages.py holds this set to the tools' own signatures.
PAGED_EVIDENCE_TOOLS = frozenset(
    {
        "cross_firmware_patterns",
        "get_data_table",
        "get_diff_deltas",
        "get_diff_sink_overlay",
        "get_diff_string_delta",
        "get_function_alignment",
        "get_functions_referencing_string",
        "get_imports_exports",
        "get_nvram_key_flow",
        "get_script_callsites",
        "get_sink_provenance",
        "get_string_keyed_edges",
        "get_string_reference_anchors",
        "get_strings",
        "get_xrefs",
        "launched_by",
        "pattern_density",
        "same_shape_siblings",
    }
)


def evidence_reads_cut(lines: list[dict[str, Any]] | None) -> dict[str, Any] | None:
    """How many of this session's evidence readings were left on a cut page: a reading is one
    paged fact tool's calls with the same arguments but for the page's own place (offset and the
    like) — read by the line's ``reading`` digest of every argument (a line logged before it, by
    its recorded parameters); it is left cut when every page of it this session read came back cut
    (a continuation, or cut to fit). A reading counts as read on once ANY page of it came back
    uncut — the last page alone included, though it leaves the pages before it unread: this counts
    readings stopped on a cut page, not readings read whole. Counted per session, never per pair or
    subject: a log line names no run pair. None when there is no log (unknown, never 0)."""
    if lines is None:
        return None
    readings: dict[tuple[Any, ...], bool] = {}
    for ln in lines:
        tool = ln.get("tool")
        if tool not in PAGED_EVIDENCE_TOOLS or ln.get("error"):
            continue
        digest = ln.get("reading")
        if isinstance(digest, str):
            key: tuple[Any, ...] = (tool, digest)
        else:
            params = ln.get("params") or {}
            key = (tool, *sorted((k, str(v)) for k, v in params.items() if k not in PAGE_PARAMS))
        readings[key] = readings.get(key, True) and bool(ln.get("truncated"))
    return {
        "count": sum(1 for cut in readings.values() if cut),
        "readings": len(readings),
        "scope": (
            "this server session's paged fact-tool readings stopped on a cut page (a reading is "
            "read on once any page of it came back uncut — the last page alone too, so this is "
            "not a count of readings read whole); a log line names no run pair, so this is per "
            "session"
        ),
    }


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
