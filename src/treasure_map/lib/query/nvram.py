# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Read-side nvram key-flow query over the atlas nvram_key_flow table (gap② phase 2).

The table holds per-op nvram read/write facts flattened at hunt time; this reader assembles the
key GRAPH on read — "who writes / who reads this key" across binaries — with a three-tier honesty
contract so the agent never over-trusts a connection:

  exact     — key_kind='constant' AND key == the requested key. A concrete nvram string key is the
              same key everywhere it appears, so these connect exactly. Returned as writers/readers.
  template  — key_kind='parametric' whose printf/strcpy TEMPLATE (wl%d_ssid) the requested concrete
              key satisfies. A POSSIBLE match (the %d is unproven), surfaced SEPARATELY as
              template_matches and flagged match='template' — never folded into the exact set.
  unresolved— key_kind='unresolved' (key came from a caller; key is NULL). These could touch ANY
              key, so they are NEVER attributed to a concrete key here. They are not silently
              dropped: their presence sets completeness='may_be_incomplete' with an explicit note,
              so the agent knows this key's writers/readers may be incomplete.

Every entry carries binary + func + source_run_id so a cross-firmware atlas stays legible (the same
key name in two firmware runs is two device instances, tagged distinctly — the reader states facts,
it does not assert one firmware's writer feeds another's reader). A surfaced fact, never a verdict.
"""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

# One printf conversion specifier: flags, width, precision, length modifier, then the conversion
# char. Mirrors a subset of the C format grammar sufficient for nvram key templates.
_SPEC_RE = re.compile(r"%[-+ 0#]*\d*(?:\.\d+)?[hljztL]*([diouxXscp%])")

# Minimum count of fixed (non-specifier) characters a parametric template must carry to be a
# MEANINGFUL key pattern. Below this a "template" is only placeholders (%s, %s%s) or an opaque
# strcpy-built marker — it regex-matches ANY key, which is really "key completely unknown", not a
# known pattern. Such templates are treated as unresolved (see template_has_anchor).
_MIN_TEMPLATE_ANCHOR = 2


def template_has_anchor(template: str) -> bool:
    """True when a parametric template has a fixed-literal anchor (>= _MIN_TEMPLATE_ANCHOR
    non-specifier, non-space chars), so it can meaningfully constrain which concrete keys match.

    A template that is only conversion specifiers (``%s``, ``%s%s``) or an opaque strcpy-built
    marker (``<built:...>``) matches any string — it carries NO information about the key, so it is
    really "key completely unknown" and must be classified unresolved, never surfaced as a
    parametric that silently matches an arbitrary key (the honesty red line). ``wl%d_ssid`` keeps
    its ``wl``/``_ssid`` anchor and stays a real template.
    """
    if not isinstance(template, str) or "<built:" in template:
        return False
    fixed = _SPEC_RE.sub("", template)  # drop every %-specifier, leaving only the literal parts
    fixed = "".join(ch for ch in fixed if not ch.isspace())
    return len(fixed) >= _MIN_TEMPLATE_ANCHOR


def _template_to_regex(template: str) -> str | None:
    """Convert a printf-style nvram key template to a full-match regex, or None if it cannot be
    matched safely (an unknown specifier or the opaque ``<built:...>`` writer marker). Returning
    None means "cannot decide" — the honest choice is no match, never a coerced one.
    """
    if "<built:" in template:  # opaque strcpy-built key: not a decidable template
        return None
    out: list[str] = []
    i = 0
    n = len(template)
    while i < n:
        ch = template[i]
        if ch != "%":
            out.append(re.escape(ch))
            i += 1
            continue
        m = _SPEC_RE.match(template, i)
        if m is None:
            return None  # malformed / unsupported specifier -> cannot match safely
        conv = m.group(1)
        if conv == "%":
            out.append(re.escape("%"))
        elif conv in "diou":  # integer index (nvram indices) -> digits
            out.append(r"\d+")
        elif conv in "xX":  # hex
            out.append(r"[0-9a-fA-F]+")
        elif conv in "sp":  # string / pointer token -> any non-empty run
            out.append(r".+")
        elif conv == "c":  # single char
            out.append(r".")
        else:  # pragma: no cover - _SPEC_RE cannot capture other chars
            return None
        i = m.end()
    return "".join(out)


def _template_matches(template: str, key: str) -> bool:
    """True when a concrete key satisfies a parametric template (a possible, not exact, match).

    Defense-in-depth: an anchorless template (%s, %s%s, <built:*>) never matches — even if a stale
    row stored one as parametric (fresh hunts reclassify these to unresolved at flatten time)."""
    if not template_has_anchor(template):
        return False
    regex = _template_to_regex(template)
    if regex is None:
        return False
    try:
        return re.fullmatch(regex, key) is not None
    except re.error:  # pragma: no cover - regex is machine-built from a small grammar
        return False


def _parse_value_source(raw: str | None) -> dict[str, Any] | None:
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def _entry(row: sqlite3.Row) -> dict[str, Any]:
    """One writer/reader entry: where the op lives + the write value source (controllability)."""
    entry: dict[str, Any] = {
        "binary": row["binary"],
        "func": row["func"],
        "api": row["api"],
        "op": row["op"],
        "source_run_id": row["source_run_id"],
    }
    via = row["via_wrapper"]
    if via:
        # A2: an INDIRECT edge — the key was a literal at a thin-nvram-wrapper call site, resolved
        # one hop. func is the CALLER; it reads/writes the key THROUGH via_wrapper. Flagged so a
        # consumer never mistakes a one-hop indirect access for a direct call.
        entry["via_wrapper"] = via
        entry["indirect"] = True
    if row["op"] == "write":
        # value_source is the write-side controllability signal (param/call_return/constant/...).
        # For an indirect (via_wrapper) write the value lives inside the wrapper and is not resolved
        # here, so value_source is None — not a claim of "no source".
        entry["value_source"] = _parse_value_source(row["value_source"])
    return entry


# The standing coverage boundary of the key graph, stated on EVERY result so a consumer can never
# read an empty writers/readers list as "confirmed no one touches this key". The extractor only
# recognizes a DIRECT nvram_get/set call with a literal key; a key reached through a business
# wrapper (a helper that internally calls nvram_get/set and forwards a caller-supplied key) is NOT
# captured yet, and a dynamically-built key is a separate blind spot. This is the honesty red line
# a real audit exposed: a key showed empty readers while a wrapper read it into a shell command
# sink. Absence here means "no DIRECT call found", never "unused".
COVERAGE_NOTE = (
    "This key graph captures DIRECT nvram_get/set calls with a literal key, PLUS one-hop "
    "wrapper-indirect edges where the key was a literal at a thin-nvram-wrapper call site (each "
    "such edge is flagged via_wrapper). NOT captured: a wrapper key forwarded from the caller's "
    "own parameter (non-literal), deeper multi-hop wrapper nesting, and dynamic keys. Empty "
    "writers/readers means no such edge was found — it does NOT mean the key is unused; a "
    "non-literal or deeper wrapper path may still read or write it."
)


def _web_settable(conn: sqlite3.Connection, key: str) -> dict[str, Any]:
    """Source-side writability: is ``key`` in the router_defaults web-settable-key table?

    THREE-STATE, with a false-negative red line — ``in_router_defaults`` is:
      True       — the key IS a located member (confirmed web-settable via the config apply path).
      False      — the table was located AND complete AND the key is not a member.
      "uncertain"— the table was NOT located in this atlas, OR it was located but parse incomplete
                   (the key could be an unresolved member). Table-not-located is NEVER False:
                   inability to locate the table is not proof the key is not settable.
    A surfaced fact only (in-table + default + flags); any judgement drawn from it is the agent's.
    """
    try:
        located = conn.execute("SELECT 1 FROM nvram_defaults LIMIT 1").fetchone() is not None
    except sqlite3.OperationalError:
        located = False  # table absent (older atlas) -> unknown, never "not settable"
    if not located:
        return {
            "in_router_defaults": "uncertain",
            "reason": "router_defaults table not located in this atlas — web-settability is "
            "unknown, NOT 'not settable' (a false-negative would be a red-line violation)",
        }
    hit = conn.execute(
        "SELECT default_value, flags, binary FROM nvram_defaults WHERE key = ? "
        "ORDER BY binary LIMIT 1",
        (key,),
    ).fetchone()
    if hit is not None:
        return {
            "in_router_defaults": True,
            "default_value": hit["default_value"],
            "flags": hit["flags"],
            "source": f"{hit['binary'] or 'libshared'} router_defaults",
        }
    incomplete = (
        conn.execute("SELECT 1 FROM nvram_defaults WHERE key IS NULL LIMIT 1").fetchone()
        is not None
    )
    if incomplete:
        return {
            "in_router_defaults": "uncertain",
            "reason": "router_defaults located but parse is incomplete (some members unresolved) — "
            "this key could be an unparsed member",
        }
    return {"in_router_defaults": False, "source": "router_defaults (located, complete)"}


def get_nvram_key_flow(conn: sqlite3.Connection, key: str) -> dict[str, Any]:
    """Assemble the cross-binary read/write graph for one concrete nvram key.

    Returns exact writers/readers (constant key match) and a separate flagged template_matches list
    (parametric templates the key satisfies). ``found`` is False only when nothing — exact or
    template — DIRECTLY references the key. Every result carries ``coverage`` (the standing
    boundary: direct calls only, wrapper-indirect not captured) and ``notes`` (the specific blind
    spots that apply). ``completeness`` is never a bare "complete": empty writers/readers or
    unresolved keys make it ``may_be_incomplete``, and even a populated graph is ``direct_only``
    because wrapper-indirect access is not resolved. Absence is NEVER "the key is unused". A fact,
    never a verdict.
    """
    exact_rows = conn.execute(
        "SELECT source_run_id, key, key_kind, binary, func, op, value_source, api, via_wrapper "
        "FROM nvram_key_flow WHERE key_kind = 'constant' AND key = ? "
        "ORDER BY binary, func",
        (key,),
    ).fetchall()
    writers = [_entry(r) for r in exact_rows if r["op"] == "write"]
    readers = [_entry(r) for r in exact_rows if r["op"] == "read"]

    param_rows = conn.execute(
        "SELECT source_run_id, key, key_kind, binary, func, op, value_source, api, via_wrapper "
        "FROM nvram_key_flow WHERE key_kind = 'parametric' AND key IS NOT NULL "
        "ORDER BY binary, func"
    ).fetchall()
    template_matches = [
        {**_entry(r), "template": r["key"], "match": "template"}
        for r in param_rows
        if _template_matches(r["key"], key)
    ]

    unresolved_count = int(
        conn.execute(
            "SELECT COUNT(*) FROM nvram_key_flow WHERE key_kind = 'unresolved'"
        ).fetchone()[0]
    )

    # match reflects the ACTUAL match state, never an unconditional "exact": a concrete (constant)
    # writer/reader is an exact connection; only template hits is a flagged possible match; neither
    # is "none" (found is False).
    if writers or readers:
        match_state = "exact"
    elif template_matches:
        match_state = "template"
    else:
        match_state = "none"
    # Honest incompleteness — two DISTINCT blind spots, never conflated into one cause:
    #  (1) wrapper-indirect: an empty writers/readers side is "no DIRECT call found", not proof of
    #      no consumer — a wrapper reading/writing this key is invisible to the extractor.
    #  (2) dynamic key: unresolved/dynamically-built keys could touch any key.
    notes: list[str] = []
    missing = [side for side, rows in (("writers", writers), ("readers", readers)) if not rows]
    if missing:
        notes.append(
            f"empty {' and '.join(missing)}: no DIRECT nvram_get/set(literal) call and no one-hop "
            "constant-key wrapper edge was found — but a wrapper path with a non-literal "
            "(caller-parameter) key or deeper nesting is NOT captured, so absence is NOT proof the "
            "key is unused"
        )
    if unresolved_count:
        notes.append(
            f"{unresolved_count} nvram ops have an unresolved/dynamically-built key "
            "(key_from_caller) and could touch any key — a SEPARATE blind spot from "
            "wrapper-indirect access above"
        )
    # completeness never claims a bare "complete": a populated direct graph is still only
    # 'direct_only' (wrapper-indirect unresolved); any applicable blind spot -> 'may_be_incomplete'.
    completeness = "may_be_incomplete" if notes else "direct_only"

    result: dict[str, Any] = {
        "key": key,
        "found": bool(writers or readers or template_matches),
        "match": match_state,
        "writers": writers,
        "readers": readers,
        "template_matches": template_matches,
        "unresolved_count": unresolved_count,
        # source-side writability: is this key web-settable via the router_defaults table? A
        # three-state fact (True / False / "uncertain") — never asserts "not settable" from a
        # not-located table (false-negative red line).
        "web_settable": _web_settable(conn, key),
        "coverage": COVERAGE_NOTE,
        "completeness": completeness,
        "notes": notes,
    }
    return result
