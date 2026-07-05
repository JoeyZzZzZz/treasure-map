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
    """True when a concrete key satisfies a parametric template (a possible, not exact, match)."""
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
    if row["op"] == "write":
        # value_source is the write-side controllability signal (param/call_return/constant/...).
        entry["value_source"] = _parse_value_source(row["value_source"])
    return entry


def get_nvram_key_flow(conn: sqlite3.Connection, key: str) -> dict[str, Any]:
    """Assemble the cross-binary read/write graph for one concrete nvram key.

    Returns exact writers/readers (constant key match), a separate flagged template_matches list
    (parametric templates the key satisfies), and a completeness flag driven by the count of
    unresolved-key ops. ``found`` is False only when nothing — exact or template — references the
    key; the completeness/unresolved fields are still populated so absence is never mistaken for
    "the key is unused" when unresolved ops could reach it. A surfaced fact, never a verdict.
    """
    exact_rows = conn.execute(
        "SELECT source_run_id, key, key_kind, binary, func, op, value_source, api "
        "FROM nvram_key_flow WHERE key_kind = 'constant' AND key = ? "
        "ORDER BY binary, func",
        (key,),
    ).fetchall()
    writers = [_entry(r) for r in exact_rows if r["op"] == "write"]
    readers = [_entry(r) for r in exact_rows if r["op"] == "read"]

    param_rows = conn.execute(
        "SELECT source_run_id, key, key_kind, binary, func, op, value_source, api "
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

    result: dict[str, Any] = {
        "key": key,
        "found": bool(writers or readers or template_matches),
        "match": "exact",
        "writers": writers,
        "readers": readers,
        "template_matches": template_matches,
        "unresolved_count": unresolved_count,
    }
    if unresolved_count:
        result["completeness"] = "may_be_incomplete"
        result["unresolved_note"] = (
            f"{unresolved_count} unresolved-key nvram ops (key_from_caller) exist and could touch "
            "any key; this key's writers/readers may be incomplete"
        )
    else:
        result["completeness"] = "complete"
    return result
