# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Row paging for the fact tools whose lists grow with the firmware.

Every list here is ASSEMBLED in full first, put in one TOTAL order, and only then cut: these lists
do not come out of one SQL statement (a JSON column, a SQL read merged with a Python scan, a list
computed in Python), so an SQL ``LIMIT``/``OFFSET`` would page each source on its own. A total
order is what makes paging correct: rows that tie on the displayed order (two binaries with the
same short name are common) would otherwise trade places between two calls, and a reader walking
``offset = next_offset`` would read one twice and miss the other. A page is never a filter: every
row stays reachable by paging on, and each total is the exact length of the whole list.

The functions here page the answers of ``lib.facts`` and ``lib.query.nvram`` from OUTSIDE those
modules, which belong to the hunt code stamp: changing them would mark every run as hunted by
other code. Each reads the answer the module gives, unchanged, and pages it; the one exception is
``functions_referencing_string``, which re-issues that function's own query without its row cap
(see there). ``limit`` None means "do not cut" everywhere — the reading a direct library caller
gets."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from typing import Any

from treasure_map.lib import facts as _facts


def page_list(rows: list[Any], offset: int, limit: int | None) -> tuple[list[Any], int]:
    """``rows[offset : offset + limit]`` (to the end when ``limit`` is None) and the whole list's
    length. ``offset`` past the end gives an empty page, never an error."""
    lo = max(0, offset)
    page = rows[lo:] if limit is None else rows[lo : lo + max(0, limit)]
    return page, len(rows)


def _nulls_first(value: Any) -> tuple[bool, Any]:
    """A sort key part that orders as SQLite's ORDER BY does: NULL before every value."""
    return (value is not None, "" if value is None else value)


def _content(row: Any) -> str:
    """The last key part: the row itself, so rows that tie on every displayed field still have one
    order. Two rows equal here are equal in every field, so which comes first changes nothing a
    reader sees."""
    return json.dumps(row, sort_keys=True, default=str)


def xref_key(edge: dict[str, Any]) -> tuple[str, str, str, str, bool]:
    """The total order of get_xrefs' callers / callees edges. Path and address sit inside the
    edge's ``anchor``; a library-level edge (no function row) has ``function`` and ``address``
    None, so each part falls back to "" — a None beside a string would not compare."""
    a = edge["anchor"]
    return (
        a.get("binary_path") or "",
        a.get("address") or "",
        a.get("function") or "",
        edge.get("xref_type") or "",
        bool(edge.get("library_level")),
    )


def page_xrefs(result: dict[str, Any], offset: int, limit: int | None) -> dict[str, Any]:
    """A get_xrefs answer with one page of ``edges`` and ``total_edges``.

    callers / callees edges come from the xrefs table AND (callers) a reverse scan of callee lists,
    in no stated order; only the merged list sorted by ``xref_key`` has one order across both
    sources. address_taken edges keep the stored export's order, which is fixed. An answer without
    ``edges`` (not found, ambiguous) is returned as it is."""
    edges = result.get("edges")
    if not isinstance(edges, list):
        return result
    if result.get("direction") in ("callers", "callees"):
        edges = sorted(edges, key=xref_key)
    result["edges"], result["total_edges"] = page_list(edges, offset, limit)
    return result


def page_lists(
    result: dict[str, Any],
    offset: int,
    limit: int | None,
    lists: tuple[str, ...],
    keys: Mapping[str, tuple[str, ...]] | None = None,
) -> dict[str, Any]:
    """Several lists of one answer paged at ONE shared index, each with its ``total_<list>``.

    Each list keeps its place in the answer. ``keys`` names a list's displayed sort fields; its
    rows are then put in that order (NULL first, as the SQL that read them) and, last, by their
    whole content, which makes the order total. A list absent from ``keys`` already has one (its
    query ends on a unique id). A list that is None (not determined) stays None, with a None
    total."""
    for name in lists:
        rows = result.get(name)
        if not isinstance(rows, list):
            result[f"total_{name}"] = None
            continue
        fields = (keys or {}).get(name)
        if fields is not None:
            rows = sorted(rows, key=_row_key(fields))
        result[name], result[f"total_{name}"] = page_list(rows, offset, limit)
    return result


def _row_key(fields: tuple[str, ...]) -> Any:
    """The total-order key of a row ordered by ``fields`` (NULL first), then by its content."""

    def key(row: dict[str, Any]) -> tuple[Any, ...]:
        return (*(_nulls_first(row.get(f)) for f in fields), _content(row))

    return key


# The lists of get_imports_exports and the fields each is ordered by (its SQL's ORDER BY).
IMPORTS_EXPORTS_LISTS = ("imports", "exports", "dt_needed_unresolved")
_IMPORTS_EXPORTS_KEYS: dict[str, tuple[str, ...]] = {
    "imports": ("func_name",),
    "exports": ("func_name",),
    # dt_needed_unresolved's query ends on the edge id: already one order.
}

# The lists of get_nvram_key_flow and the fields each is ordered by (its SQL's ORDER BY).
NVRAM_LISTS = ("writers", "readers", "template_matches")
_NVRAM_KEYS: dict[str, tuple[str, ...]] = {name: ("binary", "func") for name in NVRAM_LISTS}


def page_imports_exports(result: dict[str, Any], offset: int, limit: int | None) -> dict[str, Any]:
    """A get_imports_exports answer with its three lists paged at one index. A not-found answer is
    returned as it is."""
    if result.get("found") is not True:
        return result
    return page_lists(result, offset, limit, IMPORTS_EXPORTS_LISTS, _IMPORTS_EXPORTS_KEYS)


def page_nvram_key_flow(result: dict[str, Any], offset: int, limit: int | None) -> dict[str, Any]:
    """A get_nvram_key_flow answer with its three lists paged at one index. ``found``, ``match``,
    ``completeness`` and the notes were read from the whole lists, before the cut."""
    return page_lists(result, offset, limit, NVRAM_LISTS, _NVRAM_KEYS)


def _anchor_key(row: dict[str, Any]) -> tuple[Any, ...]:
    return (
        _nulls_first(row.get("binary")),
        _nulls_first(row.get("string_addr")),
        _nulls_first(row.get("ref_at")),
        _content(row),
    )


# Larger than any table: asks a capped reader for every row (it fetches one more than this, which
# still fits SQLite's 64-bit LIMIT).
_ALL = 2**62


def string_reference_anchors(
    conn: sqlite3.Connection,
    *,
    text: str,
    binary: str | None,
    offset: int,
    limit: int | None,
) -> dict[str, Any]:
    """get_string_reference_anchors with every reference read, then one page of them.

    ``export_truncated`` is read over every reference (the export capped this string's list),
    ``response_truncated`` says this page is not the last one, ``truncated`` is either. ``limit``
    echoes the page size asked for (None: no cut). An answer that found nothing is returned as the
    library gives it."""
    result = _facts.get_string_reference_anchors(conn, text=text, binary=binary, limit=_ALL)
    if result.get("found") is not True:
        return result
    anchors = sorted(result["anchors"], key=_anchor_key)
    page, total = page_list(anchors, offset, limit)
    more = max(0, offset) + len(page) < total
    result.update(
        {
            "anchors": page,
            "returned": len(page),
            "limit": limit,
            "total_anchors": total,
            "truncated": bool(result["export_truncated"] or more),
            "response_truncated": more,
        }
    )
    return result


def functions_referencing_string(
    conn: sqlite3.Connection,
    *,
    text: str,
    binary: str | None,
    offset: int,
    limit: int | None,
) -> dict[str, Any]:
    """get_functions_referencing_string, every hit counted and one page of them returned.

    The library function caps its hits (one ``LIMIT``) and reads each hit's whole pseudocode, which
    cannot be widened to "every hit": a substring as common as ``if (`` matches most functions of a
    large firmware, well over 100 MB of text. So this issues the same query — the same tables,
    WHERE and order, with ``f.id`` last so the order is total — for the hits' ids alone, counts
    them, and reads the pseudocode of this page's hits only, through the library's own
    first-match-line reading. The answer has the library's shape plus ``total_functions``;
    ``truncated`` says more hits follow this page."""
    if not text.strip():
        return _facts.get_functions_referencing_string(conn, text=text, binary=binary)
    sql = (
        "SELECT f.id, f.name, f.address, b.name AS binary_name, b.path AS binary_path "
        f"FROM functions f JOIN {_facts._CURRENT_BINARIES} b ON b.id = f.binary_id "  # noqa: S608
        "WHERE f.pseudocode LIKE ? ESCAPE '\\'"
    )
    params: list[Any] = [f"%{_facts._like_escape(text)}%"]
    if binary is not None:
        clause, bparams = _facts._binary_selector(binary)
        sql += f" AND {clause}"
        params.extend(bparams)
    sql += " ORDER BY b.name, f.address, f.id"
    hits = conn.execute(sql, params).fetchall()
    page, total = page_list(hits, offset, limit)
    marks = ", ".join("?" * len(page))
    text_of = (
        {
            r[0]: r[1]
            for r in conn.execute(
                f"SELECT id, pseudocode FROM functions WHERE id IN ({marks})",  # noqa: S608
                [r["id"] for r in page],
            )
        }
        if page
        else {}
    )
    functions = [
        {
            **_facts._anchor(r["binary_name"], r["binary_path"], r["name"], r["address"]),
            "match_line": _facts._first_match_line(text_of.get(r["id"]), text),
        }
        for r in page
    ]
    return {
        "found": True,
        "query": {"text": text, "binary": binary},
        "match_kind": "pseudocode_text_substring",
        "functions": functions,
        "returned": len(functions),
        "limit": limit,
        "truncated": max(0, offset) + len(functions) < total,
        "total_functions": total,
        "note": _facts._PSEUDO_TEXT_NOTE,
    }
