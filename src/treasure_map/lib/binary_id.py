# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Resolve a caller-supplied binary SELECTOR to exactly one binary, or refuse with the candidates.

The identity of a binary is its row — ``binaries.id``, content-hashed by ``binaries.sha256``.
``binaries.path`` selects a row (nothing in the schema makes it unique, so it is still checked for
multiples); ``binaries.name`` is a LABEL and repeats freely: one firmware ships the same
``libstdc++.so.6`` under two roots, with different content and different function tables.

Every read that took a short name and stopped at the first row was therefore answering about
whichever row the database happened to return — silently, and differently for different queries
over the same firmware. This module is the one place that turns a selector into a row, and its
answer to "more than one" is a REFUSAL listing the candidates, never a pick. Ambiguity is not an
error in the caller's request; it is information about the firmware, and it is returned in a shape
the caller can act on (re-issue with a path or a sha256).

Reads ``current_binaries`` (the most-recent-scan view), never ``binaries`` directly.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from typing import Any

# A selector is treated as a sha256 PREFIX only in this shape. Eight hex characters is where a
# prefix stops being a plausible file name; the upper bound is the full digest.
_SHA_PREFIX = re.compile(r"^[0-9a-fA-F]{8,64}$")


@dataclass(frozen=True)
class BinaryRow:
    """One binary's identity: the row id, its content hash, and the two things callers type."""

    id: int
    name: str
    path: str | None
    sha256: str | None


def _candidates(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    """The candidate list an ambiguous refusal carries: enough to re-issue unambiguously."""
    return [
        {"binary": r["name"], "binary_path": r["path"], "sha256": r["sha256"]}
        for r in sorted(rows, key=lambda r: (r["path"] or "", r["sha256"] or ""))
    ]


def resolve_binary(
    conn: sqlite3.Connection, selector: str
) -> tuple[BinaryRow | None, dict[str, Any] | None]:
    """``(row, None)`` for exactly one match, else ``(None, miss)``.

    Selector tiers, most specific first, stopping at the first tier that matches ANYTHING: exact
    sha256, sha256 prefix, exact path, short name. The tiers are ordered so a caller who supplies
    an identity is never dragged down to a label — and each tier is read with ``fetchall`` and
    checked for multiples, because "the first row of several" is precisely the answer this module
    exists to stop returning.

    ``miss`` is ``{"found": False, "reason": "not_found" | "ambiguous", "query": …}``, with
    ``candidates`` on the ambiguous side. It is a complete tool result: a caller returns it as-is.
    """
    tiers: list[tuple[str, tuple[Any, ...]]] = [
        ("SELECT id, name, path, sha256 FROM current_binaries WHERE sha256 = ?", (selector,)),
    ]
    if _SHA_PREFIX.match(selector):
        tiers.append(
            (
                "SELECT id, name, path, sha256 FROM current_binaries WHERE sha256 LIKE ? || '%'",
                (selector.lower(),),
            )
        )
    tiers += [
        ("SELECT id, name, path, sha256 FROM current_binaries WHERE path = ?", (selector,)),
        ("SELECT id, name, path, sha256 FROM current_binaries WHERE name = ?", (selector,)),
    ]
    for sql, params in tiers:
        rows = conn.execute(sql, params).fetchall()
        if not rows:
            continue
        if len(rows) > 1:
            return None, {
                "found": False,
                "reason": "ambiguous",
                "query": {"binary": selector},
                "candidates": _candidates(rows),
            }
        r = rows[0]
        return BinaryRow(id=int(r["id"]), name=r["name"], path=r["path"], sha256=r["sha256"]), None
    return None, {"found": False, "reason": "not_found", "query": {"binary": selector}}


def resolve_binary_in_db(
    analysis_db_path: str, selector: str
) -> tuple[BinaryRow | None, dict[str, Any] | None]:
    """``resolve_binary`` against an analysis.db named by path, opened read-only and closed.

    NEVER raises. Callers on the diff side use it inside failure handlers and fail-fast preflights
    where an exception would mask the error being reported, so an unreadable database comes back as
    a ``db_error`` miss like any other unresolvable selector."""
    try:
        con = sqlite3.connect(f"file:{analysis_db_path}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        return None, {
            "found": False,
            "reason": "db_error",
            "query": {"binary": selector},
            "detail": str(exc),
        }
    try:
        con.row_factory = sqlite3.Row
        return resolve_binary(con, selector)
    except sqlite3.Error as exc:
        return None, {
            "found": False,
            "reason": "db_error",
            "query": {"binary": selector},
            "detail": str(exc),
        }
    finally:
        con.close()
