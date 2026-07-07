# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Public entry: scan one analysis.db for call-sequence shape candidates.

Pure-static and hermetic — no LLM, no network, no router, no tier consumed. The input
database is opened strictly read-only; scan returns in-memory results and writes
nothing. It finds *shapes*, not bugs: every match is a candidate / lead.

NOTE ON EVIDENCE: a match's evidence field holds raw, firmware-derived text (e.g. a
matched format literal that may contain a device path). That is fine in this local,
ephemeral result. A persistence consumer MUST neutralize evidence before storing it.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path

from treasure_map.lib.pattern.models import FuncRef, PatternMatch, PatternStats, ScanResult
from treasure_map.lib.pattern.oss import is_oss_binary
from treasure_map.lib.pattern.shapes import DETECTORS

logger = logging.getLogger(__name__)

_KNOWN_COMPONENTS_SQL = """
SELECT DISTINCT b.name
  FROM components c
  JOIN binaries b ON b.id = c.binary_id
"""

_FUNCTIONS_SQL = """
SELECT f.id, b.name AS binary_name, f.name, f.pseudocode, f.callees
  FROM functions f
  JOIN binaries b ON b.id = f.binary_id
 WHERE f.pseudocode IS NOT NULL
   AND f.callees IS NOT NULL
   AND f.callees != '[]'
 ORDER BY b.name, f.id
"""


def _parse_callees(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return []
    if not isinstance(data, list):
        return []
    return [str(x) for x in data]


def scan(db_path: Path | str) -> ScanResult:
    """Scan an analysis.db (read-only) for call-sequence shape candidates.

    OSS/third-party binaries are excluded (components-table membership first, then a
    generic-name fallback) so the scan surfaces shapes in custom binaries only.
    """
    uri = f"file:{Path(db_path)}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        conn.row_factory = sqlite3.Row
        known_components = {row["name"] for row in conn.execute(_KNOWN_COMPONENTS_SQL)}
        rows = conn.execute(_FUNCTIONS_SQL).fetchall()
    finally:
        conn.close()

    matches: list[PatternMatch] = []
    excluded_binaries: set[str] = set()
    functions_scanned = 0
    custom_functions = 0
    hits = {
        "cmd_injection_shape": 0,
        "overflow_shape": 0,
        "bare_cmd_shape": 0,
        "fmt_string_shape": 0,
        "path_sink_shape": 0,
    }

    for row in rows:
        functions_scanned += 1
        binary_name = row["binary_name"]
        if is_oss_binary(binary_name, known_components=known_components):
            excluded_binaries.add(binary_name)
            continue

        callees = _parse_callees(row["callees"])
        if not callees:
            continue
        custom_functions += 1

        func_ref = FuncRef(binary_name=binary_name, func_name=row["name"], func_id=row["id"])
        pseudocode = row["pseudocode"] or ""
        for detector in DETECTORS:
            match = detector(func_ref, callees, pseudocode)
            if match is None:
                continue
            matches.append(match)
            hits[match.pattern_kind] += 1

    stats = PatternStats(
        functions_scanned=functions_scanned,
        oss_binaries_excluded=len(excluded_binaries),
        custom_functions=custom_functions,
        pattern_a=hits["cmd_injection_shape"],
        pattern_b=hits["overflow_shape"],
        bare_cmd=hits["bare_cmd_shape"],
        fmt_string=hits["fmt_string_shape"],
        path_sink=hits["path_sink_shape"],
    )
    return ScanResult(matches=tuple(matches), stats=stats)
