# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
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

from treasure_map.lib.errors import ConfigError
from treasure_map.lib.pattern.models import FuncRef, PatternMatch, PatternStats, ScanResult
from treasure_map.lib.pattern.shapes import DETECTORS

logger = logging.getLogger(__name__)

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


def shape_scan_invariant_holds(stats: PatternStats) -> bool:
    """Every function the pre-filter admitted either reached the detectors or is a counted gap.

    One predicate, two callers: ``scan`` checks it on every run, and Gate D re-derives it from a
    real analysis.db. Sharing it is the point — a gate that re-implements the rule it enforces can
    drift from the code, and then agrees with it about nothing in particular."""
    return stats.functions_with_callees + stats.callee_parse_failed == stats.functions_scanned


def scan(db_path: Path | str) -> ScanResult:
    """Scan an analysis.db (read-only) for call-sequence shape candidates.

    Every binary is scanned; no binary is skipped by name or by components-table membership
    (origin is a label carried on the instance, never a scan-time filter). A function whose stored
    callees cannot be parsed is counted in ``callee_parse_failed`` and surfaced as a data gap,
    never silently dropped.
    """
    uri = f"file:{Path(db_path)}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(_FUNCTIONS_SQL).fetchall()
    finally:
        conn.close()

    matches: list[PatternMatch] = []
    functions_scanned = 0
    functions_with_callees = 0
    callee_parse_failed = 0
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
        callees = _parse_callees(row["callees"])
        if not callees:
            # The SQL pre-filter already excluded a literal '[]', so an empty list here means the
            # stored value did not PARSE — malformed JSON, or JSON that is not a list. That is a
            # data gap about this function, not a decision about it: counted and reported, so an
            # incomplete candidate set never reads as a complete one.
            callee_parse_failed += 1
            continue
        functions_with_callees += 1

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
        functions_with_callees=functions_with_callees,
        callee_parse_failed=callee_parse_failed,
        pattern_a=hits["cmd_injection_shape"],
        pattern_b=hits["overflow_shape"],
        bare_cmd=hits["bare_cmd_shape"],
        fmt_string=hits["fmt_string_shape"],
        path_sink=hits["path_sink_shape"],
    )
    # ★ Checked here, at runtime, on every scan. The two counts partition what the pre-filter
    # admitted, so a mismatch means a function left the loop through neither branch — a skip
    # taken on a property of the function rather than of its data. That is the exact shape of
    # what this pass used to do by binary name, and it is a programming error, so it raises rather
    # than degrading: a scan that quietly skipped part of the firmware is worse than no scan.
    # Malformed data does NOT come here; it is counted in callee_parse_failed and reported.
    if not shape_scan_invariant_holds(stats):
        raise ConfigError(
            f"shape scan invariant violated: scanned={stats.functions_scanned} "
            f"with_callees={stats.functions_with_callees} "
            f"parse_failed={stats.callee_parse_failed}"
        )
    return ScanResult(matches=tuple(matches), stats=stats)
