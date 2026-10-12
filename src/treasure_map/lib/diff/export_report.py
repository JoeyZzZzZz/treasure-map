# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""What one side's BinExport could not represent faithfully: the export script's report.

``ExportBinExport.java`` writes it next to the ``.BinExport`` (see that script's header for the two
repairs). Two kinds of function are listed, and both are blind spots of the diff:

  * ``flow_graph_dropped`` — the function's flow graph had no entry block, so it was removed from
    the export: BinDiff cannot match the function at all.
  * ``degenerate_block`` — the export had to be rebuilt by the fallback builder, and the function
    contains a basic block entered through a delay-slot instruction. Its flow graph is exported,
    but under the block's first entry, so whatever BinDiff says about it is not reliable.

Layer 0 marks these functions on their presence / alignment rows, and every reader reports them as
undetermined with reason ``degenerate_block_source`` — never as matched, unmatched, changed or
unchanged. The two counts that change nothing (explicit entry addresses written where the reader
would have derived the same value) are recorded on diff_meta only.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from treasure_map.lib.hunt.refs import _norm_addr

GAP_FLOW_GRAPH_DROPPED = "flow_graph_dropped"
GAP_DEGENERATE_BLOCK = "degenerate_block"
# The reason every reader gives for a subject that rests on such a function.
DEGENERATE_BLOCK_SOURCE = "degenerate_block_source"

_BUILDERS = frozenset({"extension", "fallback"})


class ExportReportError(ValueError):
    """The export report is missing a field or holds a value of the wrong type."""


@dataclass(frozen=True)
class ExportReport:
    builder: str  # 'extension' (the BinExport extension's own builder) | 'fallback'
    entry_addresses_added: int
    flow_graphs_dropped: int
    dropped_functions: frozenset[str]  # function entries, normalized hex
    degenerate_functions: frozenset[str]

    def gaps(self) -> dict[str, str]:
        """Function entry (normalized hex) -> gap kind. A dropped flow graph wins over a degenerate
        block: the function is then not in BinDiff's input at all."""
        out = dict.fromkeys(self.degenerate_functions, GAP_DEGENERATE_BLOCK)
        out.update(dict.fromkeys(self.dropped_functions, GAP_FLOW_GRAPH_DROPPED))
        return out


def _addr(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ExportReportError(f"not an address: {value!r}")
    norm = _norm_addr(format(value, "x"))
    if norm is None:
        raise ExportReportError(f"not an address: {value!r}")
    return norm


def _count(data: dict[str, Any], key: str) -> int:
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ExportReportError(f"{key!r} is not a count: {value!r}")
    return value


def _addrs(data: dict[str, Any], key: str) -> frozenset[str]:
    value = data.get(key)
    if not isinstance(value, list):
        raise ExportReportError(f"{key!r} is not a list: {value!r}")
    return frozenset(_addr(v) for v in value)


def parse_export_report(text: str) -> ExportReport:
    """Parse the report JSON; raises ExportReportError on anything but the expected shape."""
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ExportReportError(f"not JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ExportReportError("not a JSON object")
    builder = data.get("builder")
    if builder not in _BUILDERS:
        raise ExportReportError(f"unknown builder: {builder!r}")
    dropped = _addrs(data, "dropped_functions")
    n_dropped = _count(data, "flow_graphs_dropped")
    if n_dropped != len(dropped):
        raise ExportReportError(
            f"flow_graphs_dropped is {n_dropped} but {len(dropped)} functions are listed"
        )
    return ExportReport(
        builder=builder,
        entry_addresses_added=_count(data, "entry_addresses_added"),
        flow_graphs_dropped=n_dropped,
        dropped_functions=dropped,
        degenerate_functions=_addrs(data, "degenerate_functions"),
    )


def report_path(export_path: Path) -> Path:
    """Where the export script writes the report for ``export_path`` (``a.BinExport`` ->
    ``a.export_report.json``)."""
    return export_path.with_name(f"{export_path.stem}.export_report.json")


def read_export_report(export_path: Path) -> ExportReport | None:
    """The report written beside ``export_path``, or None when there is none (an export not made by
    the script, e.g. a test fixture). A report that exists but cannot be parsed raises."""
    path = report_path(export_path)
    if not path.is_file():
        return None
    return parse_export_report(path.read_text(encoding="utf-8"))


def load_export_gaps(atlas: sqlite3.Connection, diff_id: str) -> tuple[set[str], set[str]]:
    """Per side, the functions of one stored diff whose comparison rests on an export that did not
    represent them faithfully: a function marked on its presence or alignment row, and the other
    half of any pair with a marked side — that pair's alignment says nothing reliable about either
    function."""
    gaps_a: set[str] = set()
    gaps_b: set[str] = set()
    for addr_a, addr_b in atlas.execute(
        "SELECT addr_a, addr_b FROM function_alignment WHERE diff_id = ? "
        "AND (export_gap_a IS NOT NULL OR export_gap_b IS NOT NULL)",
        (diff_id,),
    ):
        gaps_a.add(addr_a)
        gaps_b.add(addr_b)
    for side, addr in atlas.execute(
        "SELECT side, addr FROM function_presence WHERE diff_id = ? AND export_gap IS NOT NULL",
        (diff_id,),
    ):
        (gaps_a if side == "a" else gaps_b).add(addr)
    return gaps_a, gaps_b
