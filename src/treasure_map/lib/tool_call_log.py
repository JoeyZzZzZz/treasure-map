# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The MCP server's tool-call log: one JSON line per tool call, kept OUTSIDE the atlas.

The atlas is the knowledge base that cannot be rebuilt, and every read tool is read-only against it
(a hunt or rescan can hold its write lock for minutes), so the call trail is a plain local file next
to it: ``<atlas dir>/logs/tool_calls.jsonl``. Writing is best effort and never blocks or fails a
tool: any error while recording is swallowed. A reader that finds no log treats what it would have
inferred from it as unknown.

Each line records: the time, the server session (an id fixed at startup, the process id and the
start time), the tool, its key parameters (identifiers and paging only — never free text such as a
rationale), the size of the response in bytes, whether the response is a cut page, and its error.
The response itself is never stored.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

LOG_DIRNAME = "logs"
LOG_FILENAME = "tool_calls.jsonl"
# Above this size the log is moved aside to ``<name>.1`` (one generation kept) before a write.
MAX_LOG_BYTES = 64 * 1024 * 1024
# A recorded string parameter or error is cut to this many characters.
MAX_VALUE_CHARS = 200

# The parameters a line records: identifiers and paging only. Free text (rationale, evidence, a
# batch's annotations...) is never written to the log.
KEY_PARAMS: frozenset[str] = frozenset(
    {
        "run_id",
        "evidence_ref",
        "binary",
        "function",
        "address",
        "addr",
        "diff_id",
        "run_pair",
        "run_a",
        "run_b",
        "run_a_id",
        "run_b_id",
        "entry_id",
        "anchor_ref",
        "anchor_kind",
        "row_ref",
        "group_ref",
        "unit_id",
        "unit",
        "worker",
        "workers",
        "k",
        "verdict",
        "detail",
        "view",
        "side",
        "bucket",
        "sink",
        "kind",
        "change",
        "path",
        "name",
        "offset",
        "limit",
        "rows_offset",
        "rows_limit",
        "hunk_offset",
        "ko_offset",
        "members_offset",
    }
)

# Keys that say a response is one page of more (a continuation offset) or was cut to fit.
_CONTINUATION_KEYS = ("next_offset", "next_hunk_offset", "next_rows_offset", "next_members_offset")
_CUT_KEYS = ("truncated", "over_budget", "truncated_by_bytes", "entries_truncated")


def log_path_for(atlas_db: Path | str) -> Path:
    """Where the server bound to ``atlas_db`` writes its tool-call log."""
    return Path(atlas_db).resolve().parent / LOG_DIRNAME / LOG_FILENAME


@dataclass(frozen=True)
class Session:
    """One server process: an id fixed at startup, its pid and its start time (epoch seconds)."""

    id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    pid: int = field(default_factory=os.getpid)
    started: float = field(default_factory=time.time)


def _value(v: Any) -> Any:
    if v is None or isinstance(v, (bool, int, float)):
        return v
    if isinstance(v, str):
        return v if len(v) <= MAX_VALUE_CHARS else v[:MAX_VALUE_CHARS] + "…"
    if isinstance(v, (list, tuple, dict)):
        return {"items": len(v)}
    return type(v).__name__


def key_params(arguments: dict[str, Any]) -> dict[str, Any]:
    """The recorded subset of a call's arguments (``KEY_PARAMS``), values cut to size."""
    return {k: _value(v) for k, v in sorted(arguments.items()) if k in KEY_PARAMS}


def _is_cut(result: Any, depth: int = 0) -> bool:
    """Whether a response is a page that continues or was cut to fit — read from its own fields,
    at the top level and one level down (a paging block)."""
    if not isinstance(result, dict) or depth > 1:
        return False
    for k in _CONTINUATION_KEYS:
        if result.get(k) is not None:
            return True
    for k in _CUT_KEYS:
        if result.get(k):
            return True
    return any(_is_cut(v, depth + 1) for v in result.values() if isinstance(v, dict))


def response_bytes(result: Any) -> int | None:
    """The UTF-8 size of the response as JSON, or None when it cannot be encoded."""
    try:
        return len(json.dumps(result, default=str, ensure_ascii=False).encode("utf-8"))
    except (TypeError, ValueError):
        return None


def build_line(
    session: Session,
    tool: str,
    arguments: dict[str, Any],
    result: Any = None,
    error: str | None = None,
) -> dict[str, Any]:
    """The log line of one call. ``error`` is a raised error's text; a returned ``{"error": …}``
    result is read for its own error."""
    if error is None and isinstance(result, dict) and result.get("error"):
        error = str(result["error"])
    line = {
        "ts": time.time(),
        "session": session.id,
        "pid": session.pid,
        "session_started": session.started,
        "tool": tool,
        "params": key_params(arguments),
        "response_bytes": None if result is None else response_bytes(result),
        "truncated": _is_cut(result),
        "error": None if error is None else _value(error),
    }
    # A work unit handed out with its material (start_diff_review(run_pair=...)): which, and
    # whether its material was cut — what a later write's read basis is read from.
    if isinstance(result, dict):
        unit = result.get("next_unit") if "next_unit" in result else result.get("unit")
        if isinstance(unit, dict) and isinstance(unit.get("unit_id"), str):
            line["unit"] = unit["unit_id"]
            line["unit_material_cut"] = bool(unit.get("material_cut") or result.get("material_cut"))
    return line


def append(path: Path, line: dict[str, Any]) -> None:
    """Append one line; best effort — never raises. One ``write`` of a line opened for append, so
    concurrent servers sharing the file do not interleave within a line."""
    try:
        data = (json.dumps(line, default=str, ensure_ascii=False) + "\n").encode("utf-8")
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            if path.stat().st_size > MAX_LOG_BYTES:
                os.replace(path, path.with_name(path.name + ".1"))
        except FileNotFoundError:
            pass
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
    except Exception:  # noqa: BLE001, S110 — the log never fails a tool call
        pass


class ToolCallLog:
    """The log one server writes: its session and its file."""

    def __init__(self, path: Path, session: Session | None = None) -> None:
        self.path = path
        self.session = session or Session()

    def record(
        self,
        tool: str,
        arguments: dict[str, Any],
        result: Any = None,
        error: str | None = None,
    ) -> None:
        """Record one call; never raises."""
        try:
            line = build_line(self.session, tool, arguments, result, error)
        except Exception:  # noqa: BLE001 — the log never fails a tool call
            return
        append(self.path, line)


def read_lines(path: Path) -> Iterator[dict[str, Any]] | None:
    """The log's lines, oldest first (the moved-aside generation first), skipping any line that is
    not a JSON object; None when there is no log at all — whatever would be inferred from it is
    then unknown, never 'no calls'."""
    files = [p for p in (path.with_name(path.name + ".1"), path) if p.is_file()]
    if not files:
        return None

    def gen() -> Iterator[dict[str, Any]]:
        for p in files:
            try:
                fh = p.open(encoding="utf-8", errors="replace")
            except OSError:
                continue
            with fh:
                for raw in fh:
                    try:
                        obj = json.loads(raw)
                    except ValueError:
                        continue
                    if isinstance(obj, dict):
                        yield obj

    return gen()
