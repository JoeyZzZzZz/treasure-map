# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Flow evidence for a command-sink candidate — structured material for a downstream agent.

This module produces EVIDENCE, never a judgement. It follows "give enough, give all + honest
blind spots": it hands a reviewer the reliable facts it can establish intra-procedurally (the
source classification, the one-hop value flow, which sanitizer-shaped calls exist and whether
they sit on the sink's path, which rootfs entry points were found to invoke the binary) AND the
boundary where its tracing stops — but it NEVER decides "sanitized / not sanitized" or
"triggerable / not". Each field is a neutral mechanism fact; the judgement is the agent's.

Hard rules (do not relax):
- `sanitizer_seen` records only that a sanitizer-shaped call exists and whether it lies on the
  sink's flow path. Coverage is ALWAYS reported as ``unjudged`` — a single static read cannot
  decide that a sanitizer covers a path (the same sanitizer can guard one branch and miss
  another), so it must not claim to.
- `source_kind` classifies the source mechanism (charset_safe / free_string / unknown); it is
  NOT a safety verdict.
- `entry_reach` lists the call sites found; "no site found" is reported as ``unknown``, never as
  "unreachable" (a binary may be invoked at runtime, via another binary's exec, or over IPC).
- `trace_boundary` states honestly where the structured trace stopped and why.

Nothing here feeds recall, the review-ordering score, or the reachability grade — it is read-only
evidence attached to the candidate for a later layer to consume.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Any

from treasure_map.lib.hunt.downweight import (
    _CHARSET_COPY_EXTRA,
    _CHARSET_SAFE,
    _value_is_constrained,
)
from treasure_map.lib.reachability.filters import _is_validator_name
from treasure_map.lib.reachability.taint import (
    _CALLER_SUPPLIED_RE,
    _derives_map,
    _seed_sets,
    flows_into,
    free_taint_reaches,
)

# Decompiler markers for values an intra-procedural read cannot soundly follow: globals / shared
# state / a prior call's un-threaded output. Their presence on the path is a trace boundary.
_GLOBAL_IPC_RE = re.compile(r"\b(?:DAT_[0-9a-fA-F]+|g_\w+|extraout_\w+|_?_bss_\w+)\b")
# An indirect call through a function pointer: (*fp)(...) or (\*\w+)(...).
_INDIRECT_CALL_RE = re.compile(r"\(\s*\*\s*\w+\s*\)\s*\(")


def _source_kind(pseudocode: str, sink_arg: str | None) -> str:
    """Classify the source reaching the sink argument (mechanism, not a verdict)."""
    if sink_arg is None:
        return "unknown"
    if _value_is_constrained(pseudocode, sink_arg, _CHARSET_SAFE):
        return "charset_safe"
    if free_taint_reaches(pseudocode, sink_arg, safe_vars=set()):
        return "free_string"
    return "unknown"


def _real_vars(pseudocode: str, deps: dict[str, set[str]]) -> set[str]:
    """The function's real variables — values that are written, depended on, caller-supplied, or
    source-seeded. Used to filter format-literal noise (e.g. the `echo`/`s` of `"echo %s"`) out of
    the reported flow so the evidence lists actual flow variables, not parsed string fragments."""
    strong, weak, par = _seed_sets(pseudocode)
    real = set(deps.keys()) | strong | weak | par
    for srcs in deps.values():
        real |= srcs & set(deps.keys())  # intermediate vars that themselves have dependencies
    real |= set(_CALLER_SUPPLIED_RE.findall(pseudocode))
    return real


def _flow_path(pseudocode: str, sink_arg: str | None, deps: dict[str, set[str]]) -> dict[str, Any]:
    """The sink argument and its ONE-HOP backward dependencies (the intermediate values feeding
    it directly), filtered to real variables. Reliable range only — direct args + one intermediate
    variable; deeper links are summarized by ``trace_boundary``, not invented here."""
    if sink_arg is None:
        return {"sink_arg": None, "one_hop": []}
    real = _real_vars(pseudocode, deps)
    one_hop = sorted(v for v in deps.get(sink_arg, set()) if v in real)
    return {"sink_arg": sink_arg, "one_hop": one_hop}


def _sanitizer_seen(callees: list[str], pseudocode: str, path: set[str]) -> list[dict[str, Any]]:
    """Sanitizer-shaped callees and whether each is applied to a value on the sink's path.

    Records existence + on_path only; coverage is ALWAYS ``unjudged`` (a static read cannot
    decide a sanitizer actually covers the path). Never feeds a score or a blocked verdict."""
    seen: list[dict[str, Any]] = []
    for callee in callees:
        name = callee.strip()
        if not name or not _is_validator_name(name):
            continue
        on_path = any(
            re.search(rf"\b{re.escape(name)}\s*\([^;{{}}]*\b{re.escape(var)}\b", pseudocode)
            is not None
            for var in path
        )
        seen.append({"name": name, "on_path": on_path, "coverage": "unjudged"})
    return seen


def _trace_boundary(
    pseudocode: str, sink_arg: str | None, source_kind: str, deps: dict[str, set[str]]
) -> str:
    """Honest statement of where the structured trace stops and why.

    reached_sink      — the source reaching the sink was resolved (to a charset converter or a
                        free source) and no untraceable construct lies in the way.
    one_hop_limit     — the source was not resolved; one intermediate buffer was followed and the
                        trace stopped at the one-hop cap.
    two_hop_untraced  — the source was not resolved and passes through >=2 intermediate buffers
                        (beyond the one-hop cap — a known blind spot, not followed).
    indirect_call     — an indirect (function-pointer) call is present (a value may arrive through
                        it; intra read cannot follow it).
    ipc_global        — a global / shared-state / un-threaded value is present.
    copy_alias_untraced — a bounded copy the dependency graph does not track moved a value, so the
                        structured flow chain may be incomplete.

    Cautious by design: a present-but-maybe-unrelated indirect call / global / untracked copy is
    reported as a boundary rather than silently claiming a clean resolution."""
    if sink_arg is None:
        return "reached_sink"
    if _INDIRECT_CALL_RE.search(pseudocode):
        return "indirect_call"
    if _GLOBAL_IPC_RE.search(pseudocode):
        return "ipc_global"
    if any(re.search(rf"\b{re.escape(c)}\s*\(", pseudocode) for c in _CHARSET_COPY_EXTRA):
        # A bounded copy the global dependency graph does not track moved a value; the structured
        # chain may be shorter than reality, so flag the alias rather than overclaim resolution.
        return "copy_alias_untraced"
    if source_kind in ("charset_safe", "free_string"):
        return "reached_sink"  # the source was resolved within the intra-procedural read
    depth = _chain_depth(deps, sink_arg)
    if depth <= 1:
        return "reached_sink"
    if depth == 2:
        return "one_hop_limit"
    return "two_hop_untraced"


def _chain_depth(deps: dict[str, set[str]], start: str) -> int:
    """Longest backward chain length from ``start`` over the dependency edges (cycle-safe)."""
    best = {start: 0}
    stack = [start]
    seen = {start}
    longest = 0
    while stack:
        cur = stack.pop()
        for nxt in deps.get(cur, ()):
            cand = best[cur] + 1
            longest = max(longest, cand)
            if nxt not in seen or cand > best.get(nxt, 0):
                best[nxt] = cand
                seen.add(nxt)
                if cand < 8:  # depth guard; the answer only needs the <=2 vs >2 distinction
                    stack.append(nxt)
    return longest


def build_flow_evidence(
    *,
    pseudocode: str,
    callees: list[str],
    sink_arg: str | None,
    entry_sites: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    """Assemble the five-field flow evidence for one command-sink candidate (JSON-serializable).

    Pure and deterministic. ``entry_sites`` is the rootfs invocation evidence gathered separately
    (see ``find_entry_sites``); None or [] means none was found — reported as ``unknown``, NOT as
    "unreachable"."""
    deps = _derives_map(pseudocode)
    path = ({sink_arg} | flows_into(pseudocode, sink_arg)) if sink_arg is not None else set()
    source_kind = _source_kind(pseudocode, sink_arg)
    return {
        "source_kind": source_kind,
        "flow_path": _flow_path(pseudocode, sink_arg, deps),
        "sanitizer_seen": _sanitizer_seen(callees, pseudocode, path),
        "entry_reach": {
            "status": "found" if entry_sites else "unknown",
            "sites": entry_sites or [],
        },
        "trace_boundary": _trace_boundary(pseudocode, sink_arg, source_kind, deps),
    }


class EntryIndex:
    """In-memory index of rootfs entry evidence (L0.5 ``script_calls`` + ``web_endpoints``).

    Loaded ONCE per analysis.db, then queried per candidate binary — so entry-reach evidence does
    not re-scan the tables for every candidate. Read-only; holds only neutral rootfs evidence."""

    def __init__(
        self,
        script_calls: list[tuple[str | None, str | None, int | None, str | None]],
        web_endpoints: list[tuple[str | None, str | None, str | None, str | None, str | None]],
    ) -> None:
        self._script_calls = script_calls
        self._web_endpoints = web_endpoints

    def sites_for(self, binary_name: str | None, binary_path: str | None) -> list[dict[str, Any]]:
        """Every entry site referencing the binary (give-all). Each script site carries the script
        path, line, and coarse argument pattern (literal / var_expansion / piped) so the parameter
        source is visible. [] means none found — the caller reports ``unknown``, NOT "unreachable".
        """
        names = {n for n in (binary_name, Path(binary_path).name if binary_path else None) if n}
        if not names:
            return []
        sites: list[dict[str, Any]] = []
        for script, command, line, args_pattern in self._script_calls:
            cmd = command or ""
            # References the binary when the command token is, or ends in, the binary name
            # (handles bare-name and absolute-path forms in the script).
            if cmd.rsplit("/", 1)[-1] in names or cmd in names:
                sites.append(
                    {
                        "kind": "script_call",
                        "script": script,
                        "line": line,
                        "arg_source": args_pattern,
                    }
                )
        for asset, asset_type, method, endpoint, source in self._web_endpoints:
            ep = endpoint or ""
            if any(n in ep for n in names):
                sites.append(
                    {
                        "kind": "web_endpoint",
                        "asset": asset,
                        "asset_type": asset_type,
                        "method": method,
                        "endpoint": ep,
                        "arg_source": source,
                    }
                )
        return sites


def load_entry_index(conn: sqlite3.Connection) -> EntryIndex:
    """Load the L0.5 entry-evidence tables once (read-only). Missing tables yield an empty index
    (an older analysis.db without L0.5 simply produces ``entry_reach=unknown`` everywhere)."""
    try:
        sc = conn.execute(
            "SELECT f.path, c.command, c.line_number, c.args_pattern "
            "FROM script_calls c JOIN non_binary_files f ON f.id = c.file_id "
            "ORDER BY f.path, c.line_number"
        ).fetchall()
    except sqlite3.OperationalError:
        sc = []
    try:
        we = conn.execute(
            "SELECT f.path, e.asset_type, e.method, e.path, e.source "
            "FROM web_endpoints e JOIN non_binary_files f ON f.id = e.file_id "
            "ORDER BY e.path"
        ).fetchall()
    except sqlite3.OperationalError:
        we = []
    return EntryIndex(
        [(r[0], r[1], r[2], r[3]) for r in sc],
        [(r[0], r[1], r[2], r[3], r[4]) for r in we],
    )
