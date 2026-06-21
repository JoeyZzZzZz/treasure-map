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
    _charset_inline_constrained,
)
from treasure_map.lib.pattern.classes import SOURCE
from treasure_map.lib.reachability.copy_size import (
    SIZE_CONST,
    SIZE_SIZEOF,
    SIZE_UNTRACED,
    classify_copy_size,
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


def _charset_converter_called(pseudocode: str) -> bool:
    """Existence check: a charset-safe converter is CALLED somewhere in this function body. NOT a
    flow claim — it does not assert the converter's result actually reaches the sink."""
    return any(re.search(rf"\b{re.escape(c)}\s*\(", pseudocode) for c in _CHARSET_SAFE)


def _free_source_called(pseudocode: str) -> bool:
    """Existence check: a free-input source (network/env/config/json getter) is CALLED in the
    function body. NOT a flow claim — used only for the conservative wrapper-candidate fallback."""
    return any(re.search(rf"\b{re.escape(s)}\s*\(", pseudocode) for s in SOURCE)


def _source_kind(pseudocode: str, sink_arg: str | None, *, conservative_free: bool = False) -> str:
    """Classify the source reaching the sink argument (mechanism, not a verdict).

    Order matters — a free source wins over a charset converter so a genuinely dangerous candidate
    is never washed into a "maybe safe" lead just because some converter is also called in the
    function:
      charset_safe  — the converter builds the sink argument INLINE (downweighted elsewhere).
      free_string   — a free source (network/env/config/json/parameter) reaches the sink argument.
      charset_maybe — NOT inline and NO free source, but a charset-safe converter is called in the
                      function: the value MAY be charset-constrained through an intermediate
                      variable, but it is not value-tracked here — a lead for the agent, not safe.
      unknown       — none of the above could be established.

    ``conservative_free`` (set for wrapper-propagated candidates, where the value reaches the
    forwarded argument possibly through intermediate variables an intra read cannot fully follow):
    a free source merely CALLED in the function is enough to classify free_string even when the
    flow is not fully traced. This is the deliberate, asymmetric "do not miss a danger" direction —
    the mirror of charset's "do not drop a suspect" (charset_maybe). A free source still wins over a
    charset converter, so a real free string is never washed into charset_maybe."""
    if sink_arg is None:
        return "unknown"
    if _charset_inline_constrained(pseudocode, sink_arg):
        return "charset_safe"
    if free_taint_reaches(pseudocode, sink_arg, safe_vars=set()):
        return "free_string"
    if conservative_free and _free_source_called(pseudocode):
        return "free_string"  # free source present; flow not fully traced -> report, don't miss
    if _charset_converter_called(pseudocode):
        return "charset_maybe"
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

    reached_sink      — the source was resolved to the bottom WITHIN this function (an inline
                        charset converter, an inline free source, or a literal).
    charset_via_intermediate_untraced — a charset-safe converter is in the function but the value
                        reaches the sink through an intermediate variable that was NOT followed
                        (the `charset_maybe` lead: looked through a converter, did not trace it).
    one_hop_limit     — source not resolved; one intermediate buffer followed, stopped at the cap.
    two_hop_untraced  — source not resolved; >=2 intermediate buffers (beyond the cap).
    indirect_call     — an indirect (function-pointer) call is present (a value may arrive through
                        it; intra read cannot follow it).
    ipc_global        — a global / shared-state / un-threaded value is present.
    copy_alias_untraced — a bounded copy the dependency graph does not track moved a value, so the
                        structured flow chain may be incomplete.

    Honest by design — it NEVER claims `reached_sink` when a converter was seen but the value ran
    through an intermediate variable (that would pretend not to have seen the converter). A
    present-but-maybe-unrelated indirect call / global / untracked copy is reported as a boundary
    rather than silently claiming a clean resolution."""
    if sink_arg is None:
        return "reached_sink"
    if source_kind == "charset_maybe":
        return "charset_via_intermediate_untraced"
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
    wrapper: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble the five-field flow evidence for one command-sink candidate (JSON-serializable).

    Pure and deterministic. ``entry_sites`` is the rootfs invocation evidence gathered separately
    (see ``find_entry_sites``); None or [] means none was found — reported as ``unknown``, NOT as
    "unreachable".

    ``wrapper`` is set for a factor-① wrapper-propagated candidate (the real sink is one hop away
    inside a thin wrapper): it carries the wrapper's name + wrapped_sink, and here ``sink_arg`` is
    the argument the function forwards to that wrapper. When set, flow_path marks the wrapper hop
    and trace_boundary states `reached_sink_via_one_hop_wrapper` — honest about following exactly
    one hop. ``source_kind`` still classifies the forwarded argument (the dangerous value)."""
    deps = _derives_map(pseudocode)
    path = ({sink_arg} | flows_into(pseudocode, sink_arg)) if sink_arg is not None else set()
    # Wrapper-propagated candidates reach the forwarded argument possibly through intermediate
    # variables, so a present-but-not-fully-traced free source is reported conservatively.
    source_kind = _source_kind(pseudocode, sink_arg, conservative_free=wrapper is not None)
    flow_path = _flow_path(pseudocode, sink_arg, deps)
    if wrapper is not None:
        flow_path = {**flow_path, "sink_via_wrapper": True, "wrapper": wrapper}
        trace_boundary = "reached_sink_via_one_hop_wrapper"
    else:
        trace_boundary = _trace_boundary(pseudocode, sink_arg, source_kind, deps)
    return {
        "source_kind": source_kind,
        "flow_path": flow_path,
        "sanitizer_seen": _sanitizer_seen(callees, pseudocode, path),
        "entry_reach": {
            "status": "found" if entry_sites else "unknown",
            "sites": entry_sites or [],
        },
        "trace_boundary": trace_boundary,
    }


def _size_trace_boundary(
    pseudocode: str, kind: str, size_var: str | None, deps: dict[str, set[str]]
) -> str:
    """Honest statement of where the size trace stops and why (mirror of ``_trace_boundary``).

    reached_sink        — the length resolved within the function (a constant, a sizeof, or a
                          length variable with no further backward chain).
    size_arg_untraced   — the length argument could not be resolved here.
    indirect_call       — an indirect (function-pointer) call is present; a length may arrive
                          through it and an intra read cannot follow it.
    copy_alias_untraced — a bounded copy the dependency graph does not track moved a value, so the
                          structured size chain may be incomplete.
    one_hop_limit       — the length came through one intermediate variable, stopped at the cap.
    two_hop_untraced    — the length came through >=2 intermediates (beyond the cap)."""
    if kind in (SIZE_CONST, SIZE_SIZEOF):
        return "reached_sink"
    if kind == SIZE_UNTRACED:
        return "size_arg_untraced"
    if _INDIRECT_CALL_RE.search(pseudocode):
        return "indirect_call"
    if any(re.search(rf"\b{re.escape(c)}\s*\(", pseudocode) for c in _CHARSET_COPY_EXTRA):
        return "copy_alias_untraced"
    if size_var is None:
        return "reached_sink"
    depth = _chain_depth(deps, size_var)
    if depth <= 1:
        return "reached_sink"
    if depth == 2:
        return "one_hop_limit"
    return "two_hop_untraced"


def build_size_evidence(*, pseudocode: str, sink_name: str) -> dict[str, Any]:
    """Assemble the size-flow evidence for one copy-sink candidate (JSON-serializable).

    Pure and deterministic. Like ``build_flow_evidence`` this is EVIDENCE, never a judgement: it
    classifies the write-length source (mechanism), reports the reliable one-hop size flow, lists
    any upper-bound/guard shapes seen (each ``coverage=unjudged`` — presence only, never a
    dominance claim), and states honestly where the size trace stops. It NEVER decides
    "bounded / not" — that judgement is the agent's."""
    cs = classify_copy_size(pseudocode, sink_name)
    deps = _derives_map(pseudocode)
    if cs.size_var is not None:
        real = _real_vars(pseudocode, deps)
        one_hop = sorted(v for v in deps.get(cs.size_var, set()) if v in real)
    else:
        one_hop = []
    return {
        "size_kind": cs.kind,
        "size_flow": {"size_arg": cs.size_text, "size_var": cs.size_var, "one_hop": one_hop},
        "clamp_seen": [{"shape": s, "coverage": "unjudged"} for s in cs.clamps],
        "trace_boundary": _size_trace_boundary(pseudocode, cs.kind, cs.size_var, deps),
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
