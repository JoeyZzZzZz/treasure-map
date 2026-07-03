# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Factor ① — one-hop thin-wrapper propagation (the L3 recall step).

A function whose real sink hides inside a thin forwarding wrapper has no sink of that kind among
its OWN direct callees, so the shape scan never surfaces it (the D-2 recall blind spot: `f`
builds a string and calls `notify_wrapper(s)`; the sink is inside the wrapper). This module
recovers those candidates on TWO symmetric axes:
- COMMAND: `f` calls a thin command wrapper `W` (`is_thin_cmd_wrapper`, its `wrapped_sink` a
  shell sink) -> `f` becomes a command-sink candidate reached one hop through `W`.
- FORMAT STRING: `f` calls a thin format-string wrapper `W` (`is_thin_fmt_wrapper`, its
  `wrapped_sink` a printf-family sink) -> `f` becomes a format-string-sink candidate the same way.
Each candidate carries its `sink_class` so the downstream analyzer classifies and evidences it on
the correct axis (a fmt wrapper candidate is a fmt_string lead, never a cmd one).

Deliberately narrow (the only recall-amplifying step in L3, gated behind the FP-suppression
rounds, so it must not re-explode the candidate set):
- ONE hop only, INTRA-binary: `f -> W -> sink`. A wrapper reached through another function
  (`f -> g -> W`), an indirect/function-pointer call, or a wrapper in a different binary is NOT
  propagated (a known blind spot left to the agent, not silently followed). Cross-binary is a
  separate, deliberately unaddressed gap here.
- Per-axis skip: a function that already has a sink of THAT axis among its direct callees is
  skipped — it is already a direct candidate on that axis; propagation only recovers the functions
  whose sink of that kind is ONLY reachable through the wrapper.
- Name + same-binary match. The wrapper registry is keyed by (binary_id, function name); a callee
  name resolves to a wrapper only when a thin wrapper of that name exists in the SAME binary.

This finds a structural call-graph link; it makes no controllability or triggerability claim —
the source classification and blind-spot honesty ride on the per-candidate flow evidence.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from treasure_map.lib.diff.loader import FuncRow
from treasure_map.lib.hunt.facts import is_thin_cmd_wrapper, is_thin_fmt_wrapper
from treasure_map.lib.pattern.classes import CMD, FMT_STRING
from treasure_map.lib.pattern.oss import is_oss_binary


@dataclass(frozen=True)
class WrapperCandidate:
    """A function recovered as a candidate because it calls a thin forwarding wrapper.

    func is the caller (the new candidate); wrapper_name / wrapped_sink identify the one-hop
    wrapper it forwards through and the concrete sink that wrapper runs. sink_class is the axis
    the recovered sink lives on ("cmd" for a shell sink, "fmt_string" for a printf-family sink),
    so the downstream analyzer evidences and classifies it correctly."""

    func: FuncRow
    wrapper_name: str
    wrapped_sink: str
    sink_class: str


def _parse_callees(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return []
    return [str(x) for x in data] if isinstance(data, list) else []


def _axis_candidate(
    f: FuncRow,
    callee_names: set[str],
    direct_sinks: frozenset[str],
    wrappers: dict[tuple[int, str], str],
    sink_class: str,
) -> WrapperCandidate | None:
    """Recover ``f`` on one sink axis, or None. ``f`` is skipped when it has a direct sink of this
    axis (already a direct candidate). Otherwise the first same-binary wrapper it calls (by name,
    deterministic) yields the candidate."""
    if callee_names & direct_sinks:
        return None  # already a direct candidate on this axis (the shape scan owns it)
    called = sorted(
        (name, wrappers[(f.binary_id, name)])
        for name in callee_names
        if (f.binary_id, name) in wrappers
    )
    if not called:
        return None
    wrapper_name, wrapped_sink = called[0]  # deterministic: first wrapper by name
    return WrapperCandidate(
        func=f, wrapper_name=wrapper_name, wrapped_sink=wrapped_sink, sink_class=sink_class
    )


def find_wrapper_propagated_candidates(
    funcs: list[FuncRow], known_components: set[str]
) -> list[WrapperCandidate]:
    """Return the non-OSS functions whose only sink of a given axis is reached one hop through a
    thin wrapper in the same binary — on BOTH the command and the format-string axis. Deterministic
    (input order is binary, func id; per function the cmd candidate precedes the fmt one). A
    function can yield up to one candidate per axis (distinct sink classes reached).

    ``known_components`` is the OSS-binary set (same exclusion the shape scan uses) so propagated
    candidates surface in custom binaries only."""
    # 1) Per-binary thin-wrapper registries, one per axis: (binary_id, wrapper name) -> sink.
    cmd_wrappers: dict[tuple[int, str], str] = {}
    fmt_wrappers: dict[tuple[int, str], str] = {}
    for f in funcs:
        if not f.name or not f.pseudocode:
            continue
        if is_oss_binary(f.binary_name, known_components=known_components):
            continue
        callees = _parse_callees(f.callees)
        is_cmd, cmd_sink = is_thin_cmd_wrapper(f.pseudocode, callees)
        if is_cmd and cmd_sink is not None:
            cmd_wrappers[(f.binary_id, f.name)] = cmd_sink
        is_fmt, fmt_sink = is_thin_fmt_wrapper(f.pseudocode, callees)
        if is_fmt and fmt_sink is not None:
            fmt_wrappers[(f.binary_id, f.name)] = fmt_sink

    # 2) Callers of a same-binary wrapper that have no direct sink of that axis of their own.
    out: list[WrapperCandidate] = []
    for f in funcs:
        if not f.pseudocode:
            continue
        if is_oss_binary(f.binary_name, known_components=known_components):
            continue
        callee_names = {c.strip() for c in _parse_callees(f.callees) if c.strip()}
        cmd = _axis_candidate(f, callee_names, CMD, cmd_wrappers, "cmd")
        if cmd is not None:
            out.append(cmd)
        fmt = _axis_candidate(f, callee_names, FMT_STRING, fmt_wrappers, "fmt_string")
        if fmt is not None:
            out.append(fmt)
    return out
