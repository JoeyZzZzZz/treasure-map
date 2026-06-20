# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Factor ① — one-hop thin-command-wrapper propagation (the L3 recall step).

A function whose real command sink hides inside a thin forwarding wrapper has no command sink
among its OWN direct callees, so the shape scan never surfaces it (the D-2 recall blind spot:
`f` builds a string and calls `notify_wrapper(s)`; the `system` is inside the wrapper). This
module recovers those candidates: a function `f` that calls a function `W` recognized as a thin
command wrapper (prep's `is_thin_cmd_wrapper`, with its `wrapped_sink`) becomes a command-sink
candidate whose sink is reached one hop through `W`.

Deliberately narrow (the only recall-amplifying step in L3, gated behind the FP-suppression
rounds, so it must not re-explode the candidate set):
- ONE hop only, INTRA-binary: `f -> W -> sink`. A wrapper reached through another function
  (`f -> g -> W`), an indirect/function-pointer call, or a wrapper in a different binary is NOT
  propagated (a known blind spot left to the agent, not silently followed).
- A function that already has a command sink among its direct callees is skipped — it is already
  a direct command candidate; propagation only recovers the functions whose sink is ONLY reachable
  through the wrapper.
- Name + same-binary match. The wrapper registry is keyed by (binary_id, function name); a callee
  name resolves to a wrapper only when a thin wrapper of that name exists in the SAME binary.

This finds a structural call-graph link; it makes no controllability or triggerability claim —
the source classification and blind-spot honesty ride on the per-candidate flow evidence.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from treasure_map.lib.diff.loader import FuncRow
from treasure_map.lib.hunt.facts import is_thin_cmd_wrapper
from treasure_map.lib.pattern.classes import CMD
from treasure_map.lib.pattern.oss import is_oss_binary


@dataclass(frozen=True)
class WrapperCandidate:
    """A function recovered as a command candidate because it calls a thin command wrapper.

    func is the caller (the new candidate); wrapper_name / wrapped_sink identify the one-hop
    wrapper it forwards through and the shell sink that wrapper runs."""

    func: FuncRow
    wrapper_name: str
    wrapped_sink: str


def _parse_callees(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return []
    return [str(x) for x in data] if isinstance(data, list) else []


def find_wrapper_propagated_candidates(
    funcs: list[FuncRow], known_components: set[str]
) -> list[WrapperCandidate]:
    """Return one WrapperCandidate per non-OSS function whose only command sink is reached one hop
    through a thin wrapper in the same binary. Deterministic (input order is binary, func id).

    ``known_components`` is the OSS-binary set (same exclusion the shape scan uses) so propagated
    candidates surface in custom binaries only."""
    # 1) Per-binary thin-wrapper registry: (binary_id, wrapper name) -> wrapped sink.
    wrappers: dict[tuple[int, str], str] = {}
    for f in funcs:
        if not f.name or not f.pseudocode:
            continue
        if is_oss_binary(f.binary_name, known_components=known_components):
            continue
        is_wrapper, wrapped_sink = is_thin_cmd_wrapper(f.pseudocode, _parse_callees(f.callees))
        if is_wrapper and wrapped_sink is not None:
            wrappers[(f.binary_id, f.name)] = wrapped_sink

    # 2) Callers of a same-binary wrapper that have no direct command sink of their own.
    out: list[WrapperCandidate] = []
    for f in funcs:
        if not f.pseudocode:
            continue
        if is_oss_binary(f.binary_name, known_components=known_components):
            continue
        callee_names = {c.strip() for c in _parse_callees(f.callees) if c.strip()}
        if callee_names & CMD:
            continue  # already a direct command candidate (the shape scan owns it)
        called = sorted(
            (name, wrappers[(f.binary_id, name)])
            for name in callee_names
            if (f.binary_id, name) in wrappers
        )
        if not called:
            continue
        wrapper_name, wrapped_sink = called[0]  # deterministic: first wrapper by name
        out.append(WrapperCandidate(func=f, wrapper_name=wrapper_name, wrapped_sink=wrapped_sink))
    return out
