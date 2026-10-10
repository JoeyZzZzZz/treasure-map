# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
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
the source classification and blind-spot honesty ride on the per-candidate flow evidence. That
per-candidate source classification is also where the analyzer applies a precision gate on the
FORMAT-STRING axis: a recovered fmt candidate whose forwarded value is not a controllable source
is dropped there (variadic loggers are ubiquitous, so recall amplification must rest on a
controllable input) — this finder stays purely structural and returns the candidate regardless.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass

from treasure_map.lib.diff.loader import FuncRow
from treasure_map.lib.hunt.facts import (
    fmt_wrapper_format_index,
    is_thin_cmd_wrapper,
    is_thin_fmt_wrapper,
)
from treasure_map.lib.pattern.classes import CMD, FMT_STRING, call_offsets


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
    # FORMAT-AXIS ONLY: the position of the wrapper's format parameter in its own signature, so the
    # caller's format argument can be read at the right INDEX rather than at argument 0 (which on
    # this axis is a stream / level / program name, not the format). None on the command axis, and
    # None on the format axis whenever the position could not be established — the reader then
    # declines to read any argument instead of guessing one. Computed where the wrapper's body is
    # in hand and the registry key already pins the binary, so it cannot be resolved against a
    # same-named function from a different binary.
    format_param_index: int | None = None
    # The wrapper's own entry address (as the extractor recorded it), so a reader can tell two
    # wrappers apart by identity rather than by name — a stripped binary names many of them
    # ``FUN_<addr>``, and a name alone would make two different functions look the same.
    wrapper_addr: str | None = None
    # Which call to the wrapper this candidate is: the 0-based ordinal among ``func``'s calls to
    # ``wrapper_name`` in TEXT order (``call_offsets``), not in address order. None for the
    # function-level fallback, emitted when no call to any wrapper can be found in the text.
    occurrence: int | None = None


def _parse_callees(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return []
    return [str(x) for x in data] if isinstance(data, list) else []


def _axis_candidates(
    f: FuncRow,
    callee_names: set[str],
    direct_sinks: frozenset[str],
    wrappers: dict[tuple[int, str], tuple[str, int | None, str | None]],
    sink_class: str,
    stub_names: Mapping[int, str] | None,
) -> list[WrapperCandidate]:
    """Recover ``f`` on one sink axis: one candidate per CALL to a same-binary wrapper.

    ``f`` is skipped entirely when it has a direct sink of this axis (already a direct candidate).
    Otherwise every wrapper it calls (by name, deterministic) contributes one candidate per call to
    it, in text order — each call forwards its own argument, so each is its own lead. The calls are
    counted with ``call_offsets`` and the SAME ``stub_names`` every per-call reader is later handed,
    so "the Nth call" here and the call whose argument gets read are the same call.

    When the callee list names a wrapper but no call to any of them can be found in the text (a
    call through a function pointer, ``(*ptr)(…)``), ONE function-level candidate is kept for the
    first wrapper by name, with ``occurrence`` None — never dropped, never guessed onto a call."""
    if callee_names & direct_sinks:
        return []  # already a direct candidate on this axis (the shape scan owns it)
    called = sorted(
        (name, wrappers[(f.binary_id, name)])
        for name in callee_names
        if (f.binary_id, name) in wrappers
    )
    if not called:
        return []
    pseudocode = f.pseudocode or ""
    out: list[WrapperCandidate] = []
    for wrapper_name, (wrapped_sink, fmt_index, wrapper_addr) in called:
        n = len(call_offsets(pseudocode, wrapper_name, stub_names))
        out.extend(
            WrapperCandidate(
                func=f,
                wrapper_name=wrapper_name,
                wrapped_sink=wrapped_sink,
                sink_class=sink_class,
                format_param_index=fmt_index,
                wrapper_addr=wrapper_addr,
                occurrence=k,
            )
            for k in range(n)
        )
    if out:
        return out
    wrapper_name, (wrapped_sink, fmt_index, wrapper_addr) = called[0]  # first wrapper by name
    return [
        WrapperCandidate(
            func=f,
            wrapper_name=wrapper_name,
            wrapped_sink=wrapped_sink,
            sink_class=sink_class,
            format_param_index=fmt_index,
            wrapper_addr=wrapper_addr,
        )
    ]


def find_wrapper_propagated_candidates(
    funcs: list[FuncRow],
    stub_by_binary: Mapping[int, Mapping[int, str]] | None = None,
) -> list[WrapperCandidate]:
    """Return the calls, in every binary, through which a function reaches a sink of a given axis
    one hop away — via a thin wrapper in the same binary — on BOTH the command and the format-string
    axis, for functions with no direct sink of that axis.

    One candidate per (axis, wrapper, call): ``occurrence`` is the call's 0-based ordinal among the
    function's calls to that wrapper in TEXT order (not address order). A function whose wrappers
    cannot be found as calls in its text keeps one function-level candidate per axis
    (``occurrence`` None). Deterministic: input order (binary, func id), then per function the cmd
    axis before the fmt one, then wrapper name, then occurrence ascending.

    No binary is skipped by name. A wrapper in a shared library forwards a caller's argument to a
    sink exactly as one in any other binary does, and which project a binary came from is a label
    for the read side to weigh, not grounds for the recall pass to never look.

    ``stub_by_binary`` (binary_id -> that binary's resolved stub table) lets the command-wrapper
    test find a sink call rendered as ``FUN_<stub-addr>(…)`` in a stripped binary; without it such
    a wrapper is not recognised, which is what happened before the table was threaded here."""
    # 1) Per-binary thin-wrapper registries, one per axis: (binary_id, wrapper name) -> sink.
    # The value carries the wrapper's own entry address too, so each candidate can name WHICH
    # function it forwards through (by identity, not just by name).
    cmd_wrappers: dict[tuple[int, str], tuple[str, int | None, str | None]] = {}
    fmt_wrappers: dict[tuple[int, str], tuple[str, int | None, str | None]] = {}
    for f in funcs:
        if not f.name or not f.pseudocode:
            continue
        callees = _parse_callees(f.callees)
        stub_names = stub_by_binary.get(f.binary_id) if stub_by_binary else None
        is_cmd, cmd_sink = is_thin_cmd_wrapper(f.pseudocode, callees, stub_names=stub_names)
        if is_cmd and cmd_sink is not None:
            cmd_wrappers[(f.binary_id, f.name)] = (cmd_sink, None, f.address)
        is_fmt, fmt_sink = is_thin_fmt_wrapper(f.pseudocode, callees)
        if is_fmt and fmt_sink is not None:
            # The format position is recorded HERE, with the wrapper's own body in hand. Doing it
            # later, from the candidate, would mean finding the wrapper by name again — and a name
            # is not unique across binaries (the same helper name really does carry different
            # bodies in different binaries here), so the position could be read off the wrong
            # function. The registry key is (binary_id, name), so this cannot happen.
            fmt_wrappers[(f.binary_id, f.name)] = (
                fmt_sink,
                fmt_wrapper_format_index(f.pseudocode, fmt_sink),
                f.address,
            )

    # 2) Callers of a same-binary wrapper that have no direct sink of that axis of their own.
    out: list[WrapperCandidate] = []
    for f in funcs:
        if not f.pseudocode:
            continue
        callee_names = {c.strip() for c in _parse_callees(f.callees) if c.strip()}
        stub_names = stub_by_binary.get(f.binary_id) if stub_by_binary else None
        out.extend(_axis_candidates(f, callee_names, CMD, cmd_wrappers, "cmd", stub_names))
        out.extend(
            _axis_candidates(f, callee_names, FMT_STRING, fmt_wrappers, "fmt_string", stub_names)
        )
    return out
