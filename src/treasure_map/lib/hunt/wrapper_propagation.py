# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Factor ① — one-hop thin-wrapper propagation (the L3 recall step).

A function whose real sink hides inside a thin forwarding wrapper has no sink of that kind among
its OWN direct callees, so the shape scan never surfaces it (the D-2 recall blind spot: `f`
builds a string and calls `notify_wrapper(s)`; the sink is inside the wrapper). This module
recovers those candidates on THREE symmetric axes:
- COMMAND: `f` calls a thin command wrapper `W` (`is_thin_cmd_wrapper`, its `wrapped_sink` a
  shell sink) -> `f` becomes a command-sink candidate reached one hop through `W`.
- FORMAT STRING: `f` calls a thin format-string wrapper `W` (`is_thin_fmt_wrapper`, its
  `wrapped_sink` a printf-family sink) -> `f` becomes a format-string-sink candidate the same way.
- PATH: `f` calls a thin path wrapper `W` (`is_thin_path_wrapper`, its `wrapped_sink` a path/file
  sink such as fopen / unlink / rename) -> `f` becomes a path-sink candidate the same way.
Each candidate carries its `sink_class` so the downstream analyzer classifies and evidences it on
the correct axis (a fmt wrapper candidate is a fmt_string lead, never a cmd one).

The format and path axes are read by POSITION. Their dangerous argument is wherever the wrapper's
own signature puts the forwarded parameter, not the caller's argument 0 — a format wrapper's first
argument is often a stream or a level, and a path wrapper's is often a flag or a directory handle.
The position is recorded at registration, with the wrapper's body in hand; when it cannot be
established the candidate is still recovered, and nothing is read from the call.

Deliberately narrow (the only recall-amplifying step in L3, gated behind the FP-suppression
rounds, so it must not re-explode the candidate set):
- ONE hop only, INTRA-binary: `f -> W -> sink`. A wrapper reached through another function
  (`f -> g -> W`), an indirect/function-pointer call, or a wrapper in a different binary is NOT
  propagated (a known blind spot left to the agent, not silently followed). Cross-binary is a
  separate, deliberately unaddressed gap here.
- Per call, not per function: a function that also calls a sink of the same axis directly keeps
  its wrapper calls. Each call is its own candidate, and the direct sink's candidates name other
  calls — a constant `system("reboot")` beside `do_cmd(user_value)` once hid the second entirely.
- Name + same-binary match. The wrapper registry is keyed by (binary_id, function name); a callee
  name resolves to a wrapper only when a thin wrapper of that name exists in the SAME binary.
- On the PATH axis two further names are never registered: a name that is itself a path sink (the
  C library's own `open64` or `creat`, whose callers already hold a direct candidate for that very
  call), and a name more than one function of the binary carries (overloads of one C++ name): the
  registry holds one entry per name, so it would keep whichever came last and read every caller's
  argument at that one's positions. The command and format axes keep their registries as they were.

This finds a structural call-graph link; it makes no controllability or triggerability claim —
the source classification and blind-spot honesty ride on the per-candidate flow evidence. On the
FORMAT-STRING axis a recovered fmt candidate whose forwarded value is not shown controllable is
KEPT in the corpus and only demoted on the read side (variadic loggers are ubiquitous, so it is
counted, not dropped) — this finder stays purely structural and returns the candidate regardless.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass

from treasure_map.lib.diff.loader import FuncRow
from treasure_map.lib.hunt.facts import (
    fmt_wrapper_format_index,
    is_thin_cmd_wrapper,
    is_thin_fmt_wrapper,
    is_thin_path_wrapper,
    path_wrapper_param_positions,
)
from treasure_map.lib.pattern.classes import (
    _FMT_LITERAL_RE,
    PATH_SINK,
    ArgRef,
    arg_ref,
    call_args_at,
    call_offsets,
)

# The sink_class a path-axis candidate carries (the axis key the analyzer's label table uses).
PATH_SINK_CLASS = "path_sink"


@dataclass(frozen=True)
class WrapperCandidate:
    """A function recovered as a candidate because it calls a thin forwarding wrapper.

    func is the caller (the new candidate); wrapper_name / wrapped_sink identify the one-hop
    wrapper it forwards through and the concrete sink that wrapper runs. sink_class is the axis
    the recovered sink lives on ("cmd" for a shell sink, "fmt_string" for a printf-family sink,
    "path_sink" for a path/file sink), so the downstream analyzer evidences and classifies it
    correctly."""

    func: FuncRow
    wrapper_name: str
    wrapped_sink: str
    sink_class: str
    # FORMAT-AXIS ONLY: the position of the wrapper's format parameter in its own signature, so the
    # caller's format argument can be read at the right INDEX rather than at argument 0 (which on
    # this axis is a stream / level / program name, not the format). None on the command and path
    # axes, and None on the format axis whenever the position could not be established — the
    # reader then declines to read any argument instead of guessing one. Computed where the
    # wrapper's body is in hand and the registry key already pins the binary, so it cannot be
    # resolved against a same-named function from a different binary.
    format_param_index: int | None = None
    # The wrapper's own entry address (as the extractor recorded it), so a reader can tell two
    # wrappers apart by identity rather than by name — a stripped binary names many of them
    # ``FUN_<addr>``, and a name alone would make two different functions look the same.
    wrapper_addr: str | None = None
    # Which call to the wrapper this candidate is: the 0-based ordinal among ``func``'s calls to
    # ``wrapper_name`` in TEXT order (``call_offsets``), not in address order. None for the
    # function-level fallback, emitted when no call to any wrapper can be found in the text.
    occurrence: int | None = None
    # PATH-AXIS ONLY: every position in the wrapper's own signature whose parameter it forwards
    # into a path argument of ``wrapped_sink`` (``path_wrapper_param_positions``), ascending — the
    # caller's arguments at THESE indexes are the path, not its argument 0. None on the other two
    # axes, and None on the path axis when the position could not be established: the candidate is
    # still recovered, and the reader reads no argument of the call.
    path_param_positions: tuple[int, ...] | None = None
    # PATH-AXIS ONLY: True when every path argument the wrapper hands ``wrapped_sink`` is either a
    # literal inside the wrapper or a parameter at ``path_param_positions`` passed unchanged — the
    # one case in which literals from the caller at those positions make the sink's path constant.
    # False on the other two axes.
    path_fully_forwarded: bool = False


@dataclass(frozen=True)
class _Registered:
    """One registry entry: what a thin wrapper runs and how its caller's arguments are read."""

    wrapped_sink: str
    wrapper_addr: str | None
    format_param_index: int | None = None
    path_param_positions: tuple[int, ...] | None = None
    path_fully_forwarded: bool = False


# (binary_id, wrapper name) -> entry: one per axis.
_Registry = dict[tuple[int, str], _Registered]


def _parse_callees(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return []
    return [str(x) for x in data] if isinstance(data, list) else []


def _candidate(
    f: FuncRow, wrapper_name: str, entry: _Registered, sink_class: str, occurrence: int | None
) -> WrapperCandidate:
    return WrapperCandidate(
        func=f,
        wrapper_name=wrapper_name,
        wrapped_sink=entry.wrapped_sink,
        sink_class=sink_class,
        format_param_index=entry.format_param_index,
        wrapper_addr=entry.wrapper_addr,
        occurrence=occurrence,
        path_param_positions=entry.path_param_positions,
        path_fully_forwarded=entry.path_fully_forwarded,
    )


def _axis_candidates(
    f: FuncRow,
    callee_names: set[str],
    wrappers: _Registry,
    sink_class: str,
    stub_names: Mapping[int, str] | None,
) -> list[WrapperCandidate]:
    """Recover ``f`` on one sink axis: one candidate per CALL to a same-binary wrapper.

    Every wrapper it calls (by name, deterministic) contributes one candidate per call to it, in
    text order, whether or not ``f`` also calls a sink of this axis directly (those calls are their
    own candidates) — each call forwards its own argument, so each is its own lead. The calls are
    counted with ``call_offsets`` and the SAME ``stub_names`` every per-call reader is later handed,
    so "the Nth call" here and the call whose argument gets read are the same call.

    When the callee list names a wrapper but no call to any of them can be found in the text (a
    call through a function pointer, ``(*ptr)(…)``), ONE function-level candidate is kept for the
    first wrapper by name, with ``occurrence`` None — never dropped, never guessed onto a call."""
    called = sorted(
        (name, wrappers[(f.binary_id, name)])
        for name in callee_names
        if (f.binary_id, name) in wrappers
    )
    if not called:
        return []
    pseudocode = f.pseudocode or ""
    out: list[WrapperCandidate] = []
    for wrapper_name, entry in called:
        n = len(call_offsets(pseudocode, wrapper_name, stub_names))
        out.extend(_candidate(f, wrapper_name, entry, sink_class, k) for k in range(n))
    if out:
        return out
    wrapper_name, entry = called[0]  # first wrapper by name
    return [_candidate(f, wrapper_name, entry, sink_class, None)]


def find_wrapper_propagated_candidates(
    funcs: list[FuncRow],
    stub_by_binary: Mapping[int, Mapping[int, str]] | None = None,
) -> list[WrapperCandidate]:
    """Return the calls, in every binary, through which a function reaches a sink of a given axis
    one hop away — via a thin wrapper in the same binary — on the command, the format-string and the
    path axis, whether or not the function also calls a sink of that axis directly.

    One candidate per (axis, wrapper, call): ``occurrence`` is the call's 0-based ordinal among the
    function's calls to that wrapper in TEXT order (not address order). A function whose wrappers
    cannot be found as calls in its text keeps one function-level candidate per axis
    (``occurrence`` None). Deterministic: input order (binary, func id), then per function the cmd
    axis, then the fmt one, then the path one, then wrapper name, then occurrence ascending.

    No binary is skipped by name. A wrapper in a shared library forwards a caller's argument to a
    sink exactly as one in any other binary does, and which project a binary came from is a label
    for the read side to weigh, not grounds for the recall pass to never look.

    ``stub_by_binary`` (binary_id -> that binary's resolved stub table) lets the command-wrapper
    test find a sink call rendered as ``FUN_<stub-addr>(…)`` in a stripped binary; without it such
    a wrapper is not recognised, which is what happened before the table was threaded here. The
    format and path tests are handed the same table."""
    # 1) Per-binary thin-wrapper registries, one per axis.
    cmd_wrappers, fmt_wrappers, path_wrappers = _registries(funcs, stub_by_binary)

    # 2) Every call to a same-binary wrapper.
    out: list[WrapperCandidate] = []
    for f in funcs:
        if not f.pseudocode:
            continue
        callee_names = {c.strip() for c in _parse_callees(f.callees) if c.strip()}
        stub_names = stub_by_binary.get(f.binary_id) if stub_by_binary else None
        out.extend(_axis_candidates(f, callee_names, cmd_wrappers, "cmd", stub_names))
        out.extend(_axis_candidates(f, callee_names, fmt_wrappers, "fmt_string", stub_names))
        out.extend(_axis_candidates(f, callee_names, path_wrappers, PATH_SINK_CLASS, stub_names))
    return out


def _registries(
    funcs: list[FuncRow],
    stub_by_binary: Mapping[int, Mapping[int, str]] | None,
) -> tuple[_Registry, _Registry, _Registry]:
    """The command, format and path thin-wrapper registries: (binary_id, wrapper name) -> entry.

    The entry carries the wrapper's own entry address too, so each candidate can name WHICH
    function it forwards through (by identity, not just by name)."""
    # How many functions of each binary carry each name — every function row counts, a body or
    # not, exactly as the runner pass's link step counts them. Read by the path registry only.
    name_count = Counter((f.binary_id, f.name) for f in funcs if f.name)
    cmd_wrappers: _Registry = {}
    fmt_wrappers: _Registry = {}
    path_wrappers: _Registry = {}
    for f in funcs:
        if not f.name or not f.pseudocode:
            continue
        callees = _parse_callees(f.callees)
        stub_names = stub_by_binary.get(f.binary_id) if stub_by_binary else None
        is_cmd, cmd_sink = is_thin_cmd_wrapper(f.pseudocode, callees, stub_names=stub_names)
        if is_cmd and cmd_sink is not None:
            cmd_wrappers[(f.binary_id, f.name)] = _Registered(cmd_sink, f.address)
        is_fmt, fmt_sink = is_thin_fmt_wrapper(f.pseudocode, callees, stub_names=stub_names)
        if is_fmt and fmt_sink is not None:
            # The format position is recorded HERE, with the wrapper's own body in hand. Doing it
            # later, from the candidate, would mean finding the wrapper by name again — and a name
            # is not unique across binaries (the same helper name really does carry different
            # bodies in different binaries here), so the position could be read off the wrong
            # function. The registry key is (binary_id, name), so this cannot happen.
            fmt_wrappers[(f.binary_id, f.name)] = _Registered(
                fmt_sink,
                f.address,
                format_param_index=fmt_wrapper_format_index(f.pseudocode, fmt_sink, stub_names),
            )
        # The path registry refuses two names the other two keep. A name that is itself a path
        # sink is the C library's own (open64 calling open): each call to it is already a direct
        # path candidate, and registering it would recover that very call a second time. A name
        # more than one function of this binary carries cannot be keyed to one body: the entry
        # would be the last one seen, and every caller's path read at that one's positions.
        if f.name in PATH_SINK or name_count[(f.binary_id, f.name)] > 1:
            continue
        is_path, path_sink = is_thin_path_wrapper(f.pseudocode, callees, stub_names=stub_names)
        if is_path and path_sink is not None:
            # Positions recorded here, with the body in hand, for the reason given above.
            positions, fully = path_wrapper_param_positions(f.pseudocode, path_sink, stub_names)
            path_wrappers[(f.binary_id, f.name)] = _Registered(
                path_sink,
                f.address,
                path_param_positions=positions,
                path_fully_forwarded=fully,
            )
    return cmd_wrappers, fmt_wrappers, path_wrappers


# ── reading a path-axis candidate's call: the caller's arguments at the wrapper's positions ──
#
# The two readers below are the wrapper-axis forms of ``classes.path_arg_ref`` and
# ``classes.all_path_calls_literal``, with the caller's call to the wrapper standing in for the
# sink call and the wrapper's forwarded positions standing in for the sink's path positions. Same
# selection, same literal test, same whole-function rule for a constant: a path candidate reached
# through a wrapper is judged exactly as the direct one it stands for would be.


def _path_args_at(
    pseudocode: str,
    wrapper_name: str,
    positions: tuple[int, ...],
    stub_names: Mapping[int, str] | None,
) -> list[list[str | None]]:
    """The caller's argument texts at ``positions`` for EVERY call to ``wrapper_name``: one list
    per call, in text order, None where the call has no such argument or never closes.

    The calls come from ``call_offsets`` with the same ``stub_names`` the finder counted them with,
    so entry N here is the call candidate N is anchored at."""
    out: list[list[str | None]] = []
    for off in call_offsets(pseudocode, wrapper_name, stub_names):
        args = call_args_at(pseudocode, off)
        out.append(
            [args[p].strip() if args is not None and p < len(args) else None for p in positions]
        )
    return out


def path_wrapper_arg_ref(
    pseudocode: str,
    wrapper_name: str,
    positions: tuple[int, ...] | None,
    stub_names: Mapping[int, str] | None = None,
    occurrence: int | None = None,
) -> ArgRef | None:
    """The path a path-axis candidate's call hands its wrapper, read as ``classes.path_arg_ref``
    reads a direct sink's: among the caller's arguments at the wrapper's forwarded ``positions``,
    the first non-literal one that has a root (else the first non-literal one); a ``literal`` ref
    when every readable one is a literal; None when none could be read.

    ``occurrence`` reads the candidate's OWN call to the wrapper (0-based, text order, located with
    ``stub_names``); None reads across every call, the function-level reading.

    ``positions`` None — the wrapper's path position could not be established — reads nothing and
    answers None. Argument 0 is NOT read in its place: on this axis it is as often a flag or a
    directory handle as a path, and a constant there would pass for a constant path."""
    if not positions:
        return None
    calls = _path_args_at(pseudocode, wrapper_name, positions, stub_names)
    if occurrence is not None:
        if occurrence < 0 or occurrence >= len(calls):
            return None
        calls = [calls[occurrence]]
    first: ArgRef | None = None
    saw_literal = False
    for call in calls:
        # every forwarded position: a two-path wrapper's second as much as its first
        for arg in call:
            if arg is None:
                continue
            if _FMT_LITERAL_RE.match(arg):
                saw_literal = True
                continue
            ref = arg_ref(arg)
            if ref.root is not None:
                return ref
            if first is None:
                first = ref
    if first is None and saw_literal:
        return ArgRef("literal")
    return first


def path_wrapper_calls_literal(
    pseudocode: str,
    wrapper_name: str,
    positions: tuple[int, ...] | None,
    fully_forwarded: bool,
    stub_names: Mapping[int, str] | None = None,
) -> bool:
    """True only when every path the wrapper's sink is handed, at every call to the wrapper in
    this function, is a string literal: the wrapper fills the sink's path arguments from nothing
    but its parameters at ``positions`` and its own literals (``fully_forwarded``), and EVERY call
    to it passes a string literal at EVERY one of those positions.

    The direct path sink's constant rule, carried through the hop unchanged
    (``classes.all_path_calls_literal``): a call is a constant path only when each of its path
    arguments is a literal — ``W("/tmp/x", dest)`` into ``rename`` is not — and a function is
    judged on all its calls, so one variable call leaves its literal siblings unmarked too. A
    position that could not be established, a call that cannot be read, or no call found at all
    answers False: never marked constant on a reading that did not happen."""
    if not positions or not fully_forwarded:
        return False
    calls = _path_args_at(pseudocode, wrapper_name, positions, stub_names)
    if not calls:
        return False  # the call could not be located -> do not mark constant
    return all(a is not None and bool(_FMT_LITERAL_RE.match(a)) for call in calls for a in call)
