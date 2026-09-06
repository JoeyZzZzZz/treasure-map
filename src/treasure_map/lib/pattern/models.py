# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Frozen result models for the call-sequence pattern primitive.

No behavior. A match is a CANDIDATE SHAPE / lead — never a claimed bug. Field names
mirror the cross-firmware pattern store's columns (neutral mechanism terms) without
importing that layer; a later aggregator maps these onto its own rows.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

# The structural shape a function's call sequence matched. A shape is a lead, not a
# verdict: whether any candidate is real is a separate, later reachability question.
# The bare_* kinds are the recall fallback: a dangerous sink callsite with no constructed
# shell command (cmd) — listed at a low score rather than silently dropped.
PatternKind = Literal[
    "cmd_injection_shape",
    "overflow_shape",
    "bare_cmd_shape",
    "fmt_string_shape",
    "path_sink_shape",
]


@dataclass(frozen=True)
class FuncRef:
    """A neutral reference to one matched function (no vendor/firmware identity)."""

    binary_name: str
    func_name: str | None
    func_id: int


@dataclass(frozen=True)
class PatternMatch:
    """One function whose callee set + body matched a call-sequence shape.

    evidence is raw, firmware-derived text (e.g. a matched format literal); it is local
    and ephemeral here. See scanner.scan's docstring: a persistence consumer must
    neutralize evidence before storing it.
    """

    func_ref: FuncRef
    pattern_kind: PatternKind
    source_class: str
    sink_class: str
    call_sequence_shape: str
    structural_fingerprint: str
    fingerprint_algo_version: str
    evidence: str


@dataclass(frozen=True)
class PatternStats:
    functions_scanned: int  # function rows considered (after the SQL pre-filter)
    # ★ The two below PARTITION functions_scanned:
    #     functions_with_callees + callee_parse_failed == functions_scanned
    # That equation is the whole point. It says every function the pre-filter admitted either
    # reached the detectors or is counted as a data gap — nothing is dropped on the way, by name
    # or otherwise. It is checked at runtime (see scanner.shape_scan_invariant_holds) and by Gate D.
    # functions whose callee list parsed non-empty — the detector inputs
    functions_with_callees: int
    # functions whose stored callees could not be parsed — a data gap, surfaced, never dropped
    callee_parse_failed: int
    pattern_a: int  # cmd_injection_shape matches
    pattern_b: int  # overflow_shape matches
    bare_cmd: int = 0  # bare_cmd_shape matches (cmd sink, no constructed shell command)
    fmt_string: int = 0  # fmt_string_shape matches (non-literal format-string sink)
    path_sink: int = 0  # path_sink_shape matches (path/file sink — fopen/open/unlink/rename/…)


@dataclass(frozen=True)
class ScanResult:
    matches: tuple[PatternMatch, ...]
    stats: PatternStats
