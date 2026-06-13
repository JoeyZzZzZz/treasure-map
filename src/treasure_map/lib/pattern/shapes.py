# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Call-sequence shape detection.

classify() buckets a function's callees into semantic classes; the detectors then test
for two coarse shapes. A detector returns a PatternMatch (a candidate shape / lead) or
None — it never claims a bug. The DETECTORS registry is an explicit tuple of plain
callables (no inheritance), so adding a shape is one entry plus one function.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, replace

from treasure_map.lib.pattern.classes import CMD, COPY, FORMAT, SOURCE
from treasure_map.lib.pattern.fingerprint import (
    FINGERPRINT_ALGO_VERSION,
    structural_fingerprint,
)
from treasure_map.lib.pattern.models import FuncRef, PatternKind, PatternMatch

# A quoted literal carrying %s is shell-ish if it names a system path, contains a shell
# metacharacter, or carries a command-style flag — i.e. it looks built to feed a shell.
_PATH_PREFIXES = ("/bin/", "/sbin/", "/usr/", "/tmp/")
_SHELL_METACHARS = ";|&>`"
_FLAG_RE = re.compile(r" -\w")
_QUOTED_LITERAL = re.compile(r'"((?:[^"\\]|\\.)*)"')


@dataclass(frozen=True)
class CallClasses:
    """The callees of one function, bucketed into semantic classes."""

    source: frozenset[str]
    fmt: frozenset[str]
    cmd: frozenset[str]
    copy: frozenset[str]


def classify(callees: list[str]) -> CallClasses:
    """Bucket callee names into source / format / cmd / copy classes."""
    names = {c.strip() for c in callees if isinstance(c, str) and c.strip()}
    return CallClasses(
        source=frozenset(names & SOURCE),
        fmt=frozenset(names & FORMAT),
        cmd=frozenset(names & CMD),
        copy=frozenset(names & COPY),
    )


def _is_shellish(literal: str) -> bool:
    if any(prefix in literal for prefix in _PATH_PREFIXES):
        return True
    if any(ch in literal for ch in _SHELL_METACHARS):
        return True
    return bool(_FLAG_RE.search(literal))


def _shellish_format_literal(pseudocode: str) -> str | None:
    """Return the first quoted literal containing %s that looks shell-ish, else None."""
    for literal in _QUOTED_LITERAL.findall(pseudocode):
        if "%s" in literal and _is_shellish(literal):
            return str(literal)
    return None


def _match(
    func_ref: FuncRef,
    pattern_kind: PatternKind,
    source_class: str,
    sink_class: str,
    call_sequence_shape: str,
    evidence: str,
) -> PatternMatch:
    partial = PatternMatch(
        func_ref=func_ref,
        pattern_kind=pattern_kind,
        source_class=source_class,
        sink_class=sink_class,
        call_sequence_shape=call_sequence_shape,
        structural_fingerprint="",
        fingerprint_algo_version=FINGERPRINT_ALGO_VERSION,
        evidence=evidence,
    )
    return replace(partial, structural_fingerprint=structural_fingerprint(partial))


def pattern_a(func_ref: FuncRef, callees: list[str], pseudocode: str) -> PatternMatch | None:
    """Command-injection shape: source + format + command sink, with a shell-ish %s literal."""
    cc = classify(callees)
    if not (cc.source and cc.fmt and cc.cmd):
        return None
    literal = _shellish_format_literal(pseudocode)
    if literal is None:
        return None
    return _match(
        func_ref,
        "cmd_injection_shape",
        "external_input",
        "cmd",
        "source->format->cmd",
        literal,
    )


def pattern_b(func_ref: FuncRef, callees: list[str], pseudocode: str) -> PatternMatch | None:
    """Overflow shape: source + a copy sink. Evidence is the matched copy callee name."""
    cc = classify(callees)
    if not (cc.source and cc.copy):
        return None
    return _match(
        func_ref,
        "overflow_shape",
        "external_input",
        "copy",
        "source->copy",
        sorted(cc.copy)[0],
    )


Detector = Callable[[FuncRef, list[str], str], "PatternMatch | None"]

# Explicit registry — one entry per shape, plain callables only.
DETECTORS: tuple[Detector, ...] = (pattern_a, pattern_b)
