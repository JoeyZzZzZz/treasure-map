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

from treasure_map.lib.pattern.classes import (
    CMD,
    COPY,
    FMT_STRING,
    FORMAT,
    SOURCE,
    all_format_calls_literal,
)
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
    fmt_string: frozenset[str]


def classify(callees: list[str]) -> CallClasses:
    """Bucket callee names into source / format / cmd / copy / fmt_string classes."""
    names = {c.strip() for c in callees if isinstance(c, str) and c.strip()}
    return CallClasses(
        source=frozenset(names & SOURCE),
        fmt=frozenset(names & FORMAT),
        cmd=frozenset(names & CMD),
        copy=frozenset(names & COPY),
        fmt_string=frozenset(names & FMT_STRING),
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


# Recall before precision: a dangerous sink callsite is a candidate even when no source is
# recognized in this function (the controlled input may arrive through a caller — a cross-function
# flow the intra-procedural scan cannot see). Source presence is a SCORING signal, not a detection
# gate: it sets source_class (external_input vs unknown) and the shape label; its absence lowers the
# downstream review score (see the analyzer / triage) rather than dropping the candidate. A bare
# sink that is never listed would be the most hidden false negative.


def _source_class(cc: CallClasses) -> str:
    return "external_input" if cc.source else "unknown"


def pattern_a(func_ref: FuncRef, callees: list[str], pseudocode: str) -> PatternMatch | None:
    """Command-injection shape: a shell-ish %s command string is built and run.

    Requires format + command sink + a shell-ish %s literal (a constructed shell command).
    Source is no longer a gate — when absent, source_class is 'unknown' and the shape drops the
    'source->' prefix; the value may still arrive from a caller (e.g. an argv/optarg path)."""
    cc = classify(callees)
    if not (cc.fmt and cc.cmd):
        return None
    literal = _shellish_format_literal(pseudocode)
    if literal is None:
        return None
    has_src = bool(cc.source)
    return _match(
        func_ref,
        "cmd_injection_shape",
        _source_class(cc),
        "cmd",
        "source->format->cmd" if has_src else "format->cmd",
        literal,
    )


def bare_cmd(func_ref: FuncRef, callees: list[str], pseudocode: str) -> PatternMatch | None:
    """Bare command-sink fallback: a command sink with NO constructed shell command.

    Fires only when pattern_a does not (no shell-ish %s literal). This is the recall net for
    command-exec sinks (system/popen/exec*) that pattern_a's shape gate would otherwise drop —
    listed at a low score (the analyzer marks it / downweights it), never silently omitted."""
    cc = classify(callees)
    if not cc.cmd:
        return None
    if cc.fmt and _shellish_format_literal(pseudocode) is not None:
        return None  # pattern_a owns the constructed-shell-command case
    return _match(
        func_ref,
        "bare_cmd_shape",
        _source_class(cc),
        "cmd",
        "source->cmd" if cc.source else "cmd",
        sorted(cc.cmd)[0],
    )


def pattern_b(func_ref: FuncRef, callees: list[str], pseudocode: str) -> PatternMatch | None:
    """Copy/overflow shape: a copy sink. Source is a scoring signal, not a gate.

    Evidence is the matched copy callee. When no source is recognized the shape is bare 'copy'
    (source_class 'unknown') and is downweighted downstream, not dropped."""
    cc = classify(callees)
    if not cc.copy:
        return None
    has_src = bool(cc.source)
    return _match(
        func_ref,
        "overflow_shape",
        _source_class(cc),
        "copy",
        "source->copy" if has_src else "copy",
        sorted(cc.copy)[0],
    )


def pattern_fmtstr(func_ref: FuncRef, callees: list[str], pseudocode: str) -> PatternMatch | None:
    """Format-string-injection shape: a logger/printf-family sink with a NON-LITERAL format arg.

    The literal-format exemption is the FP-suppression that GATES this recall (the overwhelmingly
    common syslog/printf passes a fixed format string and must not flood the candidate set): a sink
    is a candidate only when not all of its calls pass a literal format argument — i.e. at least one
    call's format-string position is a variable / constructed value (a format-string-injection
    suspect). Source presence is a SCORING signal, not a gate (same as pattern_b): a non-literal
    format with no recognized in-function source is still listed, just lower. The risky sink is
    chosen deterministically (sorted) so the evidence anchor is stable."""
    cc = classify(callees)
    if not cc.fmt_string:
        return None
    risky = sorted(s for s in cc.fmt_string if not all_format_calls_literal(pseudocode, s))
    if not risky:
        return None  # every format-string sink uses a fixed format -> exempt (no candidate)
    has_src = bool(cc.source)
    return _match(
        func_ref,
        "fmt_string_shape",
        _source_class(cc),
        "fmt_string",
        "source->fmt_string" if has_src else "fmt_string",
        risky[0],
    )


Detector = Callable[[FuncRef, list[str], str], "PatternMatch | None"]

# Explicit registry — one entry per shape, plain callables only. pattern_a and bare_cmd are
# mutually exclusive on the same function (bare_cmd defers when pattern_a's shell-ish literal is
# present), so each (function, sink class) yields at most one candidate.
DETECTORS: tuple[Detector, ...] = (pattern_a, bare_cmd, pattern_b, pattern_fmtstr)
