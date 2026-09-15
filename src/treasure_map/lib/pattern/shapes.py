# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Call-sequence shape detection.

classify() buckets a function's callees into semantic classes; the detectors then test for the
coarse shapes. A detector returns a LIST of PatternMatch (candidate shapes / leads) — empty when
the shape is absent, and never a claimed bug. The DETECTORS registry is an explicit tuple of plain
callables (no inheritance), so adding a shape is one entry plus one function. One detector may emit
more than one KIND: the command axis labels a candidate by whether a shell template was built,
which is a property of the candidate and not a reason for two enumerators.

A list rather than an optional single match because the unit a candidate describes is a CALL, not
a function — a function that copies a fixed 4 bytes at one call and a caller-supplied length at
the next holds two different facts, and one row per function could only ever carry one of them.
Beneath that every shape keeps the same floor: a callee the body never spells out as a call still
yields exactly one candidate, carrying no callsite ordinal, because dropping it would pay for the
split with a silent recall loss.
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
    PATH_SINK,
    SOURCE,
    all_format_calls_literal,
    format_call_is_risky,
    sink_callsites,
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
    path_sink: frozenset[str]


def classify(callees: list[str]) -> CallClasses:
    """Bucket callee names into source / format / cmd / copy / fmt_string / path_sink classes."""
    names = {c.strip() for c in callees if isinstance(c, str) and c.strip()}
    return CallClasses(
        source=frozenset(names & SOURCE),
        fmt=frozenset(names & FORMAT),
        cmd=frozenset(names & CMD),
        copy=frozenset(names & COPY),
        fmt_string=frozenset(names & FMT_STRING),
        path_sink=frozenset(names & PATH_SINK),
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
    *,
    sink_callsite_index: int | None = None,
    sink_callsite_occurrence: int | None = None,
) -> PatternMatch:
    """Build one match, with its fingerprint filled in.

    The callsite anchor is deliberately NOT part of the fingerprint basis (see
    fingerprint.structural_fingerprint): the fingerprint describes the SHAPE, and two calls in one
    function are the same shape. Every per-callsite sibling therefore shares one fingerprint and
    folds into one pattern row, which is what keeps the recurrence ledgers (distinct pseudocode
    hashes, distinct runs) reading the same after this split as before it."""
    partial = PatternMatch(
        func_ref=func_ref,
        pattern_kind=pattern_kind,
        source_class=source_class,
        sink_class=sink_class,
        call_sequence_shape=call_sequence_shape,
        structural_fingerprint="",
        fingerprint_algo_version=FINGERPRINT_ALGO_VERSION,
        evidence=evidence,
        sink_callsite_index=sink_callsite_index,
        sink_callsite_occurrence=sink_callsite_occurrence,
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


def pattern_cmd(func_ref: FuncRef, callees: list[str], pseudocode: str) -> list[PatternMatch]:
    """Command-sink shape: ONE candidate per command-sink CALLSITE (system/popen/exec*).

    ★ ONE enumerator, two KINDS. The injection shape and the bare-sink shape were two detectors
    that had to be kept mutually exclusive by hand, but they are not two shapes — they are one
    atom, a command sink being called, carrying a template signal or not. Both end at the same
    ``system()``. So the enumeration happens once, over the callsites, and the template signal only
    decides which kind each candidate is labelled with.

    ★ The KIND and the SHAPE STRING are reused exactly, never unified. A candidate with a shell-ish
    template is ``cmd_injection_shape`` / ``format->cmd`` and one without is ``bare_cmd_shape`` /
    ``cmd``, the same strings as before. That is load-bearing: the structural fingerprint is keyed
    on (pattern kind, sink class, source class, call-sequence shape), so inventing a unified kind —
    or changing either string — would move every command fingerprint at once and break the
    recurrence ledgers that count how widely a shape recurs. Splitting rows apart does NOT do that:
    the callsite anchor is deliberately outside the fingerprint basis (see ``_match``), so the
    siblings of one function share one fingerprint and fold into the pattern row they always had.

    Per callsite, because a command sink being called is the unit. Two ``system()`` calls in one
    function that builds a shell template used to produce ONE row — the second call had no row
    anywhere, which is the same disappearance the copy split exists to undo.

    It also retires an anchoring hazard rather than working around it: with one row per function
    the concrete sink had to be chosen from the callee list, and an ``execv`` sorting ahead of a
    coexisting ``system`` could mask the shell sink. Every command callsite now has its own row, so
    there is nothing left to mask.

    The template test stays FUNCTION-level (a shell-ish %s literal is built somewhere in this
    function), so all of a function's command callsites carry the same kind. Which call the literal
    actually feeds is a value question this text-level pass does not answer, and labelling only one
    callsite would claim it did.

    A function whose body spells out no call to any of its command callees yields exactly ONE
    candidate with no callsite anchor — the same recall floor the copy split keeps."""
    cc = classify(callees)
    if not cc.cmd:
        return []
    # A constructed shell command needs a formatter to build it AND a shell-ish literal to build.
    literal = _shellish_format_literal(pseudocode) if cc.fmt else None
    has_src = bool(cc.source)
    kind: PatternKind = "cmd_injection_shape" if literal is not None else "bare_cmd_shape"
    if literal is not None:
        shape = "source->format->cmd" if has_src else "format->cmd"
    else:
        shape = "source->cmd" if has_src else "cmd"
    sites = sink_callsites(pseudocode, cc.cmd)
    if not sites:
        return [_match(func_ref, kind, _source_class(cc), "cmd", shape, sorted(cc.cmd)[0])]
    return [
        _match(
            func_ref,
            kind,
            _source_class(cc),
            "cmd",
            shape,
            site.sink_name,
            sink_callsite_index=site.index,
            sink_callsite_occurrence=site.occurrence,
        )
        for site in sites
    ]


def pattern_b(func_ref: FuncRef, callees: list[str], pseudocode: str) -> list[PatternMatch]:
    """Copy/overflow shape: ONE candidate per copy CALLSITE. Source is a scoring signal, not a gate.

    Per callsite, not per function, because the axis a copy is read on — the write length — belongs
    to the CALL. One function copying a literal 4 bytes at its first call and a caller-supplied
    length at its second produced a single row anchored at the first: the bounded call stood in for
    the unbounded one, the length shown was the safe one, and the downstream demotion for a
    constant length then sank the whole function out of the first screen. The unbounded call had no
    row anywhere to be found by, which is the least visible way to lose a candidate.

    Evidence is the copy callee AT THIS CALLSITE, and sink_callsite_index / _occurrence say which
    call it is, so the size reader downstream classifies THAT call's length.

    When the body spells out no call to any of the callees (``pcVar1 = memcpy;`` and an indirect
    call through the pointer — 49 of 1380 copy-carrying functions on one real firmware), the
    function still yields exactly ONE candidate with no callsite anchor: the function-level match
    it has always produced, byte-for-byte. Emitting nothing there would pay for the split with a
    silent recall loss, which is the trade this change exists to refuse."""
    cc = classify(callees)
    if not cc.copy:
        return []
    shape = "source->copy" if cc.source else "copy"
    sites = sink_callsites(pseudocode, cc.copy)
    if not sites:
        return [
            _match(func_ref, "overflow_shape", _source_class(cc), "copy", shape, sorted(cc.copy)[0])
        ]
    return [
        _match(
            func_ref,
            "overflow_shape",
            _source_class(cc),
            "copy",
            shape,
            site.sink_name,
            sink_callsite_index=site.index,
            sink_callsite_occurrence=site.occurrence,
        )
        for site in sites
    ]


def pattern_format(func_ref: FuncRef, callees: list[str], pseudocode: str) -> list[PatternMatch]:
    """Buffer-formatter write shape: ONE candidate per formatter CALLSITE.

    snprintf / sprintf / vsnprintf / vsprintf / strcat / strncat all build a string INTO a
    destination buffer. That is the same write-length axis a copy is read on, and until now not
    one of them produced a candidate — the class comment said they were "handled as copy/overflow"
    and nothing handled them. A formatter that overruns its destination was not a low-ranked lead;
    it had no row at all, which is the least visible way to miss one.

    Per callsite, and for the same reason pattern_b is: the length belongs to the CALL. One
    function can snprintf into a 64-byte cap at one call and sprintf with no bound at the next.

    ★ Whether a candidate EXISTS here does not depend on anything being decidable about it. Not on
    the format string — strcat has none and vsnprintf's is a variable — and not on the shape of the
    destination. A ``param_`` destination is a buffer the CALLER owns, which is the cross-function
    overflow this scan cannot see the size of, and dropping those would remove exactly the calls
    whose length is hardest to reason about. Every formatter callsite is a candidate; how much can
    be said about it is recorded separately.

    ★ This does NOT take the family away from the command-injection shape. A sprintf that builds a
    shell string still feeds pattern_cmd through ``cc.fmt``; the same call can be both a cmd
    candidate and a write-length candidate, under different refs.

    A function whose body spells out no call (the callee list names one, the text does not) yields
    ONE function-level candidate with no callsite anchor — the same recall floor pattern_b keeps."""
    cc = classify(callees)
    if not cc.fmt:
        return []
    shape = "source->format" if cc.source else "format"
    sites = sink_callsites(pseudocode, cc.fmt)
    if not sites:
        return [
            _match(
                func_ref,
                "format_overflow_shape",
                _source_class(cc),
                "format",
                shape,
                sorted(cc.fmt)[0],
            )
        ]
    return [
        _match(
            func_ref,
            "format_overflow_shape",
            _source_class(cc),
            "format",
            shape,
            site.sink_name,
            sink_callsite_index=site.index,
            sink_callsite_occurrence=site.occurrence,
        )
        for site in sites
    ]


def pattern_fmtstr(func_ref: FuncRef, callees: list[str], pseudocode: str) -> list[PatternMatch]:
    """Format-string-injection shape: ONE candidate per printf-family CALLSITE whose format
    argument is NOT a literal.

    The literal-format exemption is the FP-suppression that GATES this recall (the overwhelmingly
    common syslog/printf passes a fixed format string and must not flood the candidate set). It is
    applied PER CALL, not per function. A function that logs a fixed format ten times and a
    constructed one once used to yield a single candidate anchored at the sink NAME, which said
    only "somewhere in here this sink is called riskily" and left a reader to find which of the
    eleven calls it meant. The risky call now carries its own row and the ten exempt ones carry
    none.

    Source presence is a SCORING signal, not a gate (same as pattern_b): a non-literal format with
    no recognized in-function source is still listed, just lower.

    A sink that is risky at FUNCTION level but whose calls the body never spells out (``pcVar1 =
    syslog;`` and an indirect call) yields ONE candidate with no callsite anchor — the same recall
    floor pattern_b keeps; emitting nothing there would pay for the split with a silent recall
    loss. A call whose format position cannot be read counts as risky, never as exempt:
    prove-safe-to-exempt, never prove-dangerous-to-keep."""
    cc = classify(callees)
    if not cc.fmt_string:
        return []
    shape = "source->fmt_string" if cc.source else "fmt_string"
    sites = [
        site
        for site in sink_callsites(pseudocode, cc.fmt_string)
        if format_call_is_risky(pseudocode, site.sink_name, site.occurrence)
    ]
    if sites:
        return [
            _match(
                func_ref,
                "fmt_string_shape",
                _source_class(cc),
                "fmt_string",
                shape,
                site.sink_name,
                sink_callsite_index=site.index,
                sink_callsite_occurrence=site.occurrence,
            )
            for site in sites
        ]
    # No RISKY callsite located. Either every located call is exempt (a fixed format -> no
    # candidate, the FP gate doing its job), or the sink is risky but its calls are not in the
    # text — which is the recall floor, not an exemption, so it still yields one function-level
    # candidate. all_format_calls_literal tells the two apart: it is False when the calls could
    # not be located at all.
    risky = sorted(s for s in cc.fmt_string if not all_format_calls_literal(pseudocode, s))
    if not risky:
        return []
    return [_match(func_ref, "fmt_string_shape", _source_class(cc), "fmt_string", shape, risky[0])]


def pattern_path(func_ref: FuncRef, callees: list[str], pseudocode: str) -> list[PatternMatch]:
    """Path/file-sink shape: ONE candidate per path-sink CALLSITE (fopen/open/unlink/rename/...).

    Recall net for the whole path-sink class — a controllable path enables traversal / arbitrary
    file read-write.

    Per callsite, not per function, for the reason pattern_b is: the axis a path sink is read on —
    its PATH argument — belongs to the CALL. A function that opens a fixed "/etc/…" at one call and
    a caller-supplied name at the next produced ONE row, anchored at whichever callee name sorted
    first. So the constant path could stand in for the controllable one, and the demotion a
    hard-coded path earns would then sink the function's other, unexamined call with it.

    Source is a scoring signal, not a gate (same as pattern_b): the path may arrive from a caller,
    so a bare path sink with no recognized in-function source is still listed. Controllability of
    the path argument (constant / free / unknown) is decided downstream, on the per-sink PATH
    argument of THIS call.

    A function whose body spells out no call to any of its path callees still yields exactly ONE
    candidate with no callsite anchor — the function-level match it has always produced. Emitting
    nothing there would pay for the split with a silent recall loss."""
    cc = classify(callees)
    if not cc.path_sink:
        return []
    shape = "source->path_sink" if cc.source else "path_sink"
    sites = sink_callsites(pseudocode, cc.path_sink)
    if not sites:
        return [
            _match(
                func_ref,
                "path_sink_shape",
                _source_class(cc),
                "path_sink",
                shape,
                sorted(cc.path_sink)[0],
            )
        ]
    return [
        _match(
            func_ref,
            "path_sink_shape",
            _source_class(cc),
            "path_sink",
            shape,
            site.sink_name,
            sink_callsite_index=site.index,
            sink_callsite_occurrence=site.occurrence,
        )
        for site in sites
    ]


Detector = Callable[[FuncRef, list[str], str], "list[PatternMatch]"]

# Explicit registry — one entry per shape, plain callables only. The command axis is ONE entry
# emitting two kinds (a template signal picks which), rather than two detectors that had to be
# kept mutually exclusive by hand.
#
# HOW MANY candidates a (function, sink class) yields is the shape's own answer, not a rule of the
# registry. Every shape here yields one per CALLSITE, because the axis each is read on — a write
# length, a format argument, a path argument, the command string — belongs to the CALL and not to
# the function. Each keeps the same recall floor: exactly ONE function-level candidate, carrying no
# ordinal, when the body spells out no call to its callees. The old "at most one" held only while
# every shape was about a function, and reading it as a guarantee is what let a function's second
# copy call go unrepresented.
DETECTORS: tuple[Detector, ...] = (
    pattern_cmd,
    pattern_b,
    pattern_format,
    pattern_fmtstr,
    pattern_path,
)
