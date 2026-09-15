# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Semantic call classes — generic taint source/sink knowledge.

These frozensets describe WHAT COUNTS AS a source/formatter/command-sink/copy in
static security analysis — universal, mechanism-only knowledge. They carry only
generic, public C/libc and common-embedded API names; no vendor-proprietary symbol.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

# External-input getters, split by strength of external controllability (neutral,
# mechanism-based). Strength gates reachability grading only; R-pattern's shape detection
# uses the SOURCE union below and is unaffected by the split.

# Strong: network / request input — externally controllable by a remote party.
SOURCE_STRONG: frozenset[str] = frozenset(
    {
        "recv",
        "recvfrom",
        # Generic datagram / scatter-gather socket receives (IPC + network).
        "recvmsg",
        "recvmmsg",
        # Generic web/CGI parameter getters (public webserver API style).
        "websGetVar",
        "webGetVar",
        "getKeyValue",
        "get_cgi",
    }
)

# Weak: locally-influenced input — file/stream reads, environment, command-line args,
# config/device-self values. External controllability is not establishable within a single
# function.
SOURCE_WEAK: frozenset[str] = frozenset(
    {
        "read",
        "fread",
        "fgets",
        "gets",
        "scanf",
        "sscanf",
        "fscanf",
        # Stream/line/scatter reads (file + socket response bodies).
        "getline",
        "getdelim",
        "pread",
        "readv",
        "getenv",
        # Command-line / option parsing (the option argument is locally-influenced input).
        "getopt",
        "getopt_long",
        "getopt_long_only",
        # System-V / POSIX message-queue IPC receives.
        "msgrcv",
        "mq_receive",
        # Generic embedded config store ("non-volatile RAM") getters.
        "nvram_get",
        "nvram_safe_get",
        "nvram_bufget",
        # Generic base64 decoders.
        "b64_decode",
        "base64_decode",
        # JSON string getters — pull a string/buffer out of a parsed external object (a common
        # modern IoT request-input path). Only the value GETTERS are sources; the parser
        # (json_tokener_parse) yields an object, not a final string, and is not listed here.
        "json_object_get_string",
        "json_object_get_string_len",
    }
)

# Union — the set R-pattern uses for "is this callee an external-input source" (shape, not
# strength). Keep this equal to the historical SOURCE so R-pattern stays unchanged.
SOURCE: frozenset[str] = SOURCE_STRONG | SOURCE_WEAK

# String formatters: build a buffer from a format and arguments.
FORMAT: frozenset[str] = frozenset(
    {
        "snprintf",
        "sprintf",
        "vsnprintf",
        "vsprintf",
        "strcat",
        "strncat",
    }
)

# Command sinks: hand a string to a shell / new process image.
CMD: frozenset[str] = frozenset(
    {
        "system",
        "popen",
        "execl",
        "execlp",
        "execle",
        "execv",
        "execvp",
        "execve",
        # Generic "run a shell command" wrapper, common across embedded code.
        "doSystem",
    }
)

# Copies: move bytes into a destination buffer (length-taking or not). memmove has the same
# (dst, src, n) danger shape as memcpy and is graded on the same write-length axis.
COPY: frozenset[str] = frozenset(
    {
        "strcpy",
        "strncpy",
        "memcpy",
        "memmove",
    }
)

# Format-string-injection sinks: pass a format string to a logger / printf-family interpreter.
# The danger axis is the FORMAT-STRING argument position (NOT the destination/stream/level):
# a non-literal format argument is a format-string-injection suspect (%n write, %s/%x read). These
# do not build a buffer (so they are NOT in FORMAT, the buffer-formatter set) and are not commands.
# snprintf/sprintf are deliberately excluded — they are buffer formatters handled as copy/overflow.
FMT_STRING: frozenset[str] = frozenset(
    {
        "printf",
        "vprintf",
        "fprintf",
        "vfprintf",
        "dprintf",
        "vdprintf",
        "syslog",
        "vsyslog",
        "err",
        "errx",
        "verr",
        "verrx",
        "warn",
        "warnx",
        "vwarn",
        "vwarnx",
        "asprintf",
        "vasprintf",
    }
)

# The format-string argument index for each format-string sink (0-based). MUST be per-sink and
# correct: fprintf's format is arg1 (arg0 is the FILE*), syslog's is arg1 (arg0 is the log level),
# printf's is arg0. Blindly reading arg0 would treat a FILE*/level as the format — missing the
# real sink and mis-judging the safe ones. asprintf/vasprintf write to arg0 (char**) so the format
# is arg1.
FMT_STRING_ARG: dict[str, int] = {
    "printf": 0,
    "vprintf": 0,
    "warn": 0,
    "warnx": 0,
    "vwarn": 0,
    "vwarnx": 0,
    "fprintf": 1,
    "vfprintf": 1,
    "dprintf": 1,
    "vdprintf": 1,
    "syslog": 1,
    "vsyslog": 1,
    "err": 1,
    "errx": 1,
    "verr": 1,
    "verrx": 1,
    "asprintf": 1,
    "vasprintf": 1,
}

# Which argument of a BUFFER formatter is its format string. Distinct from FMT_STRING_ARG above,
# which is about the printf-family interpreters; these write into a destination instead, and their
# format sits after it. strcat / strncat are absent because they have no format string at all —
# absence here means "this callee has none", never "we did not look".
FORMAT_ARG: dict[str, int] = {
    "sprintf": 1,  # sprintf(dst, FMT, ...)
    "vsprintf": 1,  # vsprintf(dst, FMT, ap)
    "snprintf": 2,  # snprintf(dst, cap, FMT, ...)
    "vsnprintf": 2,  # vsnprintf(dst, cap, FMT, ap)
}

# Path / file sinks: a controllable PATH argument enables directory traversal / arbitrary file
# read / write / delete. Mechanism-only, generic libc/POSIX names (no vendor symbol). The danger
# axis is the PATH argument, whose position is per-sink (see PATH_SINK_ARG) — NOT always arg0.
PATH_SINK: frozenset[str] = frozenset(
    {
        # open for read/write (a controllable path -> traversal / arbitrary read-write)
        "fopen",
        "freopen",
        "open",
        "open64",
        "openat",
        # delete
        "unlink",
        "unlinkat",
        "remove",
        # move / rename
        "rename",
        "renameat",
        # directory create / remove / open
        "mkdir",
        "rmdir",
        "opendir",
    }
)

# The PATH argument index for each path/file sink (0-based). MUST be per-sink: fopen's path is
# arg0, but openat/unlinkat take a dirfd first so their path is arg1, and renameat's source path is
# arg1 (arg0 is olddirfd). Reading arg0 blindly would judge the dirfd, not the path — missing the
# real sink and mis-classifying a constant one. rename/renameat expose two path args; the source
# path (0 / 1) is taken this phase — the destination path is a later refinement.
PATH_SINK_ARG: dict[str, int] = {
    "fopen": 0,
    "freopen": 0,
    "open": 0,
    "open64": 0,
    "openat": 1,
    "unlink": 0,
    "unlinkat": 1,
    "remove": 0,
    "rename": 0,
    "renameat": 1,
    "mkdir": 0,
    "rmdir": 0,
    "opendir": 0,
}

# A whole argument that is a plain string literal (optionally an L"..." wide literal). A format
# argument matching this is a fixed format string — the overwhelmingly common, safe shape.
_FMT_LITERAL_RE = re.compile(r'^\s*L?"(?:[^"\\]|\\.)*"\s*$')
_IDENT_RE = re.compile(r"[A-Za-z_]\w*")


def _split_top_args(arglist: str) -> list[str]:
    """Split a call's argument text on top-level commas (respecting strings / parens / brackets)."""
    parts: list[str] = []
    depth = 0
    in_str = False
    buf: list[str] = []
    i = 0
    while i < len(arglist):
        ch = arglist[i]
        if in_str:
            buf.append(ch)
            if ch == "\\" and i + 1 < len(arglist):
                buf.append(arglist[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
            buf.append(ch)
        elif ch in "([":
            depth += 1
            buf.append(ch)
        elif ch in ")]":
            depth -= 1
            buf.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    if buf:
        parts.append("".join(buf))
    return parts


def _iter_format_args(pseudocode: str, sink_name: str) -> list[str | None]:
    """The format-argument text of EVERY call to ``sink_name`` (None when its position is absent).

    Iterates each call (balanced parentheses) so a function that calls a sink both with a literal
    and with a variable format is judged on all calls, never just the first."""
    pos = FMT_STRING_ARG.get(sink_name)
    if pos is None:
        return []
    out: list[str | None] = []
    for m in re.finditer(rf"\b{re.escape(sink_name)}\s*\(", pseudocode):
        i = m.end() - 1  # at the '('
        depth = 0
        for j in range(i, len(pseudocode)):
            ch = pseudocode[j]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    args = _split_top_args(pseudocode[i + 1 : j])
                    out.append(args[pos].strip() if pos < len(args) else None)
                    break
    return out


def all_format_calls_literal(pseudocode: str, sink_name: str) -> bool:
    """True only when EVERY call to ``sink_name`` passes a string-literal format argument.

    This is the exemption test (prove-safe-to-exempt): a sink is exempt only when all of its calls
    have a fixed format string. If any call's format argument is non-literal — or its position is
    unreadable — the function is NOT exempt (kept for recall; never miss a controllable format)."""
    fmt_args = _iter_format_args(pseudocode, sink_name)
    if not fmt_args:
        return False  # the call could not be located -> do not exempt
    return all(a is not None and bool(_FMT_LITERAL_RE.match(a)) for a in fmt_args)


def format_call_is_risky(pseudocode: str, sink_name: str, occurrence: int) -> bool:
    """True when the ``occurrence``-th call to ``sink_name`` passes a NON-literal format argument.

    The per-CALL form of ``all_format_calls_literal``. That one answers about the whole function
    (exempt only when EVERY call is literal), which is the right question for "does this function
    hold a candidate" and the wrong one for "is THIS call the risky one" — a function logging a
    fixed format ten times and a constructed one once is not ten candidates, and it is not one
    candidate that could be any of the eleven calls either.

    Same prove-safe-to-exempt direction as the function-level test: a call whose format position
    cannot be read counts as RISKY, never as exempt. An occurrence that is not there is not a call
    and so is not a candidate.
    """
    args = _iter_format_args(pseudocode, sink_name)
    if occurrence < 0 or occurrence >= len(args):
        return False
    arg = args[occurrence]
    return arg is None or not bool(_FMT_LITERAL_RE.match(arg))


def format_string_ident(pseudocode: str, sink_name: str) -> str | None:
    """Leading identifier of the FIRST non-literal format argument of ``sink_name`` (the danger
    axis), or None when every call's format argument is a literal / unreadable."""
    for arg in _iter_format_args(pseudocode, sink_name):
        if arg is None or _FMT_LITERAL_RE.match(arg):
            continue
        ident = _IDENT_RE.search(arg)
        if ident is not None:
            return ident.group(0)
    return None


def _iter_path_args(pseudocode: str, sink_name: str) -> list[str | None]:
    """The PATH-argument text of EVERY call to ``sink_name`` (None when its position is absent).

    Mirrors _iter_format_args but keyed on PATH_SINK_ARG (the per-sink path position), so a sink
    called several times (a constant path here, a variable path there) is judged on all calls."""
    pos = PATH_SINK_ARG.get(sink_name)
    if pos is None:
        return []
    out: list[str | None] = []
    for m in re.finditer(rf"\b{re.escape(sink_name)}\s*\(", pseudocode):
        i = m.end() - 1  # at the '('
        depth = 0
        for j in range(i, len(pseudocode)):
            ch = pseudocode[j]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    args = _split_top_args(pseudocode[i + 1 : j])
                    out.append(args[pos].strip() if pos < len(args) else None)
                    break
    return out


def all_path_calls_literal(pseudocode: str, sink_name: str) -> bool:
    """True only when EVERY call to ``sink_name`` passes a string-literal PATH argument.

    The prove-safe-to-mark-constant test (mirror of all_format_calls_literal): a path sink is a
    compile-time-constant path only when all of its calls have a literal path. If any call's path
    is a variable — or its position is unreadable — it is NOT constant (kept for recall; a
    controllable path is never washed into 'constant')."""
    path_args = _iter_path_args(pseudocode, sink_name)
    if not path_args:
        return False  # the call could not be located -> do not mark constant
    return all(a is not None and bool(_FMT_LITERAL_RE.match(a)) for a in path_args)


def path_arg_ident(pseudocode: str, sink_name: str) -> str | None:
    """Leading identifier of the FIRST non-literal PATH argument of ``sink_name`` (the value whose
    controllability matters), or None when every call's path is a literal / unreadable — the source
    kind of that identifier is then classified by the flow-evidence layer."""
    for arg in _iter_path_args(pseudocode, sink_name):
        if arg is None or _FMT_LITERAL_RE.match(arg):
            continue
        ident = _IDENT_RE.search(arg)
        if ident is not None:
            return ident.group(0)
    return None


# ── Call locations: one authority on "where are the calls to NAME" ──────────────────────────────


def call_offsets(pseudocode: str, name: str) -> tuple[int, ...]:
    """Offsets of the opening parenthesis of every textual call to ``name``, in source order.

    THE single authority on where a function's calls to one callee are, shared by the callsite
    enumerator below and by the per-call argument readers in the reachability layer. Sharing it is
    the point: a candidate anchored at "the 2nd memcpy call" and the call whose arguments actually
    get read have to be the SAME call. Two counts derived from two copies of this regex agree only
    by coincidence, and stop agreeing the first time either one is adjusted.
    """
    return tuple(m.end() - 1 for m in re.finditer(rf"\b{re.escape(name)}\s*\(", pseudocode))


@dataclass(frozen=True)
class SinkCallsite:
    """One textual call to a sink callee inside a function's pseudocode.

    ``index`` orders every call in the enumerated set by position, ACROSS callee names, so it names
    a callsite the same way on every re-scan of the same body. ``occurrence`` is the 0-based ordinal
    of this call among calls to ``sink_name`` alone — the number a per-call reader needs to look at
    THIS call rather than at the first one. They differ as soon as a function calls two different
    callees of the set (measured: 66 of 1380 copy-carrying functions on one real firmware).

    Named for SINKS, not for copies: the buffer formatters are read on the same write-length axis
    and enumerate their callsites through the same function. One enumerator is the point — the
    detector that emits a candidate per call and the reader that classifies each call have to agree
    about which call is the second one.
    """

    index: int
    sink_name: str
    occurrence: int


def sink_callsites(pseudocode: str, sink_names: Iterable[str]) -> tuple[SinkCallsite, ...]:
    """Every textual call to one of ``sink_names``, in source order.

    A name with no textual call contributes nothing. The callee list can name a callee the
    decompiled body never spells out — ``pcVar1 = memcpy;`` followed by an indirect call through
    the pointer is the common form — and inventing a callsite for it would anchor a candidate at a
    call that is not there. What to do with an EMPTY result is the caller's decision and it is not
    "emit nothing": on one real firmware 49 of 1380 copy-carrying functions are in that state, so a
    caller that dropped them would trade a per-callsite gain for a silent recall loss.

    Callee-set agnostic on purpose — the copy sinks and the buffer formatters both come through
    here. It answers "where are the calls", never "which calls are worth a candidate".
    """
    sites = [
        (offset, name, occurrence)
        for name in sorted({n for n in sink_names if n})
        for occurrence, offset in enumerate(call_offsets(pseudocode, name))
    ]
    sites.sort()
    return tuple(
        SinkCallsite(index=index, sink_name=name, occurrence=occurrence)
        for index, (_offset, name, occurrence) in enumerate(sites)
    )
