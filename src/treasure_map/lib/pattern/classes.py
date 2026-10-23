# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Semantic call classes — generic taint source/sink knowledge.

These frozensets describe WHAT COUNTS AS a source/formatter/command-sink/copy in
static security analysis — universal, mechanism-only knowledge. They carry only
generic, public C/libc and common-embedded API names; no vendor-proprietary symbol.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from treasure_map.lib.pattern.extractor_names import REGISTRY

# External-input getters, split by strength of external controllability (neutral,
# mechanism-based). Strength gates reachability grading only; the call-sequence shape detector
# uses the SOURCE union below and is unaffected by the split.
#
# Both sets list libc ABI aliases beside the base they mirror (the __libc_* and *_nocancel forms,
# the large-file *64 forms, *_unlocked, and the __isoc99_* scanf family): the C library exports
# these names for the same call, so matching only the base leaves a function that reads its input
# through one of them with no recognized source at all. Two boundaries, both real, neither closed
# here:
#   * The extractor's name lists (extractor_names.tsv: tokenizers / writers) match by exact name
#     and do not carry these aliases. Its provenance never reads source_class, so these record as
#     call_return either way; adding an alias THERE is a scan-side change with its own re-extract.
#   * reachability/taint keys its buffer- and return-seeding tables on the BASE names only, so an
#     alias is recognized as a source without seeding taint onto the buffer it fills. That
#     under-taints, the direction that biases to "unknown" rather than to a claim, but it does
#     make an alias weaker evidence than the name it mirrors.

# Strong: network / request input — externally controllable by a remote party.
SOURCE_STRONG: frozenset[str] = frozenset(
    {
        "recv",
        "__libc_recv",
        "__recv",
        "recvfrom",
        "__libc_recvfrom",
        # Generic datagram / scatter-gather socket receives (IPC + network).
        "recvmsg",
        "__libc_recvmsg",
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
        "__libc_read",
        "__read_nocancel",
        "fread",
        "fread_unlocked",
        "fgets",
        "fgets_unlocked",
        "gets",
        "scanf",
        "__isoc99_scanf",
        "sscanf",
        "__isoc99_sscanf",
        "fscanf",
        "__isoc99_fscanf",
        # Stream/line/scatter reads (file + socket response bodies).
        "getline",
        "getdelim",
        "__getdelim",
        "pread",
        "pread64",
        "__libc_pread",
        "__libc_pread64",
        "__pread64",
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

# Union — the set the shape detector uses for "is this callee an external-input source" (shape, not
# strength). Keep this equal to the historical SOURCE so the shape detector stays unchanged.
SOURCE: frozenset[str] = SOURCE_STRONG | SOURCE_WEAK

# String formatters: build a buffer from a format and arguments, or append to one. The _chk forms
# are the fortified (-D_FORTIFY_SOURCE) entry points a compiler substitutes for the plain calls;
# they write the same destination and carry an extra object-size argument (copy_size._OBJSIZE_ARG).
#
# This set and COPY together partition the extractor's buffer writers (extractor_names.tsv roles
# writer + writer_fmt): every writer is a copy or a formatter here, except strlcpy / strlcat, which
# truncate to the destination size they are given and are read only as writers, never as a
# candidate. The partition itself (copy vs. format/append) is not in the registry, so it is kept
# here and checked against it rather than derived from it.
FORMAT: frozenset[str] = frozenset(
    {
        "snprintf",
        "sprintf",
        "vsnprintf",
        "vsprintf",
        "strcat",
        "strncat",
        "__sprintf_chk",
        "__snprintf_chk",
        "__vsprintf_chk",
        "__vsnprintf_chk",
        "__strcat_chk",
        "__strncat_chk",
    }
)

# Command sinks: hand a string to a shell / new process image. Derived from the extractor registry
# (role sink_cmd) so the read side and the def-use pass name exactly the same sinks.
CMD: frozenset[str] = frozenset(REGISTRY.sink_cmd)

# Copies: move bytes into a destination buffer (length-taking or not). memmove has the same
# (dst, src, n) danger shape as memcpy and is graded on the same write-length axis. mempcpy and
# wmemcpy share that (dst, src, n) shape too — mempcpy returns dst+n, wmemcpy counts wide
# characters — and are graded on the same axis. Every length-taking name here MUST also appear in
# copy_size._SIZED_COPY, or its write length silently reads as untraced.
#
# Every copy here is also a buffer writer in the extractor registry (extractor_names.tsv), so the
# dominating-writer provenance that judges a stack buffer's fill knows the same copies; the _chk
# forms are the fortified entry points, with the length (where there is one) in the same position.
COPY: frozenset[str] = frozenset(
    {
        "strcpy",
        "strncpy",
        "memcpy",
        "memmove",
        "mempcpy",
        "wmemcpy",
        "stpcpy",
        "stpncpy",
        "__memcpy_chk",
        "__memmove_chk",
        "__mempcpy_chk",
        "__strcpy_chk",
        "__strncpy_chk",
        "__stpcpy_chk",
        "__stpncpy_chk",
    }
)

# Format-string-injection sinks: pass a format string to a logger / printf-family interpreter.
# The danger axis is the FORMAT-STRING argument position (NOT the destination/stream/level):
# a non-literal format argument is a format-string-injection suspect (%n write, %s/%x read). These
# do not build a buffer (so they are NOT in FORMAT, the buffer-formatter set) and are not commands.
# snprintf/sprintf are deliberately excluded — they are buffer formatters handled as copy/overflow.
# Derived from the extractor registry (role sink_fmt), the list the def-use pass traces.
FMT_STRING: frozenset[str] = frozenset(REGISTRY.sink_fmt)

# The format-string argument index for each format-string sink (0-based). MUST be per-sink and
# correct: fprintf's format is arg1 (arg0 is the FILE*), syslog's is arg1 (arg0 is the log level),
# printf's is arg0. Blindly reading arg0 would treat a FILE*/level as the format — missing the
# real sink and mis-judging the safe ones. asprintf/vasprintf write to arg0 (char**) so the format
# is arg1. The positions are the registry's sink_fmt key_idx — the argument the def-use pass reads.
FMT_STRING_ARG: dict[str, int] = dict(REGISTRY.sink_fmt)

# Which argument of a BUFFER formatter is its format string. Distinct from FMT_STRING_ARG above,
# which is about the printf-family interpreters; these write into a destination instead, and their
# format sits after it. strcat / strncat are absent because they have no format string at all —
# absence here means "this callee has none", never "we did not look". Derived from the extractor
# registry (role writer_fmt, fmt_idx): sprintf(dst, FMT, ...) -> 1, snprintf(dst, cap, FMT, ...)
# -> 2, __sprintf_chk(dst, flag, objsize, FMT, ...) -> 3, __snprintf_chk(dst, cap, flag, objsize,
# FMT, ...) -> 4.
FORMAT_ARG: dict[str, int] = dict(REGISTRY.writer_fmt)

# Path / file sinks: a controllable PATH argument enables directory traversal / arbitrary file
# read / write / delete. Mechanism-only, generic libc/POSIX names (no vendor symbol). The danger
# axis is the PATH argument, whose position is per-sink (see PATH_SINK_ARG) — NOT always arg0.
PATH_SINK: frozenset[str] = frozenset(
    {
        # open for read/write (a controllable path -> traversal / arbitrary read-write). The *64
        # names are the large-file (_FILE_OFFSET_BITS=64) variants with the same signatures.
        "fopen",
        "fopen64",
        "freopen",
        "freopen64",
        "open",
        "open64",
        "openat",
        "openat64",
        # create for writing (a controllable path -> arbitrary file creation)
        "creat",
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
        # truncate (a controllable path -> arbitrary file truncation)
        "truncate64",
    }
)

# The PATH argument index for each path/file sink (0-based). MUST be per-sink: fopen's path is
# arg0, but openat/openat64/unlinkat take a dirfd first so their path is arg1, and renameat's
# source path is arg1 (arg0 is olddirfd). Reading arg0 blindly would judge the dirfd, not the path
# — missing the real sink and mis-classifying a constant one. This is the FIRST path argument;
# a sink with more than one carries the rest in PATH_SINK_EXTRA_ARGS.
PATH_SINK_ARG: dict[str, int] = {
    "fopen": 0,
    "fopen64": 0,
    "freopen": 0,
    "freopen64": 0,
    "open": 0,
    "open64": 0,
    "openat": 1,
    "openat64": 1,
    "creat": 0,
    "unlink": 0,
    "unlinkat": 1,
    "remove": 0,
    "rename": 0,
    "renameat": 1,
    "mkdir": 0,
    "rmdir": 0,
    "opendir": 0,
    "truncate64": 0,
}

# Further path arguments, each as dangerous as the first: rename's destination (arg1) and
# renameat's (arg3, after newdirfd). A call is a constant path only when EVERY one of its path
# arguments is a literal — rename("/tmp/x", param_1) moves a fixed file to wherever the caller says.
PATH_SINK_EXTRA_ARGS: dict[str, tuple[int, ...]] = {"rename": (1,), "renameat": (3,)}

# A whole argument that is a plain string literal (optionally an L"..." wide literal). A format
# argument matching this is a fixed format string — the overwhelmingly common, safe shape.
_FMT_LITERAL_RE = re.compile(r'^\s*L?"(?:[^"\\]|\\.)*"\s*$')


def _iter_format_args(
    pseudocode: str, sink_name: str, stub_names: Mapping[int, str] | None = None
) -> list[str | None]:
    """The format-argument text of EVERY call to ``sink_name`` (None when its position is absent).

    Iterates each call (balanced parentheses) so a function that calls a sink both with a literal
    and with a variable format is judged on all calls, never just the first.

    The call positions come from ``call_offsets`` — the same authority the callsite enumerator
    counts with — so entry N here is the call candidate N is anchored at, and a call the decompiler
    rendered as ``FUN_<addr>(…)`` is included exactly when ``stub_names`` resolves that address to
    this sink. A second regex of its own would agree with the enumerator only until one of the two
    was adjusted."""
    pos = FMT_STRING_ARG.get(sink_name)
    if pos is None:
        return []
    out: list[str | None] = []
    for i in call_offsets(pseudocode, sink_name, stub_names):
        # one entry per call, an unreadable one included (as None): entry N must stay call N
        args = call_args_at(pseudocode, i)
        out.append(args[pos].strip() if args is not None and pos < len(args) else None)
    return out


def all_format_calls_literal(
    pseudocode: str, sink_name: str, stub_names: Mapping[int, str] | None = None
) -> bool:
    """True only when EVERY call to ``sink_name`` passes a string-literal format argument.

    This is the exemption test (prove-safe-to-exempt): a sink is exempt only when all of its calls
    have a fixed format string. If any call's format argument is non-literal — or its position is
    unreadable — the function is NOT exempt (kept for recall; never miss a controllable format)."""
    fmt_args = _iter_format_args(pseudocode, sink_name, stub_names)
    if not fmt_args:
        return False  # the call could not be located -> do not exempt
    return all(a is not None and bool(_FMT_LITERAL_RE.match(a)) for a in fmt_args)


def format_call_is_risky(
    pseudocode: str,
    sink_name: str,
    occurrence: int,
    stub_names: Mapping[int, str] | None = None,
) -> bool:
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
    args = _iter_format_args(pseudocode, sink_name, stub_names)
    if occurrence < 0 or occurrence >= len(args):
        return False
    arg = args[occurrence]
    return arg is None or not bool(_FMT_LITERAL_RE.match(arg))


def format_string_ident(
    pseudocode: str,
    sink_name: str,
    stub_names: Mapping[int, str] | None = None,
    occurrence: int | None = None,
) -> str | None:
    """Leading identifier of a non-literal format argument of ``sink_name`` (the danger axis).

    ``occurrence`` selects WHICH call to read. A per-callsite candidate must pass its own ordinal:
    it is anchored at the Nth call, so reporting the first call's argument would hand it a value
    the call it names never sees — and a downweight taken on that value would be decided by a
    different callsite entirely. A literal at that call yields None, which is the honest answer
    (this call's format is fixed) rather than a hunt for some other call's variable.

    ``occurrence=None`` keeps the function-level reading — the FIRST non-literal argument across
    all calls — for callers that hold no callsite, and is byte-for-byte what this always did.
    """
    ref = format_string_ref(pseudocode, sink_name, stub_names, occurrence)
    return ref.root if ref is not None else None


def format_string_call(
    pseudocode: str,
    sink_name: str,
    stub_names: Mapping[int, str] | None = None,
    occurrence: int | None = None,
    *,
    with_literal: bool = False,
) -> tuple[ArgRef, list[str]] | None:
    """The format argument ``format_string_ident`` reads, with every argument of the call it sits
    in: the first non-literal format argument that has a root (else the first non-literal one), or
    None when every call passes a literal format or none could be read. ``occurrence`` as in
    ``format_string_ident``. ``with_literal``: when every readable call passes a literal, give that
    as a ``literal`` ArgRef rather than None (None then means nothing could be read)."""
    pos = FMT_STRING_ARG.get(sink_name)
    if pos is None:
        return None
    literal_args: list[str] | None = None
    calls: list[list[str] | None] = [
        call_args_at(pseudocode, i) for i in call_offsets(pseudocode, sink_name, stub_names)
    ]
    if occurrence is not None:
        if occurrence < 0 or occurrence >= len(calls):
            return None
        calls = [calls[occurrence]]
    first: tuple[ArgRef, list[str]] | None = None
    for args in calls:
        if args is None or pos >= len(args):
            continue
        arg = args[pos].strip()
        if _FMT_LITERAL_RE.match(arg):
            if literal_args is None:
                literal_args = args
            continue
        ref = arg_ref(arg)
        if ref.root is not None:
            return ref, args
        if first is None:
            first = (ref, args)
    if first is None and literal_args is not None and with_literal:
        return ArgRef("literal"), literal_args
    return first


def format_string_ref(
    pseudocode: str,
    sink_name: str,
    stub_names: Mapping[int, str] | None = None,
    occurrence: int | None = None,
) -> ArgRef | None:
    """The format argument ``format_string_ident`` reads, as an ``ArgRef`` (its form included): a
    ``literal`` one when every readable call passes a literal format, None when none could be
    read."""
    found = format_string_call(pseudocode, sink_name, stub_names, occurrence, with_literal=True)
    return found[0] if found is not None else None


def _iter_path_args(
    pseudocode: str, sink_name: str, stub_names: Mapping[int, str] | None = None
) -> list[list[str | None]]:
    """The PATH-argument texts of EVERY call to ``sink_name``: one list per call, one entry per
    path argument (PATH_SINK_ARG, then PATH_SINK_EXTRA_ARGS), None where a position is absent.

    Mirrors _iter_format_args but keyed on the per-sink path positions, so a sink called several
    times (a constant path here, a variable path there) is judged on all calls — and, like it,
    takes its call positions from ``call_offsets`` so the enumerator and this reader cannot drift
    apart, stub-rendered calls included."""
    pos = PATH_SINK_ARG.get(sink_name)
    if pos is None:
        return []
    positions = (pos, *PATH_SINK_EXTRA_ARGS.get(sink_name, ()))
    out: list[list[str | None]] = []
    for i in call_offsets(pseudocode, sink_name, stub_names):
        # one entry per call, an unreadable one included (all None): entry N must stay call N
        args = call_args_at(pseudocode, i)
        out.append(
            [args[p].strip() if args is not None and p < len(args) else None for p in positions]
        )
    return out


def all_path_calls_literal(
    pseudocode: str, sink_name: str, stub_names: Mapping[int, str] | None = None
) -> bool:
    """True only when EVERY call to ``sink_name`` passes a string-literal PATH argument.

    The prove-safe-to-mark-constant test (mirror of all_format_calls_literal): a path sink is a
    compile-time-constant path only when all of its calls have a literal path. If any call's path
    is a variable — or its position is unreadable — it is NOT constant (kept for recall; a
    controllable path is never washed into 'constant').

    ★ ``stub_names`` matters here in the prove-safe direction: a stub-rendered call this reader
    cannot see is a call it cannot check, and marking a path constant while an unseen call passes a
    variable would be exactly the false safety the whole-function form of this test exists to
    avoid. With the table the unseen call is seen, and it can only ever turn 'constant' off."""
    path_args = _iter_path_args(pseudocode, sink_name, stub_names)
    if not path_args:
        return False  # the call could not be located -> do not mark constant
    return all(a is not None and bool(_FMT_LITERAL_RE.match(a)) for call in path_args for a in call)


def path_arg_ident(
    pseudocode: str,
    sink_name: str,
    stub_names: Mapping[int, str] | None = None,
    occurrence: int | None = None,
) -> str | None:
    """Leading identifier of a non-literal PATH argument of ``sink_name`` (the value whose
    controllability matters); the flow-evidence layer classifies that identifier's source kind.

    ``occurrence`` selects WHICH call to read, for the same reason it does on the format axis: a
    candidate anchored at the Nth call must be judged on the Nth call's path. A function that opens
    a fixed "/etc/…" at one call and a caller-supplied name at the next would otherwise hand BOTH
    rows the variable — including the row whose own path is a constant.

    ``occurrence=None`` keeps the function-level reading (first non-literal across all calls) for
    callers that hold no callsite.
    """
    ref = path_arg_ref(pseudocode, sink_name, stub_names, occurrence)
    return ref.root if ref is not None else None


def path_arg_ref(
    pseudocode: str,
    sink_name: str,
    stub_names: Mapping[int, str] | None = None,
    occurrence: int | None = None,
) -> ArgRef | None:
    """The path argument ``path_arg_ident`` reads, as an ``ArgRef``: the first non-literal path
    argument that has a root (else the first non-literal one); a ``literal`` one when every
    readable path argument is a literal; None when none could be read."""
    calls = _iter_path_args(pseudocode, sink_name, stub_names)
    if occurrence is not None:
        if occurrence < 0 or occurrence >= len(calls):
            return None
        calls = [calls[occurrence]]
    first: ArgRef | None = None
    saw_literal = False
    for call in calls:
        for arg in call:  # every path argument: rename's destination as much as its source
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


def _literal_spans(text: str) -> tuple[tuple[int, int], ...]:
    """(open_quote_index, close_quote_index) for every C string/char literal, escapes honoured.

    A ``name(`` whose paren falls inside one of these spans is text inside a printed message, not a
    call — the decompiler emits ``syslog(1,"... snprintf() failed")`` verbatim. Used by
    ``call_offsets`` to keep such a match from becoming a phantom callsite."""
    spans: list[tuple[int, int]] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == '"' or ch == "'":
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == ch or text[j] == "\n":
                    break
                j += 1
            spans.append((i, j))
            i = j + 1
        else:
            i += 1
    return tuple(spans)


def call_args_at(pseudocode: str, open_paren: int) -> list[str] | None:
    """The top-level argument texts (unstripped) of the call whose ``(`` is at ``open_paren``, or
    None when it never closes (a truncated body: no argument of it can be trusted).

    THE argument splitter every per-call reader shares. String and character literals are skipped
    whole — the same spans ``_literal_spans`` reads — so a ``(``, ``)`` or ``,`` written inside
    ``"…"`` or ``'…'`` neither opens, closes nor splits anything. Matching parentheses by bare
    characters let ``printf("done)\\n")`` close early and hand the NEXT call's arguments to this
    one. ``f()`` has no arguments: ``[]``."""
    n = len(pseudocode)
    args: list[str] = []
    buf: list[str] = []
    depth = 0
    i = open_paren
    while i < n:
        ch = pseudocode[i]
        if ch == '"' or ch == "'":
            j = i + 1
            while j < n and pseudocode[j] != ch and pseudocode[j] != "\n":
                j += 2 if pseudocode[j] == "\\" else 1
            end = min(j + 1, n)
            buf.append(pseudocode[i:end])
            i = end
            continue
        if ch in "([{":
            depth += 1
            if depth > 1:
                buf.append(ch)
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                if args or "".join(buf).strip():
                    args.append("".join(buf))
                return args
            buf.append(ch)
        elif ch == "," and depth == 1:
            args.append("".join(buf))
            buf = []
        elif depth >= 1:
            buf.append(ch)
        i += 1
    return None


# ── One argument, read: its root variable, its form, and the access path ──────────────────────

# Identifiers that are NOT variables: C/Ghidra type words and control keywords. (The taint layer
# reads these too, for the same reason — they must never become a flow edge.)
_TYPE_WORDS = frozenset(
    {
        "char",
        "int",
        "uint",
        "void",
        "short",
        "long",
        "size_t",
        "ssize_t",
        "bool",
        "unsigned",
        "signed",
        "float",
        "double",
        "const",
        "static",
        "struct",
        "union",
        "enum",
        "sizeof",
        "byte",
        "word",
        "dword",
        "qword",
        "code",
        "undefined",
        "return",
        "if",
        "else",
        "for",
        "while",
        "do",
        "switch",
        "case",
        "goto",
        "break",
        "continue",
    }
)
# Ghidra-style sized type words (undefined4, uint32, int8, ...) and the leftover of a split
# hex literal (0x96 -> "x96" once the leading 0 is dropped by the identifier regex).
_SIZED_TYPE_RE = re.compile(r"^(?:undefined|uint|int|u|byte|word|dword|qword|ushort|uchar)\d+$")
_HEX_FRAGMENT_RE = re.compile(r"^x[0-9a-fA-F]+$")
_EXTRA_TYPE_WORDS = frozenset(
    {
        "ushort",
        "uchar",
        "ulong",
        "longlong",
        "ulonglong",
        "sbyte",
        "wchar_t",
        "FILE",
        "off_t",
        "time_t",
        "pid_t",
        "uid_t",
        "gid_t",
        "mode_t",
    }
)
_FIXED_WIDTH_TYPE_RE = re.compile(r"^u?int\d+_t$")


def is_type_word(name: str) -> bool:
    """Whether ``name`` names a type (or a keyword), never a variable."""
    return (
        name in _TYPE_WORDS
        or name in _EXTRA_TYPE_WORDS
        or _SIZED_TYPE_RE.match(name) is not None
        or _FIXED_WIDTH_TYPE_RE.match(name) is not None
    )


# The forms an argument takes. ``literal`` a constant (string, character, number, NULL);
# ``var`` one variable; ``addr_of`` ``&var``; ``cast`` ``(T)var``; ``arith`` an expression whose
# first non-constant operand gives the root; ``load`` a value read through a pointer, an index or a
# field (``*p``, ``p[7]``, ``p->len``); ``call`` a call's return; ``const_addr`` a number cast to a
# pointer; ``none`` nothing a variable could be read from.
ARG_FORMS = ("literal", "var", "addr_of", "cast", "arith", "load", "call", "const_addr", "none")
# The forms in which the root IS the value passed: only these may support a reading that makes a
# candidate look safer (the value is a constant, a number, a checked character set).
SAFE_FORMS = frozenset({"var", "addr_of", "cast"})


@dataclass(frozen=True)
class ArgRef:
    """One call argument, read.

    ``form`` is one of ``ARG_FORMS``. ``root`` the variable the value is read from (for a load its
    base pointer; for an expression its first non-constant operand's), None for a literal, a
    constant address or nothing. ``lead`` the kind of that first operand (``var`` / ``load`` /
    ``call``); when it is ``load``, ``path`` is the whole access expression (outer cast removed,
    whitespace collapsed) — the thing a bound has to name, since a bound on ``p[0x14]`` is not a
    bound on ``p[7]``. ``cast_type`` the outermost cast's type text."""

    form: str
    root: str | None = None
    path: str | None = None
    cast_type: str | None = None
    lead: str | None = None


_NONE_REF = ArgRef("none")
_IDENT_FULL_RE = re.compile(r"[A-Za-z_]\w*")
# A Ghidra symbol label that carries '<' / '>' inside it (a string label made from text holding
# them): one token, not a comparison, and not a variable.
_ANGLE_LABEL_RE = re.compile(
    r"(?:DAT|PTR|s|u|LAB|UNK|FUN|SUB|EXT|switchD|caseD)_[A-Za-z0-9_<>]*[<>][A-Za-z0-9_<>]*"
)
_STRING_SEQ_RE = re.compile(r'(?:L?"(?:[^"\\\n]|\\.)*"\s*)+')
_CHAR_LIT_RE = re.compile(r"L?'(?:[^'\\\n]|\\.)+'")
_NUMBER_LIT_RE = re.compile(
    r"[+-]?\s*(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)[uUlLfF]*"
)
_SIZEOF_RE = re.compile(r"sizeof\s*(?:\(.*\)|[A-Za-z_]\w*)", re.DOTALL)
_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_TEMPLATE_TYPE_RE = re.compile(r"<[^<>]*>")
_UNARY = "*&-~!"


def _is_literal(t: str) -> bool:
    return (
        _STRING_SEQ_RE.fullmatch(t) is not None
        or _CHAR_LIT_RE.fullmatch(t) is not None
        or _NUMBER_LIT_RE.fullmatch(t) is not None
        or t in ("NULL", "true", "false")
    )


def _match_close(t: str, i: int) -> int:
    """Index of the bracket closing the one opened at ``t[i]``, literals skipped; -1 if none."""
    depth = 0
    n = len(t)
    j = i
    while j < n:
        ch = t[j]
        if ch == '"' or ch == "'":
            k = j + 1
            while k < n and t[k] != ch:
                k += 2 if t[k] == "\\" else 1
            j = k + 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return j
        j += 1
    return -1


def _is_type_text(inner: str) -> bool:
    """Whether a parenthesised text reads as a type: type words, names, ``*`` and spaces only
    (a C++ template's ``<…>`` allowed), at least one name, not starting with ``*``."""
    s = inner.strip()
    while _TEMPLATE_TYPE_RE.search(s):
        s = _TEMPLATE_TYPE_RE.sub(" ", s)
    if not s or s.startswith("*") or "sizeof" in s.split():
        return False
    if re.fullmatch(r"(?:[A-Za-z_]\w*|\*|\s)+", s) is None:
        return False
    return _IDENT_FULL_RE.search(s) is not None


def _split_cast(t: str) -> tuple[str, str] | None:
    """(type text, the rest) when ``t`` opens with a cast ``(T)``, else None. ``(n) - 1`` is not a
    cast: a single name that is not a type, followed by an operator."""
    if not t.startswith("("):
        return None
    close = _match_close(t, 0)
    if close <= 0 or close == len(t) - 1:
        return None
    inner, rest = t[1:close], t[close + 1 :].lstrip()
    if not rest or not _is_type_text(inner):
        return None
    head = rest[0]
    if not (head.isalnum() or head in "_\"'(" or head in _UNARY):
        return None
    words = inner.split()
    single_name = len(words) == 1 and "*" not in inner and "<" not in inner
    if single_name and not is_type_word(words[0]) and head in _UNARY:
        return None
    return " ".join(inner.split()), rest


def _top_level_operands(t: str) -> tuple[list[str], int | None] | None:
    """Split ``t`` on its top-level binary operators. Returns (operands, the index of the first
    operand after a top-level ``?``, or None) — or None when ``t`` has no top-level binary
    operator. ``->`` / ``.`` are not operators; a ``<`` /
    ``>`` counts only with whitespace on both sides; ``* & - ~ !`` at the start or after an
    operator are unary."""
    n = len(t)
    i = 0
    operands: list[str] = []
    start = 0
    prev_operand = False
    found = False
    branch_start: int | None = None
    while i < n:
        ch = t[i]
        if ch == '"' or ch == "'":
            k = i + 1
            while k < n and t[k] != ch:
                k += 2 if t[k] == "\\" else 1
            i = k + 1
            prev_operand = True
            continue
        if ch in "([{":
            close = _match_close(t, i)
            if close == -1:
                return None
            i = close + 1
            prev_operand = True
            continue
        if ch.isspace():
            i += 1
            continue
        if t.startswith("->", i):
            i += 2
            continue
        if ch == "." and not (i + 1 < n and t[i + 1].isdigit() and not prev_operand):
            i += 1
            continue
        if ch in "<>":
            two = t[i : i + 2]
            op = two if two in ("<<", ">>", "<=", ">=") else ch
            before = i == 0 or t[i - 1].isspace()
            after = i + len(op) >= n or t[i + len(op)].isspace()
            if before and after and prev_operand:
                operands.append(t[start:i])
                i += len(op)
                start = i
                prev_operand = False
                found = True
                continue
            i += len(op)
            continue
        if ch in "+-*/%&|^=!?:~":
            two = t[i : i + 2]
            if ch in _UNARY and not prev_operand:
                i += 1
                continue
            if two in ("&&", "||", "==", "!=", "+=", "-="):
                op_len = 2
            else:
                op_len = 1
            if ch == "!" and two != "!=":
                i += 1
                continue
            operands.append(t[start:i])
            if ch == "?" and branch_start is None:
                branch_start = len(operands)
            i += op_len
            start = i
            prev_operand = False
            found = True
            continue
        # a name or a number
        j = i
        while j < n and (t[j].isalnum() or t[j] == "_"):
            j += 1
        i = max(j, i + 1)
        prev_operand = True
    if not found:
        return None
    operands.append(t[start:])
    return [o.strip() for o in operands], branch_start


def _first_postfix(t: str) -> int:
    """Index of the first top-level ``[`` / ``->`` / ``.`` after a primary, or -1."""
    n = len(t)
    i = 0
    seen_primary = False
    while i < n:
        ch = t[i]
        if ch == '"' or ch == "'":
            k = i + 1
            while k < n and t[k] != ch:
                k += 2 if t[k] == "\\" else 1
            i = k + 1
            seen_primary = True
            continue
        if ch == "[" and seen_primary:
            return i
        if ch in "([{":
            close = _match_close(t, i)
            if close == -1:
                return -1
            i = close + 1
            seen_primary = True
            continue
        if seen_primary and (t.startswith("->", i) or ch == "."):
            return i
        if ch.isalnum() or ch == "_":
            seen_primary = True
        i += 1
    return -1


def _norm_space(t: str) -> str:
    return " ".join(t.split())


def arg_ref(arg_text: str) -> ArgRef:
    """Read one call argument (its text as ``call_args_at`` gives it): its form, its root variable,
    the access path when it is read through a pointer / index / field, and its outermost cast.

    Shared by every reader that names "the variable behind an argument", so that a type word, a
    string's first word, a hex literal's tail or a function name is never handed on as one."""
    return _arg_ref(arg_text, 0)


def _arg_ref(arg_text: str, depth: int) -> ArgRef:
    if depth > 24:
        return _NONE_REF
    t = _COMMENT_RE.sub(" ", arg_text).strip()
    cast_type: str | None = None
    while True:
        if not t:
            return ArgRef("none", cast_type=cast_type)
        if t.startswith("(") and _match_close(t, 0) == len(t) - 1:
            t = t[1:-1].strip()
            continue
        split = _split_cast(t)
        if split is not None:
            if cast_type is None:
                cast_type = split[0]
            t = split[1]
            continue
        break
    if _ANGLE_LABEL_RE.fullmatch(t):
        return ArgRef("none", cast_type=cast_type)
    if _is_literal(t) or _SIZEOF_RE.fullmatch(t):
        if cast_type is not None and cast_type.endswith("*"):
            return ArgRef("const_addr", cast_type=cast_type)
        return ArgRef("literal", cast_type=cast_type)
    ops = _top_level_operands(t)
    if ops is not None:
        operands, branch_start = ops
        if branch_start is not None:
            operands = operands[branch_start:]  # a ternary's value is one of its branches
        for operand in operands:
            if not operand or _SIZEOF_RE.fullmatch(operand):
                continue
            ref = _arg_ref(operand, depth + 1)
            if ref.form in ("literal", "const_addr"):
                continue
            return ArgRef("arith", ref.root, ref.path, cast_type, ref.lead)
        return ArgRef("literal", cast_type=cast_type)
    if t[0] in "-~!":
        inner = _arg_ref(t[1:], depth + 1)
        if inner.form in ("literal", "const_addr"):
            return ArgRef("literal", cast_type=cast_type)
        return ArgRef("arith", inner.root, inner.path, cast_type, inner.lead)
    if t.startswith("&"):
        rest = t[1:].strip()
        if _IDENT_FULL_RE.fullmatch(rest) and not is_type_word(rest):
            return ArgRef("addr_of", rest, None, cast_type, "var")
        inner = _arg_ref(rest, depth + 1)
        if inner.root is None:
            return ArgRef("none", cast_type=cast_type)
        return ArgRef("arith", inner.root, inner.path, cast_type, "load")
    if t.startswith("*"):
        return _load_ref(t, cast_type, depth)
    if _first_postfix(t) != -1:
        return _load_ref(t, cast_type, depth)
    m = re.match(r"([A-Za-z_]\w*)\s*\(", t)
    if m and not is_type_word(m.group(1)) and _match_close(t, m.end() - 1) == len(t) - 1:
        args = call_args_at(t, m.end() - 1) or []
        root = next((r.root for a in args if (r := _arg_ref(a, depth + 1)).root), None)
        return ArgRef("call", root, None, cast_type, "call")
    if _IDENT_FULL_RE.fullmatch(t):
        if is_type_word(t) or _HEX_FRAGMENT_RE.match(t):
            return ArgRef("none", cast_type=cast_type)
        return ArgRef("cast" if cast_type is not None else "var", t, None, cast_type, "var")
    return ArgRef("none", cast_type=cast_type)


def _load_ref(t: str, cast_type: str | None, depth: int) -> ArgRef:
    """A value read through a pointer / index / field: the base pointer as root, the whole access
    as the path."""
    base = t
    while base.startswith("*"):
        base = base[1:].strip()
    pos = _first_postfix(base)
    if pos != -1:
        base = base[:pos]
    inner = _arg_ref(base, depth + 1)
    return ArgRef("load", inner.root, _norm_space(t), cast_type, "load")


def _is_phantom_offset(paren_off: int, decl_end: int, spans: tuple[tuple[int, int], ...]) -> bool:
    """A regex ``name(`` hit that is NOT a call: on the function's own declaration line (paren
    before the body's opening brace ``decl_end``; ``decl_end == -1`` means no brace was found, so
    this rule is off), or with its paren inside a string/char literal span. See ``call_offsets``."""
    if decl_end != -1 and paren_off < decl_end:
        return True
    return any(lo < paren_off <= hi for lo, hi in spans)


# ── Call locations: one authority on "where are the calls to NAME" ──────────────────────────────

# A call the decompiler named after the stub it goes through (``FUN_0041eb38(...)``) rather than
# after the import behind it. The address is recoverable from the name, which is what lets a
# resolved stub table turn such a call back into a call to ``system`` / ``memcpy`` / ….
_STUB_CALL_RE = re.compile(r"\bFUN_([0-9a-fA-F]+)\s*\(")


def call_offsets(
    pseudocode: str,
    name: str,
    stub_names: Mapping[int, str] | None = None,
) -> tuple[int, ...]:
    """Offsets of the opening parenthesis of every call to ``name``, in source order.

    THE single authority on where a function's calls to one callee are, shared by the callsite
    enumerator below and by the per-call argument readers in the reachability layer. Sharing it is
    the point: a candidate anchored at "the 2nd memcpy call" and the call whose arguments actually
    get read have to be the SAME call. Two counts derived from two copies of this regex agree only
    by coincidence, and stop agreeing the first time either one is adjusted.

    ``stub_names`` maps a lazy-binding stub's ENTRY ADDRESS to the import it calls (see
    analyze/stub_resolve). When it is given, a call the decompiler rendered as ``FUN_0041eb38(...)``
    counts as a call to ``name`` whenever that address maps to ``name`` — merged into the same
    source order as the textual calls, so the Nth call is the Nth call however it was rendered. A
    plain mapping rather than the resolver's own dataclass keeps this layer free of the analyze
    layer; the caller passes ``resolution.names``.

    Without ``stub_names`` the answer is byte-for-byte what it has always been, which is what makes
    the recovery additive: every caller that has no resolution to hand behaves exactly as before.

    Two kinds of regex hit are NOT a call and are dropped (they used to invent a phantom callsite
    that shifted every real occurrence after it): a hit on the function's own DECLARATION (before
    the body's opening brace — a stub-named wrapper ``void FUN_x(...)`` whose entry address resolves
    to a sink), and a hit INSIDE a string/char literal (``syslog(1,"snprintf()")``).
    """
    spans = _literal_spans(pseudocode)
    decl_end = pseudocode.find("{")

    direct: list[int] = []
    for m in re.finditer(rf"\b{re.escape(name)}\s*\(", pseudocode):
        off = m.end() - 1
        if _is_phantom_offset(off, decl_end, spans):
            continue
        direct.append(off)
    if not stub_names:
        return tuple(direct)
    stubs: list[int] = []
    for m in _STUB_CALL_RE.finditer(pseudocode):
        if stub_names.get(int(m.group(1), 16)) != name:
            continue
        off = m.end() - 1
        if _is_phantom_offset(off, decl_end, spans):
            continue
        stubs.append(off)
    return tuple(sorted(direct + stubs))


# The same stub naming as ``_STUB_CALL_RE``, but for a bare name (a call token) rather than a call
# in running text: the WHOLE name must be ``FUN_<hex>``, so ``thunk_FUN_…`` is not a stub call.
_STUB_NAME_RE = re.compile(r"FUN_([0-9a-fA-F]+)")


def stub_resolved_name(token: str, stub_names: Mapping[int, str] | None) -> str | None:
    """The import a call token named after its stub (``FUN_<addr>``) resolves to, or None.

    The token-level twin of the stub mapping ``call_offsets`` applies to a ``FUN_<hex>(`` call in
    the text, with the same table, so a token and the call ``call_offsets`` counts resolve to the
    same name. None when the token is not exactly ``FUN_<hex>`` or its address is not in the table.
    """
    if not stub_names:
        return None
    m = _STUB_NAME_RE.fullmatch(token)
    if m is None:
        return None
    return stub_names.get(int(m.group(1), 16))


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


def sink_callsites(
    pseudocode: str,
    sink_names: Iterable[str],
    stub_names: Mapping[int, str] | None = None,
) -> tuple[SinkCallsite, ...]:
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
        for occurrence, offset in enumerate(call_offsets(pseudocode, name, stub_names))
    ]
    sites.sort()
    return tuple(
        SinkCallsite(index=index, sink_name=name, occurrence=occurrence)
        for index, (offset, name, occurrence) in enumerate(sites)
    )
