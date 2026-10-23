# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Recognize already-low-yield candidate forms.

These are FP-suppression signals, not verdicts: each names a neutral structural form known
(from manual review) to rarely carry a live issue, so review-ordering can rank it low. A
recognized form is recorded in the instance's existing `blocking_mechanism` field (a categorical
form note) and the read-side score table lowers it. Nothing here removes a candidate or grades
reachability; under doubt it stays silent (no form note), so a real candidate is never hidden.

★ This module no longer answers where a function's CODE came from. It used to, by reading the
symbol name, and that guess has been retired — see the note where it lived, below the charset
set. `origin` is written 'unknown' by the hunt now.

★ Parameter-specific by construction. A form downweight fires ONLY when the sink's dangerous
argument truly comes only from the recognized safe/constant source. If any free value — an
unsanitized string source or a caller-supplied parameter — also reaches that argument by a route
that bypasses the safe source, the downweight is suppressed (`free_taint_reaches`). Recognizing
"a safe thing exists in the function" is NOT the same as "the sink's dangerous argument is only
that safe thing"; conflating the two is how a constant-prefixed-but-tainted call, a branch-gating
(not value-flowing) external input, or a mixed safe+free format string would be wrongly hidden.

Name-based and intra-procedural by design (like the validator filters): it can miss, and it
prefers to stay silent rather than mislabel. There is no library recognition here (see the
retired library_origin below): origin is not guessed from names.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from treasure_map.lib.hunt.facts import signature_slots
from treasure_map.lib.hunt.fmt_provenance import _string_literal, call_arguments
from treasure_map.lib.pattern.classes import (
    CMD,
    COPY,
    FORMAT,
    FORMAT_ARG,
    SAFE_FORMS,
    SOURCE,
    _literal_spans,
    arg_ref,
    call_args_at,
    call_offsets,
)
from treasure_map.lib.reachability.taint import (
    _CALL_HEAD_RE,
    flows_into,
    free_taint_reaches,
)

# Leading callee name of a call expression (used to find builder calls in a statement).
_CALL_RE_HEAD = re.compile(r"\b([A-Za-z_]\w*)\s*\(")

# Neutral categorical form notes stored in blocking_mechanism. Each describes a mechanism, not
# a quality judgment. The read-side review-ordering table maps these to a strong downweight.
NO_SHELL_EXEC = "no_shell_exec"
NUMERIC_SANITIZED = "numeric_sanitized"
CALLER_CONSTANT = "caller_constant"
CONST_SINK_ARG = "const_sink_arg"
CHARSET_CONSTRAINED = "charset_constrained"

# exec-family sinks that replace the process image directly (execve(2) path) — no shell, so
# shell metacharacters in an argument are inert. system/popen/doSystem run via a shell and are
# deliberately NOT here.
_EXEC_NO_SHELL: frozenset[str] = frozenset(
    {"execl", "execlp", "execle", "execv", "execvp", "execve"}
)

# A shell explicitly launched through an exec sink ("/bin/sh -c <cmd>") is shell-like after all.
_SHELL_TARGET_RE = re.compile(r'"/bin/sh"|"/bin/bash"|"-c"')

# Shell-running command sinks whose FIRST argument is the command string itself. For these a
# literal first argument is a constant command (const_sink_arg). Exec-family sinks are excluded:
# their first argument is the program path (a constant path is normal) and the controllable argv
# is a later argument, so a literal first argument says nothing about the dangerous value.
_SHELL_RUN_SINKS: frozenset[str] = frozenset({"system", "popen", "doSystem"})

# Shell-running sinks whose first argument is a printf-style TEMPLATE, the command being the
# template with its varargs spliced in: doSystem("ifconfig %s up", name) runs whatever name holds.
_TEMPLATE_CMD_SINKS: frozenset[str] = frozenset({"doSystem"})
_CONVERSION_RE = re.compile(r"%(?!%)")


def _splices_a_variable(pseudocode: str, offset: int) -> bool:
    """The template call at ``offset`` has a conversion and a non-literal argument to fill it —
    or cannot be read, which counts the same."""
    args = call_args_at(pseudocode, offset)
    if not args:
        return True
    template = args[0].strip().replace("%%", "")
    if not _CONVERSION_RE.search(template):
        return False
    return any(not _LITERAL_ARG_RE.match(a) for a in args[1:])


# Numeric conversion / digit-check callees: a value passed through one is constrained to a
# number and cannot carry shell syntax.
_NUMERIC_VALIDATORS: frozenset[str] = frozenset(
    {
        "atoi",
        "atol",
        "atoll",
        "strtol",
        "strtoll",
        "strtoul",
        "strtoull",
        "strtoimax",
        "strtoumax",
        "isdigit",
        "isxdigit",
    }
)

# Converters whose OUTPUT is constrained to a safe character set (no shell metacharacters): MAC /
# IP address formatting and base64 ENCODING. NOT exhaustive — the list only needs to be useful;
# a missing converter merely leaves one safe candidate at its normal score (never a false miss),
# and a new device's converter is a one-line addition, not a defect. (base64/b64 DECODE is the
# opposite — it yields arbitrary bytes — and is treated as an input source elsewhere, not here.)
_CHARSET_SAFE: frozenset[str] = frozenset(
    {
        "ether_ntoa",
        "inet_ntoa",
        "inet_ntop",
        "base64_encode",
        "b64_encode",
    }
)

# ★ RETIRED: ``library_origin`` / ``_THIRD_PARTY_SYMBOL_RE`` — reading a symbol NAME to decide
# "this function belongs to a third-party library". It was a guess, and the same guess the
# by-name binary exclusion was retired for: it rests on symbols being named the way the upstream
# project names them, which a stripped firmware does not promise and a vendor is free to break by
# calling its own function ``SSL_xxx``.
#
# It was also weak where it was not wrong. It matched eight libraries' EXPORTED API prefixes, so a
# library's internal functions — most of its code — were already 'unknown' and already counted
# everywhere the label was meant to keep them out of. It labelled a small share of instances; the
# rest of the same libraries went through unlabelled. It never
# separated stock code from custom code, it skimmed the exported layer off the top.
#
# Nothing replaces it here. ``origin`` is written 'unknown' at both hunt call sites, which is the
# conservative direction (nothing is now guessed to be library code and therefore less worth
# looking at). The four-value column and its CHECK stay — see atlas_schema.sql — for a
# determinate classifier that reads content rather than names.


def _cmd_callees(callees: list[str]) -> set[str]:
    return {c.strip() for c in callees} & CMD


def _exec_is_no_shell(callees: list[str], pseudocode: str) -> bool:
    """The function's WHOLE command-sink capability is exec-without-a-shell.

    Parameter-specific: it is not enough that the anchored sink is an exec; the
    function must have NO shell-running command sink at all (`cmd ⊆ exec-no-shell`). A function
    that calls both system and execl is shell-capable and must never be downweighted no_shell."""
    cmd = _cmd_callees(callees)
    if not cmd or not (cmd <= _EXEC_NO_SHELL):
        return False
    return not _SHELL_TARGET_RE.search(pseudocode)


def _call_opens_with_a_string_literal(pseudocode: str, offset: int) -> bool:
    """True when the call whose ``(`` sits at ``offset`` opens with a direct string literal.

    The textual form of ``system("...")``. Split out from the search so the call POSITIONS come
    from the one authority (``call_offsets``) while this only judges what is written at one of
    them — a single regex doing both is how a reader stops agreeing with the enumerator.
    """
    j = offset + 1
    while j < len(pseudocode) and pseudocode[j].isspace():
        j += 1
    return j < len(pseudocode) and pseudocode[j] == '"'


def _sink_arg_is_literal(
    pseudocode: str,
    sink_name: str,
    sink_arg: str | None,
    stub_names: Mapping[int, str] | None = None,
    occurrence: int = 0,
) -> bool:
    """True when THIS candidate's sink argument is a fixed .rodata constant with no free value
    reaching it — `system("/sbin/reboot")`, the highest-frequency command false positive.

    ★ Red-line (never wrongly downweight): parameter-specific, tied to the anchored candidate's
    OWN callsite and sink_arg — NOT a whole-function search. Both guards are required:
      1. THIS candidate's call passes a DIRECT string literal (`system("...")`). It was once "some
         callsite in the function does", which was safe only while a command candidate described a
         whole function. Once each command callsite gets its own row, that form hands the row for
         `system(var)` the literal belonging to a `system("/sbin/reboot")` next to it, and guard 2
         only catches it when the variable is free-tainted — a plain global would slip through; and
      2. no free value (an in-function source output or a caller-supplied parameter) reaches this
         candidate's sink argument (`free_taint_reaches`).
    A whole-function regex satisfied only (1): a function with both `system("const")` and
    `system(free_var)` matched and wrongly downweighted the free candidate. Guard (2) closes that:
    when a free value reaches the anchored sink_arg the literal belongs to a DIFFERENT callsite, so
    the downweight is suppressed (fail-safe: keep the candidate at its normal score). A free-tainted
    argument therefore never coexists with a const_sink_arg note (Gate A), by construction.
    Restricted to shell-running sinks; an exec-family first argument is the program path, not the
    command."""
    if sink_name not in _SHELL_RUN_SINKS:
        return False
    offsets = call_offsets(pseudocode, sink_name, stub_names)
    if occurrence < 0 or occurrence >= len(offsets):
        return False
    if not _call_opens_with_a_string_literal(pseudocode, offsets[occurrence]):
        return False
    if sink_name in _TEMPLATE_CMD_SINKS and _splices_a_variable(pseudocode, offsets[occurrence]):
        return False  # a constant template is not a constant command: the vararg is the danger
    # Parameter-specific guard: a free value reaching this candidate's sink argument means the
    # literal above is a different callsite — do not downweight this (tainted) candidate.
    if sink_arg is not None and free_taint_reaches(pseudocode, sink_arg, safe_vars=set()):
        return False
    return True


def _constrained_results(pseudocode: str, path: set[str], converters: frozenset[str]) -> set[str]:
    """Variables on ``path`` that are the RESULT of a constraining converter (`lhs = …conv(…)`).

    Conversion-result only: a value laundered to a safe form is the conversion's output, not its
    input. This keeps the safe set sound — if a raw input ALSO reaches the sink by another route
    it is not in this set, so the bypass guard still sees it."""
    results: set[str] = set()
    for stmt in re.split(r"[;\n{}]", pseudocode):
        assign = re.match(r"\s*[^=]*?\b([A-Za-z_]\w*)\s*=\s*(?!=)(.*)", stmt)
        if assign is None:
            continue
        lhs, rhs = assign.group(1), assign.group(2)
        if lhs not in path:
            continue
        if any(re.search(rf"\b{re.escape(conv)}\s*\(", rhs) for conv in converters):
            results.add(lhs)
    return results


def _is_converter_call(text: str, converters: frozenset[str]) -> bool:
    """True when ``text`` (one call argument or assignment RHS) is a single inline converter
    call — `conv(...)`, allowing a leading cast `(type)` / address-of `&` / deref `*`. The
    converter's OUTPUT is charset-constrained by construction regardless of its inputs, so this
    recognizes the laundering even when the result is never bound to its own variable."""
    m = re.match(r"^[&*]?\s*(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(", text.strip())
    return m is not None and m.group(1) in converters


def _is_charset_benign(text: str, converters: frozenset[str]) -> bool:
    """True when ``text`` cannot introduce a free value: a literal (string/char/numeric/size
    constant) or a single inline charset-safe converter call. A bare identifier or any
    non-converter call is NOT benign — it may carry a free, uncontrolled value."""
    return bool(_LITERAL_ARG_RE.match(text.strip())) or _is_converter_call(text, converters)


# Bounded string-copy callees that move a value into their FIRST-argument buffer but are NOT in
# the global COPY set the taint graph uses (e.g. strlcpy breaks the dependency edge). The charset
# downweight does NOT use this — it is consumed only by the evidence layer to flag a copy/alias the
# dependency graph cannot follow (a trace boundary, not a downweight). Never used for recall.
_CHARSET_COPY_EXTRA: frozenset[str] = frozenset({"strlcpy", "strlcat", "stpcpy", "stpncpy"})


def _inline_constrained_results(pseudocode: str, converters: frozenset[str]) -> set[str]:
    """Variables whose value is built INLINE from charset-safe converter results / literals within
    a single builder/assignment expression — no intermediate-variable value tracking.

    A variable qualifies when EVERY write to it (a format/copy builder destination or a plain
    assignment) is a literal or an inline converter call, AND at least one write involves a
    converter — `snprintf(c,"...%s",ether_ntoa(x))` qualifies c. A value first copied into an
    intermediate variable and only then into this one (`strncpy(buf,ether_ntoa(x),n);
    snprintf(c,"%s",buf)`) does NOT qualify c: `buf` is a bare identifier in c's builder, not an
    inline converter. That is deliberate — charset recognition is inline-only; a value that passes
    through any intermediate variable is not value-tracked here (the evidence layer marks it
    `charset_maybe` instead). A later free write (`strcat(c,user)`) or a free value mixed into the
    same builder (`snprintf(c,"%s %s",ether_ntoa(x),raw)`) disqualifies the variable (all-writes
    rule)."""
    builders = FORMAT | COPY
    all_benign: dict[str, bool] = {}
    has_converter: dict[str, bool] = {}

    def _note(var: str, benign: bool, converter: bool) -> None:
        all_benign[var] = all_benign.get(var, True) and benign
        has_converter[var] = has_converter.get(var, False) or converter

    for stmt in re.split(r"[;\n{}]", pseudocode):
        for name in {m.group(1) for m in _CALL_RE_HEAD.finditer(stmt)} & builders:
            offsets = call_offsets(stmt, name)
            parts = call_args_at(stmt, offsets[0]) if offsets else None
            if not parts:
                continue
            dst = arg_ref(parts[0]).root
            if dst is None:
                continue
            value_args = parts[1:]
            benign = all(_is_charset_benign(a, converters) for a in value_args)
            converter = any(_is_converter_call(a, converters) for a in value_args)
            _note(dst, benign, converter)
        assign = re.match(r"\s*[^=]*?\b([A-Za-z_]\w*)\s*=\s*(?!=)(.*)", stmt)
        if assign is not None:
            lhs, rhs = assign.group(1), assign.group(2)
            _note(lhs, _is_charset_benign(rhs, converters), _is_converter_call(rhs, converters))

    return {var for var, benign in all_benign.items() if benign and has_converter.get(var)}


def _charset_inline_constrained(pseudocode: str, sink_arg: str) -> bool:
    """True when the SINK ARGUMENT itself is built inline from a charset-safe converter. Inline-only
    by design: a value laundered through any intermediate variable is not value-tracked here (it is
    left to the evidence layer to mark as a `charset_maybe` lead). The all-writes rule inside
    `_inline_constrained_results` rules out a free value written to the sink argument.

    This is the lenient PREMISE, shared with the evidence layer (which uses it for a `charset_maybe`
    recall hint). The downweight — a safety claim — adds F1 / F-escape / F-alias on top of it; see
    :func:`_charset_downweight`."""
    return sink_arg in _inline_constrained_results(pseudocode, _CHARSET_SAFE)


def _charset_downweight(pseudocode: str, sink_arg: str, sink_name: str | None = None) -> bool:
    """Charset downweight (hardened, H-3): the sink argument is built inline only from charset-safe
    converter output and literals (``_charset_inline_constrained`` — the all-writes-benign premise),
    AND it is a local array (F1) with no F-escape and no F-alias that could put a free value into it
    by a route the inline premise does not see.

    The premise's all-writes rule only inspects the FORMAT / COPY builders; a write through any
    other call, or an alias handed to one, is invisible to it. These guards close that — the same
    F1 / escape / alias the numeric path gets from :func:`_buffer_writes_all_safe` — without that
    function's "sink reads a pre-built buffer" model, so the copy-path shape where the sink itself
    builds the buffer (``strcpy(d, ether_ntoa(x))``) still qualifies. ``buf`` at the candidate's own
    sink (``sink_name`` — a command sink, or the thin command WRAPPER a propagated candidate
    forwards through), at any command sink, or at a whitelisted read is a read of the candidate,
    never an escape; ``buf`` at any other call that is not a recognized buffer writer escapes."""
    if not _charset_inline_constrained(pseudocode, sink_arg):
        return False
    if not _is_local_array(pseudocode, sink_arg):
        return False  # F1: a global / parameter could be written by a call this body does not show
    for m in re.finditer(r"([^;\n{}]*?)(?<![<>!=+\-*/%&|^~])=(?!=)([^;\n{}]*)", pseudocode):
        if _is_buf_alias(m.group(2), sink_arg):
            return False  # F-alias
    writers = _COPY_WRITE | _FORMAT_WRITE | _MEMSET
    for _off, name, args in _calls_in_function(pseudocode):
        positions = [i for i, a in enumerate(args) if _buf_contained(a, sink_arg)]
        if not positions:
            continue
        if all(p in _READONLY_ARG_POS.get(name, ()) for p in positions):
            continue  # whitelisted read position
        if positions == [0] and _is_buf_target(args[0], sink_arg) and name in writers:
            continue  # a buffer writer whose destination is buf (benign by the all-writes premise)
        if name == sink_name or name in _SHELL_RUN_SINKS or name in CMD:
            continue  # the candidate's sink / a command sink reads buf — that IS the candidate
        return False  # F-escape: buf handed to a call that is neither a safe write nor a read
    return True


# ── R5: numeric_sanitized by "every write to the sink buffer is safe" ─────────────────────────
#
# A command/path buffer is numeric-constrained only when EVERY write to it, in text order up to
# the sink, is a safe write: a literal, a memset with a constant, a single inline converter, or a
# format whose conversions are integer (or %s/%c filled by a literal / converter). Nothing escapes
# it, nothing aliases it, and it is a local array. The old "which SOURCE names reach it" reasoning
# is gone — correctness is here, not in a name list.

# Read-only argument positions: a call where the buffer sits at one of these does not write it.
# stat/lstat's path is arg0 (arg1 is the statbuf it WRITES, so it is not whitelisted).
_READONLY_ARG_POS: dict[str, tuple[int, ...]] = {
    "stat": (0,),
    "lstat": (0,),
    "access": (0,),
    "open": (0,),
    "open64": (0,),
    "fopen": (0,),
    "fopen64": (0,),
    "freopen": (0,),
    "unlink": (0,),
    "unlinkat": (1,),
    "remove": (0,),
    "strlen": (0,),
    "strnlen": (0,),
    "strcmp": (0, 1),
    "strncmp": (0, 1),
}
# Copy writers whose destination is arg0 and which are safe only when the source is a literal.
_COPY_WRITE: frozenset[str] = COPY | {"strcat", "__strcat_chk"}
_FORMAT_WRITE: frozenset[str] = frozenset(FORMAT_ARG)  # the printf-family buffer writers
_MEMSET = frozenset({"memset", "bzero", "__memset_chk"})
_STRING_OR_CHAR_LIT = re.compile(r'^\s*(?:L?"(?:[^"\\]|\\.)*"|L?\'(?:[^\'\\]|\\.)+\')\s*$')
_NUM_LIT = re.compile(r"^\s*[+-]?\s*(?:0[xX][0-9a-fA-F]+|\d+)[uUlL]*\s*$")
_CONV_SPEC_RE = re.compile(r"%[-+ #0]*(\*|\d+)?(?:\.(\*|\d+))?(?:hh|h|ll|l|L|j|z|t|q)?([a-zA-Z%])")
_POSITIONAL_RE = re.compile(r"%\d+\$")


def _is_literal_arg(text: str) -> bool:
    return bool(_STRING_OR_CHAR_LIT.match(text) or _NUM_LIT.match(text)) or text.strip() in (
        "NULL",
        "true",
        "false",
    )


def _fmt_content(text: str) -> str | None:
    """The concatenated content of a (possibly adjacent-concatenated) string literal, or None when
    the argument is not a literal format string."""
    t = text.strip()
    parts = re.findall(r'L?"((?:[^"\\]|\\.)*)"', t)
    if not parts or re.sub(r'\s*L?"(?:[^"\\]|\\.)*"\s*', "", t) != "":
        return None
    return "".join(parts)


def _format_write_safe(fmt_text: str, varargs: list[str], converters: frozenset[str]) -> bool:
    """A format write is safe when its format string is a literal whose conversions are integer
    (%d %i %u %x %X %o, width/precision ``*`` taking an int), or %s/%c whose matching vararg is a
    string/char literal or a single inline converter; and the conversions consume EXACTLY the
    varargs passed. %n / %p / float / positional (%N$) are never safe."""
    content = _fmt_content(fmt_text)
    if content is None or _POSITIONAL_RE.search(content):
        return False
    consumed = 0
    for m in _CONV_SPEC_RE.finditer(content):
        width, prec, conv = m.group(1), m.group(2), m.group(3)
        if conv == "%":
            continue
        if width == "*":
            consumed += 1  # an int width argument
        if prec == "*":
            consumed += 1  # an int precision argument
        if conv in "diuxXo":
            consumed += 1
        elif conv in "sc":
            if consumed >= len(varargs):
                return False
            va = varargs[consumed]
            if not (_STRING_OR_CHAR_LIT.match(va) or _is_converter_call(va, converters)):
                return False
            consumed += 1
        else:
            return False  # %n %p float, or an unknown conversion
    return consumed == len(varargs)


def _is_buf_target(text: str, buf: str) -> bool:
    """``text`` writes INTO the buffer: ``buf``, ``buf + k``, ``buf[k]``, ``*buf``, ``&buf`` or
    ``&buf[k]`` (casts allowed). The root is ``buf`` and the whole argument is about it."""
    ref = arg_ref(text)
    return ref.root == buf


def _is_buf_alias(rhs_text: str, buf: str) -> bool:
    """The right-hand side of an assignment stores a POINTER aliasing ``buf`` into another variable:
    ``buf``, ``&buf``, ``buf + k``, ``&buf[k]`` or a cast of these — ``arg_ref`` reads root ``buf``
    with a form that carries the pointer (``var`` / ``cast`` / ``addr_of`` / ``arith``).

    It is NOT an alias when the value is one READ out of the buffer (``buf[k]`` / ``*buf`` — a
    scalar, ``load`` form), nor when ``buf`` is merely an argument to a call on the right
    (``fp = fopen(buf,…)``, ``iVar = system(buf)`` — ``call`` form: the call is judged by the call
    loop as a read / write / escape, so treating it as an alias here would drop the mark twice).
    Catching the real aliases keeps an untrackable write through the alias from passing as safe;
    not catching a captured call return or an element read is what lets a constrained buffer
    qualify (this is the H-1 fix — the old whole-RHS token search flagged both)."""
    ref = arg_ref(rhs_text)
    return ref.root == buf and ref.form in ("var", "cast", "addr_of", "arith")


def _calls_in_function(pseudocode: str) -> list[tuple[int, str, list[str]]]:
    """(open-paren offset, callee name, top-level arguments) of every call, in text order, string
    literals skipped by ``call_args_at``. A call that never closes is left out."""
    out: list[tuple[int, str, list[str]]] = []
    for m in _CALL_HEAD_RE.finditer(pseudocode):
        off = m.end() - 1
        args = call_args_at(pseudocode, off)
        if args is not None:
            out.append((off, m.group(1), args))
    return out


def _brace_depths(pseudocode: str) -> list[int]:
    """Depth BEFORE the character at each index — ``{`` raises the following chars, ``}`` lowers
    from its own index on. String/char literals do not count."""
    depths = [0] * (len(pseudocode) + 1)
    d = 0
    i, n = 0, len(pseudocode)
    while i < n:
        ch = pseudocode[i]
        if ch == '"' or ch == "'":
            j = i + 1
            while j < n and pseudocode[j] != ch:
                j += 2 if pseudocode[j] == "\\" else 1
            for k in range(i, min(j + 1, n)):
                depths[k] = d
            i = j + 1
            continue
        if ch == "}":
            d -= 1
        depths[i] = d
        if ch == "{":
            d += 1
        i += 1
    depths[n] = d
    return depths


def _encloses_and_precedes(depths: list[int], write_pos: int, sink_pos: int) -> bool:
    """The block holding the write at ``write_pos`` also holds the sink at ``sink_pos`` and the
    write comes first: the write is earlier in text and the brace depth never drops below the
    write's between them (so the write's block has not closed before the sink)."""
    if write_pos >= sink_pos:
        return False
    base = depths[write_pos]
    return all(depths[i] >= base for i in range(write_pos, sink_pos))


# A C / Ghidra type word that can head a stack-array declaration (``char buf [N];``,
# ``undefined1 auStack_428 [1024];``). Deliberately NOT the taint layer's ``_TYPE_WORDS``, which
# folds in control keywords (``return`` / ``if`` / …): matching one of those before ``buf`` would
# read ``return buf[0];`` as a declaration. The word right before ``buf`` must be one of these.
_DECL_TYPE_PAT = (
    r"(?:undefined\d*|u?int\d{1,2}(?:_t)?|u?int|char|uchar|byte|sbyte|u?short|u?long|"
    r"longlong|ulonglong|wchar_t|void|bool|float|double|size_t|ssize_t|code|word|dword|qword)"
)


def _is_local_array(pseudocode: str, buf: str) -> bool:
    """``buf`` is declared as a local ARRAY in this function body (``T buf [N];``).

    Ghidra renders a stack array as a sized declaration — ``char acStack_38 [32];``, ``undefined1
    auStack_428 [1024];``. A named global (``cmd_buf``), a ``DAT_*`` / ``g_*`` symbol, a parameter,
    and a plain ``char *`` local — even one later indexed as ``buf[i]`` — have no sized declaration
    here, so none is read as a local array. Requiring the declaration, not merely that ``buf`` is
    indexed somewhere, is what keeps a symbol-named global out: a global can be written by a call
    this one function body does not show, which would defeat the "every write is safe" check that
    only a true local can make sound (``free`` direction: an unprovable local stays False, so the
    candidate keeps its score).

    The declaration is recognised by a real type token directly before ``buf`` and a sized ``[…]``,
    which a use (``buf[i] = …``, ``x = buf[i]``, ``return buf[0];``) never has — so the text may be
    one line (a compact fixture) or many (real output) without a line anchor."""
    if buf.startswith(("DAT_", "g_", "PTR_")):
        return False
    if buf in signature_slots(pseudocode):
        return False  # a parameter, not a local
    brace = pseudocode.find("{")
    body = pseudocode[brace + 1 :] if brace != -1 else pseudocode
    decl = rf"\b{_DECL_TYPE_PAT}\s+{re.escape(buf)}\s*(?:\[[^\[\]\n]*\]\s*)+;"
    return re.search(decl, body) is not None


def _buffer_writes_all_safe(
    pseudocode: str, buf: str, converters: frozenset[str], sink_pos: int
) -> bool:
    """Every write to ``buf`` up to the sink is a safe write: a literal, a constant memset,
    a single inline converter, or an integer/literal-only format; nothing escapes or aliases it;
    it is a local array; and at least one write is a format/converter (otherwise it is pure
    constant, not numeric-constrained)."""
    if not _is_local_array(pseudocode, buf):
        return False  # F1
    depths = _brace_depths(pseudocode)
    saw_fmt_or_conv = False

    def write_ok(pos: int) -> bool:
        return _encloses_and_precedes(depths, pos, sink_pos)

    # Assignments: a buf-target lvalue is a write; buf / &buf on the RHS of any other assignment is
    # an alias (F-alias).
    for m in re.finditer(r"([^;\n{}]*?)(?<![<>!=+\-*/%&|^~])=(?!=)([^;\n{}]*)", pseudocode):
        lhs, rhs = m.group(1).strip(), m.group(2)
        lpos = m.start()
        if lhs and _is_buf_target(lhs, buf):
            if not _is_literal_arg(rhs) or not write_ok(lpos):
                return False
            continue
        if _is_buf_alias(rhs, buf):
            return False  # F-alias: a pointer aliasing buf is stored into another variable

    for off, name, args in _calls_in_function(pseudocode):
        if off == sink_pos:
            continue  # the sink call itself (类三)
        positions = [i for i, a in enumerate(args) if _buf_contained(a, buf)]
        if not positions:
            continue
        ro = _READONLY_ARG_POS.get(name, ())
        if all(p in ro for p in positions):
            continue  # buf only at whitelisted read positions (类二): a read, never a write
        if positions == [0] and _is_buf_target(args[0], buf):
            # buf is the destination of this call.
            if name in _MEMSET:
                if len(args) < 2 or not _is_literal_arg(args[1]):
                    return False
                if not write_ok(off):
                    return False
                continue
            if name in _COPY_WRITE:
                src = args[1] if len(args) > 1 else ""
                if _STRING_OR_CHAR_LIT.match(src):
                    if not write_ok(off):
                        return False
                    continue
                if _is_converter_call(src, converters):
                    if not write_ok(off):
                        return False
                    saw_fmt_or_conv = True
                    continue
                return False
            if name in _FORMAT_WRITE:
                fpos = FORMAT_ARG.get(name)
                if fpos is None or fpos >= len(args):
                    return False
                if not _format_write_safe(args[fpos], args[fpos + 1 :], converters):
                    return False
                if not write_ok(off):
                    return False
                saw_fmt_or_conv = True
                continue
            return False  # a destination write by some other call
        return False  # F-escape: buf handed to a call that is neither a safe write nor a read

    return saw_fmt_or_conv


def _buf_contained(arg_text: str, buf: str) -> bool:
    """``buf`` appears as a token anywhere in this argument (so it is handed to the call)."""
    return re.search(rf"(?<![\w>.]){re.escape(buf)}(?![\w])", arg_text) is not None


def _value_is_constrained(
    pseudocode: str, sink_arg: str, converters: frozenset[str], sink_pos: int
) -> bool:
    """The sink buffer is numeric-constrained (R5): a converter result is on its path (the range
    filter), AND every write to the buffer up to the sink is a safe write
    (:func:`_buffer_writes_all_safe`). The old SOURCE-name reasoning is gone — a path with no
    converter result is simply not checked (no new mark), and correctness rests on the write
    check, not on which input names reach the argument."""
    path = {sink_arg} | flows_into(pseudocode, sink_arg)
    on_path = _constrained_results(pseudocode, path, converters)
    on_path |= _inline_constrained_results(pseudocode, converters) & path
    if not on_path:
        return False  # premise: no converter result on the path -> leave it unchecked
    return _buffer_writes_all_safe(pseudocode, sink_arg, converters, sink_pos)


_LITERAL_ARG_RE = re.compile(r'^\s*(?:"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)\'|[+-]?\d[\w.]*)\s*$')


def _address_taken(src: str, name: str) -> bool:
    """Whether ``src`` names ``name`` other than in a call — outside its own declaration line and
    outside string/char literals: a function pointer has callers no call site shows."""
    spans = _literal_spans(src)
    decl_end = src.find("{")
    for m in re.finditer(rf"\b{re.escape(name)}\b(?!\s*\()", src):
        if decl_end != -1 and m.start() < decl_end:
            continue
        if any(lo <= m.start() <= hi for lo, hi in spans):
            continue
        return True
    return False


def _caller_only_constants(
    func_name: str | None,
    callees: list[str],
    callers_pseudocode: list[str],
    *,
    pseudocode: str = "",
    sink_arg: str | None = None,
) -> bool:
    """One-hop: the sink's dangerous argument IS one of this function's parameters, the function
    neither reads external input nor rewrites that parameter, and EVERY call to it in EVERY
    caller passes a string/numeric literal at that parameter's position.

    Each condition closes a way a non-constant reached the sink while this read "constant":
      * the dangerous argument must be the parameter itself — a value the body looks up or reads
        from a global is not what the callers pass, whatever they pass;
      * the parameter's own position is checked, at every call: a caller whose first call passes a
        literal and whose second passes ``websGetVar(...)`` is a caller of the second kind too;
      * a function whose name is also used other than as a call (its address taken — a callback,
        a dispatch table) has callers this one hop cannot see.
    Conservative everywhere else: no callers, a call that cannot be read, an unnamed or unknown
    parameter all return False. Strictly one hop; it says nothing about callers of the callers,
    and the caller set it is given may itself be incomplete — which is why this note is a ranking
    hint and never a proof (see sink_impact.PROVABLY_CONSTANT_MARKERS)."""
    if not func_name or not callers_pseudocode or sink_arg is None:
        return False
    if {c.strip() for c in callees} & SOURCE:
        return False  # the function takes external input directly
    slots = signature_slots(pseudocode)
    if sink_arg not in slots:
        return False  # the dangerous value is not a parameter: what callers pass is not it
    k = slots.index(sink_arg)
    p = re.escape(sink_arg)
    body = pseudocode[pseudocode.find("{") + 1 :]
    if re.search(rf"\b{p}\s*(?:<<|>>|[-+*/%&|^])?=(?!=)|\+\+\s*{p}\b|\b{p}\s*(?:\+\+|--)", body):
        return False  # the parameter is rewritten before the sink: callers pass something else
    if re.search(rf"(?<!&)&\s*{p}\b", body):
        return False  # handed out by address: a callee may rewrite it
    for caller_src in callers_pseudocode:
        offsets = call_offsets(caller_src, func_name)
        if not offsets or _address_taken(caller_src, func_name):
            return False  # no call to read, or named other than as a call (a callback, a table)
        for off in offsets:
            args = call_args_at(caller_src, off)
            if args is None or k >= len(args) or not _LITERAL_ARG_RE.match(args[k]):
                return False
    return True


def detect_form_signal(
    *,
    sink_name: str | None,
    pseudocode: str,
    callees: list[str],
    sink_arg: str | None,
    func_name: str | None = None,
    callers_pseudocode: list[str] | None = None,
    stub_names: Mapping[int, str] | None = None,
    occurrence: int = 0,
    sink_class: str | None = None,
    sink_form: str | None = None,
) -> str | None:
    """Return one neutral form note to downweight this candidate, or None.

    Every branch is parameter-specific (see the module docstring): it fires only when the sink's
    dangerous argument truly comes only from the recognized safe/constant source. Returns None
    under any doubt (no downweight), so recall is never reduced — a missed downweight only leaves
    a candidate at its normal score.

    ``sink_form`` is the sink argument's :class:`classes.ArgRef` form. A note that makes the
    candidate look SAFE is trusted only when the root IS the value: numeric / charset need a safe
    form (``var`` / ``addr_of`` / ``cast``), caller_constant needs the argument to BE the parameter
    (``var`` / ``cast``, not ``&param``). A value read through a pointer / an expression / a call
    is never read as safe (its root is a base or an operand, not the value)."""
    offsets = call_offsets(pseudocode, sink_name, stub_names) if sink_name is not None else ()
    sink_pos = offsets[occurrence] if 0 <= occurrence < len(offsets) else -1
    # The call's own literal first: it is the per-callsite proof; caller_constant is a one-hop
    # hint read from callers that may not all be known, and must not stand in front of it.
    if sink_name is not None and _sink_arg_is_literal(
        pseudocode, sink_name, sink_arg, stub_names, occurrence
    ):
        return CONST_SINK_ARG
    if sink_form in ("var", "cast") and _caller_only_constants(
        func_name, callees, callers_pseudocode or [], pseudocode=pseudocode, sink_arg=sink_arg
    ):
        return CALLER_CONSTANT
    safe_form = sink_form in SAFE_FORMS
    if (
        safe_form
        and sink_arg is not None
        and _value_is_constrained(pseudocode, sink_arg, _NUMERIC_VALIDATORS, sink_pos)
    ):
        return NUMERIC_SANITIZED
    if safe_form and sink_arg is not None and _charset_downweight(pseudocode, sink_arg, sink_name):
        # Charset downweight (hardened): the sink argument is built inline only from charset-safe
        # converter output (MAC/IP/base64 formatting) and literals, it is a local array, and nothing
        # escapes or aliases it. A value laundered through an intermediate variable is not
        # value-tracked here (the evidence layer marks it `charset_maybe` instead).
        return CHARSET_CONSTRAINED
    if sink_class in (None, "cmd") and _exec_is_no_shell(callees, pseudocode):
        return NO_SHELL_EXEC  # a statement about the COMMAND sinks: not one for a path or format
    return None


def wrapper_propagation_form_note(
    pseudocode: str,
    wrapper_name: str,
    sink_arg: str | None,
    stub_names: Mapping[int, str] | None = None,
    occurrence: int | None = None,
    sink_form: str | None = None,
) -> str | None:
    """Form note for a wrapper-propagated command candidate (factor ①).

    The candidate's dangerous value is the argument the function forwards to a thin command
    wrapper, so the WRAPPER CALL stands in for the sink (its first argument is the forwarded
    command). The same FP-suppression as a direct sink applies, so a safe fanout — a function that
    just hands the wrapper a constant or a charset-constrained value — is downweighted and does not
    crowd the high band: a literal forwarded to the wrapper is a constant command; a numeric- or
    inline-charset-constrained argument cannot carry shell syntax. Returns None (no downweight) when
    the forwarded value is a free / constructed string — the real lead this recall step recovers.

    ``occurrence`` names the candidate's own call to the wrapper (0-based, text order, located with
    ``stub_names``). With it, "constant" means THAT call's first argument is exactly one string
    literal — a literal passed by a sibling call says nothing about this one. Without it (the
    function-level fallback) the historical whole-function test applies."""
    if occurrence is not None:
        args = call_arguments(pseudocode, wrapper_name, stub_names, occurrence)
        literal_first = args is not None and bool(args) and _string_literal(args[0]) is not None
    else:
        literal_first = bool(re.search(rf'\b{re.escape(wrapper_name)}\s*\(\s*"', pseudocode))
    # ★ Red-line: same parameter-specific guard as a direct sink. A literal forwarded to the
    # wrapper is a constant command ONLY when no free value also reaches this candidate's forwarded
    # argument — otherwise the literal is a different callsite and downweighting hides the lead.
    if literal_first and not (
        sink_arg is not None and free_taint_reaches(pseudocode, sink_arg, safe_vars=set())
    ):
        return CONST_SINK_ARG
    safe_form = sink_form in SAFE_FORMS
    if safe_form and sink_arg is not None:
        offsets = call_offsets(pseudocode, wrapper_name, stub_names)
        sink_pos = (
            offsets[occurrence]
            if occurrence is not None and 0 <= occurrence < len(offsets)
            else (offsets[0] if offsets else -1)
        )
        if _value_is_constrained(pseudocode, sink_arg, _NUMERIC_VALIDATORS, sink_pos):
            return NUMERIC_SANITIZED
    if (
        safe_form
        and sink_arg is not None
        and _charset_downweight(pseudocode, sink_arg, wrapper_name)
    ):
        return CHARSET_CONSTRAINED
    return None
