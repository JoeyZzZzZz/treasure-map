# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Neutral structural function-facts for the pattern analyzer.

A fact here is a STRUCTURAL observation about a function — a property of its body and the
call it makes — NOT a verdict and NOT an FP-suppression signal. A fact is recorded on the
candidate so a later analysis layer can consume it; recording a fact never changes a
candidate's recall or its review-ordering score on its own (the downweight/score path does
not read these fields).

is_thin_cmd_wrapper recognizes a "thin forwarding wrapper": a function whose body does little
more than hand one of its own parameters straight to a shell command sink
(system / popen / doSystem). is_thin_fmt_wrapper is its format-string counterpart: a thin
function that forwards a parameter straight into the FORMAT-STRING position of a printf-family
sink (fprintf's arg1, printf's arg0, syslog's arg1, …). is_thin_path_wrapper is the path/file
counterpart: a thin function that forwards a parameter straight into a PATH position of a path
sink (fopen's arg0, openat's arg1, either of rename's two). All three are structural facts about the
call graph and the function's shape — they deliberately do NOT claim the forwarded value is
attacker-controlled; that judgement is left to a later layer's positive evidence. Conservative
by construction: under any doubt they return (False, None), so a false fact is never asserted.

Name-based and intra-procedural by design (like the validator/downweight filters): it can
miss, and it prefers to stay silent rather than mislabel.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from treasure_map.lib.pattern.extractor_names import REGISTRY
from treasure_map.lib.pattern.sink_vocabulary import (
    _FMT_LITERAL_RE,
    FMT_STRING,
    PATH_SINK,
    _iter_path_args,
    arg_ref,
    format_string_call,
    path_arg_ref,
)
from treasure_map.lib.reachability.taint import (
    _CALLER_SUPPLIED_RE,
    _IDENT_RE,
    _TYPE_WORDS,
    locate_format_arg,
    locate_sink_arg,
)

# Shell-running command sinks whose FIRST argument IS the command string. A thin wrapper that
# forwards a parameter into one of these forwards the whole command. Exec-family sinks are
# excluded on purpose: their first argument is the program path, not the command string, so a
# parameter in the first slot says nothing about command forwarding (and exec-without-a-shell
# is inert for shell metacharacters anyway — handled by the no_shell_exec downweight elsewhere).
# The extractor registry's forward_cmd role — the same set its wrapper registry gates on.
_FORWARD_CMD_SINKS: frozenset[str] = REGISTRY.forward_cmd

# Buffer-building calls. If the forwarded argument is the destination of one of these, the
# value was constructed locally (format / concat / copy), so the function is NOT a verbatim
# forwarder — it builds a command, which is a different (and more interesting) shape. Every buffer
# writer the extractor knows (registry roles writer + writer_fmt), the same set the extractor's own
# wrapper test treats as a builder, so the two recognisers judge one body alike.
_BUILDERS: frozenset[str] = REGISTRY.writers

# N — a thin wrapper does ~one thing. We bound the function by its non-empty statement count
# (statements split on ; and block braces). FIXED here (and asserted in the tests). 20 (not the
# original 6) because a real command shell forwards `system(param)` AND then parses the return
# value (the WEXITSTATUS pattern: `r = system(p); if (r == -1) …; else if ((r & 0x7f) == 0) …`),
# which is ~14 statements unrelated to whether the argument is forwarded verbatim — the strict 6
# missed those real shells and recovered nothing. Five-device measurement confirmed 20 does not
# over-label: real command shells stay single-digit-to-low-teens per firmware (the verbatim-forward
# judgment ④ is what bounds it, not the statement count). Raising it only admits larger forwarders.
_WRAPPER_MAX_STATEMENTS = 20

_STMT_SPLIT_RE = re.compile(r"[;\n{}]")


def _statement_count(pseudocode: str) -> int:
    """Number of non-empty statements (a coarse body-size proxy; no basic-block info here)."""
    return sum(1 for s in _STMT_SPLIT_RE.split(pseudocode) if s.strip())


def signature_slots(pseudocode: str) -> list[str | None]:
    """One entry per parameter SLOT of the signature, in declaration order.

    A slot holds the parameter's name — its last identifier (`char* param_1` -> param_1;
    `const char *cmd` -> cmd) — or None when the slot declares a type with no name.

    ★ Unnamed slots are KEPT as None rather than dropped, because position is the whole point of
    this list and dropping them silently shifts every parameter after one: in
    `f(int, char *param_2)` a name-only list reports param_2 at position 0, so a caller's argument
    0 gets read when argument 1 is what reaches the sink. Wrong-position is worse than no position
    — it judges a real value that is simply the wrong one."""
    brace = pseudocode.find("{")
    head = pseudocode[:brace] if brace != -1 else pseudocode
    lp = head.find("(")
    if lp == -1:
        return []
    depth = 0
    rp = -1
    for i in range(lp, len(head)):
        if head[i] == "(":
            depth += 1
        elif head[i] == ")":
            depth -= 1
            if depth == 0:
                rp = i
                break
    if rp == -1:
        return []
    slots: list[str | None] = []
    for part in head[lp + 1 : rp].split(","):
        idents = _IDENT_RE.findall(part)
        name = idents[-1] if idents else None
        if name == "void" and len(slots) == 0 and head[lp + 1 : rp].strip() == "void":
            return []  # `(void)` is "no parameters", not one unnamed slot
        if name is None or name in _TYPE_WORDS or name == "void":
            slots.append(None)  # a typed-but-unnamed slot: position preserved, name unknown
            continue
        slots.append(name)
    return slots


def _signature_params(pseudocode: str) -> set[str]:
    """The signature's parameter NAMES (order-free view of ``signature_slots``)."""
    return {s for s in signature_slots(pseudocode) if s is not None}


def fmt_wrapper_format_index(
    pseudocode: str, wrapped_sink: str, stub_names: Mapping[int, str] | None = None
) -> int | None:
    """The POSITION of a thin fmt wrapper's format parameter in its own signature, or None.

    Pairs with ``is_thin_fmt_wrapper``, which answers "is this a fmt wrapper, and which sink" but
    not "which of its parameters is the format". A caller needs the position: it forwards arguments
    positionally, so this index is what turns "the wrapper's format comes from its parameter
    ``param_2``" into "read the caller's argument 1".

    None whenever the position cannot be established — the sink's format argument is not one of
    the signature's named parameters (a decompiler placeholder like ``in_r3``, or a value built
    inside the wrapper). The caller then declines to read any argument rather than guessing one,
    because a guessed position reads a DIFFERENT value than the one that reaches the sink.

    Indexed over ``signature_slots``, so an unnamed slot occupies its position instead of shifting
    the parameters after it. ``stub_names`` as in ``is_thin_fmt_wrapper``."""
    ident = locate_format_arg(pseudocode, wrapped_sink, stub_names)
    if ident is None:
        return None
    slots = signature_slots(pseudocode)
    try:
        return slots.index(ident)
    except ValueError:
        return None


def _arg_is_forwarded_verbatim(pseudocode: str, arg: str) -> bool:
    """True when ``arg`` is never assigned and never built in this function body.

    Verbatim forwarding means the value handed to the sink is the parameter itself, not a
    locally constructed string. So ``arg`` must NOT appear as an assignment target (`arg = …`)
    nor as the destination (first argument) of a format/copy builder (`snprintf(arg, …)`)."""
    if re.search(rf"\b{re.escape(arg)}\s*=\s*(?!=)", pseudocode):
        return False  # arg is reassigned locally (not a verbatim parameter forward)
    builders = "|".join(re.escape(b) for b in sorted(_BUILDERS))
    if re.search(rf"\b(?:{builders})\s*\(\s*{re.escape(arg)}\b", pseudocode):
        return False  # arg is built locally (format / concat / copy destination)
    return True


def is_thin_cmd_wrapper(
    pseudocode: str,
    callees: list[str],
    *,
    max_statements: int = _WRAPPER_MAX_STATEMENTS,
    stub_names: Mapping[int, str] | None = None,
) -> tuple[bool, str | None]:
    """Recognize a thin command-forwarding wrapper. Returns (is_wrapper, wrapped_sink).

    A function is a thin command wrapper when ALL hold:
      1. it calls a shell command sink whose first argument is the command (system/popen/doSystem);
      2. that sink's first argument is one of the function's own parameters (or a decompiler
         caller-supplied placeholder param_N / in_<reg>), forwarded verbatim — not built locally;
      3. the body is thin (<= max_statements non-empty statements).

    ``stub_names`` (a binary's resolved lazy-binding stubs, address -> import) lets step 2 find a
    sink call the decompiler rendered as ``FUN_<stub-addr>(…)``. The callee list is already
    relabelled at ingest, so step 1 sees ``system`` either way; without the table the call itself
    is invisible in the text and the function is (wrongly, but safely) not a wrapper.

    Structural fact only: it does NOT assert the forwarded value is attacker-controlled. Returns
    (False, None) under any doubt. See the module docstring."""
    cmd_sinks = {c.strip() for c in callees} & _FORWARD_CMD_SINKS
    if not cmd_sinks:
        return False, None
    # Deterministic pick; prefer the canonical 'system' when several are present.
    wrapped = "system" if "system" in cmd_sinks else sorted(cmd_sinks)[0]

    if _statement_count(pseudocode) > max_statements:
        return False, None

    arg = locate_sink_arg(pseudocode, wrapped, stub_names)
    if arg is None:
        return False, None

    params = _signature_params(pseudocode)
    is_param = arg in params or _CALLER_SUPPLIED_RE.fullmatch(arg) is not None
    if not is_param:
        return False, None

    if not _arg_is_forwarded_verbatim(pseudocode, arg):
        return False, None

    return True, wrapped


# ── R7: two gates on recognising a thin FORMAT-STRING wrapper ────────────────────────────────
#
# A same-named C++ method, or a decompiler that dropped a va_list, can wear the shape of a thin
# fmt wrapper without being one. Two gates on the call locate_format_arg selected, EITHER failing
# means this sink is not a wrapper here — they narrow the H1 recall, never the by-name sink set.

# Pointer bases that are "character-like": a format argument cast to one of these is still a
# string. Any OTHER pointer cast (e.g. ``Log *``) is a different object, not a forwarded format.
_FMT_CHAR_PTR_BASES: frozenset[str] = frozenset(
    {"char", "signed char", "unsigned char", "void", "uchar", "byte", "undefined", "undefined1"}
)
# Fixed (non-variadic) parameter count of each v* definite-argument family member. A CALL with
# MORE top-level arguments than this is not that function (a C++ same-name method carries ``this``
# -> more); FEWER is the decompiler dropping the va_list and is NOT a reason to reject.
_VARIADIC_FIXED_ARGS: dict[str, int] = {
    "vprintf": 2,
    "vwarn": 2,
    "vwarnx": 2,
    "vfprintf": 3,
    "vdprintf": 3,
    "vsyslog": 3,
    "verr": 3,
    "verrx": 3,
    "vasprintf": 3,
}


def _fmt_cast_is_nonchar_ptr(cast_type: str | None) -> bool:
    """The format argument is cast to a pointer to a NON-character type (gate 1): a different
    object was forwarded, not a format string. No cast, or a char / void / undefined pointer, is
    fine."""
    if cast_type is None:
        return False
    t = cast_type.strip()
    if not t.endswith("*"):
        return False
    base = t[:-1].rstrip("*").strip()
    return base not in _FMT_CHAR_PTR_BASES


def _variadic_arg_count_rejects(sink: str, call_args: list[str]) -> bool:
    """The selected call passes MORE top-level arguments than the definite-argument family member's
    fixed count (gate 2): it is a same-named other function, not this sink. Fewer never rejects."""
    fixed = _VARIADIC_FIXED_ARGS.get(sink)
    return fixed is not None and len(call_args) > fixed


def is_thin_fmt_wrapper(
    pseudocode: str,
    callees: list[str],
    *,
    max_statements: int = _WRAPPER_MAX_STATEMENTS,
    stub_names: Mapping[int, str] | None = None,
) -> tuple[bool, str | None]:
    """Recognize a thin format-string-forwarding wrapper. Returns (is_wrapper, wrapped_sink).

    The format-string counterpart of is_thin_cmd_wrapper. A function is a thin format wrapper
    when ALL hold:
      1. it calls a format-string sink (printf / fprintf / syslog / err / asprintf / …);
      2. that sink's FORMAT-STRING argument — the per-sink danger position (fprintf's arg1,
         printf's arg0, syslog's arg1, …), NOT merely the first argument — is one of the
         function's own parameters (or a decompiler caller-supplied placeholder param_N /
         in_<reg>), forwarded verbatim: not built locally AND not a string literal;
      3. the body is thin (<= max_statements non-empty statements).

    The literal exclusion is the load-bearing difference from the command axis. A command sink's
    whole first argument is the danger, so forwarding a parameter there is the wrapper. A format
    sink's data arguments are harmless; only the FORMAT position propagates format-string
    injection. `fprintf(f, "literal", param_1)` forwards a parameter into a DATA slot while the
    format is a fixed literal — a safe call, NOT a wrapper — so a literal in the format position
    (even with a forwarded data argument) is rejected. locate_format_arg enforces this: it skips
    every literal-format call and yields an identifier only from a non-literal format position.

    ``stub_names`` lets step 2 read a sink call the decompiler rendered as ``FUN_<stub-addr>(…)``,
    exactly as in ``is_thin_cmd_wrapper``: the callee list already says ``syslog``, but without
    the table the call itself is invisible in the text.

    Structural fact only: it does NOT assert the forwarded format is attacker-controlled. Returns
    (False, None) under any doubt. See the module docstring."""
    fmt_sinks = sorted({c.strip() for c in callees} & FMT_STRING)
    if not fmt_sinks:
        return False, None

    if _statement_count(pseudocode) > max_statements:
        return False, None

    params = _signature_params(pseudocode)
    for sink in fmt_sinks:
        # The format-position argument of the first non-literal call (per-sink index), with that
        # call's own arguments. None => every call passed a literal format (safe) or was unreadable.
        found = format_string_call(pseudocode, sink, stub_names)
        if found is None:
            continue
        ref, call_args = found
        arg = ref.root
        if arg is None:
            continue
        # R7 gate 1: a cast to a non-character pointer is a different object, not a format forward.
        if _fmt_cast_is_nonchar_ptr(ref.cast_type):
            continue
        # R7 gate 2: a definite-argument v* call with MORE args than its fixed count is a same-named
        # other function (the C++ ``this`` shape), not this sink.
        if _variadic_arg_count_rejects(sink, call_args):
            continue
        is_param = arg in params or _CALLER_SUPPLIED_RE.fullmatch(arg) is not None
        if not is_param:
            continue
        if not _arg_is_forwarded_verbatim(pseudocode, arg):
            continue
        return True, sink
    return False, None


# ── the PATH axis: a thin wrapper forwarding a parameter into a path sink's PATH position ─────

# The forms in which the argument a path sink receives IS the wrapper's parameter: the parameter
# itself, or the parameter under a cast. Only through these is a literal the CALLER passes the very
# path the sink opens; `fopen(param_1 + 4, …)`, or a field read through the parameter, is another
# value derived from it.
_PATH_FORWARD_FORMS: frozenset[str] = frozenset({"var", "cast"})


def is_thin_path_wrapper(
    pseudocode: str,
    callees: list[str],
    *,
    max_statements: int = _WRAPPER_MAX_STATEMENTS,
    stub_names: Mapping[int, str] | None = None,
) -> tuple[bool, str | None]:
    """Recognize a thin path-forwarding wrapper. Returns (is_wrapper, wrapped_sink).

    The path/file counterpart of is_thin_cmd_wrapper. A function is a thin path wrapper when ALL
    hold:
      1. it calls a path sink (``PATH_SINK``: fopen / open / openat / unlink / rename / …);
      2. that sink's path argument — as ``path_arg_ref`` reads it over EVERY path position of every
         call (``PATH_SINK_ARG`` and then ``PATH_SINK_EXTRA_ARGS``): the first non-literal one that
         has a root — is one of the function's own parameters (or a decompiler caller-supplied
         placeholder param_N / in_<reg>), forwarded verbatim, not built locally;
      3. the body is thin (<= max_statements non-empty statements).
    With several path sinks called, they are tried in NAME order and the first that qualifies is
    the one wrapped.

    Not judged here: whether the function's OWN name is a path sink (the C library's ``open64``
    calling ``open``). That is a fact about the name, not the body; the registry that turns this
    fact into propagated candidates applies it, as it applies the one-name-per-binary rule.

    ``stub_names`` as in ``is_thin_cmd_wrapper``. Structural fact only: it does NOT assert the
    forwarded path is attacker-controlled. Returns (False, None) under any doubt."""
    path_sinks = sorted({c.strip() for c in callees} & PATH_SINK)
    if not path_sinks:
        return False, None

    if _statement_count(pseudocode) > max_statements:
        return False, None

    params = _signature_params(pseudocode)
    for sink in path_sinks:
        ref = path_arg_ref(pseudocode, sink, stub_names)
        arg = ref.root if ref is not None else None
        if arg is None:
            continue
        is_param = arg in params or _CALLER_SUPPLIED_RE.fullmatch(arg) is not None
        if not is_param:
            continue
        if not _arg_is_forwarded_verbatim(pseudocode, arg):
            continue
        return True, sink
    return False, None


def path_wrapper_param_positions(
    pseudocode: str, wrapped_sink: str, stub_names: Mapping[int, str] | None = None
) -> tuple[tuple[int, ...] | None, bool]:
    """WHERE a thin path wrapper's caller supplies the path: ``(positions, fully_forwarded)``.

    Pairs with ``is_thin_path_wrapper`` as ``fmt_wrapper_format_index`` pairs with the format test:
    a caller forwards arguments positionally, so these indexes are what turn "the wrapper's path
    comes from its parameter ``param_2``" into "read the caller's argument 1".

    ``positions`` — the signature slot (``signature_slots``, so an unnamed slot keeps its place) of
    every parameter the wrapper forwards verbatim into a path position of ``wrapped_sink``, over
    every call to it, ascending: ``rename(param_1, param_2)`` forwards two. None when the parameter
    the wrapper was recognised by has no slot — a placeholder such as ``in_stack_8``, or a
    ``param_3`` the printed signature does not declare. The position then cannot be established,
    and the caller reads no argument rather than guessing one, because a guessed position reads a
    DIFFERENT value than the one that reaches the sink.

    ``fully_forwarded`` — True only when every path argument of every call to ``wrapped_sink`` in
    the wrapper is either a string literal there or one of those parameters passed as itself (or
    under a cast). Only then do literals at all of ``positions`` fix every path the sink is handed:
    a wrapper doing ``rename(param_1, g_dest)`` moves the file to a destination no caller argument
    names, so a literal source does not make that call a constant path."""
    first = path_arg_ref(pseudocode, wrapped_sink, stub_names)
    ident = first.root if first is not None else None
    slots = signature_slots(pseudocode)
    if ident is None or ident not in slots:
        return None, False
    positions: set[int] = set()
    fully_forwarded = True
    for call in _iter_path_args(pseudocode, wrapped_sink, stub_names):
        for text in call:
            if text is None:
                fully_forwarded = False  # a path position this call does not have: not fixed
                continue
            if _FMT_LITERAL_RE.match(text):
                continue  # fixed inside the wrapper
            ref = arg_ref(text)
            root = ref.root
            if (
                root is None
                or root not in slots
                or not _arg_is_forwarded_verbatim(pseudocode, root)
            ):
                fully_forwarded = False  # a value of the wrapper's own: no caller argument fixes it
                continue
            positions.add(slots.index(root))
            if ref.form not in _PATH_FORWARD_FORMS:
                fully_forwarded = False  # derived from the parameter, not the parameter itself
    return tuple(sorted(positions)), fully_forwarded
