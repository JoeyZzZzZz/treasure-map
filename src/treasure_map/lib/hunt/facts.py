# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Neutral structural function-facts for the pattern analyzer.

A fact here is a STRUCTURAL observation about a function — a property of its body and the
call it makes — NOT a verdict and NOT an FP-suppression signal. A fact is recorded on the
candidate so a later analysis layer can consume it; recording a fact never changes a
candidate's recall or its review-ordering score on its own (the downweight/score path does
not read these fields).

is_thin_cmd_wrapper recognizes a "thin forwarding wrapper": a function whose body does little
more than hand one of its own parameters straight to a shell command sink
(system / popen / doSystem). This is a structural fact about the call graph and the function's
shape — it deliberately does NOT claim the forwarded value is attacker-controlled; that
judgement is left to a later layer's positive evidence. Conservative by construction: under
any doubt it returns (False, None), so a false fact is never asserted.

Name-based and intra-procedural by design (like the validator/downweight filters): it can
miss, and it prefers to stay silent rather than mislabel.
"""

from __future__ import annotations

import re

from treasure_map.lib.pattern.classes import COPY, FORMAT
from treasure_map.lib.reachability.taint import (
    _CALLER_SUPPLIED_RE,
    _IDENT_RE,
    _TYPE_WORDS,
    locate_sink_arg,
)

# Shell-running command sinks whose FIRST argument IS the command string. A thin wrapper that
# forwards a parameter into one of these forwards the whole command. Exec-family sinks are
# excluded on purpose: their first argument is the program path, not the command string, so a
# parameter in the first slot says nothing about command forwarding (and exec-without-a-shell
# is inert for shell metacharacters anyway — handled by the no_shell_exec downweight elsewhere).
_FORWARD_CMD_SINKS: frozenset[str] = frozenset({"system", "popen", "doSystem"})

# Buffer-building calls. If the forwarded argument is the destination of one of these, the
# value was constructed locally (format / concat / copy), so the function is NOT a verbatim
# forwarder — it builds a command, which is a different (and more interesting) shape.
_BUILDERS: frozenset[str] = FORMAT | COPY

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


def _signature_params(pseudocode: str) -> set[str]:
    """Parameter identifiers from the function signature — the first top-level (...) before the
    opening brace. Each parameter's NAME is its last identifier (`char* param_1` -> param_1;
    `const char *cmd` -> cmd). Type-only words (an unnamed `(void)` / `(char*)`) are dropped."""
    brace = pseudocode.find("{")
    head = pseudocode[:brace] if brace != -1 else pseudocode
    lp = head.find("(")
    if lp == -1:
        return set()
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
        return set()
    params: set[str] = set()
    for part in head[lp + 1 : rp].split(","):
        idents = _IDENT_RE.findall(part)
        if not idents:
            continue
        name = idents[-1]
        if name == "void" or name in _TYPE_WORDS:
            continue
        params.add(name)
    return params


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
) -> tuple[bool, str | None]:
    """Recognize a thin command-forwarding wrapper. Returns (is_wrapper, wrapped_sink).

    A function is a thin command wrapper when ALL hold:
      1. it calls a shell command sink whose first argument is the command (system/popen/doSystem);
      2. that sink's first argument is one of the function's own parameters (or a decompiler
         caller-supplied placeholder param_N / in_<reg>), forwarded verbatim — not built locally;
      3. the body is thin (<= max_statements non-empty statements).

    Structural fact only: it does NOT assert the forwarded value is attacker-controlled. Returns
    (False, None) under any doubt. See the module docstring."""
    cmd_sinks = {c.strip() for c in callees} & _FORWARD_CMD_SINKS
    if not cmd_sinks:
        return False, None
    # Deterministic pick; prefer the canonical 'system' when several are present.
    wrapped = "system" if "system" in cmd_sinks else sorted(cmd_sinks)[0]

    if _statement_count(pseudocode) > max_statements:
        return False, None

    arg = locate_sink_arg(pseudocode, wrapped)
    if arg is None:
        return False, None

    params = _signature_params(pseudocode)
    is_param = arg in params or _CALLER_SUPPLIED_RE.fullmatch(arg) is not None
    if not is_param:
        return False, None

    if not _arg_is_forwarded_verbatim(pseudocode, arg):
        return False, None

    return True, wrapped
