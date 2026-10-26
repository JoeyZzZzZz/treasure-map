# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""ShellScript ingester: detect + ingest shell scripts found in firmware filesystems.

Detection: shebang line containing a known shell name, or .sh extension.
Ingestion: walk lines and record two kinds: a line SHELL_RISK_RULES marks (ordered,
first-match-wins), and a line that LAUNCHES one of this firmware's binaries — its first
executable token, past wrappers such as nohup / exec / start-stop-daemon -x, names one. The
second kind is what "which script starts this daemon" is answered from, and is the most common
line in an init script; gating it on a risk word dropped it. ``command`` is that executable token.
raw_line stores the script's OWN source line as analysis evidence — it is never a generated
payload.

A line can also start a binary without naming it as its first token, and those launches are read
from the same file: a function that runs its positional parameter (``run() { $BASE/$1 & }`` called
as ``run svc``), a variable holding a literal command (``X=/sbin/svc`` then ``$X &``), and the first
command of a command substitution (``$(svc …)`` / backquotes). Each row says where its command came
from in ``via`` — ``literal`` (named on the line), ``function_arg``, ``variable`` or ``inline`` —
and ``via_line`` is the line it was derived from (the function's definition, the assignment, or
the substitution's own line; NULL for literal). ``via`` is a mechanical provenance label, not a
reachability verdict. What cannot be read reliably (a variable argument, ``$(which …)``, unpaired
braces, ``$@``, unpaired quotes) is skipped, never guessed.
"""

from __future__ import annotations

import re
import shlex
import sqlite3
from dataclasses import dataclass, field

from treasure_map.lib.analyze.non_binary.framework import (
    NonBinaryFile,
    NonBinaryIngester,
)

# Ordered rule table (categorical observation labels only). Used as a recording
# gate to keep the table signal-dense; the label itself is not stored.
# First-match-wins, compiled once at module load.
SHELL_RISK_RULES: list[tuple[str, str]] = [
    ("eval_injection", r"(?i)\beval\b"),
    ("cmd_injection_candidate", r"(?i)\b(sh|bash|ash|dash)\s+-c\b|`|\$\("),
    ("config_file_injection", r"(?i)\b(nvram|uci|getconf|mdb)\b"),
    ("fs_op_with_tainted", r"(?i)\b(rm|mv|cp|chmod|chown|cat|tee|dd)\b.*\$"),
]

_COMPILED_RULES: list[tuple[str, re.Pattern[str]]] = [
    (label, re.compile(pattern)) for label, pattern in SHELL_RISK_RULES
]

_KNOWN_SHELLS = frozenset({"sh", "bash", "ash", "dash", "zsh"})


def _detect_shell(f: NonBinaryFile) -> str | None:
    """Return shell interpreter label if file is a shell script, else None."""
    if f.text is None:
        return None
    first_line = f.text.split("\n", 1)[0]
    if first_line.startswith("#!"):
        interp_field = first_line[2:].strip().split()[0] if first_line[2:].strip() else ""
        basename = interp_field.rsplit("/", 1)[-1]
        if basename in _KNOWN_SHELLS:
            return basename
    if f.name.endswith(".sh"):
        return "sh"
    return None


# Words that run the command after them rather than being it.
_WRAPPERS = frozenset({"nohup", "exec", "setsid", "nice", "env", "time", "chrt", "taskset"})
_ASSIGN_RE = re.compile(r"^[A-Za-z_]\w*=")
_SUBST_RE = re.compile(r"^[A-Za-z_]\w*=(?:\$\(|`)(\S+)")


def _split_respecting_quotes(line: str) -> list[str]:
    """The line's words as the shell splits them: a quoted run (single or double) is one word with
    its quotes removed, so ``X="a b c"`` is one assignment and never a command ``b``. A line whose
    quotes cannot be paired falls back to plain whitespace splitting — the reading it had before,
    which can miss a launch but never invents one from a quote it misread."""
    try:
        return shlex.split(line, posix=True)
    except ValueError:
        return line.split()


def launched_command(line: str) -> str | None:
    """The executable a shell line runs: past ``VAR=value`` assignments and wrappers (``nohup``,
    ``exec``, ``nice -n 10`` …), the ``-x``/``--exec``/``--startas`` of ``start-stop-daemon``, and
    the command inside a ``VAR=$(cmd …)`` substitution. None when there is none to name."""
    tokens = _split_respecting_quotes(line)
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        m = _SUBST_RE.match(tok)
        if m:
            return m.group(1).rstrip(");`")
        if _ASSIGN_RE.match(tok):
            i += 1
            continue
        base = tok.rsplit("/", 1)[-1]
        if base == "start-stop-daemon":
            for j in range(i + 1, len(tokens) - 1):
                if tokens[j] in ("-x", "--exec", "-a", "--startas"):
                    return tokens[j + 1].rstrip("&;")
            return tok
        if base in _WRAPPERS:
            i += 1
            while i < len(tokens) and (
                tokens[i].startswith("-") or tokens[i].lstrip("-").isdigit()
            ):
                i += 1
            continue
        return tok.rstrip("&;") or None
    return None


# ── the same-file symbol table: functions that run a positional parameter, literal variables ──

_FUNCTION_DEFS = (
    re.compile(r"^function\s+([A-Za-z_][\w.:-]*)\s*(?:\(\s*\))?\s*(\{.*|\(.*)?$"),
    re.compile(r"^([A-Za-z_][\w.:-]*)\s*\(\s*\)\s*(\{.*|\(.*)?$"),
)
_NOT_A_FUNCTION = frozenset({"if", "while", "for", "until", "case", "then", "do", "elif"})
# $1-$9 or ${1}-${9}; $@ / $* / ${1:-x} are not read.
_POSITIONAL = re.compile(r"^\$(?:([1-9])|\{([1-9])\})$")
# NAME=value with a literal value (a name or a path: no $, backquote, space or operator), optionally
# quoted and after export / readonly / local, alone on its line or before a ``;`` / comment.
_LITERAL_ASSIGN = re.compile(
    r"^(?:export\s+|readonly\s+|local\s+)?([A-Za-z_]\w*)=([\"']?)([^\s\"'$`;|&<>()]+)\2"
    r"\s*(?:;.*|#.*)?$"
)
# The executable token as a variable: $X, ${X}, or $BASE/$X (the variable is the last segment).
_VARIABLE_TOKENS = (
    re.compile(r"^\$([A-Za-z_]\w*)$"),
    re.compile(r"^\$\{([A-Za-z_]\w*)\}$"),
    re.compile(r"^\$\{?[A-Za-z_]\w*\}?/\$\{?([A-Za-z_]\w*)\}?$"),
)


@dataclass
class _SymbolTable:
    """What one file defines that a later line can launch through, read in one pass."""

    # function name -> (positional parameter it runs, 1-based line of the definition)
    functions: dict[str, list[tuple[int, int]]] = field(default_factory=dict)
    # (function, parameter) pairs whose body runs the parameter inside double quotes
    quoted: set[tuple[str, int]] = field(default_factory=set)
    # variable -> every literal value assigned to it, with its 1-based assignment line
    literals: dict[str, list[tuple[str, int]]] = field(default_factory=dict)
    # functions whose braces do not pair (or whose body is a subshell): not read
    unpaired: int = 0


def _brace_counts(line: str) -> tuple[int, int]:
    s = re.sub(r"\\.", "", line)
    s = re.sub(r"'[^']*'", "", s)
    s = re.sub(r"(^|\s)#.*$", "", s)
    return s.count("{"), s.count("}")


def _function_spans(lines: list[str]) -> list[tuple[str, int, int | None]]:
    """(name, definition line index, closing line index or None when the braces do not pair)."""
    out: list[tuple[str, int, int | None]] = []
    n = len(lines)
    for i, raw in enumerate(lines):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        for rx in _FUNCTION_DEFS:
            m = rx.match(s)
            if not m:
                continue
            name, rest = m.group(1), m.group(2) or ""
            if name in _NOT_A_FUNCTION:
                break
            if rest.startswith("("):  # a subshell body: not read
                out.append((name, i, None))
                break
            j = i
            if not rest.startswith("{"):
                k = i + 1
                while k < n and not lines[k].strip():
                    k += 1
                if k >= n or not lines[k].strip().startswith("{"):
                    out.append((name, i, None))
                    break
                j = k
            opened, closed = _brace_counts(lines[j] if j != i else s)
            depth = opened - closed
            end: int | None = None
            if opened > 0 and depth <= 0:
                end = j
            else:
                k = j + 1
                while k < n:
                    opened, closed = _brace_counts(lines[k])
                    depth += opened - closed
                    if depth <= 0:
                        end = k
                        break
                    k += 1
            out.append((name, i, end))
            break
    return out


def _scan_symbols(text: str) -> _SymbolTable:
    """One file's functions that run a positional parameter as their command, and its variables
    assigned a literal value — the same file only (``.`` / ``source`` are not followed)."""
    lines = text.splitlines()
    table = _SymbolTable()
    for name, start, end in _function_spans(lines):
        if end is None:
            table.unpaired += 1
            continue
        positions: list[int] = []
        for li in range(start, end + 1):
            s = lines[li].strip()
            if li == start:
                s = s.split("{", 1)[1] if "{" in s else ""
            if not s or s.startswith("#"):
                continue
            tok = launched_command(s)
            if not tok:
                continue
            for cand in (tok, tok.rsplit("/", 1)[-1]):
                m = _POSITIONAL.match(cand)
                if m:
                    k = int(m.group(1) or m.group(2))
                    positions.append(k)
                    table.functions.setdefault(name, []).append((k, start + 1))
                    break
        for k in positions:
            quoted = re.compile(r'"[^"]*\$\{?' + str(k) + r'\}?[^"]*"')
            if any(quoted.search(lines[li]) for li in range(start, end + 1)):
                table.quoted.add((name, k))
    for li, raw in enumerate(lines):
        m = _LITERAL_ASSIGN.match(raw.strip())
        if m:
            table.literals.setdefault(m.group(1), []).append((m.group(3), li + 1))
    return table


# ── one line's launches ─────────────────────────────────────────────────────────────────────────

VIA_PRIORITY = ("literal", "function_arg", "variable", "inline")


@dataclass(frozen=True)
class _Launch:
    command: str
    via: str
    via_line: int | None


def _substitutions(line: str) -> list[tuple[int, str]]:
    """(start, inner text) of every ``$( … )`` (paren-balanced; ``$((`` arithmetic skipped) and
    every backquoted span on the line."""
    out: list[tuple[int, str]] = []
    i = 0
    while True:
        i = line.find("$(", i)
        if i < 0:
            break
        if line.startswith("$((", i):
            i += 3
            continue
        depth, j = 0, i + 1
        while j < len(line):
            if line[j] == "(":
                depth += 1
            elif line[j] == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        out.append((i, line[i + 2 : j]))
        i += 2
    for m in re.finditer(r"`([^`]*)`", line):
        out.append((m.start(), m.group(1)))
    return out


def _single_quoted(line: str) -> list[tuple[int, int]]:
    """Single-quoted ranges outside double quotes: the shell expands nothing inside them."""
    out: list[tuple[int, int]] = []
    i, in_double = 0, False
    while i < len(line):
        ch = line[i]
        if ch == "\\" and not in_double:
            i += 2
            continue
        if ch == '"':
            in_double = not in_double
        elif ch == "'" and not in_double:
            j = line.find("'", i + 1)
            if j < 0:
                break
            out.append((i, j))
            i = j
        i += 1
    return out


_SEGMENT_CUT = re.compile(r"\|\||&&|\||;")


def _subst_command(inner: str) -> str | None:
    """The command a substitution runs: the first word of its first pipeline segment."""
    seg = _SEGMENT_CUT.split(inner, 1)[0].strip()
    return launched_command(seg) if seg else None


def _arguments_after(line: str, name: str) -> list[str] | None:
    """The words after ``name`` on the line, up to the first operator or redirection."""
    try:
        lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        return None
    if name not in tokens:
        return None
    out: list[str] = []
    for t in tokens[tokens.index(name) + 1 :]:
        if t and set(t) <= set(";&|<>()"):
            break
        if re.match(r"^\d*[<>]", t):
            break
        out.append(t)
    return out


def _launches_from_line(line: str, symtab: _SymbolTable, lineno: int) -> list[_Launch]:
    """Every command this line runs that can be named: the literal one, the first command of each
    command substitution, a function's positional parameter given here as a literal argument, and
    each literal value of a variable used as the command. Not filtered to binaries; not deduped."""
    out: list[_Launch] = []
    lit = launched_command(line)
    if lit:
        out.append(_Launch(lit, "literal", None))
    single = _single_quoted(line)
    for start, inner in _substitutions(line):
        if any(a < start < b for a, b in single):
            continue
        command = _subst_command(inner)
        if command:
            out.append(_Launch(command, "inline", lineno))
    if lit and lit in symtab.functions:
        args = _arguments_after(line, lit)
        if args is not None:
            for k, defline in symtab.functions[lit]:
                if k - 1 >= len(args):
                    continue
                arg = args[k - 1]
                if not arg or "$" in arg or "`" in arg:
                    continue
                # An unquoted "$1" is word-split by the shell, so it runs the argument's first
                # word; a quoted one runs the whole argument as one name — and a name with a space
                # in it is no binary's (its last path segment is not the command).
                if (lit, k) not in symtab.quoted:
                    arg = arg.split()[0]
                elif any(ch.isspace() for ch in arg):
                    continue
                out.append(_Launch(arg.rsplit("/", 1)[-1], "function_arg", defline))
    if lit:
        for rx in _VARIABLE_TOKENS:
            m = rx.match(lit)
            if m and m.group(1) in symtab.literals:
                for value, assigned in symtab.literals[m.group(1)]:
                    out.append(_Launch(value.rsplit("/", 1)[-1], "variable", assigned))
                break
    return out


def _ingest_shell(conn: sqlite3.Connection, file_id: int, f: NonBinaryFile) -> int:
    """Insert script_calls rows for the lines that launch one of this firmware's binaries and the
    risk-marked lines.

    A line gives one row per distinct binary command it launches (the same command reached two
    ways is one row, its ``via`` the first of literal > function_arg > variable > inline); a
    risk-marked line that launches none gives one row, as before. The binary names come from the
    analysis database's current binaries (the ELF pass runs first). raw_line stores the script's
    own source line as evidence; it is the firmware's own content, not a payload generated by
    Treasure Map.
    """
    if f.text is None:
        return 0
    try:
        binaries = {r[0] for r in conn.execute("SELECT name FROM current_binaries") if r[0]}
    except sqlite3.OperationalError:
        binaries = set()

    symtab = _scan_symbols(f.text)
    rows: list[tuple[int, str | None, str, int, str, str, int | None]] = []
    for lineno, raw in enumerate(f.text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if "$" in stripped:
            args_pattern = "var_expansion"
        elif "|" in stripped:
            args_pattern = "piped"
        else:
            args_pattern = "literal"

        best: dict[str, _Launch] = {}
        for launch in _launches_from_line(stripped, symtab, lineno):
            if launch.command.rsplit("/", 1)[-1] not in binaries:
                continue
            held = best.get(launch.command)
            if held is None or VIA_PRIORITY.index(launch.via) < VIA_PRIORITY.index(held.via):
                best[launch.command] = launch
        if best:
            for launch in best.values():
                row = (file_id, launch.command, raw, lineno, args_pattern)
                rows.append((*row, launch.via, launch.via_line))
        elif any(pattern.search(stripped) for _, pattern in _COMPILED_RULES):
            rows.append(
                (file_id, launched_command(stripped), raw, lineno, args_pattern, "literal", None)
            )

    if rows:
        conn.executemany(
            """INSERT INTO script_calls
               (file_id, command, raw_line, line_number, args_pattern, via, via_line)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )
    return len(rows)


SHELL_SCRIPT_INGESTER = NonBinaryIngester(
    kind="shell_script",
    detect=_detect_shell,
    ingest=_ingest_shell,
)
