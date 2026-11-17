# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Which of a binary's own functions hand on a known source's value (E-2a H8, criterion A).

The mechanism layer (classes.SourceHelpers, threaded through the readers) is in place; this is the
half that decides WHICH functions go in a binary's table. A firmware binary often reads its input
through a small local function: it calls a known source (classes.SOURCE) and either returns that
value or writes it into a buffer its caller passed. A caller of such a function reads, to the shape
scan, as taking no input at all — its callee list names only the local function.

Two layers, kept apart on purpose:

  * ``helper_slots`` — criterion A over ONE function body: the slots through which it hands on a
    source value (``RETURN_SLOT`` or a 0-based out-parameter position), the empty set when it is
    not a value getter. Pure; it reads the fixed SOURCE names only (never another helper — one
    layer, no transitivity).

  * ``build_helper_tables`` — the population gate plus criterion A, per binary. The gate is the
    measured one (M3): a stripped ``FUN_<addr>`` name, called with at least two distinct string
    keys where its return is taken, and a body whose shape reads like a getter. Only a function
    through the gate is handed to ``helper_slots``. ★ Only the ``RETURN_SLOT`` reading enters a
    table: the return slot's precision was measured on the built tables, and the out-parameter
    reading has had no member on any corpus it was measured on, so its precision is unknown. It
    stays computed by ``helper_slots`` (to be measured where it has members) and is not admitted
    — a table under-collects rather than grow its population through an unmeasured rule.

A helper is read as WEAK input downstream, so it labels a candidate and seeds weak taint and never
grades one ``confirmed``. Finding one says nothing about whether the value it hands on is
attacker-controlled — a structural reading, not a verdict.

Deliberately narrow, every boundary stated rather than approximated:
  * a value getter that calls no known source NAME (it parses a request itself, walks a document)
    is not found here — a shape guess for it mislabels more than it finds;
  * the out-parameter slot and the return slot both rest on the existing seeding tables, so a
    helper wrapping a source the taint layer does not seed (uci_get / uci_lookup_ptr; scanf-family)
    falls out as the empty set — under-collection, the safe direction;
  * a helper that calls another helper is not followed (only a known source name starts a value);
  * a value is followed only through value-PRESERVING steps (a copy, a cast, a read-through, one
    ``strdup`` layer, a buffer builder's destination): arithmetic, a conversion such as ``atoi`` and
    every other call break the chain. That is narrower than a general flow relation on purpose — a
    comparison can then never hand on a "value", which is how a predicate is kept out by
    construction — and the cost is recall on getters that transform what they read;
  * a variable seeded once and later overwritten (``p = getenv(k); if (p) p = (char *)1; return
    p;``) still reads as handing on the value: telling that apart from a fallback default needs
    reaching definitions, which this does not compute.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable, Mapping

from treasure_map.lib.diff.loader import FuncRow
from treasure_map.lib.pattern.classes import (
    RETURN_SLOT,
    SOURCE,
    SourceHelpers,
    arg_ref,
    call_args_at,
    call_offsets,
)
from treasure_map.lib.pattern.extractor_names import REGISTRY
from treasure_map.lib.reachability.taint import _seed_sets

# Buffer-building calls: REGISTRY.writers (writer + writer_fmt), the same set facts._BUILDERS reads.
# The destination (argument 0) is built from the other arguments, so it carries their value.
_WRITERS: frozenset[str] = REGISTRY.writers
# One-layer value-preserving copies: a source call wrapped in one of these still hands on the value.
_COPY_CALLS: frozenset[str] = frozenset({"strdup", "strndup"})
# The forms in which an expression IS the value it reads (classes.ARG_FORMS): a variable, a cast of
# one, a read through it, its address. Arithmetic / a comparison / any other call is something else.
_VALUE_FORMS: frozenset[str] = frozenset({"var", "cast", "load", "addr_of"})
# Comparison-family calls: their result is a verdict about the value, not the value.
_COMPARE_CALLS: frozenset[str] = frozenset(
    {"strcmp", "strncmp", "strcasecmp", "strncasecmp", "memcmp"}
)
# Top-level comparison / boolean operators — a return expression carrying one hands back a
# judgement. ``!`` is caught separately (a leading unary).
_COMPARE_OPS = ("==", "!=", "<=", ">=", "&&", "||", "<", ">")

_PARAM_RE = re.compile(r"^param_(\d+)$")
_STRING_LIT_RE = re.compile(r'"(?:[^"\\]|\\.)*"')
_FUN_NAME_RE = re.compile(r"^FUN_[0-9a-fA-F]+$")
_LEAD_CALL_RE = re.compile(r"^([A-Za-z_]\w*)\s*\((.*)\)\s*$", re.DOTALL)
_CAST_RE = re.compile(r"^\s*\((?:unsigned |signed |const )?\w[\w\s]*\**\s*\)\s*")
_RETURN_PREFIXES = ("param_", "__dest", "pcVar", "puVar", "pvVar")
# A call's return is TAKEN when its name is preceded by a lone ``=`` (an assignment, wherever it
# sits — a statement, a condition), with one cast allowed in between.
_RETURN_TAKEN_RE = re.compile(r"(?<![=!<>+\-*/%&|^])=\s*(?:\(\s*[A-Za-z_][\w\s]*\**\s*\)\s*)?$")
_FUN_CALL_RE = re.compile(r"\b(FUN_[0-9a-fA-F]+)\s*\(")
_SHAPE_WINDOW = 800


def _body(pseudocode: str) -> str:
    brace = pseudocode.find("{")
    return pseudocode[brace + 1 :] if brace != -1 else pseudocode


def _statements(pseudocode: str) -> list[str]:
    """The body's statements: split at ``;``, ``{``, ``}`` and a line break, but only outside
    parentheses / brackets and string literals — a call the decompiler wrapped across two lines is
    one statement, and a ``;`` inside a string splits nothing. Whitespace is collapsed."""
    body = _body(pseudocode)
    out: list[str] = []
    buf: list[str] = []
    depth = 0
    i, n = 0, len(body)

    def flush() -> None:
        s = " ".join("".join(buf).split())
        if s:
            out.append(s)
        buf.clear()

    while i < n:
        ch = body[i]
        if ch in "\"'":
            j = i + 1
            while j < n and body[j] != ch and body[j] != "\n":
                j += 2 if body[j] == "\\" else 1
            buf.append(body[i : j + 1])
            i = j + 1
            continue
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth = max(0, depth - 1)
        if depth == 0 and ch in ";{}\n":
            flush()
        else:
            buf.append(" " if ch == "\n" else ch)
        i += 1
    flush()
    return out


def _split_assignment(stmt: str) -> tuple[str, str] | None:
    """``lhs = rhs`` at the first plain ``=`` outside parentheses/brackets — never ``==`` / ``<=``
    / ``!=`` / a compound ``+=``. None when the statement is not an assignment."""
    depth = 0
    for i, ch in enumerate(stmt):
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == "=" and depth == 0:
            prev = stmt[i - 1] if i else ""
            nxt = stmt[i + 1] if i + 1 < len(stmt) else ""
            if nxt == "=" or prev in "=<>!+-*/%&|^":
                return None
            return stmt[:i].strip(), stmt[i + 1 :].strip()
    return None


def _strip_casts(expr: str) -> str:
    while True:
        m = _CAST_RE.match(expr)
        if m is None:
            return expr.strip()
        expr = expr[m.end() :]


def _lead_call(expr: str) -> tuple[str, list[str]] | None:
    """``expr`` as a single whole call ``name(args)`` (leading casts allowed), else None."""
    stripped = _strip_casts(expr)
    m = _LEAD_CALL_RE.match(stripped)
    if m is None:
        return None
    inner = m.group(2)
    # Balance check: the regex's greedy ``.*`` can span two sibling calls (``a(x) + b(y)``); a
    # genuinely single call keeps parentheses balanced to the right of its own opening one.
    if inner and (inner.count("(") != inner.count(")")):
        return None
    args = call_args_at(stripped, stripped.find("(")) if inner.strip() else []
    return m.group(1), (args or [])


def _source_calls(pseudocode: str, source_names: Iterable[str]) -> set[str]:
    """The SOURCE names CALLED in the body (``name(`` outside a string literal)."""
    return {name for name in source_names if call_offsets(pseudocode, name)}


def _value_graph(pseudocode: str) -> dict[str, set[str]]:
    """Each variable -> the variables it VALUE-derives from: an assignment that copies / casts /
    reads-through a value, a one-layer ``strdup`` of it, or a buffer builder whose destination it
    is. A comparison, a ``strcmp`` or any other arithmetic makes NO edge — that result is a
    judgement about the value, not the value, which is how the predicate getters are excluded."""
    edges: dict[str, set[str]] = defaultdict(set)
    for stmt in _statements(pseudocode):
        assign = _split_assignment(stmt)
        if assign is not None:
            lhs, rhs = assign
            root = _value_root(rhs)
            if root is not None and root != lhs:
                edges[lhs].add(root)
        for dst, srcs in _builder_edges(stmt):
            edges[dst].update(s for s in srcs if s != dst)
    return edges


def _value_root(rhs: str) -> str | None:
    """The variable ``rhs`` hands on when it is value-preserving (a copy / cast / read-through, or a
    one-layer ``strdup``), else None — a comparison, a conversion, any other call is not."""
    lead = _lead_call(rhs)
    if lead is not None:
        name, args = lead
        if name in _COPY_CALLS and args:
            return arg_ref(args[0]).root
        return None  # any other call result is not the forwarded value
    ref = arg_ref(rhs)
    return ref.root if ref.form in _VALUE_FORMS else None


def _builder_edges(stmt: str) -> list[tuple[str, list[str]]]:
    """Every buffer-builder call in ``stmt`` as (destination root, the roots of its other args)."""
    out: list[tuple[str, list[str]]] = []
    for name in _WRITERS:
        for off in call_offsets(stmt, name):
            args = call_args_at(stmt, off)
            if not args:
                continue
            dst = arg_ref(args[0]).root
            if dst is None:
                continue
            srcs = [r for a in args[1:] if (r := arg_ref(a).root) is not None]
            out.append((dst, srcs))
    return out


def _reaches(root: str, seeds: frozenset[str], edges: Mapping[str, set[str]]) -> bool:
    """``root`` is a seed, or value-derives from one over ``edges``."""
    seen = {root}
    stack = [root]
    while stack:
        cur = stack.pop()
        if cur in seeds:
            return True
        for nxt in edges.get(cur, ()):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return False


def _is_judgement(expr: str) -> bool:
    """``expr`` hands back a verdict, not a value: a top-level comparison / boolean, a leading
    ``!``, or a bare comparison-family call."""
    e = _strip_casts(expr)
    if e.startswith("!") and not e.startswith("!="):
        return True
    depth = 0
    i = 0
    while i < len(e):
        ch = e[i]
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif depth == 0:
            if e.startswith("->", i):  # a field access, not a comparison
                i += 2
                continue
            for op in _COMPARE_OPS:
                if e.startswith(op, i):
                    return True
        i += 1
    lead = _lead_call(e)
    return lead is not None and lead[0] in _COMPARE_CALLS


def _return_hands_source(expr: str, source_names: Iterable[str]) -> bool:
    """Rule 2(b): ``expr`` is a source call, or one wrapped in a single ``strdup`` / ``strndup``
    — the nested forms the seeding tables cannot seed (no assignment left-hand side)."""
    names = set(source_names)
    lead = _lead_call(expr)
    if lead is None:
        return False
    name, args = lead
    if name in names:
        return True
    if name in _COPY_CALLS and args:
        inner = _lead_call(args[0])
        return inner is not None and inner[0] in names
    return False


def _returns_a_source_value(
    pseudocode: str, seeds: frozenset[str], edges: Mapping[str, set[str]], source_names: set[str]
) -> bool:
    """Rule 2: a ``return`` hands on a source value — by returning a seed (or a value derived
    from one), or by returning a source call directly. A judgement is never a value (exclusion)."""
    for stmt in _statements(pseudocode):
        m = re.match(r"return\b\s*(.*)$", stmt, re.DOTALL)
        if m is None:
            continue  # not the return keyword (``returnValue = ...`` is an identifier)
        expr = m.group(1).strip()
        if not expr or _is_judgement(expr):
            continue
        if _return_hands_source(expr, source_names):
            return True
        root = arg_ref(expr).root
        if root is not None and _reaches(root, seeds, edges):
            return True
    return False


def _out_param_slots(
    pseudocode: str, seeds: frozenset[str], edges: Mapping[str, set[str]], source_names: set[str]
) -> set[int]:
    """Rule 3: a buffer builder writes a source value into a parameter. The destination is
    ``param_(k+1)`` and another argument carries a seed; the parameter must not itself be a source
    KEY (it must not appear in any source call's arguments)."""
    keys = _source_key_params(pseudocode, source_names)
    out: set[int] = set()
    for stmt in _statements(pseudocode):
        for dst, srcs in _builder_edges(stmt):
            m = _PARAM_RE.match(dst)
            if m is None or dst in keys:
                continue
            if any(_reaches(s, seeds, edges) for s in srcs):
                out.add(int(m.group(1)) - 1)
    return out


def _source_key_params(pseudocode: str, source_names: set[str]) -> set[str]:
    """The parameters passed as arguments to a source call (its key, never its output)."""
    keys: set[str] = set()
    for name in source_names:
        for off in call_offsets(pseudocode, name):
            for a in call_args_at(pseudocode, off) or []:
                root = arg_ref(a).root
                if root is not None and _PARAM_RE.match(root):
                    keys.add(root)
    return keys


def helper_slots(pseudocode: str, source_names: Iterable[str] = SOURCE) -> frozenset[int]:
    """The slots through which ``pseudocode`` hands on a known source's value (criterion A), or the
    empty set when it is not a value getter. ``RETURN_SLOT`` for a returned value, a 0-based
    position for each out-parameter it writes into. Reads the fixed ``source_names`` only."""
    names = set(source_names)
    if not _source_calls(pseudocode, names):  # rule 1: it must call a source directly
        return frozenset()
    seeds_strong, seeds_weak, _par = _seed_sets(pseudocode)
    seeds = seeds_strong | seeds_weak
    edges = _value_graph(pseudocode)
    slots: set[int] = set()
    if _returns_a_source_value(pseudocode, seeds, edges, names):
        slots.add(RETURN_SLOT)
    slots |= _out_param_slots(pseudocode, seeds, edges, names)
    return frozenset(slots)


# ── the population gate (M3), then criterion A ──────────────────────────────────────────────────


def _is_fun_addr_name(name: str | None) -> bool:
    return bool(name) and _FUN_NAME_RE.match(name or "") is not None


def _return_type_is_bare_void(pseudocode: str) -> bool:
    """The declared return type is exactly ``void`` (``void *`` and every other type are fine)."""
    head = pseudocode[: pseudocode.find("(")] if "(" in pseudocode else pseudocode
    ids = re.findall(r"[A-Za-z_]\w*|\*", head)
    if len(ids) < 2:
        return False
    return ids[:-1] == ["void"]


def _body_shape_ok(pseudocode: str) -> bool:
    """The getter body-shape filter (gate 4): a non-bare-void return, and in the first
    ``_SHAPE_WINDOW`` characters of the body either a ``return`` of a getter-shaped variable or a
    ``memcpy`` / ``strdup``."""
    if _return_type_is_bare_void(pseudocode):
        return False
    window = _body(pseudocode)[:_SHAPE_WINDOW]
    if "memcpy" in window or "strdup" in window:
        return True
    for m in re.finditer(r"\breturn\b\s*(?:\([^()]*\)\s*)?([A-Za-z_]\w*)", window):
        if any(m.group(1).startswith(p) for p in _RETURN_PREFIXES):
            return True
    return False


def _return_taken_call_keys(funcs: Iterable[FuncRow]) -> dict[str, set[str]]:
    """Per callee ``FUN_<addr>`` name, the distinct string literals passed where its RETURN is
    taken across the binary's callers (gate 3). A call takes the return when a lone ``=`` sits
    right before its name (one cast allowed): ``x = FUN_…(…)`` as a statement, and equally
    ``if ((p = FUN_…(…)) != 0)`` inside a condition. Judged at the call, not per statement."""
    keys: dict[str, set[str]] = defaultdict(set)
    for f in funcs:
        pc = f.pseudocode or ""
        # The FUN-<addr> gate, enforced here: only such a name is ever collected.
        for name in {m.group(1) for m in _FUN_CALL_RE.finditer(pc)}:
            for off in call_offsets(pc, name):
                start = off
                while start > 0 and pc[start - 1].isspace():
                    start -= 1
                start -= len(name)
                if not _RETURN_TAKEN_RE.search(pc[max(0, start - 120) : start]):
                    continue  # gate 3: only callsites that TAKE the return count
                for a in call_args_at(pc, off) or []:
                    keys[name].update(_STRING_LIT_RE.findall(a))
    return keys


def _binary_table(funcs: list[FuncRow]) -> SourceHelpers:
    """One binary's value-getter helpers: every ``FUN_<addr>`` function through the M3 gate whose
    body hands on a source value (criterion A)."""
    call_keys = _return_taken_call_keys(funcs)
    slots: set[tuple[str, int]] = set()
    for f in funcs:
        name = f.name
        if name is None:
            continue
        # gate 3: called with >= 2 distinct string keys where its return is taken. Only a
        # FUN_<addr> name accumulates keys (``_return_taken_call_keys``), so a named callee is
        # excluded here, at the single enforcement point of the FUN-name gate.
        if len(call_keys.get(name, ())) < 2:
            continue
        if not f.pseudocode or not _body_shape_ok(f.pseudocode):  # gate 4
            continue
        for slot in helper_slots(f.pseudocode):
            # Only the measured reading is admitted (see the module docstring).
            if slot == RETURN_SLOT:
                slots.add((name, slot))
    return SourceHelpers(frozenset(slots))


def build_helper_tables(funcs: Iterable[FuncRow]) -> dict[int, SourceHelpers]:
    """Each binary's value-getter helper table (binary_id -> SourceHelpers), for the pattern
    scanner. A binary with none is absent, so its scan is exactly what it was before."""
    by_binary: dict[int, list[FuncRow]] = defaultdict(list)
    for f in funcs:
        by_binary[f.binary_id].append(f)
    tables: dict[int, SourceHelpers] = {}
    for binary_id, binary_funcs in by_binary.items():
        table = _binary_table(binary_funcs)
        if table.slots:
            tables[binary_id] = table
    return tables
