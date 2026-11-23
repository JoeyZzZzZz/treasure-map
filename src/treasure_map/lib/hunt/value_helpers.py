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

  * ``build_helper_tables`` — the population gates plus criterion A, per binary. TWO admission
    rules, each with its own gate, and a function admitted by either is in the table:

      - the MEASURED rule (M3): a stripped ``FUN_<addr>`` name, called with at least two distinct
        string keys where its return is taken, and a body whose shape reads like a getter
        (``_body_shape_ok``). Only such a function is handed to ``helper_slots``, and only its
        ``RETURN_SLOT`` reading is admitted — the return slot's precision was measured on the built
        tables, while the out-parameter reading had no member on any corpus it was measured on, so
        under this rule it stays computed (to be measured where it has members) and unadmitted.

      - the KEYED-LOOKUP rule: a getter that parses its own input, so it calls no known source NAME
        at all and criterion A cannot see it. It is admitted on shape instead, behind a gate narrow
        enough to keep "any void writer" out: a ``FUN_<addr>`` name called with at least two
        distinct string-literal keys (at ANY callsite — a writer whose return nobody takes is the
        case this rule exists for), an indirect read in the body, and — the narrowing lock — the
        PARAMETER the keys arrive at must reach a compare/search, in the body or one hop into a
        callee (``_keyed_lookup``). Both slots are admitted under this rule: the RETURN_SLOT when
        the getter body-shape holds, and each out-parameter a buffer writer fills when the body
        writes one (a bare-void writer cannot pass ``_body_shape_ok`` at all, and that is the shape
        this rule most needs to reach).

A helper is read as WEAK input downstream, so it labels a candidate and seeds weak taint and never
grades one ``confirmed``. Finding one says nothing about whether the value it hands on is
attacker-controlled — a structural reading, not a verdict. A CALLER of a helper reads this way
because the helper is in its callee list; the helper's OWN body does not call itself, so its own
candidates would read as having no source at all. ``shapes.classify`` closes that: a candidate
whose function IS an admitted helper reads that function as the same weak source its callers read
(it was admitted because it reads external input, so its body handles that input) — never a new
admission, never widening the population, only a reading of the one already decided here.

Which KEY a caller hands a helper is evidence a reader confirms a lead with. A key is read only
from the helper's key argument position (``SourceHelpers.key_positions``, the parameters the body
compares/searches — the one authority ``_key_reaching_positions``); a default-value or separator
argument sharing the callsite is not a key and is never reported as one.

Deliberately narrow, every boundary stated rather than approximated:
  * a value getter that calls no known source NAME is reached ONLY through the keyed-lookup rule,
    on the shape of a string-keyed lookup — never on "it dereferences something" alone, which is
    nearly every function. What the keys name is evidence for a reader (``helper_keys_called``),
    not a claim that the value is controlled;
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
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

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


# ── the keyed-lookup rule: a getter that parses its own input ───────────────────────────────────

# Parsing calls: a function handed a parameter to one of these reads a structure out of it rather
# than taking a value whole, which is what makes it a getter the SOURCE-name rule cannot see.
_PARSE_CALLS: frozenset[str] = frozenset({"strstr", "strtok", "strsep", "sscanf", "strchr"})
# Compare / search calls: the key parameter reaching one of these is what separates a string-KEYED
# lookup from any function that happens to be called with two literals.
_LOOKUP_CALLS: frozenset[str] = frozenset({"strcmp", "strncmp", "strstr", "memcmp"})
# Buffer writers whose destination (argument 0) is where an out-parameter getter puts its value.
_OUT_WRITE_CALLS: frozenset[str] = frozenset({"strcpy", "memcpy", "strncpy", "sprintf"})
_DEREF_RE = re.compile(r"\*\s*\(")
# A ``&DAT_<addr>`` pointer argument: a key whose text the extractor never typed as a string. The
# ``&`` is required — a bare ``DAT_<addr>`` is the global's VALUE passed by value, not a pointer to
# a key, so it names no key here.
_DAT_REF_RE = re.compile(r"&DAT_([0-9a-fA-F]+)\b")
_PARAM_IN_RE = re.compile(r"\bparam_(\d+)\b")
_ANY_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")


@dataclass(frozen=True)
class _CallsiteKeys:
    """What a binary's callers pass to one ``FUN_<addr>`` callee: the distinct string-literal keys,
    and the 0-based ARGUMENT POSITIONS a key was seen at. The positions are what makes the lookup
    lock checkable — they say which of the callee's own parameters is the key."""

    keys: frozenset[str]
    positions: frozenset[int]


def _callsite_keys(
    funcs: Iterable[FuncRow],
) -> tuple[dict[str, set[str]], dict[str, _CallsiteKeys]]:
    """Both key tables a binary's admission needs, in ONE pass over its callsites:

      * ``taken`` — per callee ``FUN_<addr>`` name, the distinct string literals passed where its
        RETURN is taken (gate 3 of the measured rule). A call takes the return when a lone ``=``
        sits right before its name (one cast allowed): ``x = FUN_…(…)``, and equally
        ``if ((p = FUN_…(…)) != 0)``. Judged at the call, not per statement.
      * ``every`` — per such name, the string-literal keys passed at EVERY callsite and the
        argument positions they arrived at (the keyed-lookup rule, whose getters write into a
        caller's buffer and take no return). Only string LITERALS count toward the gate — a
        ``&DAT_`` pointer also names a key for a reader (``helper_keys_called``), but counting
        those would widen the admitted population without reaching a getter the literals miss.

    These were two passes until the self-source feature made each walk every (function, FUN-name,
    callsite); merged here so ``call_offsets`` / ``call_args_at`` and the return-taken test run
    once per callsite, not twice."""
    taken: dict[str, set[str]] = defaultdict(set)
    every: dict[str, set[str]] = defaultdict(set)
    positions: dict[str, set[int]] = defaultdict(set)
    for f in funcs:
        pc = f.pseudocode or ""
        # The FUN-<addr> gate, enforced here: only such a name is ever collected, so a named
        # callee can never accumulate keys.
        for name in {m.group(1) for m in _FUN_CALL_RE.finditer(pc)}:
            for off in call_offsets(pc, name):
                start = off
                while start > 0 and pc[start - 1].isspace():
                    start -= 1
                start -= len(name)
                is_taken = bool(_RETURN_TAKEN_RE.search(pc[max(0, start - 120) : start]))
                for pos, a in enumerate(call_args_at(pc, off) or []):
                    found = _STRING_LIT_RE.findall(a)
                    if not found:
                        continue
                    every[name].update(found)
                    positions[name].add(pos)
                    if is_taken:
                        taken[name].update(found)
    every_out = {
        name: _CallsiteKeys(frozenset(ks), frozenset(positions[name])) for name, ks in every.items()
    }
    return taken, every_out


def _reads_indirect(pseudocode: str) -> bool:
    """The body reads through something rather than only taking values whole: a ``memcpy``, a
    reference to a ``DAT_`` global, a pointer dereference, or a parse call handed a parameter.

    Honest about what this is: a NECESSARY condition that nearly every non-trivial body meets, not
    a filter. It states the shape the rule is about (a getter reads a structure) and keeps a
    straight-line arithmetic helper out; the admitted population is held down by the key gate and
    by ``_keyed_lookup``, never by this."""
    body = _body(pseudocode)
    if "memcpy" in body or "DAT_" in body or _DEREF_RE.search(body) is not None:
        return True
    return any(
        (args := call_args_at(pseudocode, off)) and "param_" in args[0]
        for name in _PARSE_CALLS
        for off in call_offsets(pseudocode, name)
    )


def _compared_param_positions(pseudocode: str) -> frozenset[int]:
    """The 0-based parameter positions that reach a compare/search call IN THIS body."""
    hit: set[int] = set()
    for name in _LOOKUP_CALLS:
        for off in call_offsets(pseudocode, name):
            for a in call_args_at(pseudocode, off) or []:
                hit.update(int(m.group(1)) - 1 for m in _PARAM_IN_RE.finditer(a))
    return frozenset(hit)


def _forwarded_param_positions(pseudocode: str) -> dict[str, set[tuple[int, int]]]:
    """Per callee name, the (this function's 0-based parameter position, the callee's 0-based
    argument position) pairs — how this body's parameters are handed on one hop."""
    out: dict[str, set[tuple[int, int]]] = defaultdict(set)
    for m in _ANY_CALL_RE.finditer(pseudocode):
        args = call_args_at(pseudocode, m.start(1)) or []
        for pos, a in enumerate(args):
            for pm in _PARAM_IN_RE.finditer(a):
                out[m.group(1)].add((int(pm.group(1)) - 1, pos))
    return out


def _key_reaching_positions(
    pseudocode: str, compared_in: Callable[[str], frozenset[int]]
) -> frozenset[int]:
    """This body's own 0-based parameter positions that reach a compare/search — in the body, or
    one hop into a callee at an argument position that callee compares.

    The SINGLE authority for "which of this function's parameters is a key": the admission lock
    (``_keyed_lookup``) asks whether the callers' key positions land in this set, and the key
    evidence layer (``SourceHelpers.key_positions``) records this set so a reader takes a key only
    from the key argument. One hop and no more (see ``_keyed_lookup`` on why)."""
    hit: set[int] = set(compared_in(pseudocode))
    for callee, pairs in _forwarded_param_positions(pseudocode).items():
        compared = compared_in(callee)
        if compared:
            hit.update(mine for mine, theirs in pairs if theirs in compared)
    return frozenset(hit)


def _keyed_lookup(
    pseudocode: str,
    key_positions: frozenset[int],
    compared_in: Callable[[str], frozenset[int]],
) -> bool:
    """The narrowing lock: a parameter the callers pass a KEY at reaches a compare/search — in this
    body, or one hop into a callee at an argument position that callee compares.

    This is what separates a string-keyed lookup ("find the field named k") from any function that
    merely happens to be called with two literals. One hop is needed and no more: a request parser
    commonly hands the name straight to a small matcher, and a hop count beyond that would be a
    flow relation this layer deliberately does not compute (see the module docstring). It reads
    PARAMETER POSITIONS, never values: nothing here claims the key is attacker-controlled."""
    return bool(key_positions & _key_reaching_positions(pseudocode, compared_in))


def _writes_a_caller_buffer(pseudocode: str) -> bool:
    """The out-parameter rule's stand-in for gate 4: the body copies into a buffer. A bare-void
    getter can never pass ``_body_shape_ok`` (no return type to read as a getter's), so the shape
    this rule most needs to reach has to be recognised by what the body DOES instead."""
    body = _body(pseudocode)
    return "strcpy" in body or "memcpy" in body


def _out_write_slots(pseudocode: str) -> frozenset[int]:
    """The 0-based parameter positions a buffer writer's destination IS — the slots this body hands
    its value out through. Unlike ``_out_param_slots`` (criterion A) this does not ask whether a
    KNOWN source fed the value: under the keyed-lookup rule there is no known source to find, so
    the destination parameter is read from the write itself."""
    out: set[int] = set()
    for name in _OUT_WRITE_CALLS:
        for off in call_offsets(pseudocode, name):
            args = call_args_at(pseudocode, off) or []
            if not args:
                continue
            root = arg_ref(args[0]).root
            m = _PARAM_RE.match(root) if root is not None else None
            if m is not None:
                out.add(int(m.group(1)) - 1)
    return frozenset(out)


def _keyed_lookup_slots(
    pseudocode: str,
    callsite_keys: _CallsiteKeys | None,
    compared_in: Callable[[str], frozenset[int]],
) -> frozenset[int]:
    """The slots one body hands a value through under the KEYED-LOOKUP rule, or the empty set when
    the rule does not reach it. The gate order is by cost: the precomputed key count first, the
    body-local shape next, the lookup lock (which may read a callee's body) last."""
    if callsite_keys is None or len(callsite_keys.keys) < 2:  # the key gate
        return frozenset()
    if not _reads_indirect(pseudocode):
        return frozenset()
    if not _keyed_lookup(pseudocode, callsite_keys.positions, compared_in):
        return frozenset()
    slots: set[int] = set()
    if _body_shape_ok(pseudocode):
        slots.add(RETURN_SLOT)
    if _writes_a_caller_buffer(pseudocode):
        slots |= _out_write_slots(pseudocode)
    return frozenset(slots)


def helper_keys_called(pseudocode: str, helpers: SourceHelpers) -> tuple[dict[str, Any], ...]:
    """The keys THIS function passes to its binary's value-getter helpers, as evidence rows for a
    reader: ``{"key", "key_origin", "accessor", "hops", "position"}``, ordered by accessor, origin,
    key then position.

    A key is read ONLY from the helper's KEY argument position (``helpers.key_positions_of``): the
    position its body compares/searches the parameter at. A getter's other arguments — the
    default value a lookup returns when the key is absent, a separator literal — are not keys, and
    reading them as keys reports a field name the getter was never asked for. A helper whose key
    position could not be computed contributes no rows at all (no anchor, no row).

    ``key_origin`` is ``literal`` for an inline string and ``data_ref`` for a ``&DAT_<addr>``
    pointer argument, whose text is not in the extracted ``strings`` table (Ghidra left the bytes
    untyped) and is resolved from the loaded data blocks by the caller — the row then carries
    ``address`` and a ``key`` of None until it is. ``hops`` is 1: the key is passed at a direct
    call to the accessor. ``position`` is the 0-based argument index the key sat at.

    It names ARGUMENTS, not flows: a key here is what the caller asked the getter for, not proof
    that the value came back, reached the sink, or is controlled by anyone."""
    rows: dict[tuple[str, str, str | None, int], dict[str, Any]] = {}
    for name in sorted(helpers.names):
        if name not in pseudocode:  # the cheap gate first: a binary can hold many helpers
            continue
        key_positions = helpers.key_positions_of(name)
        if not key_positions:  # no computed key position → this helper names no key here
            continue
        for off in call_offsets(pseudocode, name):
            for pos, a in enumerate(call_args_at(pseudocode, off) or []):
                if (
                    pos not in key_positions
                ):  # read only the key argument, never a default/separator
                    continue
                for lit in _STRING_LIT_RE.findall(a):
                    key = lit[1:-1]
                    rows[(name, "literal", key, pos)] = {
                        "key": key,
                        "key_origin": "literal",
                        "accessor": name,
                        "hops": 1,
                        "position": pos,
                    }
                for m in _DAT_REF_RE.finditer(a):
                    addr = m.group(1)
                    rows[(name, "data_ref", addr, pos)] = {
                        "key": None,
                        "key_origin": "data_ref",
                        "address": addr,
                        "accessor": name,
                        "hops": 1,
                        "position": pos,
                    }
    return tuple(rows[k] for k in sorted(rows, key=lambda k: (k[0], k[1], k[2] or "", k[3])))


def _binary_table(funcs: list[FuncRow]) -> SourceHelpers:
    """One binary's value-getter helpers: every ``FUN_<addr>`` function admitted by EITHER rule —
    the measured one (the M3 gate, then criterion A, RETURN_SLOT only) or the keyed-lookup one (a
    string-keyed lookup recognised on shape, both slots). A function may be admitted by both; the
    slots are a set, so one reading never doubles another."""
    call_keys, every_keys = _callsite_keys(funcs)
    bodies = {f.name: f.pseudocode or "" for f in funcs if f.name is not None}
    compared: dict[str, frozenset[int]] = {}

    def compared_in(name_or_body: str) -> frozenset[int]:
        """The compared parameter positions of a callee NAME, or of a body passed whole. Memoised:
        a request parser's matcher is reached from many of its callers."""
        body = bodies.get(name_or_body, name_or_body)
        hit = compared.get(body)
        if hit is None:
            hit = _compared_param_positions(body)
            compared[body] = hit
        return hit

    slots: set[tuple[str, int]] = set()
    for f in funcs:
        name = f.name
        if name is None or not f.pseudocode:
            continue
        pc = f.pseudocode
        # ── the measured rule, unchanged ──
        # gate 3: called with >= 2 distinct string keys where its return is taken. Only a
        # FUN_<addr> name accumulates keys (``_callsite_keys``), so a named callee is excluded
        # here, at the single enforcement point of the FUN-name gate.
        if len(call_keys.get(name, ())) >= 2 and _body_shape_ok(pc):  # gate 4
            for slot in helper_slots(pc):
                # Only the measured reading is admitted (see the module docstring).
                if slot == RETURN_SLOT:
                    slots.add((name, slot))
        # ── the keyed-lookup rule ──
        slots |= {(name, s) for s in _keyed_lookup_slots(pc, every_keys.get(name), compared_in)}
    # The key argument position of each admitted helper (``helper_keys_called`` reads a key only
    # there). Computed for admitted names only, over the same memoised ``compared_in``.
    key_positions = {
        (name, pos)
        for name in {n for n, _ in slots}
        for pos in _key_reaching_positions(bodies.get(name, ""), compared_in)
    }
    return SourceHelpers(frozenset(slots), key_positions=frozenset(key_positions))


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
