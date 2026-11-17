# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Launch edges through a runner: "f calls R(argv, ...), and R execs what f handed it".

A firmware often starts its helper programs through one small function of its own — a runner that
takes an argv array, forks, and calls ``execvp(*argv, argv)``. The launch-edge projection
(``exec_edges``) reads the extractor's per-function sink provenance, so it sees the runner's OWN
exec call, whose argument is a parameter and reads as unresolved; the program the caller actually
named is invisible to it. That gap is the one its scope boundary names, and it is closed HERE, in a
separate pass, so the projection stays a pure projection: ``exec_edges`` is not changed, and the
rows built here only land in the same table.

Three steps, each narrow on purpose:

  1. **Recognise a runner** (``runner_shapes``): a function holding an ``execv`` / ``execvp`` /
     ``execve`` / ``execvpe`` call whose argv argument is one of its own parameters, unchanged, and
     whose path argument comes from one of exactly three places — the first slot of that same array
     (``execvp(*argv, argv)``), ANOTHER parameter (``execve(path, argv, env)``), or a string
     constant in the runner (``execvp("/usr/sbin/tool", argv)``). Anything else — a path built in a
     local buffer, a transformed parameter — is not a runner. Parameters are read off the
     function's own signature, so a runner whose parameters carry real names counts the same as one
     whose parameters are ``param_N``; calls are located by ``call_offsets``, which skips text
     inside a string literal, so a log message naming ``execv(`` is not a call. The variadic
     ``execl*`` family is never a runner: its argv is structurally invisible.
     ★ A function whose name is itself in the command-sink lexicon (the C library's own ``execv``
     wrapping ``execve``) is never a runner: every call to it is already projected from the
     caller's provenance, and a second edge would repeat that edge with the wrong field read. With
     those excluded, the ``exec_api`` of a row built here — the runner's name — is by itself the
     mark of an edge that went through a runner.

  2. **Link the callers.** Across binaries through the exported-call table (``xrefs`` rows of type
     ``callees_exports``), and only when the caller's binary records an import of that name — the
     table links a call by name alone, and the import is what says the caller's binary takes that
     name from outside. Within one binary through the caller's own callee list, which the
     exported-call table does not cover (it stores cross-binary links only): the runner is the ONE
     function of that name in the binary, exported or not. The import gate does not apply there — a
     binary does not shadow a name with itself. Several functions sharing the name, or several
     exporters that do not read the same way, leave the link unresolved rather than picking one.

  3. **Read the target** at each call to the runner, by the runner's shape: (i) the first slot of
     the argv array the caller passes — every write to that stack slot in the caller, each string
     literal one row, plus one unresolved row when any write is not a literal; (ii) the caller's
     argument in the path position, a token only when it is a string literal; (iii) the runner's
     constant. Everything else is read as no token.

★ IRON LAW (the projection's, unchanged): this ENUMERATES, it does not judge. An edge says a call to
a runner exists, never that it runs or that input reaches it, and nothing here can produce a
'blocked'. ★ A target that cannot be read still produces its edge, with no token and an unresolved
state — never a guessed token, never a dropped edge — and an unresolved edge is never an entry site
(``exec_entry_sites`` keeps only a resolved binary target). ★ Only the ONE slot is read for shape
(i): argv beyond it is never reconstructed, a shell in that slot is recorded as ``shell_wrapped``
with ``inner_command_visible=0`` and the command it is handed is not read. Every row is built by
the projection's own fact rules (``_exec_facts`` + ``_build_row``), so a token means the same thing
whichever pass found it.

★ A head slot copied from a ``.data`` word (``slot = DAT_x``) stays unresolved even when those bytes
spell a program name: the block is writable, and reading its initial bytes as the value would assume
nothing changes it at run time — a guess, not a read. A slot written only through the decompiler's
two names for one stack cell (``&stack0xN`` at the call, ``in_stack_N`` at the write) is read
through that alias, which names one cell twice.

★ CALLSITE ATTRIBUTION IS THE SAME OVER-APPROXIMATION as the projection's: a stack slot reused as
the head of several argv arrays has every one of its writes read at every call that passes it, so
``sink_addr`` (here the address of the call to the runner) means "some call to the runner in this
function". "Function f can run X" is true; "this call runs X" is not guaranteed.

Each binary gets one honesty row for this pass (detector ``exec_runner_argv0``), written even at
zero edges, so a binary with no runner edge does not read as one that starts nothing through a
runner. It is kept apart from the projection's row, whose scope it does not share.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path

from treasure_map.lib.atlas.models import DetectorScanStatusRow, ExecEdgeRow
from treasure_map.lib.diff.loader import FuncRow
from treasure_map.lib.hunt.bridge import op_addr_at
from treasure_map.lib.hunt.exec_edges import (
    ExecEdgeInventory,
    _build_row,
    _exec_facts,
    replace_occurrences,
)
from treasure_map.lib.pattern.classes import arg_ref, call_args_at, call_offsets
from treasure_map.lib.pattern.extractor_names import REGISTRY
from treasure_map.lib.ro_db import ro_uri

RUNNER_DETECTOR = "exec_runner_argv0"
# The argv_provenance of every row built here. That column holds the projection's token kind; on a
# runner row whether the target was read is said by target_token (empty when not) and
# target_resolution, and this value only says which pass built the row.
RUNNER_PROVENANCE = "runner_text"

# The exec calls a runner is recognised by: path first, argv array second (execve / execvpe take
# the environment third). The variadic execl* family is absent on purpose — no argv array.
EXEC_ARRAY_APIS: tuple[str, ...] = ("execv", "execvp", "execve", "execvpe")

# Names that are never a runner: every call to one of them is a command sink the projection already
# reads from the caller's own provenance.
NOT_RUNNER_NAMES: frozenset[str] = frozenset(REGISTRY.sink_cmd) | REGISTRY.forward_cmd

SHAPE_ARGV_HEAD = "argv_head"  # execvp(*argv, argv): the image is the array's first slot
SHAPE_PATH_PARAM = "path_param"  # execve(path, argv, env): the image is another parameter
SHAPE_PATH_CONST = "path_const"  # execvp("/usr/sbin/tool", argv): the image is the runner's own

# Ghidra's names for a stack cell: ``local_<hex>``, ``<type>Stack_<hex>``, and ``in_stack_<hex>``
# for a cell the frame analysis left in the caller's area. ``stack0x<hex>`` is the same cell taken
# by address (``&stack0x00000124`` at the call, ``in_stack_00000124`` at the write).
_STACK_SLOT_RE = re.compile(r"(?:local_|[A-Za-z]*Stack_|in_stack_)[0-9a-fA-F]+")
_STACK_ADDR_RE = re.compile(r"stack0x([0-9a-fA-F]+)")
# One C string literal, after any casts. A wide literal (L"...") is not a program name here.
_STRING_LITERAL_RE = re.compile(r'"((?:[^"\\\n]|\\.)*)"')
_CAST_PREFIX_RE = re.compile(
    r"\(\s*(?:const\s+|unsigned\s+|signed\s+|struct\s+|union\s+|enum\s+)*[A-Za-z_]\w*[\s*]*\)\s*"
)
_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
# A function-pointer parameter: the name sits inside the first parenthesised group.
_FNPTR_PARAM_RE = re.compile(r"\(\s*\*\s*([A-Za-z_]\w*)\s*\)")
_IDENT_RE = re.compile(r"[A-Za-z_]\w*")

SUPPORTED_SCOPE = (
    "exec* reached through a runner: a function whose execv/execvp/execve/execvpe call takes its "
    "argv array from one of its own parameters unchanged, the image read as (i) that array's "
    "first slot, (ii) another parameter, or (iii) a string constant in the runner; callers linked "
    "across binaries through the exported-call table (the caller's binary must import the name) "
    "and within a binary through the caller's callee list (one function of that name)"
)

UNSUPPORTED_NOTE = (
    "Only a runner the criterion recognizes is followed: argv taken unchanged from a parameter and "
    "the image from one of the three places above — a path built in a local buffer, a rebound "
    "parameter, or the variadic execl* family is not a runner, and a runner reached only through "
    "another runner is not followed. A name in the command-sink lexicon (the C library's own "
    "execv/execvp) is never a runner: calls to it are the exec_argv pass's. For shape (i) only the "
    "first slot of the caller's argv array is read; the rest of argv is structurally invisible. A "
    "head slot copied from a writable .data word, a variable, a slot never assigned, a root that "
    "is not a stack slot, and a call with fewer arguments than the runner reads are unresolved: "
    "the edge is kept with no token and never offered as an entry site. A stack slot reused as the "
    "head of several arrays has every write read at every call that passes it, so sink_addr "
    "(the call to the runner) means 'some call to the runner in this function'. A slot the "
    "decompiler names twice (&stack0xN at the call, in_stack_N at the write) is read through that "
    "alias. A name held by several functions of one binary, or exported by several binaries that "
    "do not read the same way, is left unresolved; a name the exported-call table folded (exported "
    "by many binaries) is not linked across binaries. A binary whose status says scanned=0 has a "
    "function that calls a runner, or an exec call of its own, that was not read (no pseudocode)."
)


@dataclass(frozen=True)
class RunnerShape:
    """Where one runner's exec call takes its image from.

    ``argv_index`` is the 0-based position of the argv parameter in the runner's signature — the
    caller's argument at that position is the array. ``path_index`` (shape ``path_param``) is the
    position of the image parameter; ``path_const`` (shape ``path_const``) is the image itself."""

    kind: str
    argv_index: int
    path_index: int | None = None
    path_const: str | None = None


# ── recognising a runner ──────────────────────────────────────────────────────────────


def signature_params(name: str | None, pseudocode: str | None) -> list[str] | None:
    """The parameter names of the function's own declaration, by position, or None when the
    declaration cannot be found. ``void`` alone is an empty list; ``...`` is not a parameter.

    Read from the signature the decompiler printed, so a parameter keeps whatever name it was
    given — the C library names its own (``__argv``), a stripped binary's are ``param_N``."""
    if not name or not pseudocode:
        return None
    brace = pseudocode.find("{")
    head = pseudocode if brace == -1 else pseudocode[:brace]
    matches = list(re.finditer(rf"\b{re.escape(name)}\s*\(", head))
    if not matches:
        return None
    args = call_args_at(head, matches[-1].end() - 1)
    if args is None:
        return None
    names: list[str] = []
    for raw in args:
        text = _COMMENT_RE.sub(" ", raw).strip()
        if text in ("", "void", "..."):
            continue
        fnptr = _FNPTR_PARAM_RE.search(text)
        if fnptr:
            names.append(fnptr.group(1))
            continue
        idents = _IDENT_RE.findall(re.sub(r"\[[^\]]*\]\s*$", "", text))
        names.append(idents[-1] if idents else "")
    return names


def _body(pseudocode: str) -> str:
    brace = pseudocode.find("{")
    return pseudocode if brace == -1 else pseudocode[brace:]


def _rebound(body: str, name: str) -> bool:
    """Does the body assign to ``name`` (``name = …``, ``name += …``, ``name++``, ``*name = …``,
    ``name[0] = …``)?

    A rebound parameter no longer holds what the caller passed, so an exec call reading it is not
    reading the caller's value — the "transformed" case that is not a runner."""
    n = re.escape(name)
    return bool(
        re.search(rf"(?<![\w.>])\b{n}\s*(?:\[\s*0\s*\]\s*)?(?:[-+*/%|&^]|<<|>>)?=(?!=)", body)
        or re.search(rf"\b{n}\s*(?:\+\+|--)|(?:\+\+|--)\s*\b{n}\b", body)
    )


def string_literal(text: str) -> str | None:
    """The text of ``text`` when it is ONE C string literal (after any casts), else None."""
    t = _COMMENT_RE.sub(" ", text).strip()
    while True:
        m = _CAST_PREFIX_RE.match(t)
        if not m or m.end() >= len(t):
            break
        t = t[m.end() :].strip()
    m = _STRING_LITERAL_RE.fullmatch(t)
    return m.group(1) if m else None


def _reads_head(path: str | None, root: str) -> bool:
    """Is a load expression the FIRST slot of ``root`` (``*root`` / ``root[0]``, casts aside)?"""
    if not path:
        return False
    flat = re.sub(r"\s+", "", _CAST_PREFIX_RE.sub("", path))
    return flat in (f"*{root}", f"{root}[0]")


def runner_shapes(
    name: str | None, pseudocode: str | None, stub_names: Mapping[int, str] | None = None
) -> frozenset[RunnerShape]:
    """The shapes in which this function execs what its caller handed it — empty when it is not a
    runner. Judges the body alone; the sink-name exclusion is applied by ``find_runners``."""
    params = signature_params(name, pseudocode)
    if not params or not pseudocode:
        return frozenset()
    body = _body(pseudocode)
    shapes: set[RunnerShape] = set()
    for api in EXEC_ARRAY_APIS:
        for off in call_offsets(pseudocode, api, stub_names):
            args = call_args_at(pseudocode, off)
            if not args or len(args) < 2:
                continue
            argv = arg_ref(args[1])
            if argv.form not in ("var", "cast") or argv.root not in params:
                continue
            # The rebound check guards the parameter the IMAGE is read from: argv for shape (i),
            # the path parameter for (ii). A constant image (iii) does not depend on either.
            argv_index = params.index(argv.root)
            const = string_literal(args[0])
            if const is not None:
                shapes.add(RunnerShape(SHAPE_PATH_CONST, argv_index, path_const=const))
                continue
            path = arg_ref(args[0])
            if path.form in ("var", "cast") and path.root in params and path.root != argv.root:
                if not _rebound(body, path.root):
                    shapes.add(
                        RunnerShape(
                            SHAPE_PATH_PARAM, argv_index, path_index=params.index(path.root)
                        )
                    )
            elif (
                path.form == "load"
                and path.root == argv.root
                and _reads_head(path.path, argv.root)
                and not _rebound(body, argv.root)
            ):
                shapes.add(RunnerShape(SHAPE_ARGV_HEAD, argv_index))
    return frozenset(shapes)


def _callees(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return []
    return [str(x) for x in data] if isinstance(data, list) else []


def find_runners(
    funcs: Iterable[FuncRow], stub_by_binary: Mapping[int, Mapping[int, str]] | None = None
) -> dict[int, frozenset[RunnerShape]]:
    """func_id -> shapes for every runner in the run. Only a function that calls an exec-array API
    is read, and a name in the command-sink lexicon is never one (see the module docstring)."""
    stubs = stub_by_binary or {}
    out: dict[int, frozenset[RunnerShape]] = {}
    for func in funcs:
        if not func.name or func.name in NOT_RUNNER_NAMES or not func.pseudocode:
            continue
        if not set(_callees(func.callees)) & set(EXEC_ARRAY_APIS):
            continue
        shapes = runner_shapes(func.name, func.pseudocode, stubs.get(func.binary_id))
        if shapes:
            out[func.func_id] = shapes
    return out


# ── linking the callers ───────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class LinkTables:
    """What the cross-binary link reads from the analysis.db: the exported-call links (caller
    func_id -> callee func_ids) and every binary's imported names."""

    exported_calls: Mapping[int, tuple[int, ...]]
    imports: frozenset[tuple[int, str]]


def load_link_tables(db_path: Path | str) -> LinkTables:
    """Read the exported-call links and the import names, read-only. An analysis.db without either
    table yields empty links (no cross-binary runner edge, never a failure)."""
    conn = sqlite3.connect(ro_uri(Path(db_path)), uri=True)
    calls: dict[int, list[int]] = {}
    imports: set[tuple[int, str]] = set()
    try:
        try:
            for caller, callee in conn.execute(
                "SELECT caller_func_id, callee_func_id FROM xrefs "
                "WHERE xref_type = 'callees_exports' "
                "AND caller_func_id IS NOT NULL AND callee_func_id IS NOT NULL"
            ):
                calls.setdefault(int(caller), []).append(int(callee))
        except sqlite3.OperationalError:
            calls = {}
        try:
            for binary_id, name in conn.execute("SELECT binary_id, func_name FROM imports"):
                if name:
                    imports.add((int(binary_id), str(name)))
        except sqlite3.OperationalError:
            imports = set()
    finally:
        conn.close()
    return LinkTables(
        exported_calls={k: tuple(sorted(set(v))) for k, v in calls.items()},
        imports=frozenset(imports),
    )


# A link outcome: the shapes to read with, or None when the name points at several functions that
# do not read the same way (the edge is kept, unresolved).
_Link = frozenset[RunnerShape] | None


def link_callers(
    funcs: list[FuncRow],
    runners: Mapping[int, frozenset[RunnerShape]],
    links: LinkTables,
) -> dict[int, dict[str, _Link]]:
    """caller func_id -> {runner name -> how to read the call}, for every function that calls a
    runner. Within a binary the callee list is read and the name must name ONE function there;
    across binaries the exported-call links are read and the caller's binary must import the name.
    A name resolved within the caller's own binary is not also looked up across binaries."""
    by_id = {f.func_id: f for f in funcs}
    local: dict[tuple[int, str], list[int]] = {}
    for f in funcs:
        if f.name:
            local.setdefault((f.binary_id, f.name), []).append(f.func_id)
    runner_names = {by_id[i].name for i in runners if i in by_id}
    out: dict[int, dict[str, _Link]] = {}
    for f in funcs:
        named: dict[str, _Link] = {}
        for callee in set(_callees(f.callees)) & runner_names:
            ids = local.get((f.binary_id, callee), [])
            hits = [i for i in ids if i in runners and i != f.func_id]
            if not hits:
                continue
            named[callee] = runners[hits[0]] if len(ids) == 1 else None
        exporters: dict[str, list[int]] = {}
        for callee_id in links.exported_calls.get(f.func_id, ()):
            exporter = by_id.get(callee_id)
            if exporter is None or not exporter.name or exporter.binary_id == f.binary_id:
                continue
            exporters.setdefault(exporter.name, []).append(callee_id)
        for callee_name, ids in exporters.items():
            if callee_name in named or not any(i in runners for i in ids):
                continue
            if (f.binary_id, callee_name) not in links.imports:
                continue
            shapes = {runners.get(i) for i in ids}
            named[callee_name] = next(iter(shapes)) if len(shapes) == 1 else None
        if named:
            out[f.func_id] = named
    return out


# ── reading the target at a call to the runner ────────────────────────────────────────


def _head_slot(arg_text: str) -> str | None:
    """The stack slot that is the first cell of the argv array passed as ``arg_text``: the slot
    whose address is taken (``&local_28``), with ``&stack0xN`` read as its ``in_stack_N`` name.
    None when the array is anything else (a parameter, a global, a pointer variable)."""
    ref = arg_ref(arg_text)
    if ref.form != "addr_of" or not ref.root:
        return None
    alias = _STACK_ADDR_RE.fullmatch(ref.root)
    if alias:
        return f"in_stack_{alias.group(1)}"
    return ref.root if _STACK_SLOT_RE.fullmatch(ref.root) else None


def slot_writes(pseudocode: str, slot: str) -> list[str]:
    """The right-hand side of every plain assignment ``slot = …;`` in the body, in source order —
    ALL of them, not only the ones that dominate a given call (see the module docstring)."""
    out: list[str] = []
    body = _body(pseudocode)
    for m in re.finditer(rf"(?m)^[ \t]*{re.escape(slot)}[ \t]*=(?!=)", body):
        i, n = m.end(), len(body)
        start = i
        while i < n and body[i] != ";":
            if body[i] in "\"'":
                q = body[i]
                i += 1
                while i < n and body[i] != q and body[i] != "\n":
                    i += 2 if body[i] == "\\" else 1
            i += 1
        out.append(body[start:i].strip())
    return out


def _target_values(shape: RunnerShape, args: list[str] | None, pseudocode: str) -> list[str | None]:
    """The tokens one call reads under one shape; None stands for "no readable token"."""
    if shape.kind == SHAPE_PATH_CONST:
        return [shape.path_const]
    if shape.kind == SHAPE_PATH_PARAM:
        if args is None or shape.path_index is None or len(args) <= shape.path_index:
            return [None]
        return [string_literal(args[shape.path_index])]
    if args is None or len(args) <= shape.argv_index:
        return [None]
    slot = _head_slot(args[shape.argv_index])
    if slot is None:
        return [None]
    writes = slot_writes(pseudocode, slot)
    literals = [string_literal(w) for w in writes]
    values: list[str | None] = [v for v in literals if v is not None]
    if not writes or len(values) < len(writes):
        values.append(None)
    return values


def build_runner_edges(
    funcs: list[FuncRow],
    callers: Mapping[int, Mapping[str, _Link]],
    inventory: ExecEdgeInventory,
    source_run_id: str,
    stub_by_binary: Mapping[int, Mapping[int, str]] | None = None,
) -> list[ExecEdgeRow]:
    """One row per (caller, call to a runner, token), folded on the projection's own key
    ``(binary, function, sink address, token)`` with ``occurrences`` counted, in a deterministic
    order. ``sink_addr`` is the address of the call instruction, read from the call-token bridge;
    a call the bridge does not place keeps an empty one."""
    stubs = stub_by_binary or {}
    by_id = {f.func_id: f for f in funcs}
    edges: dict[tuple[str | None, str | None, str | None, str], ExecEdgeRow] = {}
    for caller_id in sorted(callers):
        func = by_id.get(caller_id)
        if func is None or not func.pseudocode:
            continue
        ps = func.pseudocode
        for name in sorted(callers[caller_id]):
            shapes = callers[caller_id][name]
            for off in call_offsets(ps, name, stubs.get(func.binary_id)):
                args = call_args_at(ps, off)
                sink_addr = op_addr_at(func.call_tokens, ps, off)
                values: list[str | None] = []
                if shapes is None:
                    values = [None]
                else:
                    for shape in sorted(shapes, key=_shape_key):
                        values.extend(_target_values(shape, args, ps))
                seen: set[str | None] = set()
                for value in values:
                    if value in seen:
                        continue
                    seen.add(value)
                    row = _build_row(
                        func, name, sink_addr, _exec_facts(value), inventory, source_run_id
                    )
                    row = replace(row, argv_provenance=RUNNER_PROVENANCE)
                    key = (func.binary_name, func.name, row.sink_addr, row.target_token or "")
                    existing = edges.get(key)
                    edges[key] = (
                        row
                        if existing is None
                        else replace_occurrences(existing, existing.occurrences + 1)
                    )
    return [edges[k] for k in sorted(edges, key=lambda k: tuple(str(p) for p in k))]


def _shape_key(shape: RunnerShape) -> tuple[str, int, int, str]:
    return (
        shape.kind,
        shape.argv_index,
        -1 if shape.path_index is None else shape.path_index,
        shape.path_const or "",
    )


# ── the pass's honesty row ────────────────────────────────────────────────────────────


def runner_scan_status(
    edge_rows: list[ExecEdgeRow],
    funcs: list[FuncRow],
    callers: Mapping[int, Mapping[str, _Link]],
    links: LinkTables,
    runner_names: Iterable[str],
    source_run_id: str,
) -> list[DetectorScanStatusRow]:
    """One row per binary for this pass, written EVEN AT zero edges (see the module docstring).

    ``scanned`` is 0 for a binary holding a function that was not read and may launch through a
    runner: one that calls an exec-array API itself (it may be a runner of that binary's own) or
    one whose callee list names a runner (by name within the binary, by an exported-call link
    across binaries), with no pseudocode. ``found_count`` counts this pass's rows, never the
    projection's, so the projection's own row keeps its count."""
    names = set(runner_names)
    by_id = {f.func_id: f for f in funcs}
    unread: set[str | None] = set()
    for f in funcs:
        if f.pseudocode and f.pseudocode.strip():
            continue
        called = set(_callees(f.callees))
        linked = any(
            (c := by_id.get(i)) is not None and c.name in names
            for i in links.exported_calls.get(f.func_id, ())
        )
        if called & set(EXEC_ARRAY_APIS) or called & names or linked or f.func_id in callers:
            unread.add(f.binary_name)
    found: dict[str | None, int] = {}
    for row in edge_rows:
        found[row.launcher_binary] = found.get(row.launcher_binary, 0) + 1
    binaries = {f.binary_name for f in funcs} | set(found)
    paths: dict[str | None, str | None] = {f.binary_name: f.binary_path for f in funcs}
    return [
        DetectorScanStatusRow(
            source_run_id=source_run_id,
            binary=binary,
            binary_path=paths.get(binary),
            detector=RUNNER_DETECTOR,
            scanned=0 if binary in unread else 1,
            supported_scope=SUPPORTED_SCOPE,
            unsupported_note=UNSUPPORTED_NOTE,
            cap_hit=0,
            found_count=found.get(binary, 0),
        )
        for binary in sorted(binaries, key=lambda b: (b is None, b or ""))
    ]


def runner_pass(
    db_path: Path | str,
    funcs: list[FuncRow],
    inventory: ExecEdgeInventory,
    source_run_id: str,
    stub_by_binary: Mapping[int, Mapping[int, str]] | None = None,
) -> tuple[list[ExecEdgeRow], list[DetectorScanStatusRow]]:
    """The whole pass for one run: recognise the runners, link their callers, read the targets,
    and write the per-binary status. Returns (edge rows, status rows)."""
    runners = find_runners(funcs, stub_by_binary)
    links = load_link_tables(db_path)
    callers = link_callers(funcs, runners, links)
    rows = build_runner_edges(funcs, callers, inventory, source_run_id, stub_by_binary)
    names = {f.name for f in funcs if f.func_id in runners and f.name}
    status = runner_scan_status(rows, funcs, callers, links, names, source_run_id)
    return rows, status
