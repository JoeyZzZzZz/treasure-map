# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Which code a stored diff, or a stored sink-overlay baseline, was computed by.

Both are versioned by hashing the code itself, so a change to it makes what it wrote read as stale
without anyone remembering to bump a number. Three hashes:

  * ``diff_code_version()`` — the Python code whose output a diff writes (``DIFF_CODE_ENTRIES``).
  * ``sink_overlay_logic_version()`` — the Python code a stored baseline row is computed by
    (``OVERLAY_CODE_ENTRIES``).
  * ``export_code_hash(builder)`` — the export script Ghidra ran for one side, by the path the
    export took (``ExportBinExport.java`` alone, or with ``FallbackBinExport2Builder.java``).

An entry is a module of the ``treasure_map`` package (``lib.diff.layer0``) or one top-level name in
it (``lib.atlas.writer:add_diff_meta``), for a large shared module of which only that function,
class or constant feeds the rows. Python source is hashed after normalisation: parsed, docstrings
dropped, and dumped without positions and without empty fields — so comments, docstrings and
formatting do not count, and the value is the same under the Python versions tmap supports (a newer
version adding an optional AST field leaves it empty here). The Java files are hashed byte for byte.

The entries are locked against their criterion by tests/unit/lib/test_code_version.py: every name
a listed entry takes from another ``treasure_map`` module, outside type annotations, must be listed
too or excluded below with the reason. ``_EXCLUDED`` is that list of reasons.

BOUNDARY: third-party libraries and the interpreter are not hashed (the listed modules use only
the standard library and sqlite); the external toolchain is recorded separately
(lib/diff/toolchain).
"""

from __future__ import annotations

import ast
import hashlib
import json
from collections.abc import Iterable
from functools import cache
from pathlib import Path

# the treasure_map package directory, the root every entry is relative to
_PACKAGE = Path(__file__).resolve().parents[2]
_SCRIPT_DIR = Path(__file__).resolve().parent / "ghidra"
_EXPORT_SCRIPT = "ExportBinExport.java"
_FALLBACK_BUILDER = "FallbackBinExport2Builder.java"

# The code a stored diff row is produced by: the diff modules, and what they take from shared
# modules into what they write.
DIFF_CODE_ENTRIES: tuple[str, ...] = (
    "lib.diff.binexport2",
    "lib.diff.callsite_facts",
    "lib.diff.code_version",
    "lib.diff.currency",
    "lib.diff.driver",
    "lib.diff.export_report",
    "lib.diff.layer0",
    "lib.diff.layer2",
    "lib.binary_id",
    "lib.callsite_ref",
    "lib.hunt.refs",
    "lib.query.runs",
    "lib.ro_db",
    "lib.atlas.models:DiffMetaRow",
    "lib.atlas.models:DimensionCapabilityStateRow",
    "lib.atlas.models:DimensionDeltaRow",
    "lib.atlas.models:FunctionAlignmentRow",
    "lib.atlas.models:FunctionPresenceRow",
    "lib.atlas.models:InstructionMatchRow",
    "lib.atlas.models:RunRow",
    "lib.atlas.writer:add_diff_meta",
    "lib.atlas.writer:add_dimension_capability_states",
    "lib.atlas.writer:add_dimension_deltas",
    "lib.atlas.writer:add_function_alignment",
    "lib.atlas.writer:add_function_presence",
    "lib.atlas.writer:add_instruction_matches",
    "lib.atlas.writer:delete_diff",
    "lib.atlas.writer:delete_dimension_delta",
    "lib.atlas.writer:set_callsite_facts_state",
    "lib.atlas.writer:set_instruction_match_facts",
    "lib.facts:_DECOMPILE_MIN_SIZE",
    "lib.hunt.analyzer2:_db_has_bridge",
    "lib.pattern.classes:_STUB_NAME_RE",
    "lib.pattern.classes:stub_resolved_name",
    "version:UNKNOWN_VERSION",
)

# The code a stored candidate baseline row is computed by.
OVERLAY_CODE_ENTRIES: tuple[str, ...] = (
    "lib.query.sink_overlay",
    "lib.diff.code_version",
    "lib.diff.export_report",
    "lib.callsite_ref",
    "lib.hunt.refs",
    "lib.atlas.models:DimensionDeltaRow",
    "lib.atlas.writer:add_dimension_deltas",
    "lib.atlas.writer:delete_dimension_delta",
    "version:UNKNOWN_VERSION",
)

# What a listed entry takes from elsewhere in the package that is NOT hashed, and why. A module
# name excludes the whole module; ``module:name`` one name. Read by the lock test.
_EXCLUDED: dict[str, str] = {
    "lib.errors": "exception types: what is raised, never what is written",
    "lib.machine": "how many exports run in parallel",
    "lib.config.config": "the configuration passed in (paths, timeouts), not a computation",
    "lib.diff.toolchain": "the toolchain's versions, recorded with the diff as they are",
    "lib.analyze.ghidra_runner:find_headless": (
        "where Ghidra is installed (its version is recorded)"
    ),
    "lib.analyze.ghidra_runner:current_pass_version": (
        "the running extraction pass, compared for the preflight refusal; the binary's own pass "
        "is the extraction stamp"
    ),
    "lib.facts:analysis_run_counts": (
        "the build hash of a run's analysis.db, stamped with the call-site facts; a reader "
        "compares it with the run's own build hash, which the hunt derives with the same function"
    ),
    "lib.query.sink_overlay:persist_sink_overlay": (
        "the stored baseline, versioned by sink_overlay_logic_version"
    ),
    "lib.query.sink_overlay:read_sink_overlay_baseline": (
        "whether a stored baseline is stale, read to decide whether to store it again"
    ),
    "lib.query.runs:run_staleness": "the run currency refusal; nothing it returns is written",
    "version:installed_commit": "the installed build, compared for the run currency refusal",
}


def _strip_docstring(body: list[ast.stmt]) -> list[ast.stmt]:
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        if isinstance(body[0].value.value, str):
            return body[1:]
    return body


def _canon(node: object) -> object:
    """A position-free, docstring-free rendering of a syntax tree. A field that is None or empty is
    left out, so an optional field a newer Python adds (and leaves empty) does not change it."""
    if isinstance(node, ast.AST):
        out: list[object] = [type(node).__name__]
        for name in node._fields:
            value = getattr(node, name, None)
            if name == "body" and isinstance(
                node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef
            ):
                value = _strip_docstring(list(value or []))
            if value is None or value == []:
                continue
            out.append([name, _canon(value)])
        return out
    if isinstance(node, list):
        return [_canon(x) for x in node]
    return [type(node).__name__, repr(node)]


def _module_path(root: Path, module: str) -> Path:
    rel = Path(*module.split("."))
    path = root / rel.with_suffix(".py")
    return path if path.is_file() else root / rel / "__init__.py"


def _top_level(tree: ast.Module, name: str) -> ast.stmt | None:
    """The top-level definition of ``name``: a function, a class, or an assignment to it."""
    for stmt in tree.body:
        if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            if stmt.name == name:
                return stmt
        elif isinstance(stmt, ast.Assign):
            if any(isinstance(t, ast.Name) and t.id == name for t in stmt.targets):
                return stmt
        elif isinstance(stmt, ast.AnnAssign):
            if isinstance(stmt.target, ast.Name) and stmt.target.id == name:
                return stmt
    return None


def entry_digest(root: Path, entry: str) -> object:
    """The normalised rendering of one entry under ``root``; a missing file or name is rendered as
    missing, so it changes the hash rather than failing a reader."""
    module, _, name = entry.partition(":")
    path = _module_path(root, module)
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, ValueError):
        return ["missing", entry]
    if not name:
        return _canon(tree)
    node = _top_level(tree, name)
    return _canon(node) if node is not None else ["missing", entry]


def code_hash(root: Path, entries: Iterable[str]) -> str:
    """The hash of the normalised code of ``entries`` under the package directory ``root``."""
    parts = [[e, entry_digest(root, e)] for e in sorted(set(entries))]
    blob = json.dumps(parts, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(blob.encode("ascii")).hexdigest()[:16]


@cache
def diff_code_version() -> str:
    """The version stamped on every diff_meta row (``diff_code_version``)."""
    return f"src-{code_hash(_PACKAGE, DIFF_CODE_ENTRIES)}"


@cache
def sink_overlay_logic_version() -> str:
    """The version stamped on every stored candidate baseline row (``overlay_version``)."""
    return f"src-{code_hash(_PACKAGE, OVERLAY_CODE_ENTRIES)}"


def export_files(builder: str | None) -> tuple[str, ...]:
    """The script files an export took, by its builder; an unknown builder (a failed attempt, a
    diff recorded before the builder was) takes both, everything it could have used."""
    if builder == "extension":
        return (_EXPORT_SCRIPT,)
    return (_EXPORT_SCRIPT, _FALLBACK_BUILDER)


@cache
def export_code_hash(builder: str | None) -> str:
    """The hash of the export script files ``builder`` took (by name and bytes, never by path, so
    an editable and an installed copy agree), for the scripts this package ships."""
    return export_code_hash_in(builder, _SCRIPT_DIR)


def export_code_hash_in(builder: str | None, script_dir: Path) -> str:
    """``export_code_hash`` for the scripts in ``script_dir``."""
    h = hashlib.sha256()
    for name in export_files(builder):
        h.update(name.encode() + b"\0")
        try:
            h.update((script_dir / name).read_bytes())
        except OSError:
            h.update(b"\0missing\0")
        h.update(b"\0")
    return h.hexdigest()[:16]
