# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Which code a scan or a hunt was produced by, hashed from the code itself.

A run is a scan (the analysis.db the pipeline builds) followed by a hunt (the candidates the
analyzer grades from it). Whether a stored run is still current — whether re-running would change
anything — used to be decided by comparing a recorded git commit against the running one, which
re-did every run on any commit, even one that touched neither the scan nor the hunt. This module
decides it by hashing the CODE that actually feeds each side, so a commit that changes nothing a
re-run would read leaves every run current.

Two stamps, each a ``src-<16hex>`` content hash:

  * ``hunt_code_version()`` — the Python whose output the hunt writes, the import closure of
    ``lib.hunt.analyzer2``.
  * ``pipeline_code_version()`` — the Python whose output the scan writes, the closure of
    ``lib.analyze.pipeline``. It rides inside the fuller SCAN STAMP (``scan_stamp_for``), which also
    carries the pyelftools version the extraction parses ELF with and the content-marked config
    leaves, because those change what a re-scan would store without any code edit.

HOW A CLOSURE IS HASHED. Starting from a root module, every ``from treasure_map.…`` import is
followed (including inside functions and ``TYPE_CHECKING`` blocks) to the set of package modules the
root can reach; ``CLOSURE_EXCLUDED`` members are not entered. Each module is normalised the way
``lib.diff.code_version`` normalises a diff entry — parsed, docstrings dropped, dumped without
positions or empty fields — so comments, docstrings and formatting do not count and the value is the
same across the Python versions tmap supports. Two large shared modules in ``NAME_GRANULAR`` are
hashed by only the part the closure actually uses, so an edit to a function no one on this side
calls does not churn the stamp. A handful of modules read a package DATA file at run time
(``ASSET_READERS``); those files are hashed too (``.sql`` normalised, everything else by bytes).

BOUNDARY: third-party libraries and the interpreter are not in the code hash (the closures use only
the standard library and sqlite). pyelftools is the one dependency that changes extraction output,
so it rides in the scan stamp by version; the Ghidra/toolchain versions are recorded with the run
separately, and the per-binary extraction pass is its own ``build_hash`` axis.

This module is excluded from the two hashes it computes (``CLOSURE_EXCLUDED`` here, and
``lib.rescan_version`` in ``lib.diff.code_version._EXCLUDED``): nothing it returns is written into a
content row, so an edit to it must not read every run as stale.
"""

from __future__ import annotations

import ast
import hashlib
import importlib.metadata
import json
import sqlite3
from dataclasses import dataclass
from functools import cache
from pathlib import Path

from pydantic import BaseModel

# Reused verbatim from the diff code-version so both stamps normalise source the same way; that
# module is NOT modified from here (it is itself a hashed diff entry).
from treasure_map.lib.diff.code_version import _canon, _module_path
from treasure_map.version import UNKNOWN_VERSION

# The treasure_map package directory (this file is <pkg>/lib/rescan_version.py).
_PACKAGE = Path(__file__).resolve().parents[1]

PIPELINE_ROOT = "lib.analyze.pipeline"
HUNT_ROOT = "lib.hunt.analyzer2"

# Modules never entered when walking a closure, with the reason. This module computes the stamp, so
# hashing it would make an edit to it read every run as stale.
CLOSURE_EXCLUDED: dict[str, str] = {
    "lib.rescan_version": (
        "computes the stamp itself; nothing it returns is written into a content row"
    )
}

# Large shared modules hashed by only the names the closure uses, not whole. Each is reached by a
# small, stable surface (``facts.open_analysis_ro`` from the hunt, the ``Config`` model from the
# pipeline); hashing the whole file would re-stamp a run whenever an unrelated accessor in it moved.
NAME_GRANULAR: tuple[str, ...] = ("lib.facts", "lib.config.config")

# Closure modules that read a package DATA file at run time, and the files (relative to the package
# dir; a glob is expanded). A module's assets count toward a root's hash when the module is in that
# root's closure. ``.sql`` is normalised before hashing (comments and whitespace do not count);
# every other file is hashed by its bytes.
ASSET_READERS: dict[str, tuple[str, ...]] = {
    "lib.storage.connection": ("lib/storage/schema.sql",),
    "lib.atlas.connection": ("lib/storage/atlas_schema.sql",),
    "lib.pattern.extractor_names": ("lib/analyze/ghidra/extractor_names.tsv",),
    "lib.analyze.ghidra_runner": ("lib/analyze/ghidra/*.java", "lib/analyze/ghidra/*.tsv"),
}


# ── import closure ───────────────────────────────────────────────────────────────────


def _is_module(package_dir: Path, module: str) -> bool:
    return _module_path(package_dir, module).is_file()


def _edges(package_dir: Path, module: str) -> set[str]:
    """The internal-module edges out of ``module``: every ``from treasure_map.…`` import, resolved
    to a module name relative to the package. ``from treasure_map.P import N`` points at ``P.N``
    when that is a module, otherwise at ``P`` (so a package ``__init__`` is entered only when a
    non-submodule name is taken from it). ``import treasure_map.…`` and relative imports are NOT
    followed here — the static guard forbids both in a closure, so none exist to resolve."""
    try:
        tree = ast.parse(_module_path(package_dir, module).read_text(encoding="utf-8"))
    except (OSError, SyntaxError, ValueError):
        return set()
    edges: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 0:
            mod = node.module or ""
            if mod == "treasure_map":
                for alias in node.names:
                    if _is_module(package_dir, alias.name):
                        edges.add(alias.name)
            elif mod.startswith("treasure_map."):
                parent = mod[len("treasure_map.") :]
                for alias in node.names:
                    cand = f"{parent}.{alias.name}"
                    edges.add(cand if _is_module(package_dir, cand) else parent)
    return edges


def _closure(package_dir: Path, root: str) -> set[str]:
    """Every package module reachable from ``root`` by ``from treasure_map`` imports, minus the
    ``CLOSURE_EXCLUDED`` members."""
    seen: set[str] = set()
    stack = [root]
    while stack:
        module = stack.pop()
        if module in seen or module in CLOSURE_EXCLUDED or not _is_module(package_dir, module):
            continue
        seen.add(module)
        stack.extend(_edges(package_dir, module))
    return seen


# ── per-module digest ──────────────────────────────────────────────────────────────


def _defined_names(stmt: ast.stmt) -> set[str]:
    """The top-level names a statement binds: a def/class name, or the plain targets of an
    assignment. Not tuple/attribute targets — only names a sibling statement could reference."""
    if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
        return {stmt.name}
    if isinstance(stmt, ast.Assign):
        return {t.id for t in stmt.targets if isinstance(t, ast.Name)}
    if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
        return {stmt.target.id}
    return set()


def _is_docstring(stmt: ast.stmt) -> bool:
    return (
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Constant)
        and isinstance(stmt.value.value, str)
    )


def _top_import_bindings(tree: ast.Module) -> dict[str, list[object]]:
    """``{local name -> [source module, original name, level]}`` for the module's TOP-LEVEL imports.

    Lets a name-granular digest notice a re-bind: pointing a used local at a different function
    changes its tuple and so the hash, while adding an import no selected statement references does
    not (that local is dropped before the tuple is formed)."""
    out: dict[str, list[object]] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.ImportFrom):
            for alias in stmt.names:
                out[alias.asname or alias.name] = [stmt.module or "", alias.name, stmt.level]
        elif isinstance(stmt, ast.Import):
            for alias in stmt.names:
                out[alias.asname or alias.name.split(".")[0]] = [alias.name, alias.name, 0]
    return out


def _transitive(required: set[str], top_defs: dict[str, list[ast.stmt]]) -> set[str]:
    """``required`` plus every top-level definition it reaches: a name used inside a required
    definition that is itself defined at this module's top level, to fixpoint. So a used function
    pulls in the private helpers and constants it is built from."""
    result = set(required)
    queue = [name for name in required if name in top_defs]
    while queue:
        for stmt in top_defs.get(queue.pop(), []):
            for node in ast.walk(stmt):
                if isinstance(node, ast.Name) and node.id in top_defs and node.id not in result:
                    result.add(node.id)
                    queue.append(node.id)
    return result


def _used_names(package_dir: Path, module: str, closure: set[str]) -> tuple[set[str], bool]:
    """Which top-level names of ``module`` the rest of ``closure`` uses, and whether the whole
    module must be hashed after all.

    A name is used when another closure module imports it directly (``from treasure_map.<module>
    import n``) or reaches it as an attribute of the module bound as a local
    (``from treasure_map.<parent> import <leaf>`` then ``leaf.n``). If that local ever appears
    as a bare value — passed on, handed to ``getattr`` — the attribute set is not the trusted
    whole surface, so the function returns ``whole=True`` and the caller hashes the whole module."""
    parent, _, leaf = module.rpartition(".")
    tm_parent = f"treasure_map.{parent}" if parent else "treasure_map"
    tm_module = f"treasure_map.{module}"
    required: set[str] = set()
    attrs: set[str] = set()
    for other in closure:
        if other == module:
            continue
        try:
            otree = ast.parse(_module_path(package_dir, other).read_text(encoding="utf-8"))
        except (OSError, SyntaxError, ValueError):
            continue
        aliases: set[str] = set()
        for node in ast.walk(otree):
            if isinstance(node, ast.ImportFrom) and node.level == 0:
                if (node.module or "") == tm_parent:
                    for alias in node.names:
                        if alias.name == leaf:
                            aliases.add(alias.asname or alias.name)
                elif (node.module or "") == tm_module:
                    for alias in node.names:
                        required.add(alias.name)
        if not aliases:
            continue
        attr_value_ids = {
            id(n.value)
            for n in ast.walk(otree)
            if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)
        }
        for node in ast.walk(otree):
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id in aliases
            ):
                attrs.add(node.attr)
            elif (
                isinstance(node, ast.Name)
                and node.id in aliases
                and isinstance(node.ctx, ast.Load)
                and id(node) not in attr_value_ids
            ):
                return set(), True
    return required | attrs, False


def _name_granular_digest(
    package_dir: Path, module: str, tree: ast.Module, closure: set[str]
) -> object:
    """The digest of only the part of ``module`` the closure uses: the used names (with the private
    definitions they reach), the normalised source of the statements that define them plus every
    top-level statement that is neither a definition, an import nor the docstring, and the import
    bindings those selected statements reference. Falls back to the whole module if the used surface
    cannot be trusted (see ``_used_names``)."""
    required, whole = _used_names(package_dir, module, closure)
    if whole:
        return _canon(tree)

    top_defs: dict[str, list[ast.stmt]] = {}
    for stmt in tree.body:
        for name in _defined_names(stmt):
            top_defs.setdefault(name, []).append(stmt)
    required = _transitive(required, top_defs)

    selected: list[ast.stmt] = []
    for i, stmt in enumerate(tree.body):
        if i == 0 and _is_docstring(stmt):
            continue
        if isinstance(stmt, ast.Import | ast.ImportFrom):
            continue
        defined = _defined_names(stmt)
        if not defined or (defined & required):
            selected.append(stmt)

    referenced = set(required)
    for stmt in selected:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Name):
                referenced.add(node.id)
    bindings = _top_import_bindings(tree)
    used_bindings = sorted(
        [local, *binding] for local, binding in bindings.items() if local in referenced
    )
    return [sorted(required), _canon(selected), used_bindings]


def _module_digest(package_dir: Path, module: str, closure: set[str]) -> object:
    """The normalised rendering of ``module``: whole, or name-granular for a ``NAME_GRANULAR``
    member. A missing file or a syntax error renders as ``["missing", module]`` so it changes the
    hash rather than raising."""
    try:
        tree = ast.parse(_module_path(package_dir, module).read_text(encoding="utf-8"))
    except (OSError, SyntaxError, ValueError):
        return ["missing", module]
    if module in NAME_GRANULAR:
        return _name_granular_digest(package_dir, module, tree, closure)
    return _canon(tree)


# ── assets ─────────────────────────────────────────────────────────────────────────


def _normalize_sql(text: str) -> str:
    """``text`` with ``--`` line comments outside single-quoted strings removed and all whitespace
    collapsed to single spaces, so a reformatted or re-commented schema hashes the same. Block
    comments are not handled; the static guard forbids ``/*`` in a hashed ``.sql``."""
    out: list[str] = []
    i, n, in_str = 0, len(text), False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "'":
                in_str = False
            i += 1
        elif ch == "'":
            in_str = True
            out.append(ch)
            i += 1
        elif ch == "-" and i + 1 < n and text[i + 1] == "-":
            while i < n and text[i] != "\n":
                i += 1
        else:
            out.append(ch)
            i += 1
    return " ".join("".join(out).split())


def _asset_digest(path: Path) -> str:
    try:
        data = path.read_bytes()
    except OSError:
        return "missing"
    if path.suffix == ".sql":
        return hashlib.sha256(
            _normalize_sql(data.decode("utf-8", "replace")).encode("utf-8")
        ).hexdigest()
    return hashlib.sha256(data).hexdigest()


def _asset_parts(package_dir: Path, closure: set[str]) -> list[list[str]]:
    """``["asset", relpath, digest]`` for every file an ``ASSET_READERS`` module in ``closure``
    reads, de-duplicated and sorted (a file two readers both reach is counted once)."""
    seen: set[tuple[str, str]] = set()
    for module in closure:
        for pattern in ASSET_READERS.get(module, ()):
            for path in sorted(package_dir.glob(pattern)):
                rel = path.relative_to(package_dir).as_posix()
                seen.add((rel, _asset_digest(path)))
    return [["asset", rel, digest] for rel, digest in sorted(seen)]


# ── the stamps ───────────────────────────────────────────────────────────────────────


def code_version_of(package_dir: Path, root: str) -> str:
    """``src-<16hex>`` over the normalised code of ``root``'s import closure and the data files it
    reads, under ``package_dir``. A pure function (no cache): it reads the tree it is given, so the
    mutation tests can point it at a copy. A missing file or syntax error counts as missing rather
    than raising, so a stamp is always produced."""
    package_dir = Path(package_dir)
    closure = _closure(package_dir, root)
    parts: list[object] = [
        ["mod", module, _module_digest(package_dir, module, closure)] for module in sorted(closure)
    ]
    parts += _asset_parts(package_dir, closure)
    blob = json.dumps(parts, separators=(",", ":"), ensure_ascii=True)
    return "src-" + hashlib.sha256(blob.encode("ascii")).hexdigest()[:16]


@cache
def pipeline_code_version() -> str:
    """The scan's code hash for the installed package. Cached: the source cannot change under a
    running process in any way this value should follow mid-session."""
    return code_version_of(_PACKAGE, PIPELINE_ROOT)


@cache
def hunt_code_version() -> str:
    """The hunt's code hash for the installed package. Cached, as ``pipeline_code_version``."""
    return code_version_of(_PACKAGE, HUNT_ROOT)


def _read_pyelftools() -> str:
    try:
        return importlib.metadata.version("pyelftools")
    except Exception:
        return UNKNOWN_VERSION


@cache
def pyelftools_version() -> str:
    """The installed pyelftools version, or the unknown sentinel when it cannot be read. Cached."""
    return _read_pyelftools()


def _leaf_fields(model_cls: type[BaseModel], prefix: str = "") -> dict[str, object]:
    """``{dotted path -> FieldInfo}`` for every LEAF field of a Config model, descending into nested
    models. A leaf is a field whose type is not itself a model."""
    out: dict[str, object] = {}
    for name, field in model_cls.model_fields.items():
        ann = field.annotation
        path = f"{prefix}{name}"
        if isinstance(ann, type) and issubclass(ann, BaseModel):
            out.update(_leaf_fields(ann, path + "."))
        else:
            out[path] = field
    return out


def _jsonable(value: object) -> object:
    if value is None or isinstance(value, bool | int | float | str):
        return value
    return str(value)


def content_config(cfg: BaseModel) -> dict[str, object]:
    """The content-marked config leaves of ``cfg``, keyed by dotted path.

    A leaf opts in with ``Field(..., json_schema_extra={"tmap_content": True})``; its value changes
    what a re-scan would store (the xref fold threshold decides which high-fan-out symbols get
    folded), so it belongs in the scan stamp. Everything else — paths, timeouts, where Ghidra lives
    — does not touch the facts and is left out."""
    out: dict[str, object] = {}
    for path, field in _leaf_fields(type(cfg)).items():
        extra = getattr(field, "json_schema_extra", None)
        if isinstance(extra, dict) and extra.get("tmap_content") is True:
            value: object = cfg
            for part in path.split("."):
                value = getattr(value, part)
            out[path] = _jsonable(value)
    return out


def _scan_stamp_json(code: str, pyelftools: str, cfg: BaseModel) -> str:
    return json.dumps(
        {"code": code, "deps": {"pyelftools": pyelftools}, "config": content_config(cfg)},
        sort_keys=True,
        separators=(",", ":"),
    )


def scan_stamp_for(cfg: BaseModel) -> str:
    """The canonical-JSON scan stamp for ``cfg``: the pipeline code hash, the pyelftools version,
    and the content-marked config leaves. This is what a scan writes into its analysis.db and what a
    hunt copies onto the run row."""
    return _scan_stamp_json(pipeline_code_version(), pyelftools_version(), cfg)


@dataclass(frozen=True)
class CodeStamp:
    """The pair a reader compares a stored run against: the running hunt code hash and the running
    scan stamp."""

    hunt: str
    scan: str


def current_code_stamp(cfg: BaseModel) -> CodeStamp:
    """The stamp of the code THIS process runs, from the cached hashes. Grab it once at the start of
    a piece of work and compare every run against that one value."""
    return CodeStamp(hunt=hunt_code_version(), scan=scan_stamp_for(cfg))


def on_disk_code_stamp(cfg: BaseModel) -> CodeStamp:
    """The stamp of the code on disk RIGHT NOW, computed without any cache. Only for the MCP hint
    that warns when the server started before the code it is serving from was edited — a long-lived
    process holds the cached ``current_code_stamp`` from its startup, and this says whether a rescan
    run from the command line (which uses the on-disk code) could ever match it."""
    return CodeStamp(
        hunt=code_version_of(_PACKAGE, HUNT_ROOT),
        scan=_scan_stamp_json(code_version_of(_PACKAGE, PIPELINE_ROOT), _read_pyelftools(), cfg),
    )


def read_scan_stamp(conn: sqlite3.Connection) -> str | None:
    """The scan stamp stored in an analysis.db, or None when there is none — a database scanned
    before the stamp existed (no table), or by a scan that did not finish (no row)."""
    try:
        row = conn.execute("SELECT stamp FROM scan_stamp WHERE id = 1").fetchone()
    except sqlite3.OperationalError:
        return None
    return None if row is None else row[0]


@dataclass(frozen=True)
class StampCompare:
    """The leaf-by-leaf result of comparing two scan stamps. ``differing`` names the leaves that are
    both present, both known and unequal (a proven change); ``unknown`` names the leaves that could
    not be compared (one side missing, or either side an unknown sentinel). The refuse gate fires
    only on ``differing``; the conservative gates treat ``unknown`` as reason to re-scan too."""

    differing: tuple[str, ...]
    unknown: tuple[str, ...]


def _flatten(data: dict[str, object], prefix: str = "") -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in data.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            out.update(_flatten(value, path + "."))
        else:
            out[path] = value
    return out


def compare_scan_stamps(stored: str | None, current: str) -> StampCompare:
    """Compare a stored scan stamp against the current one, leaf by leaf. An unreadable or absent
    stored stamp is a single ``unknown`` of ``"scan stamp"`` — nothing to compare, not a change."""
    cur = _flatten(json.loads(current))
    if stored is None:
        return StampCompare((), ("scan stamp",))
    try:
        parsed = json.loads(stored)
    except (TypeError, ValueError):
        return StampCompare((), ("scan stamp",))
    if not isinstance(parsed, dict):
        # Valid JSON but not an object (``null``, a list, a scalar): nothing to compare leaf by
        # leaf, so it reads as unknown, never a crash — the stored value was corrupted out of band.
        return StampCompare((), ("scan stamp",))
    st = _flatten(parsed)
    differing: list[str] = []
    unknown: list[str] = []
    for key in sorted(set(st) | set(cur)):
        if key not in st or key not in cur:
            unknown.append(key)
        elif st[key] == UNKNOWN_VERSION or cur[key] == UNKNOWN_VERSION:
            unknown.append(key)
        elif st[key] != cur[key]:
            differing.append(f"{key} {st[key]} → {cur[key]}")
    return StampCompare(tuple(differing), tuple(unknown))
