# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The code a stored diff or baseline was computed by is a hash of the code, and its entries are
locked against their criterion.

The version stamped on a diff (``diff_code_version``) and on a baseline row
(``sink_overlay_logic_version``) is computed from the code's normalised source, and the export
script by its bytes, per export path (lib/diff/code_version). Nothing is bumped by hand, so the one
way to miss a change is to leave code out of the hashed set: the lock below fails when a listed
entry takes a name from another treasure_map module that is neither listed nor excluded with a
reason — the machine reading of "its return value goes into a stored row", as test_pass_version
does for the extraction pipeline. A name used only in a type annotation is not taken.
"""

from __future__ import annotations

import ast
import shutil
from pathlib import Path

import pytest

from treasure_map.lib.diff import code_version as cv

_PACKAGE = Path(cv.__file__).resolve().parents[2]
_SCRIPTS = Path(cv.__file__).resolve().parent / "ghidra"


# ── the lock ─────────────────────────────────────────────────────────────────────────────────────


def _imports(tree: ast.Module) -> dict[str, tuple[str, str]]:
    """local name -> (module relative to the package, imported name) for treasure_map imports."""
    out: dict[str, tuple[str, str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module == "treasure_map" or node.module.startswith("treasure_map."):
                module = node.module.removeprefix("treasure_map").lstrip(".")
                for alias in node.names:
                    out[alias.asname or alias.name] = (module, alias.name)
    return out


def _used_names(node: ast.AST) -> set[str]:
    """Names loaded in ``node``, outside annotations (a type is not a value taken)."""
    used: set[str] = set()

    def visit(n: ast.AST) -> None:
        for field, value in ast.iter_fields(n):
            if field in ("annotation", "returns"):
                continue
            for v in value if isinstance(value, list) else [value]:
                if isinstance(v, ast.AST):
                    visit(v)
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
            used.add(n.id)

    visit(node)
    return used


def _is_module(name: str) -> bool:
    return cv._module_path(_PACKAGE, name).is_file()


def _covered(ref: str, entries: frozenset[str]) -> bool:
    module = ref.partition(":")[0]
    return any(r in entries or r in cv._EXCLUDED for r in (ref, module))


def _uncovered(entries: tuple[str, ...]) -> list[str]:
    """Every name a listed entry takes from another treasure_map module (or, for a single-name
    entry, from its own module) that is neither listed nor excluded."""
    listed = frozenset(entries)
    missing: list[str] = []
    for entry in entries:
        module, _, name = entry.partition(":")
        tree = ast.parse(cv._module_path(_PACKAGE, module).read_text(encoding="utf-8"))
        node = cv._top_level(tree, name) if name else tree
        assert node is not None, f"{entry} does not exist"
        imports = _imports(tree)
        used = _used_names(node)
        for local in sorted(used & imports.keys()):
            mod, imported = imports[local]
            # ``from treasure_map.lib.diff import toolchain`` takes the module itself
            ref = f"{mod}.{imported}" if _is_module(f"{mod}.{imported}") else f"{mod}:{imported}"
            if not _covered(ref, listed):
                missing.append(f"{entry} -> {ref}")
        if name:
            own = {
                n
                for s in tree.body
                for n in (
                    [s.name]
                    if isinstance(s, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
                    else [t.id for t in getattr(s, "targets", []) if isinstance(t, ast.Name)]
                )
            }
            for other in sorted((used & own) - {name}):
                if not _covered(f"{module}:{other}", listed):
                    missing.append(f"{entry} -> {module}:{other} (same module)")
    return missing


@pytest.mark.parametrize(
    "entries", [cv.DIFF_CODE_ENTRIES, cv.OVERLAY_CODE_ENTRIES], ids=["diff", "overlay"]
)
def test_every_name_the_hashed_code_takes_is_hashed_or_excluded_with_a_reason(
    entries: tuple[str, ...],
) -> None:
    """★ THE LOCK. Call a new helper from a diff module without listing it, and this fails.

    MUTATION (verified RED): call a helper from an unlisted module in layer0 -> it is reported
    here; drop ``lib.hunt.refs`` from the diff entries -> the same."""
    assert _uncovered(entries) == []


def test_the_writers_of_the_rows_are_hashed() -> None:
    """The modules that write diff rows and baseline rows are the roots of the two sets."""
    for root in (
        "lib.diff.driver",
        "lib.diff.layer0",
        "lib.diff.layer2",
        "lib.diff.callsite_facts",
    ):
        assert root in cv.DIFF_CODE_ENTRIES
    assert "lib.query.sink_overlay" in cv.OVERLAY_CODE_ENTRIES


def test_every_exclusion_names_something_that_exists() -> None:
    """An exclusion of a name that is gone would hide nothing — and let the next one through."""
    for ref in cv._EXCLUDED:
        module, _, name = ref.partition(":")
        path = cv._module_path(_PACKAGE, module)
        assert path.is_file(), ref
        if name:
            assert cv._top_level(ast.parse(path.read_text(encoding="utf-8")), name), ref


def test_every_entry_resolves() -> None:
    for entry in cv.DIFF_CODE_ENTRIES + cv.OVERLAY_CODE_ENTRIES:
        assert cv.entry_digest(_PACKAGE, entry)[0] != "missing", entry


# ── what moves the hash ───────────────────────────────────────────────────────────────────────


def _copy_entries(root: Path, entries: tuple[str, ...]) -> None:
    for entry in entries:
        module = entry.partition(":")[0]
        src = cv._module_path(_PACKAGE, module)
        dst = root / src.relative_to(_PACKAGE)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)


def test_comments_and_docstrings_do_not_move_the_hash_and_code_does(tmp_path: Path) -> None:
    """MUTATION (verified RED): hash the raw source -> the comment edit moves it; leave a listed
    module out -> the constant edit does not."""
    _copy_entries(tmp_path, cv.DIFF_CODE_ENTRIES)
    before = cv.code_hash(tmp_path, cv.DIFF_CODE_ENTRIES)
    assert before == cv.code_hash(_PACKAGE, cv.DIFF_CODE_ENTRIES)
    layer0 = tmp_path / "lib" / "diff" / "layer0.py"
    text = layer0.read_text(encoding="utf-8")
    edited = text.replace('"""Layer-0 parse:', '"""Layer-0 parse (reworded):', 1).replace(
        "ALIGN_THRESHOLD = 0.9", "# a comment\nALIGN_THRESHOLD = 0.9  # and another", 1
    )
    assert edited != text
    layer0.write_text(edited, encoding="utf-8")
    assert cv.code_hash(tmp_path, cv.DIFF_CODE_ENTRIES) == before
    layer0.write_text(edited.replace("ALIGN_THRESHOLD = 0.9", "ALIGN_THRESHOLD = 0.8"), "utf-8")
    assert cv.code_hash(tmp_path, cv.DIFF_CODE_ENTRIES) != before


def test_a_single_name_entry_hashes_that_name_only(tmp_path: Path) -> None:
    """From a large shared module only the listed definition counts: the rest of it may change
    without re-diffing every stored diff."""
    _copy_entries(tmp_path, cv.DIFF_CODE_ENTRIES)
    before = cv.code_hash(tmp_path, cv.DIFF_CODE_ENTRIES)
    writer = tmp_path / "lib" / "atlas" / "writer.py"
    writer.write_text(writer.read_text(encoding="utf-8") + "\n\ndef unrelated():\n    return 1\n")
    assert cv.code_hash(tmp_path, cv.DIFF_CODE_ENTRIES) == before
    text = writer.read_text(encoding="utf-8")
    writer.write_text(text.replace("INSERT INTO diff_meta", "INSERT OR REPLACE INTO diff_meta"))
    assert cv.code_hash(tmp_path, cv.DIFF_CODE_ENTRIES) != before


_FIXED_SOURCE = '''"""Module docstring."""
from __future__ import annotations

import re

LIMIT: int = 3
_RE = re.compile(r"x+")


class Box:
    """Class docstring."""

    size: int = 0

    def grow(self, by: int = 1) -> Box:
        """Method docstring."""
        return Box() if by < 0 else self


def name(value: str | None, *items: int, **kw: str) -> str:
    match value:
        case None:
            return f"none {LIMIT!r:>4}"
        case _:
            return f"{value}-{len(items)}" + "".join(kw)
'''


def test_the_hash_is_the_same_under_every_supported_python(tmp_path: Path) -> None:
    """A fixed source, pinned: CI runs this under each Python version tmap supports, so a version
    whose syntax tree renders differently (3.12 added ``type_params`` to every function and class)
    fails here instead of making every stored diff read as stale on the other interpreter.

    MUTATION (verified RED): render every field, empty ones included -> 3.11 and 3.12 disagree
    (verified by running the dump under both)."""
    (tmp_path / "fixed.py").write_text(_FIXED_SOURCE, encoding="utf-8")
    assert cv.code_hash(tmp_path, ("fixed",)) == _PINNED_FIXED


_PINNED_FIXED = "a98234152679dbf1"


# ── the export script, by the path an export took ───────────────────────────────────────────────


def _scripts(tmp_path: Path) -> Path:
    d = tmp_path / "ghidra"
    d.mkdir()
    for name in ("ExportBinExport.java", "FallbackBinExport2Builder.java"):
        shutil.copyfile(_SCRIPTS / name, d / name)
    return d


def test_a_change_to_the_fallback_builder_moves_only_the_fallback_exports(tmp_path: Path) -> None:
    """MUTATION (verified RED): hash both files whatever the path -> the extension export moves
    too."""
    d = _scripts(tmp_path)
    ext, fb, unknown = (cv.export_code_hash_in(b, d) for b in ("extension", "fallback", None))
    assert cv.export_code_hash_in("extension", _SCRIPTS) == cv.export_code_hash("extension")
    f = d / "FallbackBinExport2Builder.java"
    f.write_bytes(f.read_bytes() + b" ")
    assert cv.export_code_hash_in("extension", d) == ext
    assert cv.export_code_hash_in("fallback", d) != fb
    assert cv.export_code_hash_in(None, d) != unknown


def test_a_change_to_the_export_script_moves_every_export(tmp_path: Path) -> None:
    """MUTATION (verified RED): leave the export script out of the extension path's files -> the
    extension export does not move."""
    d = _scripts(tmp_path)
    before = {b: cv.export_code_hash_in(b, d) for b in ("extension", "fallback", None)}
    f = d / "ExportBinExport.java"
    f.write_bytes(f.read_bytes() + b" ")
    assert all(cv.export_code_hash_in(b, d) != h for b, h in before.items())


def test_the_entry_words_reader_is_no_diff_or_overlay_entry() -> None:
    """The entry-words reader (and patch_view / mcp_app, which compose it) is read on demand at
    view time and stored nowhere, so it is no entry of the diff or overlay stamp."""
    for entry in cv.DIFF_CODE_ENTRIES + cv.OVERLAY_CODE_ENTRIES:
        module = entry.partition(":")[0]
        assert module not in ("lib.query.entry_words", "lib.query.patch_view", "mcp_app"), entry
    assert "lib.facts:_DECOMPILE_MIN_SIZE" in cv.DIFF_CODE_ENTRIES
    assert "lib.facts:_RX_BYTES_WARNING" not in cv.DIFF_CODE_ENTRIES


def test_the_empty_text_reading_moves_the_diff_stamp_only_through_the_size_floor(
    tmp_path: Path,
) -> None:
    """get_pseudocode's empty-text status, its listing read and the read face's micro pair state
    (sameness / patch_view / diff_align) are read at view time and stored nowhere: none is a diff
    or overlay entry, and of lib/facts only the size floor's own assignment is hashed — changing
    get_pseudocode's code leaves the diff stamp where it was, changing the floor's value moves
    it."""
    for entry in cv.DIFF_CODE_ENTRIES + cv.OVERLAY_CODE_ENTRIES:
        module = entry.partition(":")[0]
        assert module not in ("lib.query.sameness", "lib.query.diff_align"), entry
        assert not entry.startswith("lib.facts:") or entry == "lib.facts:_DECOMPILE_MIN_SIZE"
    _copy_entries(tmp_path, cv.DIFF_CODE_ENTRIES)
    before = cv.code_hash(tmp_path, cv.DIFF_CODE_ENTRIES)
    facts_py = tmp_path / "lib" / "facts.py"
    text = facts_py.read_text(encoding="utf-8")
    body = "if status == PSEUDOCODE_SKIPPED_MICRO:\n        listing = _listing_for(conn, row)"
    assert body in text
    facts_py.write_text(text.replace(body, body + "\n        listing = dict(listing)", 1))
    assert cv.code_hash(tmp_path, cv.DIFF_CODE_ENTRIES) == before
    assert "_DECOMPILE_MIN_SIZE = 10\n" in text
    facts_py.write_text(text.replace("_DECOMPILE_MIN_SIZE = 10\n", "_DECOMPILE_MIN_SIZE = 12\n"))
    assert cv.code_hash(tmp_path, cv.DIFF_CODE_ENTRIES) != before
