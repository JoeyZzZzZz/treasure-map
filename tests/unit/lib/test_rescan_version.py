# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Static guards on the rescan code-version stamps, and the mutation table that proves the hashing
reacts to code and not to comments.

The stamps are only trustworthy if the import closure is complete (nothing reaches the hashed code
by a route the walker cannot follow), if the name-granular modules really are used by attribute
only (so the narrowed digest is the whole surface), if every data file the code reads is hashed,
and if the Config leaves are classified exhaustively into content / non-content. Each of those is
locked here against the real tree, so a future edit that breaks an assumption fails a test instead
of silently stamping the wrong thing.
"""

from __future__ import annotations

import ast
import shutil
from pathlib import Path

import pytest

from treasure_map.lib import rescan_version as rv
from treasure_map.lib.config.config import Config

PKG = rv._PACKAGE
ROOTS = (rv.PIPELINE_ROOT, rv.HUNT_ROOT)


def _tree(module: str) -> ast.Module:
    return ast.parse(rv._module_path(PKG, module).read_text(encoding="utf-8"))


def _all_closure_modules() -> set[str]:
    out: set[str] = set()
    for root in ROOTS:
        out |= rv._closure(PKG, root)
    return out


# ── 1. only import forms the closure walker can follow ──────────────────────────────


def test_the_closure_uses_no_import_form_the_walker_cannot_follow() -> None:
    """Relative imports, ``import treasure_map…`` and dynamic imports all reach code by a route
    ``_edges`` does not follow, so a module pulled in only that way would be left out of the hash.
    The one allowed exception is ``version`` importing the generated ``_build_info`` (git-ignored,
    never part of the hash); it is whitelisted explicitly.

    MUTATION: add ``from . import x`` or ``import treasure_map.lib.x`` or
    ``importlib.import_module("treasure_map.lib.x")`` to any closure module -> RED.
    """
    offenders: list[str] = []
    for module in _all_closure_modules():
        tree = _tree(module)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level:
                offenders.append(f"{module}: relative import (level {node.level})")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "treasure_map" or alias.name.startswith("treasure_map."):
                        offenders.append(f"{module}: import {alias.name}")
            elif isinstance(node, ast.Call):
                fn = node.func
                name = (
                    fn.attr
                    if isinstance(fn, ast.Attribute)
                    else fn.id
                    if isinstance(fn, ast.Name)
                    else None
                )
                if name in ("import_module", "__import__"):
                    arg = node.args[0] if node.args else None
                    literal = arg.value if isinstance(arg, ast.Constant) else None
                    allowed = module == "version" and literal == "treasure_map._build_info"
                    if not allowed:
                        offenders.append(f"{module}: dynamic import {literal!r}")
    assert offenders == [], offenders


# ── 2. the name-granular modules are used by attribute only (the narrowed digest is live) ──


@pytest.mark.parametrize("module", rv.NAME_GRANULAR)
def test_a_name_granular_module_is_used_by_attribute_only(module: str) -> None:
    """If a closure used a name-granular module as a bare value (passed it on, ``getattr`` on it),
    the attribute set could not be trusted as the whole surface and the digest would silently fall
    back to the whole module. This asserts that never happens today, so the narrowing is real.

    MUTATION: in any closure module, bind ``facts``/``config`` and then read it bare -> RED
    (``_used_names`` reports ``whole=True``)."""
    seen_in_a_closure = False
    for root in ROOTS:
        closure = rv._closure(PKG, root)
        if module not in closure:
            continue
        seen_in_a_closure = True
        _names, whole = rv._used_names(PKG, module, closure)
        assert whole is False, f"{module} falls back to whole-module hashing in {root}'s closure"
    assert seen_in_a_closure, f"{module} is in no closure — the parametrize is stale"
    # and no star-import, which would make the used-name analysis unsound
    for node in ast.walk(_tree(module)):
        assert not (isinstance(node, ast.ImportFrom) and any(a.name == "*" for a in node.names))


def test_used_names_falls_back_to_the_whole_module_when_a_name_is_a_bare_value(
    tmp_path: Path,
) -> None:
    """The counterpart of the test above, on a synthetic package: narrowing a module to the names
    reached by attribute is sound ONLY while the module local is never handed on as a value. The
    moment it is (passed on, ``getattr``'d), the attribute set is not the whole surface, so
    ``_used_names`` must report ``whole=True`` and the caller hashes the whole module — otherwise a
    change to a never-attribute-accessed function slips past the stamp.

    MUTATION: drop the bare-value fallback (``return set(), True``) -> the bare case reads
    ``whole=False`` and this goes RED.
    """
    root = tmp_path / "treasure_map"
    (root / "lib").mkdir(parents=True)
    (root / "lib" / "target.py").write_text(
        "def a():\n    return 1\n\n\ndef b():\n    return 2\n", encoding="utf-8"
    )
    (root / "lib" / "user_attr.py").write_text(
        "from treasure_map.lib import target\n\n\ndef use():\n    return target.a()\n",
        encoding="utf-8",
    )
    (root / "lib" / "user_bare.py").write_text(
        "from treasure_map.lib import target\n\n\ndef use():\n    return getattr(target, 'a')\n",
        encoding="utf-8",
    )
    attr_names, attr_whole = rv._used_names(root, "lib.target", {"lib.target", "lib.user_attr"})
    assert attr_whole is False and attr_names == {"a"}, "attribute access narrows to the names used"
    _names, bare_whole = rv._used_names(root, "lib.target", {"lib.target", "lib.user_bare"})
    assert bare_whole is True, "an alias used as a bare value forces whole-module hashing"


# ── 3. every data file the code reads is hashed, and the .sql has no block comments ──


def test_every_package_file_reader_is_a_declared_asset_reader() -> None:
    """A module that reads a file beside it at run time (``__file__`` / importlib.resources /
    pkgutil) feeds the extraction from a file the code hash does not see — unless the file is hashed
    too. Every such closure module must be an ``ASSET_READERS`` key.

    MUTATION: make a closure module read ``Path(__file__).parent / "x"`` without listing it in
    ASSET_READERS -> RED."""
    for module in _all_closure_modules():
        text = rv._module_path(PKG, module).read_text(encoding="utf-8")
        reads_file = "__file__" in text or "importlib.resources" in text or "pkgutil" in text
        if reads_file:
            assert module in rv.ASSET_READERS, f"{module} reads a package file, not an asset reader"


def test_sql_assets_have_no_block_comments() -> None:
    """``_normalize_sql`` strips only ``--`` line comments; a ``/* */`` block would survive
    normalisation and let a comment move the hash. None exist today, and this keeps it so."""
    for patterns in rv.ASSET_READERS.values():
        for pattern in patterns:
            for path in PKG.glob(pattern):
                if path.suffix == ".sql":
                    assert "/*" not in path.read_text(encoding="utf-8"), path


# ── 4. an ancestor package __init__ not in the closure carries no hidden code ──


def test_ancestor_package_inits_outside_the_closure_hold_no_code() -> None:
    """A closure module's parent package ``__init__.py`` runs on import. If it is not itself in the
    closure (nothing imports a name FROM it), its body is never hashed — so it must hold nothing but
    imports, ``__all__`` and a docstring, or a side effect there would escape the stamp."""
    closure = _all_closure_modules()
    checked: set[str] = set()
    for module in closure:
        parts = module.split(".")
        for i in range(1, len(parts)):
            pkg = ".".join(parts[:i])
            if pkg in closure or pkg in checked:
                continue
            checked.add(pkg)
            path = PKG / Path(*pkg.split(".")) / "__init__.py"
            if not path.is_file():
                continue
            for stmt in ast.parse(path.read_text(encoding="utf-8")).body:
                ok = (
                    isinstance(stmt, ast.Import | ast.ImportFrom)
                    or (isinstance(stmt, ast.Assign) and _is_dunder_all(stmt))
                    or _is_docstring(stmt)
                )
                assert ok, f"{pkg}/__init__.py has un-hashed code: {ast.dump(stmt)[:80]}"


def _is_dunder_all(stmt: ast.Assign) -> bool:
    return any(isinstance(t, ast.Name) and t.id == "__all__" for t in stmt.targets)


def _is_docstring(stmt: ast.stmt) -> bool:
    return (
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Constant)
        and isinstance(stmt.value.value, str)
    )


# ── 5. every Config leaf is classified content or non-content, exhaustively ──

# The config leaves that do NOT change what a scan would store, each with why it is left out of the
# scan stamp. Paired with the content-marked leaves, this must cover EVERY leaf of Config — a new
# setting is then forced to declare which side it is on rather than defaulting to invisible.
NON_CONTENT_CONFIG: dict[str, str] = {
    "ghidra.mode": "not read; only local mode is implemented",
    "ghidra.headless_timeout_seconds": (
        "decides which binaries time out; a changed budget re-tries timed-out binaries on rescan "
        "and the per-binary extraction may change, which is surfaced by the per-binary "
        "incomplete/timeout markers, not by a run-level scan-stamp change"
    ),
    "ghidra.max_parallel_jvms": "how many JVMs run in parallel; does not change what is stored",
    "ghidra.local.home": "where Ghidra is installed; its version is recorded separately",
    "ghidra.docker.image": "unimplemented docker mode",
    "ghidra.remote.endpoint": "unimplemented remote mode",
    "toolchain.java_home": "where the JDK is; does not change what is stored",
    "toolchain.bindiff": "where BinDiff is; a diff-time tool, not a scan input",
    "workspace_dir": "where workspaces live on disk",
    "atlas.db_path": "where the atlas lives on disk",
    "log_level": "not read; logging verbosity",
}


def test_every_config_leaf_is_classified_content_or_not() -> None:
    """The scan stamp carries exactly the config that changes what a scan stores. A leaf that is
    neither content-marked nor listed non-content is unclassified — and would silently be left out
    of the stamp, so a run scanned under a different value of it would wrongly read as current.

    MUTATION: add a Config field and mark it neither way -> RED (it appears in neither set)."""
    leaves = set(rv._leaf_fields(Config))
    content = {
        path
        for path, field in rv._leaf_fields(Config).items()
        if isinstance(getattr(field, "json_schema_extra", None), dict)
        and field.json_schema_extra.get("tmap_content") is True
    }
    non_content = set(NON_CONTENT_CONFIG)
    assert content & non_content == set(), content & non_content
    assert leaves == content | non_content, {
        "unclassified": leaves - content - non_content,
        "stale_in_lists": (content | non_content) - leaves,
    }
    assert content == {"xref_fold_edge_threshold"}


# ── 6. the mutation table: the hash reacts to code, not to comments ──


def _mutate(edit) -> tuple[str, str]:
    """Copy the package, apply ``edit``, and return (pipeline, hunt) stamps of the copy."""
    import tempfile

    tmp = Path(tempfile.mkdtemp())
    try:
        dst = tmp / "treasure_map"
        shutil.copytree(PKG, dst, ignore=shutil.ignore_patterns("__pycache__"))
        edit(dst)
        return rv.code_version_of(dst, rv.PIPELINE_ROOT), rv.code_version_of(dst, rv.HUNT_ROOT)
    finally:
        shutil.rmtree(tmp)


def _edit(dst: Path, rel: str, old: str, new: str) -> None:
    p = dst / rel
    text = p.read_text(encoding="utf-8")
    assert old in text, f"anchor missing in {rel}: {old!r}"
    p.write_text(text.replace(old, new, 1), encoding="utf-8")


def _append(dst: Path, rel: str, text: str) -> None:
    p = dst / rel
    p.write_text(p.read_text(encoding="utf-8") + text, encoding="utf-8")


@pytest.mark.parametrize(
    ("name", "edit", "pipe_changes", "hunt_changes"),
    [
        (
            "a function added to a hunt-closure module",
            lambda d: _append(d, "lib/hunt/exec_edges.py", "\n\ndef _mut():\n    return 1\n"),
            False,
            True,
        ),
        (
            "only a comment",
            lambda d: _append(d, "lib/hunt/exec_edges.py", "\n# a comment\n"),
            False,
            False,
        ),
        (
            # The negative control for the entry-words reader: an import inside a facts function
            # body is still a closure edge, so it would pull the reader into the hunt stamp.
            "facts imports the entry-words reader inside a function body",
            lambda d: _append(
                d,
                "lib/facts.py",
                "\n\ndef _probe():\n    from treasure_map.lib.query import entry_words\n\n"
                "    return entry_words\n",
            ),
            False,
            True,
        ),
        (
            "a facts function the hunt does not use",
            lambda d: _append(d, "lib/facts.py", "\n\ndef _unused_by_hunt():\n    return 1\n"),
            False,
            False,
        ),
        (
            "open_analysis_ro's body (a used facts function)",
            lambda d: _edit(
                d,
                "lib/facts.py",
                "conn = ro_connect(Path(db_path))",
                "conn = ro_connect(Path(str(db_path)))",
            ),
            False,
            True,
        ),
        (
            "a facts function the hunt reaches only TRANSITIVELY (_run_ghidra_version's body)",
            lambda d: _edit(
                d,
                "lib/facts.py",
                "SELECT DISTINCT ghidra_version FROM current_binaries WHERE ghidra_ok = 1",
                "SELECT DISTINCT ghidra_version FROM current_binaries WHERE ghidra_ok=1",
            ),
            False,
            True,
        ),
        (
            "re-binding the ro_connect import",
            lambda d: _edit(
                d,
                "lib/facts.py",
                "from treasure_map.lib.ro_db import ro_connect",
                "from treasure_map.lib.ro_db import ro_uri as ro_connect",
            ),
            False,
            True,
        ),
        (
            "an unreferenced import added to facts",
            lambda d: _append(d, "lib/facts.py", "\nimport math as _unused_math\n"),
            False,
            False,
        ),
        (
            "a schema.sql comment",
            lambda d: _append(d, "lib/storage/schema.sql", "\n-- a new comment\n"),
            False,
            False,
        ),
        (
            "a schema.sql column",
            lambda d: _edit(
                d,
                "lib/storage/schema.sql",
                "CREATE TABLE IF NOT EXISTS binaries (",
                "CREATE TABLE IF NOT EXISTS binaries (\n    mut_col TEXT,",
            ),
            True,
            False,
        ),
        (
            "the shared extractor_names.tsv",
            lambda d: _append(d, "lib/analyze/ghidra/extractor_names.tsv", "\nmut\tcol\n"),
            True,
            True,
        ),
        (
            "get_pseudocode's empty-text status (a facts function the hunt does not use)",
            lambda d: _edit(
                d,
                "lib/facts.py",
                '        listing = _listing_for(conn, row)\n        if listing["available"]:',
                '        listing = dict(_listing_for(conn, row))\n        if listing["available"]:',
            ),
            False,
            False,
        ),
        (
            "the decompile size floor's value",
            lambda d: _edit(
                d, "lib/facts.py", "_DECOMPILE_MIN_SIZE = 10", "_DECOMPILE_MIN_SIZE = 12"
            ),
            False,
            True,
        ),
        (
            "the read face's micro pair state (sameness / patch_view / diff_align)",
            lambda d: (
                _edit(
                    d,
                    "lib/query/sameness.py",
                    'U_SKIPPED_MICRO = "skipped_micro"',
                    'U_SKIPPED_MICRO = "sm"',
                ),
                _edit(
                    d,
                    "lib/query/patch_view.py",
                    "sameness.SKIPPED_MICRO_STATE: tally.get(",
                    "sameness.SKIPPED_MICRO_STATE: 0 + tally.get(",
                ),
                _edit(
                    d,
                    "lib/query/diff_align.py",
                    "a side is a micro-function not",
                    "a micro side not",
                ),
            ),
            False,
            False,
        ),
        (
            "rescan_version.py itself (excluded from both)",
            lambda d: _append(d, "lib/rescan_version.py", "\n_MUT = 1\n"),
            False,
            False,
        ),
    ],
)
def test_the_stamp_reacts_to_code_not_comments(
    name: str, edit, pipe_changes: bool, hunt_changes: bool
) -> None:
    base_pipe, base_hunt = (
        rv.code_version_of(PKG, rv.PIPELINE_ROOT),
        rv.code_version_of(PKG, rv.HUNT_ROOT),
    )
    pipe, hunt = _mutate(edit)
    assert (pipe != base_pipe) is pipe_changes, f"{name}: pipeline change expected={pipe_changes}"
    assert (hunt != base_hunt) is hunt_changes, f"{name}: hunt change expected={hunt_changes}"


# ── 7 & 8. closure membership facts ──


@pytest.mark.parametrize(
    ("module", "root"),
    [
        ("lib.analyze.xrefs", rv.PIPELINE_ROOT),
        ("lib.analyze.non_binary.orchestrator", rv.PIPELINE_ROOT),
        ("lib.hunt.exec_edges", rv.HUNT_ROOT),
        ("lib.diff.loader", rv.HUNT_ROOT),
    ],
)
def test_expected_members_are_in_the_closure(module: str, root: str) -> None:
    assert module in rv._closure(PKG, root)


def test_version_is_in_the_hunt_closure() -> None:
    """``version`` feeds the hunt's ``tool_version`` (the _version_skew comparison), so it must be
    hashed into the hunt stamp."""
    assert "version" in rv._closure(PKG, rv.HUNT_ROOT)


# ── 9. a stored scan stamp that is JSON but not an object ──


@pytest.mark.parametrize("stored", ["null", "[]", "123"])
def test_a_stored_scan_stamp_that_is_not_a_json_object_reads_unknown(stored: str) -> None:
    """A stored stamp corrupted out of band into valid JSON that is not an object (``null``, a
    list, a number) has no leaves to compare: it reads as one ``unknown`` of ``"scan stamp"`` and
    never raises — the run-staleness check behind the stale-scan refusal, and the rescan
    classifier, would otherwise crash on that one run.

    MUTATION (verified RED, 3 failed): drop the ``isinstance(parsed, dict)`` check -> each of the
    three raises AttributeError, caught here and failed as an assertion."""
    current = rv.scan_stamp_for(Config())
    try:
        got = rv.compare_scan_stamps(stored, current)
    except Exception as exc:  # noqa: BLE001 — the point: a corrupt stamp must not crash a gate
        raised: Exception | None = exc
        got = None
    else:
        raised = None
    assert raised is None, f"stored stamp {stored!r} raised {raised!r}"
    assert got == rv.StampCompare((), ("scan stamp",))


# ── the entry-words reader stays out of every stamp ──


def test_the_entry_words_reader_is_in_no_rescan_closure() -> None:
    """lib.query.entry_words and the two places that compose it (patch_view, mcp_app) are read on
    demand and write nothing, so no rescan stamp may hash them — and lib.facts must not import
    them, or the hunt stamp would move with every change to the reader."""
    for root in ROOTS:
        closure = rv._closure(PKG, root)
        assert "lib.facts" in closure or root == rv.PIPELINE_ROOT
        for module in ("lib.query.entry_words", "lib.query.patch_view", "mcp_app"):
            assert module not in closure, (root, module)


def test_the_file_comparison_is_in_no_rescan_closure() -> None:
    """lib.query.file_diff reads two scans' non-binary records at view time: no rescan stamp
    hashes it, nor the modules that judge a file."""
    for root in ROOTS:
        closure = rv._closure(PKG, root)
        for module in (
            "lib.query.file_diff",
            "lib.query.diff_review",
            "lib.query.diff_annotations",
            "lib.overlay",
        ):
            assert module not in closure, (root, module)


def test_hoisting_the_rx_warning_moves_no_stamp(tmp_path: Path) -> None:
    """The RX warning was hoisted out of get_data_bytes into a top-level constant so the data-table
    reader shares it. With the warning put back inline, all four stamps — pipeline, hunt, diff,
    overlay — are what they are now."""
    from treasure_map.lib import facts
    from treasure_map.lib.diff import code_version as cv

    dst = tmp_path / "treasure_map"
    shutil.copytree(PKG, dst, ignore=shutil.ignore_patterns("__pycache__"))
    path = dst / "lib" / "facts.py"
    text = path.read_text(encoding="utf-8")
    use = 'result["warning"] = _RX_BYTES_WARNING'
    start = text.index("_RX_BYTES_WARNING = (")
    end = text.index(")\n", start) + 2
    assert text.count(use) == 1 and start > 0
    inline = text.replace(use, f"result['warning'] = {facts._RX_BYTES_WARNING!r}")
    inline = inline[:start] + inline[end:]
    assert "_RX_BYTES_WARNING" not in inline
    path.write_text(inline, encoding="utf-8")
    for root in ROOTS:
        assert rv.code_version_of(dst, root) == rv.code_version_of(PKG, root), root
    for entries in (cv.DIFF_CODE_ENTRIES, cv.OVERLAY_CODE_ENTRIES):
        assert cv.code_hash(dst, entries) == cv.code_hash(PKG, entries)
