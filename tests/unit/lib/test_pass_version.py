# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The pass fingerprint must cover every extraction step whose output is cached per binary.

pass_version is the cache key: if it does not change when an extraction step changes, a same-content
re-scan skips every binary and the new logic never runs — a false negative that ships silently. It
was once only the .java, then a Python relabel step (stub_resolve) started changing the stored
callees while the fingerprint ignored it, and the recovery it added never fired on a re-scan. So the
fingerprint now spans the declared Python pipeline too, and this file LOCKS that set against its
criterion mechanically — a future step added and left undeclared fails here rather than shipping
blind.

★ The criterion is deliberately NOT a transitive import closure: ghidra_ingest imports elf_inventory
for the ElfRecord TYPE and reaches symlinks two hops on, and symlinks runs on every scan
(wipe-and-rebuild). Pulling those in by import transitivity would make an edit to an unrelated step
trigger a full, hours-long Ghidra re-extraction. The membership rule is "its output is CALLED into
the functions cache in the dirty loop", which a type-only import does not satisfy.
"""

from __future__ import annotations

import ast
from pathlib import Path

from treasure_map.lib.analyze.ghidra_runner import (
    _PIPELINE_PY_MODULES,
    compute_pass_version,
    pass_version_source_files,
)

_ANALYZE = Path(__file__).resolve().parents[3] / "src" / "treasure_map" / "lib" / "analyze"
_INGEST = _ANALYZE / "ghidra_ingest.py"


# ── the mechanical completeness gate ──────────────────────────────────────────────────


def _analyze_modules_called_in(path: Path) -> set[str]:
    """The ``analyze.*`` modules whose imported symbols are CALLED in ``path``.

    An imported name that is only used as a type annotation (``list[ElfRecord]``) is NOT a call, so
    the module it came from is not a pipeline member — which is exactly how elf_inventory stays out
    while stub_resolve, whose ``resolve_stubs`` / ``relabel_callees`` are invoked, stays in. This is
    the machine reading of "its output is written into the functions cache", tied to the one file
    that does that writing (ghidra_ingest)."""
    tree = ast.parse(path.read_text())
    symbol_module: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and ".analyze." in f".{node.module}.":
            module_file = node.module.rsplit(".", 1)[-1] + ".py"
            for alias in node.names:
                symbol_module[alias.asname or alias.name] = module_file
    called: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else None
            if name and name in symbol_module:
                called.add(symbol_module[name])
    return called


def test_the_declared_set_matches_the_dirty_loop_functions_writers() -> None:
    # ★ THE COMPLETENESS LOCK. The declared pipeline set must equal exactly {ghidra_ingest itself}
    # plus every analyze module whose output ghidra_ingest CALLS into the functions cache. Add an
    # extraction step and call it in ingest without declaring it here, and this fails — the set
    # cannot silently fall behind the code.
    #
    # MUTATION (verified RED, 1 failed): drop "stub_resolve.py" from _PIPELINE_PY_MODULES in
    # ghidra_runner.py -> the computed set includes it (stub_resolve is called in ingest) but the
    # declared set does not -> mismatch.
    computed = {"ghidra_ingest.py"} | _analyze_modules_called_in(_INGEST)
    assert set(_PIPELINE_PY_MODULES) == computed, (
        f"declared {set(_PIPELINE_PY_MODULES)} != writers-in-dirty-loop {computed}"
    )


def test_the_type_only_import_is_not_a_pipeline_member() -> None:
    # ★ The reason for a call-based criterion, not an import-based one. elf_inventory IS imported by
    # ghidra_ingest — for the ElfRecord type — but never CALLED to produce cached output, so it is
    # not a member. An import-closure criterion would wrongly pull it, and symlinks behind it, into
    # the fingerprint and make an unrelated edit trigger a full re-extraction.
    called = _analyze_modules_called_in(_INGEST)
    assert "elf_inventory.py" not in called
    assert "symlinks.py" not in called
    # and elf_inventory really is imported (so the exclusion is meaningful, not a missing import)
    assert "from treasure_map.lib.analyze.elf_inventory import" in _INGEST.read_text()


# ── the fingerprint composition ───────────────────────────────────────────────────────


def test_the_fingerprint_covers_the_python_relabel_step() -> None:
    # ★ THE BUG THIS FIXES, at the fingerprint level. stub_resolve rewrites the stored callees, so
    # its content must be in the hash — or a same-content re-scan skips the binary and the relabel
    # never runs.
    #
    # MUTATION (verified RED, 1 failed): in pass_version_source_files hash only the .java (drop the
    # declared Python modules) -> stub_resolve stops being covered.
    names = {p.name for p in pass_version_source_files(_ANALYZE / "ghidra")}
    assert "stub_resolve.py" in names
    assert "ghidra_ingest.py" in names
    assert any(n.endswith(".java") for n in names)


def test_a_wipe_and_rebuild_step_is_not_in_the_fingerprint() -> None:
    # ★ The boundary the whole design turns on: symlinks and elf_inventory run on every scan, so an
    # edit to them takes effect on the next scan already — folding them in would only cost an
    # unnecessary full Ghidra re-extraction. They must NOT be hashed.
    names = {p.name for p in pass_version_source_files(_ANALYZE / "ghidra")}
    assert "symlinks.py" not in names
    assert "elf_inventory.py" not in names
    assert "xrefs.py" not in names


def _fake_analyze(root: Path, *, java: str, ingest: str, stub: str, extra: dict[str, str]) -> Path:
    analyze = root / "analyze"
    (analyze / "ghidra").mkdir(parents=True)
    (analyze / "ghidra" / "ExportFunctions.java").write_text(java)
    (analyze / "ghidra_ingest.py").write_text(ingest)
    (analyze / "stub_resolve.py").write_text(stub)
    for name, body in extra.items():
        (analyze / name).write_text(body)
    return analyze / "ghidra"


def test_editing_the_python_relabel_step_changes_the_fingerprint(tmp_path: Path) -> None:
    # The behavioural proof, on an isolated copy: change stub_resolve's bytes, pass_version moves.
    #
    # MUTATION (verified RED, 1 failed): same as above — hash only .java -> editing stub_resolve
    # leaves the fingerprint unchanged, so a re-scan would skip the binary.
    d1 = _fake_analyze(tmp_path / "a", java="class X{}", ingest="# i", stub="# v1", extra={})
    before = compute_pass_version(d1)
    (d1.parent / "stub_resolve.py").write_text("# v2 CHANGED")
    assert compute_pass_version(d1) != before


def test_editing_a_wipe_and_rebuild_step_leaves_the_fingerprint(tmp_path: Path) -> None:
    # ★ THE CLOSURE-COLLATERAL GUARD. Editing symlinks (a wipe-and-rebuild step, reachable only by
    # import transitivity) must NOT move the fingerprint — otherwise an unrelated change forces a
    # full re-extraction of every firmware.
    #
    # MUTATION (verified RED, 1 failed): add "symlinks.py" to _PIPELINE_PY_MODULES (the import-
    # closure mistake) -> editing symlinks below moves the fingerprint.
    d = _fake_analyze(
        tmp_path / "a",
        java="class X{}",
        ingest="# i",
        stub="# s",
        extra={"symlinks.py": "# sym v1", "elf_inventory.py": "# elf v1"},
    )
    before = compute_pass_version(d)
    (d.parent / "symlinks.py").write_text("# sym v2 CHANGED")
    (d.parent / "elf_inventory.py").write_text("# elf v2 CHANGED")
    assert compute_pass_version(d) == before


def test_the_fingerprint_is_deterministic_and_order_independent() -> None:
    # Same content, same fingerprint — twice, with no dependence on import order or sys.modules.
    a = compute_pass_version(_ANALYZE / "ghidra")
    b = compute_pass_version(_ANALYZE / "ghidra")
    assert a == b
    # and the source-file list is sorted (java by path, python by name) so the hash order is fixed
    files = pass_version_source_files(_ANALYZE / "ghidra")
    py = [f.name for f in files if f.suffix == ".py"]
    assert py == sorted(py)


def test_a_missing_analyze_dir_yields_a_stable_sentinel(tmp_path: Path) -> None:
    # A missing pipeline file is skipped, not fatal: a scan still runs (treating everything as a
    # first extraction) rather than crashing.
    empty = tmp_path / "nope" / "ghidra"
    v1 = compute_pass_version(empty)
    v2 = compute_pass_version(empty)
    assert v1 == v2 and isinstance(v1, str) and v1


# ── integration: a Python-step edit re-dirties the binary (the whole point) ────────────


def test_a_python_step_edit_makes_a_same_content_binary_dirty_again(tmp_path: Path) -> None:
    # ★ THE FIX, END TO END (minus Ghidra). A binary marked done under the OLD fingerprint is
    # re-dirtied under a fingerprint that moved because the Python relabel step changed — so a
    # same-content re-scan re-extracts it and the new callees (the recovered sink) get stored,
    # instead of being skipped forever.
    #
    # MUTATION (verified RED, 1 failed): in pass_version_source_files hash only the .java -> editing
    # stub_resolve leaves the fingerprint unchanged -> the binary stays already_done -> not dirty ->
    # the relabel never runs on a re-scan (exactly the bug being fixed).
    from treasure_map.lib.analyze.db_ingest import ingest_elfs
    from treasure_map.lib.analyze.elf_inventory import ElfRecord
    from treasure_map.lib.storage.connection import open_db

    analyze = _fake_analyze(tmp_path / "a", java="class X{}", ingest="# i", stub="# v1", extra={})
    old_fp = compute_pass_version(analyze)

    conn = open_db(tmp_path / "analysis.db")
    rec = ElfRecord(
        path=tmp_path / "bin.so",
        name="bin.so",
        arch="MIPS:BE:32",
        elf_type="shared_library",
        sha256="a" * 64,
    )
    # first scan: binary is dirty, then marked done under the OLD fingerprint
    _, dirty1 = ingest_elfs(conn, [rec], pass_version=old_fp)
    assert rec.sha256 in dirty1
    conn.execute(
        "UPDATE binaries SET ghidra_ok=1, pass_version=? WHERE sha256=?", (old_fp, rec.sha256)
    )
    conn.commit()
    # a re-scan under the SAME fingerprint skips it (it is genuinely done)
    _, dirty_same = ingest_elfs(conn, [rec], pass_version=old_fp)
    assert rec.sha256 not in dirty_same

    # now the Python relabel step changes -> the fingerprint moves -> the binary re-dirties
    (analyze.parent / "stub_resolve.py").write_text("# v2 CHANGED — recovers a sink")
    new_fp = compute_pass_version(analyze)
    assert new_fp != old_fp
    _, dirty2 = ingest_elfs(conn, [rec], pass_version=new_fp)
    assert rec.sha256 in dirty2  # re-extraction will run; the new callees get stored
    conn.close()


def test_the_docstring_describes_the_whole_pipeline_not_just_java() -> None:
    # ★ The doc that MISLED once. The old docstring said "every .java", so a reader adding a Python
    # extraction step had no reason to think the fingerprint concerned them — which is how the bug
    # happened. It must now name the Python pipeline explicitly, or the same misread returns.
    #
    # MUTATION (verified RED, 1 failed): revert compute_pass_version's docstring to only mention the
    # .java pass -> this fails.
    doc = compute_pass_version.__doc__ or ""
    assert "stub_resolve" in doc
    assert "pipeline" in doc.lower()
    assert "pyelftools" in doc  # the library-version blind spot is named, not hidden
