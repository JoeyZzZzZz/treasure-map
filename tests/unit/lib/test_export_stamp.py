# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The export stamp (lib/export_stamp): what a scan's BinExport export was made by, kept out of the
extraction pass and the scan stamp, and which BinExport copy a scan's JVM loads.

Zero real data: a copy of the package for the stamp tests, a fake Ghidra installation (its
application.properties and extension directories) for the extension tests.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from treasure_map.lib import export_stamp as es
from treasure_map.lib import rescan_version as rv
from treasure_map.lib.analyze.ghidra_runner import compute_pass_version

PKG = Path(rv.__file__).resolve().parents[1]


@pytest.fixture
def pkg(tmp_path: Path) -> Path:
    dst = tmp_path / "treasure_map"
    shutil.copytree(PKG, dst, ignore=shutil.ignore_patterns("__pycache__"))
    return dst


def _touch(path: Path) -> None:
    path.write_bytes(path.read_bytes() + b"\n// edited\n")


# ── the export hash is its own account ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "edited",
    ["lib/diff/ghidra/ExportBinExport.java", "lib/diff/ghidra/StackVarnodeMarkup.java"],
)
def test_an_export_script_edit_moves_the_export_hash_and_neither_scan_stamp(
    pkg: Path, edited: str
) -> None:
    """★ The export scripts (the markup judge included) change no extracted fact: editing one
    leaves the extraction pass and the scan stamp's code hash where they were — no run is refused
    — and moves the export hash, which re-scans the binaries for their export.

    MUTATION (verified RED): leave the judge file out of export_files -> its edit does not move the
    export hash; add lib/diff/ghidra/*.java to ghidra_runner's assets -> the scan stamp moves."""
    analyze = pkg / "lib" / "analyze" / "ghidra"
    export_dir = pkg / "lib" / "diff" / "ghidra"
    before = (
        compute_pass_version(analyze),
        rv.code_version_of(pkg, rv.PIPELINE_ROOT),
        es.export_code_hash_in(es.SCAN_BUILDER, export_dir),
    )
    _touch(pkg / edited)
    after = (
        compute_pass_version(analyze),
        rv.code_version_of(pkg, rv.PIPELINE_ROOT),
        es.export_code_hash_in(es.SCAN_BUILDER, export_dir),
    )
    assert after[:2] == before[:2]
    assert after[2] != before[2]


def test_the_export_stamp_module_is_outside_the_scan_stamp(pkg: Path) -> None:
    """The pipeline imports lib/export_stamp, and an edit to it must not re-stamp every run: it is
    excluded from the closure (and says why).

    MUTATION (verified RED): drop it from CLOSURE_EXCLUDED -> its edit moves the scan stamp."""
    before = rv.code_version_of(pkg, rv.PIPELINE_ROOT)
    path = pkg / "lib" / "export_stamp.py"
    path.write_text(path.read_text() + "\nEDITED = 1\n")
    assert rv.code_version_of(pkg, rv.PIPELINE_ROOT) == before
    assert "lib.export_stamp" in rv.CLOSURE_EXCLUDED


def test_the_promotion_script_is_part_of_the_extraction_pass(pkg: Path) -> None:
    """Creating the functions the analysis left out changes the function set: an edit to it moves
    the extraction pass, so every binary is re-extracted.

    MUTATION (verified RED): put PromoteUndefined.java beside the export scripts -> the pass does
    not move."""
    analyze = pkg / "lib" / "analyze" / "ghidra"
    before = compute_pass_version(analyze)
    _touch(analyze / "PromoteUndefined.java")
    assert compute_pass_version(analyze) != before


@pytest.mark.parametrize("builder", ["extension", "fallback", None])
def test_every_builder_path_takes_the_export_script_and_the_judge(builder: str | None) -> None:
    files = es.export_files(builder)
    assert es.EXPORT_SCRIPT in files and es.MARKUP_JUDGE in files
    assert (es.FALLBACK_BUILDER in files) is (builder != "extension")


def test_a_fallback_builder_edit_moves_only_the_paths_that_take_it(tmp_path: Path) -> None:
    d = tmp_path / "ghidra"
    shutil.copytree(es.EXPORT_SCRIPT_DIR, d)
    before = {b: es.export_code_hash_in(b, d) for b in ("extension", "fallback", None)}
    assert es.export_code_hash_in("fallback", es.EXPORT_SCRIPT_DIR) == es.export_code_hash(
        "fallback"
    )
    _touch(d / es.FALLBACK_BUILDER)
    assert es.export_code_hash_in("extension", d) == before["extension"]
    assert es.export_code_hash_in("fallback", d) != before["fallback"]
    assert es.export_code_hash_in(None, d) != before[None]


def test_the_export_hash_moves_with_either_part() -> None:
    base = es.export_hash("aaaa", "11.4.3+lib:000000000000")
    assert es.export_hash("bbbb", "11.4.3+lib:000000000000") != base
    assert es.export_hash("aaaa", "11.4.3+lib:111111111111") != base
    assert es.export_hash("aaaa", "11.4.3+lib:000000000000") == base


# ── which BinExport a scan loads ──────────────────────────────────────────────────────────────


def _ghidra(root: Path) -> Path:
    home = root / "ghidra_11.4.3_PUBLIC"
    props = home / "Ghidra" / "application.properties"
    props.parent.mkdir(parents=True)
    props.write_text("application.version=11.4.3\napplication.release.name=PUBLIC\n")
    return home


def _extension(where: Path, version: str = "11.4.3") -> Path:
    (where / "lib").mkdir(parents=True)
    (where / "extension.properties").write_text(f"version={version}\n")
    (where / "lib" / "BinExport.jar").write_bytes(b"jar-" + version.encode())
    return where


def _user_settings(user_home: Path) -> Path:
    return user_home / ".config" / "ghidra" / "ghidra_11.4.3_PUBLIC" / "Extensions" / "BinExport"


def test_the_installations_copy_is_loaded_and_nothing_is_linked(tmp_path: Path) -> None:
    """The default install (the extension inside Ghidra): it is the one loaded, under any user home,
    so nothing is linked — a second module path is what makes Ghidra refuse to start."""
    home = _ghidra(tmp_path)
    install = _extension(es.install_binexport_dir(home))
    ext = es.scan_extension(home, environ={}, user_home=tmp_path / "user")
    assert (ext.ext_dir, ext.link_from, ext.note) == (install, None, None)
    assert ext.stamp is not None and ext.stamp.startswith("11.4.3+lib:")


def test_a_user_settings_copy_is_linked_into_the_scans_home(tmp_path: Path) -> None:
    """★ The extension only in the user settings directory: the scan's JVM, run under a temporary
    user home, would not see it, so it is linked there — a symbolic link to the one copy, never a
    copy.

    MUTATION (verified RED): copy the directory instead of linking it -> RED; skip the link ->
    RED."""
    home = _ghidra(tmp_path)
    user = tmp_path / "user"
    copy = _extension(_user_settings(user))
    ext = es.scan_extension(home, environ={}, user_home=user)
    assert (ext.ext_dir, ext.link_from) == (copy, copy)
    temp_home = tmp_path / "jvm_home"
    es.link_into_home(ext, home, temp_home)
    link = _user_settings(temp_home)
    assert link.is_symlink() and link.resolve() == copy.resolve()


def test_two_copies_use_the_installations_and_never_block(tmp_path: Path) -> None:
    """Installed AND in the user settings directory: the scan's JVM sees only the installed one
    under its temporary home, so the scan runs with it, links nothing, and only notes the pair."""
    home = _ghidra(tmp_path)
    user = tmp_path / "user"
    install = _extension(es.install_binexport_dir(home))
    _extension(_user_settings(user), version="11.4.2")
    ext = es.scan_extension(home, environ={}, user_home=user)
    assert (ext.ext_dir, ext.link_from) == (install, None)
    assert ext.note is not None and "not loaded by the scan" in ext.note


def test_no_copy_is_extension_missing_with_where_it_looked(tmp_path: Path) -> None:
    home = _ghidra(tmp_path)
    ext = es.scan_extension(home, environ={}, user_home=tmp_path / "user")
    assert (ext.ext_dir, ext.stamp, ext.link_from) == (None, None, None)
    assert ext.note is not None and "no BinExport extension" in ext.note


def test_a_copy_under_xdg_is_found_and_linked_into_the_scans_own_home(tmp_path: Path) -> None:
    """With XDG_CONFIG_HOME set, the user's copy is looked for where Ghidra keeps it for the user;
    the scan's JVM runs without XDG_CONFIG_HOME (every setting inside its temporary home), so the
    copy is linked into that home and nothing is written under the user's configuration tree.

    MUTATION (verified RED): link under XDG_CONFIG_HOME -> the user's tree gets a link -> RED."""
    home = _ghidra(tmp_path)
    user = tmp_path / "user"
    xdg = user / "xdg"
    copy = _extension(xdg / "ghidra" / "ghidra_11.4.3_PUBLIC" / "Extensions" / "BinExport")
    ext = es.scan_extension(home, environ={"XDG_CONFIG_HOME": str(xdg)}, user_home=user)
    assert ext.link_from == copy
    temp_home = tmp_path / "jvm_home"
    before = sorted(p.name for p in xdg.rglob("*"))
    es.link_into_home(ext, home, temp_home)
    assert _user_settings(temp_home).resolve() == copy.resolve()
    assert sorted(p.name for p in xdg.rglob("*")) == before
