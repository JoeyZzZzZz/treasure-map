# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""The map-model ``diff`` command: retirement of the old A1 path, the five-check preflight, and the
read-only diff MCP tools.

Hermetic and synthetic — the external toolchain (Ghidra / BinExport / BinDiff) is never invoked
here (it cannot run in CI). The preflight's five gates ARE exercised end-to-end with synthetic
runs / analysis.db files / .so files, monkeypatching only the toolchain-presence check where a test
needs to reach a later gate. The four tools are tested for their binary filter, verbose toggle,
read-only source, and explicit-atlas requirement.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path

import pytest

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import DimensionDeltaRow
from treasure_map.lib.atlas.writer import add_dimension_deltas, begin_run
from treasure_map.lib.diff import driver
from treasure_map.lib.diff.driver import DiffToolchainError, preflight
from treasure_map.lib.errors import ConfigError, GhidraNotFoundError
from treasure_map.lib.query import diff_align
from treasure_map.lib.storage.connection import open_db

_SRC = Path(__file__).resolve().parents[3] / "src" / "treasure_map"


# ── fixtures ─────────────────────────────────────────────────────────────────────────


def _mk_analysis(path: Path, binary: str, so_path: str | None) -> Path:
    """A synthetic analysis.db with one binary; ``so_path`` is what ``binaries.path`` records (None
    => the bare name, i.e. an unlocatable relative path)."""
    con = open_db(path)
    con.execute(
        "INSERT INTO binaries (id, name, path, sha256) VALUES (1, ?, ?, ?)",
        (binary, so_path if so_path is not None else binary, binary + "_sha"),
    )
    con.commit()
    con.close()
    return path


def _seed(
    tmp_path: Path,
    *,
    ghidra_a: str = "11.4.3",
    ghidra_b: str = "11.4.3",
    tool_a: str = "0.0.1",
    tool_b: str = "0.0.1",
    db_a_exists: bool = True,
    db_b_exists: bool = True,
    resolved_b: bool = True,
    so_a: str | None = None,
    so_b: str | None = None,
) -> Path:
    """Two runs (run_a/run_b) each resolving to a synthetic analysis.db carrying 'lib.so'. Knobs let
    a test break exactly one preflight precondition."""
    dba = tmp_path / "a.db"
    dbb = tmp_path / "b.db"
    _mk_analysis(dba, "lib.so", so_a)
    _mk_analysis(dbb, "lib.so", so_b)
    if not db_a_exists:
        dba.unlink()
    if not db_b_exists:
        dbb.unlink()
    atlas_path = tmp_path / "atlas.db"
    con = open_atlas(atlas_path)
    begin_run(con, "run_a", analysis_db_path=str(dba), tool_version=tool_a, ghidra_version=ghidra_a)
    begin_run(
        con,
        "run_b",
        analysis_db_path=str(dbb) if resolved_b else None,
        tool_version=tool_b,
        ghidra_version=ghidra_b,
    )
    con.close()
    return atlas_path


def _cfg():  # type: ignore[no-untyped-def]
    from treasure_map.lib.config.config import Config

    return Config()


def _no_toolchain_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make preflight check 5 a no-op so a test can assert checks 1-4 without a real toolchain."""
    monkeypatch.setattr(driver, "_check_toolchain", lambda config: None)


# ── preflight: the five checks, each failing fast at its own gate ──────────────────────


def test_check1_unscanned_run_hard_blocks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _no_toolchain_gate(monkeypatch)
    atlas_path = _seed(tmp_path, resolved_b=False)  # run_b unresolved
    con = open_atlas(atlas_path)
    with pytest.raises(ConfigError, match="unresolved|re-scan"):
        preflight(con, "run_a", "run_b", "lib.so", config=_cfg(), force=False)
    con.close()


def test_check1_run_absent_from_atlas_hard_blocks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_toolchain_gate(monkeypatch)
    atlas_path = _seed(tmp_path)
    con = open_atlas(atlas_path)
    with pytest.raises(ConfigError, match="not in this atlas"):
        preflight(con, "run_a", "nope", "lib.so", config=_cfg(), force=False)
    con.close()


def test_check2_analysis_db_missing_on_disk_hard_blocks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_toolchain_gate(monkeypatch)
    atlas_path = _seed(tmp_path, db_b_exists=False)  # path recorded, file gone
    con = open_atlas(atlas_path)
    with pytest.raises(ConfigError, match="not present on this machine"):
        preflight(con, "run_a", "run_b", "lib.so", config=_cfg(), force=False)
    con.close()


def test_check3_version_skew_without_force_hard_blocks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_toolchain_gate(monkeypatch)
    so = tmp_path / "lib.so"
    so.write_bytes(b"\x7fELF")
    atlas_path = _seed(
        tmp_path, ghidra_b="11.4.2", so_a=str(so), so_b=str(so)
    )  # decompiler differs
    con = open_atlas(atlas_path)
    with pytest.raises(ConfigError, match="different tmap/Ghidra versions|--force"):
        preflight(con, "run_a", "run_b", "lib.so", config=_cfg(), force=False)
    con.close()


def test_check3_version_skew_with_force_proceeds_and_warns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_toolchain_gate(monkeypatch)
    so = tmp_path / "lib.so"
    so.write_bytes(b"\x7fELF")
    atlas_path = _seed(tmp_path, ghidra_b="11.4.2", so_a=str(so), so_b=str(so))
    con = open_atlas(atlas_path)
    pf = preflight(con, "run_a", "run_b", "lib.so", config=_cfg(), force=True)
    assert pf.version_skew is True  # honestly recorded, not hidden by --force
    assert pf.warnings and any("version" in w for w in pf.warnings)
    con.close()


def test_check4_so_unlocatable_hard_blocks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _no_toolchain_gate(monkeypatch)
    # so_a/so_b default None -> binaries.path is the bare relative name, unresolvable -> hard block
    atlas_path = _seed(tmp_path)
    con = open_atlas(atlas_path)
    with pytest.raises(ConfigError, match="cannot be located on this machine"):
        preflight(con, "run_a", "run_b", "lib.so", config=_cfg(), force=False)
    con.close()


def test_check5_toolchain_missing_hard_blocks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # checks 1-4 pass (valid runs + real .so + same version); check 5 fails deterministically.
    so = tmp_path / "lib.so"
    so.write_bytes(b"\x7fELF")
    atlas_path = _seed(tmp_path, so_a=str(so), so_b=str(so))

    def _raise(_config):  # type: ignore[no-untyped-def]
        raise GhidraNotFoundError("no headless")

    monkeypatch.setattr("treasure_map.lib.analyze.ghidra_runner.find_headless", _raise)
    monkeypatch.setattr(driver, "_find_bindiff", lambda: None)
    con = open_atlas(atlas_path)
    with pytest.raises(DiffToolchainError, match="toolchain is not available"):
        preflight(con, "run_a", "run_b", "lib.so", config=_cfg(), force=False)
    con.close()


def test_check5_all_present_preflight_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    so = tmp_path / "lib.so"
    so.write_bytes(b"\x7fELF")
    atlas_path = _seed(tmp_path, so_a=str(so), so_b=str(so))
    monkeypatch.setattr(
        "treasure_map.lib.analyze.ghidra_runner.find_headless", lambda c: Path("/x")
    )
    monkeypatch.setattr(driver, "_binexport_present", lambda h: True)
    monkeypatch.setattr(driver, "_find_bindiff", lambda: Path("/usr/bin/bindiff"))
    con = open_atlas(atlas_path)
    pf = preflight(con, "run_a", "run_b", "lib.so", config=_cfg(), force=False)
    assert pf.binary_a == "lib.so" and pf.binary_b == "lib.so"
    assert pf.so_a == so and pf.so_b == so
    assert pf.version_skew is False and pf.warnings == ()
    con.close()


# ── binary filter + verbose (the read face, on synthetic dimension_delta rows) ──────────


def _seed_two_binary_deltas(atlas_path: Path) -> None:
    con = open_atlas(atlas_path)
    con.execute(
        "INSERT OR REPLACE INTO diff_meta (diff_id, run_a_id, run_b_id, version_skew, "
        "binary_a, binary_b) VALUES ('d', 'ra', 'rb', 0, 'lib_a.so', 'lib_a.so')"
    )
    add_dimension_deltas(
        con,
        [
            DimensionDeltaRow(
                diff_id="d",
                dimension="reachability.string_keyed_edge",
                subject_kind="edge",
                subject_key="lib_a.so|strcmp_gate|k1|1000",
                delta_kind="layer_changed",
                binary="lib_a.so",
            ),
            DimensionDeltaRow(
                diff_id="d",
                dimension="reachability.string_keyed_edge",
                subject_kind="edge",
                subject_key="lib_b.so|strcmp_gate|k2|2000",
                delta_kind="layer_unchanged",
                binary="lib_b.so",
            ),
        ],
    )
    con.close()


def test_binary_filter_returns_only_that_binary(tmp_path: Path) -> None:
    atlas_path = tmp_path / "atlas.db"
    open_atlas(atlas_path).close()
    _seed_two_binary_deltas(atlas_path)
    con = open_atlas(atlas_path)
    res = diff_align.get_diff_deltas(con, "d", binary="lib_a.so")
    con.close()
    assert res["page"]["count"] == 1
    assert [d["subject_key"] for d in res["deltas"]] == ["lib_a.so|strcmp_gate|k1|1000"]


def test_binary_filter_nonexistent_binary_returns_zero_not_all(tmp_path: Path) -> None:
    atlas_path = tmp_path / "atlas.db"
    open_atlas(atlas_path).close()
    _seed_two_binary_deltas(atlas_path)
    con = open_atlas(atlas_path)
    res = diff_align.get_diff_deltas(con, "d", binary="ghost.so")
    con.close()
    assert res["page"]["count"] == 0 and res["deltas"] == []  # never falls back to all


def test_verbose_toggles_caveats(tmp_path: Path) -> None:
    atlas_path = tmp_path / "atlas.db"
    open_atlas(atlas_path).close()
    _seed_two_binary_deltas(atlas_path)
    con = open_atlas(atlas_path)
    lean = diff_align.get_diff_deltas(con, "d")
    rich = diff_align.get_diff_deltas(con, "d", verbose=True)
    con.close()
    assert "note" not in lean and "legend" not in lean  # default is lean
    assert "note" in rich and "legend" in rich


# ── explicit atlas: helpers take the connection, never fall back to a default ───────────


def test_read_helpers_require_explicit_atlas_no_default_fallback() -> None:
    for fn in (
        diff_align.get_diff_deltas,
        diff_align.get_diff_meta,
        diff_align.get_diff_capabilities,
        diff_align.align_by_a,
        diff_align.align_by_b,
    ):
        src = inspect.getsource(fn)
        assert "load_config" not in src, f"{fn.__name__} reaches for a default atlas"
        assert "db_path" not in src, f"{fn.__name__} reaches for a default atlas path"
    # and the atlas connection is a required positional (omitting it is a TypeError, not a default)
    with pytest.raises(TypeError):
        diff_align.get_diff_meta()  # type: ignore[call-arg]


# ── read-only: neither the helpers nor the tools carry a write statement ────────────────


def test_diff_read_helpers_have_no_write_sql() -> None:
    write = re.compile(r"\b(INSERT|UPDATE|DELETE|REPLACE|CREATE|DROP|ALTER)\b", re.IGNORECASE)
    for fn in (
        diff_align.get_diff_deltas,
        diff_align.get_diff_meta,
        diff_align.get_diff_capabilities,
        diff_align.align_by_a,
        diff_align.align_by_b,
    ):
        assert not write.search(inspect.getsource(fn)), f"{fn.__name__} carries a write statement"


def test_diff_mcp_tools_have_no_write_sql(tmp_path: Path) -> None:
    from treasure_map.mcp_app import make_tools

    atlas_path = tmp_path / "atlas.db"
    open_atlas(atlas_path).close()
    tools = make_tools(atlas_path)
    write = re.compile(r"\b(INSERT|UPDATE|DELETE|REPLACE|CREATE|DROP|ALTER)\b", re.IGNORECASE)
    for name in (
        "get_diff_deltas",
        "get_diff_meta",
        "get_function_alignment",
        "get_diff_capabilities",
    ):
        assert name in tools
        assert not write.search(inspect.getsource(tools[name])), f"{name} carries a write statement"


# ── retirement: the old grading diff path is gone, not merely unwired ───────────────────


def test_retired_modules_are_removed() -> None:
    for rel in (
        "lib/diff/differ.py",
        "lib/diff/matcher.py",
        "lib/diff/models.py",
        "lib/hunt/diff_analyzer.py",
    ):
        assert not (_SRC / rel).exists(), f"{rel} should have been removed"


def test_retired_symbols_are_unimportable() -> None:
    import treasure_map.lib.diff as diffpkg
    import treasure_map.lib.hunt as huntpkg

    assert not hasattr(diffpkg, "run_diff")
    assert not hasattr(diffpkg, "Axis")
    assert not hasattr(huntpkg, "run_diff_analyzer")
    assert not hasattr(huntpkg, "AnalyzerStats")


def test_diff_command_uses_the_map_pipeline_not_the_grading_analyzer() -> None:
    src = (_SRC / "cli" / "hunt_cli.py").read_text()
    assert "run_version_diff" in src  # new map-model driver
    assert "run_diff_analyzer" not in src  # the retired grading path
    assert "_complete_run_ids" not in src.replace(  # merged away (docstring mention aside)
        "the former ``_complete_run_ids`` duplicate was merged", ""
    )


def test_grade_candidate_never_returns_blocked() -> None:
    from treasure_map.lib.reachability import grader

    src = inspect.getsource(grader.grade_candidate)
    assert 'ReachabilityVerdict("blocked"' not in src
    assert "blocked" in inspect.getdoc(grader.grade_candidate).lower()  # documented as reserved
