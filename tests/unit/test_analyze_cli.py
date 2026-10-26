# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the analyze CLI wrapper.

Stubs load_config / Workspace / run_analyze so the command runs without Ghidra,
proving the thin wrapper drives the pipeline and prints the result block.
"""

from __future__ import annotations

from dataclasses import fields as _dataclass_fields
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from treasure_map.cli.analyze_cli import analyze
from treasure_map.lib.analyze.pipeline import AnalyzeResult
from treasure_map.lib.config.config import Config

# Fields that are not plain counters, so they carry a real stand-in value.
_NON_COUNTER = {
    "db_path",
    "elapsed",
    "incomplete_binaries",
    "timeout_skipped",
    "no_functions_binaries",
    "kept_earlier_binaries",
}


def _fake_result(
    db_path: Path, timeout_skipped: list[dict[str, Any]] | None = None, **over: Any
) -> AnalyzeResult:
    """A stand-in AnalyzeResult, built FROM the real dataclass rather than hand-listed.

    The previous version was a SimpleNamespace with every printed attribute typed out by hand, so
    the moment the CLI printed one more field the stub silently lacked it — surfacing as an
    AttributeError buried inside a CliRunner result, and only in CI. Deriving the counters from
    ``AnalyzeResult`` itself means a new counter can never make this stub stale."""
    counters = {f.name: 0 for f in _dataclass_fields(AnalyzeResult) if f.name not in _NON_COUNTER}
    fields: dict[str, Any] = {
        "db_path": db_path,
        "elapsed": 0.1,
        "incomplete_binaries": [],
        "timeout_skipped": list(timeout_skipped or []),
        "no_functions_binaries": [],
        "kept_earlier_binaries": [],
        **counters,
    }
    fields.update(over)
    return AnalyzeResult(**fields)


class _DummyWorkspace:
    """Minimal context-manager workspace stub."""

    def __init__(self, path: Path, **_: Any) -> None:
        self.path = path
        self.db_path = path / "analysis.db"

    def __enter__(self) -> _DummyWorkspace:
        return self

    def __exit__(self, *_: object) -> None:
        return None


def _patch_pipeline(
    monkeypatch: pytest.MonkeyPatch,
    db_path: Path,
    timeout_skipped: list[dict[str, Any]] | None = None,
    **over: Any,
) -> None:
    """Stub load_config / Workspace / run_analyze so analyze runs without Ghidra."""

    def _fake_run_analyze(*_: Any, **__: Any) -> AnalyzeResult:
        return _fake_result(db_path, timeout_skipped, **over)

    monkeypatch.setattr(
        "treasure_map.lib.config.config.load_config",
        lambda _cfg=None: Config(llm=None),
    )
    monkeypatch.setattr(
        "treasure_map.lib.workspace.workspace.Workspace",
        _DummyWorkspace,
    )
    monkeypatch.setattr(
        "treasure_map.lib.analyze.pipeline.run_analyze",
        _fake_run_analyze,
    )


def test_analyze_runs_pipeline_and_prints_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_pipeline(monkeypatch, tmp_path / "analysis.db")

    fs_root = tmp_path / "fs"
    fs_root.mkdir()
    result = CliRunner().invoke(analyze, [str(fs_root), "--workspace", "ws"])

    assert result.exit_code == 0, result.output
    assert "Functions ingested:" in result.output
    assert "DB       :" in result.output


def test_analyze_names_the_binaries_it_did_not_re_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ A skip must reach the person running the scan, not only the log.

    Not re-running a timed-out binary is the difference between a scan that took half an hour less
    and one that looked at less. From the outside those are the same scan unless it says so — and
    the thing a faster scan most invites is the reading that there was less to find.

    MUTATION (must go RED): drop the report call from the command, or print a bare count with no
    binary named — the point is that the specific binary is nameable and re-attemptable."""
    _patch_pipeline(
        monkeypatch,
        tmp_path / "analysis.db",
        [{"binary": "big_daemon", "size_bytes": 14789215, "budget_seconds": 846}],
    )
    fs_root = tmp_path / "fs"
    fs_root.mkdir()
    result = CliRunner().invoke(analyze, [str(fs_root), "--workspace", "ws"])

    assert result.exit_code == 0, result.output
    assert "big_daemon" in result.output
    assert "846s budget" in result.output
    assert "14.1MB" in result.output
    assert "--force-retry" in result.output
    assert "still listed incomplete" in result.output
    # the base timeout, not the ceiling: for a binary this size the ceiling is not what binds, so
    # naming it would send the reader to a number that cannot change the outcome
    assert "headless_timeout_seconds" in result.output


def test_analyze_says_nothing_when_nothing_was_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The line appears only when there is something to report — silence has to mean "none"."""
    _patch_pipeline(monkeypatch, tmp_path / "analysis.db", [])
    fs_root = tmp_path / "fs"
    fs_root.mkdir()
    result = CliRunner().invoke(analyze, [str(fs_root), "--workspace", "ws"])
    assert result.exit_code == 0, result.output
    assert "timed out at the current budget" not in result.output


def test_analyze_hands_the_pipeline_an_absolute_firmware_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """binaries.path is written from this root; a relative one breaks `tmap diff` elsewhere.

    MUTATION: drop the resolve in the analyze command -> RED."""
    _patch_pipeline(monkeypatch, tmp_path / "analysis.db")
    seen: list[Path] = []

    def _capture(fs_root: Path, *_: Any, **__: Any) -> AnalyzeResult:
        seen.append(fs_root)
        return _fake_result(tmp_path / "analysis.db")

    monkeypatch.setattr("treasure_map.lib.analyze.pipeline.run_analyze", _capture)
    (tmp_path / "fs").mkdir()
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(analyze, ["fs", "--workspace", "ws"])
    assert result.exit_code == 0, result.output
    assert seen == [tmp_path.resolve() / "fs"]


def test_the_removed_skip_options_are_rejected(tmp_path: Path) -> None:
    """`--skip-non-binary` / `--skip-ingester` were removed: the non-binary stage now always runs,
    so a run's facts do not depend on which optional stages a past scan happened to skip. Passing
    either is an unknown-option error, not a silent no-op.

    MUTATION: restore either option on the analyze command -> RED."""
    for opt in ("--skip-non-binary", "--skip-ingester=shell_script"):
        out = CliRunner().invoke(analyze, [str(tmp_path), opt])
        assert out.exit_code != 0
        assert "No such option" in out.output, (opt, out.output)


# ── what an extraction left behind is said where the person running it sees it ──────────────


def test_analyze_names_no_functions_kept_earlier_and_an_unfinished_reanalyze(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """S9 / S6 / S4. The three lines the analyze command adds after the incomplete warning: the
    binaries with code and no function recovered (and what would change that), the binaries that
    kept an earlier pass's extraction, and an interrupted --reanalyze this run did not continue.

    MUTATION (verified RED): drop ``report_extraction_state`` from the command -> none printed."""
    _patch_pipeline(
        monkeypatch,
        tmp_path / "analysis.db",
        [],
        incomplete_binaries=["svc_b", "svc_c"],
        no_functions_binaries=["svc_b"],
        ghidra_ok=4,
        ghidra_no_functions=1,
        kept_earlier_binaries=[
            {"binary": "svc_c", "reason": "incomplete", "earlier_pass": "0ldpass0ldpass00"}
        ],
        reanalyze_pending=3,
    )
    fs_root = tmp_path / "fs"
    fs_root.mkdir()
    result = CliRunner().invoke(analyze, [str(fs_root), "--workspace", "ws"])
    assert result.exit_code == 0, result.output
    out = result.output
    assert "Ghidra OK: 4 (of which 1 no_functions)" in out
    assert (
        "1 binaries have executable code but Ghidra recovered no function from it — re-running "
        "with the same pass does not change this; after a Ghidra or architecture-detection "
        "change, --reanalyze <name> retries it: svc_b"
    ) in out
    assert (
        "⚠ 1 binaries kept their earlier extraction because this pass failed on them: "
        "svc_c (incomplete) — their candidates read extraction_current=false."
    ) in out
    assert (
        "⚠ an interrupted --reanalyze left 3 binaries not yet re-extracted; run the same command "
        "with --reanalyze to finish it."
    ) in out


def test_a_bare_reanalyze_run_does_not_point_at_itself(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The pending hint is for a run that did NOT continue the request; a bare --reanalyze that
    still leaves some (its own interrupt) says so through the abort message instead.

    MUTATION (verified RED): print the hint under a bare --reanalyze too."""
    _patch_pipeline(monkeypatch, tmp_path / "analysis.db", [], reanalyze_pending=3)
    fs_root = tmp_path / "fs"
    fs_root.mkdir()
    result = CliRunner().invoke(analyze, [str(fs_root), "--workspace", "ws", "--reanalyze"])
    assert result.exit_code == 0, result.output
    assert "interrupted --reanalyze" not in result.output


def test_an_interrupted_analyze_says_the_finished_binaries_are_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """S3. The abort message says what an interrupt keeps and how to continue.

    MUTATION (verified RED): print only "Aborted — all Ghidra processes terminated." again."""

    def _interrupted(*_: Any, **__: Any) -> AnalyzeResult:
        raise KeyboardInterrupt

    _patch_pipeline(monkeypatch, tmp_path / "analysis.db")
    monkeypatch.setattr("treasure_map.lib.analyze.pipeline.run_analyze", _interrupted)
    fs_root = tmp_path / "fs"
    fs_root.mkdir()
    result = CliRunner().invoke(analyze, [str(fs_root), "--workspace", "ws"])
    assert result.exit_code == 130
    assert (
        "Aborted — all Ghidra processes terminated. Finished binaries are kept; re-run the "
        "same command to continue."
    ) in result.output
