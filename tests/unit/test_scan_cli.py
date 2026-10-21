# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the `tmap scan` orchestration command.

scan is a thin CLI spine: analyze -> hunt -> triage. These tests monkeypatch the three
reused entry points to assert ordering / argument wiring / short-circuit, and use the REAL
triage + shared renderer against a seeded atlas to prove the final segment is byte-identical
to `tmap triage` (single renderer, no drift).
"""

from __future__ import annotations

import json
from dataclasses import fields as _dataclass_fields
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from click.testing import CliRunner

from treasure_map.cli.hunt_cli import scan
from treasure_map.cli.hunt_cli import triage as triage_cmd
from treasure_map.lib.analyze.pipeline import AnalyzeResult
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import InstanceRow
from treasure_map.lib.atlas.writer import add_instance, upsert_pattern
from treasure_map.lib.config.config import Config
from treasure_map.lib.errors import GhidraNotFoundError

_FID = [0]


class _DummyWorkspace:
    def __init__(self, path: Path, **_: Any) -> None:
        self.path = path
        self.db_path = path / "analysis.db"

    def __enter__(self) -> _DummyWorkspace:
        return self

    def __exit__(self, *_: object) -> None:
        return None


def _fake_analyze_result(db_path: Path) -> AnalyzeResult:
    """A stand-in built FROM the real dataclass, not typed out by hand.

    A hand-listed namespace goes stale the moment the command reads one more field, and it fails as
    an AttributeError buried inside a CliRunner result rather than as anything readable. Deriving
    the counters from ``AnalyzeResult`` means a new field cannot make this stub incomplete."""
    non_counter = {"db_path", "elapsed", "incomplete_binaries", "timeout_skipped"}
    counters = {f.name: 0 for f in _dataclass_fields(AnalyzeResult) if f.name not in non_counter}
    counters.update(binary_count=2, functions_ingested=9)
    return AnalyzeResult(
        db_path=db_path,
        elapsed=0.1,
        incomplete_binaries=[],
        timeout_skipped=[],
        **counters,
    )


def _hunt_stats(written: int = 0) -> SimpleNamespace:
    return SimpleNamespace(
        instances_written=written,
        by_status={"confirmed": 0, "unknown": written},
        data_gap_skipped=0,
        # Mirrors the real stats field-for-field ON PURPOSE (no getattr fallback, no **kwargs): a
        # field added to Analyzer2Stats and not surfaced here shows up as a failure rather than as
        # a summary line nobody notices is missing.
        callee_parse_failed=0,
        nvram_flows_written=0,
        nvram_wrapper_edges=0,
        nvram_defaults_written=0,
        web_form_fields_written=0,
        fmt_wrapper_unknown_source_demoted=0,
        # A stub of a hunt that RAN: the CLI branches on this to decide whether to print candidate
        # counts or the skip line, so leaving it off would silently exercise neither branch.
        skipped=False,
        hunt_currency="hunt ran",
    )


def _base_patches(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub config + Workspace so scan runs hermetically (no real workspace/Ghidra)."""
    monkeypatch.setattr(
        "treasure_map.lib.config.config.load_config", lambda _cfg=None: Config(llm=None)
    )
    monkeypatch.setattr("treasure_map.lib.workspace.workspace.Workspace", _DummyWorkspace)


def _seed_atlas(tmp_path: Path, run_id: str) -> Path:
    conn = open_atlas(tmp_path / "atlas.db")
    p = upsert_pattern(
        conn,
        source_class="external_input",
        sink_class="cmd",
        call_sequence_shape="source->...->sink",
        structural_fingerprint="fp",
        fingerprint_algo_version="callseq-v1",
    )

    def _inst(status: str, fn: str, origin: str = "custom", blocking: str | None = None) -> None:
        _FID[0] += 1
        prov = "L1" if status in {"confirmed", "blocked"} else "L0"
        add_instance(
            conn,
            InstanceRow(
                pattern_id=p,
                pseudocode_hash=f"h{_FID[0]}",
                source_anchor=fn,
                sink_anchor="system",
                source_run_id=run_id,
                reachability_status=status,
                blocking_mechanism=blocking,
                provenance_level=prov,
                evidence_ref=f"{run_id}#fn{_FID[0]}",
                scope_origin="intra",
                origin=origin,
            ),
        )

    _inst("unknown", "tv_fn")
    _inst("confirmed", "rc_fn")
    conn.close()
    return tmp_path / "atlas.db"


def _mkfs(tmp_path: Path) -> Path:
    fs_root = tmp_path / "fs"
    fs_root.mkdir()
    return fs_root


# ── 1. three steps, in order; run_id default = workspace name ────────────────────────


def test_scan_runs_three_steps_in_order(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _base_patches(monkeypatch)
    calls: list[str] = []
    seen: dict[str, Any] = {}

    def _fake_analyze(*_: Any, **__: Any) -> SimpleNamespace:
        calls.append("analyze")
        return _fake_analyze_result(tmp_path / "analysis.db")

    def _fake_hunt(
        db: Any,
        atlas: Any,
        *,
        source_run_id: str,
        firmware_path: str | None = None,
        # Mirrors the real run_analyzer2 signature. A stub that silently swallowed **kwargs
        # would keep passing after the real function's contract changed underneath it.
        rehunt: bool = False,
    ) -> Any:
        calls.append("hunt")
        seen["run_id"] = source_run_id
        seen["firmware_path"] = firmware_path
        return _hunt_stats()

    def _fake_triage(conn: Any, *, run_id: str | None = None) -> list[Any]:
        calls.append("triage")
        seen["triage_run_id"] = run_id
        return []

    monkeypatch.setattr("treasure_map.lib.analyze.pipeline.run_analyze", _fake_analyze)
    monkeypatch.setattr("treasure_map.lib.hunt.run_analyzer2", _fake_hunt)
    monkeypatch.setattr("treasure_map.lib.query.triage", _fake_triage)

    result = CliRunner().invoke(
        scan,
        [
            str(_mkfs(tmp_path)),
            "-w",
            "router_v1",  # a NAME (managed under the base) — the only workspace form now
            "--atlas",
            str(tmp_path / "atlas.db"),
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls == ["analyze", "hunt", "triage"]
    assert seen["run_id"] == "router_v1"  # default run-id = workspace name
    assert seen["triage_run_id"] == "router_v1"
    assert seen["firmware_path"] is not None  # scan wires the firmware root into the run lineage


def test_scan_stores_absolute_firmware_path_from_relative_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ★ Fix C: firmware_path (and binaries.path — same fs_root) must be recorded ABSOLUTE so a later
    # `tmap diff` locates the binaries from ANY cwd. Invoke scan with a RELATIVE fs_root (cwd set to
    # its parent); both the firmware_path handed to hunt AND the fs_root handed to analyze (which
    # writes binaries.path) must be absolute. Reverting the `fs_root = fs_root.resolve()` line reds
    # this.
    _base_patches(monkeypatch)
    _mkfs(tmp_path)  # creates tmp_path/fs
    monkeypatch.chdir(tmp_path)
    seen: dict[str, Any] = {}

    def _fake_analyze(fs_root: Any, *_: Any, **__: Any) -> SimpleNamespace:
        seen["analyze_fs_root"] = fs_root
        return _fake_analyze_result(tmp_path / "analysis.db")

    def _fake_hunt(
        db: Any,
        atlas: Any,
        *,
        source_run_id: str,
        firmware_path: str | None = None,
        # Mirrors the real run_analyzer2 signature. A stub that silently swallowed **kwargs
        # would keep passing after the real function's contract changed underneath it.
        rehunt: bool = False,
    ) -> Any:
        seen["firmware_path"] = firmware_path
        return _hunt_stats()

    monkeypatch.setattr("treasure_map.lib.analyze.pipeline.run_analyze", _fake_analyze)
    monkeypatch.setattr("treasure_map.lib.hunt.run_analyzer2", _fake_hunt)
    monkeypatch.setattr("treasure_map.lib.query.triage", lambda conn, *, run_id=None: [])

    result = CliRunner().invoke(
        scan,
        ["fs", "-w", "router_v1", "--atlas", str(tmp_path / "atlas.db")],  # RELATIVE fs_root
    )

    assert result.exit_code == 0, result.output
    assert Path(
        seen["firmware_path"]
    ).is_absolute()  # recorded absolute -> diff locates from any cwd
    assert Path(seen["analyze_fs_root"]).is_absolute()  # traversal (binaries.path) also absolute


def test_scan_explicit_run_id_overrides_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _base_patches(monkeypatch)
    seen: dict[str, Any] = {}

    def _fake_analyze(*_: Any, **__: Any) -> SimpleNamespace:
        return _fake_analyze_result(tmp_path / "analysis.db")

    def _fake_hunt(
        db: Any,
        atlas: Any,
        *,
        source_run_id: str,
        firmware_path: str | None = None,
        # Mirrors the real run_analyzer2 signature. A stub that silently swallowed **kwargs
        # would keep passing after the real function's contract changed underneath it.
        rehunt: bool = False,
    ) -> Any:
        seen["run_id"] = source_run_id
        return _hunt_stats()

    monkeypatch.setattr("treasure_map.lib.analyze.pipeline.run_analyze", _fake_analyze)
    monkeypatch.setattr("treasure_map.lib.hunt.run_analyzer2", _fake_hunt)
    monkeypatch.setattr("treasure_map.lib.query.triage", lambda conn, *, run_id=None: [])

    result = CliRunner().invoke(
        scan,
        [
            str(_mkfs(tmp_path)),
            "-w",
            "router_v1",
            "--run-id",
            "device_x",
            "--atlas",
            str(tmp_path / "atlas.db"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert seen["run_id"] == "device_x"  # explicit --run-id wins over the workspace name


# ── 2. analyze failure short-circuits hunt + triage ─────────────────────────────────


def test_scan_analyze_failure_short_circuits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _base_patches(monkeypatch)
    downstream: list[str] = []

    def _boom(*_: Any, **__: Any) -> SimpleNamespace:
        raise GhidraNotFoundError("ghidra missing")

    monkeypatch.setattr("treasure_map.lib.analyze.pipeline.run_analyze", _boom)
    monkeypatch.setattr(
        "treasure_map.lib.hunt.run_analyzer2",
        lambda *a, **k: downstream.append("hunt"),
    )
    monkeypatch.setattr(
        "treasure_map.lib.query.triage",
        lambda *a, **k: downstream.append("triage"),
    )

    result = CliRunner().invoke(
        scan, [str(_mkfs(tmp_path)), "-w", "ws", "--atlas", str(tmp_path / "a.db")]
    )
    assert result.exit_code != 0
    assert downstream == []  # neither hunt nor triage ran


# ── 3. final segment is byte-identical to `tmap triage` (shared renderer, no drift) ──


def test_scan_triage_segment_matches_triage_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _base_patches(monkeypatch)
    atlas = _seed_atlas(tmp_path, "ws_x")

    def _fake_analyze(*_: Any, **__: Any) -> SimpleNamespace:
        return _fake_analyze_result(tmp_path / "analysis.db")

    monkeypatch.setattr("treasure_map.lib.analyze.pipeline.run_analyze", _fake_analyze)
    monkeypatch.setattr("treasure_map.lib.hunt.run_analyzer2", lambda *a, **k: _hunt_stats(2))
    # triage + renderer are REAL here.

    scan_out = CliRunner().invoke(scan, [str(_mkfs(tmp_path)), "-w", "ws_x", "--atlas", str(atlas)])
    triage_out = CliRunner().invoke(triage_cmd, ["ws_x", "--atlas", str(atlas)])
    assert scan_out.exit_code == 0, scan_out.output
    assert triage_out.exit_code == 0, triage_out.output

    # scan's triage block (from the "triage: ..." header onward) must equal the triage command's
    # rendered list. Both commands prepend the same intended-use notice; the shared renderer's
    # output is what must not drift, so compare from the "triage: ..." header in both.
    block = scan_out.output[scan_out.output.index("triage: ") :]
    triage_block = triage_out.output[triage_out.output.index("triage: ") :]
    assert block == triage_block


# ── 4. triage presentation options pass through ─────────────────────────────────────


def test_scan_passes_through_triage_options(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _base_patches(monkeypatch)
    atlas = _seed_atlas(tmp_path, "ws_x")

    def _fake_analyze(*_: Any, **__: Any) -> SimpleNamespace:
        return _fake_analyze_result(tmp_path / "analysis.db")

    monkeypatch.setattr("treasure_map.lib.analyze.pipeline.run_analyze", _fake_analyze)
    monkeypatch.setattr("treasure_map.lib.hunt.run_analyzer2", lambda *a, **k: _hunt_stats(3))

    base = [str(_mkfs(tmp_path)), "-w", "ws_x", "--atlas", str(atlas)]
    runner = CliRunner()

    default = runner.invoke(scan, base)
    assert default.exit_code == 0, default.output
    assert "tv_fn" in default.output and "rc_fn" in default.output

    reach = runner.invoke(scan, [*base, "--status", "reachable"])
    assert reach.exit_code == 0, reach.output
    assert "rc_fn" in reach.output and "tv_fn" not in reach.output  # --status reached the renderer

    as_json = runner.invoke(scan, [*base, "--json"])
    assert as_json.exit_code == 0, as_json.output
    # stdout is the JSON and nothing else (progress goes to stderr), so it parses whole.
    # MUTATION: drop the stderr redirect of the two stages -> RED (progress lines precede the JSON).
    try:
        parsed = json.loads(as_json.stdout)
    except json.JSONDecodeError:
        parsed = None
    assert isinstance(parsed, list), f"stdout is not one JSON document:\n{as_json.stdout[:300]}"
    assert parsed and "evidence_ref" in parsed[0]
    assert "[1/" in as_json.stderr  # the progress is still shown, on stderr


# ── 5. empty candidate set is not an error ──────────────────────────────────────────


def test_scan_empty_candidates_is_ok(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _base_patches(monkeypatch)
    # an atlas with no instances for this run id -> triage returns nothing
    open_atlas(tmp_path / "atlas.db").close()

    def _fake_analyze(*_: Any, **__: Any) -> SimpleNamespace:
        return _fake_analyze_result(tmp_path / "analysis.db")

    monkeypatch.setattr("treasure_map.lib.analyze.pipeline.run_analyze", _fake_analyze)
    monkeypatch.setattr("treasure_map.lib.hunt.run_analyzer2", lambda *a, **k: _hunt_stats(0))

    result = CliRunner().invoke(
        scan,
        [
            str(_mkfs(tmp_path)),
            "-w",
            "ws_empty",
            "--atlas",
            str(tmp_path / "atlas.db"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "0 candidates" in result.output  # honest empty segment, no crash


def test_scan_says_out_loud_when_the_hunt_was_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ A skipped hunt writes nothing, so every count it reports is zero.

    Printing those zeros through the normal line would read "0 candidates written (confirmed=0,
    unknown=0)" — indistinguishable from a hunt that ran and found nothing on this
    firmware. The stored candidates are in fact untouched and still there, which is the opposite
    conclusion. So the skip gets its own line, and it names the way to override it.

    MUTATION: delete the ``if h.skipped`` branch in scan and print the counts unconditionally ->
    RED.
    """
    _base_patches(monkeypatch)

    def _fake_analyze(*_: Any, **__: Any) -> SimpleNamespace:
        return _fake_analyze_result(tmp_path / "analysis.db")

    stats = _hunt_stats()
    stats.skipped = True
    stats.hunt_currency = "already hunted by this tmap (abc123abc123) from this extraction"

    def _fake_hunt(*_: Any, **__: Any) -> Any:
        return stats

    monkeypatch.setattr("treasure_map.lib.analyze.pipeline.run_analyze", _fake_analyze)
    monkeypatch.setattr("treasure_map.lib.hunt.run_analyzer2", _fake_hunt)
    monkeypatch.setattr("treasure_map.lib.query.triage", lambda *_a, **_k: [])

    result = CliRunner().invoke(
        scan, [str(_mkfs(tmp_path)), "-w", "router_v1", "--atlas", str(tmp_path / "atlas.db")]
    )
    assert result.exit_code == 0, result.output
    assert "hunt SKIPPED" in result.output
    assert "already hunted by this tmap" in result.output
    assert "stored candidates kept as they are" in result.output
    assert "--rehunt" in result.output
    assert "candidates written" not in result.output


# ── a skipped timeout is reported by the one-shot path too ───────────────────────────


def test_scan_names_the_binaries_it_did_not_re_run_and_forwards_force_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The one-shot path carries both halves: the escape hatch down, and the skip back up.

    ``scan`` is the command most people actually run, and it is the one where a shorter wall clock
    is most likely to be read as "there was less here". The same naming the standalone analyze does
    has to survive the wrapper, and so does the flag that undoes the skip — a flag accepted at the
    top and dropped on the way down is worse than no flag.

    MUTATION (must go RED): drop the report call from scan, or stop passing force_retry through."""
    _base_patches(monkeypatch)
    seen: dict[str, Any] = {}

    def _fake_analyze(*_: Any, force_retry: bool = False, **__: Any) -> AnalyzeResult:
        seen["force_retry"] = force_retry
        res = _fake_analyze_result(tmp_path / "analysis.db")
        res.timeout_skipped.append(
            {"binary": "big_daemon", "size_bytes": 14789215, "budget_seconds": 846}
        )
        return res

    def _fake_hunt(db: Any, atlas: Any, **kwargs: Any) -> Any:
        return _hunt_stats()

    monkeypatch.setattr("treasure_map.lib.analyze.pipeline.run_analyze", _fake_analyze)
    monkeypatch.setattr("treasure_map.lib.hunt.run_analyzer2", _fake_hunt)
    monkeypatch.setattr("treasure_map.lib.query.triage", lambda conn, **_: [])

    result = CliRunner().invoke(
        scan,
        [
            str(_mkfs(tmp_path)),
            "-w",
            "router_v1",
            "--atlas",
            str(tmp_path / "atlas.db"),
            "--force-retry",
        ],
    )

    assert result.exit_code == 0, result.output
    assert seen["force_retry"] is True
    assert "big_daemon" in result.output
    assert "846s budget" in result.output
    assert "--force-retry" in result.output


def test_an_interrupted_hunt_exits_like_any_other_interrupt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ctrl-C during the hunt stage exits 130, the same as during the decompile stage.

    MUTATION: drop the KeyboardInterrupt branch around the hunt -> RED (click turns it into 1)."""
    _base_patches(monkeypatch)

    def _fake_analyze(*_: Any, **__: Any) -> SimpleNamespace:
        return _fake_analyze_result(tmp_path / "analysis.db")

    def _interrupted_hunt(*_: Any, **__: Any) -> Any:
        raise KeyboardInterrupt

    monkeypatch.setattr("treasure_map.lib.analyze.pipeline.run_analyze", _fake_analyze)
    monkeypatch.setattr("treasure_map.lib.hunt.run_analyzer2", _interrupted_hunt)
    result = CliRunner().invoke(
        scan, [str(_mkfs(tmp_path)), "-w", "router_v1", "--atlas", str(tmp_path / "atlas.db")]
    )
    assert result.exit_code == 130, result.output
    assert "rolled back" in result.output


def _try_workspace(path: Path) -> str:
    """Whether another scan of ``path`` could take the workspace now."""
    from treasure_map.lib.errors import WorkspaceError
    from treasure_map.lib.workspace.workspace import Workspace

    try:
        with Workspace(path):
            return "acquired"
    except WorkspaceError:
        return "refused"


def test_the_workspace_stays_locked_through_the_hunt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The hunt reads analysis.db, so a second scan of the same workspace must stay out until the
    hunt is done: re-extracting the database mid-hunt hands the hunt part of each extraction. The
    lock is the real one here (no stand-in Workspace), probed from inside each stage.

    MUTATION: release the lock when analyze returns (the hunt outside it, as before) -> RED: the
    probe inside the hunt acquires the workspace. Leaving the stack unclosed stays GREEN here: the
    collector closes the lock file when the command returns, so the last assertion holds anyway;
    that ``Workspace.close()`` itself releases the lock is pinned in test_workspace.
    """
    monkeypatch.setattr(
        "treasure_map.lib.config.config.load_config",
        lambda _cfg=None: Config(llm=None, workspace_dir=tmp_path / "workspaces"),
    )
    seen: dict[str, str] = {}

    def _fake_analyze(_fs_root: Path, ws: Any, *_: Any, **__: Any) -> AnalyzeResult:
        seen["analyze"] = _try_workspace(ws.path)
        return _fake_analyze_result(ws.db_path)

    def _fake_hunt(
        db: Any,
        atlas: Any,
        *,
        source_run_id: str,
        firmware_path: str | None = None,
        rehunt: bool = False,
    ) -> Any:
        seen["hunt"] = _try_workspace(Path(db).parent)
        return _hunt_stats()

    monkeypatch.setattr("treasure_map.lib.analyze.pipeline.run_analyze", _fake_analyze)
    monkeypatch.setattr("treasure_map.lib.hunt.run_analyzer2", _fake_hunt)
    result = CliRunner().invoke(
        scan,
        [
            str(_mkfs(tmp_path)),
            "-w",
            "router_v1",
            "--atlas",
            str(tmp_path / "atlas.db"),
            "--top",
            "0",
        ],
    )
    assert result.exit_code == 0, result.output
    assert seen == {"analyze": "refused", "hunt": "refused"}
    assert _try_workspace(tmp_path / "workspaces" / "router_v1") == "acquired"


def test_the_removed_skip_options_are_rejected(tmp_path: Path) -> None:
    """`tmap scan` no longer accepts `--skip-non-binary` / `--skip-ingester` (the non-binary stage
    always runs now). Passing either is an unknown-option error.

    MUTATION: restore either option on the scan command -> RED."""
    for opt in ("--skip-non-binary", "--skip-ingester=shell_script"):
        out = CliRunner().invoke(scan, [str(tmp_path), opt])
        assert out.exit_code != 0
        assert "No such option" in out.output, (opt, out.output)
