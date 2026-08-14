# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""diff full-run parallelism: the preflight/compute/persist split, parallel compute + serial write,
and the JVM-heap policy (scan keeps its per-binary ladder; diff holds a conservative fixed ceiling).

Hermetic: the external toolchain never runs. compute is stubbed to control success/failure and to
record which thread it ran on; persist is stubbed the same way so the "writes are serial on the main
thread" invariant is observable. preflight is stubbed with dummy .so files so the serial pre-phase
resolves without a real located binary / toolchain.
"""

from __future__ import annotations

import inspect
import threading
from pathlib import Path

import pytest

from treasure_map.lib.analyze.ghidra_runner import adaptive_heap_mb
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.writer import begin_run
from treasure_map.lib.diff import driver
from treasure_map.lib.diff.driver import DiffToolchainError, compute_diff
from treasure_map.lib.storage.connection import open_db


def _cfg():  # type: ignore[no-untyped-def]
    from treasure_map.lib.config.config import Config

    return Config()


def _seed(tmp_path: Path, a: dict[str, str], b: dict[str, str]) -> Path:
    """Two runs + one analysis.db each ({name -> sha256}); same tool/Ghidra -> no version skew."""
    da, db = tmp_path / "a.db", tmp_path / "b.db"
    for path, mapping in ((da, a), (db, b)):
        con = open_db(path)
        for i, (name, sha) in enumerate(mapping.items(), start=1):
            con.execute(
                "INSERT INTO binaries (id, name, path, sha256) VALUES (?, ?, ?, ?)",
                (i, name, name, sha),
            )
        con.commit()
        con.close()
    atlas_path = tmp_path / "atlas.db"
    con = open_atlas(atlas_path)
    begin_run(con, "run_a", analysis_db_path=str(da), tool_version="0.0.1", ghidra_version="11.4.3")
    begin_run(con, "run_b", analysis_db_path=str(db), tool_version="0.0.1", ghidra_version="11.4.3")
    con.close()
    return atlas_path


def _fake_preflight(tmp_path: Path):  # type: ignore[no-untyped-def]
    from treasure_map.lib.atlas.models import RunRow

    def _pf(atlas, run_a_id, run_b_id, binary_name, *, config, force):  # type: ignore[no-untyped-def]
        so_a = tmp_path / f"{binary_name}_a.so"
        so_b = tmp_path / f"{binary_name}_b.so"
        so_a.write_bytes(b"\x7fELF")
        so_b.write_bytes(b"\x7fELF")
        return driver.PreflightResult(
            run_a=RunRow(run_id=run_a_id),
            run_b=RunRow(run_id=run_b_id),
            binary_a=binary_name,
            binary_b=binary_name,
            so_a=so_a,
            so_b=so_b,
            version_skew=False,
            warnings=(),
        )

    return _pf


def _ok_persist(atlas, **kw):  # type: ignore[no-untyped-def]
    return driver.DiffSummary(
        diff_id=kw["diff_id"],
        binary=kw["binary_name"],
        matched_pairs=1,
        version_skew=kw["version_skew"],
        delta_layer_changed=1,
        delta_layer_unchanged=0,
        delta_undetermined=0,
        warnings=kw["warnings"],
    )


# ── JVM heap policy: scan keeps the per-binary ladder; diff holds a fixed ceiling ───────


def test_adaptive_heap_ladder() -> None:
    assert adaptive_heap_mb(500 * 1024) == (512, 64)  # < 1MB
    assert adaptive_heap_mb(5 * 1024 * 1024) == (768, 96)  # < 10MB
    assert adaptive_heap_mb(30 * 1024 * 1024) == (1536, 192)  # < 50MB
    assert adaptive_heap_mb(60 * 1024 * 1024) == (2048, 256)  # >= 50MB


def test_scan_still_uses_per_binary_adaptive_heap() -> None:
    # ★ scan's headroom is per-binary (a 500KB lib gets 512MB), NOT a machine-wide single heap.
    from treasure_map.lib.analyze.ghidra_runner import GhidraRunner

    src = inspect.getsource(GhidraRunner._run_once)
    assert "adaptive_heap_mb(" in src  # reverse: a machine single-heap rewrite drops this call
    assert (
        adaptive_heap_mb(500 * 1024)[0] == 512
    )  # the small-lib rung is still 512, not a big value


def test_diff_heap_stays_conservative_pending_measurement() -> None:
    # ★ diff's BinExport heap stays a fixed 4096 (NOT the ladder) until a peak-heap measurement on
    # the largest diffed binary confirms a smaller value is safe (spec: "never OOM mid-sweep").
    assert driver._DIFF_BINEXPORT_HEAP_MB == 4096
    src = inspect.getsource(driver._run_binexport)
    assert "_DIFF_BINEXPORT_HEAP_MB" in src  # the fixed ceiling, wired via the named marker
    assert "adaptive_heap_mb" not in src  # NOT ladder-ized yet (the pending downsize)


# ── the split: compute is zero-atlas, off the main thread ───────────────────────────────


def test_compute_diff_signature_has_no_atlas_or_run_id() -> None:
    # ★ MAJOR-1 defence: compute takes only Paths + config — no atlas connection, no run id — so it
    # is safe to hand to a worker thread (the atlas is check_same_thread and written serially).
    params = list(inspect.signature(compute_diff).parameters)
    assert params == ["so_a", "so_b", "td", "config"]
    assert not any("atlas" in p or "run" in p for p in params)


def test_compute_diff_runs_in_worker_without_touching_atlas(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # compute runs off the main thread and never touches the (check_same_thread) atlas -> no
    # ProgrammingError. The toolchain steps are stubbed; only the zero-atlas contract is exercised.
    from concurrent.futures import ThreadPoolExecutor

    monkeypatch.setattr(
        driver, "_run_binexport", lambda so, cfg, out, side, t: out / f"{side}.BinExport"
    )
    monkeypatch.setattr(driver, "_run_bindiff", lambda ea, eb, out, t: out / "x.BinDiff")
    seen: dict[str, object] = {}

    def _job() -> driver.DiffArtifacts:
        seen["thread"] = threading.current_thread()
        return compute_diff(tmp_path / "a.so", tmp_path / "b.so", tmp_path, _cfg())

    with ThreadPoolExecutor(max_workers=1) as pool:
        artifacts = pool.submit(_job).result()
    assert isinstance(artifacts, driver.DiffArtifacts)
    assert seen["thread"] is not threading.main_thread()  # ran off the main thread


# ── parallel compute + serial persist ───────────────────────────────────────────────────


def test_full_diff_persists_serially_on_main_thread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ★ every atlas write happens on the main thread (no concurrent connections). compute may run
    # on workers; persist must all land on the main thread.
    atlas_path = _seed(tmp_path, {"a": "1", "b": "2", "c": "3"}, {"a": "1x", "b": "2x", "c": "3x"})
    monkeypatch.setattr(driver, "_check_toolchain", lambda config: None)
    monkeypatch.setattr(driver, "preflight", _fake_preflight(tmp_path))
    monkeypatch.setattr(
        driver, "compute_diff", lambda so_a, so_b, td, config: driver.DiffArtifacts(so_a, so_b, td)
    )
    persist_threads: list[object] = []

    def _persist(atlas, **kw):  # type: ignore[no-untyped-def]
        persist_threads.append(threading.current_thread())
        return _ok_persist(atlas, **kw)

    monkeypatch.setattr(driver, "_persist_success", _persist)
    con = open_atlas(atlas_path)
    fsum = driver.run_full_diff(con, "run_a", "run_b", config=_cfg())
    con.close()
    assert len(fsum.outcomes) == 3
    assert persist_threads and all(t is threading.main_thread() for t in persist_threads)


def test_full_diff_preflight_failure_skips_parallel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ★ a binary whose preflight fails never enters the parallel compute — it is surfaced as a
    # failure outcome from the serial pre-phase.
    atlas_path = _seed(tmp_path, {"good": "1", "bad": "2"}, {"good": "1x", "bad": "2x"})
    monkeypatch.setattr(driver, "_check_toolchain", lambda config: None)
    real_pf = _fake_preflight(tmp_path)

    def _pf(atlas, run_a_id, run_b_id, binary_name, *, config, force):  # type: ignore[no-untyped-def]
        if binary_name == "bad":
            from treasure_map.lib.errors import ConfigError

            raise ConfigError("the .so for 'bad' cannot be located")
        return real_pf(atlas, run_a_id, run_b_id, binary_name, config=config, force=force)

    computed: list[str] = []

    def _compute(so_a, so_b, td, config):  # type: ignore[no-untyped-def]
        computed.append(so_a.name)
        return driver.DiffArtifacts(so_a, so_b, td)

    monkeypatch.setattr(driver, "preflight", _pf)
    monkeypatch.setattr(driver, "compute_diff", _compute)
    monkeypatch.setattr(driver, "_persist_success", _ok_persist)
    con = open_atlas(atlas_path)
    fsum = driver.run_full_diff(con, "run_a", "run_b", config=_cfg())
    con.close()
    assert not any("bad" in name for name in computed)  # 'bad' never reached compute
    bad = next(o for o in fsum.outcomes if o.binary == "bad")
    assert bad.error is not None and "cannot be located" in bad.error


def test_full_diff_compute_exc_classified_in_persist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ★ the compute failure's exception is handed to persist, which records the honest blind-spot
    # row with the right reason bucket (a flow-graph failure -> bindiff_flowgraph).
    atlas_path = _seed(tmp_path, {"lib": "1"}, {"lib": "2"})
    monkeypatch.setattr(driver, "_check_toolchain", lambda config: None)
    monkeypatch.setattr(driver, "preflight", _fake_preflight(tmp_path))

    def _compute(so_a, so_b, td, config):  # type: ignore[no-untyped-def]
        raise DiffToolchainError("BinDiff failed (rc=1) Could not find basic block 000E1920")

    monkeypatch.setattr(driver, "compute_diff", _compute)
    con = open_atlas(atlas_path)
    fsum = driver.run_full_diff(con, "run_a", "run_b", config=_cfg())
    row = con.execute(
        "SELECT diff_ok, diff_status, diff_status_reason FROM diff_meta WHERE diff_id=?",
        ("run_a::run_b::lib",),
    ).fetchone()
    con.close()
    assert (row[0], row[1], row[2]) == (0, "failed", "bindiff_flowgraph")
    lib = next(o for o in fsum.outcomes if o.binary == "lib")
    assert lib.error is not None and lib.reason == "bindiff_flowgraph"


def test_full_diff_one_failure_does_not_corrupt_others(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ★ under parallel compute, one binary's failure stays its own atomic row and never pollutes
    # another's — persist is serial + each binary is an independent transaction.
    atlas_path = _seed(tmp_path, {"ok": "1", "boom": "2"}, {"ok": "1x", "boom": "2x"})
    monkeypatch.setattr(driver, "_check_toolchain", lambda config: None)
    monkeypatch.setattr(driver, "preflight", _fake_preflight(tmp_path))

    def _compute(so_a, so_b, td, config):  # type: ignore[no-untyped-def]
        if "boom" in so_a.name:
            raise DiffToolchainError("BinExport subprocess failed (rc=1)")
        return driver.DiffArtifacts(so_a, so_b, td)

    monkeypatch.setattr(driver, "compute_diff", _compute)
    monkeypatch.setattr(driver, "_persist_success", _ok_persist)
    con = open_atlas(atlas_path)
    driver.run_full_diff(con, "run_a", "run_b", config=_cfg())
    boom = con.execute(
        "SELECT diff_ok, diff_status, diff_status_reason FROM diff_meta WHERE diff_id=?",
        ("run_a::run_b::boom",),
    ).fetchone()
    # the failed binary has exactly its own honest row; the ok binary's persist was stubbed (no
    # row), so the failure did not spill a row onto it either.
    ok_rows = con.execute(
        "SELECT COUNT(*) FROM diff_meta WHERE diff_id=?", ("run_a::run_b::ok",)
    ).fetchone()[0]
    con.close()
    assert (boom[0], boom[1], boom[2]) == (0, "failed", "binexport_ghidra_crash")
    assert ok_rows == 0  # no cross-contamination onto the other binary


# ── Ctrl-C: cancel the queued sweep, keep completed, mark cancelled ─────────────────────


class _FakeFuture:
    def __init__(self, fn, args) -> None:  # type: ignore[no-untyped-def]
        self.fn, self.args, self.ran, self.cancelled = fn, args, False, False

    def result(self):  # type: ignore[no-untyped-def]
        self.ran = True
        return self.fn(*self.args)


class _FakePool:
    """A ThreadPoolExecutor stand-in that runs submit() lazily (on result()) so the test controls
    exactly which futures 'complete' before the interrupt, and records the shutdown kwargs."""

    def __init__(self, max_workers: int) -> None:
        self.subs: list[_FakeFuture] = []
        self.shutdown_kwargs: dict[str, object] | None = None

    def submit(self, fn, *args):  # type: ignore[no-untyped-def]
        f = _FakeFuture(fn, args)
        self.subs.append(f)
        return f

    def shutdown(self, wait: bool = True, cancel_futures: bool = False) -> None:
        self.shutdown_kwargs = {"wait": wait, "cancel_futures": cancel_futures}
        if cancel_futures:  # mirror the real pool: drop the not-yet-run (queued) futures
            for f in self.subs:
                if not f.ran:
                    f.cancelled = True


def test_ctrl_c_cancels_queue_keeps_completed_marks_cancelled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ★ Ctrl-C mid-sweep must STOP scheduling (cancel the queued computes via shutdown
    # cancel_futures=True), keep the already-completed binaries, and return cancelled=True — it must
    # NOT drain the whole queue. Reverse: dropping cancel_futures=True leaves the queue to run.
    atlas_path = _seed(tmp_path, {"a": "1", "b": "2", "c": "3"}, {"a": "1x", "b": "2x", "c": "3x"})
    monkeypatch.setattr(driver, "_check_toolchain", lambda config: None)
    monkeypatch.setattr(driver, "preflight", _fake_preflight(tmp_path))
    monkeypatch.setattr(
        driver, "compute_diff", lambda so_a, so_b, td, config: driver.DiffArtifacts(so_a, so_b, td)
    )
    monkeypatch.setattr(driver, "_persist_success", _ok_persist)
    pools: list[_FakePool] = []

    def _mk_pool(max_workers):  # type: ignore[no-untyped-def]
        p = _FakePool(max_workers)
        pools.append(p)
        return p

    def _one_then_interrupt(fut_map):  # type: ignore[no-untyped-def]
        # yield exactly ONE future (the loop runs + persists it), then simulate Ctrl-C.
        yield next(iter(fut_map))
        raise KeyboardInterrupt

    monkeypatch.setattr(driver, "ThreadPoolExecutor", _mk_pool)
    monkeypatch.setattr(driver, "as_completed", _one_then_interrupt)

    con = open_atlas(atlas_path)
    fsum = driver.run_full_diff(con, "run_a", "run_b", config=_cfg())
    con.close()
    assert fsum.cancelled is True  # graceful cancel, not a crash
    assert len(fsum.outcomes) == 1  # the one completed binary is kept
    pool = pools[0]
    assert pool.shutdown_kwargs == {"wait": True, "cancel_futures": True}  # ★ the fix
    ran = [f for f in pool.subs if f.ran]
    cancelled = [f for f in pool.subs if f.cancelled]
    assert len(ran) == 1 and len(cancelled) == 2  # 1 completed, 2 queued -> cancelled (not drained)


# ── diff-side memory budget is decoupled from the shared scan/init constant ─────────────


def test_effective_diff_workers_uses_diff_per_jvm(monkeypatch: pytest.MonkeyPatch) -> None:
    # ★ diff passes its OWN heavier per-JVM budget to the clamp, never the shared PER_JVM_MB.
    captured: dict[str, object] = {}

    def _fake_clamp(configured, *, per_jvm_mb=None, **kw):  # type: ignore[no-untyped-def]
        captured["per_jvm_mb"] = per_jvm_mb
        return configured, None

    monkeypatch.setattr(driver, "clamp_parallelism_to_memory", _fake_clamp)
    rd = driver._ResolvedDiff(
        binary="x",
        binary_short="x",
        so_a=Path("/x"),
        so_b=Path("/x"),
        version_skew=False,
        warnings=(),
        diff_id="d",
        size_bytes=1000,
        prior_failed=False,
    )
    driver._effective_diff_workers(4, [rd])
    assert captured["per_jvm_mb"] == driver._DIFF_PER_JVM_MB == 1600


def test_shared_per_jvm_stays_1024_so_scan_is_not_shrunk() -> None:
    # ★ reverse of raising the shared constant: machine.PER_JVM_MB stays 1024, so scan/init pools
    # are NOT dragged down by diff's heavier BinExport budget (that would slow large scans).
    import treasure_map.lib.machine as machine

    assert machine.PER_JVM_MB == 1024
