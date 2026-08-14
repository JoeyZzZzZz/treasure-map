# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Machine capability probe + the parallelism it derives, and init writing the derived value.

Hermetic: /proc files are synthesized in tmp and passed by path; os.cpu_count / lscpu are
monkeypatched where a fallback rung must be forced. The OOM invariant (derived pool x per-JVM never
exceeds the memory budget) is asserted across inputs, with a reverse check that a CPU-only
derivation would violate it — proving the memory arm is load-bearing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import treasure_map.lib.machine as machine
from treasure_map.lib.machine import (
    MEM_FRACTION,
    PER_JVM_MB,
    clamp_parallelism_to_memory,
    derive_parallelism,
    mem_total_mb,
    physical_cores,
)

# a 6-physical / 12-logical (2-way SMT) /proc/cpuinfo: physical id 0, core ids 0..5, each twice.
_CPUINFO_6C12T = "".join(
    f"processor\t: {p}\nphysical id\t: 0\ncore id\t\t: {p % 6}\n\n" for p in range(12)
)
# a cpuinfo with NO physical/core id lines (some ARM / container kernels) -> dedup yields 0.
_CPUINFO_NO_IDS = "".join(f"processor\t: {p}\nmodel name\t: x\n\n" for p in range(12))


def _write(tmp_path: Path, name: str, text: str) -> str:
    p = tmp_path / name
    p.write_text(text)
    return str(p)


# ── physical core probe + fallback chain ───────────────────────────────────────────────


def test_physical_cores_from_cpuinfo(tmp_path: Path) -> None:
    probe = physical_cores(_write(tmp_path, "cpuinfo", _CPUINFO_6C12T))
    assert probe.count == 6  # 6 distinct (physical id, core id) pairs, not the 12 logical
    assert probe.method == "cpuinfo"


def test_physical_cores_fallback_when_cpuinfo_has_no_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ★ cpuinfo without physical/core ids must NOT collapse to 1: fall through to cpu_count//2.
    monkeypatch.setattr(machine, "_cores_from_lscpu", lambda: 0)  # force past the lscpu rung
    monkeypatch.setattr(machine.os, "cpu_count", lambda: 12)
    probe = physical_cores(_write(tmp_path, "cpuinfo", _CPUINFO_NO_IDS))
    assert probe.count == 6  # 12 logical // 2 (assumed SMT), NOT 1
    assert probe.count != 1
    assert "cpu_count//2" in probe.method


def test_physical_cores_missing_file_falls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(machine, "_cores_from_lscpu", lambda: 0)
    monkeypatch.setattr(machine.os, "cpu_count", lambda: 8)
    probe = physical_cores(str(tmp_path / "does-not-exist"))
    assert probe.count == 4  # 8 // 2
    assert probe.count != 1


# ── memory probe ───────────────────────────────────────────────────────────────────────


def test_mem_total_mb(tmp_path: Path) -> None:
    path = _write(tmp_path, "meminfo", "MemTotal:       10183640 kB\nMemAvailable:  1347584 kB\n")
    assert mem_total_mb(path) == 10183640 // 1024  # kB -> MB


def test_mem_total_mb_unreadable_is_conservative(tmp_path: Path) -> None:
    assert mem_total_mb(str(tmp_path / "nope")) == 4096


# ── derive parallelism: min(cpu, mem) + the OOM invariant ───────────────────────────────


def test_derive_parallelism_takes_the_smaller_arm() -> None:
    # owner machine: 6 cores / 9945MB -> cpu=6, mem=9945*0.6//1024=5 -> 5.
    assert derive_parallelism(6, 9945) == 5
    # many cores, same memory -> memory caps it at 5 (not 12).
    assert derive_parallelism(12, 9945) == 5
    # low memory dominates -> 1.
    assert derive_parallelism(2, 2000) == 1
    # always at least 1.
    assert derive_parallelism(0, 0) == 1


@pytest.mark.parametrize(
    ("phys", "mem_total"),
    [(6, 9945), (12, 9945), (2, 2000), (32, 4000), (1, 512), (64, 65536)],
)
def test_derive_never_overcommits_memory(phys: int, mem_total: int) -> None:
    # ★ OOM invariant: the derived pool's memory demand never exceeds the budget.
    derived = derive_parallelism(phys, mem_total)
    assert derived * PER_JVM_MB <= int(mem_total * MEM_FRACTION) or derived == 1


def test_memory_arm_is_load_bearing() -> None:
    # ★ reverse of the invariant: a CPU-ONLY derivation (dropping the memory min) WOULD overcommit
    # on a many-core / low-RAM box — proving derive_parallelism's memory arm matters.
    phys, mem_total = 12, 2000
    assert derive_parallelism(phys, mem_total) == 1  # memory caps it
    cpu_only = max(1, phys)  # what dropping the mem_limit min would yield
    assert cpu_only * PER_JVM_MB > int(mem_total * MEM_FRACTION)  # would OOM


# ── runtime clamp (low-memory protection) ───────────────────────────────────────────────


def test_clamp_reduces_when_memory_tight() -> None:
    # owner machine snapshot: 1316MB available -> 5 JVMs would need ~5GB -> clamp to 1.
    eff, note = clamp_parallelism_to_memory(5, avail_mb=1316)
    assert eff == 1
    assert note is not None and "parallelism 5->1" in note


def test_clamp_noop_when_memory_ample() -> None:
    eff, note = clamp_parallelism_to_memory(5, avail_mb=8000)
    assert eff == 5 and note is None


def test_clamp_noop_when_avail_unreadable(tmp_path: Path) -> None:
    eff, note = clamp_parallelism_to_memory(5, meminfo_path=str(tmp_path / "nope"))
    assert eff == 5 and note is None  # best-effort: never blocks, never raises


# ── init writes the derived value into config.yaml ──────────────────────────────────────


def test_configure_parallelism_detects_then_keeps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from treasure_map.lib.machine import CoreProbe
    from treasure_map.lib.setup import initializer

    monkeypatch.setattr(machine, "physical_cores", lambda: CoreProbe(6, "cpuinfo"))
    monkeypatch.setattr(machine, "mem_total_mb", lambda: 9945)
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text("ghidra:\n  mode: local\n")
    msgs: list[str] = []

    # first run: no value present -> detect + write 5
    initializer._configure_parallelism(cfg_path, force=False, echo=msgs.append)
    assert initializer._configured_max_parallel(cfg_path) == 5
    assert any("max_parallel_jvms=5" in m for m in msgs)

    # re-run without force: keep the written value even if the machine "changes"
    monkeypatch.setattr(machine, "physical_cores", lambda: CoreProbe(2, "cpuinfo"))
    monkeypatch.setattr(machine, "mem_total_mb", lambda: 2000)
    initializer._configure_parallelism(cfg_path, force=False, echo=msgs.append)
    assert initializer._configured_max_parallel(cfg_path) == 5  # kept

    # --force: re-detect (now 1 for the smaller machine)
    initializer._configure_parallelism(cfg_path, force=True, echo=msgs.append)
    assert initializer._configured_max_parallel(cfg_path) == 1
