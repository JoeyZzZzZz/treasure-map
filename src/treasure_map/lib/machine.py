# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Machine capability probe — physical cores + memory, and the parallelism they imply.

Zero third-party dependencies (Linux ``/proc`` + ``lscpu`` + ``os.cpu_count`` only). Used by
``tmap init`` to derive ``max_parallel_jvms`` once at setup, and by the scan/diff parallel pools to
clamp that stable value down at runtime if the machine is momentarily short on memory.

The two axes come from owner real-machine measurement, not guesses:
  * CPU: the effective parallelism knee is the PHYSICAL core count, not the logical count. Ghidra
    analysis is CPU-bound, so two hyperthreads on one physical core contend for the same execute
    units — pushing past physical cores makes the total SLOWER (measured: 6 cores was the knee, 8
    threads regressed).
  * Memory: derived from MemTotal × a conservative fraction, NOT MemAvailable. MemAvailable is a
    point-in-time reading — probing it while idle at init then running while busy would overcommit
    and OOM — so the stable derivation uses MemTotal, and a separate runtime clamp
    (clamp_parallelism_to_memory) reads MemAvailable just before a pool starts to back off if the
    machine is actually tight right now.
"""

from __future__ import annotations

import logging
import os
import subprocess
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# A single JVM's measured resident footprint under diff/scan (owner: ~950MB RSS; 1024 leaves
# headroom above the measured value, and is NOT the -Xmx heap ceiling — RSS runs well below -Xmx).
PER_JVM_MB = 1024
# The conservative fraction of MemTotal a run may claim (leaves the OS + other processes + the JVM
# off-heap / RSS-over-Xmx margin). A stable starting point; the runtime clamp handles the rest.
MEM_FRACTION = 0.6

_MEMINFO = "/proc/meminfo"
_CPUINFO = "/proc/cpuinfo"


@dataclass(frozen=True)
class CoreProbe:
    """A physical-core estimate plus the method that produced it, so an imprecise probe is visible
    (the fallbacks are best-effort — the log records which rung answered)."""

    count: int
    method: str


def _cores_from_cpuinfo(path: str = _CPUINFO) -> int:
    """Distinct (physical id, core id) pairs in ``/proc/cpuinfo`` = physical cores. 0 if the file is
    unreadable or carries no physical/core id lines (some ARM / container kernels omit them)."""
    try:
        seen: set[tuple[str, str]] = set()
        phys: str | None = None
        core: str | None = None
        with open(path) as fh:
            for line in fh:
                if line.startswith("physical id"):
                    phys = line.split(":", 1)[1].strip()
                elif line.startswith("core id"):
                    core = line.split(":", 1)[1].strip()
                elif not line.strip() and phys is not None and core is not None:
                    seen.add((phys, core))
                    phys = core = None
        return len(seen)
    except OSError:
        return 0


def _cores_from_lscpu() -> int:
    """``Core(s) per socket`` × ``Socket(s)`` from ``lscpu``, or 0 if lscpu is absent / unparseable.
    A separate function so a test can force the cpu_count fallback deterministically."""
    try:
        out = subprocess.run(  # noqa: S603,S607 -- fixed argv, no shell
            ["lscpu"], capture_output=True, text=True, timeout=5
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return 0
    per_socket = sockets = 0
    for line in out.splitlines():
        if line.startswith("Core(s) per socket:"):
            per_socket = _int_or_zero(line.split(":", 1)[1])
        elif line.startswith("Socket(s):"):
            sockets = _int_or_zero(line.split(":", 1)[1])
    return per_socket * sockets


def _int_or_zero(s: str) -> int:
    try:
        return int(s.strip())
    except ValueError:
        return 0


def physical_cores(cpuinfo_path: str = _CPUINFO) -> CoreProbe:
    """Estimate physical cores with an honest fallback chain (WSL2 / containers can report an
    all-zero or absent physical/core id, which dedups to a bogus 1):

        /proc/cpuinfo dedup (only trusted when it yields > 1) -> lscpu -> os.cpu_count()//2
        (assume 2-way SMT) -> os.cpu_count() raw.

    A cpuinfo result of <= 1 is treated as unreliable and falls through — a genuine single-core
    machine still lands on 1 via the tail rungs, so the gate only fixes the bogus-1 case, never
    understates a real multi-core box. The chosen rung rides on the return so the caller can log it.
    """
    n = _cores_from_cpuinfo(cpuinfo_path)
    if n > 1:
        return CoreProbe(n, "cpuinfo")
    n = _cores_from_lscpu()
    if n > 1:
        return CoreProbe(n, "lscpu")
    logical = os.cpu_count() or 1
    if logical >= 2:
        # assume 2-way SMT; a no-HT box halves here, a 4-way doubles — a last-resort estimate the
        # memory limit still caps, and the method string makes the assumption visible.
        return CoreProbe(max(1, logical // 2), "cpu_count//2 (assumed 2-way SMT)")
    return CoreProbe(max(1, logical), "cpu_count")


def mem_total_mb(meminfo_path: str = _MEMINFO) -> int:
    """MemTotal in MB, or a conservative 4096 if ``/proc/meminfo`` is unreadable."""
    try:
        with open(meminfo_path) as fh:
            for line in fh:
                if line.startswith("MemTotal"):
                    return int(line.split()[1]) // 1024
    except OSError:
        pass
    return 4096


def mem_available_mb(meminfo_path: str = _MEMINFO) -> int | None:
    """MemAvailable in MB right now, or None if it cannot be read (then no runtime clamp runs)."""
    try:
        with open(meminfo_path) as fh:
            for line in fh:
                if line.startswith("MemAvailable"):
                    return int(line.split()[1]) // 1024
    except OSError:
        pass
    return None


def derive_parallelism(
    phys_cores: int,
    mem_total: int,
    *,
    per_jvm_mb: int = PER_JVM_MB,
    mem_fraction: float = MEM_FRACTION,
) -> int:
    """The stable ``max_parallel_jvms`` for a machine: min(physical cores, memory budget / per-JVM).

    The min is load-bearing: whichever of CPU or memory tops out first bounds the pool. Removing the
    memory arm would let a many-core / low-RAM box OOM (this is the invariant a test guards). Always
    at least 1.
    """
    cpu_limit = max(1, phys_cores)
    mem_limit = max(1, int(mem_total * mem_fraction) // per_jvm_mb)
    return max(1, min(cpu_limit, mem_limit))


def clamp_parallelism_to_memory(
    configured: int,
    *,
    per_jvm_mb: int = PER_JVM_MB,
    avail_mb: int | None = None,
    meminfo_path: str = _MEMINFO,
) -> tuple[int, str | None]:
    """Clamp a stable configured parallelism DOWN to what current free memory allows, for THIS run.

    The config value is a stable MemTotal-based derivation; if actual MemAvailable is low right now
    (a build, another process), running ``configured`` JVMs would OOM/swap. Read MemAvailable once
    and cap to ``max(1, avail // per_jvm_mb)``. Returns (effective, note): note is a human-readable
    string ONLY when a clamp happened (so the caller logs it), else None. Never raises the pool
    size; if MemAvailable is unreadable, leaves it unchanged (best-effort, never blocks a run).
    """
    if avail_mb is None:
        avail_mb = mem_available_mb(meminfo_path)
    if avail_mb is None:
        return max(1, configured), None
    cap = max(1, avail_mb // per_jvm_mb)
    if cap < configured:
        return cap, (
            f"low memory: parallelism {configured}->{cap} this run (MemAvailable {avail_mb}MB, "
            f"~{per_jvm_mb}MB per JVM)"
        )
    return max(1, configured), None
