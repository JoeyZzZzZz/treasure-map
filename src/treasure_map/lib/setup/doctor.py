# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""``tmap doctor``: is this machine ready to scan and diff, and are the agents wired up?

Every check ends in one of six states, and only three of them fail the run:

  ok ✅ · warn ⚠ (works, worth knowing) · info · (just so you know) — never fail;
  missing ❌ · wrong ❌ · unknown ? — fail. ``unknown`` is never shown as ✅: a check that could
  not be answered is not a check that passed.

Read only, apart from ``mcp_live``, which starts ``tmap mcp`` the way an agent would and lists
its runs (under a throwaway home whenever touching the user's atlas is not wanted).
"""

from __future__ import annotations

import os
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, NamedTuple

from treasure_map.lib.config.config import Config
from treasure_map.lib.diff import toolchain as _toolchain
from treasure_map.lib.setup import clients as _clients
from treasure_map.lib.setup.discover import (
    Host,
    check_bindiff,
    check_ghidra,
    discover_binexport,
    is_macos_java_stub,
    read_jdk,
)
from treasure_map.lib.setup.platform import CPU_ARM64, Platform, macho_cputypes
from treasure_map.lib.setup.toolchain_lock import Lock

State = Literal["ok", "warn", "info", "missing", "wrong", "unknown"]
COUNTED: frozenset[str] = frozenset({"missing", "wrong", "unknown"})
ICON = {"ok": "✅", "warn": "⚠", "info": "·", "missing": "❌", "wrong": "❌", "unknown": "?"}


class Check(NamedTuple):
    """One finding. ``ok`` is False exactly for the states that fail the run."""

    name: str
    ok: bool
    detail: str
    state: str

    @property
    def icon(self) -> str:
        return ICON[self.state]


def check(name: str, state: State, detail: str) -> Check:
    return Check(name, state not in COUNTED, detail, state)


@dataclass(frozen=True)
class RunsCurrency:
    """How many runs in the atlas an older tmap produced. ``count`` None = unknown (``why``);
    ``absent`` = there is no atlas yet."""

    count: int | None
    absent: bool = False
    why: str = ""


@dataclass(frozen=True)
class McpProbe:
    tools: frozenset[str] | None  # None: the server did not answer
    list_runs_ok: bool
    error: str = ""


McpProber = Callable[[Path, Mapping[str, str]], McpProbe]


@dataclass
class DoctorInputs:
    platform: Platform
    host: Host
    client_host: _clients.ClientHost
    cfg: Config | None
    lock: Lock
    tmap: Path | None
    check_only: bool
    requested_clients: Sequence[str] = ()
    runs: RunsCurrency | None = None
    mcp_probe: McpProber | None = None
    detect_toolchain: Callable[[], object] | None = None
    tm_home: Path = field(default_factory=lambda: Path.home() / ".treasure-map")


# ── the toolchain checks ─────────────────────────────────────────────────────────────────────


def _platform_checks(inp: DoctorInputs) -> list[Check]:
    p = inp.platform
    out = []
    if p.support == "supported":
        out.append(
            check(
                "platform",
                "ok",
                p.key + (" (WSL2)" if p.is_wsl else "") + (f" ({p.reason})" if p.reason else ""),
            )
        )
    elif p.support == "unverified":
        out.append(check("platform", "warn", f"{p.key}: {p.reason}"))
    else:
        out.append(check("platform", "wrong", f"{p.key}: {p.reason}"))
    if p.key.startswith("linux-"):
        if p.glibc is None:
            out.append(check("glibc", "wrong", "not glibc (BinDiff needs glibc >= 2.28)"))
        elif p.glibc >= (2, 28):
            out.append(check("glibc", "ok", f"{p.glibc[0]}.{p.glibc[1]}"))
        else:
            out.append(check("glibc", "wrong", f"{p.glibc[0]}.{p.glibc[1]} < 2.28 (BinDiff 8)"))
    if p.is_wsl and inp.cfg is not None:
        slow = [
            str(x)
            for x in (inp.cfg.workspace_dir, inp.cfg.atlas.db_path)
            if str(x).startswith("/mnt/")
        ]
        if slow:
            out.append(
                check(
                    "wsl_paths",
                    "warn",
                    f"{', '.join(slow)}: Ghidra I/O over /mnt is an order of magnitude slower; "
                    "keep workspaces under ~",
                )
            )
    return out


def effective_java_home(
    environ: Mapping[str, str], which: Callable[[str], str | None]
) -> Path | None:
    """The JDK tmap's Ghidra would be started with: ``$JAVA_HOME`` when it is a JDK 21+, else the
    ``java`` on PATH (resolved, two levels up)."""
    jh = environ.get("JAVA_HOME")
    if jh:
        info = read_jdk(Path(jh))
        if info.major is not None and info.major >= 21 and info.javac:
            return Path(jh)
    java = which("java")
    if java and not (sys.platform == "darwin" and is_macos_java_stub(java)):
        return Path(os.path.realpath(java)).parent.parent
    return None


def _java_check(inp: DoctorInputs) -> Check:
    home = effective_java_home(inp.host.environ, inp.host.which)
    if home is None:
        return check("java", "missing", "no JDK: neither $JAVA_HOME nor java on PATH")
    info = read_jdk(home)
    if info.major is None:
        return check("java", "unknown", f"{home}: cannot read its release file")
    if info.major < 21:
        return check("java", "wrong", f"{home}: Java {info.version}; Ghidra 11.4 needs JDK 21")
    if not info.javac:
        return check("java", "wrong", f"{home}: a JRE (no bin/javac); Ghidra needs a JDK")
    if info.major > 21:
        return check(
            "java", "warn", f"{home}: Java {info.version}; Ghidra accepts it; tmap is tested on 21"
        )
    return check("java", "ok", f"{home} (Java {info.version})")


def _ghidra_home(inp: DoctorInputs) -> Path | None:
    if inp.cfg is None:
        return None
    from treasure_map.lib.analyze.ghidra_runner import find_headless
    from treasure_map.lib.errors import GhidraNotFoundError

    try:
        return Path(find_headless(inp.cfg.ghidra)).resolve().parent.parent
    except GhidraNotFoundError:
        return None


def _ghidra_checks(inp: DoctorInputs) -> tuple[list[Check], Path | None]:
    want = inp.lock.component("ghidra").version
    home = _ghidra_home(inp)
    if home is None:
        return [check("ghidra", "missing", "not found (config, $GHIDRA_HOME, PATH)")], None
    version, why = check_ghidra(home, inp.platform, want)
    if version is None or (why is not None and version != want):
        return [check("ghidra", "wrong", f"{home}: {why}")], None
    if not (home / "support" / "analyzeHeadless").is_file():
        return [check("ghidra", "wrong", f"{home}: no support/analyzeHeadless")], None
    if not (home / "support" / "launch.properties").is_file():
        return [
            check("ghidra", "wrong", f"{home}: no support/launch.properties — Ghidra cannot start")
        ], None
    out = [check("ghidra", "ok", f"{home} ({version})")]
    native_dir = inp.platform.ghidra_native_dir
    decompile = (
        home / "Ghidra" / "Features" / "Decompiler" / "os" / native_dir / "decompile"
        if native_dir
        else None
    )
    if decompile is None or not (decompile.is_file() and os.access(decompile, os.X_OK)):
        out.append(
            check("ghidra_native", "wrong", f"no executable decompiler for {inp.platform.key}")
        )
    elif inp.platform.key == "darwin-arm64":
        types = macho_cputypes(decompile)
        if types is None:
            out.append(check("ghidra_native", "unknown", f"{decompile}: unreadable Mach-O header"))
        elif CPU_ARM64 not in types:
            out.append(
                check(
                    "ghidra_native",
                    "wrong",
                    f"{decompile}: no arm64 slice — relies on Rosetta, which macOS stops "
                    "supporting after macOS 27",
                )
            )
        else:
            out.append(check("ghidra_native", "ok", str(decompile)))
    else:
        out.append(check("ghidra_native", "ok", str(decompile)))
    out.append(_ghidra_jdk_effective(inp, home))
    return out, home


def _ghidra_jdk_effective(inp: DoctorInputs, home: Path) -> Check:
    """Ask Ghidra's own launcher which JDK it would pick (read only: no ``-save``)."""
    which_java = inp.host.which("java")
    jh = inp.host.environ.get("JAVA_HOME")
    java = which_java or (str(Path(jh) / "bin" / "java") if jh else None)
    if java is None:
        return check("ghidra_jdk_effective", "unknown", "no java to start Ghidra's launcher with")
    jar = home / "support" / "LaunchSupport.jar"
    res = inp.host.run([java, "-cp", str(jar), "LaunchSupport", str(home), "-jdk_home"])
    if res is None or res.returncode != 0:
        return check("ghidra_jdk_effective", "unknown", "Ghidra's launcher did not answer")
    lines = [ln.strip() for ln in res.stdout.splitlines() if ln.strip()]
    if not lines:
        return check("ghidra_jdk_effective", "unknown", "Ghidra's launcher named no JDK")
    picked = Path(lines[-1])
    info = read_jdk(picked)
    if info.major is None:
        return check("ghidra_jdk_effective", "unknown", f"{picked}: cannot read its release file")
    if info.major >= 21 and info.javac:
        return check("ghidra_jdk_effective", "ok", f"Ghidra starts with {picked}")
    return check(
        "ghidra_jdk_effective", "wrong", f"Ghidra would start with {picked} ({info.version})"
    )


def _binexport_checks(inp: DoctorInputs, home: Path) -> list[Check]:
    finding = discover_binexport(
        inp.host, home, pinned_digest=inp.lock.component("binexport").lib_digest
    )
    out: list[Check] = []
    if finding.unknown:
        out.append(
            check("binexport", "unknown", f"{home}: Ghidra's settings dir cannot be determined")
        )
    elif not finding.candidates:
        where = [str(home / "Ghidra" / "Extensions")]
        if finding.settings_dir is not None:
            where.append(str(finding.settings_dir / "Extensions"))
        out.append(check("binexport", "missing", "not loaded; looked in " + ", ".join(where)))
    elif len(finding.candidates) > 1:
        dirs = ", ".join(str(c.path) for c in finding.candidates)
        out.append(check("binexport", "wrong", f"two copies; Ghidra may load either: {dirs}"))
    else:
        c = finding.candidates[0]
        if not c.ok:
            out.append(check("binexport", "wrong", f"{c.path}: {c.why_not}"))
        else:
            stamp = _toolchain._binexport_version(home) or c.version or "?"
            note = f"; {c.note}" if c.note else ""
            out.append(check("binexport", "ok", f"{c.path} ({stamp}){note}"))
    for legacy in finding.legacy:
        out.append(check("binexport_legacy", "warn", f"{legacy}: ignored by Ghidra 11.4.3"))
    return out


def _bindiff_check(inp: DoctorInputs) -> Check:
    found = inp.host.which("bindiff")
    if not found:
        return check("bindiff", "missing", "no bindiff on PATH (or toolchain.bindiff)")
    pinned = inp.lock.component("bindiff").version_line
    line, why, note = check_bindiff(Path(found), inp.platform, inp.host.run, pinned)
    if why is not None:
        state: State = "unknown" if "Mach-O" in why or "no output" in why else "wrong"
        return check("bindiff", state, f"{found}: {why}")
    return check("bindiff", "ok", f"{found} ({line})" + (f"; {note}" if note else ""))


def _diff_toolchain_check(inp: DoctorInputs, blockers: Sequence[str] = ()) -> Check:
    detect = inp.detect_toolchain
    if detect is None:

        def detect() -> object:
            from treasure_map.lib.config.config import load_config

            return _toolchain.detect_toolchain(load_config(None))

    try:
        found = detect()
    except Exception as exc:
        return check("diff_toolchain_readable", "wrong", f"cannot read the toolchain: {exc}")
    if found is None:
        cause = (
            f"because {' and '.join(blockers)} failed above"
            if blockers
            else "Ghidra / BinExport / BinDiff versions unreadable"
        )
        return check(
            "diff_toolchain_readable",
            "wrong",
            f"{cause}: stored diffs cannot be checked for staleness",
        )
    return check("diff_toolchain_readable", "ok", str(found))


# ── local state ──────────────────────────────────────────────────────────────────────────────


def _dir_checks(inp: DoctorInputs) -> list[Check]:
    ws = inp.cfg.workspace_dir if inp.cfg is not None else inp.tm_home / "workspaces"
    atlas = inp.cfg.atlas.db_path.parent if inp.cfg is not None else inp.tm_home
    out = []
    for label, path in (("atlas_dir", atlas), ("workspace_dir", ws)):
        if path.exists():
            ok = os.access(path, os.W_OK)
            out.append(check(label, "ok" if ok else "wrong", "writable" if ok else "not writable"))
        else:
            out.append(check(label, "missing", "not provisioned"))
    from treasure_map.lib.setup.completion import completion_check

    name, ok, detail = completion_check(Path.home())
    if ok:
        out.append(check(name, "ok", detail))
    else:
        # Installed but not loaded by the shell yet is not a failure of tmap: the line to add is in
        # the detail, and `tmap init` never edits an rc without a yes.
        out.append(check(name, "missing" if "not installed" in detail else "warn", detail))
    return out


# ── MCP ──────────────────────────────────────────────────────────────────────────────────────


def _client_checks(inp: DoctorInputs) -> list[Check]:
    survey = _clients.survey(inp.client_host, inp.tmap)
    out = []
    for cid in _clients.CLIENT_IDS:
        st = survey.states[cid]
        name = f"mcp.{cid}"
        detail = st.detail
        if st.state == "aligned":
            note = f" ({detail})" if detail else ""
            out.append(check(name, "ok", f"registered in {st.config_path}{note}"))
        elif st.state == "missing":
            if cid in inp.requested_clients:
                out.append(check(name, "missing", "not registered"))
            elif st.detected:
                out.append(check(name, "info", "detected, not registered"))
        elif st.state == "foreign":
            out.append(check(name, "wrong", f"{detail} — not modified"))
        elif st.state == "unknown":
            out.append(check(name, "unknown", detail))
        else:
            out.append(check(name, "wrong", f"{st.state}: {detail}".rstrip(": ")))
    return out


def _mcp_atlas_check(inp: DoctorInputs) -> Check:
    from treasure_map.lib.last_run import read_last_run

    ptr = read_last_run()
    if ptr is not None:
        if not ptr.atlas_db.exists():
            return check(
                "mcp_atlas",
                "wrong",
                f"the last-run pointer names {ptr.atlas_db}, which does not exist: the server "
                "would create an empty atlas there",
            )
        return check("mcp_atlas", "ok", f"{ptr.atlas_db} (last run)")
    atlas = inp.cfg.atlas.db_path if inp.cfg is not None else inp.tm_home / "atlas.db"
    if not atlas.exists():
        return check("mcp_atlas", "info", f"{atlas}: created on first use")
    return check("mcp_atlas", "ok", str(atlas))


def _probe_env(home: Path, source: Mapping[str, str]) -> dict[str, str]:
    env = {"HOME": str(home), "PATH": "/usr/bin:/bin"}
    for k, v in source.items():
        if k in ("XDG_CONFIG_HOME", "CLAUDE_CONFIG_DIR") or k.startswith("TM_"):
            env[k] = v
    return env


def expected_tool_names() -> frozenset[str]:
    from treasure_map.mcp_app import make_tools

    with tempfile.TemporaryDirectory() as d:
        return frozenset(make_tools(Path(d) / "atlas.db").keys())


def _mcp_live_check(inp: DoctorInputs, atlas_state: str) -> Check:
    if inp.tmap is None:
        return check("mcp_live", "unknown", "tmap was not started as `tmap`; cannot start it")
    probe = inp.mcp_probe or stdio_probe
    throwaway = inp.check_only or atlas_state != "ok"
    with tempfile.TemporaryDirectory(prefix="tmap-doctor-") as tmp:
        home = Path(tmp) if throwaway else Path(inp.host.environ.get("HOME") or Path.home())
        result = probe(inp.tmap, _probe_env(home, inp.host.environ))
    suffix = " (probed with an empty temporary home)" if throwaway else ""
    if result.tools is None:
        return check("mcp_live", "wrong", f"`{inp.tmap} mcp` did not answer: {result.error}")
    want = expected_tool_names()
    if result.tools != want:
        missing = sorted(want - result.tools)
        extra = sorted(result.tools - want)
        return check("mcp_live", "wrong", f"tool set differs: missing {missing}, extra {extra}")
    if not result.list_runs_ok:
        return check("mcp_live", "wrong", f"list_runs returned an error{suffix}")
    return check("mcp_live", "ok", f"{len(want)} tools, list_runs answers{suffix}")


def stdio_probe(tmap: Path, env: Mapping[str, str], timeout: float = 30.0) -> McpProbe:
    """Start ``<tmap> mcp`` over stdio as a client would, list its tools and call list_runs."""
    import anyio
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async def _go(errlog: object) -> McpProbe:
        params = StdioServerParameters(command=str(tmap), args=["mcp"], env=dict(env))
        with anyio.fail_after(timeout):
            async with stdio_client(params, errlog=errlog) as (read, write):  # type: ignore[arg-type]
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    listed = await session.list_tools()
                    names = frozenset(t.name for t in listed.tools)
                    res = await session.call_tool("list_runs", {})
                    return McpProbe(names, not res.isError)

    with tempfile.TemporaryFile("w+") as errlog:
        try:
            return anyio.run(_go, errlog)
        except BaseException as exc:  # timeout, spawn failure, protocol error
            if isinstance(exc, KeyboardInterrupt):
                raise
            errlog.seek(0)
            tail = [ln for ln in errlog.read().splitlines() if ln.strip()]
            last = tail[-1] if tail else f"{type(exc).__name__}: {exc}"
            return McpProbe(None, False, last)


def _runs_check(inp: DoctorInputs) -> Check | None:
    r = inp.runs
    if r is None or r.absent:
        return None
    if r.count is None:
        return check("runs_current", "info", f"runs: unknown ({r.why})")
    if r.count == 0:
        return check("runs_current", "ok", "every run was made by this tmap")
    return check(
        "runs_current",
        "warn",
        f"{r.count} runs predate this tmap — run `tmap rescan` (and re-run `tmap diff`)",
    )


def _config_check(inp: DoctorInputs) -> Check:
    path = inp.tm_home / "config.yaml"
    if not path.exists():
        return check("config", "missing", f"{path}: not written yet — run `tmap init`")
    from treasure_map.lib.config.config import load_config
    from treasure_map.lib.errors import ConfigError

    try:
        load_config(None)
    except ConfigError as exc:
        return check("config", "wrong", str(exc).splitlines()[0])
    return check("config", "ok", str(path))


def run_doctor(inp: DoctorInputs) -> list[Check]:
    out = _platform_checks(inp)
    out.append(_config_check(inp))
    out.append(_java_check(inp))
    ghidra, home = _ghidra_checks(inp)
    out += ghidra
    if home is not None:
        out += _binexport_checks(inp, home)
    out.append(_bindiff_check(inp))
    toolchain_parts = ("ghidra", "binexport", "bindiff")
    blockers = [c.name for c in out if c.name in toolchain_parts and c.state in COUNTED]
    out.append(_diff_toolchain_check(inp, blockers))
    out += _dir_checks(inp)
    out += _client_checks(inp)
    atlas = _mcp_atlas_check(inp)
    out.append(atlas)
    out.append(_mcp_live_check(inp, atlas.state))
    runs = _runs_check(inp)
    if runs is not None:
        out.append(runs)
    return out


def failing(checks: Sequence[Check]) -> list[Check]:
    return [c for c in checks if c.state in COUNTED]
