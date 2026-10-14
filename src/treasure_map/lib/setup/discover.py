# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Find the toolchain already on this machine — read only.

Each component (JDK, Ghidra, BinExport, BinDiff) gets a list of CANDIDATES, in priority order,
each checked at file level against what tmap needs: Ghidra exactly the pinned version with its
headless launcher and this platform's native decompiler; a JDK (not a JRE) of major version 21;
exactly one BinExport that this Ghidra loads, of the Ghidra's own version; a BinDiff 8. A
candidate that differs from the lock only in a detail tmap does not depend on (a JDK patch
release, another build of BinExport, another BinDiff 8 version line) is accepted with a note.

Nothing here writes. The only things run are ``bindiff --version`` (and, on macOS,
``/usr/libexec/java_home``), with a timeout. Paths under ``~/.treasure-map/toolchain`` are tmap's
own and count only when the install ledger records them — never as something the user brought.
"""

from __future__ import annotations

import getpass
import os
import shutil
import subprocess
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol

from treasure_map.lib.diff.toolchain import (
    _properties_value,
    binexport_dirs,
    binexport_lib_digest,
    ghidra_settings_dir,
)
from treasure_map.lib.setup.platform import CPU_ARM64, Platform, macho_cputypes

ComponentName = Literal["jdk", "ghidra", "binexport", "bindiff"]

# tests/unit/conftest.py turns this off: no PATH lookup, no subprocess, no system directories.
SYSTEM_PROBES = True

_RUN_TIMEOUT = 30.0


@dataclass(frozen=True)
class RunResult:
    returncode: int
    stdout: str
    stderr: str


class Runner(Protocol):
    def __call__(
        self, argv: Sequence[str], *, cwd: Path | None = None, timeout: float = _RUN_TIMEOUT
    ) -> RunResult | None: ...


def run_command(
    argv: Sequence[str], *, cwd: Path | None = None, timeout: float = _RUN_TIMEOUT
) -> RunResult | None:
    """Run a fixed argv (no shell) with a timeout; None when it cannot be started or times out."""
    try:
        proc = subprocess.run(  # noqa: S603 -- fixed argv, no shell
            list(argv), capture_output=True, timeout=timeout, cwd=cwd, check=False
        )
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None
    return RunResult(
        proc.returncode,
        proc.stdout.decode(errors="replace"),
        proc.stderr.decode(errors="replace"),
    )


def _no_run(
    argv: Sequence[str], *, cwd: Path | None = None, timeout: float = _RUN_TIMEOUT
) -> RunResult | None:
    return None


@dataclass(frozen=True)
class Host:
    """Everything discovery reads from the machine, so a test can stand up any machine."""

    environ: Mapping[str, str]
    home: Path
    user_name: str
    platform: Platform
    which: Callable[[str], str | None]
    run: Runner
    ghidra_scan_roots: tuple[Path, ...]
    ghidra_globs: tuple[str, ...]
    jdk_globs: tuple[str, ...]
    bindiff_paths: tuple[Path, ...]
    darwin_java_home_tool: bool = True

    @property
    def tm_home(self) -> Path:
        return self.home / ".treasure-map"

    @property
    def toolchain_dir(self) -> Path:
        return self.tm_home / "toolchain"


def current_host(platform: Platform) -> Host:
    """The real machine (or, with SYSTEM_PROBES off, only its home directory)."""
    home = Path.home()
    environ = os.environ
    try:
        user = getpass.getuser()
    except Exception:
        user = environ.get("USER", "")
    home_roots = (home, home / "tools", home / "opt", home / "Downloads")
    home_jdks = (
        str(home / ".sdkman/candidates/java/*"),
        str(home / ".asdf/installs/java/*"),
        str(home / ".jdks/*"),
    )
    if not SYSTEM_PROBES:
        return Host(
            environ=environ,
            home=home,
            user_name=user,
            platform=platform,
            which=lambda _name: None,
            run=_no_run,
            ghidra_scan_roots=home_roots,
            ghidra_globs=(),
            jdk_globs=home_jdks,
            bindiff_paths=(),
            darwin_java_home_tool=False,
        )
    jdk_globs = list(home_jdks)
    jdk_globs += [
        "/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home",
        "/usr/local/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home",
    ]
    if platform.is_darwin:
        jdk_globs.insert(0, "/Library/Java/JavaVirtualMachines/*/Contents/Home")
    else:
        jdk_globs.insert(0, "/usr/lib/jvm/*")
    bindiff_paths = [Path("/opt/bindiff/bin/bindiff")]
    if platform.is_darwin:
        bindiff_paths.append(Path("/Applications/BinDiff/BinDiff.app/Contents/MacOS/bin/bindiff"))
    return Host(
        environ=environ,
        home=home,
        user_name=user,
        platform=platform,
        which=lambda name: shutil.which(name, path=environ.get("PATH")),
        run=run_command,
        ghidra_scan_roots=(
            *home_roots,
            Path("/opt"),
            Path("/usr/local"),
            Path("/usr/share"),
            Path("/Applications"),
        ),
        ghidra_globs=(
            "/opt/homebrew/Caskroom/ghidra/*/ghidra_*_PUBLIC",
            "/usr/local/Caskroom/ghidra/*/ghidra_*_PUBLIC",
        ),
        jdk_globs=tuple(jdk_globs),
        bindiff_paths=tuple(bindiff_paths),
    )


@dataclass(frozen=True)
class Candidate:
    component: ComponentName
    path: Path  # jdk: java_home; ghidra: install root; binexport: extension dir; bindiff: exe
    source: str
    version: str | None
    ok: bool
    why_not: str | None = None
    note: str | None = None
    managed: bool = False  # tmap installed it (the ledger records it)


# ── per-component checks (file level) ────────────────────────────────────────────────────────


def check_ghidra(root: Path, platform: Platform, want: str) -> tuple[str | None, str | None]:
    """(version read, why it is not usable — None when it is)."""
    version = _properties_value(root / "Ghidra" / "application.properties", "application.version")
    if version is None:
        return None, "no Ghidra/application.properties"
    if version != want:
        return version, f"Ghidra {version}; tmap needs {want}"
    if not (root / "support" / "analyzeHeadless").is_file():
        return version, "no support/analyzeHeadless"
    native = platform.ghidra_native_dir
    if native is None:
        return version, f"Ghidra has no native decompiler for {platform.key}"
    if not (root / "Ghidra" / "Features" / "Decompiler" / "os" / native / "decompile").is_file():
        return version, f"no native decompiler for {native}"
    return version, None


@dataclass(frozen=True)
class JdkInfo:
    version: str | None  # JAVA_VERSION from the release file
    major: int | None
    java: bool  # bin/java executable
    javac: bool  # bin/javac executable (a JDK, not a JRE)


def java_major(version: str) -> int | None:
    parts = version.strip().split(".")
    try:
        first = int(parts[0])
        if first == 1 and len(parts) > 1:  # 1.8.0 -> 8
            return int(parts[1])
        return first
    except ValueError:
        return None


def read_jdk(java_home: Path) -> JdkInfo:
    version: str | None = None
    try:
        for line in (java_home / "release").read_text(errors="replace").splitlines():
            key, sep, value = line.partition("=")
            if sep and key.strip() == "JAVA_VERSION":
                version = value.strip().strip('"') or None
                break
    except OSError:
        pass
    bin_dir = java_home / "bin"
    return JdkInfo(
        version=version,
        major=java_major(version) if version else None,
        java=os.access(bin_dir / "java", os.X_OK) and (bin_dir / "java").is_file(),
        javac=os.access(bin_dir / "javac", os.X_OK) and (bin_dir / "javac").is_file(),
    )


def check_jdk(java_home: Path) -> tuple[str | None, str | None]:
    """(version read, why it is not usable — None when it is). Major 21, and a JDK: Ghidra
    refuses a JRE."""
    info = read_jdk(java_home)
    if info.version is None:
        return None, "no readable release file"
    if info.major != 21:
        return info.version, f"Java {info.version}; tmap needs JDK 21"
    if not info.java:
        return info.version, "no bin/java"
    if not info.javac:
        return info.version, "a JRE (no bin/javac); Ghidra needs a JDK"
    return info.version, None


def jdk_note(version: str | None, pinned: str) -> str | None:
    pinned_plain = pinned.split("+", 1)[0]
    if version is None or version == pinned_plain:
        return None
    return f"differs from pinned {pinned} (accepted: any JDK 21)"


def bindiff_version_line(exe: Path, run: Runner) -> str | None:
    res = run([str(exe), "--version"])
    if res is None:
        return None
    for line in (res.stdout + "\n" + res.stderr).splitlines():
        if line.strip():
            return line.strip()
    return None


def check_bindiff(
    exe: Path, platform: Platform, run: Runner, version_line: str | None
) -> tuple[str | None, str | None, str | None]:
    """(version line, why not usable, note)."""
    if not (exe.is_file() and os.access(exe, os.X_OK)):
        return None, "not an executable file", None
    line = bindiff_version_line(exe, run)
    if line is None:
        return None, "`bindiff --version` gave no output", None
    if not line.startswith("BinDiff 8 "):
        return line, f"{line!r}; tmap needs BinDiff 8", None
    if platform.key == "darwin-arm64":
        types = macho_cputypes(exe)
        if types is None:
            return line, "cannot read its Mach-O header", None
        if CPU_ARM64 not in types:
            return line, "no arm64 slice (it would run under Rosetta)", None
    note = None
    if version_line and line != version_line:
        note = f"version line {line!r} differs from pinned {version_line!r}"
    return line, None, note


# ── candidate sources ────────────────────────────────────────────────────────────────────────


def _under(path: Path, root: Path) -> bool:
    try:
        return Path(os.path.realpath(path)).is_relative_to(os.path.realpath(root))
    except (OSError, ValueError):
        return False


@dataclass
class _Collector:
    host: Host
    managed: Sequence[Path]  # ledger-committed paths for this component
    seen: set[str] = field(default_factory=set)
    out: list[tuple[Path, str, bool]] = field(default_factory=list)

    def add(self, path: Path | None, source: str) -> None:
        if path is None:
            return
        path = Path(os.path.expanduser(str(path)))
        key = os.path.realpath(path)
        if key in self.seen:
            return
        managed = any(_under(path, m) for m in self.managed)
        if _under(path, self.host.toolchain_dir) and not managed:
            return  # tmap's own directory, but not a recorded install: never a user candidate
        self.seen.add(key)
        self.out.append((path, source, managed))


def _ghidra_root_of(exe: Path) -> Path | None:
    p = Path(os.path.realpath(exe)).parent
    for _ in range(4):
        if (p / "Ghidra" / "application.properties").is_file():
            return p
        if p.parent == p:
            return None
        p = p.parent
    return None


def _shallow_ghidra_scan(roots: Iterable[Path], *, skip: Sequence[Path]) -> list[Path]:
    found: list[Path] = []
    skip_real = [os.path.realpath(s) for s in skip]

    def walk(d: Path, depth: int) -> None:
        if depth > 3:
            return
        real = os.path.realpath(d)
        if any(real == s or real.startswith(s + os.sep) for s in skip_real):
            return
        try:
            entries = sorted(os.scandir(d), key=lambda e: e.name)
        except OSError:
            return
        for e in entries:
            try:
                if not e.is_dir(follow_symlinks=False):
                    continue
            except OSError:
                continue
            p = Path(e.path)
            if (
                e.name.startswith("ghidra_")
                and e.name.endswith("_PUBLIC")
                and (p / "Ghidra" / "application.properties").is_file()
            ):
                found.append(p)
                continue
            walk(p, depth + 1)

    for root in roots:
        if root.is_dir():
            walk(root, 1)
    return found


def _glob(pattern: str) -> list[Path]:
    import glob

    return [Path(p) for p in sorted(glob.glob(pattern))]


def discover_ghidra(
    host: Host, *, config_home: Path | None, want: str, managed: Sequence[Path] = ()
) -> list[Candidate]:
    c = _Collector(host, managed)
    c.add(config_home, "config")
    for m in managed:
        c.add(m, "managed")
    c.add(_env_path(host, "GHIDRA_HOME"), "$GHIDRA_HOME")
    c.add(_env_path(host, "GHIDRA_INSTALL_DIR"), "$GHIDRA_INSTALL_DIR")
    for exe in ("analyzeHeadless", "ghidraRun"):
        found = host.which(exe)
        if found:
            c.add(_ghidra_root_of(Path(found)), "PATH")
    for pattern in host.ghidra_globs:
        for p in _glob(pattern):
            c.add(p, "Homebrew")
    skip = [Path("/mnt"), host.tm_home]
    for p in _shallow_ghidra_scan(host.ghidra_scan_roots, skip=skip):
        c.add(p, f"scan:{p.parent}")
    out: list[Candidate] = []
    for path, source, is_managed in c.out:
        version, why = check_ghidra(path, host.platform, want)
        out.append(Candidate("ghidra", path, source, version, why is None, why, None, is_managed))
    return out


def _env_path(host: Host, name: str) -> Path | None:
    value = host.environ.get(name)
    return Path(value) if value else None


def settings_dir_for(host: Host, ghidra_home: Path) -> Path | None:
    return ghidra_settings_dir(
        ghidra_home,
        environ=host.environ,
        user_home=host.home,
        platform="darwin" if host.platform.is_darwin else "linux",
        user_name=host.user_name,
    )


def discover_jdk(
    host: Host,
    *,
    config_java_home: Path | None,
    ghidra_home: Path | None,
    pinned: str,
    managed: Sequence[Path] = (),
) -> list[Candidate]:
    c = _Collector(host, managed)
    c.add(config_java_home, "config")
    for m in managed:
        c.add(m, "managed")
    c.add(_env_path(host, "JAVA_HOME"), "$JAVA_HOME")
    if ghidra_home is not None:
        settings = settings_dir_for(host, ghidra_home)
        if settings is not None:
            try:
                saved = (settings / "java_home.save").read_text(errors="replace").strip()
            except OSError:
                saved = ""
            if saved:
                c.add(Path(saved), "java_home.save")
    java = host.which("java")
    if java:
        c.add(Path(os.path.realpath(java)).parent.parent, "PATH")
    if host.platform.is_darwin and host.darwin_java_home_tool:
        res = host.run(["/usr/libexec/java_home", "-v", "21"])
        if res is not None and res.returncode == 0 and res.stdout.strip():
            c.add(Path(res.stdout.strip().splitlines()[0]), "java_home -v 21")
    for pattern in host.jdk_globs:
        for p in _glob(pattern):
            c.add(p, f"scan:{p.parent}")
    out: list[Candidate] = []
    for path, source, is_managed in c.out:
        version, why = check_jdk(path)
        note = jdk_note(version, pinned) if why is None else None
        out.append(Candidate("jdk", path, source, version, why is None, why, note, is_managed))
    return out


@dataclass(frozen=True)
class BinExportFinding:
    candidates: list[Candidate]  # every loaded copy (ok only when exactly one, right version)
    unknown: bool  # the settings directory could not be determined
    legacy: list[Path]  # copies in the old ~/.ghidra directory, which Ghidra 11.4 ignores
    settings_dir: Path | None

    def chosen(self) -> Candidate | None:
        return next((c for c in self.candidates if c.ok), None)


def discover_binexport(
    host: Host,
    ghidra_home: Path,
    *,
    pinned_digest: str | None,
    managed: Sequence[Path] = (),
) -> BinExportFinding:
    ghidra_version = _properties_value(
        ghidra_home / "Ghidra" / "application.properties", "application.version"
    )
    settings = settings_dir_for(host, ghidra_home)
    dirs = binexport_dirs(
        ghidra_home,
        environ=host.environ,
        user_home=host.home,
        platform="darwin" if host.platform.is_darwin else "linux",
        user_name=host.user_name,
    )
    legacy: list[Path] = []
    old = host.home / ".ghidra"
    if ghidra_version and old.is_dir():
        for d in sorted(old.glob(f".ghidra_{ghidra_version}*")):
            if (d / "Extensions" / "BinExport").is_dir():
                legacy.append(d / "Extensions" / "BinExport")
    if dirs is None:
        return BinExportFinding([], True, legacy, settings)
    out: list[Candidate] = []
    for d in dirs:
        version = _properties_value(d / "extension.properties", "version")
        is_managed = any(_under(d, m) for m in managed)
        source = "Ghidra install" if _under(d, ghidra_home) else "user settings"
        why: str | None = None
        note: str | None = None
        if len(dirs) > 1:
            why = "two copies; Ghidra may load either"
        elif version != ghidra_version:
            why = f"BinExport {version} does not match Ghidra {ghidra_version}"
        elif pinned_digest and not pinned_digest.startswith("<"):
            if binexport_lib_digest(d) != pinned_digest:
                note = "built from a different source than tmap's pinned build"
        out.append(Candidate("binexport", d, source, version, why is None, why, note, is_managed))
    return BinExportFinding(out, False, legacy, settings)


def discover_bindiff(
    host: Host,
    *,
    config_bindiff: Path | None,
    version_line: str | None,
    managed: Sequence[Path] = (),
) -> list[Candidate]:
    c = _Collector(host, managed)
    c.add(config_bindiff, "config")
    for m in managed:
        c.add(m, "managed")
    found = host.which("bindiff")
    if found:
        c.add(Path(found), "PATH")
    for p in host.bindiff_paths:
        if p.exists():
            c.add(p, str(p.parent))
    out: list[Candidate] = []
    for path, source, is_managed in c.out:
        line, why, note = check_bindiff(path, host.platform, host.run, version_line)
        out.append(Candidate("bindiff", path, source, line, why is None, why, note, is_managed))
    return out


def first_ok(candidates: Sequence[Candidate]) -> Candidate | None:
    return next((c for c in candidates if c.ok), None)
