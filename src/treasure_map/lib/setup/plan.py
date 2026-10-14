# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""What ``tmap init`` will change, shown before anything changes, and the toolchain half of
carrying it out.

A plan is a list of actions, each naming its target and — for a download — the URL, size and
sha256 it will be checked against. Things already in place are not listed, so a second run of an
up-to-date setup plans nothing. Things tmap will NOT do for the user (a placeholder artifact, a
BinExport of another version already loaded, an entry it does not own) are listed as needing
the user, never dropped.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from treasure_map.lib.diff.toolchain import binexport_dirs, binexport_lib_digest
from treasure_map.lib.setup.discover import (
    Host,
    check_bindiff,
    check_ghidra,
    check_jdk,
    settings_dir_for,
)
from treasure_map.lib.setup.fetch import (
    Fetcher,
    FetchError,
    install_archive,
    stderr_progress,
)
from treasure_map.lib.setup.ledger import Ledger
from treasure_map.lib.setup.toolchain_lock import Asset, Lock

TOOLCHAIN_KINDS = (
    "download_jdk",
    "download_ghidra",
    "set_ghidra_jdk_override",
    "install_binexport",
    "download_bindiff",
)


@dataclass
class Action:
    kind: str
    title: str
    target: Path | None = None
    lines: list[str] = field(default_factory=list)
    asset: Asset | None = None
    client: str | None = None
    project_dir: Path | None = None
    values: dict[str, str | None] = field(default_factory=dict)  # write_config keys

    def render(self) -> list[str]:
        head = f"  • {self.title}"
        if self.target is not None:
            head += f" → {self.target}"
        return [head, *(f"      {ln}" for ln in self.lines)]


def _mb(size: int) -> str:
    return f"{size / 1_000_000:.0f} MB"


def download_lines(asset: Asset, mirror: str | None) -> list[str]:
    from treasure_map.lib.setup.fetch import source_url

    return [
        f"from   {source_url(asset, mirror)}",
        f"size   {asset.size} bytes ({_mb(asset.size)})",
        f"sha256 {asset.sha256}",
    ]


@dataclass
class Plan:
    actions: list[Action] = field(default_factory=list)
    needs_you: list[str] = field(default_factory=list)

    def add(self, action: Action) -> None:
        self.actions.append(action)

    def of(self, kind: str) -> Action | None:
        return next((a for a in self.actions if a.kind == kind), None)

    def render(self) -> list[str]:
        out: list[str] = []
        for a in self.actions:
            out += a.render()
        if self.needs_you:
            out.append("  Needs you (tmap will not do these):")
            out += [f"    - {n}" for n in self.needs_you]
        return out


# ── the managed Ghidra's JDK override ────────────────────────────────────────────────────────

OVERRIDE_KEY = "JAVA_HOME_OVERRIDE="


def override_line(launch_properties: Path) -> str | None:
    """The ``JAVA_HOME_OVERRIDE=`` line as it stands (None when the file or line is absent)."""
    try:
        lines = launch_properties.read_text().splitlines()
    except OSError:
        return None
    return next((ln for ln in lines if ln.startswith(OVERRIDE_KEY)), None)


def set_override(launch_properties: Path, java_home: Path) -> str:
    """Point the managed Ghidra at ``java_home`` (the launcher's top priority); returns the line
    it replaced."""
    text = launch_properties.read_text()
    lines = text.splitlines(keepends=True)
    for i, ln in enumerate(lines):
        if ln.startswith(OVERRIDE_KEY):
            before = ln.rstrip("\r\n")
            lines[i] = f"{OVERRIDE_KEY}{java_home}\n"
            launch_properties.write_text("".join(lines))
            return before
    raise FetchError(f"{launch_properties} has no {OVERRIDE_KEY} line")


# ── carrying out the toolchain actions ───────────────────────────────────────────────────────


@dataclass
class ToolchainResult:
    java_home: Path | None = None
    ghidra_home: Path | None = None
    bindiff: Path | None = None
    failed: list[str] = field(default_factory=list)
    done: list[str] = field(default_factory=list)


def apply_toolchain(
    plan: Plan,
    *,
    host: Host,
    lock: Lock,
    ledger: Ledger,
    fetcher: Fetcher,
    mirror: str | None,
    chosen_ghidra: Path | None,
    chosen_jdk: Path | None,
    echo: Callable[[str], None],
) -> ToolchainResult:
    """Run the plan's toolchain actions in order. The first failure skips the rest (each later
    one depends on, or is pointless without, the earlier); what succeeded stays recorded."""
    res = ToolchainResult(java_home=chosen_jdk, ghidra_home=chosen_ghidra)
    tdir = host.toolchain_dir
    tdir.mkdir(parents=True, exist_ok=True)
    plat = host.platform
    want_ghidra = lock.component("ghidra").version
    for action in [a for a in plan.actions if a.kind in TOOLCHAIN_KINDS]:
        if res.failed:
            res.failed.append(f"{action.title}: skipped after an earlier failure")
            continue
        try:
            if action.kind == "download_jdk":
                asset = _asset(action)
                java_home = tdir / (asset.java_home or asset.root or "")
                install_archive(
                    "jdk",
                    asset,
                    tdir / (asset.root or "jdk"),
                    toolchain_dir=tdir,
                    ledger=ledger,
                    fetcher=fetcher,
                    verify=_jdk_verifier(java_home),
                    run=host.run,
                    mirror=mirror,
                    progress=stderr_progress("JDK"),
                    extra={"java_home": str(java_home)},
                )
                res.java_home = java_home
            elif action.kind == "download_ghidra":
                asset = _asset(action)
                target = tdir / (asset.root or "ghidra")
                install_archive(
                    "ghidra",
                    asset,
                    target,
                    toolchain_dir=tdir,
                    ledger=ledger,
                    fetcher=fetcher,
                    verify=lambda p: check_ghidra(p, plat, want_ghidra)[1],
                    run=host.run,
                    mirror=mirror,
                    progress=stderr_progress("Ghidra"),
                )
                res.ghidra_home = target
            elif action.kind == "set_ghidra_jdk_override":
                assert res.ghidra_home is not None and res.java_home is not None
                props = res.ghidra_home / "support" / "launch.properties"
                ledger.add_pending("ghidra_jdk_override", "edit", props)
                before = set_override(props, res.java_home)
                ledger.commit(
                    "ghidra_jdk_override",
                    line_before=before,
                    line_after=f"{OVERRIDE_KEY}{res.java_home}",
                )
            elif action.kind == "install_binexport":
                asset = _asset(action)
                assert res.ghidra_home is not None
                ext_dir = binexport_target(host, res.ghidra_home, ledger)
                if ext_dir is None:
                    raise FetchError("Ghidra's settings directory cannot be determined")
                home = res.ghidra_home
                install_archive(
                    "binexport",
                    asset,
                    ext_dir,
                    toolchain_dir=tdir,
                    ledger=ledger,
                    fetcher=fetcher,
                    verify=_binexport_verifier(host, home, want_ghidra),
                    run=host.run,
                    mirror=mirror,
                    progress=stderr_progress("BinExport"),
                )
                ledger.commit("binexport", lib_digest=binexport_lib_digest(ext_dir))
            elif action.kind == "download_bindiff":
                asset = _asset(action)
                target = tdir / f"bindiff-{lock.component('bindiff').version}"
                exe = target / (asset.exe or "bindiff")
                pinned = lock.component("bindiff").version_line
                install_archive(
                    "bindiff",
                    asset,
                    target,
                    toolchain_dir=tdir,
                    ledger=ledger,
                    fetcher=fetcher,
                    verify=_bindiff_verifier(exe, host, pinned),
                    run=host.run,
                    mirror=mirror,
                    progress=stderr_progress("BinDiff"),
                    extra={"exe": str(exe)},
                )
                res.bindiff = exe
            res.done.append(action.title)
            echo(f"  ✓ {action.title}")
        except (FetchError, OSError) as exc:
            res.failed.append(f"{action.title}: {exc}")
            echo(f"  ✗ {action.title}: {exc}")
    return res


def _jdk_verifier(java_home: Path) -> Callable[[Path], str | None]:
    def verify(_installed: Path) -> str | None:
        return check_jdk(java_home)[1]

    return verify


def _binexport_verifier(host: Host, ghidra_home: Path, want: str) -> Callable[[Path], str | None]:
    def verify(installed: Path) -> str | None:
        return verify_binexport(host, ghidra_home, installed, want)

    return verify


def _bindiff_verifier(exe: Path, host: Host, pinned: str | None) -> Callable[[Path], str | None]:
    def verify(_installed: Path) -> str | None:
        return check_bindiff(exe, host.platform, host.run, pinned)[1]

    return verify


def _asset(action: Action) -> Asset:
    if action.asset is None:
        raise FetchError(f"{action.title}: no pinned artifact")
    return action.asset


def binexport_target(host: Host, ghidra_home: Path, ledger: Ledger) -> Path | None:
    """Where BinExport goes: inside a Ghidra tmap installed; for the user's own Ghidra, its
    user settings directory — tmap never writes into a Ghidra install it did not make."""
    managed = ledger.committed("ghidra")
    if managed is not None and os.path.realpath(managed.path) == os.path.realpath(ghidra_home):
        return ghidra_home / "Ghidra" / "Extensions" / "BinExport"
    settings = settings_dir_for(host, ghidra_home)
    return None if settings is None else settings / "Extensions" / "BinExport"


def verify_binexport(host: Host, ghidra_home: Path, ext_dir: Path, want: str) -> str | None:
    from treasure_map.lib.diff.toolchain import _properties_value

    dirs = binexport_dirs(
        ghidra_home,
        environ=host.environ,
        user_home=host.home,
        platform="darwin" if host.platform.is_darwin else "linux",
        user_name=host.user_name,
    )
    if dirs is None:
        return "Ghidra's settings directory cannot be determined"
    if [os.path.realpath(d) for d in dirs] != [os.path.realpath(ext_dir)]:
        return f"Ghidra would load {[str(d) for d in dirs]}, not exactly {ext_dir}"
    version = _properties_value(ext_dir / "extension.properties", "version")
    if version != want:
        return f"BinExport {version} does not match Ghidra {want}"
    return None
