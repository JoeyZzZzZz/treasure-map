# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Fake toolchain trees, hosts and fetchers for the setup tests — all under tmp_path, no network,
no real Ghidra / JDK / BinDiff."""

from __future__ import annotations

import io
import os
import zipfile
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from treasure_map.lib.setup.discover import Host, RunResult
from treasure_map.lib.setup.platform import Platform, detect_platform

BINDIFF_LINE = "BinDiff 8 (@568181968, Sep 25 2023)"


def linux() -> Platform:
    return detect_platform(
        system="Linux",
        machine="x86_64",
        environ={},
        osrelease=Path("/nonexistent-osrelease"),
        glibc=(2, 39),
    )


def darwin_arm() -> Platform:
    return detect_platform(system="Darwin", machine="arm64", environ={}, glibc=None)


def _exe(path: Path, body: str = "#!/bin/sh\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    path.chmod(0o755)
    return path


def make_ghidra(root: Path, version: str = "11.4.3", native: str = "linux_x86_64") -> Path:
    (root / "Ghidra").mkdir(parents=True, exist_ok=True)
    (root / "Ghidra" / "application.properties").write_text(
        f"application.name=Ghidra\napplication.version={version}\n"
        "application.release.name=PUBLIC\napplication.java.min=21\n"
    )
    _exe(root / "support" / "analyzeHeadless")
    (root / "support" / "launch.properties").write_text(
        "JAVA_HOME_OVERRIDE=\n#VMARGS=-Dapplication.settingsdir=\n"
    )
    _exe(root / "Ghidra" / "Features" / "Decompiler" / "os" / native / "decompile")
    return root


def make_jdk(home: Path, version: str = "21.0.12.1", javac: bool = True) -> Path:
    home.mkdir(parents=True, exist_ok=True)
    (home / "release").write_text(f'JAVA_VERSION="{version}"\n')
    _exe(home / "bin" / "java")
    if javac:
        _exe(home / "bin" / "javac")
    return home


def make_bindiff(path: Path) -> Path:
    return _exe(path, f"#!/bin/sh\necho '{BINDIFF_LINE}'\n")


def make_binexport(ext_dir: Path, version: str = "11.4.3", jar: bytes = b"jar-bytes") -> Path:
    (ext_dir / "lib").mkdir(parents=True, exist_ok=True)
    (ext_dir / "extension.properties").write_text(f"name=BinExport\nversion={version}\n")
    (ext_dir / "lib" / "BinExport.jar").write_bytes(jar)
    return ext_dir


def fake_run(
    answers: Mapping[str, RunResult | None] | None = None,
    log: list[list[str]] | None = None,
) -> Callable[..., RunResult | None]:
    """A Runner: ``bindiff --version`` answers the pinned line for any path named bindiff;
    other argv[0] basenames come from ``answers``."""
    answers = dict(answers or {})

    def run(
        argv: Sequence[str], *, cwd: Path | None = None, timeout: float = 30.0
    ) -> RunResult | None:
        if log is not None:
            log.append(list(argv))
        name = Path(argv[0]).name
        if name in answers:
            return answers[name]
        if name == "bindiff" and argv[1:] == ["--version"]:
            if not os.access(argv[0], os.X_OK):
                return None
            return RunResult(0, BINDIFF_LINE + "\n", "")
        return None

    return run


def make_host(
    home: Path,
    *,
    platform: Platform | None = None,
    environ: Mapping[str, str] | None = None,
    which: Mapping[str, str] | None = None,
    run: Callable[..., RunResult | None] | None = None,
    scan_roots: Sequence[Path] | None = None,
) -> Host:
    env = dict(environ or {})
    env.setdefault("HOME", str(home))
    table = dict(which or {})
    return Host(
        environ=env,
        home=home,
        user_name="tester",
        platform=platform or linux(),
        which=lambda name: table.get(name),
        run=run or fake_run(),  # type: ignore[arg-type]
        ghidra_scan_roots=tuple(scan_roots if scan_roots is not None else (home,)),
        ghidra_globs=(),
        jdk_globs=(),
        bindiff_paths=(),
        darwin_java_home_tool=False,
    )


def zip_bytes(members: Mapping[str, tuple[bytes, int]]) -> bytes:
    """A zip whose members carry the given unix permission bits."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, (data, mode) in members.items():
            info = zipfile.ZipInfo(name)
            info.external_attr = (mode & 0xFFFF) << 16
            zf.writestr(info, data)
    return buf.getvalue()


class BytesFetcher:
    """A Fetcher serving fixed bytes per file name, counting calls."""

    def __init__(self, payloads: Mapping[str, bytes]) -> None:
        self.payloads = dict(payloads)
        self.calls: list[str] = []

    def fetch(self, url: str, dest: Path, *, progress: object = None) -> bool:
        name = url.rsplit("/", 1)[-1]
        self.calls.append(url)
        dest.write_bytes(self.payloads[name])
        return True  # the whole payload, as a server that declared its length sends it


class RefusingFetcher:
    """A Fetcher that fails every download (offline), counting calls."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def fetch(self, url: str, dest: Path, *, progress: object = None) -> bool:
        from treasure_map.lib.setup.fetch import FetchError

        self.calls.append(url)
        raise FetchError(f"offline test: {url}")


# ── fake pinned archives, and a lock pinned to them ──────────────────────────────────────────


def _tar_gz(members: Mapping[str, tuple[bytes, int]]) -> bytes:
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, (data, mode) in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = mode
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def deb_bytes(data_members: Mapping[str, tuple[bytes, int]]) -> bytes:
    import lzma
    import tarfile

    tar = io.BytesIO()
    with tarfile.open(fileobj=tar, mode="w") as tf:
        for name, (data, mode) in data_members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = mode
            tf.addfile(info, io.BytesIO(data))
    data_xz = lzma.compress(tar.getvalue(), format=lzma.FORMAT_XZ)

    def member(name: str, body: bytes) -> bytes:
        header = f"{name:<16}{0:<12}{0:<6}{0:<6}{100644:<8}{len(body):<10}`\n".encode()
        return header + body + (b"\n" if len(body) % 2 else b"")

    return (
        b"!<arch>\n"
        + member("debian-binary", b"2.0\n")
        + member("control.tar.gz", b"")
        + member("data.tar.xz", data_xz)
    )


def fake_archives() -> dict[str, bytes]:
    """file name -> bytes for the four linux-x86_64 components."""
    sh = b"#!/bin/sh\n"
    jdk = _tar_gz(
        {
            "jdk-21.0.12.1+1/release": (b'JAVA_VERSION="21.0.12.1"\n', 0o644),
            "jdk-21.0.12.1+1/bin/java": (sh, 0o755),
            "jdk-21.0.12.1+1/bin/javac": (sh, 0o755),
        }
    )
    g = "ghidra_11.4.3_PUBLIC/"
    ghidra = zip_bytes(
        {
            g + "Ghidra/application.properties": (
                b"application.version=11.4.3\napplication.release.name=PUBLIC\n",
                0o100644,
            ),
            g + "support/analyzeHeadless": (sh, 0o100755),
            g + "support/launch.properties": (b"JAVA_HOME_OVERRIDE=\n", 0o100644),
            g + "Ghidra/Features/Decompiler/os/linux_x86_64/decompile": (b"\x7fELF", 0o100771),
        }
    )
    binexport = zip_bytes(
        {
            "BinExport/extension.properties": (b"name=BinExport\nversion=11.4.3\n", 0o100644),
            "BinExport/lib/BinExport.jar": (b"jar", 0o100644),
        }
    )
    bindiff = deb_bytes(
        {"./opt/bindiff/bin/bindiff": (f"#!/bin/sh\necho '{BINDIFF_LINE}'\n".encode(), 0o755)}
    )
    return {
        "OpenJDK21U-jdk_x64_linux_hotspot_21.0.12.1_1.tar.gz": jdk,
        "ghidra_11.4.3_PUBLIC_20251203.zip": ghidra,
        "BinExport-ghidra_11.4.3-b56dea7b0a8b.zip": binexport,
        "bindiff_8_amd64.deb": bindiff,
    }


def fake_lock(archives: Mapping[str, bytes]) -> object:
    """The shipped lock with every linux-x86_64 asset re-pinned to ``archives`` (and the
    BinExport placeholders filled)."""
    import dataclasses
    import hashlib

    from treasure_map.lib.setup.toolchain_lock import Lock, load_lock

    lock = load_lock()
    comps = {}
    for name, comp in lock.components.items():
        assets = {}
        for plat, asset in comp.assets.items():
            data = archives.get(asset.file_name)
            if data is not None:
                asset = dataclasses.replace(
                    asset, sha256=hashlib.sha256(data).hexdigest(), size=len(data)
                )
            assets[plat] = asset
        extra = {"lib_digest": "f" * 64} if name == "binexport" else {}
        comps[name] = dataclasses.replace(comp, assets=assets, **extra)
    return Lock(components=comps)
