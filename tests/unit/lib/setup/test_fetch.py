# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Download → verify → unpack → record, in that order; nothing unverified is ever installed."""

from __future__ import annotations

import hashlib
import io
import stat
import tarfile
from pathlib import Path

import pytest

from treasure_map.lib.setup.fetch import (
    FetchError,
    OfflineFetcher,
    download_verified,
    extract_deb,
    extract_tar_gz,
    extract_zip,
    install_archive,
    recover_pending,
    source_url,
)
from treasure_map.lib.setup.ledger import LEDGER_NAME, Ledger
from treasure_map.lib.setup.toolchain_lock import Asset

from . import fakes


def _asset(
    data: bytes, name: str = "thing.zip", root: str | None = "thing", kind: str = "zip"
) -> Asset:
    return Asset(
        url=f"https://example.invalid/dl/{name}",
        sha256=hashlib.sha256(data).hexdigest(),
        size=len(data),
        kind=kind,
        root=root,
    )


def _tool_zip() -> bytes:
    return fakes.zip_bytes(
        {
            "thing/support/run": (b"#!/bin/sh\n", 0o100755),
            "thing/readme.txt": (b"hello", 0o100644),
        }
    )


def test_a_checksum_mismatch_installs_nothing(tmp_path: Path) -> None:
    """★ MUTATION: skip the size/sha256 check -> the target exists and the ledger has an entry
    -> RED."""
    tdir = tmp_path / "toolchain"
    good = _tool_zip()
    asset = _asset(good)
    bad = good[:-1] + bytes([good[-1] ^ 1])
    ledger = Ledger(tdir / LEDGER_NAME)
    target = tdir / "thing"
    with pytest.raises(FetchError, match="sha256"):
        install_archive(
            "thing",
            asset,
            target,
            toolchain_dir=tdir,
            ledger=ledger,
            fetcher=fakes.BytesFetcher({"thing.zip": bad}),
            verify=lambda _p: None,
            run=fakes.fake_run(),
        )
    assert not target.exists()
    assert ledger.entries == [] and not (tdir / LEDGER_NAME).exists()
    assert list(tdir.glob("**/*.part")) == []
    assert [p for p in tdir.iterdir()] == []  # staging removed too


def test_download_verified_deletes_the_partial_file(tmp_path: Path) -> None:
    asset = _asset(b"right")
    staging = tmp_path / "staging"
    with pytest.raises(FetchError):
        download_verified(asset, staging, fakes.BytesFetcher({"thing.zip": b"wrong"}))
    assert list(staging.iterdir()) == []


def test_zip_permission_bits_are_restored(tmp_path: Path) -> None:
    """Ghidra's launchers must stay executable. MUTATION: ignore external_attr -> RED."""
    archive = tmp_path / "a.zip"
    archive.write_bytes(_tool_zip())
    extract_zip(archive, tmp_path / "out")
    mode = (tmp_path / "out" / "thing" / "support" / "run").stat().st_mode
    assert mode & stat.S_IXUSR
    assert not (tmp_path / "out" / "thing" / "readme.txt").stat().st_mode & stat.S_IXUSR


@pytest.mark.parametrize(
    "members",
    [
        {"../evil": (b"x", 0o100644)},
        {"/abs/evil": (b"x", 0o100644)},
        {"thing/link": (b"/etc/passwd", 0o120777)},
    ],
)
def test_unsafe_zip_members_are_refused_and_staging_cleaned(
    tmp_path: Path, members: dict[str, tuple[bytes, int]]
) -> None:
    """MUTATION: drop the member path / link checks -> extraction succeeds -> RED."""
    data = fakes.zip_bytes({"thing/ok": (b"ok", 0o100644), **members})
    tdir = tmp_path / "toolchain"
    ledger = Ledger(tdir / LEDGER_NAME)
    with pytest.raises(FetchError):
        install_archive(
            "thing",
            _asset(data),
            tdir / "thing",
            toolchain_dir=tdir,
            ledger=ledger,
            fetcher=fakes.BytesFetcher({"thing.zip": data}),
            verify=lambda _p: None,
            run=fakes.fake_run(),
        )
    assert not (tmp_path / "evil").exists()
    assert list(tdir.iterdir()) == []
    assert ledger.entries == []


def test_install_records_pending_then_committed(tmp_path: Path) -> None:
    tdir = tmp_path / "toolchain"
    data = _tool_zip()
    ledger = Ledger(tdir / LEDGER_NAME)
    seen_states: list[str] = []

    def verify(p: Path) -> str | None:
        e = Ledger.load(tdir / LEDGER_NAME).find("thing")
        seen_states.append(e.state if e else "none")
        return None

    out = install_archive(
        "thing",
        _asset(data),
        tdir / "thing",
        toolchain_dir=tdir,
        ledger=ledger,
        fetcher=fakes.BytesFetcher({"thing.zip": data}),
        verify=verify,
        run=fakes.fake_run(),
    )
    assert (out / "support" / "run").is_file()
    assert seen_states == ["pending"]  # recorded before the check, on disk
    assert Ledger.load(tdir / LEDGER_NAME).committed("thing") is not None


def test_a_failed_post_install_check_removes_it(tmp_path: Path) -> None:
    tdir = tmp_path / "toolchain"
    data = _tool_zip()
    ledger = Ledger(tdir / LEDGER_NAME)
    with pytest.raises(FetchError, match="failed its check"):
        install_archive(
            "thing",
            _asset(data),
            tdir / "thing",
            toolchain_dir=tdir,
            ledger=ledger,
            fetcher=fakes.BytesFetcher({"thing.zip": data}),
            verify=lambda _p: "not what we wanted",
            run=fakes.fake_run(),
        )
    assert not (tdir / "thing").exists() and ledger.entries == []


def test_a_pending_entry_left_by_a_crash_is_settled(tmp_path: Path) -> None:
    """★ Interrupted between the move and the commit: the next init checks the path; a failing
    one is removed with its entry, a passing one is committed.

    MUTATION: leave pending entries alone -> the broken directory survives -> RED."""
    tdir = tmp_path / "toolchain"
    broken = tdir / "broken"
    broken.mkdir(parents=True)
    fine = tdir / "fine"
    fine.mkdir()
    ledger = Ledger(tdir / LEDGER_NAME)
    ledger.add_pending("broken", "dir", broken)
    ledger.add_pending("fine", "dir", fine)
    lines = recover_pending(
        ledger,
        {"broken": lambda _p: "half unpacked", "fine": lambda _p: None},
        toolchain_dir=tdir,
    )
    assert not broken.exists()
    assert fine.exists()
    reloaded = Ledger.load(tdir / LEDGER_NAME)
    assert reloaded.find("broken") is None
    assert reloaded.committed("fine") is not None
    assert len(lines) == 2


def test_a_pending_path_outside_the_toolchain_dir_is_never_deleted(tmp_path: Path) -> None:
    tdir = tmp_path / "toolchain"
    outside = tmp_path / "user" / "BinExport"
    outside.mkdir(parents=True)
    ledger = Ledger(tdir / LEDGER_NAME)
    ledger.add_pending("binexport", "dir", outside)
    recover_pending(ledger, {"binexport": lambda _p: "bad"}, toolchain_dir=tdir)
    assert outside.exists() and ledger.entries == []


def _tar_gz(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_tar_gz_uses_the_data_filter(tmp_path: Path) -> None:
    good = tmp_path / "good.tar.gz"
    good.write_bytes(_tar_gz({"jdk/bin/java": b"x"}))
    extract_tar_gz(good, tmp_path / "out")
    assert (tmp_path / "out" / "jdk" / "bin" / "java").is_file()
    evil = tmp_path / "evil.tar.gz"
    evil.write_bytes(_tar_gz({"../escape": b"x"}))
    with pytest.raises(FetchError):
        extract_tar_gz(evil, tmp_path / "out2")
    assert not (tmp_path / "escape").exists()


def _deb(data_members: dict[str, bytes]) -> bytes:
    import lzma

    tar = io.BytesIO()
    with tarfile.open(fileobj=tar, mode="w") as tf:
        for name, data in data_members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755
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


def test_deb_unpacks_only_the_prefix(tmp_path: Path) -> None:
    deb = tmp_path / "b.deb"
    deb.write_bytes(
        _deb(
            {
                "./opt/bindiff/bin/bindiff": b"#!/bin/sh\n",
                "./etc/opt/bindiff/bindiff.json": b"{}",
            }
        )
    )
    extract_deb(deb, tmp_path / "out", "./opt/bindiff/")
    assert (tmp_path / "out" / "opt" / "bindiff" / "bin" / "bindiff").is_file()
    assert not (tmp_path / "out" / "etc").exists()


def test_mirror_and_offline(tmp_path: Path) -> None:
    asset = _asset(b"z", name="a%2Bb.zip")
    assert source_url(asset, "https://m.example/x/") == "https://m.example/x/a+b.zip"
    (tmp_path / "a+b.zip").write_bytes(b"z")
    out = download_verified(asset, tmp_path / "st", OfflineFetcher(tmp_path))
    assert out.read_bytes() == b"z"
