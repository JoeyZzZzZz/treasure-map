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


# ── audit follow-ups ─────────────────────────────────────────────────────────────────────────


def test_a_pending_edit_never_deletes_the_file(tmp_path: Path) -> None:
    """★ An interrupted JAVA_HOME_OVERRIDE edit left a pending EDIT entry on Ghidra's
    launch.properties: recovery must never remove that file (Ghidra cannot start without it).

    MUTATION: treat an edit entry like an unfinished directory -> the file is unlinked -> RED."""
    tdir = tmp_path / "toolchain"
    props = tdir / "ghidra" / "support" / "launch.properties"
    props.parent.mkdir(parents=True)
    props.write_text("JAVA_HOME_OVERRIDE=\n")
    ledger = Ledger(tdir / LEDGER_NAME)
    ledger.add_pending(
        "ghidra_jdk_override", "edit", props, line_before="JAVA_HOME_OVERRIDE=", line_after="X"
    )
    lines = recover_pending(ledger, {}, toolchain_dir=tdir)  # no verifier at all
    assert props.is_file(), "recovery removed Ghidra's launch.properties"
    assert props.read_text() == "JAVA_HOME_OVERRIDE=\n"
    assert ledger.entries == [] and "left" in lines[0]


def test_set_override_records_before_writing_and_cleans_up_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MUTATION: keep the pending entry when the write fails -> the next run finds a pending edit
    for a line that was never written -> RED."""
    from treasure_map.lib.setup import plan
    from treasure_map.lib.setup.plan import set_override

    tdir = tmp_path / "toolchain"
    props = tdir / "g" / "support" / "launch.properties"
    props.parent.mkdir(parents=True)
    props.write_text("# x\nJAVA_HOME_OVERRIDE=\nVMARGS=-Xmx1g\n")
    ledger = Ledger(tdir / LEDGER_NAME)
    set_override(ledger, props, tmp_path / "jdk")
    assert props.read_text() == f"# x\nJAVA_HOME_OVERRIDE={tmp_path / 'jdk'}\nVMARGS=-Xmx1g\n"
    e = ledger.committed("ghidra_jdk_override")
    assert e is not None and e.extra["line_before"] == "JAVA_HOME_OVERRIDE="
    no_line = tdir / "h" / "launch.properties"
    no_line.parent.mkdir()
    no_line.write_text("VMARGS=x\n")
    ledger.remove("ghidra_jdk_override")
    with pytest.raises(FetchError):
        set_override(ledger, no_line, tmp_path / "jdk")
    assert ledger.entries == [] and no_line.read_text() == "VMARGS=x\n"
    # the write itself fails after the entry was recorded: the entry goes with it
    fresh = tdir / "k" / "launch.properties"
    fresh.parent.mkdir()
    fresh.write_text("JAVA_HOME_OVERRIDE=\n")

    def disk_full(_p: Path, _t: str) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(plan, "atomic_write_text", disk_full)
    with pytest.raises(OSError):
        set_override(ledger, fresh, tmp_path / "jdk")
    assert ledger.entries == [] and fresh.read_text() == "JAVA_HOME_OVERRIDE=\n"


def test_install_refuses_a_target_it_did_not_make(tmp_path: Path) -> None:
    """MUTATION: drop the exists() refusal -> the user's directory is overwritten -> RED."""
    tdir = tmp_path / "toolchain"
    target = tdir / "thing"
    target.mkdir(parents=True)
    (target / "theirs").write_text("keep")
    data = _tool_zip()
    with pytest.raises(Exception) as raised:
        install_archive(
            "thing",
            _asset(data),
            target,
            toolchain_dir=tdir,
            ledger=Ledger(tdir / LEDGER_NAME),
            fetcher=fakes.BytesFetcher({"thing.zip": data}),
            verify=lambda _p: None,
            run=fakes.fake_run(),
        )
    assert isinstance(raised.value, FetchError) and "already exists" in str(raised.value)
    assert (target / "theirs").read_text() == "keep"


def test_the_pending_entry_is_on_disk_before_the_move(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ A crash during the move must leave a pending entry naming the target, or the next run
    could not find what to settle.

    MUTATION: write the pending entry after the move -> no entry survives the crash -> RED."""
    from treasure_map.lib.setup import fetch

    tdir = tmp_path / "toolchain"
    data = _tool_zip()

    def crash(_src: Path, _target: Path) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(fetch, "_move", crash)
    with pytest.raises(KeyboardInterrupt):
        install_archive(
            "thing",
            _asset(data),
            tdir / "thing",
            toolchain_dir=tdir,
            ledger=Ledger(tdir / LEDGER_NAME),
            fetcher=fakes.BytesFetcher({"thing.zip": data}),
            verify=lambda _p: None,
            run=fakes.fake_run(),
        )
    e = Ledger.load(tdir / LEDGER_NAME).find("thing")
    assert e is not None and e.state == "pending" and e.path == str(tdir / "thing")


class _ResumingFetcher:
    """Serves the rest of ``data`` after whatever ``dest`` already holds (a Range request)."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.resumed_from: list[int] = []

    def fetch(self, url: str, dest: Path, *, progress: object = None) -> None:
        have = dest.stat().st_size if dest.exists() else 0
        self.resumed_from.append(have)
        with dest.open("ab") as fh:
            fh.write(self.data[have:])


def test_an_interrupted_download_resumes(tmp_path: Path) -> None:
    """MUTATION: download into the per-run staging directory -> the earlier part is never seen
    -> resumed from 0 -> RED."""
    tdir = tmp_path / "toolchain"
    data = _tool_zip()
    part = tdir / ".downloads" / "thing.zip.part"
    part.parent.mkdir(parents=True)
    part.write_bytes(data[:100])
    fetcher = _ResumingFetcher(data)
    install_archive(
        "thing",
        _asset(data),
        tdir / "thing",
        toolchain_dir=tdir,
        ledger=Ledger(tdir / LEDGER_NAME),
        fetcher=fetcher,
        verify=lambda _p: None,
        run=fakes.fake_run(),
    )
    assert fetcher.resumed_from == [100]
    assert not (tdir / ".downloads").exists()


def test_an_unfinished_binexport_outside_is_removed_only_when_provably_ours(
    tmp_path: Path,
) -> None:
    """MUTATION: ignore the recorded digest -> both copies stay (or both go) -> RED."""
    from treasure_map.lib.diff.toolchain import binexport_lib_digest

    tdir = tmp_path / "toolchain"
    ours = fakes.make_binexport(tmp_path / "s1" / "Extensions" / "BinExport")
    theirs = fakes.make_binexport(tmp_path / "s2" / "Extensions" / "BinExport", jar=b"other")
    ledger = Ledger(tdir / LEDGER_NAME)
    ledger.add_pending("binexport", "dir", ours, expect_digest=binexport_lib_digest(ours))
    recover_pending(ledger, {"binexport": lambda _p: "half"}, toolchain_dir=tdir)
    assert not ours.exists()
    ledger.add_pending("binexport", "dir", theirs, expect_digest="0" * 64)
    recover_pending(ledger, {"binexport": lambda _p: "half"}, toolchain_dir=tdir)
    assert theirs.is_dir()


def test_the_toolchain_directory_itself_is_never_removed(tmp_path: Path) -> None:
    """A tampered ledger naming the toolchain directory itself.

    MUTATION: accept the root as 'under' itself -> the whole directory goes -> RED."""
    tdir = tmp_path / "toolchain"
    (tdir / "keep").mkdir(parents=True)
    ledger = Ledger(tdir / LEDGER_NAME)
    ledger.add_pending("jdk", "dir", tdir)
    recover_pending(ledger, {"jdk": lambda _p: "bad"}, toolchain_dir=tdir)
    assert (tdir / "keep").is_dir()


def test_a_reinstall_removes_what_it_replaced(tmp_path: Path) -> None:
    """A newer pin installs a component at a new path: the old copy goes once the new one is in
    place and checked — or it would be an unrecorded directory nothing ever removes.

    MUTATION: skip removing the superseded install -> the old directory stays -> RED."""
    tdir = tmp_path / "toolchain"
    old = tdir / "thing-old"
    (old / "bin").mkdir(parents=True)
    ledger = Ledger(tdir / LEDGER_NAME)
    ledger.add_pending("thing", "dir", old)
    ledger.commit("thing")
    data = _tool_zip()
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
    assert not old.exists() and (tdir / "thing").is_dir()
    e = Ledger.load(tdir / LEDGER_NAME).committed("thing")
    assert e is not None and e.path == str(tdir / "thing")


class _ShortFetcher:
    """The connection drops: only the first ``n`` bytes arrive, without an error."""

    def __init__(self, data: bytes, n: int) -> None:
        self.data, self.n = data, n
        self.calls: list[str] = []

    def fetch(self, url: str, dest: Path, *, progress: object = None) -> None:
        self.calls.append(url)
        dest.write_bytes(self.data[: self.n])


def test_a_dropped_connection_keeps_the_part_for_the_next_run(tmp_path: Path) -> None:
    """MUTATION: treat a short download as a mismatch (delete it) -> RED."""
    data = _tool_zip()
    staging = tmp_path / "dl"
    outcome = ""
    try:
        download_verified(_asset(data), staging, _ShortFetcher(data, 100))
    except FetchError as exc:
        outcome = str(exc)
    assert "run again to resume" in outcome
    assert (staging / "thing.zip.part").is_file()
    assert (staging / "thing.zip.part").stat().st_size == 100


class _CountingFetcher:
    """Records the call and leaves the file as it is (a server that has nothing more)."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def fetch(self, url: str, dest: Path, *, progress: object = None) -> None:
        self.calls.append(url)


def test_a_complete_part_is_verified_without_fetching(tmp_path: Path) -> None:
    """An interrupted run left the whole file: asking for the rest gets HTTP 416 forever.

    MUTATION: always fetch -> RED."""
    data = _tool_zip()
    staging = tmp_path / "dl"
    staging.mkdir()
    (staging / "thing.zip.part").write_bytes(data)
    fetcher = _CountingFetcher()
    out = download_verified(_asset(data), staging, fetcher)
    assert fetcher.calls == []
    assert out.read_bytes() == data


class _Resp:
    def __init__(self, status: int, headers: dict[str, str], body: bytes) -> None:
        self.status, self.headers, self._body = status, headers, io.BytesIO(body)

    def read(self, n: int = -1) -> bytes:
        return self._body.read(n)

    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *_a: object) -> None:
        return None


def test_416_on_a_resume_is_left_to_the_size_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MUTATION: treat HTTP 416 as a failed download -> RED."""
    import urllib.error

    from treasure_map.lib.setup.fetch import UrlFetcher

    def _416(req: object, timeout: float = 0) -> None:
        raise urllib.error.HTTPError("https://x/a", 416, "Range Not Satisfiable", {}, None)  # type: ignore[arg-type]

    monkeypatch.setattr("urllib.request.urlopen", _416)
    part = tmp_path / "a.part"
    part.write_bytes(b"12345")
    outcome = "ok"
    try:
        UrlFetcher().fetch("https://x/a", part)
    except FetchError as exc:
        outcome = str(exc)
    assert outcome == "ok" and part.read_bytes() == b"12345"


def test_a_resume_at_the_wrong_offset_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MUTATION: append whatever a 206 sends -> the file is corrupt -> RED."""
    from treasure_map.lib.setup.fetch import UrlFetcher

    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda req, timeout=0: _Resp(206, {"Content-Range": "bytes 0-9/10"}, b"0123456789"),
    )
    part = tmp_path / "a.part"
    part.write_bytes(b"12345")
    outcome = "ok"
    try:
        UrlFetcher().fetch("https://x/a", part)
    except FetchError as exc:
        outcome = str(exc)
    assert "wrong offset" in outcome and not part.exists()


def test_a_broken_managed_install_is_repaired(tmp_path: Path) -> None:
    """The ledger records tmap's own copy at the target, and it no longer checks out: init
    replaces it instead of claiming tmap never installed it.

    MUTATION: refuse any existing target -> RED."""
    tdir = tmp_path / "toolchain"
    target = tdir / "thing"
    (target / "support").mkdir(parents=True)  # broken: the launcher is gone
    ledger = Ledger(tdir / LEDGER_NAME)
    ledger.add_pending("thing", "dir", target)
    ledger.commit("thing")
    data = _tool_zip()
    outcome = "ok"
    try:
        install_archive(
            "thing",
            _asset(data),
            target,
            toolchain_dir=tdir,
            ledger=ledger,
            fetcher=fakes.BytesFetcher({"thing.zip": data}),
            verify=lambda p: None if (p / "support" / "run").is_file() else "no launcher",
            run=fakes.fake_run(),
        )
    except FetchError as exc:
        outcome = str(exc)
    assert outcome == "ok"
    assert (target / "support" / "run").is_file()
    assert ledger.committed("thing") is not None
    assert [p.name for p in tdir.iterdir() if p.name.startswith(".staging-")] == []


def test_an_unrecorded_existing_target_is_still_refused(tmp_path: Path) -> None:
    tdir = tmp_path / "toolchain"
    target = tdir / "thing"
    target.mkdir(parents=True)
    (target / "mine.txt").write_text("mine")
    data = _tool_zip()
    with pytest.raises(FetchError, match="did not record"):
        install_archive(
            "thing",
            _asset(data),
            target,
            toolchain_dir=tdir,
            ledger=Ledger(tdir / LEDGER_NAME),
            fetcher=fakes.BytesFetcher({"thing.zip": data}),
            verify=lambda _p: None,
            run=fakes.fake_run(),
        )
    assert (target / "mine.txt").read_text() == "mine"


class _Hdiutil:
    """A fake runner for the dmg steps; ``detach_rc`` answers each plain detach in turn."""

    def __init__(
        self, *, attach_ok: bool = True, detach_rc: tuple[int, ...] = (0,), force_rc: int = 0
    ):
        from treasure_map.lib.setup.discover import RunResult

        self.RunResult = RunResult
        self.attach_ok, self.detach_rc, self.force_rc = attach_ok, list(detach_rc), force_rc
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], *, cwd: object = None, timeout: float = 0) -> object:
        self.calls.append(list(argv))
        if argv[:2] == ["hdiutil", "attach"]:
            if not self.attach_ok:
                return None  # timed out: the image may be mounted anyway
            (Path(argv[-2]) / "BinDiff.pkg").write_bytes(b"pkg")
            return self.RunResult(0, "", "")
        if argv[:2] == ["hdiutil", "detach"]:
            rc = (
                self.force_rc
                if "-force" in argv
                else (self.detach_rc.pop(0) if self.detach_rc else 16)
            )
            return self.RunResult(rc, "", "")
        if argv[0] == "pkgutil":
            (Path(argv[-1]) / "Payload" / "BinDiff.app").mkdir(parents=True)
            return self.RunResult(0, "", "")
        if argv[0] == "ditto":
            Path(argv[-1]).mkdir(parents=True)
            return self.RunResult(0, "", "")
        return self.RunResult(1, "", "")


def test_a_timed_out_attach_that_mounted_is_still_detached(tmp_path: Path) -> None:
    """MUTATION: detach only after a successful attach -> the mount stays -> RED."""
    from treasure_map.lib.setup.fetch import extract_dmg_pkg

    run = _Hdiutil(attach_ok=False, detach_rc=(16, 16), force_rc=0)
    with pytest.raises(FetchError, match="attach failed"):
        extract_dmg_pkg(tmp_path / "b.dmg", tmp_path / "out", "BinDiff.app", run, lambda _p: True)
    detaches = [c for c in run.calls if c[:2] == ["hdiutil", "detach"]]
    assert detaches and "-force" in detaches[-1]


def test_a_mount_that_will_not_detach_is_reported_with_the_command(tmp_path: Path) -> None:
    """MUTATION: ignore what detach returns -> the image stays mounted silently -> RED."""
    from treasure_map.lib.setup.fetch import extract_dmg_pkg

    run = _Hdiutil(detach_rc=(16, 16), force_rc=16)
    outcome = "ok"
    try:
        extract_dmg_pkg(tmp_path / "b.dmg", tmp_path / "out", "BinDiff.app", run, lambda _p: True)
    except FetchError as exc:
        outcome = str(exc)
    assert "still mounted" in outcome and "hdiutil detach -force" in outcome
