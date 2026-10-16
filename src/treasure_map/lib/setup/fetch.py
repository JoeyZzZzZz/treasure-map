# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Download a pinned archive, verify it, and unpack it — in that order, and only in that order.

A download lands in ``<file>.part`` inside a staging directory and is resumed with a ``Range``
request when the server allows it. Its size and sha256 are checked against the lock before
anything reads it as an archive: a short file is kept for the next run to resume, a complete one
from an interrupted run is verified without fetching again, and a mismatch deletes it — a file the
server sent whole but shorter than the lock included, since no later run could resume it. Unpacking
refuses absolute paths, ``..``, anything that resolves outside the destination, and link entries;
zip permission bits are restored (Ghidra's launchers and decompiler must stay executable).

The network sits behind the ``Fetcher`` protocol so a test (or ``--offline DIR``) supplies the
bytes instead.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import sys
import tarfile
import uuid
import zipfile
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import IO, Protocol

from treasure_map.lib.errors import TreasureMapError
from treasure_map.lib.setup.discover import Runner
from treasure_map.lib.setup.ledger import Entry, Ledger, strictly_under
from treasure_map.lib.setup.toolchain_lock import Asset

STAGING_PREFIX = ".staging-"


class FetchError(TreasureMapError):
    """A download or unpack failed; nothing unverified was installed."""


Progress = Callable[[int, int], None]  # (bytes so far, total or 0)


class Fetcher(Protocol):
    def fetch(self, url: str, dest: Path, *, progress: Progress | None = None) -> bool:
        """Write the resource at ``url`` to ``dest``, resuming from ``dest``'s current size when
        it exists and the source allows it (else starting over).

        True when the source declared where the resource ends and ``dest`` reaches that end: what
        is there is all the source has, not a transfer that stopped short. False when that is not
        known."""
        ...


class UrlFetcher:
    """Plain HTTPS via urllib (which honours ``HTTPS_PROXY``)."""

    def __init__(self, timeout: float = 60.0) -> None:
        self.timeout = timeout

    def fetch(self, url: str, dest: Path, *, progress: Progress | None = None) -> bool:
        import http.client
        import urllib.error
        import urllib.request

        have = dest.stat().st_size if dest.exists() else 0
        req = urllib.request.Request(url, headers={"User-Agent": "tmap-init"})  # noqa: S310
        if have:
            req.add_header("Range", f"bytes={have}-")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                status = getattr(resp, "status", 200)
                length = resp.headers.get("Content-Length")
                body = int(length) if length and length.isdigit() else None
                if status == 206:
                    content_range = str(resp.headers.get("Content-Range", ""))
                    if not content_range.startswith(f"bytes {have}-"):
                        dest.unlink(missing_ok=True)
                        raise FetchError(f"download failed: {url}: resumed at the wrong offset")
                    mode = "ab"
                    whole = content_range.rpartition("/")[2]  # "bytes a-b/N": N, or "*"
                    end = int(whole) if whole.isdigit() else None
                else:
                    mode, have = "wb", 0
                    end = body  # a whole response: the resource is its body
                total = have + body if body is not None else 0
                with dest.open(mode) as out:
                    size = _copy(resp, out, have, total, progress)
        except urllib.error.HTTPError as exc:
            if exc.code == 416 and have:
                return True  # nothing past what is here: the source's resource ends within it
            raise FetchError(f"download failed: {url}: {exc}") from exc
        except (OSError, http.client.HTTPException) as exc:
            raise FetchError(f"download failed: {url}: {exc}") from exc
        # urllib returns a short body without an error when the connection drops, so the bytes
        # are counted against what the server declared
        return end is not None and size == end


class OfflineFetcher:
    """``--offline DIR``: the archive is ``DIR/<file name>``."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def fetch(self, url: str, dest: Path, *, progress: Progress | None = None) -> bool:
        from urllib.parse import unquote, urlparse

        src = self.directory / unquote(PurePosixPath(urlparse(url).path).name)
        if not src.is_file():
            raise FetchError(f"--offline: {src} not found")
        with src.open("rb") as fh, dest.open("wb") as out:
            _copy(fh, out, 0, src.stat().st_size, progress)
        return True  # the whole file was copied


def _copy(src: IO[bytes], out: IO[bytes], have: int, total: int, progress: Progress | None) -> int:
    """Append ``src`` to ``out``; returns the size reached (``have`` plus what was copied)."""
    while True:
        chunk = src.read(1 << 20)
        if not chunk:
            break
        out.write(chunk)
        have += len(chunk)
        if progress is not None:
            progress(have, total)
    return have


def source_url(asset: Asset, mirror: str | None) -> str:
    """The URL to fetch: the lock's, or ``--mirror BASE`` + the same file name."""
    if mirror:
        return mirror.rstrip("/") + "/" + asset.file_name
    return asset.url


def stderr_progress(label: str) -> Progress:
    """A progress line on stderr: rewritten in place on a terminal, every 10% otherwise."""
    tty = sys.stderr.isatty()
    last = [-1]

    def report(done: int, total: int) -> None:
        if total <= 0:
            return
        pct = min(100, done * 100 // total)
        if tty:
            if pct != last[0]:
                sys.stderr.write(f"\r  {label}: {pct:3d}% ({done >> 20} / {total >> 20} MB)")
                if pct == 100:
                    sys.stderr.write("\n")
                sys.stderr.flush()
        elif pct // 10 != last[0] // 10 or (pct == 100 and last[0] != 100):
            sys.stderr.write(f"  {label}: {pct}%\n")
        last[0] = pct

    return report


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download_verified(
    asset: Asset,
    staging: Path,
    fetcher: Fetcher,
    *,
    mirror: str | None = None,
    progress: Progress | None = None,
) -> Path:
    """Fetch ``asset`` into ``staging`` and return the verified file — the bytes are never opened
    as an archive before that. A ``.part`` already as long as the asset (an interrupted run) is
    checked without fetching; a longer one is deleted first. A short result whose transfer stopped
    (the connection dropped) is kept for the next run to resume, with FetchError. A size or sha256
    mismatch deletes it, with FetchError — a short file the source declared complete included:
    the source has no more to give, so resuming it would fail the same way on every run."""
    staging.mkdir(parents=True, exist_ok=True)
    part = staging / (asset.file_name + ".part")
    url = source_url(asset, mirror)
    if part.is_file() and part.stat().st_size > asset.size:
        part.unlink()
    complete = False
    if not (part.is_file() and part.stat().st_size == asset.size):
        complete = fetcher.fetch(url, part, progress=progress)
    if not part.is_file():
        raise FetchError(f"download produced no file: {url}")
    size = part.stat().st_size
    if size < asset.size and not complete:
        raise FetchError(
            f"{asset.file_name}: download stopped at {size} of {asset.size} bytes; "
            "run again to resume it"
        )
    digest = sha256_file(part)
    if size != asset.size or digest != asset.sha256:
        part.unlink(missing_ok=True)
        raise FetchError(
            f"{asset.file_name}: got {size} bytes sha256 {digest}; "
            f"pinned {asset.size} bytes sha256 {asset.sha256} — deleted, nothing installed"
        )
    final = staging / asset.file_name
    os.replace(part, final)
    return final


# ── unpacking ────────────────────────────────────────────────────────────────────────────────


def _safe_target(dest: Path, name: str) -> Path:
    """Where member ``name`` lands under ``dest``, or FetchError when it would escape."""
    pure = PurePosixPath(name)
    if pure.is_absolute() or name.startswith(("/", "\\")) or ".." in pure.parts:
        raise FetchError(f"archive member {name!r} has an unsafe path")
    target = (dest / Path(*pure.parts)).resolve() if pure.parts else dest.resolve()
    root = dest.resolve()
    if target != root and not target.is_relative_to(root):
        raise FetchError(f"archive member {name!r} resolves outside the destination")
    return target


def extract_zip(archive: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as zf:
        infos = zf.infolist()
        for info in infos:  # check every member before writing any
            _safe_target(dest, info.filename)
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise FetchError(f"archive member {info.filename!r} is a link")
        for info in infos:
            target = _safe_target(dest, info.filename)
            mode = (info.external_attr >> 16) & 0o777
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target.open("wb") as out:
                shutil.copyfileobj(src, out, 1 << 20)
            if mode:
                os.chmod(target, mode)


def _require_data_filter() -> None:
    if not hasattr(tarfile, "data_filter"):
        raise FetchError("Python >= 3.11.4 required (tarfile extraction filters)")


def extract_tar_gz(archive: Path, dest: Path) -> None:
    """The ``data`` extraction filter refuses absolute paths, ``..``, members landing outside
    ``dest`` and links pointing outside it (a macOS JDK carries one relative link inside itself)."""
    _require_data_filter()
    dest.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(archive, mode="r:gz") as tf:
            tf.extractall(dest, filter="data")
    except tarfile.TarError as exc:
        raise FetchError(f"{archive.name}: {exc}") from exc


def _ar_members(data: bytes) -> dict[str, bytes]:
    if not data.startswith(b"!<arch>\n"):
        raise FetchError("not an ar archive")
    out: dict[str, bytes] = {}
    pos = 8
    while pos + 60 <= len(data):
        header = data[pos : pos + 60]
        name = header[:16].decode(errors="replace").strip().rstrip("/")
        try:
            size = int(header[48:58].decode().strip())
        except ValueError as exc:
            raise FetchError("malformed ar header") from exc
        if header[58:60] != b"`\n":
            raise FetchError("malformed ar header")
        start = pos + 60
        out[name] = data[start : start + size]
        pos = start + size + (size % 2)
    return out


def extract_deb(archive: Path, dest: Path, member_prefix: str) -> None:
    """Only the members under ``member_prefix`` of the deb's ``data.tar.xz``, through the same
    ``data`` extraction filter."""
    import io
    import lzma

    _require_data_filter()
    members = _ar_members(archive.read_bytes())
    data = members.get("data.tar.xz")
    if data is None:
        raise FetchError(f"{archive.name}: no data.tar.xz")
    dest.mkdir(parents=True, exist_ok=True)
    prefix = member_prefix
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:xz") as tf:
            chosen = [
                m
                for m in tf.getmembers()
                if m.name.startswith(prefix) or m.name.startswith(prefix.removeprefix("./"))
            ]
            if not chosen:
                raise FetchError(f"{archive.name}: nothing under {member_prefix}")
            tf.extractall(dest, members=chosen, filter="data")
    except (tarfile.TarError, EOFError, lzma.LZMAError) as exc:
        raise FetchError(f"{archive.name}: {exc}") from exc


def _detach(mnt: Path, run: Runner, mounted: Callable[[Path], bool]) -> bool:
    """Detach the image at ``mnt``: twice as asked (Spotlight often holds a fresh mount busy),
    then with ``-force``. True once it is no longer mounted."""
    for argv in (
        ["hdiutil", "detach", str(mnt)],
        ["hdiutil", "detach", str(mnt)],
        ["hdiutil", "detach", "-force", str(mnt)],
    ):
        res = run(argv, timeout=120)
        if (res is not None and res.returncode == 0) or not mounted(mnt):
            return True
    return False


def extract_dmg_pkg(
    archive: Path,
    dest: Path,
    app: str,
    run: Runner,
    mounted: Callable[[Path], bool] = os.path.ismount,
) -> None:
    """macOS only: mount the dmg read-only, expand its installer package, copy the one ``app``
    bundle out, and always detach — an attach that timed out may still have mounted it, and a
    detach that fails is retried, then forced, then reported with the command to run."""
    work = dest.parent / f"dmg-{uuid.uuid4().hex[:8]}"
    mnt = work / "mnt"
    pkg = work / "pkg"
    mnt.mkdir(parents=True)
    attached = False
    try:
        res = run(
            [
                "hdiutil",
                "attach",
                "-nobrowse",
                "-readonly",
                "-noautoopen",
                "-mountpoint",
                str(mnt),
                str(archive),
            ],
            timeout=300,
        )
        if res is None or res.returncode != 0:
            attached = mounted(mnt)
            raise FetchError(f"hdiutil attach failed for {archive.name}")
        attached = True
        pkgs = sorted(mnt.glob("*.pkg"))
        if len(pkgs) != 1:
            raise FetchError(f"{archive.name}: expected one installer package, found {len(pkgs)}")
        res = run(["pkgutil", "--expand-full", str(pkgs[0]), str(pkg)], timeout=300)
        if res is None or res.returncode != 0:
            raise FetchError(f"pkgutil --expand-full failed for {pkgs[0].name}")
        apps = sorted(pkg.glob(f"**/{app}"))
        if len(apps) != 1:
            raise FetchError(f"{archive.name}: expected one {app}, found {len(apps)}")
        dest.mkdir(parents=True, exist_ok=True)
        res = run(["ditto", str(apps[0]), str(dest / app)], timeout=300)
        if res is None or res.returncode != 0:
            raise FetchError(f"ditto failed copying {app}")
    finally:
        stuck = attached and not _detach(mnt, run, mounted)
        if not stuck:
            shutil.rmtree(work, ignore_errors=True)
    if stuck:
        raise FetchError(
            f"{archive.name} is still mounted at {mnt}; run: hdiutil detach -force {mnt}"
        )


def unpack(asset: Asset, archive: Path, dest: Path, run: Runner) -> None:
    if asset.kind == "zip":
        extract_zip(archive, dest)
    elif asset.kind == "tar.gz":
        extract_tar_gz(archive, dest)
    elif asset.kind == "deb":
        extract_deb(archive, dest, asset.member_prefix or "./")
    elif asset.kind == "dmg-pkg":
        extract_dmg_pkg(archive, dest, asset.app or "", run)
    else:
        raise FetchError(f"unknown archive kind {asset.kind!r}")


# ── staging ──────────────────────────────────────────────────────────────────────────────────


def new_staging(toolchain_dir: Path) -> Path:
    path = toolchain_dir / f"{STAGING_PREFIX}{uuid.uuid4().hex}"
    path.mkdir(parents=True)
    return path


def sweep_staging(toolchain_dir: Path) -> list[Path]:
    """Delete staging directories a previous, interrupted init left behind."""
    removed: list[Path] = []
    if not toolchain_dir.is_dir():
        return removed
    for p in sorted(toolchain_dir.glob(f"{STAGING_PREFIX}*")):
        if p.is_dir() and not p.is_symlink():
            shutil.rmtree(p, ignore_errors=True)
            removed.append(p)
    return removed


# ── install: staging -> pending ledger entry -> move into place -> verify -> committed ───────


def _move(src: Path, target: Path) -> None:
    import errno

    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.replace(src, target)
    except OSError as exc:
        if exc.errno != errno.EXDEV:
            raise
        shutil.move(str(src), str(target))  # another filesystem: the pending entry covers it


DOWNLOADS = ".downloads"


def install_archive(
    entry_id: str,
    asset: Asset,
    target: Path,
    *,
    toolchain_dir: Path,
    ledger: Ledger,
    fetcher: Fetcher,
    verify: Callable[[Path], str | None],
    run: Runner,
    mirror: str | None = None,
    progress: Progress | None = None,
    extra: dict[str, object] | None = None,
    pending_extra: Callable[[Path], dict[str, object]] | None = None,
) -> Path:
    """Download, verify and unpack ``asset``, then move its top directory to ``target``.

    Order is what makes it safe to interrupt: the ledger records ``target`` as pending BEFORE the
    move (with ``pending_extra(unpacked)`` — what lets a later run recognise this very copy), the
    installed copy is checked with ``verify`` (None = usable), and only then is the entry
    committed. A failed check removes ``target`` and the entry. The staging directory is removed
    on every path out, Ctrl-C included. The download itself sits in ``.downloads/`` until it is
    verified, so an interrupted download resumes where it stopped on the next run.

    An existing ``target`` is replaced only when it is tmap's own copy of this component (the
    ledger records it at this path and it is provably tmap's — a broken managed install being
    repaired), and only once the new copy is unpacked; anything else there is refused."""
    # A newer pin replacing an older install of the same component: the entry is rewritten below,
    # so the old path is remembered here and removed once the new copy is in place and checked —
    # never left behind unrecorded, never removed before its replacement works.
    previous = ledger.committed(entry_id)
    if target.exists() or target.is_symlink():
        if previous is None or Path(previous.path) != target:
            raise FetchError(f"{target} already exists and tmap did not record installing it")
        if not _provably_ours(previous, toolchain_dir):
            raise FetchError(
                f"{target} is where tmap installed {entry_id}, but it changed since; not replaced"
            )
    staging = new_staging(toolchain_dir)
    try:
        archive = download_verified(
            asset, toolchain_dir / DOWNLOADS, fetcher, mirror=mirror, progress=progress
        )
        unpacked = staging / "unpacked"
        try:
            unpack(asset, archive, unpacked, run)
        finally:
            archive.unlink(missing_ok=True)
        src = unpacked / asset.root if asset.root else unpacked
        if not src.is_dir():
            raise FetchError(f"{asset.file_name} has no {asset.root or 'content'}/ at its top")
        recognise = pending_extra(src) if pending_extra is not None else {}
        if target.exists():  # tmap's own copy, failing its check: out of the way, gone with staging
            _move(target, staging / "replaced")
        ledger.add_pending(
            entry_id,
            "dir",
            target,
            source_sha256=asset.sha256,
            **dict(extra or {}),
            **recognise,
        )
        _move(src, target)
        why = verify(target)
        if why is not None:
            shutil.rmtree(target, ignore_errors=True)
            ledger.remove(entry_id)
            raise FetchError(f"installed {entry_id} at {target} failed its check: {why}")
        ledger.commit(entry_id)
        if previous is not None and Path(previous.path) != target:
            remove_superseded(previous, toolchain_dir)
        return target
    finally:
        shutil.rmtree(staging, ignore_errors=True)
        downloads = toolchain_dir / DOWNLOADS
        if downloads.is_dir() and not any(downloads.iterdir()):
            downloads.rmdir()


def _provably_ours(entry: Entry, toolchain_dir: Path) -> bool:
    """Whether the path ``entry`` records is still tmap's: strictly under the toolchain directory,
    or (BinExport in a user's Ghidra) a directory whose jars hash to what tmap recorded."""
    from treasure_map.lib.diff.toolchain import binexport_lib_digest

    path = Path(entry.path)
    if path.is_symlink():
        return False
    recorded = entry.extra.get("lib_digest")
    return strictly_under(path, toolchain_dir) or (
        entry.id == "binexport"
        and path.is_dir()
        and isinstance(recorded, str)
        and binexport_lib_digest(path) == recorded
    )


def remove_superseded(entry: Entry, toolchain_dir: Path) -> bool:
    """Remove the install a newer one replaced — only when it is provably tmap's: strictly under
    the toolchain directory, or (BinExport in a user's Ghidra) a copy whose jars still hash to what
    tmap recorded. True when it was removed."""
    path = Path(entry.path)
    if not path.exists() or path.is_symlink():
        return False
    if not _provably_ours(entry, toolchain_dir):
        return False
    if path.is_dir():
        shutil.rmtree(path, ignore_errors=True)
    else:
        path.unlink(missing_ok=True)
    return True


def recover_pending(
    ledger: Ledger,
    verifiers: dict[str, Callable[[Path], str | None]],
    *,
    toolchain_dir: Path,
) -> list[str]:
    """Settle the entries an interrupted run left pending. Returns report lines.

    * An entry whose path passes its check is committed.
    * An EDIT entry (a line tmap changes inside a file) is never deleted: the file is not tmap's
      to remove. Applied -> committed; otherwise the entry is dropped and the file left as is.
    * A directory strictly under ``toolchain_dir`` that fails its check is removed with its entry.
    * Elsewhere (BinExport in a user's Ghidra settings), only a copy whose jars still hash to what
      was recorded before the move is removed — else it is left in place and reported."""
    from treasure_map.lib.diff.toolchain import binexport_lib_digest

    lines: list[str] = []
    for entry in list(ledger.pending()):
        path = Path(entry.path)
        check = verifiers.get(entry.id)
        why = "no check for it" if check is None else (check(path) if path.exists() else "absent")
        if why is None:
            ledger.commit(entry.id)
            lines.append(f"recovered {entry.id} at {path} (interrupted run verified)")
            continue
        if entry.kind == "edit":
            ledger.remove(entry.id)
            lines.append(f"left {path} as it is: tmap's edit there was not completed ({why})")
            continue
        expect = entry.extra.get("expect_digest")
        ours_outside = (
            isinstance(expect, str)
            and path.is_dir()
            and not path.is_symlink()
            and binexport_lib_digest(path) == expect
        )
        if path.exists() and (strictly_under(path, toolchain_dir) or ours_outside):
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path, ignore_errors=True)
            else:
                path.unlink(missing_ok=True)
            lines.append(f"removed unfinished {entry.id} at {path} ({why})")
        elif path.exists():
            lines.append(
                f"left {path} in place: an unfinished {entry.id} tmap cannot prove is its own"
            )
        ledger.remove(entry.id)
    return lines
