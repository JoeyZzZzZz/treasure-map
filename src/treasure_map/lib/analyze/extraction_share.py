# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""One extraction per binary across the runs of one rescan.

Firmware versions share most of their binaries byte for byte, and a rescan of several runs used to
decompile each of them once per run that held it — the same work again, and not even the same
result: Ghidra's analysis is not fully deterministic, so the copies came out slightly apart.

A rescan keeps one ``ExtractionShare`` for all its runs. The first run that needs a binary extracts
it as always; each Ghidra session's outcome (its result, its JSON, its export and report) is kept,
keyed by everything that decides it. A later run that needs the same binary under the same key is
handed a copy of that outcome instead of starting a JVM: every session happens once, phase 2's
isolated re-run included, and every holder stores the same functions and the same export, under the
same session name.

The KEY is explicit: the content (sha256) and name of the file, the language it is imported under,
the budget, whether the retry runs inside and whether the larger output limit is set, and the
extraction pass, the Ghidra and the BinExport the JVM runs, and the environment it inherits. A
binary that needs another session under any of them is extracted again; the reason is logged.

A session that was cut off by the run's teardown, or that could not be started, is not kept.
"""

from __future__ import annotations

import dataclasses
import hashlib
import logging
import shutil
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# The key's fields, in order (for the log line that names what differed).
KEY_FIELDS = (
    "sha256",
    "name",
    "arch",
    "timeout",
    "retry",
    "large_payload",
    "pass_version",
    "ghidra_version",
    "extension",
    "environment",
)


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class ExtractionShare:
    """The sessions of one rescan, by key (see the module docstring). ``root`` holds the kept files;
    the caller owns it (a temporary directory removed when the rescan ends)."""

    root: Path
    _kept: dict[tuple[Any, ...], tuple[Any, dict[str, Path]]] = field(default_factory=dict)
    _seen: dict[tuple[str, str], tuple[Any, ...]] = field(default_factory=dict)
    _hashes: dict[tuple[str, int, int], str] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    sessions: int = 0  # sessions kept (run once)
    handed: int = 0  # outcomes handed to a later holder instead of a session

    def key(
        self,
        binary: Path,
        *,
        arch: str,
        timeout: int,
        retry: bool,
        large_payload: bool,
        pass_version: str,
        ghidra_version: str,
        extension: str | None,
        environment: Mapping[str, str],
    ) -> tuple[Any, ...]:
        st = binary.stat()
        ident = (str(binary), st.st_size, st.st_mtime_ns)
        with self._lock:
            digest = self._hashes.get(ident)
        if digest is None:
            digest = file_sha256(binary)
            with self._lock:
                self._hashes[ident] = digest
        return (
            digest,
            binary.name,
            arch,
            timeout,
            retry,
            large_payload,
            pass_version,
            ghidra_version,
            extension,
            tuple(sorted(environment.items())),
        )

    def get(self, key: tuple[Any, ...], binary: Path, output_dir: Path) -> Any | None:
        """A copy of the kept outcome of ``key`` for the holder of ``binary`` writing into
        ``output_dir`` (its files copied there, under the names its own session would have
        written), or None when no session of this key has run."""
        with self._lock:
            kept = self._kept.get(key)
            if kept is None:
                earlier = self._seen.get((key[0], key[1]))
                if earlier is not None and earlier != key:
                    pairs = zip(KEY_FIELDS, earlier, key, strict=True)
                    differs = [f for f, a, b in pairs if a != b]
                    logger.info(
                        "extraction share: %s extracted again (%s differs from the shared session)",
                        binary.name,
                        ", ".join(differs),
                    )
                return None
            self.handed += 1
        result, files = kept
        output_dir.mkdir(parents=True, exist_ok=True)
        moved: dict[str, Path | None] = {}
        for attr in ("output_file", "export_file", "export_report_file"):
            src = files.get(attr)
            if src is None:
                moved[attr] = None
                continue
            dest = output_dir / src.name
            shutil.copyfile(src, dest)
            moved[attr] = dest
        return dataclasses.replace(result, binary=binary, **moved)

    def put(self, key: tuple[Any, ...], result: Any) -> None:
        """Keep one session's outcome under ``key``: its result, and copies of its files (the
        caller's pipeline moves or removes the originals once it has stored them)."""
        with self._lock:
            self._seen[(key[0], key[1])] = key
            if key in self._kept:
                return
            slot = self.root / f"s{len(self._kept)}"
        slot.mkdir(parents=True, exist_ok=True)
        files: dict[str, Path] = {}
        for attr in ("output_file", "export_file", "export_report_file"):
            src = getattr(result, attr, None)
            if src is not None and Path(src).is_file():
                dest = slot / Path(src).name
                shutil.copyfile(src, dest)
                files[attr] = dest
        with self._lock:
            self._kept.setdefault(key, (result, files))
            self.sessions += 1
