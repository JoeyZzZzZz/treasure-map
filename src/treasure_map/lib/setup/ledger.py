# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The install ledger: what ``tmap init`` put on this machine, and so what ``tmap uninstall`` may
take away (``~/.treasure-map/toolchain/installed.json``).

An entry is written ``pending`` (with its target path) BEFORE the install moves into place, and
turned ``committed`` only after the installed copy passes the same check discovery applies. An
interrupted install therefore always leaves a pending entry naming what to verify or remove — never
an unrecorded directory and never a recorded one that was not checked.

Nothing outside the ledger is ever removed, even when config.yaml points at it.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from treasure_map.lib.errors import ConfigError

State = Literal["pending", "committed"]
Kind = Literal["dir", "file", "edit"]

LEDGER_NAME = "installed.json"


@dataclass
class Entry:
    id: str
    state: State
    kind: Kind
    path: str
    extra: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "state": self.state,
            "kind": self.kind,
            "path": self.path,
            **self.extra,
        }

    @classmethod
    def from_json(cls, raw: Any) -> Entry:
        if not isinstance(raw, dict):
            raise ConfigError("ledger: an entry is not an object")
        for key in ("id", "state", "kind", "path"):
            if not isinstance(raw.get(key), str):
                raise ConfigError(f"ledger: an entry has no {key}")
        if raw["state"] not in ("pending", "committed"):
            raise ConfigError(f"ledger: unknown state {raw['state']!r}")
        if raw["kind"] not in ("dir", "file", "edit"):
            raise ConfigError(f"ledger: unknown kind {raw['kind']!r}")
        extra = {k: v for k, v in raw.items() if k not in ("id", "state", "kind", "path")}
        return cls(raw["id"], raw["state"], raw["kind"], raw["path"], extra)


class Ledger:
    def __init__(self, path: Path, entries: list[Entry] | None = None) -> None:
        self.path = path
        self.entries: list[Entry] = list(entries or [])

    @classmethod
    def load(cls, path: Path) -> Ledger:
        if not path.exists():
            return cls(path)
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError) as exc:
            raise ConfigError(f"ledger {path} is unreadable: {exc}") from exc
        if not isinstance(data, dict) or data.get("schema") != 1:
            raise ConfigError(f"ledger {path}: schema is not 1")
        raw = data.get("entries")
        if not isinstance(raw, list):
            raise ConfigError(f"ledger {path}: no entries list")
        return cls(path, [Entry.from_json(e) for e in raw])

    def save(self) -> None:
        """Atomic: a temporary file in the same directory, then ``os.replace``."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        body = json.dumps({"schema": 1, "entries": [e.to_json() for e in self.entries]}, indent=2)
        fd, tmp = tempfile.mkstemp(prefix=".installed-", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(body + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def find(self, entry_id: str) -> Entry | None:
        return next((e for e in self.entries if e.id == entry_id), None)

    def committed(self, entry_id: str) -> Entry | None:
        e = self.find(entry_id)
        return e if e is not None and e.state == "committed" else None

    def add_pending(self, entry_id: str, kind: Kind, path: Path, **extra: Any) -> Entry:
        self.entries = [e for e in self.entries if e.id != entry_id]
        entry = Entry(entry_id, "pending", kind, str(path), dict(extra))
        self.entries.append(entry)
        self.save()
        return entry

    def commit(self, entry_id: str, **extra: Any) -> None:
        e = self.find(entry_id)
        if e is None:
            raise ConfigError(f"ledger: no entry {entry_id!r} to commit")
        e.state = "committed"
        e.extra.update(extra)
        self.save()

    def remove(self, entry_id: str) -> None:
        self.entries = [e for e in self.entries if e.id != entry_id]
        self.save()

    def pending(self) -> list[Entry]:
        return [e for e in self.entries if e.state == "pending"]


def strictly_under(path: Path, root: Path) -> bool:
    """``path`` resolves to something INSIDE ``root`` — never ``root`` itself (a tampered ledger
    naming the toolchain directory must not get the whole directory removed)."""
    try:
        real = Path(os.path.realpath(path))
        base = Path(os.path.realpath(root))
    except OSError:
        return False
    return real != base and real.is_relative_to(base)


def atomic_write_text(path: Path, text: str) -> None:
    """Replace ``path``'s content in one step (temporary file in the same directory, fsync,
    ``os.replace``), keeping its permission bits: an interruption leaves the old file or the new
    one, never neither."""
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o644
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
