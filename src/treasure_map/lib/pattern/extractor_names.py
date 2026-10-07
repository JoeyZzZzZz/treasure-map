# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Read side of the extractor name registry (``analyze/ghidra/extractor_names.tsv``).

The Ghidra extraction pass builds every callee-name list it recognises — command and format-string
sinks with their key argument, buffer writers, printf-family writer format positions, tokenizers,
nvram accessors, shell-forwarding sinks — from that one file at run time. This module parses the
SAME file, by the same rules, so the read side can derive its own lists from it or check them
against it. Two hand-kept copies of a name list drift silently: a writer the extractor learns that
the read side never hears of, or the reverse. One file, read by both, is what stops that.

Read at hunt time; it is not an extraction step and is not part of the extraction fingerprint (the
TSV itself is). The parse is strict and fails loudly (``RegistryError``): ``validate_registry`` is
run once before any extraction starts, so a malformed file stops a scan up front instead of failing
every binary one JVM at a time.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

REGISTRY_PATH: Path = (
    Path(__file__).resolve().parents[1] / "analyze" / "ghidra" / ("extractor_names.tsv")
)

HEADER: tuple[str, ...] = (
    "name",
    "role",
    "op",
    "key_idx",
    "name_idx",
    "val_idx",
    "fmt_idx",
    "returns_value",
    "notes",
)

ROLES: frozenset[str] = frozenset(
    {"sink_cmd", "sink_fmt", "writer", "writer_fmt", "nvram", "tokenizer", "forward_cmd"}
)
NVRAM_OPS: frozenset[str] = frozenset({"read", "write", "commit", "getall"})

_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class RegistryError(ValueError):
    """The registry file is missing or does not follow its format. Never recovered from."""


@dataclass(frozen=True)
class NvramSpec:
    """One nvram accessor. Index fields are 0-based argument positions, -1 when not applicable.

    ``returns_value`` is True for a read that returns the stored value, False for a read that
    returns a predicate about it, and None for write / commit / getall."""

    op: str
    key_idx: int
    name_idx: int
    val_idx: int
    returns_value: bool | None


@dataclass(frozen=True)
class ExtractorNames:
    """Every name list the extractor recognises, grouped by registry role."""

    sink_cmd: Mapping[str, int]
    sink_fmt: Mapping[str, int]
    writer: frozenset[str]
    writer_fmt: Mapping[str, int]
    tokenizer: frozenset[str]
    forward_cmd: frozenset[str]
    nvram: Mapping[str, NvramSpec]

    @property
    def writers(self) -> frozenset[str]:
        """Every buffer writer the extractor reads a stack buffer's fill from: plain writers plus
        the printf-family ones (a ``writer_fmt`` row is a writer whose format position is known)."""
        return self.writer | frozenset(self.writer_fmt)

    @property
    def nvram_value_getters(self) -> frozenset[str]:
        """nvram reads that RETURN the stored value — a value source. Predicate reads excluded."""
        return frozenset(
            n for n, s in self.nvram.items() if s.op == "read" and s.returns_value is True
        )


def _int_cell(cell: str, column: str, lineno: int) -> int:
    if cell == "":
        return -1
    try:
        return int(cell)
    except ValueError:
        raise RegistryError(f"line {lineno}: {column} must be an integer, got {cell!r}") from None


def _bool_cell(cell: str, lineno: int) -> bool | None:
    if cell == "":
        return None
    if cell == "true":
        return True
    if cell == "false":
        return False
    raise RegistryError(f"line {lineno}: returns_value must be true/false/empty, got {cell!r}")


def parse_registry(text: str) -> ExtractorNames:
    """Parse registry text. Raises ``RegistryError`` on anything outside the format.

    The rules are mirrored one for one by ExportFunctions.java (``loadRegistry``); a file this
    accepts the extractor accepts, and the reverse."""
    sink_cmd: dict[str, int] = {}
    sink_fmt: dict[str, int] = {}
    writer: set[str] = set()
    writer_fmt: dict[str, int] = {}
    tokenizer: set[str] = set()
    forward_cmd: set[str] = set()
    nvram: dict[str, NvramSpec] = {}
    seen: set[tuple[str, str]] = set()
    header_seen = False

    for lineno, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        cells = raw.split("\t")
        if not header_seen:
            if tuple(cells) != HEADER:
                raise RegistryError(f"line {lineno}: header must be {HEADER}, got {tuple(cells)}")
            header_seen = True
            continue
        if len(cells) > len(HEADER):
            raise RegistryError(f"line {lineno}: {len(cells)} cells, at most {len(HEADER)}")
        cells = cells + [""] * (len(HEADER) - len(cells))
        name, role, op = cells[0], cells[1], cells[2]
        if not _NAME_RE.fullmatch(name):
            raise RegistryError(f"line {lineno}: name {name!r} is not an identifier")
        if role not in ROLES:
            raise RegistryError(f"line {lineno}: unknown role {role!r}")
        if (name, role) in seen:
            raise RegistryError(f"line {lineno}: duplicate {role} row for {name!r}")
        seen.add((name, role))
        key_idx = _int_cell(cells[3], "key_idx", lineno)
        name_idx = _int_cell(cells[4], "name_idx", lineno)
        val_idx = _int_cell(cells[5], "val_idx", lineno)
        fmt_idx = _int_cell(cells[6], "fmt_idx", lineno)
        returns_value = _bool_cell(cells[7], lineno)
        if role != "nvram" and (op != "" or returns_value is not None):
            raise RegistryError(f"line {lineno}: op/returns_value apply to nvram rows only")

        if role in ("sink_cmd", "sink_fmt"):
            if key_idx < 0:
                raise RegistryError(f"line {lineno}: {role} needs key_idx")
            (sink_cmd if role == "sink_cmd" else sink_fmt)[name] = key_idx
        elif role == "writer":
            writer.add(name)
        elif role == "writer_fmt":
            if fmt_idx < 0:
                raise RegistryError(f"line {lineno}: writer_fmt needs fmt_idx")
            writer_fmt[name] = fmt_idx
        elif role == "tokenizer":
            tokenizer.add(name)
        elif role == "forward_cmd":
            forward_cmd.add(name)
        else:  # nvram
            if op not in NVRAM_OPS:
                raise RegistryError(f"line {lineno}: nvram op must be one of {sorted(NVRAM_OPS)}")
            if op in ("read", "write") and key_idx < 0:
                raise RegistryError(f"line {lineno}: nvram {op} needs key_idx")
            if op == "read" and returns_value is None:
                raise RegistryError(f"line {lineno}: nvram read needs returns_value")
            if op != "read" and returns_value is not None:
                raise RegistryError(f"line {lineno}: returns_value applies to nvram reads only")
            nvram[name] = NvramSpec(op, key_idx, name_idx, val_idx, returns_value)

    if not header_seen:
        raise RegistryError("registry has no header line")
    groups: dict[str, object] = {
        "sink_cmd": sink_cmd,
        "sink_fmt": sink_fmt,
        "writer": writer,
        "writer_fmt": writer_fmt,
        "tokenizer": tokenizer,
        "forward_cmd": forward_cmd,
        "nvram": nvram,
    }
    empty = sorted(role for role, group in groups.items() if not group)
    if empty:
        # A role with no rows is a truncated or damaged file, not a deliberate choice: the
        # extractor would silently recognise nothing of that kind.
        raise RegistryError(f"registry has no rows for role(s) {empty}")
    return ExtractorNames(
        sink_cmd=MappingProxyType(sink_cmd),
        sink_fmt=MappingProxyType(sink_fmt),
        writer=frozenset(writer),
        writer_fmt=MappingProxyType(writer_fmt),
        tokenizer=frozenset(tokenizer),
        forward_cmd=frozenset(forward_cmd),
        nvram=MappingProxyType(nvram),
    )


def load_registry(path: Path = REGISTRY_PATH) -> ExtractorNames:
    """Read and parse the registry file. A missing or unreadable file is a ``RegistryError``."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RegistryError(f"cannot read extractor registry {path}: {exc}") from exc
    return parse_registry(text)


def validate_registry(path: Path = REGISTRY_PATH) -> None:
    """Fail fast before any extraction starts: raise ``RegistryError`` when the file the extractor
    is about to read would be rejected by it."""
    load_registry(path)


# The registry as shipped, parsed once at import. A damaged file fails every importer loudly.
REGISTRY: ExtractorNames = load_registry()
