# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""A minimal reader for a BinExport2 file: instruction address -> its recorded call targets.

BinExport2 is a protobuf message (binexport2.proto, Apache-2.0). Only what the diff layer needs is
decoded, with no protobuf library: the top-level ``instruction`` list (field 5) and, inside each
``Instruction``, ``address`` (1), ``call_target`` (2) and ``raw_bytes`` (5). Every other field, at
either level, is skipped by its wire type.

★ The address of an instruction is written ONLY when it does not follow on from the previous one.
Otherwise it is the previous instruction's address plus the length of the previous instruction's
``raw_bytes``. Getting this wrong does not fail: every following target lands on the wrong address,
silently. So the reconstruction mirrors the writer exactly, and an instruction recorded without
``raw_bytes`` (its bytes could not be read at export) makes the addresses after it UNCERTAIN until
the next explicit address — their targets are dropped rather than attached to a guessed address.

``call_target`` is what the exporter recorded for a call or a jump to a function entry (a tail call
included), with an external function mapped to its linkage address. It names a target; it does not
by itself say the instruction is a call.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from treasure_map.lib.errors import TreasureMapError
from treasure_map.lib.hunt.refs import _norm_addr

# Field numbers from binexport2.proto.
_TOP_INSTRUCTION = 5
_INSN_ADDRESS = 1
_INSN_CALL_TARGET = 2
_INSN_RAW_BYTES = 5

_WT_VARINT, _WT_FIXED64, _WT_LEN, _WT_FIXED32 = 0, 1, 2, 5


class BinExportDecodeError(TreasureMapError):
    """The file is not a BinExport2 message this reader can walk (truncated, or a shape it does
    not support). The caller treats it as "targets not decoded", never as "no targets"."""


@dataclass(frozen=True)
class DecodedInstruction:
    address: int | None  # None when it could not be reconstructed with certainty
    call_targets: tuple[int, ...]


def _varint(buf: bytes, pos: int, end: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if pos >= end:
            raise BinExportDecodeError("truncated varint")
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7
        if shift > 70:
            raise BinExportDecodeError("varint too long")


def _skip(buf: bytes, pos: int, end: int, wire_type: int) -> int:
    if wire_type == _WT_VARINT:
        return _varint(buf, pos, end)[1]
    if wire_type == _WT_FIXED64:
        nxt = pos + 8
    elif wire_type == _WT_FIXED32:
        nxt = pos + 4
    elif wire_type == _WT_LEN:
        length, pos = _varint(buf, pos, end)
        nxt = pos + length
    else:
        raise BinExportDecodeError(f"unsupported wire type {wire_type}")
    if nxt > end:
        raise BinExportDecodeError("truncated field")
    return nxt


def _instruction(buf: bytes, pos: int, end: int) -> tuple[int | None, list[int], int | None]:
    """(explicit address or None, call targets, raw_bytes length or None) of one Instruction."""
    address: int | None = None
    targets: list[int] = []
    raw_len: int | None = None
    while pos < end:
        key, pos = _varint(buf, pos, end)
        field, wire_type = key >> 3, key & 7
        if field == _INSN_ADDRESS and wire_type == _WT_VARINT:
            address, pos = _varint(buf, pos, end)
        elif field == _INSN_CALL_TARGET and wire_type == _WT_VARINT:
            value, pos = _varint(buf, pos, end)
            targets.append(value)
        elif field == _INSN_CALL_TARGET and wire_type == _WT_LEN:  # packed encoding
            length, pos = _varint(buf, pos, end)
            stop = pos + length
            if stop > end:
                raise BinExportDecodeError("truncated packed call_target")
            while pos < stop:
                value, pos = _varint(buf, pos, stop)
                targets.append(value)
        elif field == _INSN_RAW_BYTES and wire_type == _WT_LEN:
            length, pos = _varint(buf, pos, end)
            if pos + length > end:
                raise BinExportDecodeError("truncated raw_bytes")
            raw_len = length
            pos += length
        else:
            pos = _skip(buf, pos, end, wire_type)
    if pos != end:
        raise BinExportDecodeError("instruction overruns its length")
    return address, targets, raw_len


def iter_instructions(data: bytes) -> Iterator[DecodedInstruction]:
    """Every instruction of a BinExport2 message, in file order, with its reconstructed address.

    Raises BinExportDecodeError on a malformed message or a first instruction with no address."""
    end = len(data)
    pos = 0
    prev_addr: int | None = None
    prev_size: int | None = None
    seen_any = False
    while pos < end:
        key, pos = _varint(data, pos, end)
        field, wire_type = key >> 3, key & 7
        if field != _TOP_INSTRUCTION or wire_type != _WT_LEN:
            pos = _skip(data, pos, end, wire_type)
            continue
        length, pos = _varint(data, pos, end)
        stop = pos + length
        if stop > end:
            raise BinExportDecodeError("truncated instruction")
        explicit, targets, raw_len = _instruction(data, pos, stop)
        pos = stop
        if explicit is not None:
            address: int | None = explicit
        elif not seen_any:
            raise BinExportDecodeError("first instruction carries no address")
        elif prev_addr is None or prev_size is None:
            address = None  # follows an instruction whose length was not recorded: uncertain
        else:
            address = prev_addr + prev_size
        seen_any = True
        # The writer advances by the bytes it read; with none recorded the next implicit address
        # cannot be reconstructed, so it is marked uncertain until an explicit address resets it.
        prev_addr = address
        prev_size = raw_len if raw_len else None
        yield DecodedInstruction(address=address, call_targets=tuple(targets))


def decode_call_targets(path: Path) -> dict[str, list[str]]:
    """``{instruction address -> [call target, ...]}`` for every instruction with at least one
    target, both normalized with ``_norm_addr``; targets de-duplicated, in recorded order.
    Instructions whose address is uncertain are left out. Raises BinExportDecodeError."""
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise BinExportDecodeError(f"cannot read {path.name}: {exc}") from exc
    out: dict[str, list[str]] = {}
    for insn in iter_instructions(data):
        if insn.address is None or not insn.call_targets:
            continue
        key = _norm_addr(hex(insn.address))
        if key is None:
            continue
        targets: list[str] = out.setdefault(key, [])
        for t in insn.call_targets:
            norm = _norm_addr(hex(t))
            if norm is not None and norm not in targets:
                targets.append(norm)
    return out
