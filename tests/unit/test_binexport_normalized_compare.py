# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""scripts/binexport_normalized_compare.py: two exports of one program compare equal once the
timestamp is removed and the three order-free lists are sorted; any other difference does not.

Zero real data: hand-encoded BinExport2 wire bytes.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "binexport_normalized_compare.py"
_spec = importlib.util.spec_from_file_location("binexport_normalized_compare", _SCRIPT)
assert _spec is not None and _spec.loader is not None
bnc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bnc)


def _len(field: int, body: bytes) -> bytes:
    return bnc._enc_varint(field << 3 | 2) + bnc._enc_varint(len(body)) + body


def _int(field: int, value: int) -> bytes:
    return bnc._enc_varint(field << 3) + bnc._enc_varint(value)


def _export(timestamp: int, edges: list[bytes], refs: list[bytes], operand: bytes = b"r0") -> bytes:
    meta = _len(1, b"httpd") + _int(4, timestamp)
    call_graph = _len(1, b"vertex-a") + _len(1, b"vertex-b") + b"".join(_len(2, e) for e in edges)
    return (
        _len(1, meta)
        + _len(3, operand)
        + _len(8, call_graph)
        + b"".join(_len(11, r) for r in refs)
        + _len(15, b"data-ref")
    )


def test_timestamp_and_list_order_do_not_count(tmp_path: Path) -> None:
    """★ Two sessions' exports of one program: another timestamp, call-graph edges and string
    references in another order -> one normalized sha.

    MUTATION (verified RED): keep the timestamp -> RED; stop sorting the edges -> RED."""
    a = _export(1_700_000_000, [b"e1", b"e2"], [b"s1", b"s2"])
    b = _export(1_800_000_000, [b"e2", b"e1"], [b"s2", b"s1"])
    assert a != b
    assert bnc.normalized(a) == bnc.normalized(b)
    pa, pb = tmp_path / "a.BinExport", tmp_path / "b.BinExport"
    pa.write_bytes(a)
    pb.write_bytes(b)
    assert bnc.main([str(pa), str(pb)]) == 0


def test_a_markup_difference_counts_and_is_named(tmp_path: Path) -> None:
    """An operand written differently is a difference — in the normalized sha and in the markup
    sha; a different vertex order (not an order-free list) is a difference too."""
    a = _export(1, [b"e1"], [b"s1"])
    b = _export(1, [b"e1"], [b"s1"], operand=b"[sp,#0x20]")
    assert bnc.normalized(a)[0] != bnc.normalized(b)[0]
    assert bnc.normalized(a)[1] != bnc.normalized(b)[1]
    pa, pb = tmp_path / "a.BinExport", tmp_path / "b.BinExport"
    pa.write_bytes(a)
    pb.write_bytes(b)
    assert bnc.main([str(pa), str(pb)]) == 1
