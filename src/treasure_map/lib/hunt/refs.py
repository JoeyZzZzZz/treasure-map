# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The per-instance locator (``evidence_ref``) — built to survive a re-scan.

``evidence_ref`` is the single anchor an agent carries around: it self-resolves a candidate's
run + binary + function, and a durable judgement store keys its records by it. So the ref MUST be
**re-scan stable**: scanning the same firmware again has to yield the SAME string for the same
function, or every stored judgement silently loses its anchor.

The ref is built from facts that belong to the BINARY, never from ingest bookkeeping:

* the binary anchor = its content hash prefix. Content-derived (a re-scan of the same file hashes
  the same) and, unlike the binary NAME, collision-free: real firmware ships several distinct
  binaries under one name (libstdc++.so.6, mtdinfo, …), whose functions would otherwise share a ref.
  The full PATH is unique too but carries the vendor/model string, and a ref must stay neutral.
* the function anchor = its entry ADDRESS. A property of the binary; a stripped function's name is
  itself address-derived (FUN_0040a1c0 <-> 0040a1c0).

★ NEVER derive a ref from a rowid / AUTOINCREMENT id / enumeration index. ``functions.id`` fails
BOTH ways: the analysis DB is delete-and-reingest per binary, and AUTOINCREMENT never reuses a
number, so every re-scan shifts every id by the function count — the ref drifts with ZERO code
change. Enumeration order is the second, smaller trap: it also moves ids when the extractor changes.

Scope: re-scan stable, which is what a durable judgement store needs. NOT cross-recompile stable —
aligning a function across two firmware BUILDS is the diff layer's (harder) problem, and its edge
anchors carry {name, addr, kind} for exactly that. A ref deliberately does not pay for it here.
"""

from __future__ import annotations

import re
from collections.abc import Hashable, Iterable, Mapping
from typing import Any

from treasure_map.lib.callsite_ref import (
    callsite_abs_addr,
    is_wrapper_class,
    ref_suffix_parts,
    wrapper_call_abs_addr,
)

_BIN_ANCHOR_LEN = 8  # sha256 prefix; distinct across every binary of a real firmware tested

# Per-axis labels for a wrapper-propagated candidate: (call_sequence_shape prefix, evidence_ref
# suffix), keyed by the candidate's sink_class. "cmd" keeps its historical strings byte-for-byte.
# The single source of truth for the wrapper axis; analyzer2 reads it when minting refs. It
# lives HERE,
# with the ref builder, because the second half IS ref vocabulary and this module is the leaf every
# ref-building caller can import. A wrapper candidate is emitted per CALL to its wrapper, so its ref
# carries that call's offset like any per-callsite ref (``…@cmd_via_wrapper@<offset>``); the offset
# names the call to the WRAPPER, not to the sink inside it.
#
# ★ There is deliberately NO reverse (suffix -> "base ref") map. A wrapper ref and the thin wrapper
# it forwards into are DIFFERENT candidates at DIFFERENT addresses, related through the
# ``wrapped_sink`` field — never by swapping a ref's suffix at the same address. A reverse map was
# tried and removed: on real data the same-address "base ref" it computed existed 0 times out of 20
# sampled, i.e. it pointed at an anchor that never exists.
_WRAPPER_AXIS: dict[str, tuple[str, str]] = {
    "cmd": ("wrapper-cmd", "cmd_via_wrapper"),
    "fmt_string": ("wrapper-fmt", "fmt_via_wrapper"),
}


def callsite_offset_suffix(
    sink_class: str, offset_norm: str | None, callsite_index: int | None = None
) -> str:
    """The ref suffix for a per-callsite candidate anchored by its ADDRESS offset: ``<class>@<off>``
    (e.g. ``cmd@0x001218``), replacing an earlier ``<class>#<index>`` text-ordinal form.

    Why the offset and not the ordinal: both name the same call, but the offset from the function
    entry survives a decompiler UPGRADE where the Nth-call ordinal does not.

      * ``offset_norm`` given         -> ``<class>@<offset>``  (the call's in-body address is known)
      * else ``callsite_index`` given -> ``<class>#<index>``   (the LEGACY ordinal form)
      * else                          -> ``<class>``           (function-level, no callsite located)

    THE CALLER'S CONTRACT decides the middle case, and it is what keeps the rekey safe. It is
    decided per DATABASE, never per row. When the database was extracted with the bridge
    (post-churn: the normal case), the caller passes ``callsite_index=None`` for every candidate,
    so a call the bridge could not place — register-indirect, unrendered, out of body, or a row
    whose export carried no tokens (a data gap) — degrades to the bare class, and NO ``#index`` ref
    is ever emitted. The ``#index`` form appears ONLY when the whole database predates the bridge
    (a pre-churn / un-migrated analysis.db), where it reproduces the historical ref byte-for-byte so
    per-callsite candidates stay distinct. A per-row decision broke this once: a stale token-less
    row in a bridged database emitted a shifted ordinal that read as an old ref.
    Since the churn forces a re-scan, the atlas the rekey migrates NEVER holds a ``#index`` ref, so
    an old numbered anchor left un-remapped resolves to nothing (visible staleness) rather than
    silently matching a re-hunted ``#index`` a retired phantom shifted onto a different call."""
    if offset_norm is not None:
        return f"{sink_class}@{offset_norm}"
    if callsite_index is not None:
        return f"{sink_class}#{callsite_index}"
    return sink_class


def _norm_addr(address: str | None) -> str | None:
    """Canonicalize an entry address to lowercase, 0x-free, zero-padded hex ("0040a1c0").

    Canonicalizing (rather than trusting the raw string) keeps the ref stable even if the extractor
    ever changes its address formatting — "0x40a1c0" and "0040a1c0" must not be two anchors for one
    function. A non-hex form is kept verbatim: still deterministic, never silently dropped.
    """
    if not address:
        return None
    a = address.strip().lower().removeprefix("0x")
    if not a:
        return None
    try:
        return f"{int(a, 16):08x}"
    except ValueError:
        return a


def _addr_to_int(address: str | int | None) -> int | None:
    """Parse an address (``"0x40a1c0"`` / ``"0040a1c0"`` / int) to int, or None when unparseable.

    Shared by _norm_offset; kept separate from _norm_addr, which renders a STRING and deliberately
    passes a non-hex form through verbatim, a policy the arithmetic here must not inherit."""
    if address is None:
        return None
    if isinstance(address, int):
        return address
    a = address.strip().lower().removeprefix("0x")
    if not a:
        return None
    try:
        return int(a, 16)
    except ValueError:
        return None


def _norm_offset(sink_addr: str | int | None, func_entry: str | int | None) -> str | None:
    """The canonical, signed offset of a callsite from its function entry:
    ``sink_addr - func_entry`` rendered ``[-]0x<zero-padded hex>`` (``0x001218`` / ``-0x000040``).

    Address-relative on purpose: the offset survives a decompiler upgrade that moves the text
    ordinal (see callsite_offset_suffix). SIGNED because an out-of-line block the compiler placed
    below the entry is a real, in-body call at a negative offset — dropping the sign would alias it
    onto a different call. Zero-padded to a fixed minimum width so one offset has exactly one
    spelling ("0x1218" and "0x001218" must never be two anchors), mirroring _norm_addr; an offset
    wider than the pad still renders deterministically. None when either address is unparseable —
    the caller then falls back to the bare/ordinal suffix, never a guessed anchor."""
    sa = _addr_to_int(sink_addr)
    fe = _addr_to_int(func_entry)
    if sa is None or fe is None:
        return None
    delta = sa - fe
    return f"{'-' if delta < 0 else ''}0x{abs(delta):06x}"


def build_evidence_ref(
    run_id: str,
    *,
    suffix: str,
    binary_sha256: str | None = None,
    binary_name: str | None = None,
    address: str | None = None,
    func_name: str | None = None,
    func_id: int | None = None,
) -> str:
    """The neutral, re-scan-stable per-instance locator: ``<run>#<sha8>:<addr>@<suffix>``.

    ``suffix`` is the sink-class hit (``cmd`` / ``copy`` / ``cmd_via_wrapper`` …), which keeps the
    ref unique when one function matches several sinks, and for a per-callsite shape carries the
    call's address offset too (``copy@0x000480``) so siblings within one function stay distinct —
    build it with ``callsite_offset_suffix`` rather than by hand. Each anchor degrades honestly,
    worst-anchor
    last: binary = sha256 prefix -> name -> "nobin"; function = address -> name -> "id<func_id>".
    The ``id<func_id>`` tail is the only unstable form and is unreachable on real firmware (every
    function there carries an address); it exists so a degenerate row still gets a unique
    ref rather than silently colliding with another.
    """
    bin_anchor = (binary_sha256 or "").strip()[:_BIN_ANCHOR_LEN] or (binary_name or "").strip()
    fn_anchor = _norm_addr(address) or (func_name or "").strip()
    if not fn_anchor:
        fn_anchor = f"id{func_id}" if func_id is not None else "nofn"
    return f"{run_id}#{bin_anchor or 'nobin'}:{fn_anchor}@{suffix}"


# ── one formal anchor per call, for the calls only a degraded anchor names ─────────────────────


def _bare_parts(evidence_ref: str) -> tuple[str, int, str] | None:
    """(``<run>#<bin>`` prefix, entry, class) of a bare ``…:<entry>@<class>`` ref (no callsite
    tail), or None for any other shape."""
    head, sep, tail = evidence_ref.rpartition(":")
    if not sep:
        return None
    entry_hex, at, cls = tail.partition("@")
    if not at or not re.fullmatch(r"[a-z_]+", cls):
        return None
    try:
        entry = int(entry_hex, 16)
    except ValueError:
        return None
    return head, entry, cls


def _anchored_call(evidence_ref: str) -> tuple[str, str, int] | None:
    """(``<run>#<bin>`` prefix, class, absolute call address) of a ref that carries an offset —
    the call it is the formal anchor of — or None. Read by the one suffix parser."""
    parts = ref_suffix_parts(evidence_ref)
    if parts is None:
        return None
    cls = parts[0]
    addr = (
        wrapper_call_abs_addr(evidence_ref)
        if is_wrapper_class(cls)
        else callsite_abs_addr(evidence_ref)
    )
    if addr is None:
        return None
    return evidence_ref.rpartition(":")[0], cls, addr


def mint_out_of_body_refs(
    rows: Iterable[tuple[Hashable, str, Mapping[str, Any] | None]],
) -> dict[Hashable, str]:
    """For one run's candidate rows, ``{row key: offset ref}`` — the rows whose bare ref becomes
    the formal anchor of their call.

    ``rows`` are (row key, evidence_ref, flow_evidence). A bare ref is one per (function, class):
    calls the bridge located in the text but not inside the function's body (the ``out_of_body``
    degrade) share it, each in its own row, with the call's address recovered as
    ``flow_evidence.callsite_addr``. Per (``<run>#<bin>``, class, call address):

      * a row already anchored at that call by an offset ref: it is the call's anchor; the bare
        rows stay bare and fold onto it (sink_overlay, by ``callsite_addr``) — nothing is minted;
      * else the rows of the LOWEST function entry among the call's bare claimants get
        ``<bare ref>@<offset>``, the offset signed from that entry (the call is outside its body;
        the evidence keeps ``anchor_degraded``); the other claimants stay bare and fold onto it.

    Deterministic, needs nothing but the refs and the recovered addresses, and drops no row: one
    formal anchor per call, every claimant kept."""
    anchored: set[tuple[str, str, int]] = set()
    claims: dict[tuple[str, str, int], list[tuple[int, Hashable, str]]] = {}
    for key, ref, evidence in rows:
        call = _anchored_call(ref)
        if call is not None:
            anchored.add(call)
            continue
        parts = _bare_parts(ref)
        ev = evidence or {}
        if parts is None or ev.get("anchor_degraded") != "out_of_body":
            continue
        addr = _addr_to_int(ev.get("callsite_addr"))
        if addr is None:
            continue
        head, entry, cls = parts
        claims.setdefault((head, cls, addr), []).append((entry, key, ref))
    minted: dict[Hashable, str] = {}
    for (_head, _cls, addr), claimants in claims.items():
        if (_head, _cls, addr) in anchored:
            continue
        first = min(entry for entry, _k, _r in claimants)
        offset = _norm_offset(addr, first)
        if offset is None:
            continue
        for entry, key, ref in claimants:
            if entry == first:
                minted[key] = f"{ref}@{offset}"
    return minted
