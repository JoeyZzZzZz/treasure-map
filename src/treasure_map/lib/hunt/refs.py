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
  itself address-derived (FUN_000b32a0 <-> 000b32a0).

★ NEVER derive a ref from a rowid / AUTOINCREMENT id / enumeration index. ``functions.id`` fails
BOTH ways: the analysis DB is delete-and-reingest per binary, and AUTOINCREMENT never reuses a
number, so every re-scan shifts every id by the function count (measured on real firmware: a
4-times-scanned DB held 88,178 functions numbered 266,156..354,333) — the ref drifts with ZERO code
change. Enumeration order is the second, smaller trap: it also moves ids when the extractor changes.

Scope: re-scan stable, which is what a durable judgement store needs. NOT cross-recompile stable —
aligning a function across two firmware BUILDS is the diff layer's (harder) problem, and its edge
anchors carry {name, addr, kind} for exactly that. A ref deliberately does not pay for it here.
"""

from __future__ import annotations

_BIN_ANCHOR_LEN = 8  # sha256 prefix; 479 real binaries -> 479 distinct prefixes (no collision)

# Per-axis labels for a wrapper-propagated candidate: (call_sequence_shape prefix, evidence_ref
# suffix), keyed by the candidate's sink_class. "cmd" keeps its historical strings byte-for-byte.
# The single source of truth for the wrapper axis; A2 reads it when minting refs. It lives HERE,
# with the ref builder, because the second half IS ref vocabulary and this module is the leaf every
# ref-building caller can import.
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


def callsite_suffix(sink_class: str, callsite_index: int | None) -> str:
    """The ref suffix for a candidate: its sink class, plus the callsite ordinal when it has one.

    A shape emitted per CALLSITE needs this or it does not survive being read back. Readers resolve
    a ref to ONE instance (``WHERE evidence_ref = ? ORDER BY instance_id LIMIT 1``), so siblings
    sharing a ref are not two candidates — the second one is silently not there, which is the same
    disappearance the per-callsite split exists to undo. ``copy#0`` / ``copy#1`` keep them apart.

    A candidate with no callsite ordinal keeps the bare class suffix it has always had, byte for
    byte. Two reasons, both about not overstating: a function-level anchor is a different claim
    from "the Nth call", and writing ``copy#0`` for a call that could not be located would dress a
    fallback up as a precise hit.

    ★ Callsite ordinals do change the refs of the per-callsite candidates themselves — the same
    copy that answered to ``…@copy`` now answers to ``…@copy#0``. That is deliberate and it is the
    honest direction: the old ref named a FUNCTION's copy, and once a function can hold several,
    silently re-pointing that name at whichever call happens to sort first would hand an existing
    judgement a different callsite without saying so. A ref that stops resolving is visible; one
    that resolves to something else is not.

    ★ SCOPE, stated because it is weaker than the rest of the ref: the ordinal counts calls in the
    DECOMPILED TEXT, so it is a property of the decompiler's output rather than of the binary the
    way an entry address is. Re-scanning the same firmware with the same decompiler reproduces the
    body and therefore the ordinal, which is the stability a durable judgement store needs. A
    decompiler UPGRADE is where the two anchors part company: the address survives it and the
    ordinal need not, so a candidate's callsite ref can move while its function's does not. That is
    the same regime as the cross-recompile boundary this module already declines to pay for — worth
    naming here because the rest of the ref is stronger and would otherwise be read as covering it.
    """
    return sink_class if callsite_index is None else f"{sink_class}#{callsite_index}"


def callsite_offset_suffix(
    sink_class: str, offset_norm: str | None, callsite_index: int | None = None
) -> str:
    """The ref suffix for a per-callsite candidate anchored by its ADDRESS offset: ``<class>@<off>``
    (e.g. ``cmd@0x001218``), replacing the ``<class>#<index>`` text-ordinal form (callsite_suffix).

    Why the offset and not the ordinal: both name the same call, but the offset from the function
    entry survives a decompiler UPGRADE where the Nth-call ordinal does not (callsite_suffix spells
    out that scope).

      * ``offset_norm`` given         -> ``<class>@<offset>``  (the call's in-body address is known)
      * else ``callsite_index`` given -> ``<class>#<index>``   (the LEGACY ordinal form)
      * else                          -> ``<class>``           (function-level, no callsite located)

    THE CALLER'S CONTRACT decides the middle case, and it is what keeps the rekey safe. When the
    extraction carried the bridge (post-churn: the normal case), the caller passes
    ``callsite_index=None``, so a call the bridge could not place — register-indirect, unrendered,
    out of body — degrades to the bare class, and NO ``#index`` ref is ever emitted. The ``#index``
    form appears ONLY when the caller has no bridge at all (a pre-churn / un-migrated analysis.db),
    where it reproduces the historical ref byte-for-byte so per-callsite candidates stay distinct.
    Since the churn forces a re-scan, the atlas the rekey migrates NEVER holds a ``#index`` ref, so
    an old numbered anchor left un-remapped resolves to nothing (visible staleness) rather than
    silently matching a re-hunted ``#index`` a retired phantom shifted onto a different call."""
    if offset_norm is not None:
        return f"{sink_class}@{offset_norm}"
    if callsite_index is not None:
        return f"{sink_class}#{callsite_index}"
    return sink_class


def _norm_addr(address: str | None) -> str | None:
    """Canonicalize an entry address to lowercase, 0x-free, zero-padded hex ("000b32a0").

    Canonicalizing (rather than trusting the raw string) keeps the ref stable even if the extractor
    ever changes its address formatting — "0xb32a0" and "000b32a0" must not be two anchors for one
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
    """Parse an address (``"0xb32a0"`` / ``"000b32a0"`` / int) to int, or None when unparseable.

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
    one of 88,178 functions carried an address); it exists so a degenerate row still gets a unique
    ref rather than silently colliding with another.
    """
    bin_anchor = (binary_sha256 or "").strip()[:_BIN_ANCHOR_LEN] or (binary_name or "").strip()
    fn_anchor = _norm_addr(address) or (func_name or "").strip()
    if not fn_anchor:
        fn_anchor = f"id{func_id}" if func_id is not None else "nofn"
    return f"{run_id}#{bin_anchor or 'nobin'}:{fn_anchor}@{suffix}"
