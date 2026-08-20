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
#
# It lives HERE, with the ref builder, because the second half IS the ref vocabulary: the suffix
# that distinguishes a wrapper-recovered instance from the direct one is what a reader must be able
# to map BACK to the direct (base) suffix. Keeping the table in one leaf module means the forward
# use (A2 minting refs) and the reverse use (a read tool pointing a wrapper ref at its base) can
# never drift apart into two hand-written copies.
_WRAPPER_AXIS: dict[str, tuple[str, str]] = {
    "cmd": ("wrapper-cmd", "cmd_via_wrapper"),
    "fmt_string": ("wrapper-fmt", "fmt_via_wrapper"),
}

# Reverse of the suffix half: a wrapper-recovered ref suffix -> the suffix its DIRECT counterpart
# carries (the sink_class, which is exactly what a direct instance uses). DERIVED, never re-typed.
_WRAPPER_SUFFIX_TO_BASE: dict[str, str] = {
    suffix: sink_class for sink_class, (_shape, suffix) in _WRAPPER_AXIS.items()
}


def base_evidence_ref(evidence_ref: str) -> str | None:
    """The DIRECT-candidate ref a wrapper-recovered ``evidence_ref`` corresponds to, else None.

    A purely mechanical suffix swap (``…@cmd_via_wrapper`` -> ``…@cmd``): same run, same binary
    anchor, same function anchor, only the sink-axis suffix changes. It says NOTHING about whether
    that base ref exists — proving existence is the caller's job, and inventing a ref that resolves
    to nothing would be exactly the fabricated-anchor failure the ref contract forbids."""
    for suffix, base_suffix in _WRAPPER_SUFFIX_TO_BASE.items():
        tail = f"@{suffix}"
        if evidence_ref.endswith(tail):
            return f"{evidence_ref[: -len(tail)]}@{base_suffix}"
    return None


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
    ref unique when one function matches several sinks. Each anchor degrades honestly, worst-anchor
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
