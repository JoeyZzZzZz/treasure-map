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
