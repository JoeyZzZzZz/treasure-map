# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Coarse structural fingerprint for a call-sequence match.

This is the COARSE, high-recall layer: a stable hash over the match's structural shape
(pattern kind, sink class, source class, call-sequence shape) — deliberately ignoring
data-flow detail so that the same shape across firmwares yields the same fingerprint. A
finer, data-flow-normalized layer is future work; FINGERPRINT_ALGO_VERSION exists so the
algorithm can evolve without invalidating fingerprints already accumulated downstream.
"""

from __future__ import annotations

import hashlib

from treasure_map.lib.pattern.models import PatternMatch

FINGERPRINT_ALGO_VERSION = "callseq-v1"


def structural_fingerprint(match: PatternMatch) -> str:
    """Return a stable hex fingerprint over the match's structural shape."""
    basis = "|".join(
        (
            match.pattern_kind,
            match.sink_class,
            match.source_class,
            match.call_sequence_shape,
        )
    )
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]
