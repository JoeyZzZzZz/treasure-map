# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Atlas row models — frozen dataclasses mirroring pattern + instance columns.

No behavior. Field names are neutral: they describe mechanism, not interpretation.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PatternRow:
    """Mirrors the pattern table columns. pattern_id is None before insert."""

    source_class: str
    sink_class: str
    call_sequence_shape: str
    structural_fingerprint: str | None = None
    fingerprint_algo_version: str = "v0"
    device_spread: int = 0
    pattern_id: int | None = None
    first_seen_at: str | None = None
    last_updated_at: str | None = None


@dataclass(frozen=True)
class InstanceRow:
    """Mirrors the instance table columns. instance_id is None before insert."""

    pattern_id: int
    reachability_status: str = field(default="unknown")
    provenance_level: str = field(default="L0")
    pseudocode_hash: str | None = None
    source_anchor: str | None = None
    sink_anchor: str | None = None
    source_run_id: str | None = None
    blocking_mechanism: str | None = None
    external_anchor: str | None = None
    fix_diff: str | None = None
    scope_origin: str | None = None
    evidence_ref: str | None = None
    # Candidate locatability: the full path + content hash of the binary the evidence function
    # lives in. Auto-filled from the source build; both REDACT ON EXPORT (private evidence).
    binary_path: str | None = None
    binary_content_hash: str | None = None
    # Neutral origin dimension; not forced at ingest — defaults to 'unknown' (refined later
    # at the aggregation layer). One of custom/vendor_modified_oss/stock_oss_known/unknown.
    origin: str = "unknown"
    instance_id: int | None = None
    created_at: str | None = None
