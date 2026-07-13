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
    # Neutral structural fact: the function is a thin wrapper forwarding a parameter to a shell
    # command sink, and which sink (system/popen/doSystem). Recorded for a later analysis layer;
    # no recall/downweight/triage path reads these — a fact, not a verdict or a score input.
    is_thin_cmd_wrapper: bool = False
    wrapped_sink: str | None = None
    # Structured flow evidence for a command-sink candidate (JSON string; see lib/hunt/evidence.py).
    # Read-only structured facts — no recall/score/grade path consumes it.
    flow_evidence: str | None = None
    instance_id: int | None = None
    created_at: str | None = None


@dataclass(frozen=True)
class RunRow:
    """Mirrors one ``run`` row: a scan's lineage + the run_id -> analysis.db resolver.

    ``analysis_db_path`` is the authority a run-aware fact tool routes on (the run_id -> analysis.db
    map is STORED, not derived — there is no reliable workspaces/<run_id> convention).
    ``build_hash`` is the extraction pass_version, the stale-scan signal. ``scan_status`` is the
    lifecycle honesty axis: 'in_progress' (started, not finished — a crash leaves it here),
    'complete', 'partial', or 'failed'. ``resolved`` is a synthesized flag (NOT a column): False for
    a run seen only via instance.source_run_id with no run-table row (a pre-existing scan — visible
    but unresolved)."""

    run_id: str
    analysis_db_path: str | None = None
    firmware_path: str | None = None
    firmware_sha256: str | None = None
    build_hash: str | None = None
    tool_version: str | None = None
    ghidra_version: str | None = None
    machine: str | None = None
    binaries: int | None = None
    functions: int | None = None
    functions_empty: int | None = None
    scan_status: str = "in_progress"
    scanned_at: str | None = None
    updated_at: str | None = None
    # Synthesized (not a column): True when a real run-table row backs this run; False for a run
    # seen only via instance.source_run_id (a pre-existing scan with no lineage row) — surfaced so
    # list_runs never hides a run yet stays honest that its analysis.db/lineage is unresolved.
    resolved: bool = True


@dataclass(frozen=True)
class NvramFlowRow:
    """Mirrors one nvram_key_flow row: a single nvram read/write op flattened from a function's
    nvram_ops. Neutral per-op fact; the key graph is a query over these, not a stored graph.

    key_kind is the honesty axis: 'constant' (concrete key), 'parametric' (a template, e.g.
    wl%d_ssid — a possible not exact match), or 'unresolved' (key came from a caller, key is None —
    never connected to a concrete key by the query, but stored so it is exposed + counted).
    """

    source_run_id: str | None
    key: str | None
    key_kind: str
    binary: str | None
    func: str | None
    op: str
    value_source: str | None = None  # write-side value provenance JSON; None for reads
    api: str | None = None
    via_wrapper: str | None = (
        None  # A2: thin nvram wrapper an indirect edge resolved through; None=direct
    )
    id: int | None = None
    created_at: str | None = None


@dataclass(frozen=True)
class NvramDefaultRow:
    """Mirrors one nvram_defaults row: a member of the router_defaults web-settable-key table,
    flattened from analysis.db. key is the default key name (None for an unresolved/unparsed member,
    which keeps a located-but-incomplete table honest). A neutral data-segment fact — the
    web_settable answer is a query over these rows, never a stored verdict."""

    source_run_id: str | None
    key: str | None
    default_value: str | None = None
    flags: int | None = None
    member_index: int | None = None
    binary: str | None = None
    id: int | None = None
    created_at: str | None = None


@dataclass(frozen=True)
class PublicCvePatternRow:
    """Mirrors one public_cve_pattern row: a public-CVE exploit form (front-stage material).

    Agent-fillable, not sensitive, and NOT counted in barrier depth. ``pattern``/``source``/``sink``
    are free text — no structured match key is presumed. Physically separate from the private
    exploited-hole ledger."""

    pattern: str
    cve_id: str | None = None
    source: str | None = None
    sink: str | None = None
    ref: str | None = None
    notes: str | None = None
    id: int | None = None
    created_at: str | None = None


@dataclass(frozen=True)
class WebFormFieldRow:
    """Mirrors one web_form_fields row: a USER-EDITABLE web form field name, flattened from
    analysis.db (SaTC front-end surface). field_keyword is the asset's OWN content. A neutral
    front-end fact — the web_settable answer is a QUERY crossing these against the back-end
    nvram_key_flow constant keys, never a stored verdict."""

    source_run_id: str | None
    field_keyword: str | None
    source_asset: str | None = None
    source_rule: str | None = None
    id: int | None = None
    created_at: str | None = None
