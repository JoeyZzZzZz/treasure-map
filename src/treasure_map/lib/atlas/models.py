# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
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
    # An exposure SHAPE (e.g. bare_sink = a raw command/format sink with no recognized in-function
    # source), kept OUT of blocking_mechanism so a danger form is never read as a mitigation. NULL
    # when no shape is flagged.
    exposure_shape: str | None = None
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
    # The tmap commit that produced this run's INSTANCES, when the install that hunted it recorded
    # one. None on a run hunted before the stamp existed, and 'unknown' when the hunting install
    # had no commit to record — neither is a commit, so neither ever reads as "up to date".
    hunt_commit: str | None = None
    # How many instance rows that hunt committed. None on a run hunted before the count was
    # recorded — which is not zero: zero is a run that legitimately produced no candidates, and the
    # two must not collapse, or a real empty result would be indistinguishable from an unknown one.
    hunt_instances: int | None = None
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
    # The binary's recorded path. The short name beside it is a LABEL that repeats across a
    # firmware, so it is the path that says which file this row is about. None on a row read
    # back from before the column existed.
    binary_path: str | None = None
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
    # The binary's recorded path. The short name beside it is a LABEL that repeats across a
    # firmware, so it is the path that says which file this row is about. None on a row read
    # back from before the column existed.
    binary_path: str | None = None
    id: int | None = None
    created_at: str | None = None


@dataclass(frozen=True)
class PublicCvePatternRow:
    """Mirrors one public_cve_pattern row: a public-CVE exploit form (public material).

    Agent-fillable, not sensitive, and NOT counted in ``distinct_exploits``.
    ``pattern``/``source``/``sink`` are free text — no structured match key is presumed. Physically
    separate from the private verified-exploit records. ``origin`` marks the row as externally
    imported (not tmap deterministic extraction) — always 'external_import'."""

    pattern: str
    cve_id: str | None = None
    source: str | None = None
    sink: str | None = None
    ref: str | None = None
    notes: str | None = None
    origin: str = "external_import"
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


@dataclass(frozen=True)
class StringKeyedEdgeRow:
    """Mirrors one string_keyed_edge row: ONE (key, callee) of an enumerated string-keyed edge.

    An attacker-influenceable string ``key`` gates/dispatches to ``callee_name`` — a deterministic
    fact recovered structurally (strcmp ladder or a {string, func_ptr} table), NEVER a reachability
    verdict. callee_name + callee_addr + callee_kind are the BinDiff-alignable anchor (a bare addr
    drifts across a recompile). ``completeness`` is fine-grained so a cross-version diff tells an
    incomplete scan region from a real edge delta. One flattened row per (key, callee)."""

    source_run_id: str | None
    binary: str | None
    from_function: str | None
    key: str | None
    mechanism: str  # 'strcmp_gate' | 'static_string_table'
    callee_name: str | None = None
    callee_addr: str | None = None
    callee_kind: str | None = None
    from_func_addr: str | None = None
    ladder_size: int | None = None
    table_addr: str | None = None
    completeness_status: str = "complete"
    completeness_reason: str | None = None
    completeness_scope: str | None = None
    # The binary's recorded path. The short name beside it is a LABEL that repeats across a
    # firmware, so it is the path that says which file this row is about. None on a row read
    # back from before the column existed.
    binary_path: str | None = None
    id: int | None = None
    created_at: str | None = None


@dataclass(frozen=True)
class ExecEdgeRow:
    """Mirrors one exec_edge row: ONE cross-binary "A launches B" fact.

    Binary ``launcher_binary`` calls ``exec_api`` with an argument naming ``target_token``, which
    resolved (or did not) to ``target_binary``. ★ An ENUMERATED EDGE, never a reachability verdict:
    it does not claim the callsite runs or that input reaches it. ``target_resolution`` is total and
    mutually exclusive over six states; ``unmatched`` carries the three symlink facts plus
    ``token_form`` so a reader tells damage from ambiguity from a genuine miss without tmap
    judging. ``occurrences`` counts identical callsite/token repeats folded into one row."""

    source_run_id: str | None
    launcher_binary: str | None
    launcher_function: str | None
    exec_api: str | None
    target_token: str | None
    target_resolution: str
    launcher_addr: str | None = None
    sink_addr: str | None = None
    target_layer: str | None = None
    shell_wrapped: int = 0
    piped: int = 0
    inner_command_visible: int = 0
    argv_visibility: str | None = None
    argv_template: str | None = None
    argv_provenance: str | None = None
    token_form: str | None = None
    symlink_ambiguous: int = 0
    symlink_corrupt: int = 0
    symlink_target_unresolved: int = 0
    target_binary: str | None = None
    occurrences: int = 1
    # The LAUNCHER's recorded path. ``launcher_binary`` is a short name and repeats across a
    # firmware, so it is the path that says which file holds the callsite. None on a pre-column row.
    launcher_binary_path: str | None = None
    id: int | None = None
    created_at: str | None = None


@dataclass(frozen=True)
class DetectorScanStatusRow:
    """Mirrors one atlas detector_scan_status row: the hunt-flattened honesty status of a table-form
    detector for one (run, binary). ``scanned`` = the detector ran; ``supported_scope`` = the
    form(s) it checks; ``cap_hit`` = a probe/entry cap truncated the walk; ``found_count`` = tables
    found. It lets an EMPTY string_keyed_edge result carry its own honesty (genuine-none vs
    unsupported-form vs capped) instead of reading as a confident false negative."""

    source_run_id: str | None
    binary: str | None
    detector: str
    scanned: int = 0
    supported_scope: str | None = None
    unsupported_note: str | None = None
    cap_hit: int = 0
    found_count: int = 0
    # The binary's recorded path. The short name beside it is a LABEL that repeats across a
    # firmware, so it is the path that says which file this row is about. None on a row read
    # back from before the column existed.
    binary_path: str | None = None
    id: int | None = None


@dataclass(frozen=True)
class RunCapabilityRow:
    """Mirrors one run_capability row: the deterministic fact that a run produced a given analysis
    sub-dimension (e.g. 'reachability.string_keyed_edge'). present=1 is registered UNCONDITIONALLY
    when the detector code runs — absence-of-findings is not absence-of-capability — so a diff can
    iterate capabilities instead of hardcoding sub-dimension names."""

    run_id: str | None
    capability: str
    present: int = 1
    id: int | None = None
    created_at: str | None = None


@dataclass(frozen=True)
class FunctionAlignmentRow:
    """Mirrors one function_alignment row: ONE BinDiff-matched (A-side, B-side) function pair.

    An ALIGNMENT FACT (BinDiff matched these two addresses), NEVER a change verdict.
    ``alignment_confidence`` is BinDiff ``confidence`` (trust in the pairing); ``similarity`` is the
    separate change-magnitude fact (a pair may be similarity=1.0 yet confidence ~0.02). Addresses
    normalized hex; names are carried, never the anchor."""

    diff_id: str
    addr_a: str
    addr_b: str
    alignment_confidence: float
    alignment_state: str  # 'aligned' | 'alignment_undetermined'
    name_a: str | None = None
    name_b: str | None = None
    similarity: float | None = None
    basicblocks: int | None = None
    edges: int | None = None
    instructions: int | None = None
    id: int | None = None


@dataclass(frozen=True)
class FunctionPresenceRow:
    """Mirrors one function_presence row: a baseline-domain function NOT in any matched
    pair. States ONLY 'this function is not in any matched pair' — NEVER 'added' or 'removed' (a
    later stage's judgement). ``presence_state`` is three-state (a decompile gap / inventory gap
    is existence-undetermined, never an add/delete)."""

    diff_id: str
    side: str  # 'a' | 'b'
    addr: str
    presence_state: str
    name: str | None = None
    decompiled: int | None = None
    id: int | None = None


@dataclass(frozen=True)
class DiffMetaRow:
    """Mirrors the diff_meta row for one A-vs-B comparison: the runs, their analysis-tool versions,
    the honest coverage counts (so the existence blind spot is quantifiable, not invisible), and the
    version_skew flag (analysis-tool versions only — it does NOT detect build-side compiler/inlining
    skew)."""

    diff_id: str
    run_a_id: str
    run_b_id: str
    tool_version_a: str | None = None
    tool_version_b: str | None = None
    ghidra_version_a: str | None = None
    ghidra_version_b: str | None = None
    version_skew: int = 0
    bindiff_source: str | None = None
    matched_pairs: int | None = None
    alignment_undetermined: int | None = None
    functions_total_a: int | None = None
    functions_total_b: int | None = None
    matched_in_domain_a: int | None = None
    matched_in_domain_b: int | None = None
    unmatched_a: int | None = None
    unmatched_b: int | None = None
    # The resolved PATH per side. ``binary_a``/``binary_b`` hold the short name, which can name
    # several files; these say which one was actually diffed. None until the diff is re-run.
    binary_path_a: str | None = None
    binary_path_b: str | None = None
    out_of_inventory_a: int | None = None
    out_of_inventory_b: int | None = None
    inventory_mismatch_a: int | None = None
    inventory_mismatch_b: int | None = None
    functions_empty_a: int | None = None  # REAL decompile failures only (== run.functions_empty)
    functions_empty_b: int | None = None
    micro_skipped_a: int | None = None  # design-skipped micro-funcs, kept separate (never merged)
    micro_skipped_b: int | None = None
    presence_computed_a: int = 0
    presence_computed_b: int = 0
    # the diff's TARGET binary per side (a diff aligns ONE binary), stored as the short name. A
    # consumer that filters per-binary facts (string_keyed_edge spans the whole firmware) needs this
    # scope; NULL on a diff written before it was recorded -> the consumer must refuse, not silently
    # skip filtering (empty != absent on the binary-scope axis).
    binary_a: str | None = None
    binary_b: str | None = None
    # per-binary diff status (the scan-side ghidra_ok/status/reason model ported to diff). diff_ok
    # is the RERUN GATE: 1 = usable output (all steps ok), never re-diffed while sha unchanged; 0 =
    # failed, re-diffed next full run. diff_status is tri-state (ok / failed / NULL pre-feature);
    # diff_status_reason buckets the failure; diff_attempts counts attempts at the SAME content (a
    # retry cap reads it, reset when either sha256 changes); sha256_a/b are the content the diff ran
    # on -- the incremental-skip and attempts-reset gate. A failed row carries NO coverage counts.
    diff_ok: int = 0
    diff_status: str | None = None
    diff_status_reason: str | None = None
    diff_attempts: int = 0
    sha256_a: str | None = None
    sha256_b: str | None = None


@dataclass(frozen=True)
class DimensionDeltaRow:
    """Mirrors one dimension_delta row: one dimension's difference for one subject between two runs.

    A PROJECTION of two already-computed layer annotations, NEVER a fresh analysis or a quality
    verdict. ``delta_kind`` is tri-state; ``layer_unchanged`` only when both sides are present,
    comparable and equal. ``state_a``/``state_b`` are OPAQUE (existence/equality only, never a
    branch basis). ``undetermined_scope`` ('data' | 'capability') is the sole consumer key;
    ``undetermined_reason`` is a human-readable label whose enum may grow."""

    diff_id: str
    dimension: str
    subject_kind: str  # 'edge' | 'candidate' | 'function'
    subject_key: str
    delta_kind: str  # 'layer_changed' | 'layer_unchanged' | 'delta_undetermined'
    state_a: str | None = None
    state_b: str | None = None
    undetermined_scope: str | None = None  # 'data' | 'capability'
    undetermined_reason: str | None = None
    capability_ref: str | None = None
    alignment_confidence: float | None = None
    binary: str | None = None  # diff's target binary (short name), parsed from subject_key
    id: int | None = None


@dataclass(frozen=True)
class DimensionCapabilityStateRow:
    """Mirrors one dimension_capability_state row: a dimension's capability on both sides, recorded
    explicitly so a dimension neither side can delta is a VISIBLE declared gap, never absent.

    ``state_a``/``state_b`` = each run's ANALYSIS capability ('present' | 'declared_absent' |
    'registration_unknown' -- a missing run_capability row is registration_unknown, NEVER
    declared_absent). ``delta_supported`` = whether THIS code version can compute the delta at all
    (orthogonal to the analysis capability)."""

    diff_id: str
    dimension: str
    state_a: str
    state_b: str
    delta_supported: int
    id: int | None = None
