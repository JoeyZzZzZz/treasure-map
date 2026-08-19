-- Treasure Map atlas — persistent cross-firmware pattern store.
-- PERSISTENT, append-and-corroborate. NOT wipe-and-rebuild (that is analysis.db).
-- Lives OUTSIDE any repo (default ~/.treasure-map/atlas.db). Zero vendor identity.
-- Field names are NEUTRAL: they describe mechanism, not interpretation.
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS pattern (
    pattern_id               INTEGER PRIMARY KEY AUTOINCREMENT,
    source_class             TEXT NOT NULL,
    sink_class               TEXT NOT NULL,
    call_sequence_shape      TEXT NOT NULL,
    structural_fingerprint   TEXT,
    fingerprint_algo_version TEXT NOT NULL DEFAULT 'v0',
    device_spread            INTEGER NOT NULL DEFAULT 0,  -- exposure ledger: COUNT(DISTINCT source_run_id); device distribution, NOT the pattern-recurrence number
    first_seen_at            DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_updated_at          DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS instance (
    instance_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_id          INTEGER NOT NULL,
    pseudocode_hash     TEXT,             -- deterministic content hash of the evidence function
    source_anchor       TEXT,             -- located via name/address/string/diff (stripped-safe)
    sink_anchor         TEXT,
    source_run_id       TEXT,             -- NEUTRAL per-firmware-run id (device_spread unit); vendor-free
    reachability_status TEXT NOT NULL DEFAULT 'unknown'
        CHECK (reachability_status IN ('confirmed','blocked','unknown')),
    blocking_mechanism  TEXT,             -- categorical: char_filter/length_check/... NULL if none
    -- exposure_shape is an exposure SHAPE (e.g. bare_sink = a raw command/format sink with no
    --   recognized in-function source), NOT a blocking mechanism. Kept in its own column so a
    --   consumer never reads a danger form as a mitigation. NULL when no shape is flagged.
    exposure_shape      TEXT,
    provenance_level    TEXT NOT NULL DEFAULT 'L0'
        CHECK (provenance_level IN ('L0','L1','L2','L3')),
    external_anchor     TEXT,             -- external evidence authorizing L2/L3 (patch ref / CVE); NULL for L0/L1
    fix_diff            TEXT,             -- neutral change region; redact on export
    scope_origin        TEXT,             -- intra_firmware | intra_vendor | cross_vendor
    evidence_ref        TEXT,             -- provenance trail to source analysis.db + binary/function
    binary_path         TEXT,             -- full path of the binary the evidence function lives in;
                                          --   auto-filled from the source build so a candidate stays
                                          --   locatable when analysis.db is gone. REDACT ON EXPORT.
    binary_content_hash TEXT,             -- content hash of that binary (content-identity); auto-filled,
                                          --   stored only this round (no metric consumes it yet). REDACT ON EXPORT.
    -- Neutral STRUCTURAL fact: the function is a thin wrapper forwarding a parameter to a shell
    --   command sink, and which sink it forwards to. Recorded for a later analysis layer; NO
    --   recall/downweight/triage path reads these (a fact, not a verdict or a score input).
    is_thin_cmd_wrapper INTEGER NOT NULL DEFAULT 0 CHECK (is_thin_cmd_wrapper IN (0,1)),
    wrapped_sink        TEXT,
    -- Structured flow EVIDENCE for a command-sink candidate (JSON: source_kind / flow_path /
    --   sanitizer_seen[coverage=unjudged] / entry_reach / trace_boundary). Material for a
    --   downstream agent — NOT a verdict; no recall/score/grade path reads it. May hold neutral
    --   rootfs paths as private evidence. REDACT ON EXPORT.
    flow_evidence       TEXT,
    -- origin is not forced at ingest; default unknown is expected (refined later at aggregation)
    origin              TEXT NOT NULL DEFAULT 'unknown'
        CHECK (origin IN ('custom','vendor_modified_oss','stock_oss_known','unknown')),
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
    -- traceability (anti-orphan): an instance must trace to source evidence
    CHECK (pseudocode_hash IS NOT NULL OR evidence_ref IS NOT NULL),
    -- no L2/L3 without an external anchor: schema-enforced, not writer-only
    CHECK (provenance_level IN ('L0','L1') OR external_anchor IS NOT NULL),
    FOREIGN KEY(pattern_id) REFERENCES pattern(pattern_id) ON DELETE CASCADE
);

-- run: per-scan lineage + the run_id -> analysis.db RESOLVER. One row per source_run_id.
-- Written by the scan pipeline (run_analyzer2): scan_status='in_progress' at START, 'complete' at
-- END. A crash between leaves 'in_progress' — the honest "did not finish, do NOT trust this run"
-- signal (a run whose instances exist but never resolved to a finished scan must stay VISIBLE, not
-- silently look complete). This table is the AUTHORITY mapping a neutral run_id to its analysis.db:
-- there is NO reliable workspaces/<run_id> path convention (run_id may be a custom label, and a
-- workspace may be a literal path anywhere), so the absolute path is STORED here, not derived.
-- build_hash (the extraction pass_version) is the STALE-scan signal: two scans of one firmware with
-- different build_hash means one was produced by an older analysis pass. analysis_db_path /
-- firmware_path are private evidence — REDACT ON EXPORT.
CREATE TABLE IF NOT EXISTS run (
    run_id            TEXT PRIMARY KEY,
    analysis_db_path  TEXT,             -- absolute path to this run's analysis.db (the resolver)
    firmware_path     TEXT,             -- the scanned firmware root, when known; else NULL
    firmware_sha256   TEXT,             -- run-identity content hash (manifest/firmware); NULL if unknown
    build_hash        TEXT,             -- extraction-pipeline content hash (pass_version) — STALE-scan signal
    tool_version      TEXT,             -- treasure_map __version__ that produced this run
    ghidra_version    TEXT,             -- decompiler version, when known; else NULL
    machine           TEXT,             -- host that ran the scan, when known; else NULL
    binaries          INTEGER,          -- binaries in the analysis.db
    functions         INTEGER,          -- functions in the analysis.db
    functions_empty   INTEGER,          -- functions that never decompiled (partial-analysis count)
    scan_status       TEXT NOT NULL DEFAULT 'in_progress'
        CHECK (scan_status IN ('in_progress','complete','partial','failed')),
    scanned_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE VIEW IF NOT EXISTS dormant_instance AS
  SELECT * FROM instance
  WHERE reachability_status = 'blocked' AND provenance_level IN ('L0','L1');

CREATE VIEW IF NOT EXISTS public_finding AS
  SELECT * FROM instance
  WHERE reachability_status = 'confirmed' AND provenance_level IN ('L2','L3');

-- density_candidate: neutral clustering of candidate instances — "where do dangerous-sink
-- candidate shapes cluster". The scope dimension is the neutral source_run_id. Counts per run /
-- sink_class / structural_fingerprint. All rows are LEADS; counts only, no scoring or ranking
-- column. (The atlas is a PRIVATE, out-of-repo runtime evidence store; it may hold neutral
-- binary_path / binary_content_hash as private evidence — REDACTED before any export/publish.
-- The zero-vendor-identity rule binds artifacts committed to the public repo, not this store.)
CREATE VIEW IF NOT EXISTS density_candidate AS
  SELECT i.source_run_id          AS source_run_id,
         p.sink_class             AS sink_class,
         p.structural_fingerprint AS structural_fingerprint,
         COUNT(*)                 AS instance_count
  FROM instance i
  JOIN pattern p ON p.pattern_id = i.pattern_id
  GROUP BY i.source_run_id, p.sink_class, p.structural_fingerprint;

-- twin_candidate: structural fingerprints observed with BOTH a blocked and a non-blocked
-- instance — the same call-sequence shape once with a filter, once without. A neutral
-- structural observation surfaced as a lead; any interpretation of it is out of scope here.
CREATE VIEW IF NOT EXISTS twin_candidate AS
  SELECT p.structural_fingerprint AS structural_fingerprint,
         p.sink_class             AS sink_class,
         SUM(CASE WHEN i.reachability_status =  'blocked' THEN 1 ELSE 0 END) AS blocked_count,
         SUM(CASE WHEN i.reachability_status <> 'blocked' THEN 1 ELSE 0 END) AS non_blocked_count
  FROM instance i
  JOIN pattern p ON p.pattern_id = i.pattern_id
  WHERE p.structural_fingerprint IS NOT NULL
  GROUP BY p.structural_fingerprint, p.sink_class
  HAVING blocked_count >= 1 AND non_blocked_count >= 1;

-- pattern_ledger: the two derived recurrence ledgers, computed on read (never frozen scalars).
--   device_spread   = COUNT(DISTINCT source_run_id) over the pattern's instances.
--   pattern_breadth = COUNT(DISTINCT pseudocode_hash) over the pattern's instances with
--                     origin IN ('custom','unknown') and pseudocode_hash IS NOT NULL — the count
--                     of distinct fine fingerprints (M2 fine fingerprint = pseudocode_hash).
-- The stored pattern.device_spread column is a write-side convenience counter with the same
-- definition; this view's device_spread is the read-side authority and should agree with it.
CREATE VIEW IF NOT EXISTS pattern_ledger AS
  SELECT p.pattern_id              AS pattern_id,
         p.sink_class              AS sink_class,
         p.structural_fingerprint  AS structural_fingerprint,
         (SELECT COUNT(DISTINCT i.source_run_id) FROM instance i
          WHERE i.pattern_id = p.pattern_id)                       AS device_spread,
         (SELECT COUNT(DISTINCT i.pseudocode_hash) FROM instance i
          WHERE i.pattern_id = p.pattern_id
            AND i.origin IN ('custom','unknown')
            AND i.pseudocode_hash IS NOT NULL)                     AS pattern_breadth
  FROM pattern p;

-- nvram_key_flow: per-op nvram read/write facts, flattened from functions.nvram_ops at hunt time,
-- so an agent can trace "who writes / who reads this nvram key" across binaries (cross-process
-- config dataflow) as a table lookup instead of two manual reverse-lookups. These are ROW-LEVEL raw
-- facts; the KEY GRAPH is the QUERY over them (get_nvram_key_flow), exactly as the density/twins
-- views are read-side queries over instance rows. Honesty is enforced at the QUERY, not the store:
--   key_kind='constant'   -> a concrete key; connected EXACTLY across binaries.
--   key_kind='parametric' -> a printf/strcpy template (e.g. wl%d_ssid); a POSSIBLE match, surfaced
--                            separately and flagged, never treated as an exact connection.
--   key_kind='unresolved' -> the key came from a caller (untraceable here); key IS NULL. The query
--                            NEVER attributes these to a concrete key (that would connect the wrong
--                            key), but they are STORED so they can be exposed and drive the
--                            completeness flag -- the agent is told "N unresolved-key ops could
--                            touch any key", never left to assume the graph is complete.
-- source_run_id is the neutral per-firmware-run id (append-and-corroborate; a re-run of one run
-- deletes its own rows first, like instance). May hold neutral binary/func names as private
-- evidence -- REDACT ON EXPORT (this is a private, out-of-repo runtime store).
CREATE TABLE IF NOT EXISTS nvram_key_flow (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    source_run_id TEXT,
    key           TEXT,   -- concrete key (constant) or template text (parametric); NULL if unresolved
    key_kind      TEXT NOT NULL DEFAULT 'unresolved'
        CHECK (key_kind IN ('constant','parametric','unresolved')),
    binary        TEXT,
    func          TEXT,
    op            TEXT NOT NULL DEFAULT 'read' CHECK (op IN ('read','write')),
    value_source  TEXT,   -- write-side value provenance JSON (controllability signal); NULL for reads
    api           TEXT,   -- the concrete nvram API (nvram_set / nvram_get / ...)
    via_wrapper   TEXT,   -- A2: the thin nvram wrapper this indirect edge was resolved through (the
                          --   key was a literal at the wrapper call site); NULL for a DIRECT nvram call
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_nvram_key      ON nvram_key_flow(key);
CREATE INDEX IF NOT EXISTS idx_nvram_run      ON nvram_key_flow(source_run_id);
CREATE INDEX IF NOT EXISTS idx_nvram_key_kind ON nvram_key_flow(key_kind);

-- naming-bridge phase 1: the router_defaults web-settable-key table, flattened from analysis.db at
-- hunt time (mirrors nvram_key_flow). get_nvram_key_flow reads it to answer "is this source key
-- web-settable?" — a source-side controllability fact. A key row (key NOT NULL) is a located member;
-- a key=NULL row marks a member whose name could not be parsed (located-but-incomplete). NO rows for
-- a run means the table was not located (uncertain — NEVER "not web-settable"): a false-negative red
-- line. member_index is kept for reproducibility; the query draws no verdict from these facts.
CREATE TABLE IF NOT EXISTS nvram_defaults (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    source_run_id TEXT,
    key           TEXT,   -- web-settable default key; NULL = an unresolved (unparsed) member
    default_value TEXT,   -- member default value (nullable)
    flags         INTEGER,
    member_index  INTEGER,
    binary        TEXT,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_nvdef_key ON nvram_defaults(key);
CREATE INDEX IF NOT EXISTS idx_nvdef_run ON nvram_defaults(source_run_id);

-- SaTC front-end surface: user-editable web form field names, flattened from analysis.db at hunt
-- time (mirrors nvram_defaults). web_settable crosses these (front-end editable) against
-- nvram_key_flow constant keys (back-end nvram ops, all binaries) to separate an editable web key
-- from a read-only display key: a key present on BOTH sides is web-settable; back-end-only is a
-- read-only display; front-end-only is a UI control. field_keyword is the asset's OWN content
-- (evidence). NO rows for a run means the front-end was not collected -> web_settable reads
-- 'uncertain', NEVER 'not settable' (the false-negative red line). May hold neutral asset paths as
-- private evidence -- REDACT ON EXPORT.
CREATE TABLE IF NOT EXISTS web_form_fields (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    source_run_id TEXT,
    field_keyword TEXT,   -- editable web form field name (front-end attack surface)
    source_asset  TEXT,   -- the web asset the field was seen in
    source_rule   TEXT,   -- input / textarea / select / js_assign / nvram_ascii
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_wff_key ON web_form_fields(field_keyword);
CREATE INDEX IF NOT EXISTS idx_wff_run ON web_form_fields(source_run_id);

-- string_keyed_edge: a deterministic "string-keyed edge" fact — a string key (attacker-influenceable)
-- gates or dispatches to a set of callees, recovered structurally (NOT a per-firmware handler name).
-- One ROW per (key, callee) so the reachability layer can look up "is this function a callee of some
-- edge?" by callee_name, and a cross-version diff can enumerate by run + align by key. mechanism
-- distinguishes the recovering detector (strcmp_gate = a same-variable strcmp ladder; static_string_table
-- = a {string_ptr, func_ptr} data-segment table). ★ IRON LAW: this is an ENUMERATED EDGE (a fact),
-- NEVER a reachability verdict — a candidate that is an edge callee stays reachability=unknown (the
-- key is a lead the agent confirms). callee_addr + callee_name + callee_kind together are the
-- BinDiff-alignable anchor (a bare address drifts across a recompile). completeness is FINE-GRAINED
-- (status + reason + scope) so a diff can tell "this region was incomplete on one side" from "a real
-- edge delta". Flattened from analysis.db (functions.string_keyed_edges) at hunt time, replace-by-run.
CREATE TABLE IF NOT EXISTS string_keyed_edge (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    source_run_id       TEXT,
    binary              TEXT,
    from_function       TEXT,   -- the dispatcher/table function (strcmp ladder) or NULL (static table)
    from_func_addr      TEXT,
    key                 TEXT,   -- the gating string (strcmp constant) or table entry name
    mechanism           TEXT NOT NULL DEFAULT 'strcmp_gate'
        CHECK (mechanism IN ('strcmp_gate','static_string_table')),
    callee_name         TEXT,   -- BinDiff-alignable anchor: Ghidra name + addr + kind (NOT bare addr)
    callee_addr         TEXT,
    callee_kind         TEXT,   -- direct / thunk / indirect / ptr / undefined_text. undefined_text =
                                --   a .text entry with no Ghidra Function object (a dispatch table
                                --   is often its only reference); the address is still the anchor.
    ladder_size         INTEGER,  -- strcmp_gate: distinct keys gated on the same variable; NULL for A
    table_addr          TEXT,     -- static_string_table: the table's base address; NULL for B
    completeness_status TEXT NOT NULL DEFAULT 'complete'
        CHECK (completeness_status IN ('complete','incomplete','partial')),
    completeness_reason TEXT,   -- switch_form_unrecognized / gate_branch_unresolved / got_relative_table_skipped / …
    completeness_scope  TEXT,   -- function@addr or region id, so a diff can match by region
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ske_key    ON string_keyed_edge(key);
CREATE INDEX IF NOT EXISTS idx_ske_run    ON string_keyed_edge(source_run_id);
CREATE INDEX IF NOT EXISTS idx_ske_callee ON string_keyed_edge(callee_name);
CREATE INDEX IF NOT EXISTS idx_ske_from   ON string_keyed_edge(from_function);

-- exec_edge: a cross-binary "A launches B" fact — binary A's code calls a command/exec sink whose
-- argument names B. Recovered from the per-function sink argument provenance the extractor already
-- computed, then resolved against the rootfs link inventory (fs_symlinks), so /bin/sh -> busybox
-- lands as a real edge instead of an unmatched token.
--
-- ★ IRON LAW: this is an ENUMERATED EDGE (a fact), NEVER a reachability verdict. "A execs B" does
-- not say the exec callsite runs, nor that an attacker reaches it. The reachability layer may use
-- an edge as an entry SITE, and its status stays found/unknown — an edge NEVER produces 'blocked'.
--
-- target_resolution is a six-state, mutually exclusive, total classification of the argument token:
--   resolved_direct     the token names a binary in this run's inventory
--   resolved_symlink    the token is a rootfs link whose target is such a binary
--   resolved_script     the token is a .sh that the non-binary inventory holds
--   self_exec           /proc/self/exe (the launcher re-executes itself)
--   unresolved          the token could not be read out of the provenance at all
--   unmatched           read fine, matched nothing
-- ★ unmatched is NOT "absent". It carries four plain facts so a reader can tell the cases apart
-- WITHOUT tmap judging them: token_form (absolute/bare/relative), symlink_ambiguous (several
-- link targets are binaries — undecided, not guessed), symlink_corrupt (the extraction damaged
-- the link), symlink_target_unresolved (the link exists but its target is not a known binary — it
-- may be a script, another link, or an extraction gap; the link's own name is basename of the
-- token, so it is not stored a second time).
-- The last one is DEFAULT-DENY: any link hit that does not land on an inventory member reports it,
-- so a damage shape nobody has seen yet degrades visibly instead of silently resolving.
--
-- The two sink families never overlap. SHELL (system/popen/doSystem) -> target_layer='shell_command':
-- the target is the command's first word; the image is always /bin/sh and is deliberately NOT
-- listed as a separate edge. EXEC (execl*/execv*) -> target_layer='exec_image': the target is the
-- image path in arg0. ★ For the EXEC family argv is structurally invisible (a variadic list or a
-- caller-built array): arg0 is recorded and argv is NEVER reconstructed.
-- Replace-by-run at hunt time, alongside the other flattened edge facts.
CREATE TABLE IF NOT EXISTS exec_edge (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    source_run_id            TEXT,
    launcher_binary          TEXT,     -- A: the binary whose code holds the call
    launcher_function        TEXT,
    launcher_addr            TEXT,
    exec_api                 TEXT,     -- system / popen / doSystem / execl / execv / ...
    sink_addr                TEXT,     -- the callsite address (part of the dedup identity)
    target_layer             TEXT,     -- shell_command | exec_image
    shell_wrapped            INTEGER,  -- the command runs through an explicit shell -c
    piped                    INTEGER,  -- the shell command contains a pipeline
    inner_command_visible    INTEGER,  -- can tmap read the command the shell will run?
    argv_visibility          TEXT,     -- known | known_with_placeholder | structurally_invisible
    argv_template            TEXT,     -- the visible command text (shell family only)
    argv_provenance          TEXT,     -- provenance kind of the sink argument (constant/stack_buf/...)
    target_token             TEXT,     -- B as written at the callsite
    target_resolution        TEXT NOT NULL,
    token_form               TEXT,     -- absolute | relative | bare
    symlink_ambiguous        INTEGER,
    symlink_corrupt          INTEGER,
    symlink_target_unresolved INTEGER,
    target_binary            TEXT,     -- B resolved: a binary short name, or a script's path
    occurrences              INTEGER NOT NULL DEFAULT 1,
    created_at               DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_execedge_run      ON exec_edge(source_run_id);
CREATE INDEX IF NOT EXISTS idx_execedge_target   ON exec_edge(target_binary);
CREATE INDEX IF NOT EXISTS idx_execedge_launcher ON exec_edge(launcher_binary);
CREATE INDEX IF NOT EXISTS idx_execedge_res      ON exec_edge(target_resolution);

-- detector_scan_status: the hunt-flattened per-(run, binary, detector) honesty status of a
-- table-form detector, crossing the analysis.db -> atlas boundary alongside string_keyed_edge so
-- the consumer query (which reads ATLAS, not analysis.db) can attach it to an EMPTY result. Without
-- this an empty static-table result reads as a confident "none" and conflates genuine-none from
-- unsupported-form / capped. Replace-by-run at hunt time (one row per run,binary,detector).
CREATE TABLE IF NOT EXISTS detector_scan_status (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    source_run_id    TEXT,
    binary           TEXT,             -- short name, matching string_keyed_edge.binary
    detector         TEXT,             -- 'string_tables'
    scanned          INTEGER NOT NULL DEFAULT 0,
    supported_scope  TEXT,
    unsupported_note TEXT,
    cap_hit          INTEGER NOT NULL DEFAULT 0,
    found_count      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_detstat_run    ON detector_scan_status(source_run_id);
CREATE INDEX IF NOT EXISTS idx_detstat_binary ON detector_scan_status(binary);

-- run_capability: a per-run capability registry — the deterministic fact that a given tmap version's
-- scan/hunt produced a given analysis sub-dimension. present=1 is registered UNCONDITIONALLY when the
-- detector code runs (absence-of-findings ≠ absence-of-capability), so a cross-version diff iterates
-- capabilities instead of hardcoding sub-dimension names, and treats an edge delta as undetermined
-- when one side lacks the capability. Replace-by-run at hunt time. CI-assertable.
CREATE TABLE IF NOT EXISTS run_capability (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id       TEXT,
    capability   TEXT,      -- e.g. 'reachability.string_keyed_edge'
    present      INTEGER NOT NULL DEFAULT 1 CHECK (present IN (0,1)),
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_runcap_run ON run_capability(run_id);
CREATE INDEX IF NOT EXISTS idx_runcap_cap ON run_capability(capability);

-- exploit record tables — the two are PHYSICALLY SEPARATE tables on purpose (not one table + a
-- source column). They differ in sensitivity, who can produce them, and whether they are counted;
-- the split makes those three un-mixable at the storage layer (a public row can never be
-- mis-exported as private, and public volume can never inflate the private count).

-- public_cve_pattern (PUBLIC): public-CVE exploit forms. An agent may fill it. NOT counted in
-- distinct_exploits (it is reference material, not a verified exploit). Not sensitive.
-- pattern/source/sink are FREE TEXT — no structured match key is presumed (the fingerprint key is
-- unproven; no fuzzy match is built here, only exact human-readable lookup).
-- origin marks these rows as EXTERNALLY IMPORTED material, not tmap deterministic extraction — a
-- machine-readable guard (on top of the physical table separation) so external/fuzzy-source rows can
-- never be read as deterministic facts. Every import writes 'external_import'; CI asserts it.
CREATE TABLE IF NOT EXISTS public_cve_pattern (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id      TEXT,                 -- the public CVE this form belongs to (many rows may share one)
    pattern     TEXT NOT NULL,        -- exploit form (free text — no presumed structured dimensions)
    source      TEXT,                 -- attacker input point (free text: nvram key / POST param / …)
    sink        TEXT,                 -- dangerous sink (system / popen / SQL / …)
    ref         TEXT,                 -- writeup / public source link
    notes       TEXT,
    origin      TEXT NOT NULL DEFAULT 'external_import'  -- non-deterministic import provenance
        CHECK (origin IN ('external_import')),
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- private_exploit (PRIVATE): a candidate its owner PROVED exploitable. Admission bar =
-- EXPLOITED: exploit_note is NOT NULL (schema) AND the write tool rejects blank/whitespace — a
-- structural lead that was never exploited does NOT belong here (it stays in the pending-to-exploit
-- queue). distinct_exploits counts THIS table only, by COUNT(DISTINCT evidence_ref) (one per
-- candidate, not per corroboration row). evidence_ref is the STABLE candidate handle (survives a re-scan), never the
-- AUTOINCREMENT instance_id (which drifts). Private evidence about a shipping product —
-- redact='vendor_sensitive' by default; REDACT ON EXPORT, and the read path withholds exploit_note
-- unless a caller explicitly reveals it. Append-only, NOT unique: one evidence_ref may gather several
-- rows (corroboration / escalation), a later write never overwrites an earlier one.
CREATE TABLE IF NOT EXISTS private_exploit (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_ref  TEXT NOT NULL,      -- the candidate this record anchors to (stable handle, not id)
    pattern       TEXT NOT NULL,      -- exploit form (free text)
    exploit_note  TEXT NOT NULL,      -- proof: how it triggers, effect obtained, guard bypassed (bar)
    patch_form    TEXT,               -- empty; the diff line backfills the correct patch form later.
                                      --   patch_form is a property of the CANDIDATE (evidence_ref), not
                                      --   of a corroboration row: read it as the latest non-empty
                                      --   value per evidence_ref (same candidate-vs-row rule as the count).
    cve_id        TEXT,               -- empty; backfilled on disclosure (credibility compounding)
    redact        TEXT DEFAULT 'vendor_sensitive',  -- export-sensitivity marker (marker only here)
    attributed_to TEXT,               -- auto-attribution; nullable; NULL = "attribution unrecorded",
                                      --   NEVER a fabricated identity (no process user / model name)
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_priv_ref ON private_exploit(evidence_ref);

CREATE INDEX IF NOT EXISTS idx_pattern_classes ON pattern(source_class, sink_class);
CREATE INDEX IF NOT EXISTS idx_pattern_fp      ON pattern(structural_fingerprint);
CREATE INDEX IF NOT EXISTS idx_instance_pattern ON instance(pattern_id);
CREATE INDEX IF NOT EXISTS idx_instance_reach   ON instance(reachability_status);
CREATE INDEX IF NOT EXISTS idx_instance_prov    ON instance(provenance_level);
CREATE INDEX IF NOT EXISTS idx_instance_scope   ON instance(scope_origin);
CREATE INDEX IF NOT EXISTS idx_instance_run     ON instance(source_run_id);

-- ── layer-0 diff: function_alignment ─────────────────────────────────────────
-- One BinDiff-matched function pair (A-side <-> B-side), parsed from a .BinDiff
-- SQLite. It is the substrate a version comparison aligns candidates on.
--
-- IRON LAW: a row is an ALIGNMENT FACT (BinDiff matched these two addresses),
-- NEVER a verdict about what changed. A change verdict is a later stage.
--
-- MATCHED PAIRS ONLY: a function present on one side with no match is NOT a row
-- here (BinDiff's function table stores pairs). The ABSENCE of a row must NEVER
-- be read as "function removed" -- unmatched functions are listed per-side in
-- function_presence, and out-of-inventory entries are counted in diff_meta.
--
-- alignment_confidence is BinDiff `confidence` (trust in THIS pairing), NOT
-- `similarity` (content likeness). A pair can be similarity=1.0 yet confidence
-- ~0.02 (many identical small wrappers) -- that pair is undetermined, not aligned.
-- similarity is a FIRST-CLASS fact (how much the pair differs), surfaced next to
-- confidence, never hidden as "reference only" -- it is the change-magnitude axis
-- a consumer triages on, and it is a raw BinDiff fact, not a change verdict.
CREATE TABLE IF NOT EXISTS function_alignment (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    diff_id               TEXT NOT NULL,   -- identifies this A-vs-B comparison
    addr_a                TEXT NOT NULL,   -- A-side entry addr, normalized hex
    addr_b                TEXT NOT NULL,   -- B-side entry addr, same normalization
    name_a                TEXT,            -- carried, not an anchor
    name_b                TEXT,
    alignment_confidence  REAL NOT NULL,   -- = BinDiff confidence. Trust in the pairing.
    similarity            REAL,            -- = BinDiff similarity: HOW MUCH the pair differs.
    alignment_state       TEXT NOT NULL,   -- 'aligned' | 'alignment_undetermined'
    basicblocks           INTEGER,         -- carried for candidate-level alignment
    edges                 INTEGER,
    instructions          INTEGER,
    UNIQUE(diff_id, addr_a, addr_b)
);
CREATE INDEX IF NOT EXISTS idx_falign_diff ON function_alignment(diff_id);
CREATE INDEX IF NOT EXISTS idx_falign_a    ON function_alignment(diff_id, addr_a);
CREATE INDEX IF NOT EXISTS idx_falign_b    ON function_alignment(diff_id, addr_b);

-- ── layer-0 diff: function_presence ──────────────────────────────────────────
-- Per-side functions that are IN this run's function inventory but did NOT end
-- up in a matched pair. Exists so the ABSENCE of a function from
-- function_alignment is never the only way a consumer learns of it: an unmatched
-- function is an explicit, countable, inspectable row.
--
-- BASELINE DOMAIN: this run's own functions table, NOT the diff tool's function
-- enumeration. The two disagree by design -- this exporter skips thunks,
-- externals and micro-functions, the diff tool keeps them. Subtracting from the
-- diff tool's larger set would manufacture hundreds of phantom "unmatched" rows.
-- Entries the diff tool matched but this inventory does not carry are counted as
-- out_of_inventory in diff_meta, never as unmatched, never as add/delete.
--
-- IRON LAW: a row states ONLY "this function is not in any matched pair". It is
-- NOT a claim of "added" or "removed" -- a refactor may split one function into
-- two, a compiler change may inline one away. add-vs-delete is a later stage's
-- judgement; presence is this stage's fact.
CREATE TABLE IF NOT EXISTS function_presence (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    diff_id        TEXT NOT NULL,
    side           TEXT NOT NULL,   -- 'a' | 'b'
    addr           TEXT NOT NULL,   -- normalized hex
    name           TEXT,
    presence_state TEXT NOT NULL,   -- ANALYSIS COMPLETENESS (not the decompile action):
                                    -- 'unmatched_analysis_complete'    = no analysis gap (decompiled
                                    --   OR a design-skipped micro-function) -> existence DETERMINED
                                    -- | 'unmatched_analysis_incomplete' = a real gap (decompile
                                    --   failed, or size unknown) -> existence UNDETERMINED, NEVER
                                    --   read as add/delete
                                    -- | 'inventory_mismatch'            = the other side's baseline
                                    --   lacks this address
    decompiled     INTEGER,         -- 1 / 0 / NULL(unknown): was this side's decompile a success?
                                    --   NULL when size_bytes is unrecorded (cannot classify)
    UNIQUE(diff_id, side, addr)
);
CREATE INDEX IF NOT EXISTS idx_fpres ON function_presence(diff_id, side);

-- ── layer-0 diff: diff_meta ──────────────────────────────────────────────────
-- One row per A-vs-B comparison: which runs, their analysis-tool versions, the
-- honest coverage counts that turn the existence blind spot from invisible into
-- quantifiable, and the version_skew flag.
--
-- version_skew compares the ANALYSIS TOOL versions (tool_version / ghidra_version)
-- of the two runs -- NOT firmware_sha256 (A and B are DIFFERENT firmware by
-- definition, a patch changes the image) and NOT build_hash (a single-firmware
-- stale-pass signal). It does NOT detect BUILD-SIDE skew: a compiler/inlining
-- difference between the two firmware builds shows up as a phantom add/delete and
-- a spuriously low similarity, and this flag never marks that -- do not read
-- version_skew=false as "the two are comparable".
CREATE TABLE IF NOT EXISTS diff_meta (
    diff_id                 TEXT PRIMARY KEY,
    run_a_id                TEXT NOT NULL,
    run_b_id                TEXT NOT NULL,
    tool_version_a          TEXT,
    tool_version_b          TEXT,
    ghidra_version_a        TEXT,
    ghidra_version_b        TEXT,
    version_skew            INTEGER NOT NULL DEFAULT 0,   -- 1 = analysis-tool versions differ
    bindiff_source          TEXT,            -- the input .BinDiff file identity
    matched_pairs           INTEGER,         -- rows in function_alignment for this diff
    alignment_undetermined  INTEGER,         -- of those, confidence < threshold
    functions_total_a       INTEGER,         -- baseline domain size = tmap functions table (A)
    functions_total_b       INTEGER,
    matched_in_domain_a     INTEGER,         -- matched pairs whose A addr is in baseline_a
    matched_in_domain_b     INTEGER,
    unmatched_a             INTEGER,         -- baseline_a not in any matched pair
    unmatched_b             INTEGER,
    out_of_inventory_a      INTEGER,         -- matched A addr NOT in baseline_a (thunk/extern/micro)
    out_of_inventory_b      INTEGER,
    inventory_mismatch_a    INTEGER,         -- baseline_a addr the other side's baseline lacks
    inventory_mismatch_b    INTEGER,
    functions_empty_a       INTEGER,         -- REAL decompile failures (size >= MIN, no pseudocode)
                                             --   — same meaning as run.functions_empty; does NOT
                                             --   include design-skipped micro-functions
    functions_empty_b       INTEGER,
    micro_skipped_a         INTEGER,         -- micro-functions (size < MIN) the exporter skipped by
                                             --   design — known-benign, kept SEPARATE from
                                             --   functions_empty (never merged: same-name-diff-meaning)
    micro_skipped_b         INTEGER,
    presence_computed_a     INTEGER NOT NULL DEFAULT 0,  -- 1 = A side's baseline was available
    presence_computed_b     INTEGER NOT NULL DEFAULT 0,
    binary_a                TEXT,            -- the diff's TARGET binary per side (a diff aligns ONE
    binary_b                TEXT,            --   binary), stored as short name; NULL on a pre-feature
                                             --   diff -> a per-binary consumer must refuse, not skip
                                             --   filtering (empty != absent on the binary-scope axis)
    -- per-binary diff status (mirrors the scan-side ghidra_ok/status/reason model): a FAILED binary
    -- writes its own row (diff_ok=0 + status + reason) so a blind spot is persisted and queryable,
    -- never invisible. diff_ok is the RERUN GATE: an ok=1 binary whose content is unchanged is
    -- skipped next full diff (incremental); an ok=0 binary is retried (self-healing for a flaky
    -- toolchain failure). A failed row carries NO coverage counts (there is no usable output).
    diff_ok                 INTEGER NOT NULL DEFAULT 0,  -- 1 = usable output (BinExport x2 + BinDiff
                                             --   + layer0/2 all succeeded); 0 = this diff failed
    diff_status             TEXT,            -- tri-state outcome: ok / failed / NULL (pre-feature)
    diff_status_reason      TEXT,            -- WHY a failed diff failed: binexport_ghidra_crash /
                                             --   bindiff_flowgraph / binexport_no_file / timeout /
                                             --   other; NULL on success. Lets a consumer tell a
                                             --   likely-transient failure from a hard boundary
    diff_attempts           INTEGER NOT NULL DEFAULT 0,  -- cumulative attempts at the SAME content;
                                             --   reset to 1 when either side's sha256 changes (a
                                             --   recompiled binary may now diff, so a past 'hard'
                                             --   verdict is void); a retry cap uses this
    sha256_a                TEXT,            -- A-side binary sha256 at diff time; the incremental
    sha256_b                TEXT,            --   skip + attempts-reset gate (current sha != this ->
                                             --   content changed -> re-diff, attempts reset)
    created_at              DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ── layer-2 diff: dimension_delta ────────────────────────────────────────────
-- One dimension's difference for one subject between two runs. A row is a
-- PROJECTION of two already-computed layer annotations, NEVER a fresh analysis
-- and NEVER a quality judgement: this layer says "this annotation differs",
-- never "the change fixed / broke / regressed anything". There is deliberately
-- no fixed / incomplete_fix / regression value.
--
-- IRON LAW (tri-state): delta_kind is 'layer_unchanged' ONLY when both sides are
-- present, comparable and equal. Anything unresolved on either side is
-- 'delta_undetermined' -- NEVER collapsed into 'layer_unchanged'. A wrong
-- 'unchanged' is the expensive error: a consumer acts on it as "this dimension
-- was not touched by the change".
--
-- undetermined_scope separates two kinds of not-knowing a consumer must handle
-- differently:
--   'data'       -- this subject was not resolvable (alignment broke, a region
--                   was incomplete). Another subject may resolve fine.
--   'capability' -- this whole dimension is unavailable in this tool/code
--                   version; it is identical for EVERY subject and no amount of
--                   data fixes it. NEVER present it as a per-subject data gap.
-- A consumer keys ONLY on undetermined_scope; undetermined_reason is human/agent
-- readable and its enum may grow -- never branch bucketing on an unknown reason.
--
-- ★ state_a / state_b are OPAQUE evidence carried for the reader, NOT a branch
-- basis: this layer may compare them ONLY for existence and equality, and must
-- NEVER read their content to decide anything (no `if state_a == '<value>'`).
-- Branching on content would make this a second verdict engine; its job is to
-- project, never to judge. (Free text; enforced by contract + review, not schema.)
--
-- "vanished edge" honesty: a completeness guard blocks a diff over a region a
-- detector SELF-REPORTED as incomplete, but it cannot catch a detector silently
-- missing an edge inside a region it reported 'complete'. So an edge absent on
-- one side is "not detected there" -- usually, but NOT necessarily, "removed".
CREATE TABLE IF NOT EXISTS dimension_delta (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    diff_id              TEXT NOT NULL,
    dimension            TEXT NOT NULL,   -- registry/declaration-driven, never a semantic verdict
    subject_kind         TEXT NOT NULL,   -- 'edge' | 'candidate' | 'function'
    subject_key          TEXT NOT NULL,   -- identity WITHIN the dimension (edges: binary|mech|key|func)
    binary               TEXT,            -- the diff's target binary (short name), parsed from
                                          -- subject_key; NULL for the marker / scope-unrecorded row
    state_a              TEXT,            -- A-side annotation, OPAQUE to this layer
    state_b              TEXT,            -- B-side annotation, OPAQUE to this layer
    delta_kind           TEXT NOT NULL
        CHECK (delta_kind IN ('layer_changed','layer_unchanged','delta_undetermined')),
    undetermined_scope   TEXT
        CHECK (undetermined_scope IS NULL OR undetermined_scope IN ('data','capability')),
    undetermined_reason  TEXT,            -- machine-readable label; enum may grow (do not branch on it)
    capability_ref       TEXT,            -- the dimension, when scope='capability'
    alignment_confidence REAL,            -- carried when the delta relied on a function alignment
    UNIQUE(diff_id, dimension, subject_kind, subject_key)
);
CREATE INDEX IF NOT EXISTS idx_dimdelta_diff ON dimension_delta(diff_id);
CREATE INDEX IF NOT EXISTS idx_dimdelta_dim  ON dimension_delta(diff_id, dimension);
CREATE INDEX IF NOT EXISTS idx_dimdelta_kind ON dimension_delta(diff_id, delta_kind);
CREATE INDEX IF NOT EXISTS idx_dimdelta_bin  ON dimension_delta(diff_id, binary);

-- ── layer-2 diff: dimension_capability_state ─────────────────────────────────
-- Per-dimension capability state on BOTH sides, recorded explicitly so a
-- dimension neither side can delta is VISIBLE as a declared gap, never invisible
-- by absence. TWO ORTHOGONAL facts:
--   * state_a / state_b = ANALYSIS capability of each RUN: 'present' (a
--     run_capability row with present=1) | 'declared_absent' (present=0) |
--     'registration_unknown' (NO row). Absence of a row is NOT 'declared_absent'
--     -- that conflation is the empty!=absent trap at the capability layer.
--   * delta_supported = whether THIS layer's CODE version can compute a delta for
--     the dimension at all. An analysis can exist while no delta is implemented
--     (delta_supported=0) -- the dimension is then visible here, never silently
--     absent. These two are independent: (present,present,1)=normal;
--     (present,present,0)=analysis exists, delta not built; (not-present,*)=no
--     analysis.
CREATE TABLE IF NOT EXISTS dimension_capability_state (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    diff_id      TEXT NOT NULL,
    dimension    TEXT NOT NULL,
    state_a      TEXT NOT NULL
        CHECK (state_a IN ('present','declared_absent','registration_unknown')),
    state_b      TEXT NOT NULL
        CHECK (state_b IN ('present','declared_absent','registration_unknown')),
    delta_supported INTEGER NOT NULL CHECK (delta_supported IN (0,1)),
    UNIQUE(diff_id, dimension)
);

-- ── layer-2 diff: dimension_delta_full (visibility view) ─────────────────────
-- The base dimension_delta stays honest: it writes NO per-subject placeholder
-- rows for a dimension it never examined a subject of (that would fake "checked
-- every subject, all undetermined"). But a consumer scanning only dimension_delta
-- would then miss those dimensions -- back to expressing a gap by absence. This
-- view projects each unsupported/absent dimension into ONE dimension-level
-- capability-undetermined row and unions it in, so one query sees the whole
-- dimension universe while the base table tells no per-subject lie.
CREATE VIEW IF NOT EXISTS dimension_delta_full AS
  SELECT diff_id, dimension, subject_kind, subject_key, delta_kind,
         undetermined_scope, undetermined_reason, capability_ref
    FROM dimension_delta
  UNION ALL
  SELECT diff_id, dimension, 'dimension' AS subject_kind, dimension AS subject_key,
         'delta_undetermined', 'capability',
         CASE WHEN delta_supported = 0 THEN 'delta_not_implemented'
              ELSE 'capability_absent' END,
         dimension
    FROM dimension_capability_state
   WHERE delta_supported = 0 OR state_a <> 'present' OR state_b <> 'present';

-- ── overlay: a mutable annotation layer over the read-only candidate map ──────
-- Holds an AGENT's OWN annotations on scan/hunt candidates — never a tool-emitted
-- fact, and NEVER written back onto instance/pattern (which stay untouched). A
-- consumer reads the base map, decides something about a candidate, and records
-- that decision here, keyed by the candidate's evidence_ref. Two views share one
-- base map: with the overlay off (the default) the base map reads byte-for-byte
-- as if this table were empty; with it on, these annotations are shown ALONGSIDE
-- the base facts, always distinguishable from them.
--
-- The row is MUTABLE (one annotation per anchor, last write wins) — this is why
-- it lives outside the append-only instance/pattern store. basis_state snapshots
-- the facts the annotation rested on at write time (the function's pseudocode
-- hash + the per-sibling dimension set); a later read re-derives that basis and
-- reports what moved, so an annotation made against now-stale facts is flagged
-- for re-review. The layer reports those facts ONLY — whether a changed basis
-- undoes the annotation is the consumer's judgement, never asserted here.
CREATE TABLE IF NOT EXISTS overlay (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    anchor_kind   TEXT NOT NULL DEFAULT 'evidence_ref'
        CHECK (anchor_kind IN ('evidence_ref','diff_subject')),  -- diff_subject reserved (unused)
    anchor_ref    TEXT NOT NULL,            -- evidence_ref (run_id#sha8:addr@suffix) for the MVP kind
    -- Which firmware this annotation belongs to. DERIVED from anchor_ref (the segment before '#'),
    -- stored explicitly so filtering to one firmware is an exact equality match instead of a
    -- string prefix probe. Nullable: an anchor kind that carries no run segment leaves it NULL
    -- rather than guessing. It does NOT change the uniqueness rule below.
    run_id        TEXT,
    -- No CHECK here on purpose. The vocabulary is still evolving, and pinning it in the schema
    -- means every wording change costs a table rebuild that has to carry real annotations across.
    -- Validity is enforced where the writes are: the sole write path is overlay.py::upsert_overlay,
    -- which validates at its head. A static gate pins that overlay writes spelled contiguously in
    -- source text, outside lib/overlay.py, are zero apart from the whitelisted migrations — text
    -- matching, so it cannot claim more than that. A second test pins that every known verdict has
    -- an ordering band, so a new one cannot slip in unhandled.
    verdict       TEXT NOT NULL,
    rationale     TEXT NOT NULL,            -- why + next step + confidence; blank is rejected at write
    attributed_to TEXT
        CHECK (attributed_to IS NULL OR attributed_to IN ('agent','agent-via-mcp')),  -- coarse; never faked
    basis_state   TEXT,                     -- JSON snapshot: pseudocode_hash + per-sibling dimension set
    -- Structured justification for the two verdicts that require one, JSON keyed by `kind`:
    -- safe {block_source, block_point, block_why} / exploitable {chain, verification_gaps,
    -- shared_prereq}. NULL for every verdict that carries none. NOT the same thing as basis_state
    -- above: that snapshots the FACTS an annotation rested on (for staleness); this records WHY the
    -- consumer reached the conclusion. Two columns, two jobs, neither written from the other.
    verdict_basis TEXT,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- one annotation per anchor: a re-annotation UPDATES in place (last write wins)
    UNIQUE (anchor_kind, anchor_ref)
);
CREATE INDEX IF NOT EXISTS idx_overlay_verdict ON overlay(verdict);
