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
    build_hash        TEXT,             -- extraction-pass content hash (pass_version) — STALE-scan signal
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

-- exploit-barrier buckets — the two are PHYSICALLY SEPARATE tables on purpose (not one table + a
-- source column). They differ in sensitivity, who can produce them, and whether they count toward
-- barrier depth; the split makes those three un-mixable at the storage layer (a public row can never
-- be mis-exported as private, and public volume can never inflate depth — depth counts private only).

-- public_cve_pattern (FRONT-STAGE): public-CVE exploit forms. An agent may fill it. NOT counted
-- in barrier depth (it is breadth/material, not a barrier). Not sensitive.
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

-- private_exploit (BACK-STAGE, the real barrier): a hole its owner PROVED reachable. Admission bar =
-- EXPLOITED: exploit_note is NOT NULL (schema) AND the write tool rejects blank/whitespace — a
-- structural lead that was never exploited does NOT belong here (it stays in the pending-to-exploit
-- queue). Barrier DEPTH counts THIS table only, by COUNT(DISTINCT evidence_ref) (a hole, not a
-- corroboration row). evidence_ref is the STABLE candidate handle (survives a re-scan), never the
-- AUTOINCREMENT instance_id (which drifts). Private evidence of a real hole in a shipping product —
-- redact='vendor_sensitive' by default; REDACT ON EXPORT, and the read path withholds exploit_note
-- unless a caller explicitly reveals it. Append-only, NOT unique: one evidence_ref may gather several
-- rows (corroboration / escalation), a later write never overwrites an earlier one.
CREATE TABLE IF NOT EXISTS private_exploit (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_ref  TEXT NOT NULL,      -- the candidate this hole anchors to (stable handle, not id)
    pattern       TEXT NOT NULL,      -- exploit form (free text)
    exploit_note  TEXT NOT NULL,      -- proof: how it triggers, effect obtained, guard bypassed (bar)
    patch_form    TEXT,               -- empty; the diff line backfills the correct patch form later.
                                      --   patch_form is a property of the HOLE (evidence_ref), not
                                      --   of a corroboration row: read it as the latest non-empty
                                      --   value per evidence_ref (same hole-vs-row rule as depth).
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
