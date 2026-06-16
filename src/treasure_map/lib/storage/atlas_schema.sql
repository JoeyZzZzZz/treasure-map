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

CREATE INDEX IF NOT EXISTS idx_pattern_classes ON pattern(source_class, sink_class);
CREATE INDEX IF NOT EXISTS idx_pattern_fp      ON pattern(structural_fingerprint);
CREATE INDEX IF NOT EXISTS idx_instance_pattern ON instance(pattern_id);
CREATE INDEX IF NOT EXISTS idx_instance_reach   ON instance(reachability_status);
CREATE INDEX IF NOT EXISTS idx_instance_prov    ON instance(provenance_level);
CREATE INDEX IF NOT EXISTS idx_instance_scope   ON instance(scope_origin);
CREATE INDEX IF NOT EXISTS idx_instance_run     ON instance(source_run_id);
