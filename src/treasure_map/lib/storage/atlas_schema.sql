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
    device_category          TEXT,             -- generic ONLY: router/camera/nas; NEVER vendor/model
    recurrence_breadth       INTEGER NOT NULL DEFAULT 0,  -- COUNT(DISTINCT source_run_id) — see writer
    first_seen_at            DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_updated_at          DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS instance (
    instance_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_id          INTEGER NOT NULL,
    pseudocode_hash     TEXT,             -- deterministic content hash of the evidence function
    source_anchor       TEXT,             -- located via name/address/string/diff (stripped-safe)
    sink_anchor         TEXT,
    source_run_id       TEXT,             -- NEUTRAL per-firmware-run id (recurrence_breadth unit); vendor-free
    reachability_status TEXT NOT NULL DEFAULT 'unknown'
        CHECK (reachability_status IN ('confirmed','blocked','unknown')),
    blocking_mechanism  TEXT,             -- categorical: char_filter/length_check/... NULL if none
    provenance_level    TEXT NOT NULL DEFAULT 'L0'
        CHECK (provenance_level IN ('L0','L1','L2','L3')),
    external_anchor     TEXT,             -- external evidence authorizing L2/L3 (patch ref / CVE); NULL for L0/L1
    fix_diff            TEXT,             -- neutral change region; redact on export
    scope_origin        TEXT,             -- intra_firmware | intra_vendor | cross_vendor
    evidence_ref        TEXT,             -- provenance trail to source analysis.db + binary/function
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

CREATE INDEX IF NOT EXISTS idx_pattern_classes ON pattern(source_class, sink_class);
CREATE INDEX IF NOT EXISTS idx_pattern_fp      ON pattern(structural_fingerprint);
CREATE INDEX IF NOT EXISTS idx_instance_pattern ON instance(pattern_id);
CREATE INDEX IF NOT EXISTS idx_instance_reach   ON instance(reachability_status);
CREATE INDEX IF NOT EXISTS idx_instance_prov    ON instance(provenance_level);
CREATE INDEX IF NOT EXISTS idx_instance_scope   ON instance(scope_origin);
CREATE INDEX IF NOT EXISTS idx_instance_run     ON instance(source_run_id);
