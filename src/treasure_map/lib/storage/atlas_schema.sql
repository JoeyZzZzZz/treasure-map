-- Treasure Map atlas — cross-firmware pattern store (THE moat, PRD §13).
-- PERSISTENT, append-and-corroborate. NOT wipe-and-rebuild (that is analysis.db).
-- Lives OUTSIDE any repo (default ~/.treasure-map/atlas.db). Zero vendor identity (§5.5).
-- Field names are NEUTRAL (§2.8): mechanism, never the shield's judgment.
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS pattern (
    pattern_id               INTEGER PRIMARY KEY AUTOINCREMENT,
    source_class             TEXT NOT NULL,
    sink_class               TEXT NOT NULL,
    call_sequence_shape      TEXT NOT NULL,
    structural_fingerprint   TEXT,
    fingerprint_algo_version TEXT NOT NULL DEFAULT 'v0',
    device_category          TEXT,             -- generic ONLY: router/camera/nas; NEVER vendor/model (§5.5)
    moat_breadth             INTEGER NOT NULL DEFAULT 0,  -- COUNT(DISTINCT source_run_id) — see writer
    first_seen_at            DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_updated_at          DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS instance (
    instance_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_id          INTEGER NOT NULL,
    pseudocode_hash     TEXT,             -- deterministic content hash of the evidence function
    source_anchor       TEXT,             -- located via name/address/string/diff (§6.7 stripped-safe)
    sink_anchor         TEXT,
    source_run_id       TEXT,             -- NEUTRAL per-firmware-run id (moat_breadth unit, §13.7); §5.5-safe
    reachability_status TEXT NOT NULL DEFAULT 'unknown'
        CHECK (reachability_status IN ('confirmed','blocked','unknown')),
    blocking_mechanism  TEXT,             -- categorical: char_filter/length_check/... NULL if none
    provenance_level    TEXT NOT NULL DEFAULT 'L0'
        CHECK (provenance_level IN ('L0','L1','L2','L3')),
    external_anchor     TEXT,             -- external evidence authorizing L2/L3 (patch ref / CVE); NULL for L0/L1
    fix_diff            TEXT,             -- NEUTRAL change region (NOT fix_quality_score); redact on export
    scope_origin        TEXT,             -- intra_firmware | intra_vendor | cross_vendor (§4.4)
    evidence_ref        TEXT,             -- provenance trail to source analysis.db + binary/function
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
    -- traceability (anti-orphan, §8.6/§13.7): an instance must trace to source evidence
    CHECK (pseudocode_hash IS NOT NULL OR evidence_ref IS NOT NULL),
    -- no L2/L3 without an external anchor (§13.4/§8.8): schema-enforced, not writer-only
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
