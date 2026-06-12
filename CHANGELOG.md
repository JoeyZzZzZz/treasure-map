# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial project structure
- AGPL-3.0 license
- M2 Step 1 (R-KB): `atlas` cross-firmware pattern store (`lib/atlas/`) — persistent,
  append-and-corroborate cross-firmware pattern store (`atlas.db`).
  Schema (`lib/storage/atlas_schema.sql`) with two schema-level CHECK constraints:
  traceability (pseudocode_hash OR evidence_ref required) and L2/L3 anchor gate
  (external_anchor required for provenance ≥ L2). Idempotent opener (`open_atlas`),
  frozen row models (`PatternRow`, `InstanceRow`), append-only writer
  (`upsert_pattern`, `add_instance`, `add_instances`), and `AtlasStats` counter.
  recurrence_breadth = COUNT(DISTINCT source_run_id) — never COUNT(DISTINCT scope_origin).
  **WARNING**: Moving atlas.db requires `sqlite3.backup()` or `wal_checkpoint(TRUNCATE)`
  before any file-copy — never a bare `cp` while WAL side-files (.db-wal, .db-shm)
  exist; unmerged pages yield "database disk image is malformed" on next open.
