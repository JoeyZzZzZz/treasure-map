# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `tmap init` now provisions the config-resolved directories (`workspace_dir`,
  `atlas.db_path` parent, LLM cache parent) after loading config, and the preflight
  doctor checks those same paths. Previously provisioning used `Path.home()` while the
  doctor checked an `expanduser`-resolved path, so a `HOME` / `Path.home()` mismatch
  reported a freshly-provisioned `workspace_dir` as "not provisioned".

### Changed

- Boundary hygiene: removed private-path / private-document references from committed
  artifacts (`initializer.py` watchlist seeding now keys off `TM_VENDOR_WATCHLIST` only,
  `xrefs.py` comments, `CONTRIBUTING.md`, pre-commit messages, watchlist example header).
  Renamed a vendor-specific daemon name in a test fixture to a neutral placeholder.
- pre-commit hook: added a private-document / private-path guard (blocks staged
  `src/`, `docs/`, `*.md`, `.githooks/*`, `CONTRIBUTING.md` content that names private
  notes or paths).
- boundary: removed private-document section and design-code citations from committed
  code (comment/docstring/string edits only, no logic change); added a matching
  self-contained-code guard to the pre-commit hook.

### Added

- M2 Step 3 (R1): function summary filler (`lib/analyze/summarize.py`). Fills
  `functions.summary` via the S-tier LLM router — the first real pipeline use of
  router → cache → cost-guard → S-tier provider. Idempotent and resumable (selects
  only `summary IS NULL` rows with pseudocode; failed items stay NULL for the next
  run). Opt-in via `tmap analyze --summarize` / `--summary-limit N`; a plain key-less
  `analyze` is unchanged and never builds a router. Missing/invalid S-tier key skips
  with one message and analysis still succeeds. `PROMPT_VERSION` constant gates the
  router cache. `build_router` gained a `tiers=` parameter so summarization needs only
  the S-tier key.
- Initial project structure
- AGPL-3.0 license
- M2 Step 2 (R0): `tmap init` onboarding command (`cli/init_cli.py`, `lib/setup/`).
  Provisions `~/.treasure-map/` tree (config.yaml, .env chmod 0600, workspaces/).
  Runs preflight doctor: Ghidra, Java, binwalk, API keys, dir writability.
  Flags: `--force` (overwrite existing config), `--non-interactive` (skip prompts),
  `--check-only` (inspect only; exits non-zero on any red check).
  `AtlasConfig` added to `Config`; `_source_env_file` wired into `load_config` as
  first statement (non-override semantics; `TM_ENV_FILE` override for testability).
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
