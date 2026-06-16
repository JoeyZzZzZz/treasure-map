# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Candidate locatability: every atlas `instance` now records the **full path** of the binary
  its evidence function lives in plus that binary's **content hash**, both auto-filled from the
  source build (no manual entry). `tmap triage`, `tmap scan`, and `tmap triage --explain` print
  the binary path (`in: <path>` under each row; `binary` in the explain view; `binary_path` in
  `--json`) so a high-ranked candidate in a firmware of hundreds of binaries is directly
  actionable — which file to open in the decompiler. The location is read straight from the
  atlas (no read-time join back to `analysis.db`), so candidates stay locatable even after the
  per-firmware `analysis.db` is wiped/rebuilt. Both new columns are nullable, added by an
  idempotent in-place migration (old atlases gain them with NULLs; rows and all derived ledger
  counts are preserved), and marked **redact-on-export** as private evidence. The content hash
  is **stored only** this round — no metric consumes it yet.
- Intended-use / legal reminder: `tmap scan` and `tmap triage` print a short neutral notice
  (defensive audit + research tool; output is leads, not attack code; lawful, authorized use is
  the user's responsibility), and the README gains an "Intended Use & Legal" section. The notice
  goes to stderr and is suppressed under `--json`, so machine output is unchanged.

### Changed

- reachability (R2) v1 verdict set is now `confirmed` / `unknown` only; `blocked` is reserved
  for the deep data-flow engine (R2-deep) and v1 never emits it. Deciding NON-reachability
  soundly needs path-/alias-sensitivity an intra-procedural regex read does not have, and a
  false `blocked` would route a live path into the dormant partition and halt investigation —
  the one error v1 must never make. A would-be `blocked` (a validator appears to cover the
  inputs reaching the sink) now grades `unknown` with an honest `basis`. `confirmed` is
  unchanged. `blocked` stays a valid `ReachabilityStatus` and in the atlas schema and the
  `dormant_instance` / `twin_candidate` views (R2-deep's slot); the taint / validator / clamp
  helpers stay wired into the `confirmed` gate (a validator on the path, a parameter
  contribution, or a clamp demotes a would-be `confirmed` to `unknown`). No new field added.
- Gate amendments (M2): the R2 gate's landap-class case now expects `unknown` (apparent
  filter v1 cannot verify), the filter-present vs filter-absent verdict deferred to R2-deep;
  greendownload-class and stripped/empty-callee cases are unchanged. The A2 gate's `dormant`
  and `twins` views are honestly EMPTY in M2 (both require a sound `blocked` v1 cannot
  produce); the `density` view is unaffected and remains the A2 deliverable.
- Docs: `uv` is now the recommended install method (`uv tool install --python 3.11
  "git+…"`). uv brings its own managed CPython 3.11, so no system Python and no
  deadsnakes/PPA is needed (the prior path failed on locked-down networks where Launchpad
  is unreachable); pipx remains a one-line alternative.
- `tmap init` is now idempotent: it reuses an existing `config.yaml` / `.env` / Ghidra
  config instead of erroring (no more `FileExistsError` when reinstalling over a persisted
  `~/.treasure-map/`). A re-run never clobbers `.env` (present keys are kept; only missing
  ones are prompted for and appended); an already-configured + valid `ghidra.local.home` is
  reused without re-prompting (effective order: existing config → `GHIDRA_HOME` → PATH →
  prompt). `--force` regenerates `config.yaml` only — it never touches `.env` or `atlas.db`.
- Docs: README documents how to uninstall (`uv tool uninstall treasure-map`) — which
  deliberately keeps `~/.treasure-map/` (config, `.env`, the never-rebuilt `atlas.db`) — and
  the not-recommended full wipe (`rm -rf ~/.treasure-map`), with a warning about losing keys
  and the accumulated `atlas.db`. Removed the "Upgrading from earlier versions" section.
- `tmap analyze -w/--workspace` now accepts a workspace **name** (managed under `workspace_dir`,
  e.g. `-w router_v1` → `<base>/router_v1`) or a **path** (a value with a `/`, `~`, leading `.`,
  or absolute is used verbatim, e.g. `-w /mnt/scratch/fw1`). Omitting it picks a **deterministic
  auto name** derived from the firmware root (re-runs on the same firmware resume; the old random
  uuid suffix is gone). The resolved workspace is echoed, showing which form was used. Resolution
  is a tested pure function in `lib/workspace/`. `tmap init` now confirms/persists the workspace
  base dir (`workspace_dir`), idempotent per the init rules. CLI help expanded: every command has
  a `short_help`, so `tmap --help` no longer truncates the command list; `analyze --help` documents
  the name/path rule with examples.

### Removed

- **Breaking:** removed the `tm` command alias — only `tmap` ships now. (Pre-alpha with no
  real user base; the README previously promised removal in v0.3, removed now instead.)

### Fixed

- reachability (R2): `blocked` now requires clean, direct, unambiguous full coverage — a
  possibly-reachable path is never downgraded to `blocked` (which would route it into the
  dormant partition and stop investigation). Two mis-downgrade paths are removed: (1) the
  function-wide inline-clamp `blocked` return is gone — a clamp may only downgrade a
  would-be `confirmed` to `unknown` (the safe direction), never produce `blocked`; (2) the
  flow/dependency set is now cleaned (callee names, C/Ghidra type words, and split-hex
  fragments are no longer treated as flow edges), and coverage is judged per ORIGINATING
  seed input with a single-direction test (a validator must sit on that seed's own path
  into the sink) — a validated, unrelated intermediate can no longer spuriously cover a
  dangerous input. `blocked` fires only when every dangerous seed reaching the sink is
  cleanly covered; under any doubt the verdict is `unknown`. Clean single-input blocks are
  preserved. Regression fixtures are synthetic and vendor-neutral.

- reachability (R2): block only when ALL dangerous inputs reaching a sink are covered by a
  validator. Previously the grader returned `blocked` as soon as ANY variable on the flow
  path matched a validator, so a sink fed by [validated value + an unvalidated parameter or
  weak/config value] was mislabeled `blocked` — mislabeling a live, unfiltered path as
  dormant ("stop looking"). The grader now computes each tainted value reaching the sink,
  marks it covered only if a validator sits on its flow line (either direction), and blocks
  only when every such input is covered; otherwise it grades by the most-severe UNCOVERED
  input (uncovered strong in-function source → `confirmed` subject to the existing guards;
  uncovered parameter or weak source → `unknown`). A covered sibling can no longer mask an
  uncovered input. Fully-covered sinks still block (precision, not retreat); the
  never-auto-confirm invariant and mis-block caution are unchanged. Regression fixtures are
  synthetic and vendor-neutral.

- reachability (R2): recognize a validator applied anywhere on the data-flow path into the
  sink, not only on the sink argument's final name. A validated value that reaches the sink
  through renamed intermediates (copy/format calls) was graded `unknown` instead of
  `blocked`; a new conservative backward dependency walk (`flows_into`) computes the sink's
  in-function flow set and the validator check widens to any variable in it. This improves
  blocked/dormant precision (genuinely filtered candidates leave the unknown pool) and is
  purely a precision gain — it only moves some `unknown` → `blocked`, creates no new
  `confirmed` (the never-auto-confirm invariant is unchanged), and an off-path validator
  still does not block (mis-block caution preserved). Regression fixtures are synthetic and
  vendor-neutral.

- `tmap init` now CONFIGURES Ghidra, not only checks it. A new step runs between secrets
  entry and the preflight doctor: it auto-detects `analyzeHeadless` (via `GHIDRA_HOME`/PATH)
  and accepts it without prompting when found; otherwise it prompts for the install root,
  validates that the path contains `support/analyzeHeadless`, and writes it to
  `config.yaml` as `ghidra.local.home`. Non-interactive or blank input leaves the setting
  unset (run-time auto-discovery), never blocking a scripted init. The path is written to
  `config.yaml` only (non-secret); the `.env` secrets model is unchanged. Previously a user
  with Ghidra installed elsewhere finished init with a red check and had to hand-edit config.

- reachability (R2): tighten `confirmed` so it requires a provable in-function flow from a
  STRONG (network/request) source. A real-firmware run over-claimed `confirmed`; three
  causes are fixed: (1) taint now follows real flow, not co-occurrence — a source taints
  only the value it produces (assigned LHS for return-value sources; the specific buffer
  argument for buffer-output sources), and `confirmed` requires the sink argument itself to
  be tied to an in-function source by the assignment chain; (2) inline bounds/clamps (e.g.
  `if (N < len) len = N;`, ternary clamps, `min(...)`) are now recognized, so a clamped copy
  grades `blocked`, not `confirmed`; (3) sources are split into strength tiers
  (`SOURCE_STRONG` network/request vs `SOURCE_WEAK` env/config/device-self/file) — only a
  strong in-function source can grade `confirmed`; a weak one grades `unknown`. The `SOURCE`
  union is unchanged, so R-pattern's shape detection is unaffected. Net effect: `confirmed`
  is rare; under any gap the verdict is `unknown`. No public count was affected (all
  instances are L1; `public_finding` needs confirmed AND ≥ L2, still empty). New regression
  fixtures are synthetic and vendor-neutral (no real firmware strings).

### Added

- `lib/hunt/analyzer2.py` + `tmap hunt-pattern` + `lib/query/` + `tmap atlas-view`: Analyzer-2,
  the pattern-driven analyzer, and the neutral read-side views — the last M2 round. A2 composes
  two hermetic primitives (no LLM): R-pattern scans one analysis.db for call-sequence shape
  candidates (OSS excluded at scan time), R2 grades each, and A2 upserts the RICH `callseq-v1`
  pattern + writes a graded instance into the atlas — the first time R-pattern's output reaches
  the persistent store. L0/L1 only (never L2/L3, never an external anchor); raw firmware-derived
  evidence is never persisted (traceability rides `pseudocode_hash`; `evidence_ref` holds only the
  neutral structural fingerprint). New neutral atlas views `density_candidate` (candidate count per
  run / sink_class / fingerprint) and `twin_candidate` (a fingerprint seen with both a blocked and
  a non-blocked instance), plus a thin reader of the existing `dormant_instance`; `lib/query/`
  exposes `density` / `twins` / `dormant` returning frozen rows. `tmap hunt-pattern <db> --run-id R`
  runs the writer (hermetic, no key needed) and `tmap atlas-view {dormant|density|twins}` prints a
  view; every row is a lead/candidate, never a confirmed result. `public_finding` stays empty.
  Honest M2 scope: density runs for real intra-firmware, but with one device the recurrence stays
  ~1 — A2 builds the machine, it does not produce a thick cross-firmware store from one device.
  Synthetic, mock-free tests cover the write path, OSS exclusion, evidence neutralization, the
  L0/L1 mapping, density/twins/dormant logic, append-only accumulation, and the boundary.
- `lib/hunt/analyzer1.py` + `tmap hunt-diff`: Analyzer-1, the diff-driven analyzer and
  the first thing that writes to the atlas. Composes R-diff (locate changed functions) +
  R2 (grade reachability) end-to-end on one operator-supplied version pair and writes
  neutral, graded instances into atlas.db. A1 writes provenance L0/L1 only (confirmed or
  blocked → L1, unknown → L0); L2/L3 need an external anchor and are out of reach here, so
  A1 never passes one — the writer and schema CHECK enforce this. It upserts a COARSE
  pattern versioned `diff-coarse-v0` (deliberately distinct from R-pattern's `callseq-v1`)
  to satisfy the instance→pattern link without running R-pattern. `public_finding`
  (confirmed AND ≥ L2) is empty by construction; a blocked candidate shows in
  `dormant_instance`. Both analysis DBs are read-only; the atlas is append-only.
  `tmap hunt-diff <db_a> <db_b> --axis version --run-id-a A --run-id-b B` runs the chain
  and prints the stats plus an honest note. Honest M2 scope: this validates the
  primitive→scenario→write-atlas pipeline, not the cross-device find (only one firmware is
  analyzed). Synthetic, mock-router tests cover the L0/L1 mapping, the empty-public_finding
  gate, dormant population, the never-L2/L3 invariant, no-sink degrade, append-only
  accumulation, and the boundary.
- `lib/reachability/`: reachability grading primitive (`grade_candidate`). Given one
  function's pseudocode + callees + the sink it reaches, grades the candidate
  confirmed / blocked / unknown with a neutral `blocking_mechanism` / `basis`. Honest
  intra-procedural v1: a single-function heuristic, deliberately NOT an inter-procedural
  data-flow engine — `unknown` is first-class and expected to dominate, and `confirmed`
  is tightly gated (in-function external-input origin + unfiltered + fully visible; a
  parameter-sourced sink is never confirmed). Validator detection is a generic name
  heuristic (`check_*`/`validate_*`/`saniti[sz]e_*`/…); ambiguity prefers `unknown` over
  a confident `blocked`. Pure-static, hermetic (no LLM); degrade-and-flag on incomplete
  input; returns a graded lead, never a claimed bug (a confirmed path is provenance L1 at
  most, not a publishable result). Library API only (no CLI). Synthetic, network-free
  tests cover the grading table, the never-auto-confirm invariant, mis-block caution,
  degrade-and-flag, and a vendor-/label-vocabulary boundary check.
- `lib/pattern/`: call-sequence shape primitive (`scan`). Given one analysis.db, it
  finds functions whose callee set forms a coarse dangerous shape — a command-injection
  shape (external-input source + string formatter + command sink, gated by a shell-ish
  `%s` format literal) or an overflow shape (source + copy sink) — and computes a coarse
  structural fingerprint (`callseq-v1`) aligned to the cross-firmware pattern columns.
  Pure-static and hermetic: no LLM, no router, no tier. OSS/third-party binaries are
  excluded data-driven first (components-table membership) then by a generic public-OSS
  name list plus the `lib*` heuristic, so custom binaries surface without third-party
  noise. Read-only on the input; returns in-memory candidate shapes only (a match is a
  lead, never a claimed bug; evidence is raw firmware-derived text a persistence consumer
  must neutralize). Library API only (no CLI). Detectors live in an explicit registry of
  plain callables. Synthetic, network-free tests cover both shapes (positive + negative),
  OSS exclusion, the fingerprint, read-only safety, and a vendor-/label-vocabulary
  boundary check.
- `lib/diff/`: cross-entity diff primitive (`run_diff`). Given two analysis databases and
  a neutral axis (version | mod | sibling), it matches functions across them
  (exact symbol → identical pseudocode hash → bounded M-tier assist on the residue, with a
  degrade-and-flag overflow cap), classifies each as unchanged/added/removed/changed, and
  for a changed function emits a one-sentence neutral, mechanism-level description of what
  the diff changes (control flow, calls, buffer/length handling). Both inputs are opened
  read-only; the primitive returns in-memory results only — it writes nothing and judges
  nothing. Library API only (no CLI). Synthetic, mock-router tests cover the matching
  passes, the verdict path, the assist budget, read-only safety, and a boundary check that
  the package and its prompts stay mechanism-only.
- LLM infra: per-tier `thinking` control for DeepSeek-V4. `TierConfig` gains
  `thinking: bool | None` (tri-state: `None` sends nothing — legacy/Anthropic unchanged;
  `false` sends an explicit disabled; `true` enables) and `reasoning_effort` (`high`|`max`).
  Needed because V4 thinking defaults to ENABLED, so a non-thinking tier must explicitly
  disable it. Example config now maps S = `deepseek-v4-flash` (no thinking), M =
  `deepseek-v4-flash` (thinking, effort high), L = Claude.

### Changed

- Concurrency defaults raised to reflect DeepSeek-V4 capacity (flash up to 2500, pro up to
  500): S 8→64, M 20→32, L 5→8. Still well under the provider caps; raise further per plan.
- `--summarize` UX: third-party HTTP loggers (`httpx`, `httpcore`, `openai`, `anthropic`) are
  pinned to WARNING unless `--debug`, so per-request `"HTTP/1.1 200 OK"` noise no longer drowns
  our own INFO lines. Summarization now shows an in-place `summarizing functions: done/total`
  progress counter (stderr; generic counter only, no pseudocode/firmware strings) via the
  router's existing per-item `progress_callback`. `summarize_functions` gained an optional
  `progress` callback and stays presentation-free (it forwards, it does not print).

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
