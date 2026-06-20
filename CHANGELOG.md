# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- The pattern analyzer now recovers command candidates whose sink hides one hop inside a thin
  command wrapper (factor ①): a function that builds a string and forwards it to a function marked
  `is_thin_cmd_wrapper` — with no command sink among its own callees — becomes a command candidate
  whose sink is the wrapper's `wrapped_sink`. This recovers the recall blind spot where the real
  `system` lives in a 3-12-instruction forwarding shell, invisible to the direct-callee shape scan.
  Deliberately narrow (the only recall-amplifying step): ONE hop, INTRA-binary, and only for
  functions with no direct command sink of their own; multi-hop, indirect/function-pointer, and
  cross-binary wrappers are not propagated (blind spots left to the agent). New candidates run
  through the same FP-suppression — a constant or inline-charset-constrained argument forwarded to
  the wrapper is downweighted (`const_sink_arg` / `charset_constrained`), so a safe fanout stays
  low while a free / constructed string surfaces high. They are graded unknown / L0 (the sink is
  across a call boundary) and their flow evidence marks `sink_via_wrapper` + the wrapper name and a
  `reached_sink_via_one_hop_wrapper` boundary. A `wrapper_propagated` stat reports how many were
  recovered (so an over-broad wrapper judgment surfaces as a count to tighten, not a silent flood).
- Command-sink candidates now carry structured flow EVIDENCE (`flow_evidence` JSON on the
  instance, with an in-place atlas migration): `source_kind` (charset_safe / free_string /
  charset_maybe / unknown), `flow_path` (the one-hop value flow, real variables only),
  `sanitizer_seen` (any sanitizer-shaped call + whether it sits on the sink path, coverage ALWAYS
  `unjudged`), `entry_reach` (rootfs invocation sites consumed from the L0.5 `script_calls` /
  `web_endpoints` tables — every site listed; none-found is reported as `unknown`, never
  "unreachable"), and `trace_boundary` (an honest statement of where the structured trace stopped:
  reached_sink / charset_via_intermediate_untraced / one_hop_limit / two_hop_untraced /
  indirect_call / ipc_global / copy_alias_untraced). It is material for a downstream agent — it
  states facts and blind spots, never a "sanitized" / "triggerable" verdict, and no recall,
  review-ordering score, or reachability grade reads it.
- The charset-constrained-source downweight is INLINE-ONLY: it fires only when the converter
  builds the sink argument directly within one expression (`snprintf(cmd,"…%s",ether_ntoa(x))`).
  A value laundered through any intermediate variable (`conv(); strncpy(buf,…); snprintf(cmd,…,buf)`)
  is deliberately NOT value-tracked or downweighted — charset recognition does not chase a value
  across one hop, two hops, … (the slippery slope of value tracking). Such a candidate is instead
  surfaced to the agent as a `charset_maybe` lead with a `charset_via_intermediate_untraced`
  boundary. A free source reaching the sink always wins over a charset converter also present in
  the function, so a genuinely dangerous candidate is never washed into `charset_maybe`.

- The pattern analyzer now records a neutral STRUCTURAL fact on each candidate: whether the
  function is a thin command-forwarding wrapper (its body does little more than hand one of its
  own parameters straight to a shell command sink) and which sink it forwards to. Stored on the
  instance (`is_thin_cmd_wrapper` / `wrapped_sink`, with an in-place atlas migration); it is a
  fact, not a verdict — no recall, downweight, or review-ordering path reads it this round (it is
  recorded for a later analysis layer to consume). Conservative under doubt; synthetic fixtures.
- The charset-constrained-source downweight now also fires on the command-sink path for the
  inline shape — a command string built directly from a charset-safe converter result
  (`snprintf(cmd, "...%s", ether_ntoa(x)); system(cmd)`) with no intermediate variable to name
  the result — matching the buffer-copy path's standard. Recall-neutral by an all-writes rule: a
  buffer qualifies only when every write to it is a literal or an inline charset-safe converter,
  so a later free append or a free value mixed into the same builder leaves the candidate at its
  normal score (never a false downweight).

- Vendor-neutrality enforcement is now wired to actually run, in three layers sharing one
  detection library (`.githooks/lib.sh`): the existing `pre-commit` (scans staged diff content),
  a new `commit-msg` hook (scans the commit message — a model number must not hide there), and a
  new CI `vendor-neutrality` job that re-scans both the diff and every commit message over the
  pushed range as a backstop when the local hooks were never installed or were bypassed. A new
  `scripts/install-hooks.sh` sets `core.hooksPath`, and `CONTRIBUTING.md` makes running it a
  required post-clone step. The example watchlist gains a lower-case run-together model pattern
  (short letter prefix + ≥3 digits) with a negative lookahead whitelisting common technical tokens
  of the same shape (`sha256`, `base64`, `arm32`, `ipv4`, `crc32`, int/float widths, arch/OS tags)
  so they are never flagged; covered by false-positive tests.

### Removed

- Five historical leftovers are cleared: (1) the empty `lib/verify/` placeholder is deleted (it
  was the repo's only `verify`-named placeholder and will not be rebuilt); (2) the dead `agent/`
  stub — a never-implemented natural-language tool-call loop plus its old analyze-tool wrapper —
  is deleted, since exposing capabilities to an AI consumer is the (future) MCP layer's job, not
  the tool's own loop (the CLI is untouched: it is the human/CI entry point, not an agent loop);
  (3) the built-in per-1M-token price tables in both providers (`_COST_PER_1M*`, `_DEFAULT_COST`)
  are removed — the tool no longer ships any vendor dollar figure; (4) the
  `07_ai_summarize.py` provenance comment in `router.py` is dropped (the `--summarize` command was
  already removed; the migration's `_DROPPED_COLUMNS` `functions.summary` entry is intentionally
  kept). All deletions verified zero-reference.

### Changed

- LLM cost is now computed from operator-supplied prices, not built-in vendor rates. `TierConfig`
  gains optional `input_price_per_1m` / `output_price_per_1m`; when both are set a provider
  computes real cost = price × actual token usage. When either is unset, real cost is unknown
  (`LLMResponse.cost_usd` is `None`) and the cost-guard degrades to count-based accounting — each
  call is charged one `max_cost_per_call_usd` quota unit, so the run/day caps still bound the call
  count without inventing a price. The cost-guard's confirm/circuit-breaker/ledger machinery is
  unchanged; only the source of the cost number changed (built-in table → operator price or count).
- `tmap init` now generates a config using the current model names and explicit thinking control
  (S: `deepseek-v4-flash`, `thinking: false`; M: `deepseek-v4-flash`, `thinking: true`,
  `reasoning_effort: high`; L unchanged), matching `config.example.yaml` and retiring the legacy
  `deepseek-chat` / `deepseek-reasoner` aliases before their upstream removal. Price fields are
  left unset (operator-supplied).

### Fixed

- Diff change-classification is now three-state, so a missing decompilation is never mistaken for
  a change. A both-present pair is decided by whether each side has a body: both bodies present →
  compare hashes (equal = unchanged, else = changed + unified diff); neither side has a body (both
  decompilations timed out) → `skipped_no_body` (no information, not a change, dropped like
  unchanged); exactly one side has a body → `changed_unverifiable` (cannot tell — flagged, never
  silently unchanged, never mixed into the describable `changed`). Previously a both-empty pair
  fell through to `changed`, inflating the lead count and burying real patches. On the dcs932l
  before/after pairs this removed hundreds of phantom changes: a self-diff (identical re-analysis)
  went from 330 "changed" (all from timed-out functions) to 0; two near-identical v2.18 builds from
  348 to 17; the real v2.17→v2.18 bump from 809 to 480 — while every both-bodies-present change is
  unchanged-in-behavior (a substantively patched function whose counterpart timed out stays
  `changed_unverifiable`, never `unchanged`). `DiffStats` and the `hunt-diff` summary now print
  `changed` / `changed_unverifiable` / `skipped_no_body` separately.

### Removed

- The L-tier `patch_verdict` step (`describe_change`) is removed from the diff path: it produced a
  neutral one-sentence description of each changed function that the `hunt-diff` writer discarded
  (it keeps its own deterministic unified diff), so it was unused cost and "reading the facts for
  the AI" — which the AI consumer does better itself. `lib/diff/verdict.py` is deleted, the
  `verdict_calls` stat is gone, and the diff path now builds only the M-tier router
  (`--max-assist > 0` no longer needs an L-tier key; `--max-assist 0` remains zero-LLM). The
  `patch_verdict` cache/registry plumbing is left in place (generic, still tested). This actions
  the L-tier item flagged in the previous round.

### Changed

- `hunt-diff` no longer hard-gates on an LLM key. The LLM is only a fallback for the residue the
  two deterministic passes (exact symbol, then pseudocode hash) cannot align — a symbol-complete
  before/after pair aligns fully statically. New `--max-assist N` exposes the match-assist budget
  (default 200); `--max-assist 0` runs PURE STATIC alignment — exact + hash only, no LLM call of
  any kind, no API key required — with the unmatched residue degraded to added/removed and
  reported (the same degrade-and-flag path as exceeding the budget). With a positive budget the
  command still builds the router, but the error when a key is missing now names `--max-assist 0`
  as the no-key escape hatch. Provider dispatch is config-driven (a test pins that a `deepseek`
  (or any OpenAI-compatible) tier builds without an Anthropic key). The matcher's alignment and
  the differ's classification are unchanged; only the CLI and tier assembly moved.

  L-tier note (recorded, not actioned this round): the L-tier `patch_verdict` call
  (`describe_change`) produces a neutral one-sentence mechanism description of each changed
  function, but the `hunt-diff` writer (`diff_analyzer`) does not consume it — it stores its own
  deterministic unified diff. The description is therefore unused cost on this path and overlaps
  the "the AI consumer reads the facts itself" principle that retired the build-time summaries.
  It is gated off at `--max-assist 0` and left intact otherwise; flagged for the owner to decide
  whether to remove `describe_change` from the diff path in a follow-up.

- Form-note downweighting is now **parameter-specific**: a candidate is ranked low only when the
  sink's dangerous argument truly comes only from the recognized safe/constant source. If any free
  value — an unsanitized string source or a caller-supplied parameter — also reaches that argument
  by a route that bypasses the safe source, the downweight is suppressed (a new taint helper,
  `free_taint_reaches`, prunes the backward walk at the converter's output). This fixes a family of
  over-suppressions that shared one root cause ("a safe thing exists in the function" wrongly read
  as "the dangerous argument is only that safe thing"): (1) a function calling both `system` and
  `execl` now anchors to the shell-running sink and is never marked `no_shell_exec` (which requires
  the whole command capability to be exec-without-a-shell); (2) the caller-constant note fires only
  when EVERY caller argument is a literal, so `f("prefix", tainted)` is not downweighted; (3) a new
  `const_sink_arg` note downweights a fixed `.rodata` command string (the highest-frequency command
  false positive) while a branch-gating-but-not-value-flowing external input no longer suppresses a
  real one; (4) a new `charset_constrained` note downweights a value rendered to a safe character
  set (MAC/IP/base64-encode) only when no free value shares the same sink argument. Each fix ships
  with a symmetric "looks-downweightable but is actually dangerous" regression so suppressing a
  false positive never creates a false negative. On a real device, candidate volume is unchanged
  (506) and the top score band stays free of downweighted forms; the over-broad numeric note
  dropped from 21 to 1 candidate (those move back up, not down). The reachability grader is
  untouched.

### Removed

- Build-time LLM pre-judgment and dead placeholder fields dropped from `analysis.db` — the
  consumer of this base is an AI that reads the facts (pseudocode / disassembly / xrefs) and
  judges for itself, faster and more accurately than re-reading our pre-chewed interpretation.
  Removed the `--summarize` opt-in step and `lib/analyze/summarize.py` (LLM one-line
  `functions.summary`), the never-read `library_summaries` table (and its `library_summary` LLM
  task), the dead placeholder columns `functions.func_types` / `functions.vuln_hints` /
  `functions.capa_tags`, the categorical `vuln_hint` columns on `script_calls` / `config_entries`
  / `credentials` / `web_endpoints`, and the unverifiable predicted `script_calls.has_user_input`
  flag. All were verified write-only / never-read before removal. Kept: the deterministic candidate
  generation + grading (the product), the structural `script_calls.args_pattern`, the binary-level
  `binaries.capa_tags` placeholder, and the rule matching that gates which lines are recorded
  (signal density) and drives `is_sensitive` — only the stored label is gone. An idempotent
  in-place migration removes these columns/table from older databases while preserving every
  surviving column and all rows; building a fresh `analysis.db` no longer needs any LLM key.

### Changed

- `lib/hunt/analyzer1.py` → `lib/hunt/diff_analyzer.py` (and `run_analyzer1` → `run_diff_analyzer`):
  it is the diff-driven patch analyzer / first atlas writer, and the old name did not say so. No
  behavior change.
- Candidate generation — recall before precision: a recognized source is no longer a *gate* for
  emitting a candidate, only a scoring signal. The command-injection shape now matches on a
  constructed shell command (format + shell-ish `%s` + command sink) whether or not an
  in-function source is recognized (the controlled value may arrive through a caller), and a new
  bare command-sink fallback lists any `system`/`popen`/`exec*` callsite that has no constructed
  shell command at all. The copy/overflow shape likewise lists any `strcpy`/`strncpy`/`memcpy`
  callsite. A bare sink with no in-function source is listed but ranked low (`bare_sink`) instead
  of being silently dropped — a never-listed candidate is the most hidden false negative. Source
  coverage widened (getopt/getopt_long, recvmsg/recvmmsg, getline/getdelim/pread/readv, msgrcv/
  mq_receive). On one real device this lifted command-exec recall from ~0 to ~all callsites while
  the top of the ranked list stayed real source→sink shapes (the bare/exec/numeric forms sank to
  the low band). The reachability grader is unchanged.

### Added

- FP-suppression downweighting (recall-neutral): the pattern analyzer now recognizes known
  low-yield candidate forms and ranks them low instead of dropping them — an exec sink that
  bypasses the shell (`no_shell_exec`), a numeric validator on the value reaching the sink
  (`numeric_sanitized`), and a constant supplied by the sole one-hop caller (`caller_constant`),
  each recorded in the existing neutral `blocking_mechanism` field; plus function-symbol-level
  third-party-library recognition (e.g. statically-linked openssl/mbedtls/json-c/thrift symbols
  in a custom-named binary) which sets `origin=stock_oss_known` — beyond the existing
  binary-level OSS exclusion, and routed out of the `pattern_breadth` ledger (which counts only
  `custom`/`unknown`). Read-side
  review ordering downweights these forms hard so they sink to the bottom of their tier; nothing
  is removed and nothing is graded `blocked`. The reachability grader is untouched. Conservative:
  under doubt no form note is attached and origin stays `unknown` (never defaults to `custom`).

- Triage view entry: `tmap triage` / `tmap scan` gain `--all` (show every candidate, no cap) and
  `--sink <x>` (show every candidate for one sink — by callee `system`/`popen`/`execl`/`strcpy`/…
  or class `cmd`/`copy`/`format` — uncapped and across all statuses). The default list still caps
  at 20 but now says so when more exist. This keeps a recalled-but-low-scored sink (e.g. `system`)
  reachable from the workflow instead of being hidden below the cap. Pure view/filter: scoring, the
  atlas, candidate generation, and the stable global rank (assigned before any filter) are
  unchanged; `--json` output is unchanged.

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
