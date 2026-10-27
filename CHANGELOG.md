# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-10-26

Still a developer preview. Several MCP tool parameters and result fields changed (see Changed);
an agent prompt or script written against 0.1.0 may need adjusting.

### Upgrading from 0.1.0

- Run `tmap rescan` once. A run scanned by 0.1.0 records no code stamp, so every run is offered.
  The extraction pass is the same as 0.1.0's, so no binary is decompiled again (only binaries
  whose last extraction failed are retried): the rescan rebuilds the inventory, cross-binary
  references and non-binary facts, and hunts the run again.
- Run `tmap diff --before A --after B` again for each pair you diffed. The diff code changed, so
  every stored diff reads as out of date (`source_stale`) until it is re-run.
- Restart your MCP client (or reconnect the `treasure-map` server) so it loads the new tool list.
- `analysis.db` and the atlas gain their new tables and columns automatically on first open.

### Added

- **`start_diff_review(diff_id)`**: one call that opens a diff review — the entries to read
  first, the change at the top shown inline, the diff's metadata and its non-binary files, and
  the review workflow — sized to fit one response.
- **The changed lines, inline.** A function pair's `pseudocode_delta` carries `inline_hunk`: the
  changed blocks as each side's original text writes them, with substitutions (a moved number, a
  renamed identifier) grouped one per line. The comparisons a change introduces (a variable
  checked against a constant) are listed beside it as `guards`.
- **More reasons to read a pair first**: a sink call that changes in the callee set but not at
  the matched instruction (`sink_callee_swap`); an undetermined pair that shares an address or
  real name across the two sides and reads differently (`anchored_differs`); a function that
  loses every direct caller (`callers_a` / `callers_b`, bucket E).
- **`same_shape_siblings`**: the other calls of one sink call's shape in the same binary, and
  where each landed in the diff. A judgement that names such a group is flagged for re-checking
  when the group changes.
- **Non-binary files in a diff.** `get_file_diff` compares two runs' scripts, config files,
  credentials and web assets by path (credential values and embedded secrets are never
  returned), and `annotate_diff(..., run_pair=...)` records a judgement on one file.
- **`annotate_diff_batch`**: up to 200 judgements on one diff in a single call, all or none.
  `no_real_change` now has to point at something it checked in the current view.
- **`get_data_table`** and entry words: where a function's entry address is stored as data (a
  dispatch table, a callback slot), and a reader for the table around it.
- **`get_tool_reference`**: a tool's full description, the working guide, and the parameter-name
  table.
- `get_pseudocode` says why a function has no pseudocode (`skipped_micro`, `decompile_empty`,
  `size_unknown`); a function too small to decompile comes with its disassembly inline.
- **Scripts that start a binary indirectly** are recorded as its entry evidence: through a
  function's positional parameter (`run_it svc`), a variable holding a command (`$DAEMON`,
  `$BASE/$NAME`), or a command substitution (`X=$(svc ...)`). Each recorded script line says
  where its command came from (`via`) and which line that was (`via_line`).
  `get_script_callsites` pages its results (`tmap fact script-callsites --offset`).
- **An interrupted scan keeps its finished binaries.** Each binary is stored as soon as its
  decompile finishes; running the same command again (scan, analyze or rescan) decompiles only
  the rest. An interrupted bare `--reanalyze` continues where it stopped the next time it is run.
- **`tmap rescan` and `tmap runs` judge a run by the code that produced it** (a hash of the scan
  and hunt code, plus the parsing library version and the content-affecting config), not by the
  tmap commit: an update that does not touch the scan or the hunt leaves every run current. Runs
  that need work are grouped by what it costs — a full scan, re-extraction of the binaries the
  running pass has not yet extracted, or a re-hunt with no decompile.
- `tmap diff` retries a binary whose toolchain step failed transiently once more in the same
  run, after the parallel phase, and reports it under `recovered`.

### Changed

- **MCP tool descriptions are short cards** (the first line names the required parameters); the
  full text is one `get_tool_reference` call away. What the server sends at startup drops from
  about 95,000 to 23,000 characters. **An unknown parameter name is now refused** instead of
  being silently ignored.
- `get_diff_patch_view` reads in **significance order** by default (the entries a reviewer
  should open first lead); the previous default is `sort_by="candidate_tier"`. Pages are cut to
  fit the response budget, an entry carries at most 20 candidate rows inline (the rest paged by
  `rows_offset`), `entry_id` reads one entry in full, and `detail="summary"` gives a whole
  ranking as counts.
- A change that only shifts `__FILE__` / `__LINE__` build-info numbers is moved out of the
  read-first list, but only when the two sides' callee sets and sizes are proven equal.
- Every successful diff stores its candidate baseline, so reading a diff no longer recomputes
  the overlay.
- A promoted judgement records which kind of diff row it was carried from.
- Sink arguments are read by their form (a literal, a variable, an address, a cast, a field
  read, a call), so a type name, the first word of a string or a callee name is no longer taken
  for the variable a value flows from; the safe-value downweights are stricter about aliases.
- Script lines are split the way the shell splits them, quotes respected: a quoted value with
  spaces is one word, never a command. The command text recorded for a script line no longer
  carries those quotes.
- A binary whose extraction finished, that has executable code, and from which Ghidra recovered
  no function is recorded as `no_functions`: still listed as incomplete, named on its own line,
  and not decompiled again by the same extraction pass.
- Interactive `tmap init` downloads missing tools without asking about each one and shows a
  short numbered plan; `--dry-run` still prints the full plan with URLs and checksums.
- The agent prompts printed by `tmap init` and shown in the README ask for the whole firmware
  pair, allow an inconclusive judgement, and end with a report.

### Fixed

- `tmap uninstall` no longer leaves an empty dsh patch file that stops dsh from starting.
- A transient toolchain failure in `tmap diff` no longer needs a second run.
- Downloads under 1 MB show their size in KB instead of `0 / 0 MB`.
- `tmap init` says that tab-completion takes effect in a new shell.
- `tmap uninstall` removes the backup and the emptied config it left in Cursor and Claude
  Desktop, putting back the user's original file byte for byte.
- Interrupting a scan no longer discards every binary already decompiled in it.
- A run that has one binary the current extraction pass cannot extract is no longer listed as
  needing re-extraction forever; `tmap runs`, `tmap rescan` and `tmap init` name such binaries
  instead.
- A binary cut off by Ctrl-C (or SIGTERM / SIGHUP) is no longer recorded as failed.
- A timeout or import failure logged by an earlier Ghidra run of the same binary is no longer
  read as this run's.
- `tmap rescan` no longer changes which run `tmap mcp` serves by default.
- An interrupted `tmap diff` counts as new only the binaries it actually diffed.

## [0.1.0] - 2026-10-16

First public release — a developer preview. Commands, configuration, the atlas database and MCP
tool fields may still change incompatibly between versions.

### Added

- **Firmware map (`tmap scan`).** Takes an already-extracted firmware filesystem, decompiles every
  ELF with Ghidra 11.4.3 (headless, in parallel, with a per-binary heap and timeout and one serial
  retry, at a doubled budget, for binaries that fail), and records the facts in a per-firmware `analysis.db`:
  functions with pseudocode and a compact disassembly listing, callees, cross-binary references,
  strings, imports/exports, raw data-segment bytes, and the shell scripts, config files and web
  assets around the binaries. It then marks every call that runs a shell command, copies into a
  buffer, formats a string or opens a file by path, and writes those candidates into the shared
  atlas (`~/.treasure-map/atlas.db`).
- **Candidates annotated layer by layer, with no score.** Each candidate carries a three-state
  reading (YES / NO / UNKNOWN with the reason) on where its data comes from, how much of it is
  controllable, who wrote the value, how the spot is reached, whether anything filters it, its
  impact, and whether the function was fully analyzed. The default view ranks by impact and
  sinks only candidates proven safe; an UNKNOWN never pushes a candidate down. Command, copy and
  format-string sinks carry in-function argument provenance from Ghidra's def-use data.
- **Patch diff (`tmap diff --before RUN --after RUN`).** Runs Ghidra, BinExport and BinDiff end
  to end over every binary whose content changed, and presents a function-level patch view
  grouped by what happened around each function's dangerous calls, with an address-normalized
  pseudocode comparison and flags for changed length constants. Binaries that could not be
  diffed are listed as blind spots, never counted as unchanged; a function without a
  counterpart is reported as undetermined, never as removed or added.
- **MCP server (`tmap mcp`) with 34 tools** for an AI agent: the candidate map
  (`list_candidates`, `explain_candidate`, `get_sink_provenance`), fact readers (pseudocode,
  disassembly, callees, xrefs, strings, imports/exports, data bytes, script call sites, string
  references), cross-firmware and nvram views (`cross_firmware_patterns`, `pattern_density`,
  `get_nvram_key_flow`, `get_string_keyed_edges`, `launched_by`), the diff views
  (`get_diff_patch_view`, `get_diff_deltas`, `get_diff_sink_overlay`, `list_diff_blindspots`,
  ...), and an annotation layer (`annotate`, `annotate_diff`, `promote`, `list_overlays`,
  `clear_overlay`) that records the agent's judgements without changing the facts. Every result
  carries an anchor (binary + function + address) and the lineage of the scan that answered.
  A scan made by different extraction or hunt code than the one answering is refused, with the
  command that refreshes it.
- **Command-line readers** for a person cross-checking the agent: `tmap runs`, `tmap triage RUN`,
  `tmap fact` (pseudocode, disassembly, callees, xrefs, script call sites), `tmap atlas-view`
  (density, ledger), and `tmap exploit` for the private ledger of verified findings.
- **Install and setup.** `install.sh` installs `tmap` (PyPI `tmap-agents`) with a uv-managed
  Python 3.11 and runs `tmap init`, which reuses or downloads the toolchain (JDK 21, Ghidra
  11.4.3, BinExport, BinDiff 8) from pinned URLs checked by size and sha256, and registers the
  MCP server with Claude Code, Codex, Cursor, Claude Desktop or dsh. `tmap doctor` re-checks the
  setup, `tmap update` upgrades a uv-managed install, and `tmap uninstall` removes tmap's own
  files (`--purge-data` also deletes scans and the atlas after a typed confirmation).

### Known limitations

- Reachability is graded one function at a time. It is not a taint-propagation engine and never
  claims a path is unreachable; most candidates read UNKNOWN on that layer.
- Path and file sinks are detected and ranked, but their controllability comes from a text-level
  reading of the pseudocode, and is marked as such.
- The disassembly listing is only present for firmware scanned by this version; an older scan
  answers `available: false` until it is rescanned.
- Supported platforms are Linux x86_64 (including WSL2) and macOS on Apple Silicon. macOS on
  Intel runs the same toolchain but has not been acceptance-tested; Linux arm64 and native
  Windows are not supported.
- Licensed under the Apache License 2.0.
