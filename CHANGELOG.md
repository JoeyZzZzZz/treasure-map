# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - Unreleased

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
