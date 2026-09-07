# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **A run that never finished is no longer reported as a fast re-hunt.** `tmap runs` and
  `tmap rescan` sorted every out-of-date run into "needs re-extraction" or "needs re-hunt", and a
  run that stopped mid-scan — or that has no lineage row at all, a pre-existing scan this tmap
  never recorded — landed in the second one: "fast: stored facts are re-graded, the decompiler does
  not run". That is a promise about how long the fix takes, and it was wrong in the expensive
  direction. Those runs have an incomplete analysis.db or none, so bringing one forward is a whole
  scan with the decompiler in it. The reader was told seconds and got Ghidra.
  A third tier, `needs a full re-scan`, now holds them, ordered first because it is the most work.
  Its cost line says the time is not measured and assumes the slow case: analyze is per-binary and
  idempotent, so a run that stopped after every binary was already extracted can come back
  quickly — but a run that stopped is not known to be that one, and quoting the faster figure
  would be a promise about work nobody has looked at.
  ★ The check runs FIRST, ahead of the extraction and unknown-commit comparisons. A run that never
  finished has nothing to compare, and on an install that records no commit — an editable
  checkout, where this is most often read — the unknown-commit branch matches every run there is;
  behind it the new tier would be empty exactly where it is needed.
  ★ `--json` carries the new axis. A tier missing there reports `staleness: null`, which a script
  reads as "confirmed current" — the one thing these runs are not.
  ★ The closing line of `tmap runs` counts the new tier when deciding whether `tmap rescan` can
  refresh what was listed. Without that it said "rescan refreshes them" about runs with no
  firmware root at all.


- **Every binary now reaches the shape scan and the wrapper propagation.** The recall pass skipped
  whole binaries before looking at any of their code: anything the `components` table listed,
  anything whose name matched a 22-entry list of generic project names, and anything called `lib*`.
  A perfect command-injection shape inside one of those produced nothing at all, and the only trace
  was a counter on the `tmap scan` summary — nothing in the MCP surface, and no way for a reader of
  the result to tell "looked and found nothing" from "never looked".
  It was also a weaker test than it looked. The `components` table has no writer, so in practice
  the exclusion was the name heuristic alone: it cannot tell a vendor's own shared library from
  libc, and `lib*` matched every shared object in the firmware, custom ones included. Which project
  a binary came from is a label for the read side to weigh against everything else known about a
  candidate — `origin`, which recognises third-party code at function-symbol granularity, is
  untouched and still carried on every instance. It is not grounds for the recall pass to never
  look.
  `oss.py` is deleted. `custom_functions` is renamed `functions_with_callees`, and a new
  `callee_parse_failed` counts functions whose stored callee list would not parse — previously
  dropped silently, now reported as the data gap it is. The two partition what the scan admitted
  (`functions_with_callees + callee_parse_failed == functions_scanned`), checked on every scan and
  re-derived from a real database by a new Gate D, so "was this looked at" is answerable from the
  numbers rather than from the code.
  ★ Expect materially more candidates, and a `pattern_breadth` upper bound that loosens with them —
  the recurrence ledgers now count instances from widely-shipped stock binaries until origin is
  component-confirmed. That caveat is stated where the counts are read.
  ★ Two wrapper-propagation tests that pinned per-binary isolation had been passing vacuously:
  their fixtures used a binary named `libb`, which the heuristic short-circuited before the
  isolation they were testing was ever exercised. They now test it.

### Changed

- **`tmap runs`' human listing drops the provenance columns.** The build hash, the hunt stamp and
  the row count are what a machine compares; they are in `--json`, and on six lines they crowded
  out the list they were annotating. A person reading a list of runs is answering a different
  question — what is here, and is it current — so each line is now the run, its status, its scan
  date and its counts, in aligned columns. The reason a tier is out of date is said ONCE per tier
  rather than beside every run, in a sentence with the cost of fixing it folded in
  (`→ hunted by an older tmap; re-hunt is fast (no decompile)`); when a tier holds several reasons
  each gets its own line naming the runs it covers, so grouping never merges two situations into
  whichever sentence came first. A reason the mapping does not recognise passes through verbatim.
  ★ The one-run banner at the top of a candidate view KEEPS the build hash. It exists so a stale
  scan cannot be read in silence and it has no `--json` to fall back on — the listing dropped
  provenance because the listing has somewhere else to put it; there, there is nowhere else.
  ★ The closing line names the limit when there is one: if any listed run's firmware root is gone,
  it says so and points at `tmap fact --analysis-db` for those, rather than sending the reader at
  a command that fails on a subset without saying which.
  Unchanged: the tier classification, `tmap rescan`'s output, and `--json`.

### Fixed

- **A binary is identified by its row, not by its name.** One firmware ships the same
  `libstdc++.so.6` under two roots — different content, different function tables, different data.
  Every read that selected a binary by short name and took the first row back was answering about
  whichever one the database returned: silently, and not necessarily the same one for two queries
  over the same firmware. Selector resolution now lives in one module, accepts a sha256 (an
  ≥8-hex prefix works), a full path or a short name, and answers a name that several binaries share
  with `reason: "ambiguous"` and every candidate's `binary_path` + `sha256` — a fact about the
  firmware, returned in a form the caller can act on, never a pick. A CI gate keeps the by-name
  lookup from reappearing elsewhere.
  Concretely fixed by this: `get_callees`' `resolved_in_binary` claimed a call stayed inside the
  file when the callee only existed in the namesake (the function set was pooled by name); the
  reverse-caller pass de-duplicated on the name, so every same-named caller after the first
  vanished and a caller set came back short; a version diff resolved the same selector eight times
  and could get a different row each time, with the ambiguity surfacing much later as "this
  .BinDiff does not correspond to the two runs' binaries" or as an assertion that disappears under
  `-O`; `load_baseline` merged every namesake's functions into one presence domain, which — where
  their addresses overlap — was wrong about the entries it did contain, not merely short; and a
  full diff's "did this binary change" compared one arbitrary sha per side.
  ★ Every anchor now carries `binary_path` beside the short name, so a result says which file it
  came from. When `func` resolves, ITS binary is used and `binary` does not re-select — a function
  that identified itself is not dragged back into an ambiguity.
  ★ `tmap diff` refuses a shared short name with the candidates listed, and records that refusal
  as that binary's blind spot (`ambiguous_binary_selector`) — a distinct reason, because it is
  fixed by naming a path or a sha, not by retrying. A full diff reports such names as
  `ambiguous` alongside changed/unchanged rather than comparing them; the three partition the
  names present in both runs.

- **A library dependency whose soname names two binaries no longer picks one.** The soname index
  assigned per name (last row won) and its version-stripped fallbacks kept the first, so a
  `DT_NEEDED` edge pointed at whichever file the scan happened to reach — a confident edge to an
  arbitrary target, indistinguishable in the table from a correct one. Such an edge is now not
  written, and is recorded in `xref_unresolved_sonames` with every candidate and which name form
  matched; `get_imports_exports` surfaces it as `dt_needed_unresolved`, and the `list_candidates`
  red-line block carries the count. Same shape as the folded-xref ledger: not written, never
  silently dropped.
  ★ Stated cost: the edges this removes were probably right (their callers sit where the obvious
  candidate lives). Probably is not a proof — the candidates are handed over instead of assumed,
  and reading one costs a step that guessing did not.

- **Per-binary rows record which file they are about.** `exec_edge`, `string_keyed_edge`,
  `detector_scan_status`, `nvram_key_flow`, `nvram_defaults` and `diff_meta` scoped a row to a
  binary by short name, so a per-binary filter on that name matched every file answering to it.
  Each now stores the path beside the name (nullable; a pre-existing row keeps working and says
  so). The string-key reachability lead is scoped by path when the row has one, and every returned
  edge reports which basis it matched on rather than presenting the two as equivalent.
  `exec_edge.target_binary` now holds the resolved PATH; when the launched name belongs to several
  binaries the target is left unset and the resolution says `ambiguous_direct` /
  `ambiguous_symlink_target` — the name resolved, the file did not, and such an edge grants no
  entry site.

- **A scan proven to be out of date is now refused on every tool, including the candidate map.**
  The refusal lived on one code path — the one the fact tools route through — so it was reachable
  from `get_pseudocode` and not from `list_candidates` or `explain_candidate`, which read the atlas
  directly. A run demonstrably graded by code that no longer exists therefore handed back
  candidates with no marking at all, through the entry the tool instructions name first. The gate
  is now a single function called from every entry: the run-scoped readers refuse with
  `stale_scan` + `remedy`, a diff refuses when either side is stale and says which side, and the
  cross-run readers — which serve many firmware at once and so cannot refuse — drop those runs'
  rows and name them under `stale_runs_refused`.
  The bar for refusing is unchanged and deliberately narrow: only a PROVEN mismatch. A run whose
  extraction hash or commit cannot be compared is still served, with its reason stated — widening
  the coverage without widening the bar is the whole point, since a gate that fired on "cannot
  tell" would make an existing atlas unreadable the day it landed.
  ★ `list_candidates` without a `run_id` reports `candidates_excluded` per refused run and a
  `corpus_note`, both counted under the same filters as `corpus`, so the arithmetic holds. Two
  aggregations (`pattern_twins`, `cross_firmware_patterns`) count ACROSS runs and carry no run
  column: their refused runs are named with a null count and a note saying the numbers still
  include them, rather than a zero that would claim the run contributed nothing.

- **A skipped re-hunt no longer trusts a stamp whose rows are gone.** The commit stamp said which
  code produced a run's candidates; nothing checked that those candidates were still in the table.
  Remove them by any route that is not the hunt itself — a manual DELETE, a partially restored
  atlas copy, another caller of the delete helper — and the next scan read the stamp, skipped, and
  reported "already hunted by this tmap" over an empty result. The run row now also records HOW
  MANY rows the hunt committed (`hunt_instances`), and the skip requires that count to equal what
  the table holds now.
  The check compares counts, never existence: a run whose analysis.db legitimately yields no
  candidates writes zero rows, and an "does it have any rows" probe would re-hunt it forever.
  Zero is a real result, and storing it makes zero comparable.
  ★ Consequence, stated so it is not misread as a bug: every run scanned before this lands has no
  recorded count, which cannot be confirmed and therefore re-hunts once. After that first pass the
  count is stored and the skip resumes. Same shape as the commit stamp's own first landing.

- **A skipped hunt now records where the firmware and the analysis.db moved to.** The skip returns
  before the run row is rewritten, so the recorded locations stayed at whatever they were when the
  hunt last actually ran. Move the firmware, re-scan, and the run kept pointing at a directory that
  is no longer there — which then broke the rescan classification and the remedy lines that read
  it. The relocation is written and nothing else: the stamp, the status, the counts and the
  extraction hash describe the hunt that ran, which a skip did not.

- **A completeness check that could not run no longer looks like a clean scan.**
  `incomplete_binaries` / `partially_incomplete_binaries` / `folded_xref_symbols` exist so an
  absent candidate is not read as a clean binary. When the run had no recorded analysis.db, or the
  file was gone, the answer was the same three empty lists — the strongest possible statement of
  cleanliness, produced by not looking. `list_candidates` now carries an `analysis_completeness`
  block whose `unavailable` says why the check did not run, and whose note says in words that the
  empty lists above are unavailable, not clean.

- **`tmap fact` now says so when the analysis.db records no extraction pipeline at all.** The
  staleness note filtered unversioned rows out of its own query, so a database predating the
  versioning produced exactly the same silence as one that matched the installed pipeline. The
  fact is still printed — this path annotates, it does not refuse — but unknown is now stated
  instead of read as "same".

- **A run with no firmware root is told what it can still do.** Its remedy said only "re-scan once
  you have the firmware". What that run already extracted is on disk and readable directly, so the
  remedy now names `tmap fact --analysis-db <path>` alongside the re-scan — offered only when
  there is a recorded path to name, since the command needs an argument.

### Changed

- **`tmap runs` and `tmap rescan` now group runs by WHICH input moved, and say what each costs.**
  Both commands answered "out of date" without saying whether that meant a full re-decompile or a
  seconds-long re-grade — a difference of orders of magnitude that the reader could previously
  discover only by starting the work. Runs are now split into `needs re-extraction` (the
  decompiler runs over every binary again; the binary count is shown) and `needs re-hunt` (stored
  facts are re-graded, no decompiler), with the up-to-date ones listed separately. One classifier
  answers both commands, so what `tmap runs` calls out of date and what `tmap rescan` offers to
  redo cannot drift apart. Runs whose firmware root is missing are still reported by name, in
  their own section, exactly as before.
  `tmap runs` also shows the hunt stamp and the row count on the human line (`hunt <commit>` /
  `hunt none`, `rows N` / `rows ?`), and `--json` gains `hunt_commit`, `hunt_instances` and the
  `staleness` classification. Without them, a run offered for refresh was unexplained: the build
  hash matched and nothing else was visible.

- **The pass fingerprint now covers the whole per-binary extraction pipeline, not just the Java.**
  `pass_version` is the cache key that decides whether a same-content binary is re-extracted; it
  hashed only the `.java` scripts. When a Python relabel step (the stub resolver) started rewriting
  the stored callees, the fingerprint did not move, so a re-scan skipped every binary and the
  recovered sink was never stored — a false-negative fix that shipped as a false negative. The
  fingerprint now spans the declared Python pipeline (`ghidra_ingest` + `stub_resolve`) alongside
  the `.java`.
  The set is declared explicitly and locked by a mechanical gate, not a transitive import closure:
  `ghidra_ingest` imports `elf_inventory` for a TYPE and reaches `symlinks` two hops on, and those
  run on every scan (wipe-and-rebuild), so an import-based rule would make an unrelated edit trigger
  a full, hours-long re-extraction. The gate parses the ingest write-path and requires every
  analyze module it CALLS into the functions cache to be declared — a type-only import does not
  qualify, and a future extraction step added and left undeclared fails the gate rather than
  shipping blind. The hash is deterministic (sorted files, no `sys.modules`).
  ★ Consequence, stated so it is not misread as a bug: this changes `build_hash` too (it is the
  `pass_version`), so after this lands every already-scanned firmware shows a stale-scan signal
  until it is re-scanned once — which is correct, because those scans never ran the relabel and
  genuinely need re-extracting; the signal converges to the new value afterward.
  ★ Boundary, named because it is the same shape of blind spot one level out: the hash covers the
  extraction CODE, not the versions of the libraries it calls. A `pyelftools` or Ghidra upgrade can
  change the extracted result while the fingerprint stays put, so a library/tool upgrade still needs
  a manual `--reanalyze`; folding tool versions into the dirty check is a larger, separate decision.

- **A large `list_candidates` response no longer overflows the transport.** A wide-row page at a
  large limit — path_sink rows run ~440 bytes each — serialized to ~95KB and spilled to a file.
  The candidate array is now trimmed to a response byte budget: byte-aware, because row width
  varies by sink class and path length so a fixed row count cannot bound the response. The trim is
  a visible decision, not a silent drop — `candidates_truncated` says the page was cut, `total` and
  `corpus` stay exact, and `next_offset` resumes at the first row the byte trim could not carry, so
  every candidate is reachable by paging on. A single row larger than the whole budget is
  trimmed-to-one and flagged, never turned into an empty page. On a real firmware a path_sink query
  at limit 200 drops from ~102KB to ~48KB.
- **The folded-xref red-line is serialized once, not twice.** The full list of high-fan-out symbols
  whose constrained edges were suppressed appeared in full at the top level AND inside the coverage
  block. The authoritative copy stays at the top level — the per-scan red-line present on every
  response — and the coverage site now carries a count and a pointer to it, not a second copy. The
  authority deliberately lives in the container that cannot be absent: deduping into a block some
  response shapes may not produce would be a new silent drop. Every folded symbol and its
  suppressed-edge counts stay readable once.

### Added

- **A command-execution sink the decompiler dropped is recovered from the ELF.** When a program
  calls `system`, the compiler routes it through a lazy-binding stub; if the decompiler does not
  stitch that stub back to the import — which it routinely does not, depending on how it was
  configured and how the binary was linked — the caller is left calling `FUN_004125b0`, and a real
  sink drops out of every downstream reading. That is a false negative on a sink that objectively
  exists. A pure-ELF pass now resolves each stub to its import name from the relocations and GOT
  the binary already carries, INDEPENDENT of the decompiler, and rewrites the callee at ingest —
  so the rest of the pipeline sees `system` and the caller becomes a candidate, with no downstream
  change. On one real firmware this returns 75 caller functions to the candidate set, across its
  web-facing cgi binaries, including the case this started from.
  Two paths, both deterministic: the PLT's `JUMP_SLOT` relocations, and the classic global-GOT
  position formula. The formula's domain guards are load-bearing, not defensive: on a new-ABI
  binary it produces a negative symbol index for a `.got.plt` slot, and reading that out would
  write a WRONG name — a fabricated `system` is worse than an unresolved one, so an out-of-boundary
  slot yields nothing. When the two paths disagree on a slot (a corrupt or adversarial binary),
  the slot is dropped, not guessed: recovering a false negative must never manufacture a false
  positive.
  ★ Scope: this recovers the stub-mediated call — a direct call to a stub, which the decompiler
  names after the stub's address so the address is recoverable. It does not recover an inline
  `%call16` GOT call written straight into the caller, which the decompiler renders as a nameless
  indirect call carrying no address to work back from; finding those needs a disassembler this
  layer deliberately does not depend on. Such a call, left unresolved, is surfaced instead —
  `get_pseudocode` reports a function's unclassified external calls as a completeness lead, so a
  possible unrecognized sink stays visible rather than being read as an ordinary internal call.

### Fixed

- **A diff now says whether the builds it describes still exist.** A diff is a statement about two
  specific binaries; re-scan one with different content and the alignment underneath still reads as
  current, while the addresses it matched belong to a file that is gone. `list_diffs` and
  `get_diff_deltas` now carry `source_stale`, checked where the result is consumed — the one point
  every reader passes through.
  The test is the CONTENT, never the clock. Re-scanning identical sources is the ordinary case and
  leaves every diff valid; judging by which happened later would brand a whole table stale on any
  re-scan, which is the same failure — old data read as current — pointed the other way.
  Two details it would be easy to get wrong, and both are load-bearing. The current hashes come
  from the run's own analysis database, resolved through the path the run row records: the atlas's
  per-candidate hash exists only for binaries that produced a candidate, so on a real firmware it
  covers about a third of what was diffed, and reading "no hash" as "changed" would brand most of
  an unchanged table. And a stored hash is compared for MEMBERSHIP among the hashes under that
  name, because one short name really can cover several files in a scan — a measured run has four
  such names, one of them a binary that was itself diffed — so reading "the" hash for a name would
  be a coin flip that calls unchanged diffs stale half the time.
  Three answers, not two: stale, not stale, and could-not-check (the source database is
  unreachable, or the diff predates the content stamp). The third is reported as itself rather than
  rounded — a real atlas holds one such row. Staleness is also kept apart from `diff_status`: a
  diff can have computed perfectly and still be about a file that has since been replaced.

- **An integrity gate for candidates whose run was never registered.** An instance naming a
  `source_run_id` with no row in `run` is a scan that left its results behind without its lineage —
  no build hash, no scan status, no path back to the analysis it came from — yet it still counts
  toward device spread and still lists as a candidate. The `run` table is the single authority on
  which runs exist. The gate is read-only and does not clean anything: re-hunting a run under its
  own name does that in one pass. It exists for the two ways the problem returns afterwards — a
  re-hunt under a DIFFERENT name, leaving the old label's rows with nothing to remove them, and a
  future "delete this run" that forgets its instances.

### Fixed

- **A leftover run-pair row is no longer listed as a binary's diff.** A diff aligns one binary and
  its id names it as a third segment; a row whose id is just the two run ids predates that and
  describes nothing a reader can act on. It is identified by the SHAPE OF ITS ID, never by
  `diff_ok` — a failed per-binary diff carries that same flag and is a blind spot a reader must
  keep seeing, so filtering on it would hide a binary that could not be diffed behind the same
  silence.

### Changed

- **Every candidate now says whether anyone has been through it.** The annotation layer recorded
  conclusions but could only be read by asking for it, so the question a reader most needs
  answered — which of these have I already done? — had no answer on the map. Each row carries a
  `coverage` state, present whether or not the annotation view is on, because whether a candidate
  has been looked at is a fact about the world rather than a view to opt into. What stays behind
  the view switch is the annotation's CONTENT. It is derived from what was already stored: no new
  column, no new verdict, and in particular no "working on it" state — the overlay records
  conclusions, and progress is answered by presence instead.
  Four states beyond "nobody has looked": a conclusion was reached; `inconclusive`, which is a real
  conclusion (looked, could not settle) and deliberately NOT counted as settled; a verdict written
  in a word that has since been retired, which cannot be read as either; and a conclusion whose
  facts have moved since. A conclusion whose candidate has disappeared entirely is reported
  separately — judged by re-deriving the anchor now, not by the snapshot taken when it was
  written, which by definition said the anchor was fine.

- **Progress is reported in pages, with the remainder stated every time.** A class on a large
  firmware runs to thousands of candidates; "N of N" is unreachable and, worse, rewards clearing
  the board. A listing now carries how many candidates it holds, how many are unread, how many
  pages that is, and — named individually, not as a page number — the ones to work through next.
  The paging order is pinned to the default impact table and ignores filters and lens choices: an
  `--impact-order` override replaces that table, so letting it reach the paging would move
  candidates onto pages already passed, and "everything gets reached eventually" would quietly
  stop being true. Page counts are recomputed from the annotations on every read; no page number
  is stored anywhere.
  A completion signal never travels alone. It sits with the run's blind-spot ledger, since
  binaries that failed to analyse produced no candidates for anyone to read, and with the shape of
  the verdicts reached, since `safe` demands a structured evidence basis while `excluded` needs
  only a sentence — a scope cleared entirely by the second is covered only in the bookkeeping
  sense, and this is the only place that shows. Finishing one class also reports what is left
  everywhere else, so it is not read as finishing the firmware.
  `explain_candidate` says where to record a conclusion when none exists, argued from the reader's
  own interest: a conclusion kept anywhere else goes stale silently when the code moves, while one
  recorded here is flagged for another look.
  ★ What this cannot do: it cannot make anyone read carefully. It can make shallow work land as an
  open state rather than a clean-looking dismissal, and make a batch of cheap dismissals visible.
  And it is exhaustive over the CANDIDATE SET, not the firmware — a sink that never became a
  candidate is not in the set being paged through, which is a recall question and not this one.

### Changed

- **The project is licensed under Apache-2.0.** `LICENSE` is the authoritative Apache text, a
  `NOTICE` file carries the attribution Apache asks for, every per-file SPDX header states
  `Apache-2.0`, and the package classifier agrees. The per-file headers stay: Apache does not
  require them, but they are what a licence scanner reads. Both READMEs drop the offer of separate
  commercial terms, which Apache leaves nothing to offer. A test holds this as an invariant rather
  than a one-off sweep: a second licence marker anywhere in the tree fails it, since that is the
  state leaving a reader unable to tell which terms apply. Copyright is the project's single year,
  2026. Nothing was ever released under other terms, so there is no migration for anyone to make.
  The runtime legal notice is unchanged in substance: it states how the tool may be used, which is
  a different thing from the licence.

- **The diff fixture no longer comes from real firmware.** The layer-0 parse was verified against a
  BinDiff of a firmware library. It is replaced by real BinDiff output over a synthetic subject:
  two variants of a C file written for this repository, built stripped so the tool meets the same
  nameless, repetitive code it meets in production — including several byte-identical functions it
  pairs at similarity 1.0 while reporting low confidence, which is the case proving alignment must
  follow confidence and not similarity. The fixture is regenerable from committed sources
  (`tests/fixtures/layer0/make_fixture.sh`) and its provenance is written down beside it.
  One thing is lost with the old fixture and worth stating: it was production-scale, ~1800 matched
  pairs against 48 here, so these tests no longer evidence anything about scale.

- **The example config stops advertising what does not exist.** Its Ghidra path example named a
  version the README does not pin, and it offered `docker` and `remote` modes for which there is no
  image and no service. The version now matches the pinned toolchain, and the two unbuilt modes are
  commented out and labelled, so neither reads as a working option.

- **Removed `.env.example`.** It asked for LLM API keys that nothing in the tool reads — analysis is
  hermetic and `tmap init` provisions no keys — so its only effect was telling a first-time user to
  go and find credentials they do not need.

- **One version string.** `pyproject` said 0.1.0 while `version.py` said 0.0.1; the second is
  stamped onto every run this tool records. Both now read 0.1.0.

- **`CONTRIBUTING` said end users install with pipx**, while the README uses `uv tool`. It now
  matches the README.

- **The package description no longer casts tmap as the one judging** — and the check that pins
  the rest of the public wording now covers it. `exploit-path discovery` survived the sweep that
  fixed the CLI, in the one line an index and an installer put in front of everyone who never opens
  the README. The scanned surface now includes the description and the keywords: free text we
  choose, the most widely read of it, and the easiest to forget. Classifiers stay out — that
  vocabulary is PyPI's, not ours.

- **The public-facing wording no longer casts tmap as the one judging.** `tmap --help` opened with
  "IoT firmware exploit-path discovery", and two commands summarised themselves as matching
  "suspicious" call-chains and sinks. tmap supplies facts a model cannot generate for itself; the
  model and the person do the reasoning, and a word that quietly promotes the tool from witness to
  judge invites a reader to stop verifying. The front door now describes what the tool is, and the
  two summaries describe what they mechanically do — match call-chains against known sink patterns,
  and record sink call-sites. A check pins this: the `help` text under `cli/` and the legal notice
  are scanned against a hand-written list of judgement words, with negated disclaimers ("NOT a
  verdict") exempt, because punishing those would push the text toward saying less about its own
  limits. Its scope is written into it — notably why the overlay verdict vocabulary an annotator
  writes (`suspicious`, `exploitable`) is a different thing and out of scope.

### Fixed

- **`launched_by` explains the one remaining lookup that answers zero.** A launched script is
  stored under the path the extraction produced, whose first segment can differ from the runtime
  path the code names — an overlay physical path against a logical-path token. No spelling of one
  is the other, so pasting the token in returns nothing. The prefix is not stripped automatically:
  it differs per firmware and per extraction, so there is nothing exact to strip, and a pattern
  loose enough to cover them all would be guessing. The docstring names the way out instead — ask
  for the short name — so the zero is explained rather than silent.

- **Looking an edge up by the token it shows you now works.** `launched_by` matched a target the
  way the inventory stores it — a script by its root-relative path, a binary by its short name —
  but the spelling a reader has in hand is the edge's own `target_token`, which is the code's text
  and so carries a leading slash. Copying it straight back in returned zero, which reads as
  "nothing launches this": the misreading this whole surface exists to prevent. A leading-slash
  query is now also compared against the stored value with the slash removed, and against its
  basename. Every comparison stays exact equality — never a prefix or suffix match — and a query
  with no slash in it collapses to the same string three times, so short-name lookups are
  unchanged. One case still answers zero on purpose: a token a SYMLINK renamed (`/bin/sh` resolves
  to `busybox`, and no spelling of `sh` is `busybox`); the docstring now points at `target_binary`,
  which the edge already carries, instead of leaving an unexplained empty.
- **`launched_by` carries its per-binary status where it is actually read.** The rows were attached
  to every answer — across several firmware, around two thousand of them — burying the answer they
  annotate. They ride now only when the result came back EMPTY, which is the one moment a reader
  goes looking for whether the launcher they suspect was scanned at all. Two totals ride along
  always, so "did this pass cover anything" stays answerable without the list. The rows are
  withheld when unread, never summarised away: an empty answer still returns every one of them,
  including the scanned-but-found-nothing binaries that are precisely the evidence an empty answer
  is trustworthy.
- **An atlas built before `resolved_via` was removed now sheds the column on open.** Dropping it
  from the schema stopped new writes, but `CREATE TABLE IF NOT EXISTS` cannot alter a table that
  already exists, so an older atlas kept it — holding values written under the old meaning for as
  long as its runs went un-hunted. The migration that removes it has to run on the ATLAS
  connection, since that is where the table is created; hanging it on the analysis database would
  find no such table and skip in silence.

- **A launched script is recognised by being a script, not by its name ending in `.sh`.** The
  resolver demanded both inventory membership AND the suffix, which reads backwards on a real
  rootfs: a script invoked as a program is typically the one WITHOUT a suffix (an `init.d` entry,
  an `sbin` helper), while `.sh` tends to mark the library scripts other scripts source. Known
  scripts were therefore reported `unmatched` — "I do not recognise this" about a file the
  inventory holds by name. Membership is now the whole test; the query behind the inventory selects
  shell scripts only, so nothing else can arrive there, and no second-guessing heuristic is layered
  on the file classification.
- **A launched script can now be looked up.** Script edges recorded no target at all, so the read
  tool — which looks up by that column — could never answer for one. A resolved script now records
  its PATH (not the token: a third of these tokens are bare, and storing whichever spelling the
  callsite used would fill one column with two kinds of key). Because that makes the lookup key
  heterogeneous — binaries by short name, scripts by path — a short name is now also matched
  against the stored path's basename, so asking for `getmac` finds the script edge instead of
  returning a silent zero that reads as "nothing launches it". The comparison is on the exact
  basename, never a suffix match. When several scripts share a basename the edge still says a
  script resolved but names none of them: picking one would be a guess, and the candidates stay
  recoverable from the inventory.
- **A command built as `"%s ..."` no longer hides the program it runs.** Commands are routinely
  assembled as `snprintf(buf, "%s '%s'", "/usr/sbin/tool -j", user)`. Only the template was read,
  so the first word was a conversion, the program name — sitting right there as a constant argument
  — was invisible, and the edge resolved to nothing. Constant arguments are now substituted back
  into the template. Runtime arguments are NOT: their conversion stays, the visibility still
  reports a placeholder, and no target is claimed for a value nobody has seen. Neither is a
  constant whose text the extractor could not read, which would paste in an address as if it were
  a name. The conversion-to-argument mapping comes from the format scanner the read layer already
  uses — now shared rather than written a second time, because an off-by-one there does not fail
  loudly, it silently attributes the wrong argument to a conversion.
- **`launched_by` no longer buries its answer under a repeated disclaimer.** The pass's scope note
  describes the PASS, not the binary, but a copy rode on every per-binary status row — on a real
  atlas around 1500 identical copies, several times the size of the answer they annotated, enough
  to push even a zero-result response over the size limit. It is carried once at the top now; the
  per-binary rows keep only what varies. `cap_hit` stays even though no scan has ever set it: an
  honest-degrade channel that has not fired is not a channel to delete.
- **Dropped `resolved_via`, which restated `target_binary`.** The two were filled from the same
  value and were equal on every row. Where a symlink resolved the target, the link's own name is
  the basename of the token — derivable, and the honest note now says so instead of storing it a
  second time.

- **A sink that left no trace of itself can no longer be called constant.** `constant` is the only
  "safe" reading the map asserts, and the only one that sinks a candidate out of the first screen —
  so a wrong one is the single worst error available: nobody looks again. Two exits reached it, and
  both trusted evidence that had never seen the sink being judged. The value origin is recorded per
  function and per direct call, so when the real sink sits behind a thin forwarding wrapper the
  caller's records describe the caller's OTHER sinks. "Every record is a constant" then came out
  true for a sink not among them; and the `const_sink_arg` marker, computed from the same caller
  body, found the constant shell around the conversion an attacker fills and read it as a constant
  command. Both exits now require at least one record for the sink actually being judged, and fall
  back to the ordinary source reading without it.
  The rule that this enforces was written in a docstring the whole time and never in code — which
  is why the guard ships with the mutation that breaks it. The two controllable readings are
  deliberately NOT gated: promoting on partial evidence costs a review, demoting on it hides a real
  lead. Nor is it a claim of completeness — it establishes that the sink was seen at all, not that
  its record is whole. Candidates whose sink IS in their records are entirely unaffected: on a real
  atlas, exactly the escaped ones move and every other reading is unchanged.

- **A filter naming a dimension that does not exist is now refused instead of matching everything.**
  An unrecognised name fell through to a catch-all that returns true, so every candidate landed in
  the matched band and the count came back equal to the whole corpus — reading as "they all matched"
  rather than "there is no such dimension", the worst of the three possible answers. Both
  `--filter` and `--only` now refuse an unknown name and list the real ones, on the MCP tool and the
  CLI alike. The valid set is anchored on what the matcher actually honours, including the two sink
  spellings, so live filters like `sink_class=` are not broken by the check. This catches a bad NAME
  only; a real dimension given a value it has no rule for still matches everything.
- **`list_diff_blindspots` no longer reports a run-pair row as a per-binary blind spot.** A blind
  spot means one binary was not diffed, and its row id reads `run_a::run_b::binary`. A row whose id
  is just `run_a::run_b` describes the pair itself; listing it invented a gap on a binary that had
  in fact diffed cleanly under its own row. Excluded by comparing against the id rebuilt from the
  row's own run columns rather than by counting separators, since a binary name may contain them.

### Added

- **`launched_by` — which binaries' code launches a given binary.** The call graph inside one
  binary was covered; the edge between two was not, so a daemon nothing in the rootfs mentions read
  as a plain coverage gap even when another binary starts it on every boot. The hunt now reads the
  command and exec callsites out of the sink argument provenance it already stores, resolves the
  named program against a new inventory of the rootfs symlinks, and records one `A launches B`
  edge per callsite. `/bin/sh -> busybox` therefore lands as a real edge instead of a dead token.
  Each edge names the launcher (binary, function, address), the API, whether a shell wraps it, and
  the command template when one is visible.
  These are ENUMERATED FACTS, never a reachability verdict: an edge does not say the callsite runs
  or that input reaches it. A token that resolved to nothing is still on the table, carrying why —
  the shape it was written in, and separately whether a symlink was ambiguous, damaged by the
  extraction tool, or pointing at something that never became a binary. An empty answer ships with
  the pass's own scan status naming what it cannot see; most sharply, a caller whose command sink
  sits behind a thin forwarding wrapper is INVISIBLE to this pass, because the caller's provenance
  does not contain the wrapped sink. Reading empty as "nothing launches this" would be wrong there.
- **Reachability can now read `entry:exec`.** A resolved launch edge counts as an entry reference
  alongside the rootfs script and web-asset ones, and combines with them (`entry:web+script+exec`)
  in a fixed order that leaves the existing spellings untouched. Only an edge whose target resolved
  to a real binary qualifies; a script target and every unresolved state do not. As before, an
  entry reading is a MECHANISTIC label and never a verdict — and this path can only ever report
  found or unknown, never "blocked".
- **`tmap analyze` records the firmware's symbolic links** and reports the count. The walk already
  tested each entry for being a link on its way to skipping it; that test now runs BEFORE the
  is-a-regular-file test, because following a link answers False for exactly the two damaged
  classes that matter — a dangling link and one an extraction tool flattened onto `/dev/null`. Each
  link records its final target and, when it has none, which kind of damage: placeholder, dangling,
  escaping the firmware root, or a chain too long to follow. tmap does not repair a damaged link
  and does not guess which applet a flattened one meant; it records the damage and leaves the call
  to the reader.

- **`get_nvram_key_flow` takes an optional `run_id`.** The graph still spans every scanned firmware
  by default — often the point, and each row already names its run — but auditing one image no
  longer means reading another device's rows out of the answer. The scope applies to all three
  reads behind the result (exact hits, template matches, unresolved count); narrowing only some
  would return an answer that looks scoped and is not. Note it also scopes the completeness caveat,
  which then means "may be incomplete within THIS run".
- **A static check pins that overlay writes live in one place.** Dropping the database's verdict
  CHECK rested on every write going through one validating function — true, but asserted only in a
  comment. Now checked: a coarse token plus an explicit per-file budget, copying the wipe guard
  rather than a narrow pattern, since a precise pattern is easy to slip past by accident (a
  different column order, `INSERT OR REPLACE`, a schema-qualified name) and then silently permits
  what it was written to forbid. Its limits are documented where it lives: it cannot see a
  statement split across string literals, a quoted identifier, or a write added inside the write
  path's own module.

### Removed

- **`get_components_cves` is gone from the MCP surface.** The tables it read have never had a
  writer, so it always returned empty — an honest answer, but a permanent one, and it cost a slot
  in every agent's tool list. Component identification and CVE matching are deliberately not built;
  the tool is withdrawn rather than left returning nothing. The tables stay: the scanner reads
  `components` to help exclude third-party code, and degrades cleanly while it is empty. The
  separate CVE-form reference tables and their tools are untouched.

- **A candidate a person already confirmed now says so on its row.** `list_candidates` marks any
  candidate whose reference appears in the exploit ledger with `in_exploit_ledger: true` — the
  highest-trust marker on a row, and usually a reason not to spend effort re-analysing it. It is a
  read-only derivation from data that already existed, matched on the exact reference (no fuzzy or
  cross-firmware matching), and it shows whether or not the opt-in overlay view is on, because
  whether a person recorded something is a fact rather than a view preference. It sits in its own
  top-level key, keeping three provenance layers separate on one row: what the tool established,
  what the agent decided, and what a person confirmed. What it does NOT claim is stated with it:
  the logic was proven and recorded, not reproduced on hardware.
- **The annotation layer is now discoverable.** It had existed for several rounds while the
  server's own instructions never mentioned it, so almost nothing was ever annotated and the
  vocabulary, gates and ordering built on top of it went unused. The agent loop is now
  RECALL → FETCH FACTS → JUDGE → **RECORD**, named in the header as well as the body so a client
  that truncates still shows it, with a phase that says what `annotate` is for and how
  `list_candidates(overlay=true)` and `list_overlays` build on it. `annotate` itself now says WHEN
  to call it — on reaching a conclusion worth keeping past the session, not on every read. The
  ledger marker is explained in the row legend, which rides on every listing. Nothing is pushed
  from a fact tool's results; each tool describes itself.

### Removed

- **`mark_exploited` is gone from the MCP surface — the exploit ledger is now written by people
  only.** An entry in that ledger says someone proved a hole on a real device. An assistant cannot
  reach a device, so it cannot testify to that, and a claim relayed through one is still a claim
  nobody verified. Rather than gate the tool, the write path is removed: there is no agent-facing
  way to add to the ledger at all. Reading is untouched — `list_verified_exploits` behaves exactly
  as before, including withholding the proof text unless explicitly revealed.

### Added

- **`tmap exploit add` / `tmap exploit rm` — the ledger's human write path.** `add` takes the
  candidate, the shape, the proof, and `--operator`: a named person, required, recorded with the
  entry (in the existing attribution column — no schema change). The admission bar is unchanged;
  nothing here checks the proof is real, and it says so. A reference matching no candidate is
  still written, with a warning naming both possibilities (a scan that does not exist yet, or a
  typo) rather than deciding which. `rm` retracts ONE entry by id — the ledger is append-only
  because corroboration accumulates, and this is the single sanctioned exception: scoped to one id,
  never keyed on the reference (which several rows can share), and it prints the entry before
  removing it. One consequence to know about: the finer "this run has no recorded analysis.db"
  warning the old tool produced is not reproduced on the human path.

- **A new top verdict, `exploitable`, for a candidate that is done being investigated.** Where
  `suspicious` means "worth digging into", `exploitable` means the digging finished and only
  real-machine confirmation is left. It sorts ABOVE every suspicious candidate in the overlay-on
  view, via its own ordering band rather than a bigger display bias (nothing sorts by the bias), and
  it is never auto-demoted: if its basis later moves, that is surfaced on the row instead of sinking
  the candidate judged closest to proven. Passing `chain` (the path, citing code) and
  `verification_gaps` (two or more things still to confirm on hardware) is strongly recommended and
  validated when given, but not yet required — the shape is still being learned from real cases, and
  requiring it early would only produce filler.
- **`safe` now has to say why.** It was documented as a high bar but enforced exactly like
  `excluded`. It now requires all three of `block_source` / `block_point` / `block_why` — what input
  was traced, where it is stopped, and why that stop covers every path in and cannot be worked
  around — and the write is refused without them. This is the judgement that takes a candidate off
  the table, and a wrong one only comes back if the CODE changes, never because the judgement was
  wrong; the tool answers a successful `safe` by saying so. **Honest limit:** these are non-blank
  checks. Filler passes them. They are a speed bump and a way to leave a reviewable record — never
  evidence that the claim is true.
- Both justifications live in one new nullable `overlay.verdict_basis` column, keyed by `kind`.
  Distinct from `basis_state`, which snapshots the FACTS an annotation rested on: that one is about
  staleness, this one about reasoning, and neither is written from the other. `list_overlays`
  returns it parsed, so `list_overlays(verdict="safe")` reads as an audit of standing safe claims.

### Changed

- **The verdict vocabulary is now four words, and reading an old one never fails.** `to-review` is
  renamed **`inconclusive`**: the old name described a task still to be done, but this layer records
  what was CONCLUDED about a candidate — and "it was looked at and nothing decisive could be
  established from what this tool can see" is itself a conclusion, with the next step going in the
  rationale. `in-progress` is retired: it sat at the same neutral bias, meant the same thing in
  practice, and had no real use. Existing `to-review` rows are renamed in place on the next open
  (idempotent; no table rebuild — nothing pins the vocabulary in the database any more), and every
  other verdict is left alone. Retired words are **not** rewritten or deleted — the overlay holds
  the consumer's own annotations, and the tool does not edit them. Instead, reading tolerates them:
  a verdict this build does not recognise falls back to neutral bias and keeps the candidate's
  base-map position, rather than raising or guessing at what it meant.
- **`clear_overlay` can clear one entry or one firmware instead of everything.** It took no
  arguments and wiped the table, which made "retire this one annotation I no longer stand behind"
  impossible without starting over. It now accepts `run_id` **or** `evidence_ref` (never both — a
  combination would have to invent a meaning, and guessing wrong deletes the consumer's work); with
  no argument it still wipes everything, as before. Exposed on the MCP tool too, which echoes back
  the scope it acted on and how many rows went.

- **The verdict vocabulary is no longer pinned in the database.** `overlay.verdict` carried a
  schema-level `CHECK` listing every allowed word, so changing the vocabulary — renaming a verdict,
  retiring one, adding one — meant rebuilding the table and carrying real annotations across. That
  cost is now paid once: the CHECK is gone, and validity is enforced where the writes happen (both
  write paths reject an unknown verdict) plus a test that pins every known verdict to a band, so a
  new one cannot slip through unhandled. Existing databases are migrated in place, atomically —
  explicitly transactional and statement-by-statement, because SQLite commits a bare `CREATE`
  immediately and `executescript` commits whatever is already open, either of which would strand a
  half-built table that nothing is allowed to clean up. A crash mid-rebuild rolls back to exactly
  where it started, and the retry succeeds. Every other constraint (the anchor-kind and attribution
  CHECKs, the uniqueness rule, both NOT NULLs), every column and every row survive unchanged.
- **The atlas wipe guard now names one exemption instead of forbidding all table drops.** It still
  refuses every `DROP VIEW` / `DROP INDEX` and every `DROP TABLE` of an evidence table — those hold
  cross-run findings only a full re-scan could reproduce. `overlay` is exempt: it holds the
  consumer's own annotations, which the design has always let them clear in one call. The check
  extracts the table name rather than matching text, so a near-miss like `overlay_backup` is still
  refused.

### Added

- **Annotations now record which firmware they are about, and `list_overlays` can filter to one.**
  The atlas accumulates every scan, so a multi-firmware audit read its annotations back as one
  mixed pile — the run was in there, buried inside the `evidence_ref` string, but nothing could
  query it. `overlay` gains a `run_id` column, derived from the anchor (the segment before `#`) and
  written alongside every new annotation, plus `list_overlays(run_id=...)` — an exact equality match
  on a real column, so nothing hinges on how an anchor happens to be punctuated. Each row also
  surfaces its own `run_id`, so even an unfiltered listing stays attributable, and the two filters
  AND together. Existing annotations are backfilled in place by the atlas migration; an anchor
  carrying no run segment is left NULL rather than guessed at, and the write path applies the same
  rule so a migrated row and a fresh one agree. Purely additive: `UNIQUE(anchor_kind, anchor_ref)`
  is untouched (`run_id` is derived, adding no identity of its own), and no table is rebuilt.

- **`tmap init` can now activate shell completion for you — with your explicit yes.** Installing the
  completion script into the shell's autoload directory is often not enough for the shell to load
  it, and init's only recourse was to print the one line and leave it to you. An interactive init
  now asks (`[Y/n]`, Enter = yes) and, on a yes, APPENDS a fenced block
  (`# >>> tmap completion >>>` … `# <<< tmap completion <<<`) to `~/.zshrc` / `~/.bashrc`. It is
  append-only (never a read-modify-write of your rc), idempotent (the marker is the check, so
  re-running init leaves exactly one block), and removable (cut between the markers to be back where
  you started). A **non-interactive init never asks and never writes** — an unattended run editing a
  shell rc is the no-consent edit the rule exists to prevent, and there is nobody there to agree —
  and an unrecognised answer is treated as no. An rc that cannot be written reports the failure and
  falls back to printing the line; it never claims an edit the filesystem refused. Once the line is
  in place the preflight's `completion` check reports ✅ instead of a stale ❌ (bash gained the same
  rc-reading activation check zsh already had, so sourcing the script directly counts as active).
  This deliberately relaxes the previous "never edit the user's rc" rule to "never edit it without
  consent" — what that rule protects is an rc changed behind your back, which an explicit yes is not.

### Fixed

- **Dropped a docker image default that pointed at a tag which does not exist.** The `docker` Ghidra
  mode (not implemented yet) carried `image: "…-ghidra:11.2"` as its default — a stale tag naming a
  version the project no longer uses. Left as-is it would have failed at pull time with a confusing
  registry error instead of an honest "you have not configured an image", so the default is now
  empty and will be filled in when the docker mode is actually built.

- **`scan` no longer silently caches a code-rich binary as "empty".** `ghidra_status='ok_empty'`
  was trusted as permanent ground truth, but it is derived from `has_substantial_text`, which
  returns `False` on *any* file read/parse error. So a code-rich binary whose file was momentarily
  unreadable at analysis time (a temp/cpio extraction cleaned, a migration to another machine, a
  race) got frozen as "legitimately empty" — and every honesty net (`already_done`, the Step 1b
  self-heal, the incomplete-binaries warning) then skipped it by trusting that stale label. It read
  as done+clean with 0 functions, silently, forever — exactly the failure a re-scan months later
  hits. The self-heal now re-verifies code-richness against the file the *current* scan sees: a
  done+0-function binary that is code-rich now is re-dirtied and re-analyzed (regardless of its
  stored label, no DB deletion), while one that is genuinely code-free stays cached as `ok_empty`
  and is never churned. The current file is the authority; a label can be stale, the bytes cannot.
- **The format-string wrapper gate now demotes instead of dropping (a `?` is never removed).** A
  recovered fmt-wrapper candidate whose forwarded value was "not a controllable source" was dropped
  from the corpus. But the forwarded `source_kind` here is only ever `free_string` or `unknown` —
  there is no proven-uncontrollable reading — so the gate was discarding candidates whose
  controllability is **unknown**, i.e. 100% `?`. The same function found *directly* keeps its unknown
  candidate, so removing it when found through a wrapper was a pure false negative that also let the
  set read as complete. The candidate now stays in the corpus and stays queryable. The original
  motive — variadic loggers are ubiquitous and would flood the high band — is a **ranking** concern
  the read-side ladder already serves: an unknown controllability ranks below `free`, while the
  demotion iron law keeps it off the floor (only a proven-safe fact sinks a candidate). The stat
  `fmt_wrapper_unknown_source_skipped` becomes `fmt_wrapper_unknown_source_demoted`, and the CLI no
  longer reports it as a recall narrowing.

- **Detector A no longer shatters a real dispatch table (systematic handler loss).** The per-slot
  handler test required Ghidra to have already created a `Function` object at the target. But a
  dispatch table is very often the *only* reference to its handler, so nothing calls it directly and
  auto-analysis never defines one — the run terminated at every such slot, splitting one real table
  into fragments and dropping every fragment below the run minimum, which lost even *defined*
  handlers whose undefined neighbours broke the run around them. Measured on real firmware: a
  32-entry handler table is strictly contiguous with every `word0` a `.rodata` string and every
  `word1` inside `.text`, yet only 17 of 32 targets were Ghidra-defined. The test is now "points at
  a plausible function ENTRY in `.text`" — an initialized executable block, instruction-aligned, and
  not into another function's body — anchored by address and marked `callee_kind='undefined_text'`
  when no `Function` object backs it. Rather-miss-than-err holds: `.rodata`/`.data` targets are
  still rejected (so `{str,str}` and `{ptr,ptr}` arrays are), on top of the unchanged
  consecutive-slot minimum. Replayed over the real data segment: **13 fragmented tables / 80 entries
  → 1 contiguous table / 203 entries**, with no new spurious table, recovering the previously lost
  `nvram_dump` handler. Completeness still reports `incomplete` — the relaxation recovers
  absolute-2-field entries that were mis-cut, it does not start reading GOT/MIPS/3-field forms.

- **`evidence_ref` no longer drifts across a re-scan.** The per-instance locator was built from
  `functions.id`, an AUTOINCREMENT rowid — and the analysis DB is delete-and-reingest per binary,
  so SQLite (which never reuses a number) shifted every id by the whole function count on **every**
  re-scan, with no code change required. Measured on real firmware: a four-times-scanned DB held
  88,178 functions numbered 266,156..354,333, and one unchanged function's ref moved from
  `#fn109348@cmd` to `#fn199770@cmd`. Any judgement stored against a ref therefore lost its anchor
  on the next scan. The ref is now built from facts belonging to the **binary** — its content-hash
  prefix plus the function's entry address (`<run>#<sha8>:<addr>@<sink>`) — via one shared builder
  used by every writer. Validated against real firmware: 88,178 functions → 88,178 collision-free
  refs. Anchoring the binary by *name* was rejected (real firmware ships distinct binaries sharing
  one name, which collided 4,460 refs) and by *path* (it carries the vendor/model string, and a ref
  must stay neutral). Scope is deliberately re-scan stability, not cross-recompile alignment — that
  remains the diff layer's problem. Refs from earlier scans change shape; re-run the hunt to refresh.

### Removed

- **LLM infrastructure removed — the fact substrate is now purely deterministic.** The `lib/llm/`
  and `lib/llm_cache/` packages (router, providers, task registry, cache) and the orphaned
  `lib/cost_guard/` are gone, along with the `llm` config block and its API-key onboarding. The core
  analysis layers were already hermetic; the LLM's only real use was an optional fallback in the
  cross-version function matcher, which the deterministic exact + pseudocode-hash passes fully
  cover. The matcher's stripped/renamed residue now surfaces honestly as added/removed instead of
  being force-matched, and `diff` needs no API key. Drops the `openai` / `anthropic` / `aiohttp` /
  `aiosqlite` runtime dependencies and the `--max-assist` flag.

### Added

- **An overlay annotation layer — an agent can record its own judgements over the read-only
  candidate map without ever touching it.** Three new MCP tools (`annotate`, `list_overlays`,
  `clear_overlay`) write to a separate, mutable `overlay` table; the base map (`list_candidates` and
  the instance/pattern tables behind it) reads byte-identical whether the overlay is empty or full,
  so the annotations are always distinguishable from tool facts and clearing them restores nothing.
  Each annotation carries a verdict (`to-review` / `in-progress` / `suspicious` / `excluded` /
  `safe`) plus a required rationale, coarse attribution (never a fabricated identity — a schema CHECK
  enforces it), and last-write-wins semantics (re-annotating overwrites in place and echoes whom it
  overwrote). The load-bearing honesty piece is **basis staleness**: each write snapshots the facts
  the annotation rested on — the function's pseudocode hash plus the per-sibling dimension SET (an
  `evidence_ref` maps to several instances, keyed by the content-stable pattern_id, so a change to
  *any* sibling is caught and a same-content re-scan produces zero delta). A later `list_overlays`
  re-derives that basis and reports what moved (`unchanged` / `changed` / `unverifiable` when there
  is no pseudocode hash to compare / `anchor_unresolved` when the candidate is gone), flagging a
  stale annotation for re-review rather than silently trusting it — the tool reports those facts
  only; whether a changed basis undoes the annotation is the consumer's call. Anchors scan/hunt
  candidates (`evidence_ref`) for now; a version-diff anchor kind is reserved in the schema.

- **`list_candidates(overlay=true)` — an opt-in view that ranks the map by your own annotations.**
  Default off; with it on, the annotations become the OUTERMOST ordering band, applied after the
  lens has fully sorted the list: `suspicious` floats, `excluded`/`safe` sink, and a dismissal whose
  basis has since moved floats back up for re-review instead of staying quietly sunk (an
  `unverifiable` basis counts as moved — a judgement resting on facts nobody can check is not a
  reason to keep a candidate out of sight). It **re-ranks, never reduces**: a sunk candidate stays
  in the corpus, still filterable and still queryable. Because the band reads only the annotation
  and never a base-map fact, an agent's `suspicious` can float a candidate the base map itself sank
  as provably constant — and the row then shows BOTH readings, the agent's verdict in its own
  top-level `overlay` key (verdict + attribution + basis freshness, naming what moved when stale)
  alongside the untouched tool-derived fields, so a float can never be misread as tmap having found
  the candidate dangerous. The band is stable, so the lens order survives inside it. The base sort
  engine is unchanged and knows nothing about any of this: with `overlay=false` the listing is the
  base map's, order and rows alike, and the annotation key is simply absent.

- **`tmap init` sizes the JVM pool to the machine, and `diff` full runs now run in parallel.**
  `max_parallel_jvms` was a hardcoded 4 and diff's BinExport heap a hardcoded `-Xmx4096m`, neither
  looking at the machine; a full diff ran every changed binary serially. Now `tmap init` probes the
  box — physical cores (the measured CPU knee, since Ghidra analysis is CPU-bound and hyperthreads
  contend) and MemTotal (a conservative fraction, not the volatile MemAvailable) — and writes the
  smaller of the two as `max_parallel_jvms` (`tmap init --force` re-detects; the probe method is
  logged so a WSL2/container fallback is visible). A full `diff` is split into three phases —
  preflight (serial, reads the atlas), compute (BinExport + BinDiff, parallel across a thread pool,
  zero atlas), and persist (serial on the main thread) — so the CPU-heavy middle runs concurrently
  while every atlas write stays single-threaded (no WAL, and each binary keeps its own independent
  atomic transaction from the retry-status work). Before a pool starts, parallelism is clamped down
  for that run if free memory or disk is tight — diff uses its own heavier per-JVM budget for that
  clamp (BinExport's peak is above scan's) without shrinking scan's pool. scan's per-binary adaptive
  heap ladder is now a shared `adaptive_heap_mb` helper it keeps using; diff's BinExport heap holds
  the conservative fixed 4096 until a peak-heap measurement on the largest diffed binary confirms the
  ladder is safe there (never an OOM mid-sweep). A full diff runs without a confirmation prompt (it
  is the normal usage — it announces the count, then streams progress); Ctrl-C stops scheduling
  further binaries and exits cleanly, keeping every binary already diffed (the rest are picked up on
  the next run) — the in-flight exports still finish, since a pool thread cannot kill them.

- **`diff` full runs are now incremental, self-healing, and honest about failures.** A full diff
  used to fail permanently on any per-binary toolchain error: the failure was printed once and never
  persisted, so a flaky, one-off failure stayed in the blind spot forever, a genuinely hard boundary
  (BinDiff cannot rebuild a binary's flow graph) could not be told apart from a transient one, and
  re-running redid every already-succeeded binary from scratch. The scan pipeline already solved this
  trio for Ghidra (a tri-state `ghidra_status` + an `ok` gate + auto re-run of the not-ok), so the
  same model is ported to diff: each binary now records a `diff_ok` / `diff_status` /
  `diff_status_reason` / `diff_attempts` row in `diff_meta` (a **failed** binary writes its own row —
  a persisted, queryable blind spot, never a silent drop), plus the `sha256` it ran on. The next full
  diff then **skips** already-ok binaries whose content is unchanged (incremental), **retries** failed
  ones (a transient crash self-heals within a couple of attempts), and after a retry cap marks a
  same-content repeat failure a *suspected hard boundary* it stops re-attempting — unless
  `--force-retry`, or the binary's content changes (a recompile voids the past verdict and resets the
  count). The failure write is a single **atomic** transaction (rollback → delete → insert → commit)
  so a second failure of the same binary never crashes on its own primary key and a layer-2 failure
  leaves no half-written or falsely-ok row behind. Read side: `list_diffs` carries each binary's
  status, a new `list_diff_blindspots` MCP tool enumerates the un-diffed binaries with their reason
  and attempt count, and an empty `get_diff_deltas` now points at the diff status — so an un-diffed
  binary can never masquerade as "no change" (UNKNOWN is not SAFE).

- **Reachability leads: string-key edges now reach one hop down, structurally.** A candidate that
  IS an edge callee already carried its key as a prose note. A candidate one direct call BELOW an
  edge callee — where the flagship command sink actually sits — carried nothing. Both now surface as
  machine-readable rows on the reachability layer's `evidence`: `{via, key, hops, through}`. Zero-hop
  is read straight from the atlas edge table; one-hop is walked downward at hunt time from each edge
  callee into its direct callees (the atlas holds no call graph) and rides on `flow_evidence`, so one
  pass lets a fan-out handler hand its key to every candidate below it. **The two hop depths are
  worded differently on purpose:** zero hop means the key dispatches *here*, but one hop only means
  the edge callee *calls* this function — an edge callee is often a fat handler, so the note states
  outright that the key-selected data's ARRIVAL is unproven. Deliberately **no thinness gate**: that
  is right for wrapper propagation, which creates candidates and must cross a thin forwarder, but the
  edge callees worth following here are exactly the fat handlers. Pure annotation — no new candidates,
  no rank change. **★ IRON LAW: `reachability` stays `unknown`; a lead is a fact, never a grant, and
  the word "reached" never appears.**

- **`tmap init` installs shell tab-completion (bash + zsh), by default and honestly.** Completion
  now rides along with the setup a user already runs — no `--no-completion` flag, because a
  completion script is side-effect-free and a skip toggle would only push a non-decision onto the
  user. The script is written to the shell's own autoload directory (bash:
  `~/.local/share/bash-completion/completions/tmap`; zsh: `~/.zsh/completions/_tmap`) — **never** by
  editing an rc file. It is idempotent (a re-run rewrites only on change). Honest about activation: a
  new `completion` doctor check reports where it went and, when the shell will not pick it up
  (bash-completion absent, or the zsh dir not yet on `fpath`), the exact one line to add — it never
  presents an inert completion as working. bash and zsh only for now; other shells are added on
  demand.
- **Shell completion for `scan -w` and `diff --run-id-a/-b`.** `scan -w <tab>` suggests existing
  workspace names (so a re-scan reuses a workspace instead of a typo silently starting a fresh one)
  while still accepting a brand-new name; `diff`'s run-id options complete the run names already in
  the atlas. Both callbacks are read-only and best-effort — an absent atlas or any error yields no
  suggestions, never a crashed shell. (The `diff` CLI currently takes two analysis.db paths plus
  run-id labels; a fuller "pick two existing runs" completion awaits a diff-CLI redesign.)
- **String-keyed edges exposed (detector B: strcmp-ladder dispatch).** A string-keyed edge is a
  deterministic fact — an attacker-influenceable string key gates or dispatches to a set of callees.
  A new Ghidra P-Code detector enumerates each same-variable `strcmp`/`strncmp`/`strcasecmp` ladder
  (multi-line strcmp is one CALL op, so decompiler line-wrapping never hides it), attributes callees
  to a key by CHK dominance (a callee is the key's only when the key's matched block dominates it —
  sound, no cross-key contamination), and records `ladder_size`, the callee anchor (`{name, addr,
  kind}`, BinDiff-alignable), and fine-grained completeness (a per-edge `gate_branch_unresolved` →
  `partial`; an unrecognized switch region → `incomplete`). Facts land in a new cross-run
  `string_keyed_edge` atlas table (one row per `(key, callee)`; a key whose gate resolved no callee
  keeps a callee-less lead row, never dropped) plus a `run_capability` registry that records the
  detector ran even when it found zero edges (absence-of-findings ≠ absence-of-capability). Read via
  the `get_string_keyed_edges` MCP tool (by run / binary / key / callee / from_function) and, on the
  reachability layer, as a key lead appended to a candidate's note. **★ IRON LAW: these are
  ENUMERATED edges, never a reachability verdict — a candidate that is an edge callee stays
  `reachability=unknown`; the key is a lead the agent confirms.**
- **String-keyed edges from static dispatch tables (detector A).** A companion Ghidra detector walks
  the initialized, non-executable data segments for a static `{string, funcptr}` dispatch table — a
  run of ≥4 records at a fixed `2*ptrsize` stride where one word resolves to a `.rodata` string (the
  key) and the next to a `.text` function entry (the handler). ★ rather-miss-than-err: a table is
  collected only when *every* record resolves both pointers, so a random `{ptr,ptr}` array or a data
  fragment is never mistaken for a table. It lands in the same `string_keyed_edge` atlas table
  (`mechanism='static_string_table'`), so one query, one MCP tool, and one capability key serve both
  detectors. The MVP recognizes absolute-addressed 2-field tables only; GOT/PIC-relative, MIPS, and
  3-field forms are not detected and are marked `incomplete` on every row (missed honestly, never
  misreported). Same iron law: a table entry is an enumerated edge, never a reachability verdict.
- **`public_cve_pattern.origin` provenance guard.** Every externally imported CVE-pattern row is
  now tagged `origin='external_import'` — a machine-readable guard (on top of the existing physical
  table separation) so external/agent-imported material can never be read as deterministic tmap
  extraction. CI-assertable: no row may carry any other origin.
- **`web_settable` now carries drill-down evidence.** The source-writability reading previously
  collapsed the front-end match to a bool; it now exposes the concrete `web_form_fields` rows behind
  it — `{field_keyword, source_asset, source_rule, match_kind}` — under a new `evidence` key. It
  rides through `get_nvram_key_flow` and the `source_writability` dimension of `explain_candidate`,
  so an agent can confirm the web reach or demote a keyword collision (SaTC keyword joins are
  collision-prone) without re-deriving. The yes/likely/uncertain verdict is unchanged.

### Changed

- **`-w`/`--workspace` is now a workspace NAME only — the literal-path mode is removed.** A path-mode
  used to exist, and it silently split one logical run across two physical directories: `-w router`
  (managed under the base) and `-w ./router` (a relative path resolved against the current dir)
  landed in different places, so a re-scan written one way could not see data written the other, and
  it left 0-byte orphan databases behind — which misled a whole verification pass. A workspace is now
  addressed one way: `-w <name>` always maps to `<workspace_dir>/<name>`, so the same name is always
  the same directory. A path-like value is rejected with a message that points at the name form (it
  is no longer silently resolved). `atlas.db` is unaffected; `analysis.db` is a rebuildable
  intermediate, so re-run `scan` once to repopulate the managed workspace.
- **`tmap --help` is grouped to make the human/agent division legible.** Commands were a flat list;
  they now fall into three sections: **Main** (`init` / `scan` / `diff` / `runs`) — where a person
  hands tmap the work only a person decides; **Analysis (recommended)** (`mcp`) — running the
  analysis itself is recommended via an agent over MCP; and **Advanced** (`analyze` / `hunt` /
  `triage` / `atlas-view` / `fact`) — for inspecting results yourself or re-running a single stage.
  The Main group stays terse (what each does, not how); the Advanced group labels `analyze`/`hunt`/
  `triage` as scan's stages and points out `fact` reads the same facts an agent sees via MCP. Hidden
  back-compat aliases are unchanged; a future command with no group still shows under "Other".

- **`bare_sink` moved out of `blocking_mechanism` into a new `exposure_shape` column.** `bare_sink`
  is a danger form (a raw command/format sink with no recognized in-function source), not a
  mitigation, so filing it under `blocking_mechanism` risked a consumer reading it as "blocked". It
  now lives in its own `instance.exposure_shape` column, surfaced distinctly by the CLI, the JSON,
  and `explain_candidate`. Controllability is unchanged (such candidates still read a live `?`).

### Fixed

- **Never wrongly downweight (recall red line).** The `const_sink_arg` form-downweight matched a
  string literal ANYWHERE in the function body, so a function containing both a constant
  `system("…")` and a `system(free_var)` wrongly downweighted the real, tainted candidate. It is
  now parameter-specific: the note fires only when a free value (an in-function source output or a
  caller-supplied parameter) does NOT reach the anchored candidate's own sink argument, and the
  analyzer additionally drops any note that contradicts the candidate's evidence at write time. A
  command candidate whose argument comes from a free string is no longer buried.
- **Analysis failure is no longer silent (degrade red line).** Ghidra success was decided purely by
  output-file size (> 200 bytes), so a truncated/partial run that left a well-formed-but-empty shell
  was frozen as "analyzed" and never re-ran — a code binary with 0 recovered functions masqueraded
  as clean. Success now requires a NON-EMPTY functions array; a binary that carries real code but
  yields 0 functions is recorded `failed` (and retried), while a genuinely code-free object is
  recorded `ok_empty` (and left alone). Binaries `binaries.ghidra_status` gains a tri-state
  (`ok` / `ok_empty` / `failed`).

### Added

- A new `ghidra_status` tri-state, a **self-heal** on re-analysis (a cached binary marked done but
  holding 0 functions despite real code is re-analyzed — no database rebuild needed), and a
  `--reanalyze` escape hatch on `scan` / `analyze` (bare = all binaries; `--reanalyze <name|path>` =
  one) to force past the cache.
- **Analysis-incompleteness is surfaced, not hidden.** `scan` / `analyze` print a warning naming any
  binary that produced no functions ("analysis incomplete, NOT clean … rerun with --reanalyze"), and
  the MCP `list_candidates` / `cross_firmware_patterns` / `pattern_density` results carry an
  `incomplete_binaries` field so an AI never mistakes a failed analysis for "nothing to find".
- **CI red-line gates** (`scripts/check_recall_integrity.py`, plus a `Recall Integrity` CI job): two
  machine-enforced invariants — no `const_sink_arg` candidate may have a `free_string` sink argument
  (Gate A), and no `ghidra_status='ok'` binary may have 0 functions (Gate B). Runs against real
  `--atlas` / `--analysis` databases, or `--self-test` for CI. These turn two previously
  docstring-only contracts into a build that fails red on violation.
- Each candidate now carries its `structural_fingerprint`, and MCP `list_candidates` gained a
  `fingerprint=` filter, so an AI can pivot from a `cross_firmware_patterns` hit straight to that
  pattern's instances.

### Changed

- **Command names shortened** to their common form: `hunt-pattern` → `hunt`, `hunt-diff` →
  `diff`, `mcp-serve` → `mcp`. The previous names stay resolvable as hidden aliases (not shown in
  `--help`) so existing scripts keep working; command behavior, options, and output are unchanged.

### Added

- `tmap mcp` now starts **without explicit paths**: `scan` / `hunt` / `analyze` record a last-run
  pointer (`~/.treasure-map/last_run.json`, the analysis.db + atlas absolute paths + run id), and
  `tmap mcp` serves that most-recent run when `--analysis-db` / `--atlas` are omitted (explicit
  paths still win). A missing pointer is a friendly message, not a traceback; a missing `mcp`
  optional dependency prints a one-line install hint and exits non-zero; and the stdio server
  prints a "launch me from an MCP client" hint to **stderr** (stdout stays clean JSON-RPC).
- The MCP server gained the capabilities the CLI already had, plus the cross-firmware views:
  - `list_candidates` defaults to the **firmware the server is bound to** (the current run), so a
    shared cross-firmware atlas no longer mixes another image's leads into the session; a
    stale/mismatched binding falls back to all runs annotated with `is_current_run` and a per-run
    `runs` summary. It also gained the `tmap triage` filters (`sink` by callee or class, exact
    `sink_class`, `status`, `include_gated`) and **pagination** (`limit` capped at 200 + `offset`,
    with `total` / `returned` / `truncated` / `next_offset` metadata replacing the ambiguous
    `count`). The sink/status filter logic now lives in `lib.query` so the CLI and MCP share it.
  - New read-only aggregation tools over the atlas: `cross_firmware_patterns` (per-pattern
    `device_spread` × `pattern_breadth` — the highest-value cross-firmware recurrence signal),
    `pattern_density`, `pattern_twins`, and `dormant_candidates`. Each carries the derived-not-a-
    verdict note; twins/dormant may be empty depending on the atlas's firmware mix.
  - The MCP protocol `instructions` are now the agent **workflow guide** (recall → fetch facts →
    judge; candidates are leads not verdicts; `evidence_ref` is the cross-tool anchor; empty
    callers may be an indirect call) instead of just the legal banner, which stays reachable via
    the `legal_notice` tool.

- An AI-facing **MCP server** (`tmap mcp`, a core dependency — the substrate's primary consumer,
  bundled on every install) exposes the
  analysis knowledge base as read-only tools: `list_candidates` / `explain_candidate` (recall
  candidates + derived, evidence-backed review-ordering signals), `get_pseudocode`, `get_callees`,
  `get_xrefs`, `get_strings`, `get_imports_exports`, `get_script_callsites`, `get_components_cves`,
  and `get_disassembly`. A new shared read layer (`treasure_map.lib.facts`) backs both the server
  and the `tmap fact …` CLI commands, so a fact fetched either way is identical (one query, two
  thin wrappers). Two contracts hold on every tool: no anchor → no output (a miss returns a
  "not found" record, never a guess), and facts/chains/reachability-evidence/trigger-conditions
  only — never a payload, trigger bytes, or PoC. `get_disassembly` is produced on demand and, when
  same-source address alignment cannot be established, degrades honestly to "unavailable" rather
  than emit possibly-misaligned addresses. Derived signals are labelled "derived, evidence-backed,
  not a verdict"; no interpretation column is reconstructed.
- The shared read layer (`treasure_map.lib.facts`, used by both the MCP server and the `tmap
  fact …` CLI) gained three lookups so verification rarely has to leave the substrate: (1)
  `get_pseudocode` / `get_callees` / `get_xrefs` / `get_disassembly` now resolve a function address
  typed in any common form — `0x38de8` / `38de8` / `00038de8` / decimal / `FUN_00038de8` — by
  normalizing to the stored zero-padded hex, and `binary` accepts either the short name or the full
  path (so a candidate listing's `binary_path` resolves directly); (2) `get_xrefs(direction=
  "callers")` recovers a same-binary caller the xref table does not record by reverse-scanning each
  function's recorded callee list, and when none is found it says so HONESTLY with a note that the
  function may yet be reached via an indirect / dispatch-table / function-pointer call static
  analysis cannot resolve (a true unresolved caller is never silently the same as "uncalled"); (3)
  `get_strings` can search by string CONTENT, returning each hit with its address and owning binary
  in one call, and states honestly that the reverse "which function references this string" lookup
  is not indexed. No analyze/index change; recall, scoring, and sink logic are untouched.
- **entry-reach review-ordering** (a second-level ranking key): the review score now reads the
  per-candidate `entry_reach` evidence (a rootfs startup/maintenance script or web asset was found
  to invoke the candidate's binary) and PROMOTES a candidate within its tier when an entry path is
  proven, so a network/script-reachable sink surfaces above a same-class same-status local-only
  one. Strictly asymmetric: only `found` promotes — `unknown` is neutral and NEVER demotes (an
  unknown may be a coverage gap, and demoting it could bury a real lead). It is a presentation-only
  ordering key, smaller than the sink-class gap (never reverses the status/sink-class order) and
  never alters a stored reachability state or adds/removes a candidate. Copy-sink candidates now
  also carry `entry_reach` in their size evidence so the ranking is even across cmd/copy/format/
  fmt_string.
- Format-string-injection sinks (`printf` / `fprintf` / `dprintf` / `syslog` / `vsyslog` / `err` /
  `warn` / `asprintf` and their `v*` variants) are now recalled as a new `fmt_string` sink class —
  an entire sink category that was previously absent (it builds no buffer, runs no command, copies
  nothing). The danger axis is each sink's own FORMAT-STRING argument position (per-sink map:
  `printf` arg0, `fprintf` / `syslog` / `err` arg1, …) — never a blind arg0, which would read a
  `FILE*` / log level as the format. The literal-format exemption GATES the recall (the
  FP-suppression that makes this safe to turn on): a sink is a candidate only when not all of its
  calls pass a literal format string — the overwhelmingly common `syslog(level, "msg %s", x)` /
  `printf("%s", x)` is exempt and never floods the candidate set, while `syslog(level, buf)` /
  `printf(user)` (a non-literal, controllable-shaped format) is recalled. Prove-safe-to-exempt: a
  format that cannot be shown literal (any non-literal call, or an unreadable position) is kept.
  Format-string candidates are graded on the format argument (a strong in-function source flowing
  to it confirms; a caller-supplied format is unknown) and carry flow evidence on that argument
  plus the format-position facts (`fmt_arg_pos`, `fmt_arg_literal`); the `fmt_string` sink class
  ranks alongside `cmd` (both RCE-class interpreters), above copy/format. This closes the L0 recall
  floor for the format-string-injection class.
- Copy sinks (`memcpy` / `memmove` / `strncpy` / `strcpy`) are now graded on their WRITE LENGTH
  (the danger axis), not on whether taint reaches the destination pointer. A copy never confirms
  within one function (proving a length is truly unbounded and externally controllable needs
  cross-function context), so the verdict is always `unknown` — with a size-source classification:
  a literal constant (`const_size`) or `sizeof` (`sizeof_bound`) length is non-controllable
  (downweighted hard, out of the high band); a clamp / pointer guard REFERENCING the length
  (`clamp_size` / `pointer_guard_size`, including the check-then-abort form `if (CONST < n) ...`)
  is a coverage-unjudged signal (downweighted mildly — the candidate stays visible); a variable
  with no visible upper bound, a length taken from the source string's own length (`strncpy(dst,
  src, strlen(src))` — equivalent to unbounded), or an untraced length gets NO downweight and keeps
  its normal rank. Prove-bounded-to-demote, never prove-dangerous-to-keep: a copy not proven
  bounded is never silently demoted (a clamp tied to a *different* variable, or a `> 0` non-bound,
  does not count). This clears the false `confirmed` copies (a constant-length copy of tainted
  bytes is bounded) so a real command candidate is no longer ranked beneath them. `memmove` is now
  in the copy class. Copy candidates carry structured SIZE evidence (`size_kind`, `size_flow`,
  `clamp_seen` with `coverage=unjudged`, `trace_boundary`) in the same `flow_evidence` field —
  material for an agent, never a verdict.
- The pattern analyzer now recovers command candidates whose sink hides one hop inside a thin
  command wrapper (factor ①): a function that builds a string and forwards it to a function marked
  `is_thin_cmd_wrapper` — with no command sink among its own callees — becomes a command candidate
  whose sink is the wrapper's `wrapped_sink`. This recovers the recall blind spot where the real
  `system` lives in a small forwarding shell, invisible to the direct-callee shape scan.
  Deliberately narrow (the only recall-amplifying step): ONE hop, INTRA-binary, and only for
  functions with no direct command sink of their own; multi-hop, indirect/function-pointer, and
  cross-binary wrappers are not propagated (blind spots left to the agent). New candidates run
  through the same FP-suppression — a constant or inline-charset-constrained argument forwarded to
  the wrapper is downweighted (`const_sink_arg` / `charset_constrained`), so a safe fanout stays
  low while a free / constructed string surfaces high. They are graded unknown / L0 (the sink is
  across a call boundary) and their flow evidence marks `sink_via_wrapper` + the wrapper name and a
  `reached_sink_via_one_hop_wrapper` boundary, and classifies the forwarded value conservatively —
  a free source present but not fully traceable through intermediate variables is reported
  `free_string` (do not miss a danger; the mirror of charset's `charset_maybe`). A
  `wrapper_propagated` stat reports how many were recovered (so an over-broad wrapper judgment
  surfaces as a count to tighten, not a silent flood). The thin-wrapper bound is 20 statements
  (a real command shell forwards `system(param)` then parses the return value); five-device
  measurement confirmed this does not over-label (the verbatim-forward judgment is the real bound).
- `json_object_get_string` / `json_object_get_string_len` are now recognized as external-input
  sources (a common modern IoT request-input path), so a command built from a JSON-getter value is
  classified `free_string` and surfaces high rather than being missed as `unknown`.
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
- Apache-2.0 license
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
