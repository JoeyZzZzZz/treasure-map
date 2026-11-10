---
name: tmap-diff-review
description: Review every change between two firmware versions with the tmap MCP server, unit by unit; a whole run pair usually spans several sessions, or tmap's batch driver. Use when asked to review, triage or audit a version diff (a run pair) with tmap.
---

# Reviewing a version diff with tmap

tmap compares two scans of one firmware (a run pair, `{run_a}::{run_b}`) and hands the review out
in work units. The server decides what must be read and counts what has been judged; your job is to
read each unit's material and record a judgment on every member. tmap draws no conclusion and
produces no payload: every judgment is yours.

{loop}

## Rules

- A whole run pair is usually larger than one agent context. For full coverage a person runs
  `tmap review run <run_pair> --agent claude-code` (it probes the agent's tool set first, then
  one fresh agent run per unit; `--until complete` for the second tier too). Working here, you
  review one slice of the pair.
- An unjudged member is UNREAD, which is not "nothing found".
- Stop only at a unit boundary (every member of the unit in hand judged): when `next_unit` is
  null, or when your context nears its limit (`progress.this_session` counts what this session
  has read). An early stop is a hand-off: from your last answer, quote
  `progress.coverage_statement`, `progress.must_read_left`, `progress.reduce_owed`,
  `progress.must_read_complete` and, when it is false with nothing left, `progress.still_open`;
  say the review is not complete, and name `progress.resume_with` as the call a fresh session
  continues with. Never call the review complete unless `must_read_complete` is true. Working a
  shard (`progress.scope` is `shard`), the counts `progress.pair_wide` names are the whole
  pair's, not this shard's.
- Name the unit you judge (`unit_id`). A judgment written before its subject's material was read
  reads `needs_recheck` — not disposed — until you judge it again after reading it.
- Do not judge from the summary alone. Read both sides of the code the material gives (or fetch
  it) before a verdict.
- `must_read_complete` is the bar for "the must-read part is done"; `complete` also needs every
  second-tier entry. Report both as the server gives them.
- By default only the must-read units are handed out: `next_unit` null then comes with
  `coverage_offer`, which counts the second tier still unread (`second_tier.by_bucket`). Quote it
  as it is and ask the person whether to read the second tier; only on their yes, call
  `start_diff_review(run_pair=..., sweep=true)` and go on as before.
- `report.not_seen` lists what this view cannot see. Do not claim coverage of those classes.
- With several workers, give each its own `worker` / `workers` pair so no two judge the same unit.
- The full unit list is not sent over MCP: `tmap review report <run_pair> --md -o review.md`
  writes it for a person to read.

Full rules: `get_tool_reference(name="guide")`.
