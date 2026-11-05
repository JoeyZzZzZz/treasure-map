---
name: tmap-diff-review
description: Review every change between two firmware versions with the tmap MCP server, unit by unit, until the server reports the must-read set complete. Use when asked to review, triage or audit a version diff (a run pair) with tmap.
---

# Reviewing a version diff with tmap

tmap compares two scans of one firmware (a run pair, `{run_a}::{run_b}`) and hands the review out
in work units. The server decides what must be read and counts what has been judged; your job is to
read each unit's material and record a judgment on every member. tmap draws no conclusion and
produces no payload: every judgment is yours.

{loop}

## Rules

- An unjudged member is UNREAD, which is not "nothing found". Do not stop after a few units and
  summarise: the report shows what was skipped.
- Name the unit you judge (`unit_id`). A judgment written before its subject's material was read
  reads `needs_recheck` — not disposed — until you judge it again after reading it.
- Do not judge from the summary alone. Read both sides of the code the material gives (or fetch
  it) before a verdict.
- `must_read_complete` is the bar for "the must-read part is done"; `complete` also needs every
  second-tier entry. Report both as the server gives them.
- `report.not_seen` lists what this view cannot see. Do not claim coverage of those classes.
- With several workers, give each its own `worker` / `workers` pair so no two judge the same unit.
- The full unit list is not sent over MCP: `tmap review report <run_pair> --md -o review.md`
  writes it for a person to read.
- To have tmap drive the review instead (one fresh agent run per unit, coverage guaranteed):
  `tmap review <run_pair> --agent claude-code` — it probes the agent's tool set first.

Full rules: `get_tool_reference(name="guide")`.
