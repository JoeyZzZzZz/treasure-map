---
name: tmap-diff-review
description: Review every change between two firmware versions with the tmap MCP server, unit by unit, until the server reports the must-read set complete. Use when asked to review, triage or audit a version diff (a run pair) with tmap.
---

# Reviewing a version diff with tmap

tmap compares two scans of one firmware (a run pair, `{run_a}::{run_b}`) and hands the review out
in work units. The server decides what must be read and counts what has been judged; your job is to
read each unit's material and record a judgment on every member. tmap draws no conclusion and
produces no payload: every judgment is yours.

## The loop

1. `list_runs` / `list_diffs` give the run pair. Call
   `start_diff_review(run_pair="<run_a>::<run_b>")`.
2. Read `report.coverage_statement` and keep it: it is the server's own count. When you report
   progress, quote it as it is — never your own estimate.
3. Read `next_unit.material`:
   - an `entry` unit: one diff entry in full (its `pseudocode_delta` / `inline_hunk`, its candidate
     rows, `pair_evidence`, `sink_callsite_counts`). Page more rows with the `read_more` call.
   - an `s_batch` / `second_tier_batch` unit: several entries of one diff as a scan; open any one
     with `get_diff_patch_view(diff_id, entry_id=...)` before judging it.
   - a `binary_presence` unit: a binary one version holds alone, with its first candidates;
     `explain_candidate(evidence_ref)` reads one.
   - a `non_binary_file` unit: a changed script / config / web file and its line difference.
   If the material says it was cut (`entries_truncated`, `top_truncated`, a withheld hunk), read
   the rest with the calls it names before judging. When a function is too large to show, read it
   with `get_pseudocode`.
4. Judge every member: `annotate_diff(anchor_ref, verdict, ..., diff_id=...)` — or
   `annotate_diff_batch` for a batch, `run_pair=...` for a binary_presence binary or a file.
   Verdicts: `changed_real` (the change matters; give evidence), `no_real_change` (say what you
   checked and why it is unchanged), `change_inconclusive` (say what is missing).
5. Call `start_diff_review(run_pair=...)` again. Repeat until `next_unit` is null.

## Rules

- An unjudged member is UNREAD, which is not "nothing found". Do not stop after a few units and
  summarise: the report shows what was skipped.
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
