---
name: tmap-diff-review
description: Review every change between two firmware versions with the Treasure Map (tmap) MCP server, unit by unit; a whole run pair usually spans several sessions, or tmap's batch driver. Use when asked to review, triage or audit a version diff (a run pair) with Treasure Map or tmap.
---

# Reviewing a version diff with tmap

tmap compares two scans of one firmware (a run pair, `{run_a}::{run_b}`) and hands the review out
in work units. The server decides what must be read and counts what has been judged; your job is to
read each unit's material and record a judgment on every member. tmap draws no conclusion and
produces no payload: every judgment is yours.

## The loop

For a version diff, review the WHOLE PAIR (run ids from list_diffs): start_diff_review(run_pair='<run_a>::<run_b>') hands out work units; judge each member of next_unit with annotate_diff(..., unit_id=...) (annotate_diff_batch for many; run_pair=... for a binary_presence binary or a file), then call again until next_unit is null; worker/workers shard it; before reporting, quote its coverage_statement. One diff alone: start_diff_review(diff_id), get_diff_patch_view(diff_id, entry_id=...), promote a finding onto a candidate. get_diff_handoff(run_pair) pages the hand-off.

Read next_unit.material (start_diff_review(run_pair, unit=<unit_id>) reads one unit alone), judge each member with annotate_diff(anchor_ref, verdict, ..., diff_id=<its diff>, unit_id=<next_unit.unit_id>) — or annotate_diff_batch with the same unit_id for a batch, run_pair=... for a binary_presence binary or a file — then call start_diff_review(run_pair) again: the next unit follows. The report counts what is disposed; an unjudged member is UNREAD, which is not 'nothing found'; a judgment written before its subject was read reads needs_recheck (not disposed) until judged again after reading it — for no_real_change / change_inconclusive on a must-read subject, read whole; a changed_real read in part still counts. Once must_read_complete is true, get_diff_handoff(run_pair) pages a standardized hand-off of the changed_real findings (refused before; tmap review report --handoff writes a partial one for a person). A pair larger than one session is reviewed in several: a fresh session's start_diff_review(run_pair) continues with the next unit not yet disposed (progress counts what is left). Both sides are material to read: a hunk's '-' lines are the A side and its '+' lines the B side; an entry's candidate rows with a ref on one side only are read by entry — get_diff_patch_view(diff_id=<its diff>, entry_id=<its entry_id>, rows_offset=<offset>).

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
- Name the unit you judge (`unit_id`). A judgment written before its subject was read reads
  `needs_recheck` — not disposed — until you judge it again after reading it. A `no_real_change`
  or `change_inconclusive` on a must-read subject needs it read whole (every candidate row; code
  held back, read in full); a `changed_real` read in part still counts.
- Do not judge from the summary alone. Read both sides of the code the material gives (or fetch
  it) before a verdict.
- A `changed_real` on a must-read function_pair or function_presence entry has to CITE the rows the
  change landed on: `evidence` names each row whose `landing` is not `persisted`, by that row's
  `a_ref` or `b_ref`, up to 20 of them. On a function_presence entry — a function only one side
  holds — every row lands, so that is all of them. Citing fewer reads `needs_recheck`;
  `coverage_statement` counts the rest under `entry citations short`. An entry whose rows are all
  `persisted` owes no row citation — a change in the function body that lands on no candidate is
  legitimate.
- On ONE narrow class of one-sided subject a `changed_real` also has to say what the code on that
  side HELD: a binary only one run has, holding a command-execution candidate, whose binary a
  recorded entry edge references (a web endpoint, a rootfs script call, or an exec from another
  binary). There "the binary is gone, so its candidates are gone" cites every candidate and reads
  disposed, so nothing would be said about what was lost — and on the added side, about what
  appeared. Pass `one_sided_characterized`: `sink_classes` (every class its candidates carry,
  class -> count; the NAMES are what is asked for), `reachability` (tmap's own entry reading,
  restated — `status`, `kinds` and `basis` are COMPARED against it, and the hand-off's
  `reachable shape` cell prints all three), and `cmd_sinks` (one record per command candidate —
  `callee`, `arg_kind`, `source_kind`; where the callsite has no def-use record say so rather
  than leaving the candidate out, and the hand-off's `command sinks` cell names every callee the
  gate wants). Facts only: no impact judgement, and no claim about an authentication boundary is
  asked for. Short reads `needs_recheck`, counted under `one-sided characterisation short`; the
  write's own answer tells you whether this subject is held and what it still owes.
- A `pairing_component` unit holds the alternative pairings an alternative-pairing claim proposes
  for mis-paired entries. Read its alternative entries first and judge each on its own anchor; a
  superseded entry needs no judgment; judge an end function (`ends`) on the entry it is in; in a
  component with a conflict, judge every claim.
- `must_read_complete` is the bar for "the must-read part is done"; `complete` also needs every
  second-tier entry. Report both as the server gives them.
- By default only the must-read units are handed out: `next_unit` null then comes with
  `coverage_offer`, which counts the second tier still unread (`second_tier.by_bucket`). Quote it
  as it is and ask the person whether to read the second tier; only on their yes, call
  `start_diff_review(run_pair=..., sweep=true)` and go on as before.
- `report.not_seen` lists what this view cannot see. Do not claim coverage of those classes.
- With several workers, give each its own `worker` / `workers` pair so no two judge the same unit.
- A report of the pair's findings is tmap's hand-off, never a list rebuilt from summaries (a
  sub-agent's, an earlier session's or your own). `get_diff_handoff(run_pair)` pages it; on the
  command line `tmap review report <run_pair> --handoff --analysis <file> -o handoff.md` writes it
  with your texts under each finding, `<file>` holding
  `{"findings": [{"anchor_ref": …, "hypotheses": …, "device_checks": …}]}` — one `--analysis`
  per sub-agent's file, never merged by hand. Each sub-agent writes its own file; one that cannot
  returns that JSON as its final message, which you save to a file as it is. A finding no file
  names, or names with both texts empty, is still written, saying the agent wrote nothing for it,
  and the command lists it. A summary of your own may pick some findings out; it names the
  hand-off file and its finding count as the whole list.
- The full unit list is not sent over MCP: `tmap review report <run_pair> --md -o review.md`
  writes it for a person to read.

Full rules: `get_tool_reference(name="guide")`.
