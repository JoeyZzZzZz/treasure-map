# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""How a version diff is read, said once and quoted by every place that says it. A leaf: it
imports nothing, so any module may import it.

* ``DIFF_WORKFLOW`` — the whole-pair loop first, then one diff alone: the MCP server's standing
  instructions, the full guide, start_diff_review(diff_id)'s ``workflow``, the diff command's
  closing lines, get_diff_meta's note and the agent skill.
* ``PAIR_WORKFLOW`` — what start_diff_review(run_pair) hands back as its ``workflow``: how to work
  through its units. The agent skill quotes it too.
* ``PAIR_SIDES`` — that both sides of a change are read, and how a side's rows are read: the
  close of ``PAIR_WORKFLOW`` and a line of the findings hand-off's header.
* ``DIFF_ONE_DIFF`` — the earlier one-diff sentence, kept word for word for the full guide only:
  the guide must keep every sentence of the instructions as they were frozen at a671109
  (tests/fixtures/tool_descriptions_a671109.json), and these two were among them."""

DIFF_ONE_DIFF = (
    "For a version diff: list_diffs names the diff ids; start_diff_review(diff_id) gives the "
    "entries to read first, in the default order; read one in full with "
    "get_diff_patch_view(diff_id, entry_id=...), judge it from its pseudocode_delta / "
    "inline_hunk, record the judgment with annotate_diff (or annotate_diff_batch for many "
    "entries of one diff), and carry a finding onto one of its candidates with promote. The "
    "non-binary files of the two runs (scripts, configs, credentials, web assets) are compared "
    "by get_file_diff(run_pair) and one is judged with annotate_diff(..., run_pair=...)."
)

DIFF_WORKFLOW = (
    "For a version diff, review the WHOLE PAIR (run ids from list_diffs): "
    "start_diff_review(run_pair='<run_a>::<run_b>') hands out work units; judge each member of "
    "next_unit with annotate_diff(..., unit_id=...) (annotate_diff_batch for many; run_pair=... "
    "for a binary_presence binary or a file), then call again until next_unit is null; "
    "worker/workers shard it; before reporting, quote its coverage_statement. One diff alone: "
    "start_diff_review(diff_id), get_diff_patch_view(diff_id, entry_id=...), promote a finding "
    "onto a candidate. get_diff_handoff(run_pair) pages the hand-off."
)

# Both sides of a change are read: said in PAIR_WORKFLOW and in the hand-off's header.
PAIR_SIDES = (
    "Both sides are material to read: a hunk's '-' lines are the A side and its '+' lines the B "
    "side; an entry's candidate rows with a ref on one side only are read by entry — "
    "get_diff_patch_view(diff_id=<its diff>, entry_id=<its entry_id>, rows_offset=<offset>)."
)

PAIR_WORKFLOW = (
    "Read next_unit.material (start_diff_review(run_pair, unit=<unit_id>) reads one unit alone), "
    "judge each member with annotate_diff(anchor_ref, verdict, ..., diff_id=<its diff>, "
    "unit_id=<next_unit.unit_id>) — or annotate_diff_batch with the same unit_id for a batch, "
    "run_pair=... for a binary_presence binary or a file — then call start_diff_review(run_pair) "
    "again: the next unit follows. The report counts what is disposed; an unjudged member is "
    "UNREAD, which is not 'nothing found'; a judgment written before its subject was read reads "
    "needs_recheck (not disposed) until judged again after reading it — for no_real_change / "
    "change_inconclusive on a must-read subject, read whole; a changed_real read in part still "
    "counts. Once must_read_complete is true, get_diff_handoff(run_pair) pages a standardized "
    "hand-off of the changed_real findings (refused before; tmap review report --handoff writes "
    "a partial one for a person). A pair larger than one session is reviewed in several: a fresh "
    "session's start_diff_review(run_pair) continues with the next unit not yet disposed (progress "
    "counts what is left). " + PAIR_SIDES
)
