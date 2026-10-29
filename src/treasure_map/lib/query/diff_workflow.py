# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The one sentence that says how a version diff is read, shared by every place that says it: the
MCP server's instructions, the diff command's closing lines and get_diff_meta's note. A leaf: it
imports nothing, so any module may import it."""

DIFF_WORKFLOW = (
    "For a version diff: list_diffs names the diff ids; start_diff_review(diff_id) gives the "
    "entries to read first, in the default order; read one in full with "
    "get_diff_patch_view(diff_id, entry_id=...), judge it from its pseudocode_delta / "
    "inline_hunk, record the judgment with annotate_diff (or annotate_diff_batch for many "
    "entries of one diff), and carry a finding onto one of its candidates with promote. The "
    "non-binary files of the two runs (scripts, configs, credentials, web assets) are compared "
    "by get_file_diff(run_pair) and one is judged with annotate_diff(..., run_pair=...)."
)
