# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The pair review's report in three faces — terminal summary, markdown, HTML — all rendered from
one reading (lib/query/review_units.PairReview), so they never part. The terminal summary's first
line is the ``coverage_statement``; markdown and HTML add every unit in the hand-out order, each
member with its review state and the reasons it is must-read. A subject under an open audit
shows neither: its state names the verdict under audit, which an audit reads blind.

A reading face only: nothing here writes. Every string taken from the firmware (binary names,
paths, entry ids) is escaped in the HTML, which carries no script.
"""

from __future__ import annotations

import html
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from treasure_map.lib import handoff_boundary as _handoff_boundary
from treasure_map.lib.query import review_units as ru

# How many next units the terminal summary names.
TERMINAL_NEXT = 10

_STATEMENT_NOTE = (
    "Quote the coverage_statement as it is: it is computed by tmap from the judgements, not by "
    "whoever ran the review."
)
_NOT_SEEN_NOTE = (
    "What this view cannot see — a gap here is closed only by a judgement on the subject that "
    "holds it, never by acknowledging it."
)


# The state a subject under an open audit shows, in every row it appears in: its own state
# (inconclusive / concluded) would name the verdict the audit reads blind.
UNDER_AUDIT = "under audit"


def _shown_states(review: ru.PairReview) -> dict[str, str]:
    """Each member's state as the member tables show it: a subject under an open audit as
    ``UNDER_AUDIT``."""
    shown = dict(review.progress.states)
    for a in review.audits.open:
        shown[a.member.anchor_ref] = UNDER_AUDIT
    return shown


def _short(stream: str) -> str:
    return stream.rsplit("::", 1)[-1]


def _unit_line(u: ru.Unit, states: dict[str, str]) -> str:
    done = sum(1 for m in u.members if ru.disposed(states.get(m.anchor_ref)))
    first = u.members[0]
    what = first.entry_id or first.anchor_ref.rsplit("#", 1)[-1]
    more = f" (+{len(u.members) - 1})" if len(u.members) > 1 else ""
    return (
        f"{u.unit_id}  {u.kind:<18} {_short(u.stream):<24} round {u.position:<4} "
        f"{done}/{len(u.members)} disposed  {what}{more}"
    )


def terminal(review: ru.PairReview, *, header: dict[str, Any] | None = None) -> str:
    """The terminal summary: the coverage_statement first, then the must-read set by kind and by
    reason, what no unit can reach, and the next units in the hand-out order."""
    rep = review.report
    states = review.progress.states
    out = [rep["coverage_statement"]]
    for k, v in (header or {}).items():
        out.append(f"{k}: {v}")
    mr = rep["must_read"]
    out.append(
        f"must_read_complete: {str(rep['must_read_complete']).lower()}   "
        f"complete: {str(rep['complete']).lower()}"
    )
    out.append(
        f"must-read units {mr['units_disposed']}/{mr['units']} disposed; members "
        f"{mr['members_disposed']}/{mr['members']}; candidate rows in them {mr['candidate_rows']}"
    )
    out.append("units by kind (disposed / units, members):")
    for kind, row in rep["units_by_kind"].items():
        out.append(f"  {kind:<18} {row['disposed']}/{row['units']}  ({row['members']})")
    out.append(
        "must-read by reason: " + ", ".join(f"{r} {n}" for r, n in mr["by_reason"].items() if n)
    )
    nr = rep["not_reachable"]
    out.append(
        f"not reachable: failed diffs {len(nr['failed_diffs'])}, withheld diffs "
        f"{len(nr['withheld_diffs'])}, binaries no diff covers "
        f"{'yes' if nr['not_diffed_binaries'] else 'none'}, files "
        f"{nr['non_binary_files_unavailable'] or 'read'}"
    )
    out.append("not seen: " + ", ".join(rep["not_seen"]))
    pending = [u for u in review.units if not ru.unit_disposed(u, states)]
    out.append(f"next units ({len(pending)} with a member not disposed):")
    out += ["  " + _unit_line(u, states) for u in pending[:TERMINAL_NEXT]]
    return "\n".join(out)


def _md_cell(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


# Above this many members a callee group is listed, not drawn (a diagram that size reads worse
# than the table under it; the HTML page lists it the same way).
MERMAID_MAX_MEMBERS = 15
_MERMAID_SAFE = re.compile(r"[^0-9A-Za-z_:.]")


def _mermaid_group(u: ru.Unit) -> list[str]:
    """A callee group as a mermaid graph: each member -> the callee it newly calls."""
    g = u.group or {}
    # Members kept though their A-side call list was unreadable: "newly calls" is UNCONFIRMED for
    # them, so the report names them rather than letting "N members newly call X" read as settled.
    unread = list(g.get("members_a_side_unread") or [])
    caveat = (
        [
            f"_{len(unread)} member(s) kept with the A-side call list unreadable, so "
            "'newly calls' is UNCONFIRMED for: "
            + ", ".join(f"`{_md_cell(x)}`" for x in unread)
            + "._",
            "",
        ]
        if unread
        else []
    )
    if len(u.members) > MERMAID_MAX_MEMBERS:
        return [
            f"_Callee group `{_md_cell(g.get('ref'))}`: {len(u.members)} members newly call "
            f"`{_md_cell(g.get('name'))}` — too many to draw; listed below._",
            "",
            *caveat,
        ]

    def label(text: Any) -> str:
        return _MERMAID_SAFE.sub("_", str(text))

    out = ["```mermaid", "graph LR"]
    callee = f'X["{label(g.get("name"))} {label(g.get("callee_b"))}"]'
    for i, m in enumerate(u.members):
        out.append(f'  M{i}["{label(m.entry_id)}"] --> {callee if i == 0 else "X"}')
    out += ["```", ""]
    return out + caveat


def markdown(review: ru.PairReview, *, header: dict[str, Any] | None = None) -> str:
    """The whole report as markdown: the summary, then every unit in the hand-out order."""
    rep = review.report
    states = review.progress.states
    shown = _shown_states(review)
    out = [f"# Review of {_md_cell(rep['run_pair'])}", "", f"**{rep['coverage_statement']}**", ""]
    out.append(f"_{_STATEMENT_NOTE}_")
    out.append("")
    for k, v in (header or {}).items():
        out.append(f"- {k}: `{_md_cell(v)}`")
    out += [
        f"- must_read_complete: **{str(rep['must_read_complete']).lower()}**",
        f"- complete: **{str(rep['complete']).lower()}**",
        f"- predicate: `{rep['predicate_version']}`, k = {rep['k']}",
        "",
        "## Units by kind",
        "",
        "| kind | units | disposed | members |",
        "|---|---|---|---|",
    ]
    for kind, row in rep["units_by_kind"].items():
        out.append(f"| {kind} | {row['units']} | {row['disposed']} | {row['members']} |")
    out += ["", "## Must-read by reason", "", "| reason | members |", "|---|---|"]
    for reason, n in rep["must_read"]["by_reason"].items():
        out.append(f"| {reason} | {n} |")
    nr = rep["not_reachable"]
    out += ["", "## Not reachable by any unit", ""]
    out.append(f"- failed diffs: {len(nr['failed_diffs'])}")
    for d in nr["failed_diffs"]:
        out.append(f"  - `{_md_cell(d.get('diff_id'))}` ({_md_cell(d.get('diff_status_reason'))})")
    out.append(f"- withheld diffs: {len(nr['withheld_diffs'])}")
    for d in nr["withheld_diffs"]:
        out.append(f"  - `{_md_cell(d['diff_id'])}`: {_md_cell(', '.join(d['banners']))}")
    out.append(f"- binaries no diff covers: `{_md_cell(nr['not_diffed_binaries'] or 'none')}`")
    out.append(f"- non-binary files: {_md_cell(nr['non_binary_files_unavailable'] or 'read')}")
    out += ["", "## Not seen by this view", "", f"_{_NOT_SEEN_NOTE}_", ""]
    out += [f"- {x}" for x in rep["not_seen"]]
    if rep["dangling_judgements"]:
        out += ["", "## Judgements whose subject is gone", ""]
        out += [f"- `{_md_cell(a)}`" for a in rep["dangling_judgements"]]
    out += ["", "## Units in hand-out order", ""]
    for u in review.units:
        done = sum(1 for m in u.members if ru.disposed(states.get(m.anchor_ref)))
        tag = "must-read" if u.must_read else "second tier"
        out.append(
            f"### `{u.unit_id}` — {u.kind}, {tag}, round {u.position}, "
            f"{_md_cell(_short(u.stream))} ({done}/{len(u.members)} disposed)"
        )
        out.append("")
        out.append(
            f'Read: `start_diff_review(run_pair="{_md_cell(rep["run_pair"])}", '
            f'unit="{u.unit_id}"' + (f", k={rep['k']}" if rep["k"] != ru.DEFAULT_K else "") + ")`"
        )
        anchor = "" if len(u.members) == 1 else " --anchor <anchor_ref>"
        out.append(
            f"Judge (a person): `tmap review judge {u.unit_id} {_md_cell(rep['run_pair'])}"
            f"{anchor} --verdict <changed_real|no_real_change|change_inconclusive> "
            '--rationale "<why>"`'
        )
        out.append("")
        if u.kind == ru.GROUP and u.group is not None:
            out += _mermaid_group(u)
        out.append("| member | bucket | state | reasons |")
        out.append("|---|---|---|---|")
        for m in u.members:
            out.append(
                f"| `{_md_cell(m.entry_id or m.anchor_ref)}` | {_md_cell(m.bucket or '')} | "
                f"{_md_cell(shown.get(m.anchor_ref, ''))} | {_md_cell(', '.join(m.reasons))} |"
            )
        out.append("")
    return "\n".join(out) + "\n"


_CSS = (
    "body{font:14px/1.5 system-ui,sans-serif;margin:16px;max-width:1100px}"
    "table{border-collapse:collapse;margin:8px 0}td,th{border:1px solid #bbb;padding:2px 6px;"
    "text-align:left}code{font-size:13px}.stmt{font-weight:600;font-size:15px}"
    ".done{color:#2a7a2a}.open{color:#a0522d}"
)


def html_page(review: ru.PairReview, *, header: dict[str, Any] | None = None) -> str:
    """The whole report as one static HTML page — no script; every value escaped."""
    rep = review.report
    states = review.progress.states
    shown = _shown_states(review)
    e = html.escape
    out = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        "style-src 'unsafe-inline'\">",
        f"<title>Review {e(rep['run_pair'])}</title><style>{_CSS}</style></head><body>",
        f"<h1>Review of {e(rep['run_pair'])}</h1>",
        f"<p class='stmt'>{e(rep['coverage_statement'])}</p>",
        f"<p><em>{e(_STATEMENT_NOTE)}</em></p><ul>",
    ]
    for k, v in (header or {}).items():
        out.append(f"<li>{e(str(k))}: <code>{e(str(v))}</code></li>")
    out.append(f"<li>must_read_complete: <b>{str(rep['must_read_complete']).lower()}</b></li>")
    out.append(f"<li>complete: <b>{str(rep['complete']).lower()}</b></li></ul>")
    out.append("<h2>Units by kind</h2><table><tr><th>kind</th><th>units</th><th>disposed</th>")
    out.append("<th>members</th></tr>")
    for kind, row in rep["units_by_kind"].items():
        out.append(
            f"<tr><td>{e(kind)}</td><td>{row['units']}</td><td>{row['disposed']}</td>"
            f"<td>{row['members']}</td></tr>"
        )
    out.append("</table><h2>Must-read by reason</h2><table>")
    for reason, n in rep["must_read"]["by_reason"].items():
        out.append(f"<tr><td>{e(reason)}</td><td>{n}</td></tr>")
    out.append("</table><h2>Not seen by this view</h2>")
    out.append(f"<p><em>{e(_NOT_SEEN_NOTE)}</em></p><ul>")
    out += [f"<li>{e(x)}</li>" for x in rep["not_seen"]]
    out.append("</ul><h2>Units in hand-out order</h2>")
    for u in review.units:
        done = sum(1 for m in u.members if ru.disposed(states.get(m.anchor_ref)))
        cls = "done" if done == len(u.members) else "open"
        tag = "must-read" if u.must_read else "second tier"
        out.append(
            f"<h3 class='{cls}'><code>{e(u.unit_id)}</code> {e(u.kind)}, {tag}, round "
            f"{u.position}, {e(_short(u.stream))} ({done}/{len(u.members)} disposed)</h3>"
        )
        out.append("<table><tr><th>member</th><th>bucket</th><th>state</th><th>reasons</th></tr>")
        for m in u.members:
            out.append(
                f"<tr><td><code>{e(m.entry_id or m.anchor_ref)}</code></td>"
                f"<td>{e(m.bucket or '')}</td><td>{e(shown.get(m.anchor_ref, ''))}</td>"
                f"<td>{e(', '.join(m.reasons))}</td></tr>"
            )
        out.append("</table>")
    out.append("</body></html>")
    return "\n".join(out) + "\n"


# ── the findings handoff (Design B) ─────────────────────────────────────────────────────────────
# A standardized hand-off of a run pair's changed_real findings: one block per finding, the facts
# rendered by tmap, the analysis left to a person (hypotheses and device checks), the status always
# "awaiting human verification". tmap draws NO conclusion here — it emits facts and the recorded
# judgment, never a verdict about whether the change can be reached or what it could do, and never
# the word "blocked". The whole pair is far larger than one MCP response, so get_diff_handoff pages
# the blocks and the CLI `review report --handoff` writes them all to a file; the two are the same
# text byte for byte. The batch driver writes the same document with an agent's two texts filled in
# under each block's placeholders (handoff_document's ``analysis``).
#
# Every fact is read through the lib call its MCP tool makes (get_diff_patch_view, get_xrefs,
# get_file_diff, same_shape_siblings), so a cell states what that tool would answer.

# Neutral section titles (B-6): the analysis a person fills, never a verdict in a tmap string.
HANDOFF_HYPOTHESES_TITLE = "agent analysis — unverified hypotheses"
HANDOFF_DEVICE_TITLE = "to check on a device"
HANDOFF_STATUS = "awaiting human verification"
# The boundary (B-7) lives outside this neutral layer (it spells what NOT to write); imported, not
# spelled here, so the query layer stays neutral while the hand-off still carries it at runtime.
HANDOFF_BOUNDARY = _handoff_boundary.HANDOFF_BOUNDARY
# What an analysis section of the driver's document says when the agent wrote nothing for it.
HANDOFF_NOTHING_WRITTEN = "(the agent wrote nothing for this finding)"
# A block's ceiling, in the bytes of its JSON string form (the measure of the MCP page contract).
# A longer block is cut here, where it is rendered, so the CLI file and the MCP pages carry the
# same cut; the placeholders and the status are never cut.
HANDOFF_BLOCK_CAP = 30_000
# How much of a file's line difference a block shows (JSON-encoded bytes of the shown lines); the
# rest is named by its get_file_diff call.
HANDOFF_FILE_HUNK_BYTES = 6_000
# How many caller names, and how many hunk-shape segments, a cell lists.
HANDOFF_LIST_ITEMS = 10
# The structural labels of a block, scanned for neutrality: they carry no verdict word. The embedded
# verdict / change_kind / rationale / pseudocode are the agent's or the firmware's, not scanned.
_HANDOFF_LABELS: tuple[str, ...] = (
    "subject",
    "recorded verdict",
    "recorded change kind",
    "recorded rationale",
    "basis",
    "change (tmap facts)",
    "change (tmap facts, proposed pairing — alignment undetermined)",
    "substitution group",
    "reachable shape (tmap facts)",
    "sink class",
    "candidate rows",
    "one-level callers",
    "same-shape unchanged siblings (tmap facts)",
    "file difference (tmap facts)",
    "file hunk (tmap facts)",
    "whole-binary presence (tmap facts)",
    HANDOFF_HYPOTHESES_TITLE,
    HANDOFF_DEVICE_TITLE,
    "status",
)
_CHANGE = "change (tmap facts)"
_CHANGE_PROPOSED = "change (tmap facts, proposed pairing — alignment undetermined)"
_SHAPE = "reachable shape (tmap facts)"
_SIBLINGS = "same-shape unchanged siblings (tmap facts)"
_FILE = "file difference (tmap facts)"
_FILE_HUNK = "file hunk (tmap facts)"
_FENCE = "```"


@dataclass(frozen=True)
class HandoffStamp:
    """The staleness context same_shape_siblings needs (its ``build_hash`` / ``current`` /
    ``commit``). The MCP tool and the CLI build it the same way (CLI uses installed_commit() for
    the same ``commit``), so a block reads the same either side — B-4(d)."""

    build_hash: str | None
    current: Any
    commit: str


def local_handoff_context(
    atlas: Any, config: Any = None
) -> tuple[HandoffStamp, Callable[[str, str], dict[str, Any]]]:
    """The staleness context and the file judgements' ``file_staleness`` reading for a caller with
    no MCP server of its own (the command line, the batch driver): the values the server builds
    (the running code stamp, installed_commit, each run's stale-run reading), so the CLI file and
    the server's pages are one text."""
    from treasure_map.lib import rescan_version
    from treasure_map.lib.analyze.ghidra_runner import current_pass_version
    from treasure_map.lib.config.config import load_config
    from treasure_map.version import installed_commit

    cfg = config if config is not None else load_config(None)
    stamp = HandoffStamp(
        build_hash=current_pass_version(),
        current=rescan_version.current_code_stamp(cfg),
        commit=installed_commit(),
    )
    read: dict[tuple[str, str], dict[str, Any]] = {}

    def file_staleness(run_a: str, run_b: str) -> dict[str, Any]:
        if (run_a, run_b) not in read:
            read[(run_a, run_b)] = ru.pair_staleness(atlas, run_a, run_b, cfg)
        return read[(run_a, run_b)]

    return stamp, file_staleness


def _cell(label: str, value: str) -> str:
    """One fact line; ``value`` is never blank (an unavailable fact states its reason)."""
    return f"- {label}: {value}"


def _unavailable(reason: str) -> str:
    return f"unavailable ({reason})"


def _json_len(text: str) -> int:
    """The bytes ``text`` takes inside a JSON string (json.dumps' default form, no quotes)."""
    return len(json.dumps(text)) - 2


def _val(value: Any) -> str:
    return "null" if value is None else str(value)


def _short_error(text: Any, limit: int = 300) -> str:
    s = str(text)
    return s if len(s) <= limit else f"{s[:limit]}… ({len(s)} chars)"


# ── the function shapes ─────────────────────────────────────────────────────────────────────────


def _view_entry(atlas: Any, diff_id: str, anchor_ref: str) -> tuple[dict[str, Any] | None, str]:
    """The finding's entry as get_diff_patch_view(diff_id, entry_id=anchor_ref) gives it, or
    (None, why not)."""
    from treasure_map.lib.query import patch_view as _pv

    try:
        page = _pv.get_diff_patch_view(atlas, diff_id, entry_id=anchor_ref)
    except Exception as exc:  # noqa: BLE001 — a fact that cannot be read is stated, not raised
        return None, f"view error: {type(exc).__name__}"
    if page.get("error"):
        return None, f"view: {_short_error(page['error'])}"
    entries = page.get("entries") or []
    if not entries:
        return None, "entry not in the view"
    return entries[0], ""


def _hunk_lines(label: str, delta: dict[str, Any]) -> list[str]:
    """A pseudocode delta's inline hunk, shown as the view gives it: the structural runs (original
    text, ``-`` / ``+`` / `` `` / ``=`` prefixed) and the substitution groups — or why there is none
    (withheld over the gate, or a delta with nothing to show)."""
    hunk = delta.get("inline_hunk")
    if not isinstance(hunk, dict):
        kind = delta.get("kind") or "unknown kind"
        return [_cell(label, _unavailable(f"the pseudocode delta ({kind}) carries no inline hunk"))]
    if hunk.get("withheld"):
        return [
            _cell(
                label,
                _unavailable(
                    f"inline hunk withheld: {hunk['withheld']}, "
                    f"{_val(hunk.get('structural_lines'))} structural line(s), "
                    f"{_val(hunk.get('groups'))} substitution group(s); read it with "
                    f"{_val(hunk.get('read_with'))}"
                ),
            )
        ]
    out = [f"- {label}:"]
    runs = [r for r in hunk.get("structural") or [] if r]
    if runs:
        out.append(_FENCE)
        for k, run in enumerate(runs):
            if k:
                out.append("…")
            out += [str(x) for x in run]
        out.append(_FENCE)
    for g in hunk.get("substitution_groups") or []:
        step = f" step {g['step']}" if "step" in g else ""
        first = "; ".join(
            f"{_val(p[0])} → {_val(p[1])} (line {_val(p[2])} / {_val(p[3])})"
            for p in g.get("first") or []
            if isinstance(p, list | tuple) and len(p) == 4
        )
        out.append(
            f"  - substitution group: {_val(g.get('kind'))}{step}, {_val(g.get('total'))} "
            f"time(s): {first or 'none shown'}"
        )
    if len(out) == 1:
        return [_cell(label, _unavailable("the inline hunk shows no line"))]
    return out


def _change_lines(entry: dict[str, Any]) -> list[str]:
    """The change: the entry's pseudocode delta, else — an undetermined pair — the delta read as
    if paired (proposed_pair_reading), titled so; else why there is none."""
    delta = entry.get("pseudocode_delta")
    if isinstance(delta, dict):
        return _hunk_lines(_CHANGE, delta)
    proposed = entry.get("proposed_pair_reading")
    if isinstance(proposed, dict):
        pdelta = proposed.get("pseudocode_delta")
        if isinstance(pdelta, dict):
            return _hunk_lines(_CHANGE_PROPOSED, pdelta)
        why = f"no pseudocode delta; the proposed pairing reads {proposed.get('state')}"
        return [_cell(_CHANGE_PROPOSED, _unavailable(why))]
    state = entry.get("pseudocode_sameness")
    why = f"no pseudocode delta; the pair reads {state}" if state else "no pseudocode delta"
    return [_cell(_CHANGE, _unavailable(why))]


def _axis_text(axes: Any, axis: str, fields: tuple[str, ...]) -> str:
    """One axis of a row's sink_axes, per side the row has: the fields' values, or the reason the
    view gives for not giving the axis."""
    if not isinstance(axes, dict):
        return "not given (no sink_axes on the row)"
    parts: list[str] = []
    for side in ("a", "b"):
        sa = axes.get(side)
        if not isinstance(sa, dict):
            continue
        value = sa.get(axis)
        if isinstance(value, dict):
            parts.append(f"{side} {','.join(_val(value.get(f)) for f in fields)}")
            continue
        why = next(
            (r for r, names in (sa.get("unavailable") or {}).items() if axis in (names or [])),
            "not in the row's axes",
        )
        parts.append(f"{side} not given ({why})")
    return "; ".join(parts) if parts else "not given (neither side has axes)"


def _row_line(i: int, v: dict[str, Any]) -> str:
    axes = v.get("sink_axes")
    return (
        f"  - row {i}: a_ref {_val(v.get('a_ref'))} · b_ref {_val(v.get('b_ref'))} · sink_class "
        f"{_val(v.get('sink_class'))} · landing {_val(v.get('landing'))} · size_kind,size_arg "
        f"{_axis_text(axes, 'bound', ('size_kind', 'size_arg'))} · source_kind "
        f"{_axis_text(axes, 'source', ('source_kind',))}"
    )


def _row_sink_classes(v: dict[str, Any]) -> list[str]:
    return [str(v[k]) for k in ("sink_class", "class_a", "class_b") if v.get(k)]


def _shape_lines(diff_id: str, entry: dict[str, Any]) -> list[str]:
    """The reachable shape the entry's candidate rows give: how many are shown of how many (and the
    call that reads the rest), their sink classes, and one line per row."""
    rows = entry.get("rows") or []
    total = entry.get("rows_total")
    total = len(rows) if not isinstance(total, int) else total
    if total == 0:
        return [
            _cell(_SHAPE, "the entry has no candidate row"),
            _cell("sink class", _unavailable("the entry has no candidate row")),
        ]
    head = f"rows shown {len(rows)} of {total}"
    if len(rows) < total:
        head += (
            f' — rest: get_diff_patch_view(diff_id="{diff_id}", '
            f'entry_id="{entry.get("anchor_ref")}", rows_offset={len(rows)})'
        )
    classes = sorted({c for v in rows for c in _row_sink_classes(v)})
    of = f" (of the {len(rows)} rows shown)" if len(rows) < total else ""
    out = [
        _cell(_SHAPE, head),
        _cell("sink class", (", ".join(classes) + of) if classes else _unavailable("no class")),
        "- candidate rows:",
    ]
    out += [_row_line(i, v) for i, v in enumerate(rows, 1)]
    return out


def _diff_side(atlas: Any, diff_id: str, side: str) -> tuple[str, str] | None:
    """(run id, binary selector) of one side of a diff — the binary by its content hash when the
    diff records one, else its path, else its short name."""
    row = atlas.execute(
        "SELECT run_a_id, run_b_id, sha256_a, sha256_b, binary_path_a, binary_path_b, binary_a, "
        "binary_b FROM diff_meta WHERE diff_id = ?",
        (diff_id,),
    ).fetchone()
    if row is None:
        return None
    k = 0 if side == "a" else 1
    run, sha, path, name = row[k], row[2 + k], row[4 + k], row[6 + k]
    return str(run), str(sha or path or name or "")


def _callers_cell(atlas: Any, diff_id: str, side: str, addr: Any) -> str:
    """One-level callers of the finding's function on ``side``, as get_xrefs(direction="callers")
    reads them from that side's run's analysis.db: a count, the first names and its note. A
    function the run cannot resolve is stated, never read as 'no caller'."""
    from treasure_map.lib import facts as _facts
    from treasure_map.lib.query.runs import get_run

    if not addr:
        return _unavailable("no function address on the entry")
    where = _diff_side(atlas, diff_id, side)
    if where is None:
        return _unavailable(f"no diff {diff_id!r}")
    run_id, binary = where
    run = get_run(atlas, run_id)
    if run is None or not run.analysis_db_path:
        return _unavailable(f"run {run_id!r} records no analysis.db")
    if not Path(run.analysis_db_path).is_file():
        return _unavailable(f"the analysis.db of run {run_id!r} is not at its recorded path")
    try:
        conn = _facts.open_analysis_ro(run.analysis_db_path)
        try:
            xr = _facts.get_xrefs(conn, func=str(addr), direction="callers", binary=binary or None)
        finally:
            conn.close()
    except Exception as exc:  # noqa: BLE001
        return _unavailable(f"xref error: {type(exc).__name__}")
    if not xr.get("found"):
        why = "ambiguous" if xr.get("reason") == "ambiguous" else "no such function"
        return _unavailable(f"function not resolved: {addr} on side {side}, {why}")
    edges = xr.get("edges") or []
    names = []
    for e in edges:
        a = e.get("anchor") or {}
        name = a.get("function") or a.get("address") or a.get("binary")
        names.append(f"{_val(name)} (library-level)" if e.get("library_level") else _val(name))
    body = f"{len(edges)} caller(s) on side {side}"
    if names:
        body += ": " + ", ".join(names[:HANDOFF_LIST_ITEMS])
        if len(names) > HANDOFF_LIST_ITEMS:
            body += f" (+{len(names) - HANDOFF_LIST_ITEMS} more: get_xrefs)"
    note = xr.get("note")
    return f"{body} — {note}" if note else body


def _siblings_lines(
    atlas: Any, diff_id: str, rows: list[dict[str, Any]], stamp: HandoffStamp | None
) -> list[str]:
    """The same-shape groups of the rows shown, one line per group (its size and by-landing counts,
    and which rows fall in it); the member lists stay in same_shape_siblings' own pages (B-1). A row
    whose group cannot be read states why."""
    from treasure_map.lib.query import same_shape_siblings as _sss

    if stamp is None:
        return [_cell(_SIBLINGS, _unavailable("staleness context not provided"))]
    if not rows:
        return [_cell(_SIBLINGS, _unavailable("entry has no candidate row to key a shape"))]
    groups: dict[str, tuple[Any, Any, list[int]]] = {}
    other: dict[str, list[int]] = {}
    read: dict[str, dict[str, Any]] = {}
    for i, v in enumerate(rows, 1):
        ref = v.get("b_ref") or v.get("a_ref")
        if not ref:
            other.setdefault(_unavailable("the row names no candidate"), []).append(i)
            continue
        if ref not in read:
            try:
                read[ref] = _sss.same_shape_siblings(
                    atlas,
                    diff_id,
                    evidence_ref=str(ref),
                    build_hash=stamp.build_hash,
                    current=stamp.current,
                    commit=stamp.commit,
                )
            except Exception as exc:  # noqa: BLE001
                read[ref] = {"error": f"siblings error: {type(exc).__name__}"}
        res = read[ref]
        if res.get("error"):
            other.setdefault(_unavailable(_short_error(res["error"])), []).append(i)
        elif res.get("not_a_member") is not None or res.get("group_ref") is None:
            other.setdefault("no same-shape group for this candidate", []).append(i)
        else:
            n = res.get("member_count")
            groups.setdefault(str(res["group_ref"]), (n, res.get("by_landing"), []))[2].append(i)
    out = [_cell(_SIBLINGS, f"{len(groups)} group(s) over the {len(rows)} row(s) shown")]
    for gref, (n, landing, idx) in groups.items():
        out.append(
            f"  - group `{gref}`: {_val(n)} member(s), by landing "
            f"{json.dumps(landing, sort_keys=True)} — row(s) {', '.join(map(str, idx))}"
        )
    for what, idx in other.items():
        out.append(f"  - row(s) {', '.join(map(str, idx))}: {what}")
    return out


def _handoff_function_facts(
    atlas: Any, diff_id: str, anchor_ref: str, stamp: HandoffStamp | None, *, paired: bool
) -> list[str]:
    """A function's facts — a pair's or a single side's: the change, the reachable shape (the
    candidate rows, their sink classes, size / source kind), the one-level callers and the
    same-shape siblings. Each cell stated; an unavailable one with its reason, never blank."""
    entry, why = _view_entry(atlas, diff_id, anchor_ref)
    if entry is None:
        return [
            _cell(_CHANGE, _unavailable(why)),
            _cell(_SHAPE, _unavailable(why)),
            _cell(_SIBLINGS, _unavailable(why)),
        ]
    if paired:
        out = _change_lines(entry)
        side, addr = "b", entry.get("addr_b") or entry.get("addr_a")
        if not entry.get("addr_b"):
            side = "a"
    else:
        side, addr = str(entry.get("side") or ""), entry.get("addr")
        out = [
            _cell(
                _CHANGE,
                f"function on side {side} only ({_val(entry.get('presence_state'))}): no "
                "counterpart pseudocode to compare",
            )
        ]
    out += _shape_lines(diff_id, entry)
    out.append(_cell("one-level callers", _callers_cell(atlas, diff_id, side, addr)))
    out += _siblings_lines(atlas, diff_id, entry.get("rows") or [], stamp)
    return out


# ── the file and whole-binary shapes ──────────────────────────────────────────────────────────


def _handoff_file_facts(atlas: Any, run_a: str, run_b: str, path: str) -> list[str]:
    """A non-binary file's difference as get_file_diff(run_pair, path=…) gives it: its change,
    kind, hunk stats and structured counts, then the first page of its line difference — or, when
    file_diff holds the text back (sensitive), only its shape. Values are masked by file_diff
    itself; nothing here reads a file. Sink and sibling cells do not apply to a file."""
    from treasure_map.lib.query import file_diff as _fd

    tail = [
        _cell(_SHAPE, "not applicable (file)"),
        _cell(_SIBLINGS, "not applicable (file)"),
    ]
    pair = f"{run_a}::{run_b}"
    try:
        pf = _fd.read_pair(atlas, run_a, run_b)
        summary = _fd.file_diff(atlas, run_a, run_b, path=path, detail="summary", pf=pf).get(
            "entry"
        )
        full = _fd.file_diff(atlas, run_a, run_b, path=path, hunk_offset=0, pf=pf).get("entry")
    except Exception as exc:  # noqa: BLE001
        return [_cell(_FILE, _unavailable(f"file_diff: {_short_error(exc)}")), *tail]
    if not isinstance(summary, dict) or not isinstance(full, dict):
        return [_cell(_FILE, _unavailable("file_diff gave no entry for the path")), *tail]
    kind = full.get("kind") or f"{_val(full.get('kind_a'))} → {_val(full.get('kind_b'))}"
    parts = [f"change {_val(full.get('change'))}", f"kind {kind}"]
    if isinstance(summary.get("hunk_stats"), dict):
        parts.append(f"hunk stats {json.dumps(summary['hunk_stats'], sort_keys=True)}")
    if summary.get("hunk_unavailable"):
        parts.append(_unavailable(f"no line difference: {summary['hunk_unavailable']}"))
    counts = summary.get("structured_counts")
    if counts:
        parts.append(f"structured counts {json.dumps(counts, sort_keys=True)}")
    out = [_cell(_FILE, ", ".join(parts))]
    shape, hunk = full.get("hunk_shape"), full.get("hunk")
    more = f'get_file_diff(run_pair="{pair}", path="{path}", hunk_offset='
    if isinstance(shape, dict):
        segments = shape.get("segments") or []
        out.append(
            _cell(
                _FILE_HUNK,
                f"hunk held back (sensitive: {_val(full.get('hunk_suppressed'))}): shape only, "
                f"{_val(shape.get('total_segments'))} segment(s)",
            )
        )
        out += [
            f"  - {_val(s.get('range'))}: +{_val(s.get('plus_lines'))} / "
            f"-{_val(s.get('minus_lines'))}"
            for s in segments[:HANDOFF_LIST_ITEMS]
        ]
        total = shape.get("total_segments")
        if isinstance(total, int) and total > min(len(segments), HANDOFF_LIST_ITEMS):
            shown = min(len(segments), HANDOFF_LIST_ITEMS)
            out.append(f"  - segments shown {shown} of {total} — rest: {more}{shown})")
    elif isinstance(hunk, dict):
        lines = [str(x) for x in hunk.get("lines") or []]
        kept: list[str] = []
        size = 0
        for x in lines:
            cost = _json_len(x + "\n")
            if kept and size + cost > HANDOFF_FILE_HUNK_BYTES:
                break
            kept.append(x)
            size += cost
        out += [f"- {_FILE_HUNK}:", _FENCE, *kept, _FENCE]
        total = hunk.get("total_pieces")
        total = len(lines) if not isinstance(total, int) else total
        if len(kept) < total:
            out.append(f"  - hunk shown {len(kept)} of {total} piece(s) — rest: {more}{len(kept)})")
    return out + tail


def _handoff_binary_facts(side_path: str) -> list[str]:
    """A binary present in one run of the pair only: a whole-binary add or remove, so the function
    facts do not apply."""
    return [
        _cell("whole-binary presence (tmap facts)", f"present on one side only: {side_path}"),
        _cell(_CHANGE, "not applicable (whole-binary add / remove)"),
        _cell(_SHAPE, "not applicable (whole-binary add / remove)"),
        _cell(_SIBLINGS, "not applicable (whole-binary add / remove)"),
    ]


def _finding_change_kind(finding: dict[str, Any]) -> str:
    basis = finding.get("verdict_basis") or {}
    ck = basis.get("change_kind") if isinstance(basis, dict) else None
    if isinstance(ck, list) and ck:
        return ", ".join(str(x) for x in ck)
    if isinstance(ck, str) and ck:
        return ck
    return "not named"


def _finding_basis_line(finding: dict[str, Any]) -> str:
    """Whether the facts the judgment rests on still hold — a moved basis is marked, not dropped,
    and never read as the current conclusion (B-4). The reason is the basis state when the basis
    itself moved, else why the source reads stale (the diff's or the runs')."""
    state = finding.get("review_state")
    if state == "concluded":
        return "current"
    moved = finding.get("basis_moved") or {}
    basis = finding.get("basis_state")
    if basis and basis != "unchanged":
        reason = str(basis)
    else:
        reason = str(finding.get("source_stale_reason") or state or "moved")
    extra = f" — {json.dumps(moved, sort_keys=True, default=str)}" if moved else ""
    return f"MOVED since the judgment ({reason}){extra}; re-read before relying on it"


def _read_more(kind: str, run_pair: str, diff_id: Any, anchor: str) -> str:
    """The call that reads a block's whole facts, named in a cut block's note."""
    if kind in ("function_pair", "function_presence") and isinstance(diff_id, str):
        return f'get_diff_patch_view(diff_id="{diff_id}", entry_id="{anchor}")'
    if kind == "non_binary" and "#non_binary#" in anchor:
        return f'get_file_diff(run_pair="{run_pair}", path="{anchor.split("#non_binary#", 1)[1]}")'
    return f'list_overlays(anchor_kind="diff_subject", run_id="{run_pair}")'


def _cap_lines(lines: list[str], room: int, more: str) -> list[str]:
    """``lines`` within ``room`` bytes (JSON string form, each line with its newline): whole lines
    kept in order, an open code fence closed, and a note naming what was cut and where to read it.
    Unchanged when they fit."""
    total = sum(_json_len(x + "\n") for x in lines)
    if total <= room:
        return lines
    note_room = 400 + _json_len(more)
    kept: list[str] = []
    size = 0
    for x in lines:
        cost = _json_len(x + "\n")
        if size + cost > room - note_room:
            break
        kept.append(x)
        size += cost
    if sum(1 for x in kept if x == _FENCE) % 2:
        kept.append(_FENCE)
    left = total - sum(_json_len(x + "\n") for x in kept)
    kept.append(f"- [block cut to fit a page: {left} more bytes of facts; read them with {more}]")
    return kept


def _analysis_lines(text: str | None) -> list[str]:
    """A filled analysis section's body (the driver's document): the agent's text, or the line
    saying it wrote nothing; the skeleton (None) has no body."""
    if text is None:
        return []
    body = text.strip()
    return [body or HANDOFF_NOTHING_WRITTEN, ""]


def handoff_chunk(
    atlas: Any,
    run_pair: str,
    finding: dict[str, Any],
    *,
    stamp: HandoffStamp | None = None,
    analysis: dict[str, str] | None = None,
    cap: int | None = None,
) -> str:
    """One finding's hand-off block (Design B): the recorded judgment, the tmap facts for its
    subject shape, the two analysis placeholders a person fills, and the standing status. The block
    is self-contained text; the same text is served by get_diff_handoff and written by
    `review report --handoff`. ``stamp`` is the staleness context for same_shape_siblings; the MCP
    tool and the CLI pass the same one so the block reads identically either side.

    ``cap`` (default HANDOFF_BLOCK_CAP, JSON-string bytes) cuts the judgment and facts part, with a
    note naming the call that reads the rest; the placeholders and the status are never cut.
    ``analysis`` (the driver's document) fills the two placeholders with an agent's
    ``hypotheses`` / ``device_checks`` — a missing or blank one says the agent wrote nothing; the
    skeleton (None) leaves them for a person."""
    from treasure_map.lib.query import file_diff as _fd

    anchor = str(finding["anchor_ref"])
    kind = finding.get("subject_kind") or ""
    diff_id = finding.get("diff_id")
    lines = [
        f"## `{anchor}`",
        "",
        _cell("subject", kind or "unknown"),
        _cell("recorded verdict", str(finding.get("verdict") or "")),
        _cell("recorded change kind", _finding_change_kind(finding)),
        _cell("recorded rationale", str(finding.get("rationale") or "(none recorded)")),
        _cell("basis", _finding_basis_line(finding)),
        "",
    ]
    if kind in ("function_pair", "function_presence") and isinstance(diff_id, str):
        lines += _handoff_function_facts(
            atlas, diff_id, anchor, stamp, paired=kind == "function_pair"
        )
    elif kind == "non_binary":
        runs = _fd.split_run_pair(atlas, run_pair)
        path = anchor.split("#non_binary#", 1)[1] if "#non_binary#" in anchor else ""
        if runs is None or not path:
            lines.append(_cell(_FILE, _unavailable("cannot resolve the file")))
            lines.append(_cell(_SHAPE, "not applicable (file)"))
            lines.append(_cell(_SIBLINGS, "not applicable (file)"))
        else:
            lines += _handoff_file_facts(atlas, runs[0], runs[1], path)
    elif kind == "binary_presence":
        side = anchor.split("#binary_presence#", 1)[1] if "#binary_presence#" in anchor else anchor
        lines += _handoff_binary_facts(side)
    else:
        why = f"unknown subject kind {kind!r}" if kind else "no diff for this finding"
        lines.append(_cell(_CHANGE, _unavailable(why)))
        lines.append(_cell(_SHAPE, _unavailable(why)))
        lines.append(_cell(_SIBLINGS, _unavailable(why)))
    filled = analysis is not None
    tail = [
        "",
        f"### {HANDOFF_HYPOTHESES_TITLE}",
        f"_{HANDOFF_BOUNDARY}_",
        "",
        *_analysis_lines((analysis or {}).get("hypotheses", "") if filled else None),
        f"### {HANDOFF_DEVICE_TITLE}",
        f"_{HANDOFF_BOUNDARY}_",
        "",
        *_analysis_lines((analysis or {}).get("device_checks", "") if filled else None),
        _cell("status", HANDOFF_STATUS),
        "",
    ]
    room = (HANDOFF_BLOCK_CAP if cap is None else cap) - sum(_json_len(x + "\n") for x in tail)
    lines = _cap_lines(lines, room, _read_more(kind, run_pair, diff_id, anchor))
    return "\n".join(lines + tail) + "\n"


def handoff_findings(
    atlas: Any,
    run_pair: str,
    *,
    file_staleness: Callable[[str, str], dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """The pair's changed_real findings, ordered by anchor_ref (a stable paging order), each with
    its review_state and basis as list_overlays reads them (B-1 / B-4). Only this pair's judgements
    are read and only their diffs' views built — no review_progress. ``file_staleness`` is the
    caller's reading of the two runs for the file and binary_presence judgements (the MCP server's
    stale-run gate, or local_handoff_context's); without it they read needs_recheck."""
    from treasure_map.lib.query import diff_annotations as da

    res = da.list_diff_overlays(
        atlas,
        verdict="changed_real",
        run_id=run_pair,
        progress=False,
        file_staleness=file_staleness,
    )
    rows = [r for r in res.get("overlays", []) if r.get("run_id") == run_pair]
    rows.sort(key=lambda r: str(r["anchor_ref"]))
    return rows


def handoff_header(run_pair: str, n_findings: int) -> str:
    """The document's header line, served as its own first page by get_diff_handoff so the CLI file
    and the MCP pages are the same text."""
    return (
        f"# Findings hand-off for {run_pair}\n\n"
        f"_{n_findings} changed_real finding(s). Each block carries tmap's facts and the "
        f"recorded judgment; the analysis is for a person to fill. {HANDOFF_BOUNDARY}_\n\n"
    )


def handoff_blocks(
    atlas: Any,
    run_pair: str,
    findings: list[dict[str, Any]],
    *,
    stamp: HandoffStamp | None = None,
    analysis: dict[str, dict[str, str]] | None = None,
) -> list[str]:
    """One block per finding, in the findings' order. ``analysis`` maps an anchor_ref to the agent's
    two texts (the driver's document); with it, a finding the map does not name says the agent
    wrote nothing for it."""
    return [
        handoff_chunk(
            atlas,
            run_pair,
            f,
            stamp=stamp,
            analysis=None if analysis is None else analysis.get(str(f["anchor_ref"]), {}),
        )
        for f in findings
    ]


def handoff_document(
    atlas: Any,
    run_pair: str,
    *,
    stamp: HandoffStamp | None = None,
    file_staleness: Callable[[str, str], dict[str, Any]] | None = None,
    analysis: dict[str, dict[str, str]] | None = None,
) -> str:
    """The whole findings hand-off as one markdown document — the header then every block in anchor
    order. The concatenation of get_diff_handoff's pages is this same text (B-4); with
    ``analysis`` it is the driver's document, the agent's texts under each block's placeholders."""
    findings = handoff_findings(atlas, run_pair, file_staleness=file_staleness)
    return handoff_header(run_pair, len(findings)) + "".join(
        handoff_blocks(atlas, run_pair, findings, stamp=stamp, analysis=analysis)
    )
