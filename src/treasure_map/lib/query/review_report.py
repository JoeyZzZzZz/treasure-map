# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The pair review's report in three faces — terminal summary, markdown, HTML — all rendered from
one reading (lib/query/review_units.PairReview), so they never part. The terminal summary's first
line is the ``coverage_statement``; markdown and HTML add every unit in the hand-out order, each
member with its review state and the reasons it is must-read.

A reading face only: nothing here writes. Every string taken from the firmware (binary names,
paths, entry ids) is escaped in the HTML, which carries no script.
"""

from __future__ import annotations

import html
from typing import Any

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


def markdown(review: ru.PairReview, *, header: dict[str, Any] | None = None) -> str:
    """The whole report as markdown: the summary, then every unit in the hand-out order."""
    rep = review.report
    states = review.progress.states
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
        out.append("")
        out.append("| member | bucket | state | reasons |")
        out.append("|---|---|---|---|")
        for m in u.members:
            out.append(
                f"| `{_md_cell(m.entry_id or m.anchor_ref)}` | {_md_cell(m.bucket or '')} | "
                f"{_md_cell(states.get(m.anchor_ref, ''))} | {_md_cell(', '.join(m.reasons))} |"
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
                f"<td>{e(m.bucket or '')}</td><td>{e(states.get(m.anchor_ref, ''))}</td>"
                f"<td>{e(', '.join(m.reasons))}</td></tr>"
            )
        out.append("</table>")
    out.append("</body></html>")
    return "\n".join(out) + "\n"
