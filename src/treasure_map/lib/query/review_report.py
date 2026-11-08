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
from typing import TYPE_CHECKING, Any

from treasure_map.lib import handoff_boundary as _handoff_boundary
from treasure_map.lib.query import diff_review as dr
from treasure_map.lib.query import dispatch_groups as dg
from treasure_map.lib.query import review_navigation as _rn
from treasure_map.lib.query import review_units as ru
from treasure_map.lib.query import upstream_version as uv

if TYPE_CHECKING:
    from treasure_map.lib.query.same_shape_siblings import SameShapeReads

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


def _counts(by: dict[str, int]) -> str:
    return ", ".join(f"{k} {v}" for k, v in sorted(by.items())) or "none"


def _keys(keys: list[str]) -> str:
    return ", ".join(f"`{_md_cell(k)}`" for k in keys) or "—"


def _side(value: Any) -> str:
    return f"`{_md_cell(value)}`" if value is not None else "null"


def _dispatch_md(review: ru.PairReview) -> list[str]:
    """The full dispatch-group table (every group, every member with its keys per side) — the
    report file's face of review_navigation; the MCP answer carries its counts and member labels."""
    nav = review.navigation
    block = review.report.get("dispatch_groups")
    if nav is None or not isinstance(block, dict):
        return []
    out = ["", "## Dispatch groups", ""]
    if "unreadable" in block or nav.dispatch is None:
        return [*out, f"- unreadable: `{_md_cell(block.get('unreadable'))}`"]
    unc, det = block["uncovered"], block["static_table_detector"]
    out += [
        f"_{_md_cell(_rn.DISPATCH_NOTES['mechanism'])}_",
        "",
        f"- grouped must-read entries: {block['grouped_members']} ({block['grouped_pct']}%), "
        f"also in a callee group: {block['also_in_callee_group']}",
        f"- uncovered: {unc['count']} — {_md_cell(_rn.DISPATCH_NOTES['uncovered'])}",
        f"  - side a: {_md_cell(_counts(unc['by_static_table_detector'].get('a') or {}))}",
        f"  - side b: {_md_cell(_counts(unc['by_static_table_detector'].get('b') or {}))}",
        f"- static-table detector supported_scope: "
        f"{_keys(det['supported_scope'])}; unsupported: {_keys(det['unsupported_note'])}",
        f"- {_md_cell(_rn.DISPATCH_NOTES['static_table_detector'])}",
        f"- {_md_cell(_rn.DISPATCH_NOTES['counterpart'])}",
    ]
    for g in nav.dispatch.groups:
        j = dg.group_json(g)
        where = j.get("table") or j.get("dispatch_function") or {}
        out += [
            "",
            f"### `{_md_cell(j['group_ref'])}`",
            "",
            f"{j['mechanism']} ({_md_cell(j['note'])}), `{_md_cell(j['binary'])}`, "
            f"{j['member_count']} member(s); a {_side(where.get('a'))}, b {_side(where.get('b'))}",
        ]
        if j.get("counterpart_enumerates") is False:
            out.append(
                f"- counterpart_enumerates: false; counterpart {_side(j.get('counterpart'))}"
            )
        if "completeness" in j:
            c = j["completeness"]
            out.append(
                f"- completeness: {_keys(c['reasons'])}; split_by_undefined_handler: "
                f"{str(c['split_by_undefined_handler']).lower()}"
            )
        out += ["", "| entry | keys (a) | keys (b) |", "|---|---|---|"]
        for m in j["members"]:
            keys = m["keys"]
            out.append(f"| `{_md_cell(m['entry_id'])}` | {_keys(keys['a'])} | {_keys(keys['b'])} |")
    return out


def _upstream_md(review: ru.PairReview) -> list[str]:
    """Every upstream library group, each diff with the versions its two sides state."""
    nav = review.navigation
    block = review.report.get("upstream_groups")
    if nav is None or not isinstance(block, dict):
        return []
    out = ["", "## Upstream library groups", ""]
    if "unreadable" in block:
        return [*out, f"- unreadable: `{_md_cell(block['unreadable'])}`"]
    out += [f"_{_md_cell(_rn.UPSTREAM_NOTES['groups'])}_", ""]
    if not nav.upstream_rows:
        return [*out, "- none"]
    out += ["| library | diffs | units | must-read units | open units |", "|---|---|---|---|---|"]
    for r in nav.upstream_rows:
        out.append(
            f"| {_md_cell(r['library'])} | {r['diffs']} | {r['units']} | {r['must_read_units']} | "
            f"{r['open_units']} |"
        )
    for r in nav.upstream_rows:
        out += ["", f"- {_md_cell(r['library'])}:"]
        for did in r["diff_ids"]:
            lab = uv.label(nav.upstream.get(did)) or {}
            out.append(f"  - `{_md_cell(did)}`: a `{lab.get('a')}`, b `{lab.get('b')}`")
    return out


def _navigation_md(review: ru.PairReview) -> list[str]:
    return _dispatch_md(review) + _upstream_md(review)


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
    jnl = rep.get("judged_not_listed") or {}
    if jnl.get("count"):
        by = ", ".join(f"{v} {n}" for v, n in jnl["by_verdict"].items())
        out += ["", "## Judgements whose subject is no longer listed", "", f"_{jnl['means']}_", ""]
        out.append(
            f"- {jnl['count']} ({_md_cell(by)}); changed_real {jnl['changed_real']['count']}"
        )
        out += [f"  - changed_real: `{_md_cell(a)}`" for a in jnl["changed_real"]["anchors"]]
        apart = set(jnl["changed_real"]["anchors"])
        rest = [a for a in jnl["anchors"] if a not in apart]
        out += [f"  - `{_md_cell(a)}`" for a in rest]
        listed = len(apart) + len(rest)  # what the lines above name, each anchor once
        if jnl["count"] > listed:
            out.append(f"  - … {jnl['count'] - listed} more")
    out += _navigation_md(review)
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


def _navigation_html(review: ru.PairReview) -> list[str]:
    """The dispatch-group and upstream-group tables of the markdown report, as HTML (escaped)."""
    e = html.escape
    nav = review.navigation
    if nav is None:
        return []
    out: list[str] = []
    block = review.report.get("dispatch_groups")
    if isinstance(block, dict):
        out.append("<h2>Dispatch groups</h2>")
        if "unreadable" in block or nav.dispatch is None:
            out.append(f"<p>unreadable: <code>{e(str(block.get('unreadable')))}</code></p>")
        else:
            unc, det = block["uncovered"], block["static_table_detector"]
            by = unc["by_static_table_detector"]
            out += [
                f"<p><em>{e(_rn.DISPATCH_NOTES['mechanism'])}</em></p><ul>",
                f"<li>grouped must-read entries: {block['grouped_members']} "
                f"({block['grouped_pct']}%), also in a callee group: "
                f"{block['also_in_callee_group']}</li>",
                f"<li>uncovered: {unc['count']} — {e(_rn.DISPATCH_NOTES['uncovered'])}; side a: "
                f"{e(_counts(by.get('a') or {}))}; side b: {e(_counts(by.get('b') or {}))}</li>",
                f"<li>static-table detector supported_scope: "
                f"{e(', '.join(det['supported_scope']) or '—')}; unsupported: "
                f"{e(', '.join(det['unsupported_note']) or '—')}</li>",
                f"<li>{e(_rn.DISPATCH_NOTES['static_table_detector'])}</li>"
                f"<li>{e(_rn.DISPATCH_NOTES['counterpart'])}</li></ul>",
            ]
            for g in nav.dispatch.groups:
                j = dg.group_json(g)
                where = j.get("table") or j.get("dispatch_function") or {}
                facts = f"a {where.get('a')}, b {where.get('b')}"
                if j.get("counterpart_enumerates") is False:
                    facts += f"; counterpart_enumerates false, counterpart {j.get('counterpart')}"
                if "completeness" in j:
                    c = j["completeness"]
                    facts += (
                        f"; completeness {', '.join(c['reasons'])}, split_by_undefined_handler "
                        f"{str(c['split_by_undefined_handler']).lower()}"
                    )
                out.append(
                    f"<h3><code>{e(j['group_ref'])}</code></h3><p>{e(j['mechanism'])} "
                    f"({e(j['note'])}), <code>{e(str(j['binary']))}</code>, "
                    f"{j['member_count']} member(s); {e(facts)}</p>"
                )
                out.append("<table><tr><th>entry</th><th>keys (a)</th><th>keys (b)</th></tr>")
                for m in j["members"]:
                    out.append(
                        f"<tr><td><code>{e(m['entry_id'])}</code></td>"
                        f"<td>{e(', '.join(m['keys']['a']) or '—')}</td>"
                        f"<td>{e(', '.join(m['keys']['b']) or '—')}</td></tr>"
                    )
                out.append("</table>")
    ublock = review.report.get("upstream_groups")
    if isinstance(ublock, dict):
        out.append("<h2>Upstream library groups</h2>")
        if "unreadable" in ublock:
            out.append(f"<p>unreadable: <code>{e(str(ublock['unreadable']))}</code></p>")
            return out
        out.append(f"<p><em>{e(_rn.UPSTREAM_NOTES['groups'])}</em></p>")
        out.append(
            "<table><tr><th>library</th><th>diff</th><th>a</th><th>b</th><th>units</th>"
            "<th>must-read units</th><th>open units</th></tr>"
        )
        for r in nav.upstream_rows:
            for i, did in enumerate(r["diff_ids"]):
                lab = uv.label(nav.upstream.get(did)) or {}
                tail = (
                    f"<td>{r['units']}</td><td>{r['must_read_units']}</td><td>{r['open_units']}</td>"
                    if i == 0
                    else "<td></td><td></td><td></td>"
                )
                out.append(
                    f"<tr><td>{e(r['library'] if i == 0 else '')}</td><td><code>{e(did)}</code>"
                    f"</td><td>{e(str(lab.get('a')))}</td><td>{e(str(lab.get('b')))}</td>{tail}</tr>"
                )
        out.append("</table>")
    return out


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
    out.append("</ul>")
    out += _navigation_html(review)
    out.append("<h2>Units in hand-out order</h2>")
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
#
# Text tmap did not write never reads as one of a block's own lines: a multi-line text (a rationale,
# an agent's text, a hunk) is fenced, and a firmware value on one of the block's own lines (a size
# expression, a caller's name, a path) is inline code with its line breaks escaped.

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


_BACKTICKS = re.compile(r"`+")
# What a markdown reader can take as a line break: the C0 controls, NEL and the two Unicode
# separators. A value tmap did not write, put on one of the block's own lines, has them escaped
# (``\xNN`` / ``\uNNNN``), so it cannot start a line of its own (a status, a heading).
_LINE_BREAKERS = re.compile("[\x00-\x1f\x85\u2028\u2029]")


def _escape_controls(text: str) -> str:
    """``text`` with every line-breaking character (_LINE_BREAKERS) escaped."""

    def esc(m: re.Match[str]) -> str:
        c = ord(m.group())
        return f"\\x{c:02x}" if c < 0x100 else f"\\u{c:04x}"

    return _LINE_BREAKERS.sub(esc, text)


def _inline(value: Any) -> str:
    """A firmware value (a name, a path, an expression) written inside one of the block's own
    lines: a code span — a backtick run longer than any the value holds, so no backtick in it can
    close the span, and no markup in it (HTML, emphasis) is read as markup — with its line-breaking
    characters escaped."""
    text = _escape_controls(str(value))
    if not text:
        return "` `"
    ticks = "`" * (max((len(m) for m in _BACKTICKS.findall(text)), default=0) + 1)
    # A span whose text starts or ends with a backtick or a space is padded with one space each
    # side; a markdown reader strips exactly that padding, so the value reads as it is.
    pad = " " if text[0] in "` " or text[-1] in "` " else ""
    return f"{ticks}{pad}{text}{pad}{ticks}"


def handoff_anchor_text(anchor: str) -> str:
    """A finding's anchor_ref as its block's heading writes it (inside ``## `...` ``): line-breaking
    characters escaped, nothing else changed — the text an agent copies back to name the block."""
    return _escape_controls(anchor)


def _fenced(lines: list[str]) -> list[str]:
    """``lines`` inside a code fence longer than any backtick run they hold (three at least), so no
    line of embedded text — a rationale, an agent's text, firmware text — can close it and be read
    as one of the block's own lines (a status, a basis, a heading)."""
    longest = max((len(m) for x in lines for m in _BACKTICKS.findall(x)), default=0)
    fence = "`" * max(len(_FENCE), longest + 1)
    return [fence, *lines, fence]


def _is_fence(line: str) -> bool:
    return len(line) >= len(_FENCE) and line == "`" * len(line)


def _open_fence(lines: list[str]) -> str | None:
    """The fence ``lines`` leave open (as _fenced writes them: a line of backticks only, closed by
    one at least as long), or None."""
    open_: str | None = None
    for x in lines:
        if not _is_fence(x):
            continue
        if open_ is None:
            open_ = x
        elif len(x) >= len(open_):
            open_ = None
    return open_


def _embedded(label: str, text: str) -> list[str]:
    """A cell whose value is text tmap did not write (a recorded rationale): the label, then the
    text fenced, line by line as it was written."""
    return [f"- {label}:", *_fenced(text.splitlines() or [""])]


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
        shown: list[str] = []
        for k, run in enumerate(runs):
            if k:
                shown.append("…")
            shown += [str(x) for x in run]
        out += _fenced(shown)
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


# The sink-axis fields whose value is firmware text (an expression or a name from the code), written
# inline as code; the other fields are tmap's own kinds.
_FIRMWARE_AXIS_FIELDS = frozenset({"size_arg", "size_var"})


def _axis_value(value: dict[str, Any], name: str) -> str:
    v = value.get(name)
    return _inline(v) if v is not None and name in _FIRMWARE_AXIS_FIELDS else _val(v)


def _axis_text(axes: Any, axis: str, fields: tuple[str, ...]) -> str:
    """One axis of a row's sink_axes, per side the row has: the fields' values (a firmware one
    inline as code), or the reason the view gives for not giving the axis."""
    if not isinstance(axes, dict):
        return "not given (no sink_axes on the row)"
    parts: list[str] = []
    for side in ("a", "b"):
        sa = axes.get(side)
        if not isinstance(sa, dict):
            continue
        value = sa.get(axis)
        if isinstance(value, dict):
            parts.append(f"{side} {','.join(_axis_value(value, f) for f in fields)}")
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
    """One-level callers of the finding's function on ``side``, as the get_xrefs tool
    (direction="callers") reads them from that side's run's analysis.db — through the same lib call,
    entry_words.xrefs_with_entry_words, so a function with no caller carries the tool's note on the
    data words holding its entry value: a count, the first names and that note, verbatim. A function
    the run cannot resolve is stated, never read as 'no caller'."""
    from treasure_map.lib import facts as _facts
    from treasure_map.lib.query import entry_words as _entry_words
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
            xr = _entry_words.xrefs_with_entry_words(
                conn, func=str(addr), direction="callers", binary=binary or None
            )
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
        shown = _val(name) if name is None else _inline(name)
        names.append(f"{shown} (library-level)" if e.get("library_level") else shown)
    body = f"{len(edges)} caller(s) on side {side}"
    if names:
        body += ": " + ", ".join(names[:HANDOFF_LIST_ITEMS])
        if len(names) > HANDOFF_LIST_ITEMS:
            body += f" (+{len(names) - HANDOFF_LIST_ITEMS} more: get_xrefs)"
    note = xr.get("note")
    return f"{body} — {note}" if note else body


def _siblings_lines(
    atlas: Any,
    diff_id: str,
    rows: list[dict[str, Any]],
    stamp: HandoffStamp | None,
    reads: SameShapeReads | None = None,
) -> list[str]:
    """The same-shape groups of the rows shown, one line per group (its size and by-landing counts,
    and which rows fall in it); the member lists stay in same_shape_siblings' own pages (B-1). A row
    whose group cannot be read states why. ``reads`` (same_shape_siblings.SameShapeReads) is the
    hand-off pass's holder: each diff's view is built once for all its rows, not once per row."""
    from treasure_map.lib.query import same_shape_siblings as _sss

    reads = _sss.SameShapeReads() if reads is None else reads

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
                    reads=reads,
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
    atlas: Any,
    diff_id: str,
    anchor_ref: str,
    stamp: HandoffStamp | None,
    *,
    paired: bool,
    reads: SameShapeReads | None = None,
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
    out += _siblings_lines(atlas, diff_id, entry.get("rows") or [], stamp, reads)
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

    def more(offset: int) -> str:
        return _inline(f'get_file_diff(run_pair="{pair}", path="{path}", hunk_offset={offset})')

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
            out.append(f"  - segments shown {shown} of {total} — rest: {more(shown)}")
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
        out += [f"- {_FILE_HUNK}:", *_fenced(kept)]
        total = hunk.get("total_pieces")
        total = len(lines) if not isinstance(total, int) else total
        if len(kept) < total:
            out.append(f"  - hunk shown {len(kept)} of {total} piece(s) — rest: {more(len(kept))}")
    return out + tail


def _handoff_binary_facts(side_path: str, addr: str | None = None) -> list[str]:
    """A binary present in one run of the pair only, or one function of it (``addr``): a
    whole-binary add or remove, so the function-pair facts do not apply."""
    where = f"present on one side only: {_inline(side_path)}"
    if addr is not None:
        where = f"function {_inline(addr)} of one-sided binary {_inline(side_path)} ({where})"
    return [
        _cell("whole-binary presence (tmap facts)", where),
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
    and never read as the current conclusion (B-4). The reason names a subject no longer listed,
    or one that no longer resolves (the judgement is dangling), apart; else it is the basis state
    when the basis itself moved, else why the source reads stale (the diff's or the runs')."""
    state = finding.get("review_state")
    if state == "concluded":
        return "current"
    moved = finding.get("basis_moved") or {}
    basis = finding.get("basis_state")
    if state == "subject_unlisted":
        reason = "subject_unlisted — no longer listed (now read identical)"
    elif basis == "anchor_unresolved":
        reason = "anchor_unresolved — the subject no longer resolves (pairing moved?)"
    elif basis and basis != "unchanged":
        reason = str(basis)
    else:
        reason = str(finding.get("source_stale_reason") or state or "moved")
    extra = f" — {json.dumps(moved, sort_keys=True, default=str)}" if moved else ""
    return f"MOVED since the judgment ({reason}){extra}; re-read before relying on it"


def _read_more(kind: str, run_pair: str, diff_id: Any, anchor: str) -> str:
    """The call that reads a block's whole facts, named in a cut block's note — inline as code, as
    it carries firmware text (a path, a binary name)."""
    if kind in ("function_pair", "function_presence") and isinstance(diff_id, str):
        return _inline(f'get_diff_patch_view(diff_id="{diff_id}", entry_id="{anchor}")')
    if kind == "non_binary" and "#non_binary#" in anchor:
        path = anchor.split("#non_binary#", 1)[1]
        return _inline(f'get_file_diff(run_pair="{run_pair}", path="{path}")')
    return _inline(f'list_overlays(anchor_kind="diff_subject", run_id="{run_pair}")')


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
    left_open = _open_fence(kept)
    if left_open is not None:
        kept.append(left_open)
    left = total - sum(_json_len(x + "\n") for x in kept)
    kept.append(f"- [block cut to fit a page: {left} more bytes of facts; read them with {more}]")
    return kept


def _analysis_lines(text: str | None) -> list[str]:
    """A filled analysis section's body (the driver's document): the agent's text, fenced so none
    of its lines reads as one of the block's own (a status, a heading), or the line saying it wrote
    nothing; the skeleton (None) has no body."""
    if text is None:
        return []
    body = text.strip()
    if not body:
        return [HANDOFF_NOTHING_WRITTEN, ""]
    return [*_fenced(body.splitlines()), ""]


def _handoff_tail(analysis: dict[str, str] | None) -> list[str]:
    """A block's two analysis sections and its status: the placeholders, filled with the agent's
    texts in the driver's document (``analysis``), left for a person in the skeleton (None)."""
    filled = analysis is not None
    return [
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


def handoff_chunk(
    atlas: Any,
    run_pair: str,
    finding: dict[str, Any],
    *,
    stamp: HandoffStamp | None = None,
    analysis: dict[str, str] | None = None,
    cap: int | None = None,
    reads: SameShapeReads | None = None,
) -> str:
    """One finding's hand-off block (Design B): the recorded judgment, the tmap facts for its
    subject shape, the two analysis placeholders a person fills, and the standing status. The block
    is self-contained text; the same text is served by get_diff_handoff and written by
    `review report --handoff`. ``stamp`` is the staleness context for same_shape_siblings; the MCP
    tool and the CLI pass the same one so the block reads identically either side.

    ``cap`` (default HANDOFF_BLOCK_CAP, JSON-string bytes) cuts the judgment and facts part, with a
    note naming the call that reads the rest; the placeholders and the status are never cut, and
    the basis line comes before the recorded rationale, so a long rationale never cuts it.
    ``analysis`` (the driver's document) fills the two placeholders with an agent's
    ``hypotheses`` / ``device_checks`` — a missing or blank one says the agent wrote nothing; the
    skeleton (None) leaves them for a person. The agent's texts do not count against ``cap``: the
    facts are cut where the skeleton cuts them, and the texts follow whole. Text tmap did not write
    (the rationale, the agent's texts) is fenced, and a firmware value on one of the block's own
    lines is inline code, so none of it can read as the block's own basis or status line; the
    heading's anchor_ref has its line breaks escaped (handoff_anchor_text).
    ``reads`` (same_shape_siblings.SameShapeReads) is the caller's holder for one pass over many
    blocks; handoff_blocks passes one."""
    from treasure_map.lib.query import file_diff as _fd

    anchor = str(finding["anchor_ref"])
    kind = finding.get("subject_kind") or ""
    diff_id = finding.get("diff_id")
    lines = [
        f"## `{handoff_anchor_text(anchor)}`",
        "",
        _cell("subject", kind or "unknown"),
        _cell("recorded verdict", str(finding.get("verdict") or "")),
        _cell("recorded change kind", _finding_change_kind(finding)),
        _cell("basis", _finding_basis_line(finding)),
    ]
    rationale = str(finding.get("rationale") or "")
    if rationale:
        lines += _embedded("recorded rationale", rationale)
    else:
        lines.append(_cell("recorded rationale", "(none recorded)"))
    lines.append("")
    if kind in ("function_pair", "function_presence") and isinstance(diff_id, str):
        lines += _handoff_function_facts(
            atlas, diff_id, anchor, stamp, paired=kind == "function_pair", reads=reads
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
        fn = dr.split_presence_function(anchor)
        base = fn[0] if fn is not None else anchor
        side = base.split("#binary_presence#", 1)[1] if "#binary_presence#" in base else base
        lines += _handoff_binary_facts(side, fn[1] if fn is not None else None)
    else:
        why = f"unknown subject kind {kind!r}" if kind else "no diff for this finding"
        lines.append(_cell(_CHANGE, _unavailable(why)))
        lines.append(_cell(_SHAPE, _unavailable(why)))
        lines.append(_cell(_SIBLINGS, _unavailable(why)))
    tail = _handoff_tail(analysis)
    # The room is the skeleton's: the agent's texts (the driver's document, written whole to a file,
    # never paged) do not count against the cap, so however long they are, the facts — the heading,
    # the subject, the basis — are cut exactly where the skeleton cuts them.
    skeleton_tail = tail if analysis is None else _handoff_tail(None)
    room = (HANDOFF_BLOCK_CAP if cap is None else cap) - sum(
        _json_len(x + "\n") for x in skeleton_tail
    )
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
    wrote nothing for it. The blocks are one pass: each diff's view (and each side's calls) that
    the same-shape cells read is built once for all of them, and dropped when the pass ends."""
    from treasure_map.lib.query import same_shape_siblings as _sss

    reads = _sss.SameShapeReads()
    return [
        handoff_chunk(
            atlas,
            run_pair,
            f,
            stamp=stamp,
            analysis=None if analysis is None else analysis.get(str(f["anchor_ref"]), {}),
            reads=reads,
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
