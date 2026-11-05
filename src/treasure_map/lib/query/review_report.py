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
import re
from dataclasses import dataclass
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
# the blocks and the CLI
# `review report --handoff` writes them all to a file; the two are the same text byte for byte.

# Neutral section titles (B-6): the analysis a person fills, never a verdict in a tmap string.
HANDOFF_HYPOTHESES_TITLE = "agent analysis — unverified hypotheses"
HANDOFF_DEVICE_TITLE = "to check on a device"
HANDOFF_STATUS = "awaiting human verification"
# The boundary (B-7) lives outside this neutral layer (it spells what NOT to write); imported, not
# spelled here, so the query layer stays neutral while the hand-off still carries it at runtime.
HANDOFF_BOUNDARY = _handoff_boundary.HANDOFF_BOUNDARY
# The structural labels of a block, scanned for neutrality: they carry no verdict word. The embedded
# verdict / change_kind / rationale / pseudocode are the agent's or the firmware's, not scanned.
_HANDOFF_LABELS: tuple[str, ...] = (
    "subject",
    "recorded verdict",
    "recorded change kind",
    "recorded rationale",
    "basis",
    "change (tmap facts)",
    "reachable shape (tmap facts)",
    "sink class",
    "size / source kind",
    "one-level callers",
    "same-shape unchanged siblings (tmap facts)",
    "file difference (tmap facts)",
    "whole-binary presence (tmap facts)",
    HANDOFF_HYPOTHESES_TITLE,
    HANDOFF_DEVICE_TITLE,
    "status",
)


@dataclass(frozen=True)
class HandoffStamp:
    """The staleness context same_shape_siblings needs (its ``build_hash`` / ``current`` /
    ``commit``). The MCP tool and the CLI build it the same way (CLI uses installed_commit() for
    the same ``commit``), so a block reads the same either side — B-4(d)."""

    build_hash: str | None
    current: Any
    commit: str


def _cell(label: str, value: str) -> str:
    """One fact line; ``value`` is never blank (an unavailable fact states its reason)."""
    return f"- {label}: {value}"


def _unavailable(reason: str) -> str:
    return f"unavailable ({reason})"


def _handoff_pair_facts(
    atlas: Any, run_a: str, run_b: str, diff_id: str, anchor_ref: str, stamp: HandoffStamp | None
) -> list[str]:
    """The function-pair facts: the change (inline hunk), the reachable shape (sink class, size /
    source kind, one-level callers), and the same-shape unchanged siblings — each cell stated, an
    unavailable one with its reason, never blank."""
    from treasure_map.lib import facts as _facts
    from treasure_map.lib.query import patch_view as _pv

    out: list[str] = []
    entry: dict[str, Any] | None = None
    try:
        page = _pv.get_diff_patch_view(atlas, diff_id, entry_id=anchor_ref)
        entries = page.get("entries") or []
        entry = entries[0] if entries else None
    except Exception as exc:  # noqa: BLE001 — a fact that cannot be read is stated, not raised
        out.append(_cell("change (tmap facts)", _unavailable(f"view error: {type(exc).__name__}")))
    if entry is None:
        if not out:
            out.append(_cell("change (tmap facts)", _unavailable("entry not in the view")))
        out.append(_cell("reachable shape (tmap facts)", _unavailable("entry not in the view")))
        out.append(_cell("same-shape unchanged siblings (tmap facts)", _unavailable("no entry")))
        return out
    delta = entry.get("pseudocode_delta") or {}
    hunk = delta.get("inline_hunk")
    if hunk:
        text = hunk if isinstance(hunk, str) else "\n".join(str(x) for x in hunk)
        out.append("- change (tmap facts):")
        out.append("```")
        out.append(text.rstrip("\n"))
        out.append("```")
    else:
        out.append(_cell("change (tmap facts)", _unavailable("no inline hunk for this entry")))
    rows = entry.get("rows") or []
    classes = sorted({c for v in rows for c in _row_sink_classes(v)})
    out.append(
        _cell("sink class", ", ".join(classes) if classes else _unavailable("no candidate row"))
    )
    out.append(_cell("size / source kind", _axes_summary(rows)))
    out.append(_cell("one-level callers", _callers_summary(_facts, atlas, entry)))
    out.append(
        _cell(
            "same-shape unchanged siblings (tmap facts)",
            _siblings_summary(atlas, run_a, run_b, diff_id, rows, stamp),
        )
    )
    return out


def _row_sink_classes(v: dict[str, Any]) -> list[str]:
    return [str(v[k]) for k in ("sink_class", "class_a", "class_b") if v.get(k)]


def _axes_summary(rows: list[dict[str, Any]]) -> str:
    """The reachable shape the rows' sink axes carry: for each side present, its sink class and the
    axes (bound, source, sanitizer, flow path, def-use) that have evidence versus are unavailable —
    an unread axis is stated, never read as absent."""
    parts: list[str] = []
    for v in rows:
        axes = v.get("sink_axes")
        if not isinstance(axes, dict):
            continue
        for side in ("a", "b"):
            sa = axes.get(side)
            if not isinstance(sa, dict):
                continue
            cls = sa.get("class") or "unknown"
            missing = sorted((sa.get("unavailable") or {}).get("no_evidence") or [])
            have = sorted(k for k, val in sa.items() if k not in ("class", "unavailable") and val)
            desc = f"class {cls}"
            if have:
                desc += f", evidence for {', '.join(have)}"
            if missing:
                desc += f", no evidence for {', '.join(missing)}"
            parts.append(f"{side}: {desc}")
    return "; ".join(parts) if parts else _unavailable("no sink axes on the rows")


def _callers_summary(facts_mod: Any, atlas: Any, entry: dict[str, Any]) -> str:
    """One-level callers of the changed function (the B side when paired), as a count and a few
    names; an unresolved caller set is stated, never read as 'none'."""
    addr = entry.get("addr_b") or entry.get("addr_a") or entry.get("addr")
    if not addr:
        return _unavailable("no function address on the entry")
    try:
        xr = facts_mod.get_xrefs(atlas, func=str(addr), direction="callers")
    except Exception as exc:  # noqa: BLE001
        return _unavailable(f"xref error: {type(exc).__name__}")
    if xr.get("error"):
        return _unavailable(str(xr.get("error")))
    edges = xr.get("callers") or xr.get("edges") or []
    names = [str(e.get("name") or e.get("func") or e.get("addr")) for e in edges][:5]
    note = xr.get("note")
    body = f"{len(edges)} caller(s)" + (f": {', '.join(names)}" if names else "")
    return f"{body} — {note}" if note else body


def _siblings_summary(
    atlas: Any,
    run_a: str,
    run_b: str,
    diff_id: str,
    rows: list[dict[str, Any]],
    stamp: HandoffStamp | None,
) -> str:
    """The same-shape unchanged siblings of the entry's first candidate — its group size and the
    by-landing counts only; the member list stays in same_shape_siblings' own pages (B-1). The call
    is keyed on a candidate anchor built from the row; a missing staleness context or candidate is
    stated, not left blank."""
    from treasure_map.lib.query import same_shape_siblings as _sss

    if stamp is None:
        return _unavailable("staleness context not provided")
    # Key the shape on the row's own candidate reference (its evidence_ref), the changed B side
    # first; same_shape_siblings resolves it to the group.
    ref = next(
        (v.get("b_ref") or v.get("a_ref") for v in rows if v.get("b_ref") or v.get("a_ref")), None
    )
    if not ref:
        return _unavailable("entry has no candidate row to key a shape")
    try:
        res = _sss.same_shape_siblings(
            atlas,
            diff_id,
            evidence_ref=str(ref),
            build_hash=stamp.build_hash,
            current=stamp.current,
            commit=stamp.commit,
        )
    except Exception as exc:  # noqa: BLE001
        return _unavailable(f"siblings error: {type(exc).__name__}")
    if res.get("error"):
        return _unavailable(str(res.get("error")))
    if res.get("not_a_member") is not None or res.get("group_ref") is None:
        return "no same-shape group for this candidate"
    counts = res.get("by_landing") or {}
    n = res.get("member_count")
    if n is None:
        n = res.get("members_total") or res.get("members")
    return f"group `{res.get('group_ref')}`: {n} member(s), by landing {counts}"


def _handoff_presence_facts(entry_available: bool) -> list[str]:
    """A function present on one side only: there is no paired delta to show."""
    return [
        _cell("change (tmap facts)", "single side — no paired delta"),
        _cell("reachable shape (tmap facts)", "single side — no paired delta"),
        _cell(
            "same-shape unchanged siblings (tmap facts)", "not applicable (single-side function)"
        ),
    ]


def _handoff_file_facts(atlas: Any, run_a: str, run_b: str, path: str) -> list[str]:
    """A non-binary file's difference: its structured change, with sensitive values masked by
    file_diff itself. Sink and sibling cells do not apply to a file."""
    from treasure_map.lib.query import file_diff as _fd

    out: list[str] = []
    try:
        res = _fd.file_diff(atlas, run_a, run_b, path=path, detail="summary")
    except Exception as exc:  # noqa: BLE001
        out.append(
            _cell("file difference (tmap facts)", _unavailable(f"file_diff: {type(exc).__name__}"))
        )
        out.append(_cell("reachable shape (tmap facts)", "not applicable (file)"))
        out.append(_cell("same-shape unchanged siblings (tmap facts)", "not applicable (file)"))
        return out
    files = res.get("files") or ([res] if res.get("path") else [])
    if not files:
        out.append(
            _cell("file difference (tmap facts)", _unavailable("file not in the pair's diff"))
        )
    else:
        f = files[0]
        change = f.get("change") or f.get("status") or "changed"
        kind = f.get("kind") or "file"
        hunks = f.get("hunk_stats") or f.get("hunks") or {}
        out.append(_cell("file difference (tmap facts)", f"{change} {kind}; hunk stats {hunks}"))
    out.append(_cell("reachable shape (tmap facts)", "not applicable (file)"))
    out.append(_cell("same-shape unchanged siblings (tmap facts)", "not applicable (file)"))
    return out


def _handoff_binary_facts(side_path: str) -> list[str]:
    """A binary present in one run of the pair only: a whole-binary add or remove, so the function
    facts do not apply."""
    return [
        _cell("whole-binary presence (tmap facts)", f"present on one side only: {side_path}"),
        _cell("change (tmap facts)", "not applicable (whole-binary add / remove)"),
        _cell("reachable shape (tmap facts)", "not applicable (whole-binary add / remove)"),
        _cell(
            "same-shape unchanged siblings (tmap facts)",
            "not applicable (whole-binary add / remove)",
        ),
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
    and never read as the current conclusion (B-4)."""
    state = finding.get("review_state")
    if state == "concluded":
        return "current"
    moved = finding.get("basis_moved") or {}
    reason = finding.get("basis_state") or state or "moved"
    extra = f" — {moved}" if moved else ""
    return f"MOVED since the judgment ({reason}){extra}; re-read before relying on it"


def handoff_chunk(
    atlas: Any, run_pair: str, finding: dict[str, Any], *, stamp: HandoffStamp | None = None
) -> str:
    """One finding's hand-off block (Design B): the recorded judgment, the tmap facts for its
    subject shape, the two analysis placeholders a person fills, and the standing status. The block
    is self-contained text; the same text is served by get_diff_handoff and written by
    `review report --handoff`. ``stamp`` is the staleness context for same_shape_siblings; the MCP
    tool and the CLI pass the same one so the block reads identically either side."""
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
    if kind == "function_pair" and isinstance(diff_id, str):
        runs = _fd.split_run_pair(atlas, run_pair)
        ra, rb = runs if runs is not None else (run_pair, run_pair)
        lines += _handoff_pair_facts(atlas, ra, rb, diff_id, anchor, stamp)
    elif kind == "function_presence":
        lines += _handoff_presence_facts(isinstance(diff_id, str))
    elif kind == "non_binary":
        runs = _fd.split_run_pair(atlas, run_pair)
        path = anchor.split("#non_binary#", 1)[1] if "#non_binary#" in anchor else ""
        if runs is None or not path:
            lines.append(
                _cell("file difference (tmap facts)", _unavailable("cannot resolve the file"))
            )
            lines.append(_cell("reachable shape (tmap facts)", "not applicable (file)"))
            lines.append(
                _cell("same-shape unchanged siblings (tmap facts)", "not applicable (file)")
            )
        else:
            lines += _handoff_file_facts(atlas, runs[0], runs[1], path)
    elif kind == "binary_presence":
        side = anchor.split("#binary_presence#", 1)[1] if "#binary_presence#" in anchor else anchor
        lines += _handoff_binary_facts(side)
    else:
        lines.append(_cell("change (tmap facts)", _unavailable(f"unknown subject kind {kind!r}")))
        lines.append(_cell("reachable shape (tmap facts)", _unavailable("unknown subject kind")))
        lines.append(
            _cell(
                "same-shape unchanged siblings (tmap facts)", _unavailable("unknown subject kind")
            )
        )
    lines += [
        "",
        f"### {HANDOFF_HYPOTHESES_TITLE}",
        f"_{HANDOFF_BOUNDARY}_",
        "",
        f"### {HANDOFF_DEVICE_TITLE}",
        f"_{HANDOFF_BOUNDARY}_",
        "",
        _cell("status", HANDOFF_STATUS),
        "",
    ]
    return "\n".join(lines) + "\n"


def handoff_findings(atlas: Any, run_pair: str) -> list[dict[str, Any]]:
    """The pair's changed_real findings, ordered by anchor_ref (a stable paging order). Read from
    list_diff_overlays WITHOUT a run_id, so the expensive whole-pair review_progress is not built;
    each row already carries its review_state and basis (B-1 / B-4)."""
    from treasure_map.lib.query import diff_annotations as da

    res = da.list_diff_overlays(atlas, verdict="changed_real")
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


def handoff_document(atlas: Any, run_pair: str, *, stamp: HandoffStamp | None = None) -> str:
    """The whole findings hand-off as one markdown document — the header then every block in anchor
    order. The concatenation of get_diff_handoff's pages is this same text (B-4)."""
    findings = handoff_findings(atlas, run_pair)
    return handoff_header(run_pair, len(findings)) + "".join(
        handoff_chunk(atlas, run_pair, f, stamp=stamp) for f in findings
    )
