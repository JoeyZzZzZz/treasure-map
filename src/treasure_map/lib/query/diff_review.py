# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Judgements on a diff's function-level view: how an entry is named, what a judgement on it rests
on, and how far through the view a reader is.

The diff-side counterpart of lib/query/coverage, over a different unit. get_diff_patch_view
(lib/query/patch_view) lists ENTRIES — a function pair, or a function with no counterpart — and an
entry is what gets judged and what progress is counted in. Its candidate rows can be judged too,
but they are not paged through: the view is read entry by entry, so that is what has to be covered.

The states are coverage's, derived the same way: nothing new is stored. A judgement exists for an
entry or it does not; its verdict is in the diff vocabulary or it has been retired; the facts it
was written on still hold or they have moved. Nothing here writes — the judgements themselves are
written by lib/overlay.py, the one place an overlay row is written.

ANCHORS. A judgement is keyed by an anchor that names its subject, not its position:

    {run_a}::{run_b}#function_pair#{binary}::{addr_a}::{addr_b}
    {run_a}::{run_b}#function_presence#{binary}::{side}:{addr}
    {run_a}::{run_b}#candidate#{subject_key}

``binary`` is the diff's short binary name (diff_meta.binary_a): two binaries of one run pair can
hold a function at the same address, and without it their entries would share one judgement. A
candidate's ``subject_key`` already names the evidence_ref of each side. Everything before the first
``#`` is the run pair, which is what the overlay's run_id column holds, so one run pair's
judgements are one exact-match filter. Keys are read from the right (``rsplit``), and a run pair is
only ever matched whole, never split.

THE BASIS is the entry's own diff facts at write time — for a pair its alignment state,
similarity, export gaps, bucket and the (a_ref, b_ref, presence, reason, counterpart call) of every
candidate row; for a function with no counterpart its presence state, export gap and bucket; for a
candidate row its presence, reason, counterpart call and where it lands. A later read re-derives
them: any that moved puts the judgement in ``needs_recheck``. An anchor whose subject is gone (the
diff paired the functions differently, or a candidate was re-keyed) is not a row state; it is
reported beside the counts as dangling.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from treasure_map.lib.overlay import _DIFF_VERDICTS
from treasure_map.lib.query.coverage import (
    CONCLUDED,
    DEFAULT_PAGE_SIZE,
    NEEDS_RECHECK,
    NEEDS_RELABEL,
    OPEN,
    UNSEEN,
)
from treasure_map.lib.query.sink_overlay import _subject_key

if TYPE_CHECKING:  # typing only — patch_view imports this module
    from treasure_map.lib.query.patch_view import _Entry

SUBJECT_KINDS = ("function_pair", "function_presence", "candidate")
STATES = (UNSEEN, OPEN, CONCLUDED, NEEDS_RELABEL, NEEDS_RECHECK)
BUCKET_ORDER = ("A", "B", "C", "R", "P", "E")

# The basis states a judgement on a diff entry can read with. Only ``unchanged`` leaves its review
# state to the verdict; ``anchor_unresolved`` is what dangling means.
UNCHANGED = "unchanged"
CHANGED = "changed"
ANCHOR_UNRESOLVED = "anchor_unresolved"
DIFF_WITHHELD = "diff_withheld"


# ── anchors ────────────────────────────────────────────────────────────────────────────────


def run_pair(run_a: str, run_b: str) -> str:
    return f"{run_a}::{run_b}"


def pair_anchor(run_a: str, run_b: str, binary: str, addr_a: str, addr_b: str) -> str:
    return f"{run_pair(run_a, run_b)}#function_pair#{binary}::{addr_a}::{addr_b}"


def presence_anchor(run_a: str, run_b: str, binary: str, side: str, addr: str) -> str:
    return f"{run_pair(run_a, run_b)}#function_presence#{binary}::{side}:{addr}"


def candidate_anchor(run_a: str, run_b: str, subject_key: str) -> str:
    return f"{run_pair(run_a, run_b)}#candidate#{subject_key}"


def entry_anchor(e: _Entry, run_a: str, run_b: str, binary: str) -> str:
    if e.pair is not None:
        return pair_anchor(run_a, run_b, binary, e.pair.addr_a, e.pair.addr_b)
    assert e.unpaired is not None
    return presence_anchor(run_a, run_b, binary, e.unpaired.side, e.unpaired.addr)


def split_anchor(anchor_ref: str, run_a: str, run_b: str) -> tuple[str, str] | None:
    """``(subject_kind, subject_key)`` of an anchor in this run pair, else None. The run pair is
    matched whole, as the anchor's prefix."""
    prefix = f"{run_pair(run_a, run_b)}#"
    if not anchor_ref.startswith(prefix):
        return None
    kind, sep, key = anchor_ref[len(prefix) :].partition("#")
    if not sep or kind not in SUBJECT_KINDS:
        return None
    return kind, key


def key_binary(kind: str, key: str) -> str | None:
    """The binary named by a function_pair / function_presence key, read from the right; None for
    a candidate key (it names the binary only through its refs) or a key of the wrong shape."""
    if kind == "function_pair":
        parts = key.rsplit("::", 2)
        return parts[0] if len(parts) == 3 else None
    if kind == "function_presence":
        parts = key.rsplit("::", 1)
        return parts[0] if len(parts) == 2 else None
    return None


# ── what a judgement rests on ───────────────────────────────────────────────────────────────


def entry_facts(e: _Entry) -> dict[str, Any]:
    """The facts a judgement on this entry rests on (see the module docstring), JSON-shaped."""
    if e.pair is not None:
        p = e.pair
        rows = sorted(
            ([r.a_ref, r.b_ref, r.presence, r.presence_reason, r.counterpart_call] for r in e.rows),
            key=json.dumps,
        )
        return {
            "alignment_state": p.state,
            "similarity": p.similarity,
            "export_gap_a": p.export_gap_a,
            "export_gap_b": p.export_gap_b,
            "bucket": e.bucket or None,
            "rows": rows,
        }
    assert e.unpaired is not None
    u = e.unpaired
    return {
        "presence_state": u.presence_state,
        "export_gap": u.export_gap,
        "bucket": e.bucket or None,
    }


def row_facts(view: dict[str, Any]) -> dict[str, Any]:
    """The facts a judgement on one candidate row rests on."""
    return {
        "presence": view["presence"],
        "presence_reason": view["presence_reason"],
        "counterpart_call": view["counterpart_call"],
        "landing": view["landing"],
    }


@dataclass(frozen=True)
class Subject:
    """One thing in a diff's current view that a judgement can be anchored on."""

    kind: str
    facts: dict[str, Any]
    entry: _Entry
    row_view: dict[str, Any] | None = None  # the row, for a candidate subject


def subjects_of(placed: list[_Entry], run_a: str, run_b: str, binary: str) -> dict[str, Subject]:
    """anchor -> subject, for every entry the view placed (listed or not) and every candidate row
    in them. Not-listed entries are included so that a judged entry whose pair has since become
    identical reads as moved, not as gone."""
    out: dict[str, Subject] = {}
    for e in placed:
        out[entry_anchor(e, run_a, run_b, binary)] = Subject(
            "function_pair" if e.pair is not None else "function_presence", entry_facts(e), e
        )
        for r, v in zip(e.rows, e.row_views, strict=True):
            out[candidate_anchor(run_a, run_b, _subject_key(r))] = Subject(
                "candidate", row_facts(v), e, v
            )
    return out


def snapshot(diff_id: str, subject: Subject) -> dict[str, Any]:
    """What is stored as a diff judgement's basis: the facts, plus the diff they were read from
    (identity, not a fact — it is what a candidate anchor, which names no binary, is found by)."""
    return {"diff_id": diff_id, "subject": subject.kind, "facts": _plain(subject.facts)}


def stored_snapshot(raw: str | None) -> dict[str, Any] | None:
    try:
        data = json.loads(raw) if raw else None
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def facts_delta(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """What moved between two fact sets, per field: ``[then, now]`` for a value, the rows added and
    removed for ``rows``. Empty when nothing moved."""
    old, new = _plain(old), _plain(new)
    moved: dict[str, Any] = {}
    for key in sorted(set(old) | set(new)):
        then, now = old.get(key), new.get(key)
        if then == now:
            continue
        if key == "rows" and isinstance(then, list) and isinstance(now, list):
            moved[key] = {
                "added": [r for r in now if r not in then],
                "removed": [r for r in then if r not in now],
            }
        else:
            moved[key] = [then, now]
    return moved


def _plain(value: Any) -> Any:
    """``value`` as it reads back from JSON, so a stored and a fresh fact set compare equal."""
    return json.loads(json.dumps(value))


# ── one judgement's state ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class DiffAnnotation:
    """One judgement on a diff entry or candidate row, with its basis re-derived now."""

    anchor_ref: str
    verdict: str
    basis_state: str  # unchanged | changed | anchor_unresolved | diff_withheld
    moved: dict[str, Any]
    source_stale: bool | None
    source_stale_reason: str | None

    @property
    def state(self) -> str:
        return review_state(self)


def review_state(a: DiffAnnotation | None) -> str:
    """The review state of one entry, in coverage's precedence: a retired verdict first, then any
    reason the judgement may no longer hold, then the verdict.

    A judgement can stop holding two ways, and either is ``needs_recheck``: the entry's own facts
    moved (or the diff is withheld, so they cannot be read), or the diff no longer describes the
    builds it was computed from — ``source_stale`` anything but false, so a diff that could not be
    checked is not taken as current."""
    if a is None:
        return UNSEEN
    if a.verdict not in _DIFF_VERDICTS:
        return NEEDS_RELABEL
    if a.basis_state != UNCHANGED or a.source_stale is not False:
        return NEEDS_RECHECK
    return OPEN if a.verdict == "change_inconclusive" else CONCLUDED


def judge(
    anchor_ref: str,
    verdict: str,
    stored: dict[str, Any] | None,
    current: Subject | None,
    *,
    withheld: bool,
    staleness: dict[str, Any],
    group_delta: dict[str, Any] | None = None,
) -> DiffAnnotation:
    """One judgement read against its diff's current view. ``group_delta`` is what the caller found
    moved in the same-shape group this judgement leaned on (S6, computed in the view read path
    where the diff is built), folded in under ``moved["group"]``: a group that moved re-checks the
    judgement exactly as a move in its own facts does."""
    moved: dict[str, Any] = {}
    if withheld:
        state = DIFF_WITHHELD
    elif current is None:
        state = ANCHOR_UNRESOLVED
    else:
        then = stored.get("facts") if stored is not None else None
        moved = facts_delta(then if isinstance(then, dict) else {}, current.facts)
        if group_delta is not None:
            moved["group"] = group_delta
        state = CHANGED if moved else UNCHANGED
    return DiffAnnotation(
        anchor_ref=anchor_ref,
        verdict=verdict,
        basis_state=state,
        moved=moved,
        source_stale=staleness.get("source_stale"),
        source_stale_reason=staleness.get("source_stale_reason"),
    )


def as_dicts(cur: sqlite3.Cursor) -> list[dict[str, Any]]:
    """A cursor's rows by column name, whatever row factory the connection was opened with."""
    names = [c[0] for c in cur.description]
    return [dict(zip(names, row, strict=True)) for row in cur.fetchall()]


def read_judgements(atlas: sqlite3.Connection, run_a: str, run_b: str) -> list[dict[str, Any]]:
    """Every judgement on a diff entry of one run pair (an exact match on the run_id column)."""
    return as_dicts(
        atlas.execute(
            "SELECT id, anchor_ref, run_id, verdict, rationale, attributed_to, basis_state, "
            "verdict_basis, updated_at FROM overlay "
            "WHERE anchor_kind = 'diff_subject' AND run_id = ? ORDER BY id",
            (run_pair(run_a, run_b),),
        )
    )


def belongs_to(
    anchor_ref: str,
    stored: dict[str, Any] | None,
    *,
    diff_id: str,
    run_a: str,
    run_b: str,
    binary: str | None,
) -> bool:
    """Is this judgement about this diff? A pair or a function names the diff's binary; a candidate
    names no binary, so it is found by the diff its snapshot was read from."""
    parts = split_anchor(anchor_ref, run_a, run_b)
    if parts is None:
        return False
    kind, key = parts
    if kind == "candidate":
        return stored is not None and stored.get("diff_id") == diff_id
    return binary is not None and key_binary(kind, key) == binary


def judgements_for(
    rows: list[dict[str, Any]],
    *,
    diff_id: str,
    run_a: str,
    run_b: str,
    binary: str | None,
    subjects: dict[str, Subject],
    withheld: bool,
    staleness: dict[str, Any],
    group_review: Callable[[dict[str, Any]], dict[str, Any] | None] | None = None,
) -> tuple[dict[str, DiffAnnotation], list[str]]:
    """The run pair's judgements that are about this diff, each read against its current view, and
    the anchors among them whose subject is gone (dangling). ``group_review`` (S6), when given, is
    asked to re-derive the same-shape group a judgement recorded (its stored ``group`` block) and
    say what moved; the caller owns it because rebuilding a group needs the atlas and the build."""
    judged: dict[str, DiffAnnotation] = {}
    for row in rows:
        anchor = row["anchor_ref"]
        stored = stored_snapshot(row["basis_state"])
        if not belongs_to(anchor, stored, diff_id=diff_id, run_a=run_a, run_b=run_b, binary=binary):
            continue
        group_delta = None
        if group_review is not None and not withheld and stored is not None and stored.get("group"):
            group_delta = group_review(stored["group"])
        judged[anchor] = judge(
            anchor,
            row["verdict"],
            stored,
            subjects.get(anchor),
            withheld=withheld,
            staleness=staleness,
            group_delta=group_delta,
        )
    dangling = sorted(a for a, j in judged.items() if j.basis_state == ANCHOR_UNRESOLVED)
    return judged, dangling


# ── band: the opt-in ordering by judgement ────────────────────────────────────────────────


def band_bias(state: str, verdict: str | None) -> int:
    """Where a judged entry sorts among the entries the base order already holds together (smaller
    first). Read from the judgement alone.

    Due a re-check first, whatever the verdict — its facts moved or its word was retired, and a
    settled-looking entry is exactly where that would go unseen. Then the ones looked at and left
    open, ahead of the ones nobody has looked at. ``no_real_change`` last."""
    if state in (NEEDS_RECHECK, NEEDS_RELABEL):
        return 0
    if state == OPEN:
        return 1
    if state == UNSEEN:
        return 2
    if verdict == "changed_real":
        return 3
    if verdict == "no_real_change":
        return 5
    return 4


# ── progress ──────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Item:
    """One listed entry, as progress counts it."""

    entry_id: str
    anchor_ref: str
    bucket: str
    subclass: str
    tier: int | str
    state: str
    verdict: str | None
    order: tuple[Any, ...]  # the view's default order; a run pair's items lead with the diff
    diff_id: str | None = None


@dataclass
class Tally:
    states: dict[str, int] = field(default_factory=lambda: dict.fromkeys(STATES, 0))
    by_bucket: dict[str, dict[str, int]] = field(
        default_factory=lambda: {b: dict.fromkeys(STATES, 0) for b in BUCKET_ORDER}
    )
    verdict_shape: dict[str, int] = field(default_factory=dict)

    def add(self, item: Item) -> None:
        self.states[item.state] = self.states.get(item.state, 0) + 1
        bucket = self.by_bucket.setdefault(item.bucket, dict.fromkeys(STATES, 0))
        bucket[item.state] = bucket.get(item.state, 0) + 1
        if item.verdict is not None:
            self.verdict_shape[item.verdict] = self.verdict_shape.get(item.verdict, 0) + 1


def _pages(n: int, page_size: int) -> int:
    return -(-n // page_size) if n > 0 else 0


def counts(items: list[Item], page_size: int = DEFAULT_PAGE_SIZE) -> dict[str, Any]:
    """The numbers of one scope: totals, pages, every state, the same per bucket, and the shape of
    the verdicts reached. Every listed entry is in exactly one state."""
    tally = Tally()
    for item in items:
        tally.add(item)
    unseen = tally.states[UNSEEN]
    return {
        "total": len(items),
        "looked_at": len(items) - unseen,
        "not_looked_at": unseen,
        "page_size": page_size,
        "pages_total": _pages(len(items), page_size),
        "pages_remaining": _pages(unseen, page_size),
        "states": tally.states,
        "by_bucket": tally.by_bucket,
        "verdict_shape": dict(sorted(tally.verdict_shape.items())),
    }


def next_page(items: list[Item], page_size: int = DEFAULT_PAGE_SIZE) -> list[dict[str, Any]]:
    """The first ``page_size`` entries nobody has judged, in the view's default order — named, so
    they can be opened from here."""
    unseen = sorted((i for i in items if i.state == UNSEEN), key=lambda i: i.order)
    out = []
    for i in unseen[:page_size]:
        row: dict[str, Any] = {
            "entry_id": i.entry_id,
            "anchor_ref": i.anchor_ref,
            "bucket": i.bucket,
            "subclass": i.subclass,
            "tier": i.tier,
        }
        if i.diff_id is not None:
            row = {"diff_id": i.diff_id, **row}
        out.append(row)
    return out


# The sentence of PROGRESS_NOTE that says what 'complete' means. get_diff_patch_view gives it alone
# on a page past the first, where the whole note (the state words defined) is not repeated.
PROGRESS_NOTE_COMPLETE = (
    "'complete' means no entry in THIS scope is unjudged — not that the diff, or the firmware, has "
    "been read: what the view cannot see is in blind_spots beside it, and a sink that never became "
    "a candidate is not in any entry."
)
PROGRESS_NOTE = (
    "Progress over the view's ENTRIES, per page, with the remainder stated every time. An entry "
    "counts as looked at once a judgement exists on its anchor (annotate_diff). "
    + PROGRESS_NOTE_COMPLETE
    + " 'needs_recheck' = the entry's facts moved since the judgement, or the diff "
    "is not current (source_stale not false), or the diff is withheld; 'needs_relabel' = the "
    "verdict word is retired. A judgement that cannot be settled is 'change_inconclusive': it "
    "stays in view."
)


# ── the annotation block: how to write one, said on the view itself ───────────────────────


def _call(name: str, **args: str) -> str:
    return f"{name}(" + ", ".join(f"{k}={v}" for k, v in args.items()) + ")"


def annotation_block(diff_id: str, run_a: str, run_b: str, items: list[Item]) -> dict[str, Any]:
    """How to judge this diff's entries, with this diff's own values filled in, and how many of
    each bucket have been judged beside the call that opens the rest. Present with no judgement
    at all — that is when it is needed most."""
    ordered = sorted(items, key=lambda i: i.order)
    first = next((i for i in ordered if i.state == UNSEEN), ordered[0] if ordered else None)
    anchor = json.dumps(first.anchor_ref) if first is not None else '"<an entry\'s anchor_ref>"'
    entry = json.dumps(first.entry_id) if first is not None else '"<an entry\'s entry_id>"'
    did = json.dumps(diff_id)
    by_bucket: dict[str, Any] = {}
    for bucket in BUCKET_ORDER:
        members = [i for i in items if i.bucket == bucket]
        if not members:
            continue
        unseen = sum(1 for i in members if i.state == UNSEEN)
        by_bucket[bucket] = {
            "seen": len(members) - unseen,
            "unseen": unseen,
            "next": _call("get_diff_patch_view", diff_id=did, bucket=json.dumps(bucket))
            if unseen
            else None,
        }
    return {
        "available": True,
        "what": (
            "A writable layer of YOUR judgements over this read-only view: one per entry "
            "(anchor_ref on every entry), or per candidate row. The view's facts never change "
            "because of it; with band=true it reorders entries only inside the groups the "
            "default order already forms."
        ),
        "annotate_diff": _call(
            "annotate_diff",
            diff_id=did,
            anchor_ref=anchor,
            verdict='"changed_real|no_real_change|change_inconclusive"',
            rationale='"..."',
        ),
        "no_real_change_needs": (
            'checked=["<a fact or anchor read>", "<another>"] and why_unchanged="..." — two or '
            "more of the first, and the second non-blank"
        ),
        "candidate_anchor": (
            f"{run_pair(run_a, run_b)}#candidate#<key_granularity>|<sink_class>|"
            "<a_ref or (none)>|<b_ref or (none)>"
        ),
        "promote": _call(
            "promote",
            diff_id=did,
            entry_id=entry,
            row_ref='"<the a_ref or b_ref of one of its rows>"',
            verdict='"<a candidate verdict>"',
            rationale='"..."',
        ),
        "promote_note": (
            "carries the judgement onto one candidate, as a candidate verdict. Only from a row "
            "that lands A or persisted, or P with subclass unmatched_analysis_complete, in an "
            "entry whose counterpart is determined, on a diff that is current (source_stale "
            "false)."
        ),
        "review_with": _call(
            "list_overlays",
            anchor_kind='"diff_subject"',
            run_id=json.dumps(run_pair(run_a, run_b)),
        ),
        "by_bucket": by_bucket,
    }


def annotation_unavailable(why: str, banners: list[str]) -> dict[str, Any]:
    """The annotation block of a diff that cannot be judged now: why, and no call to copy."""
    return {"available": False, "why": why, "banners": list(banners)}
