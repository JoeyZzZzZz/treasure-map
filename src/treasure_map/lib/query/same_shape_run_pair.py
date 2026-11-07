# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The calls of the same shape as one sink call, across every binary of a run pair's two runs.

READ-ONLY and DERIVED, like same_shape_siblings (whose one-diff group this widens): it writes
nothing and draws no conclusion. same_shape_siblings answers it when its ``diff_id`` names a run
pair (``{run_a}::{run_b}``) instead of one binary's diff.

THE SCOPE is every binary of the two runs, on both sides: side A's calls in run A, side B's in run
B, each side read from its own run's candidates as the one-diff group reads its side. A member in a
binary a diff of the pair covers carries that diff (``diffed`` true); a member in a binary no diff
of the pair covers carries ``diffed`` false, a null ``diff_id``, the binary's short name and
``not_diffed_reason`` (same_shape_siblings.NotDiffedBasis, the reason the one-diff group's
``binaries_not_diffed`` gives that binary), and is ordered like any other member. The input call is
looked up in the binary a diff of the pair covers on its side (the diff it is a candidate of is
echoed as ``input.diff_id``).

THE SHAPE KEY is the one-diff key, unchanged: ``same_shape_siblings.f2_key`` of the pattern's
structural fingerprint, the sink's name and the kind, computed by the same ``_call`` / ``_Call.key``
/ ``_groups`` the one-diff group uses. No finer key is used at this scope: a member's key here is
the key its own diff's group is built on, so each binary's count here is that binary's one-diff
group size.

THE ORDER is by literal strings shared with the input call's function (analysis.db ``string_refs``,
literals of at least ``MIN_LITERAL_LENGTH`` characters, compared by text): members whose function
references a literal the input's function references come first, the one whose rarest shared
literal is referenced by the fewest functions of its own run first, then the one sharing more of
them; then the members whose literals could not be read (``?`` never sinks below a known none); then
the members sharing none. Ties, and each tier, follow the diffed members by diff then side, then
the members no diff covers by binary name, side and content hash, then the one-diff order (function
entry, call address, evidence_ref). The literals only order the list — they are never part of the
key and never a reading of the change.

WHERE A MEMBER LANDED is its own diff's answer, not repeated here (that would build every diff's
view of the pair for one call): each member carries the ``diff_id`` and ``evidence_ref`` that
same_shape_siblings takes for its one-diff group, with its landing and its ``group_ref``. A member
no diff covers has no landing and no one-diff group to read.

HOW THIS RELATES TO ``binaries_not_diffed``: the one-diff group's ``sibling_set_bounds`` counts
calls of the same sink name and kind in the binaries of the run that NO diff of the pair covers — a
coarser measure (sink name and kind, not shape). This group lists those binaries' calls of the
shape itself as members, and ``bounds.not_diffed_same_shape`` counts them per side and reason.

WHAT CAN MAKE THIS GROUP LOOK SMALLER (``bounds``): ``calls_unreadable`` — per side, the binaries
whose calls could not be read (a diff records no content hash for that side; the run's analysis.db
records the binary's analysis as other than ok), counted and never read as holding no member (the
calls such a binary does hold are members all the same); ``literals_unreadable`` — per side,
binaries whose literals could not be read (not in the run's analysis.db, or an analysis recorded as
other than ok; their members sit in the unknown tier); ``unkeyed`` — calls of this sink name, or
with no sink name, that no shape could be given; ``excluded_non_callsite`` — function-level
candidates of this sink name and kind, per granularity; ``recall_gaps`` — not read at this scope
(it is a per-binary reading of callee lists; the one-diff group gives it). Beside them,
``not_diffed_same_shape`` counts the members no diff covers, per side, by reason.

SOURCE STALENESS: ``source_stale_diffs`` counts the pair's diffs by their ``source_stale`` as
list_diffs gives each (diff_align.diffs_source_staleness / staleness_summary); a member row does
not repeat its diff's.

``run_pair_group_summary`` returns a compact summary of one candidate's run-pair group for another
answer to carry; nothing calls it yet.
"""

from __future__ import annotations

import sqlite3
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from treasure_map.lib.query import diff_review
from treasure_map.lib.query import same_shape_siblings as sss
from treasure_map.lib.query.diff_align import (
    _is_whole_run_row,
    diffs_source_staleness,
    staleness_summary,
)
from treasure_map.lib.ro_db import ro_connect

RUN_PAIR_SCOPE = "run_pair"
MIN_LITERAL_LENGTH = 4
PAIR_MEMBERS_ORDER = (
    "shared_literal_tier_then_rarest_shared_literal_then_most_shared_then_diffed_by_diff_id_side_"
    "then_not_diffed_by_binary_side_then_function_entry_then_call_address_then_evidence_ref"
)
RECALL_GAPS_NOT_READ = "not_read_at_this_scope"
NO_CONTENT_HASH = "no_content_hash"
ANALYSIS_STATUS = "analysis_status"
# A binary's analysis.db status that leaves its candidates readable: analysed (``ok``), or analysed
# and found to hold no function (``ok_empty``).
_READ_STATUSES = ("ok", "ok_empty")
BY_BINARY_CAP = 64
NAMES_CAP = 5
_IN_CHUNK = 500

_SELECT = (
    "SELECT i.evidence_ref, p.sink_class, i.sink_anchor, i.flow_evidence, "
    "p.structural_fingerprint, p.fingerprint_algo_version, i.binary_content_hash, i.binary_path "
    "FROM instance i JOIN pattern p ON i.pattern_id = p.pattern_id "
)

_NOTE = (
    "The calls of this shape in every binary of the two runs, both sides; the shape key is the "
    "one-diff group's. Members whose function shares a literal string with the input's function "
    "come first: an order to read in, not a reading of the change. Where a member landed is its "
    "own diff's answer: same_shape_siblings(diff_id=<its diff_id>, evidence_ref=<its "
    "evidence_ref>). A member in a binary no diff of the pair covers has diffed false, a null "
    "diff_id, its binary and not_diffed_reason: it has no landing to read."
)


# ── the scope ───────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class _PairDiff:
    diff_id: str
    binary: dict[str, str | None]
    sha: dict[str, str | None]


def _pair_diffs(atlas: sqlite3.Connection, run_a: str, run_b: str) -> list[_PairDiff]:
    """The per-binary diffs of the pair, by diff_id (a whole-run leftover row is not one)."""
    rows = atlas.execute(
        "SELECT diff_id, binary_a, binary_b, sha256_a, sha256_b FROM diff_meta "
        "WHERE run_a_id = ? AND run_b_id = ? ORDER BY diff_id",
        (run_a, run_b),
    ).fetchall()
    return [
        _PairDiff(str(r[0]), {"a": r[1], "b": r[2]}, {"a": r[3], "b": r[4]})
        for r in rows
        if not _is_whole_run_row(str(r[0]), run_a, run_b)
    ]


def run_pair_scope(atlas: sqlite3.Connection, diff_id: str) -> tuple[str, str] | None:
    """``(run_a, run_b)`` when ``diff_id`` names a run pair with per-binary diffs (and no one diff:
    a whole-run leftover row with that id is not one), else None."""
    row = atlas.execute(
        "SELECT run_a_id, run_b_id FROM diff_meta WHERE diff_id = ?", (diff_id,)
    ).fetchone()
    if row is not None and not _is_whole_run_row(diff_id, str(row[0]), str(row[1])):
        return None
    parts = diff_id.split("::")
    for cut in range(1, len(parts)):
        run_a, run_b = "::".join(parts[:cut]), "::".join(parts[cut:])
        if _pair_diffs(atlas, run_a, run_b):
            return run_a, run_b
    return None


def probe_diff(atlas: sqlite3.Connection, diff_id: str) -> str | None:
    """One per-binary diff of the run pair ``diff_id`` names (they all share its two runs, so its
    stale-run refusal is the pair's), else None."""
    pair = run_pair_scope(atlas, diff_id)
    if pair is None:
        return None
    return _pair_diffs(atlas, *pair)[0].diff_id


def pair_hint(atlas: sqlite3.Connection, diff_id: str) -> str:
    """One sentence for a ``diff_id`` that names neither one binary's diff nor a run pair: the run
    pair it names the other way round when there is one, else how a run pair is written."""
    parts = diff_id.split("::")
    for cut in range(1, len(parts)):
        run_b, run_a = "::".join(parts[:cut]), "::".join(parts[cut:])
        if _pair_diffs(atlas, run_a, run_b):
            pair = diff_review.run_pair(run_a, run_b)
            return f" Its two runs are the other way round: the run pair is {pair!r}."
    return (
        " A run pair is passed as diff_id='<run_a_id>::<run_b_id>', the two ids as list_diffs "
        "gives them, run_a first."
    )


# ── one side's calls of the shape ───────────────────────────────────────────────────────────


@dataclass
class _Side:
    """One side of the scope: the diffed binaries by content hash, the run's calls of the sink (and
    with no sink name) by binary, the binaries no diff covers with their short name and reason,
    and the binaries whose calls could not be read, by reason. A binary is keyed by its content
    hash, or ``path:<path>`` when the instance row records none."""

    run: str
    diff_of: dict[str, _PairDiff] = field(default_factory=dict)  # sha -> its (first) diff
    calls: dict[str, list[sss._Call]] = field(default_factory=dict)  # binary key -> calls
    not_diffed: dict[str, tuple[str | None, str]] = field(default_factory=dict)  # (name, reason)
    unreadable: dict[str, list[str]] = field(default_factory=dict)  # reason -> binary names

    def name(self, side: str, key: str) -> str:
        """A binary's short name: its diff's binary for a diffed one, else its path's basename."""
        if key in self.diff_of:
            d = self.diff_of[key]
            return d.binary[side] or d.diff_id
        return self.not_diffed[key][0] or key


def _scope_side(diffs: list[_PairDiff], side: str, run: str) -> _Side:
    out = _Side(run)
    for d in diffs:
        sha = d.sha[side]
        if not sha:
            out.unreadable.setdefault(NO_CONTENT_HASH, []).append(d.binary[side] or d.diff_id)
            continue
        out.diff_of.setdefault(sha, d)  # one content in two diffs is read once, under the first
    return out


def _read_calls(
    atlas: sqlite3.Connection, scope: _Side, sink: str, basis: sss.NotDiffedBasis
) -> None:
    """The calls of ``sink`` — and those with no sink name, which any shape may be — in every
    binary of the side's run, by binary, in instance order; a binary no diff covers is recorded
    with its reason (``basis``). Filtering by the sink's name loses no member: the name is part of
    the key."""
    for c in scope.diff_of:
        scope.calls.setdefault(c, [])
    for row in atlas.execute(
        _SELECT + "WHERE i.source_run_id = ? AND (i.sink_anchor = ? OR i.sink_anchor IS NULL "
        "OR i.sink_anchor = '') ORDER BY i.instance_id",
        (scope.run, sink),
    ):
        sha, path = row[6] or None, row[7]
        key = sha if sha is not None else f"path:{path}"
        if key not in scope.diff_of and key not in scope.not_diffed:
            base = path.rsplit("/", 1)[-1] if path else None
            scope.not_diffed[key] = (base, basis.reason(sha, path))
        scope.calls.setdefault(key, []).append(sss._call(tuple(row[:6])))


# ── the literals ────────────────────────────────────────────────────────────────────────────


@dataclass
class _Literals:
    """One side's literal facts: the binaries read (content hash -> analysis status), how many
    functions of the run reference each of the input's literals, and which of them each function
    references; ``error`` when the side's analysis.db could not be read."""

    error: str | None = None
    status: dict[str, str | None] = field(default_factory=dict)
    df: Counter[str] = field(default_factory=Counter)
    by_fn: dict[tuple[str, int], set[str]] = field(default_factory=dict)
    truncated: set[str] = field(default_factory=set)


def _hex_int(value: Any) -> int | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return int(value, 16)
    except ValueError:
        return None


def _fn_key(value: Any) -> int:
    """A function entry as the int a name is looked up by; -1 (no function) when unparsable."""
    fn = _hex_int(value)
    return -1 if fn is None else fn


def _adb_path(atlas: sqlite3.Connection, run: str) -> str | None:
    row = atlas.execute("SELECT analysis_db_path FROM run WHERE run_id = ?", (run,)).fetchone()
    return str(row[0]) if row is not None and row[0] else None


def _open_adb(atlas: sqlite3.Connection, run: str) -> sqlite3.Connection | str:
    path = _adb_path(atlas, run)
    if path is None:
        return "the run records no analysis.db"
    try:
        conn = ro_connect(path)
        # A readability probe only (a valid sqlite db with the expected table); binaries are
        # resolved by sha / path below, never selected by name here.
        conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'binaries'"
        ).fetchall()
    except sqlite3.Error as e:
        return f"analysis.db could not be read: {e}"
    return conn


def _input_literals(
    atlas: sqlite3.Connection, run: str, sha: str, func: int
) -> tuple[frozenset[str], str | None]:
    """The literals (by text, at least MIN_LITERAL_LENGTH long) the input's function references,
    or why they could not be read."""
    conn = _open_adb(atlas, run)
    if isinstance(conn, str):
        return frozenset(), conn
    try:
        found = conn.execute("SELECT id FROM binaries WHERE sha256 = ?", (sha,)).fetchone()
        if found is None:
            return frozenset(), "the input's binary is not in its run's analysis.db"
        rows = conn.execute(
            "SELECT string_value, ref_in_func_addr FROM string_refs WHERE binary_id = ?",
            (found[0],),
        ).fetchall()
    except sqlite3.Error as e:
        return frozenset(), f"analysis.db could not be read: {e}"
    finally:
        conn.close()
    lits = {
        v
        for v, fa in rows
        if isinstance(v, str) and len(v) >= MIN_LITERAL_LENGTH and _hex_int(fa) == func
    }
    return frozenset(lits), None


def _side_literals(
    atlas: sqlite3.Connection, run: str, shas: set[str], wanted: frozenset[str]
) -> _Literals:
    """For one side: each scope binary's analysis status, and for each of ``wanted`` (the input's
    literals) how many functions of the run reference it and which functions of the scope do."""
    conn = _open_adb(atlas, run)
    if isinstance(conn, str):
        return _Literals(error=conn)
    out = _Literals()
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(binaries)")}
        status_col = "ghidra_status" if "ghidra_status" in cols else "NULL"
        sha_of: dict[int, str] = {}
        for bid, sha, status in conn.execute(f"SELECT id, sha256, {status_col} FROM binaries"):
            if sha in shas:
                sha_of[int(bid)] = sha
                out.status[sha] = status
        seen: set[tuple[int, int, str]] = set()
        values = sorted(wanted)
        for i in range(0, len(values), _IN_CHUNK):
            chunk = values[i : i + _IN_CHUNK]
            marks = ", ".join("?" * len(chunk))
            for bid, fa, value, truncated in conn.execute(
                "SELECT binary_id, ref_in_func_addr, string_value, truncated FROM string_refs "
                f"WHERE string_value IN ({marks})",
                chunk,
            ):
                if truncated:
                    out.truncated.add(value)
                fn = _hex_int(fa)
                if fn is None or (bid, fn, value) in seen:
                    continue
                seen.add((bid, fn, value))
                out.df[value] += 1  # functions of the run, any binary, that reference it
                sha = sha_of.get(int(bid))
                if sha is not None:
                    out.by_fn.setdefault((sha, fn), set()).add(value)
    except sqlite3.Error as e:
        return _Literals(error=f"analysis.db could not be read: {e}")
    finally:
        conn.close()
    return out


def _function_names(
    atlas: sqlite3.Connection, run: str, wanted: set[tuple[str, int]]
) -> dict[tuple[str, int], str]:
    """Function names for (content hash, entry) pairs, read from the run's analysis.db; what
    cannot be read is left out (a member row then carries a null name)."""
    if not wanted:
        return {}
    conn = _open_adb(atlas, run)
    if isinstance(conn, str):
        return {}
    out: dict[tuple[str, int], str] = {}
    try:
        for sha in sorted({s for s, _ in wanted}):
            found = conn.execute("SELECT id FROM binaries WHERE sha256 = ?", (sha,)).fetchone()
            if found is None:
                continue
            for address, name in conn.execute(
                "SELECT address, name FROM functions WHERE binary_id = ?", (found[0],)
            ):
                key = (sha, _fn_key(address))
                if key in wanted and name:
                    out[key] = str(name)
    except sqlite3.Error:
        return out
    finally:
        conn.close()
    return out


# ── the group ───────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class _Member:
    side: str
    sha: str  # the binary key: its content hash, or path:<path>
    diff_id: str | None  # None: no diff of the pair covers its binary
    call: sss._Call
    literal: tuple[int, int | None] | None  # (shared, rarest df) or None when unreadable
    binary: str | None = None  # a member no diff covers: its binary's short name
    not_diffed_reason: str | None = None  # ... and why (NOT_DIFFED_REASONS)

    def order(self) -> tuple[Any, ...]:
        if self.literal is None:
            tier: tuple[int, int, int] = (1, 0, 0)
        elif self.literal[0] > 0:
            tier = (0, self.literal[1] or 0, -self.literal[0])
        else:
            tier = (2, 0, 0)
        if self.diff_id is not None:
            where: tuple[Any, ...] = (0, self.diff_id, self.side, "")
        else:
            where = (1, self.binary or "", self.side, self.sha)
        return (*tier, *where, *sss._order(self.call))


@dataclass
class _Group:
    run_a: str
    run_b: str
    pair: str
    inp_ref: str
    inp_side: str
    inp_diff: _PairDiff
    inp_granularity: str
    key: str
    first: sss._Call
    sides: dict[str, _Side]
    literals: dict[str, _Literals]
    input_literals: frozenset[str]
    input_literals_error: str | None
    members: list[_Member]  # in PAIR_MEMBERS_ORDER
    diff_ids: list[str]  # every per-binary diff of the pair


def _err(pair: str, message: str, **extra: Any) -> dict[str, Any]:
    return {"diff_id": pair, "scope": RUN_PAIR_SCOPE, "error": message, **extra}


def _locate_input(
    atlas: sqlite3.Connection,
    pair: str,
    runs: dict[str, str],
    diffs: list[_PairDiff],
    inp: Any,
) -> tuple[str, _PairDiff, list[sss._Call]] | dict[str, Any]:
    """The input's side, its diff and its rows, or the refusal: it must be a candidate of a binary
    a diff of the pair covers on its side."""
    for s in (inp.side,) if inp.side else ("a", "b"):
        by_sha: dict[str, list[sss._Call]] = {}
        for row in atlas.execute(
            _SELECT + "WHERE i.source_run_id = ? AND i.evidence_ref = ? ORDER BY i.instance_id",
            (runs[s], inp.ref),
        ):
            by_sha.setdefault(str(row[6] or ""), []).append(sss._call(tuple(row[:6])))
        if not by_sha:
            continue
        diffed: dict[str, _PairDiff] = {}
        for d in diffs:
            sha = d.sha[s]
            if sha:
                diffed.setdefault(sha, d)  # under the first diff, as _scope_side reads it
        hits = sorted((sha for sha in by_sha if sha in diffed), key=lambda x: diffed[x].diff_id)
        if not hits:
            return _err(
                pair,
                f"{inp.ref!r} is a candidate of run {runs[s]!r} in a binary no diff of this run "
                "pair covers (its calls are counted by the one-diff group's "
                "sibling_set_bounds.binaries_not_diffed)",
            )
        if len(hits) > 1:
            return _err(
                pair,
                f"{inp.ref!r} is recorded in {len(hits)} diffed binaries on side {s}; name it in "
                "one diff: " + ", ".join(diffed[h].diff_id for h in hits),
            )
        return s, diffed[hits[0]], by_sha[hits[0]]
    s = inp.side or "a"
    return _err(pair, f"{inp.ref!r} is not a candidate of run {runs[s]!r} (side {s})")


def _member_literal(
    lits: _Literals, wanted: frozenset[str], wanted_error: str | None, m_sha: str, c: sss._Call
) -> tuple[int, int | None] | None:
    if wanted_error is not None or lits.error is not None or m_sha not in lits.status:
        return None
    status = lits.status[m_sha]
    if status is not None and status not in _READ_STATUSES:
        return None  # an analysis recorded as other than ok: its references are not all there
    fn = _hex_int(c.func_entry)
    if fn is None:
        return None
    shared = wanted & lits.by_fn.get((m_sha, fn), set())
    if not shared:
        return (0, None)
    return (len(shared), min(lits.df[x] for x in shared))


def _build(
    atlas: sqlite3.Connection,
    pair: str,
    run_a: str,
    run_b: str,
    evidence_ref: str | None,
    candidate_anchor: str | None,
) -> _Group | dict[str, Any]:
    """The run-pair group of the input call, or the refusal / the not-a-member answer."""
    runs = {"a": run_a, "b": run_b}
    diffs = _pair_diffs(atlas, run_a, run_b)
    bases = {s: sss.not_diffed_basis(atlas, run_a, run_b, s) for s in ("a", "b")}
    probe = sss._Meta(pair, runs, {"a": None, "b": None}, {"a": None, "b": None})
    inp = sss._resolve_input(probe, evidence_ref, candidate_anchor)
    if isinstance(inp, str):
        return _err(pair, inp)
    located = _locate_input(atlas, pair, runs, diffs, inp)
    if isinstance(located, dict):
        return located
    side, inp_diff, rows = located
    if inp.sink_class is not None:
        rows = [c for c in rows if c.sink_class == inp.sink_class]
        if not rows:
            return _err(
                pair,
                f"the anchor's sink class {inp.sink_class!r} is not a class {inp.ref!r} is "
                "recorded with",
            )
    keyed = [c for c in rows if c.unkeyed is None]
    if not keyed:
        return _err(pair, f"{inp.ref!r} cannot be given a shape: {rows[0].unkeyed}")
    mine = [c for c in keyed if c.granularity in sss.MEMBER_GRANULARITIES]
    head = {
        "diff_id": pair,
        "scope": RUN_PAIR_SCOPE,
        "input": {
            "evidence_ref": inp.ref,
            "key_granularity": keyed[0].granularity,
            "diff_id": inp_diff.diff_id,
            "side": side,
            "binary": inp_diff.binary[side],
        },
    }
    if not mine or len({c.key for c in mine}) > 1:
        shapes: dict[str, sss._Call] = {}
        for c in mine or keyed:
            shapes.setdefault(c.key, c)
        f2_keys = []
        for k in sorted(shapes):
            counts = {}
            for s in ("a", "b"):
                scope = _scope_side(diffs, s, runs[s])
                _read_calls(atlas, scope, shapes[k].sink, bases[s])
                counts[s] = sum(len(sss._groups(cs).get(k, [])) for cs in scope.calls.values())
            f2_keys.append(
                {
                    "f2_key": k,
                    "sink_anchor": shapes[k].sink,
                    "kind": shapes[k].kind,
                    "member_count": counts,
                }
            )
        if not mine:
            return {
                **head,
                "not_a_member": True,
                "key_granularity": keyed[0].granularity,
                "f2_keys": f2_keys,
                "note": (
                    "A function-level candidate has no call address of its own, so it is no "
                    "group's member. f2_keys are the shapes it has, each with its run-pair "
                    "member count per side."
                ),
            }
        return _err(
            pair,
            f"{inp.ref!r} is recorded with {len(shapes)} shapes, so it is a member of "
            f"{len(shapes)} groups; name it by a candidate anchor, whose sink class narrows it",
            f2_keys=f2_keys,
        )
    first = mine[0]
    key = first.key
    sides = {s: _scope_side(diffs, s, runs[s]) for s in ("a", "b")}
    for s, scope in sides.items():
        _read_calls(atlas, scope, first.sink, bases[s])
    inp_sha = inp_diff.sha[side]
    assert inp_sha is not None and first.func_entry is not None
    wanted, wanted_error = _input_literals(atlas, runs[side], inp_sha, int(first.func_entry, 16))
    literals = {s: _side_literals(atlas, runs[s], set(sides[s].calls), wanted) for s in ("a", "b")}
    members: list[_Member] = []
    for s, scope in sides.items():
        status = literals[s].status
        for sha, calls in scope.calls.items():
            # A recorded analysis outcome other than ok leaves the binary's candidates short of
            # what it holds: it is counted, and the calls it does hold are members all the same.
            st = status.get(sha)
            if st is not None and st not in _READ_STATUSES:
                scope.unreadable.setdefault(f"{ANALYSIS_STATUS}:{st}", []).append(
                    scope.name(s, sha)
                )
            d = scope.diff_of.get(sha)
            nd = scope.not_diffed.get(sha, (None, None))
            for c in sss._groups(calls).get(key, []):
                lit = _member_literal(literals[s], wanted, wanted_error, sha, c)
                if d is not None:
                    members.append(_Member(s, sha, d.diff_id, c, lit))
                else:
                    members.append(_Member(s, sha, None, c, lit, scope.name(s, sha), nd[1]))
    members.sort(key=_Member.order)
    return _Group(
        run_a,
        run_b,
        pair,
        inp.ref,
        side,
        inp_diff,
        keyed[0].granularity,
        key,
        first,
        sides,
        literals,
        wanted,
        wanted_error,
        members,
        [d.diff_id for d in diffs],
    )


def _ranked(counts: Counter[str], key: str) -> dict[str, Any]:
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    out: dict[str, Any] = {key: dict(ranked[:BY_BINARY_CAP])}
    if len(ranked) > BY_BINARY_CAP:
        out[f"{key}_not_listed"] = len(ranked) - BY_BINARY_CAP
    return out


def _side_counts(g: _Group, side: str) -> dict[str, Any]:
    """One side's members: all of them, then those a diff covers by the diff's binary and those no
    diff covers by short name (``binaries`` counts both, by binary key)."""
    scope = g.sides[side]
    ms = [m for m in g.members if m.side == side]
    diffed = [m for m in ms if m.diff_id is not None]
    not_diffed = [m for m in ms if m.diff_id is None]
    out: dict[str, Any] = {
        "member_count": len(ms),
        "binaries": len({m.sha for m in ms}),
        **_ranked(Counter(scope.name(side, m.sha) for m in diffed), "by_binary"),
        "not_diffed_members": len(not_diffed),
        "not_diffed_binaries": len({m.sha for m in not_diffed}),
        **_ranked(Counter(m.binary or m.sha for m in not_diffed), "by_binary_not_diffed"),
    }
    shares = [m for m in ms if m.literal is not None and m.literal[0] > 0]
    out["shared_literal_members"] = len(shares)
    out["shared_literal_binaries"] = len({m.sha for m in shares})
    out["literal_unknown_members"] = sum(1 for m in ms if m.literal is None)
    return out


def _not_diffed_bound(g: _Group, side: str) -> dict[str, Any]:
    """The members no diff of the pair covers on one side, by reason: binaries by binary key,
    members by evidence_ref; every reason is given, 0 included."""
    found: dict[str, tuple[set[str], set[str]]] = {
        r: (set(), set()) for r in sss.NOT_DIFFED_REASONS
    }
    for m in g.members:
        if m.side == side and m.diff_id is None:
            binaries, refs = found[m.not_diffed_reason or sss.NOT_DIFFED_REASONS[-1]]
            binaries.add(m.sha)
            refs.add(m.call.ref or "")
    return {
        "members": sum(len(r) for _b, r in found.values()),
        "binaries": len({b for bs, _r in found.values() for b in bs}),
        "by_reason": {r: {"binaries": len(b), "members": len(c)} for r, (b, c) in found.items()},
    }


def _bounds(g: _Group) -> dict[str, Any]:
    calls_unreadable: dict[str, Any] = {}
    literals_unreadable: dict[str, Any] = {}
    unkeyed: dict[str, Any] = {}
    excluded: dict[str, Any] = {}
    for s, scope in g.sides.items():
        calls_unreadable[s] = {
            why: {"binaries": len(names), "first": sorted(names)[:NAMES_CAP]}
            for why, names in sorted(scope.unreadable.items())
        }
        lits = g.literals[s]
        if g.input_literals_error is not None:
            literals_unreadable[s] = {"input_literals_unreadable": len(scope.calls)}
        elif lits.error is not None:
            literals_unreadable[s] = {"analysis_db_unreadable": len(scope.calls)}
        else:
            missing = sum(1 for sha in scope.calls if sha not in lits.status)
            not_ok = sum(
                1 for st in lits.status.values() if st is not None and st not in _READ_STATUSES
            )
            literals_unreadable[s] = {
                k: n for k, n in (("not_in_analysis_db", missing), (ANALYSIS_STATUS, not_ok)) if n
            }
        every = [c for cs in scope.calls.values() for c in cs]
        unkeyed[s] = sss._unkeyed(every)
        excluded[s] = sss._excluded(every, g.first.sink, g.first.kind)
    return {
        "calls_unreadable": calls_unreadable,
        "literals_unreadable": literals_unreadable,
        "unkeyed": unkeyed,
        "excluded_non_callsite": excluded,
        "recall_gaps": {"families": None, "state": RECALL_GAPS_NOT_READ},
        "not_diffed_same_shape": {s: _not_diffed_bound(g, s) for s in ("a", "b")},
    }


def _input_group_ref(g: _Group) -> str | None:
    """The one-diff group of the input: its diff, its side, its fingerprint version."""
    mine = [m.call for m in g.members if m.diff_id == g.inp_diff.diff_id and m.side == g.inp_side]
    if not mine:
        return None
    return sss.group_ref(g.inp_diff.diff_id, g.key, g.inp_side, sss._fp_version(mine))


def _head(g: _Group) -> dict[str, Any]:
    return {
        "diff_id": g.pair,
        "scope": RUN_PAIR_SCOPE,
        "input": {
            "evidence_ref": g.inp_ref,
            "key_granularity": g.inp_granularity,
            "diff_id": g.inp_diff.diff_id,
            "side": g.inp_side,
            "binary": g.inp_diff.binary[g.inp_side],
        },
        "f2_key": g.key,
    }


def _literal_block(g: _Group) -> dict[str, Any]:
    return {
        "min_length": MIN_LITERAL_LENGTH,
        "input_literals": None if g.input_literals_error is not None else len(g.input_literals),
        "state": (
            "read" if g.input_literals_error is None else f"unreadable:{g.input_literals_error}"
        ),
        "truncated": {s: len(g.literals[s].truncated & g.input_literals) for s in ("a", "b")},
    }


def _outside(g: _Group) -> list[_Member]:
    return [m for m in g.members if m.diff_id != g.inp_diff.diff_id]


def source_stale_diffs(atlas: sqlite3.Connection, diff_ids: list[str]) -> dict[str, Any]:
    """The pair's diffs counted by their ``source_stale`` as list_diffs gives each (stale true,
    unverified null, current false) and by reason."""
    return staleness_summary(diffs_source_staleness(atlas, diff_ids))


def _group_object(atlas: sqlite3.Connection, g: _Group, page_ref: dict[str, Any]) -> dict[str, Any]:
    outside = _outside(g)
    return {
        **_head(g),
        "input_group_ref": _input_group_ref(g),
        "shape": {
            "structural_fingerprint": g.first.fingerprint,
            "sink_anchor": g.first.sink,
            "kind": g.first.kind,
        },
        "diffs_in_scope": len({d.diff_id for s in g.sides.values() for d in s.diff_of.values()}),
        "member_count": len(g.members),
        "members_outside_input_diff": len(outside),
        "shared_literal_members_outside_input_diff": sum(
            1 for m in outside if m.literal is not None and m.literal[0] > 0
        ),
        "sides": {s: _side_counts(g, s) for s in ("a", "b")},
        "shared_literals": _literal_block(g),
        "bounds": _bounds(g),
        "source_stale_diffs": source_stale_diffs(atlas, g.diff_ids),
        "members_order": PAIR_MEMBERS_ORDER,
        "members_page_ref": page_ref,
        "note": _NOTE,
    }


def _member_row(m: _Member, names: dict[tuple[str, int], str]) -> dict[str, Any]:
    c = m.call
    row: dict[str, Any] = {
        "diff_id": m.diff_id,
        "diffed": m.diff_id is not None,
        "side": m.side,
    }
    if m.diff_id is None:
        row["binary"] = m.binary
        row["not_diffed_reason"] = m.not_diffed_reason
    row |= {
        "evidence_ref": c.ref,
        "key_granularity": c.granularity,
        "function_entry": c.func_entry,
        "function_name": names.get((m.sha, _fn_key(c.func_entry))),
        "call_addr": c.call_addr,
        "shared_literals": None if m.literal is None else m.literal[0],
        "rarest_shared_literal_df": None if m.literal is None else m.literal[1],
    }
    if c.granularity == "wrapper_callsite":
        row["wrapper"] = {"name": c.wrapper[0], "entry": c.wrapper[1]}
    return row


def run_pair_siblings(
    atlas: sqlite3.Connection,
    diff_id: str,
    run_a: str,
    run_b: str,
    *,
    evidence_ref: str | None,
    candidate_anchor: str | None,
    members_offset: int | None,
    members_limit: int,
) -> dict[str, Any]:
    """same_shape_siblings at run-pair scope (see the module docstring): the group object without
    ``members_offset``, one page of members in ``PAIR_MEMBERS_ORDER`` with it. The arguments are
    checked, and a stale run refused, by same_shape_siblings before it calls this."""
    g = _build(atlas, diff_id, run_a, run_b, evidence_ref, candidate_anchor)
    if isinstance(g, dict):
        if members_offset is not None and g.get("not_a_member"):
            return _err(
                diff_id,
                f"{g['input']['evidence_ref']!r} is no group's member, so there are no members "
                "to page",
            )
        return g
    if members_offset is None:
        page_ref: dict[str, Any] = {"diff_id": diff_id}
        page_ref["candidate_anchor" if candidate_anchor is not None else "evidence_ref"] = (
            candidate_anchor if candidate_anchor is not None else g.inp_ref
        )
        page_ref["members_offset"] = 0
        return _group_object(atlas, g, page_ref)
    total = len(g.members)
    if members_offset >= total and members_offset > 0:
        return _err(
            diff_id,
            f"members_offset {members_offset} is past the group's {total} members",
            member_count=total,
        )
    end = members_offset + members_limit
    page = g.members[members_offset:end]
    names: dict[tuple[str, int], str] = {}
    for s in ("a", "b"):
        wanted = {(m.sha, _fn_key(m.call.func_entry)) for m in page if m.side == s}
        names.update(_function_names(atlas, g.sides[s].run, wanted))
    return {
        **_head(g),
        "member_count": total,
        "members_order": PAIR_MEMBERS_ORDER,
        "members_offset": members_offset,
        "members": [_member_row(m, names) for m in page],
        "members_next_offset": end if end < total else None,
    }


def run_pair_group_summary(
    atlas: sqlite3.Connection,
    run_a: str,
    run_b: str,
    *,
    evidence_ref: str | None = None,
    candidate_anchor: str | None = None,
    first: int = 3,
) -> dict[str, Any]:
    """A compact summary of one candidate call's run-pair same-shape group (the ``f2_key`` group
    across every binary of the pair's two runs), for another answer to carry beside a judgement: the
    key, the member count per side (and how many of them no diff covers), how many members sit
    outside the input's diff and how many of
    those share a literal with it, the binaries whose calls could not be read, the first ``first``
    members outside the input's diff in PAIR_MEMBERS_ORDER, and the call that pages the rest. The
    caller checks a stale run first, as same_shape_siblings does. A refusal or a function-level
    input comes back as same_shape_siblings would give it (``error`` / ``not_a_member``)."""
    pair = diff_review.run_pair(run_a, run_b)
    g = _build(atlas, pair, run_a, run_b, evidence_ref, candidate_anchor)
    if isinstance(g, dict):
        return g
    outside = _outside(g)
    arg = (
        f"candidate_anchor={candidate_anchor!r}"
        if candidate_anchor is not None
        else f"evidence_ref={g.inp_ref!r}"
    )
    return {
        "scope": RUN_PAIR_SCOPE,
        "f2_key": g.key,
        "input_diff_id": g.inp_diff.diff_id,
        "member_count": {s: sum(1 for m in g.members if m.side == s) for s in ("a", "b")},
        "not_diffed_members": {
            s: sum(1 for m in g.members if m.side == s and m.diff_id is None) for s in ("a", "b")
        },
        "members_outside_input_diff": len(outside),
        "shared_literal_members_outside_input_diff": sum(
            1 for m in outside if m.literal is not None and m.literal[0] > 0
        ),
        "binaries_calls_unreadable": sum(
            len(names) for s in g.sides.values() for names in s.unreadable.values()
        ),
        "first_outside_input_diff": [
            {
                "diff_id": m.diff_id,
                "diffed": m.diff_id is not None,
                **({} if m.diff_id is not None else {"binary": m.binary}),
                "side": m.side,
                "evidence_ref": m.call.ref,
                "shared_literals": None if m.literal is None else m.literal[0],
            }
            for m in outside[: max(first, 0)]
        ],
        "members": f"same_shape_siblings(diff_id={pair!r}, {arg}, members_offset=0)",
    }
