# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The function-level view of one diff: each function pair that changed, what happened around its
sink calls, sorted into buckets, with a ledger of what this view cannot see.

READ-ONLY and DERIVED. It writes nothing and adds no judgement of its own. Every entry is built from
facts other layers already hold, and says which: the candidate overlay of the diff
(lib/query/sink_overlay — the stored baseline when it is current, else the same computation in
memory, never stored), the diff's function alignment and function presence, and the callee lists
each side's analysis.db extracted. No score and no verdict: a bucket says what kind of evidence an
entry carries, never what it means.

THE SUBJECT is a function pair, or a function with no counterpart — not a candidate, not a
string-keyed edge. Those two finer views are one argument away (``view``), and every response counts
all three subjects, so switching the view re-projects the same diff and drops nothing.

BUCKETS (``bucket``):
  A  at the call instruction BinDiff matched, the other side calls a different callee, and the
     paired function holds no candidate with the original callee.
  B  a sink candidate whose cross-side reading stayed undetermined; a changed pair whose candidates
     all line up (``sink_present_no_visible_delta``); or a changed pair with no candidate that calls
     a sink the hunt does not recall (``recall_gap_sink:<family>``).
  R  the pair itself is undetermined (its alignment confidence is low, or its export could not hold
     one of the two functions as it is).
  C  a changed pair (similarity below 1) with no sink candidate on either side.
  P  a function with no counterpart (``presence_state`` from function_presence, ``absent`` when the
     function has no presence record at all).
A pair that is identical (similarity 1) and whose candidates all line up, or that has none, is not
listed; it is counted under ``not_listed``. Where each overlay ``presence_reason`` lands is
``row_landing``; a reason it does not know lands in B as ``unmapped_reason:<reason>`` and is
counted, never dropped.

THE SECOND SIGNAL (``callee_set``): for an aligned pair, the two functions' extracted callee lists
compared as sets. A ``FUN_<addr>`` callee is compared by address through this diff's alignment,
never by name; one that cannot be mapped (or is a stub the extractor could not name) makes the
comparison undetermined. It never moves an entry between buckets: an entry with a sink candidate
is never C because its callees look unchanged.

ORDER: A first, then the R and B entries that carry a sink candidate, then the entries with none,
then P; inside each, by the named components of ``rank_key`` (visible on every entry). ``tier`` is
the sink-impact tier of the entry's candidates (lib/query/sink_impact), ``no_sink`` without any.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import asdict, dataclass, field
from typing import Any

from treasure_map.lib.diff.layer0 import norm_hex
from treasure_map.lib.query.diff_align import diff_source_staleness, get_diff_deltas
from treasure_map.lib.query.sink_impact import impact_tier
from treasure_map.lib.query.sink_overlay import (
    _SENTINEL,
    SinkOverlayRow,
    _func_entry_hex,
    compute_sink_overlay,
    page_overlay,
    read_sink_overlay_baseline,
)
from treasure_map.version import UNKNOWN_VERSION

VIEWS = ("sink_patch", "string_edge", "candidate_flat")
BUCKETS = ("A", "B", "C", "R", "P")
SORT_BY = ("tier", "similarity", "address")
NO_SINK = "no_sink"
UNKNOWN = "unknown"
MAX_LIMIT = 2000

# Sinks the hunt does not recall as candidates, by family. A changed pair with no candidate whose
# callees name one of these is B, never C: there the absence of a candidate is the hunt's blind
# spot, not a fact about the function. Matched by exact name.
RECALL_GAP_SINKS: dict[str, tuple[str, ...]] = {
    "wide_char_string": ("wcscpy", "wcscat", "vswprintf"),
    "argv_runner": ("_eval",),
    "exec_path_variant": ("execvpe",),
}
# Callee-name prefixes of an input source the hunt does not model. Only tagged on A / B entries
# (``source_gap:<family>``); never moves an entry.
SOURCE_GAP_PREFIXES: dict[str, tuple[str, ...]] = {"uci_ubus": ("uci_", "ubus_")}

# The overlay rows that are about a direct sink call (not a wrapper): their sink's name can be
# looked for in the paired function's callee list.
_DIRECT_GRANULARITIES = ("callsite", "degraded_out_of_body", "function_fallback")
_WRAPPER_FUNCTION_LEVEL = "wrapper"
_FUN_RE = re.compile(r"FUN_([0-9a-fA-F]+)")
_SPS = "sink_presence_signal"
_REF_CHUNK = 500  # refs per IN (...) list, well under SQLite's bound-parameter limit

# Reasons that speak for the whole diff (or a whole run pair): no row of such a diff is placed.
_DIFF_WIDE = (
    "diff_meta_missing_sha",
    "diff_failed",
    "version_skew",
    "extraction_generation_mismatch",
)
_RUN_PAIR = ("binary_not_diffed", "shadowed_by_name_collision")
_DIFFERENT_CALLEE = ("present_different_callee", "counterpart_different_callee")
# Reasons a row keeps as its B subclass as they are.
_B_AS_IS = (
    "crossside_match_degraded",
    "crossgranularity_unresolved",
    "callee_unreadable",
    "counterpart_call_facts_absent",
    "counterpart_facts_stale",
    "counterpart_no_call_fact",
    "counterpart_call_ambiguous",
    "counterpart_callee_unresolved",
    "counterpart_not_candidate",
    "a_counterpart_not_candidate",
    "coclaim_unresolved",
)

# The structural blind spots: what this view cannot see at all, so it cannot count.
_STRUCTURAL_BLIND_SPOTS = {
    "register_indirect_calls": (
        "a call through a register records no callee name, so neither the overlay nor the callee "
        "lists see it"
    ),
    "multi_hop": "only direct calls are read; a sink two or more calls away is not followed",
    "exec_thin_wrappers_unnamed": (
        "a thin exec-family wrapper has no fixed name, so the recall-gap check cannot list it"
    ),
    "one_hop_cmd_only": (
        "one_hop_sink covers only the command thin wrappers the hunt records, not other classes"
    ),
}

_CAVEATS = {
    "A": (
        "At the call instruction BinDiff matched, the other side calls a different callee, and the "
        "paired function holds no candidate with the original callee. Evidence, not a verdict."
    ),
    "C": (
        "Neither side has a sink candidate tmap recognizes. This does not mean the change is "
        "unrelated to security."
    ),
    "callee_set_differs": (
        "The extracted callee lists differ. tmap's decompile can miss a call, so this is not proof "
        "a call was added or removed."
    ),
    "sink_name_in_paired_callees": (
        "false = the paired function's extracted callee list does not hold this name. It is read "
        "by exact name and a call through an unresolved stub prints as FUN_<addr>, so false can "
        "also mean the call is there under another name."
    ),
    "tier": (
        "tier is the highest sink-impact tier of the entry's candidates (the same tiers that "
        "order list_candidates), an ordering aid, not a measure of what the change does."
    ),
}

_LEGEND = {
    "A": "matched call instruction now calls another callee; no same-callee candidate in the pair",
    "B": (
        "a candidate's cross-side reading is undetermined; the candidates line up in a changed "
        "pair; or a changed pair with no candidate calls a sink the hunt does not recall"
    ),
    "R": "the pair itself is undetermined (low confidence, or an export gap)",
    "C": "changed pair, no sink candidate on either side",
    "P": "function with no counterpart",
}


# ── where an overlay row lands ───────────────────────────────────────────────────────────────


def row_landing(
    presence: str,
    reason: str | None,
    counterpart_call: str | None,
    *,
    confidence: float | None,
    elsewhere: bool | None,
    sink_name_in_paired_callees: bool | None,
    presence_state: str | None,
) -> tuple[str, str | None]:
    """(landing, subclass) of one overlay row: ``persisted`` (no change seen at that candidate),
    ``banner`` (the reason speaks for the whole diff), or a bucket.

    A is read from ``counterpart_call`` — the matched instruction calls another callee — together
    with ``same_callee_candidate_elsewhere`` (``elsewhere``): False is A, True is B
    ``rematch_suspected``, None is B ``elsewhere_unreadable``. That covers both readings that say it
    (the other side's candidate, and the call-site facts). ``confidence`` splits the two reasons a
    function with no counterpart and a function in an aligned pair share: null means the function
    has no alignment record (P), set means it has one (B or R)."""
    if presence == "persisted":
        return "persisted", None
    if reason in _DIFF_WIDE or reason in _RUN_PAIR:
        return "banner", f"diff_undetermined:{reason}"
    if counterpart_call == "present_different_callee":
        if elsewhere is False:
            return "A", "matched_call_other_callee"
        if elsewhere is True:
            return "B", "rematch_suspected"
        return "B", "elsewhere_unreadable"
    if reason == "function_unmatched":
        return "P", "unmatched_analysis_complete"
    if reason == "counterpart_not_analyzed":
        return "P", "absent"
    if reason == "no_counterpart_undetermined":
        if confidence is None:
            return "P", presence_state or "absent"
        return "B", f"{_SPS}:funclevel_no_counterpart"
    if reason == "degenerate_block_source":
        if confidence is None:
            return "P", presence_state or "absent"
        return "R", reason
    if reason in ("alignment_low_confidence", "callsite_not_exported"):
        return "R", reason
    if reason == "instruction_unmatched":
        if sink_name_in_paired_callees is False:
            return "B", f"{_SPS}:sink_name_absent_in_paired_callees"
        return "B", reason
    if reason == "counterpart_same_callee":
        return "B", "same_callee_non_candidate"
    if reason == "crossside_count_mismatch":
        return "B", f"{_SPS}:count_mismatch"
    if reason in _B_AS_IS or reason in _DIFFERENT_CALLEE:
        return "B", reason
    return "B", f"unmapped_reason:{reason}"


# ── reading the overlay rows: the stored baseline when current, else computed in memory ─────


def split_subject_key(
    key: str, run_a: str, run_b: str
) -> tuple[str, str, str | None, str | None] | None:
    """``(key_granularity, sink_class, a_ref, b_ref)`` of a stored candidate row's subject_key
    (``{granularity}|{class}|{a_ref}|{b_ref}``, an absent side written as ``(none)``), or None when
    it cannot be split one way only. A ref starts ``{run}#``, which places the separator between the
    two refs even if a ref were to contain one."""
    gran, sep1, rest = key.partition("|")
    sink_class, sep2, refs = rest.partition("|")
    if not sep1 or not sep2:
        return None
    splits: list[tuple[str, str]] = []
    for i, ch in enumerate(refs):
        if ch != "|":
            continue
        a, b = refs[:i], refs[i + 1 :]
        if (a == _SENTINEL or a.startswith(f"{run_a}#")) and (
            b == _SENTINEL or b.startswith(f"{run_b}#")
        ):
            splits.append((a, b))
    if len(splits) != 1:
        return None
    a, b = splits[0]
    return gran, sink_class, (None if a == _SENTINEL else a), (None if b == _SENTINEL else b)


_CALLEE_KEYS = ("matched_addr", "callees", "same_callee_candidate_elsewhere")
_CALLEE_ENTRY_KEYS = ("name", "addr", "kind", "addr_source")


def _ordered(d: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    return {**{k: d[k] for k in keys if k in d}, **{k: d[k] for k in sorted(d) if k not in keys}}


def _stored_callee(raw: str | None) -> dict[str, Any] | None:
    """A stored ``counterpart_callee`` in the key order the overlay writes it in (it is stored with
    sorted keys). Raises ValueError when it is not the JSON object the overlay stores."""
    if raw is None:
        return None
    data = json.loads(raw)
    if not isinstance(data, dict) or not isinstance(data.get("callees", []), list):
        raise ValueError("counterpart_callee is not an object")
    out = _ordered(data, _CALLEE_KEYS)
    if "callees" in out:
        out["callees"] = [
            _ordered(c, _CALLEE_ENTRY_KEYS) if isinstance(c, dict) else c for c in out["callees"]
        ]
    return out


def _split_coclaim(raw: str | None) -> tuple[list[str] | None, list[str] | None]:
    """The stored side-tagged co-claimer list back into the A and the B list."""
    if not raw:
        return None, None
    tagged = json.loads(raw)
    a = [t[2:] for t in tagged if isinstance(t, str) and t.startswith("a:")]
    b = [t[2:] for t in tagged if isinstance(t, str) and t.startswith("b:")]
    return a or None, b or None


def _baseline_rows(
    diff_id: str, run_a: str, run_b: str, stored: list[dict[str, Any]], callees: dict[str, Any]
) -> list[SinkOverlayRow] | None:
    """The stored rows as overlay rows, or None when one cannot be read back exactly."""
    out: list[SinkOverlayRow] = []
    try:
        for rec in stored:
            parts = split_subject_key(rec["subject_key"], run_a, run_b)
            if parts is None or parts[0] != rec["key_granularity"]:
                return None
            gran, sink_class, a_ref, b_ref = parts
            co_a, co_b = _split_coclaim(rec["coclaimed_by"])
            out.append(
                SinkOverlayRow(
                    diff_id=diff_id,
                    binary=rec["binary"],
                    sink_class=sink_class,
                    a_ref=a_ref,
                    b_ref=b_ref,
                    key_granularity=gran,
                    presence=rec["presence"],
                    presence_reason=rec["presence_reason"],
                    match_basis=rec["match_basis"],
                    counterpart_call=rec["counterpart_call"],
                    alignment_confidence=rec["alignment_confidence"],
                    coclaimed_by=co_a,
                    coclaimed_by_b=co_b,
                    a_n=rec["a_n"],
                    b_n=rec["b_n"],
                    counterpart_callee=_stored_callee(callees[rec["subject_key"]]),
                )
            )
    except (ValueError, TypeError, KeyError):
        return None
    return out


@dataclass
class _Overlay:
    rows: list[SinkOverlayRow]
    baseline_state: str  # fresh | recomputed_absent | recomputed_stale | recomputed_mismatch
    coverage: dict[str, Any] | None  # the computation's coverage check; None when read from storage


def read_overlay_rows(atlas: sqlite3.Connection, diff_id: str, run_a: str, run_b: str) -> _Overlay:
    """The diff's overlay rows: the stored baseline when it is current, else computed in memory.

    The baseline and its ``counterpart_callee`` column are read in ONE transaction (two statements
    outside one could see two states of a table written meanwhile), and used only when the two
    reads name the same rows. Otherwise — absent, stale, or the two disagree — the overlay is
    computed for the whole diff, once, and NOT stored: this is a reader."""
    own = not atlas.in_transaction
    if own:
        atlas.execute("BEGIN")
    try:
        base = read_sink_overlay_baseline(atlas, diff_id)
        extra: list[Any] = []
        if base.get("stale_baseline") is False:
            extra = atlas.execute(
                "SELECT subject_key, counterpart_callee FROM dimension_delta "
                "WHERE diff_id = ? AND subject_kind = 'candidate'",
                (diff_id,),
            ).fetchall()
    finally:
        if own:
            atlas.execute("COMMIT")
    state = "recomputed_absent" if base.get("baseline_absent") else "recomputed_stale"
    if base.get("stale_baseline") is False:
        stored: list[dict[str, Any]] = base["rows"]
        keys = sorted(r["subject_key"] for r in stored)
        callees = {row[0]: row[1] for row in extra}
        rows = None
        if keys == sorted(row[0] for row in extra) and len(callees) == len(keys):
            rows = _baseline_rows(diff_id, run_a, run_b, stored, callees)
        if rows is not None:
            return _Overlay(rows, "fresh", None)
        state = "recomputed_mismatch"
    result = compute_sink_overlay(atlas, diff_id)
    return _Overlay(list(result.rows), state, asdict(result.coverage))


# ── the diff's functions ────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class _Pair:
    addr_a: str
    addr_b: str
    name_a: str | None
    name_b: str | None
    confidence: float | None
    similarity: float | None
    state: str
    export_gap_a: str | None
    export_gap_b: str | None

    @property
    def aligned(self) -> bool:
        return self.state == "aligned"


@dataclass(frozen=True)
class _Unpaired:
    side: str
    addr: str
    name: str | None
    presence_state: str  # from function_presence; ``absent`` with no record
    export_gap: str | None


@dataclass(frozen=True)
class _Fn:
    """One function's row in a side's analysis.db."""

    name: str | None
    callees: tuple[str, ...] | None  # None: the list could not be read
    truncated: bool | None  # None: not recorded by that analysis.db
    unresolved: frozenset[str] | None  # stub addresses the extractor could not name; None: unknown


@dataclass
class _Side:
    """One side's analysis.db, as far as this view reads it."""

    error: str | None = None  # why it could not be read; None when it was
    raw: dict[str, tuple[Any, ...]] = field(default_factory=dict)  # addr -> (name, callees, …)
    names: dict[str, str] = field(default_factory=dict)  # addr -> function name
    by_name: dict[str, list[str]] = field(default_factory=dict)  # name -> addrs
    parsed: dict[str, _Fn | None] = field(default_factory=dict)

    def fn(self, addr: str) -> _Fn | None:
        """The function at ``addr``, or None when that analysis.db does not hold it."""
        if addr not in self.parsed:
            raw = self.raw.get(addr)
            self.parsed[addr] = None if raw is None else _parse_fn(raw)
        return self.parsed[addr]


def _json_list(raw: Any) -> list[Any] | None:
    if raw is None:
        return None
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, list) else None


def _parse_fn(raw: tuple[Any, ...]) -> _Fn:
    name, callees_raw, truncated, unresolved_raw, has_truncated, has_unresolved = raw
    callees = _json_list(callees_raw)
    unresolved = _json_list(unresolved_raw) if has_unresolved else None
    norm_unresolved = (
        frozenset(a for a in (norm_hex(str(u)) for u in unresolved) if a is not None)
        if unresolved is not None
        else None
    )
    return _Fn(
        name=name,
        callees=tuple(str(c) for c in callees) if callees is not None else None,
        truncated=bool(truncated) if has_truncated and truncated is not None else None,
        unresolved=norm_unresolved,
    )


def _read_side(atlas: sqlite3.Connection, run_id: str, sha: str | None) -> _Side:
    """The diffed binary's functions in the run's own analysis.db, opened read-only."""
    row = atlas.execute("SELECT analysis_db_path FROM run WHERE run_id = ?", (run_id,)).fetchone()
    if row is None or not row[0]:
        return _Side(error="the run records no analysis.db")
    if not sha:
        return _Side(error="the diff records no content hash for this side")
    try:
        conn = sqlite3.connect(f"file:{row[0]}?mode=ro", uri=True)
    except sqlite3.Error as e:
        return _Side(error=f"analysis.db could not be opened: {e}")
    try:
        found = conn.execute("SELECT id FROM binaries WHERE sha256 = ?", (sha,)).fetchone()
        if found is None:
            return _Side(error="the diffed binary is not in that analysis.db")
        cols = {r[1] for r in conn.execute("PRAGMA table_info(functions)")}
        has_t, has_u = "callees_truncated" in cols, "unresolved_external_calls" in cols
        select = "SELECT address, name, callees"
        select += ", callees_truncated" if has_t else ", NULL"
        select += ", unresolved_external_calls" if has_u else ", NULL"
        rows = conn.execute(select + " FROM functions WHERE binary_id = ?", (found[0],)).fetchall()
    except sqlite3.Error as e:
        return _Side(error=f"analysis.db could not be read: {e}")
    finally:
        conn.close()
    side = _Side()
    for address, name, callees, truncated, unresolved in rows:
        addr = norm_hex(address) if address else None
        if addr is None:
            continue
        side.raw[addr] = (name, callees, truncated, unresolved, has_t, has_u)
        if name:
            side.names[addr] = name
            side.by_name.setdefault(name, []).append(addr)
    return side


def _instance_index(
    atlas: sqlite3.Connection, run_id: str, refs: set[str]
) -> dict[str, tuple[set[str], set[str]]]:
    """evidence_ref -> (sink classes, sink names) of the run's candidate rows carrying it, for
    ``refs``: every row of the run with that ref, whichever binary it was recorded under."""
    out: dict[str, tuple[set[str], set[str]]] = {}
    wanted = sorted(refs)
    for i in range(0, len(wanted), _REF_CHUNK):
        chunk = wanted[i : i + _REF_CHUNK]
        marks = ", ".join("?" * len(chunk))
        for ref, sink_class, sink in atlas.execute(
            "SELECT i.evidence_ref, p.sink_class, i.sink_anchor FROM instance i "
            "JOIN pattern p ON i.pattern_id = p.pattern_id "
            f"WHERE i.source_run_id = ? AND i.evidence_ref IN ({marks})",
            (run_id, *chunk),
        ):
            classes, sinks = out.setdefault(ref, (set(), set()))
            if sink_class:
                classes.add(sink_class)
            sinks.add(sink or "")
    return out


def _one(values: set[str] | None) -> str | None:
    """The single value of a ref's rows; None when there is none or they disagree."""
    if not values or len(values) != 1:
        return None
    (v,) = values
    return v or None


def _thin_wrappers(atlas: sqlite3.Connection, run_id: str, sha: str | None) -> dict[str, str]:
    """Function entry -> the sink it forwards to, for the binary's thin command wrappers."""
    if not sha:
        return {}
    out: dict[str, str] = {}
    for ref, sink in atlas.execute(
        "SELECT evidence_ref, wrapped_sink FROM instance WHERE source_run_id = ? "
        "AND binary_content_hash = ? AND is_thin_cmd_wrapper = 1",
        (run_id, sha),
    ):
        entry = _func_entry_hex(ref) if ref else None
        if entry is not None and sink:
            out.setdefault(entry, sink)
    return out


@dataclass
class _Diff:
    diff_id: str
    run_a: str
    run_b: str
    binary: str | None
    sha_a: str | None
    sha_b: str | None
    wide: list[str]  # diff-wide reasons read from the diff itself
    pairs: list[_Pair]
    pair_of_a: dict[str, _Pair]
    pair_of_b: dict[str, _Pair]
    unpaired: dict[tuple[str, str], _Unpaired]
    instruction_rows: int


def _gen(atlas: sqlite3.Connection, run_id: str) -> tuple[str | None, str | None] | None:
    row = atlas.execute(
        "SELECT hunt_commit, build_hash FROM run WHERE run_id = ?", (run_id,)
    ).fetchone()
    return None if row is None else (row[0], row[1])


def _known(commit: str | None) -> bool:
    return bool(commit) and commit != UNKNOWN_VERSION


def _load_diff(atlas: sqlite3.Connection, diff_id: str) -> _Diff | None:
    meta = atlas.execute(
        "SELECT run_a_id, run_b_id, binary_a, sha256_a, sha256_b, diff_ok, version_skew "
        "FROM diff_meta WHERE diff_id = ?",
        (diff_id,),
    ).fetchone()
    if meta is None:
        return None
    run_a, run_b, binary, sha_a, sha_b, diff_ok, skew = tuple(meta)
    # The same diff-wide reasons the overlay gives its rows, read from the diff itself, so a diff
    # with no candidate at all is not listed as if it were comparable.
    wide: list[str] = []
    if not sha_a or not sha_b:
        wide.append("diff_meta_missing_sha")
    elif not diff_ok:
        wide.append("diff_failed")
    elif skew:
        wide.append("version_skew")
    else:
        ga, gb = _gen(atlas, run_a), _gen(atlas, run_b)
        if ga is not None and gb is not None:
            if ga[1] != gb[1] or (_known(ga[0]) and _known(gb[0]) and ga[0] != gb[0]):
                wide.append("extraction_generation_mismatch")
    pairs = [
        _Pair(*r)
        for r in atlas.execute(
            "SELECT addr_a, addr_b, name_a, name_b, alignment_confidence, similarity, "
            "alignment_state, export_gap_a, export_gap_b FROM function_alignment "
            "WHERE diff_id = ? ORDER BY addr_a, addr_b",
            (diff_id,),
        )
    ]
    unpaired = {
        (side, addr): _Unpaired(side, addr, name, state, gap)
        for side, addr, name, state, gap in atlas.execute(
            "SELECT side, addr, name, presence_state, export_gap FROM function_presence "
            "WHERE diff_id = ?",
            (diff_id,),
        )
    }
    n_imatch = atlas.execute(
        "SELECT COUNT(*) FROM instruction_match WHERE diff_id = ?", (diff_id,)
    ).fetchone()[0]
    return _Diff(
        diff_id=diff_id,
        run_a=run_a,
        run_b=run_b,
        binary=binary,
        sha_a=sha_a,
        sha_b=sha_b,
        wide=wide,
        pairs=pairs,
        pair_of_a={p.addr_a: p for p in pairs},
        pair_of_b={p.addr_b: p for p in pairs},
        unpaired=unpaired,
        instruction_rows=int(n_imatch),
    )


# ── entries ──────────────────────────────────────────────────────────────────────────────────


@dataclass
class _Entry:
    pair: _Pair | None
    unpaired: _Unpaired | None
    rows: list[SinkOverlayRow] = field(default_factory=list)
    bucket: str = ""
    subclass: str = ""
    tier: int | str = NO_SINK
    row_views: list[dict[str, Any]] = field(default_factory=list)
    callee_set: dict[str, Any] | None = None
    facts: list[str] = field(default_factory=list)
    blind_spots: list[str] = field(default_factory=list)
    string_edges: dict[str, Any] | None = None
    rank: dict[str, Any] = field(default_factory=dict)

    @property
    def entry_id(self) -> str:
        if self.pair is not None:
            return f"pair:{self.pair.addr_a}:{self.pair.addr_b}"
        assert self.unpaired is not None
        return f"{self.unpaired.side}:{self.unpaired.addr}"

    @property
    def address(self) -> str:
        if self.pair is not None:
            return self.pair.addr_a
        assert self.unpaired is not None
        return self.unpaired.addr


class _Builder:
    """Everything one read of the view needs, computed once."""

    def __init__(
        self,
        atlas: sqlite3.Connection,
        diff: _Diff,
        overlay: _Overlay,
        source_stale: bool | None,
    ) -> None:
        self.atlas = atlas
        self.diff = diff
        self.overlay = overlay
        self.inst = {
            "a": _instance_index(atlas, diff.run_a, {r.a_ref for r in overlay.rows if r.a_ref}),
            "b": _instance_index(atlas, diff.run_b, {r.b_ref for r in overlay.rows if r.b_ref}),
        }
        self.sides = {"a": _read_side(atlas, diff.run_a, diff.sha_a)}
        self.sides["b"] = _read_side(atlas, diff.run_b, diff.sha_b)
        self.wrappers = {
            "a": _thin_wrappers(atlas, diff.run_a, diff.sha_a),
            "b": _thin_wrappers(atlas, diff.run_b, diff.sha_b),
        }
        # Why the callee lists cannot be compared on this diff at all (None: they can).
        self.callee_block: str | None = None
        self.unavailable = [s for s in ("a", "b") if self.sides[s].error is not None]
        if source_stale is not False:
            self.callee_block = "source_stale"
        elif self.unavailable:
            self.callee_block = "analysis_db_unavailable"
        self.unattributed = 0

    # ── per-ref facts ──

    def class_of(self, side: str, ref: str | None) -> str | None:
        if ref is None:
            return None
        found = self.inst[side].get(ref)
        return _one(found[0]) if found is not None else None

    def sink_of(self, side: str, ref: str) -> str | None:
        found = self.inst[side].get(ref)
        return _one(found[1]) if found is not None else None

    # ── grouping the rows by function ──

    def entries(self) -> tuple[list[_Entry], dict[str, int]]:
        by_pair: dict[tuple[str, str], _Entry] = {}
        by_fn: dict[tuple[str, str], _Entry] = {}

        def unpaired_entry(side: str, addr: str) -> _Entry:
            key = (side, addr)
            if key not in by_fn:
                up = self.diff.unpaired.get(key) or _Unpaired(side, addr, None, "absent", None)
                by_fn[key] = _Entry(pair=None, unpaired=up)
            return by_fn[key]

        for p in self.diff.pairs:
            by_pair[(p.addr_a, p.addr_b)] = _Entry(pair=p, unpaired=None)
        for side, addr in self.diff.unpaired:
            unpaired_entry(side, addr)
        for r in self.overlay.rows:
            side, ref = ("a", r.a_ref) if r.a_ref else ("b", r.b_ref)
            fe = _func_entry_hex(ref) if ref else None
            if fe is None:
                self.unattributed += 1
                continue
            pair = (self.diff.pair_of_a if side == "a" else self.diff.pair_of_b).get(fe)
            if pair is not None:
                by_pair[(pair.addr_a, pair.addr_b)].rows.append(r)
            else:
                unpaired_entry(side, fe).rows.append(r)
        listed: list[_Entry] = []
        not_listed = {"aligned_identical_all_persisted": 0, "aligned_identical_no_candidate": 0}
        for e in [*by_pair.values(), *by_fn.values()]:
            self._place(e)
            if e.bucket:
                listed.append(e)
            elif e.rows:
                not_listed["aligned_identical_all_persisted"] += 1
            else:
                not_listed["aligned_identical_no_candidate"] += 1
        return listed, not_listed

    # ── placing one entry ──

    def _place(self, e: _Entry) -> None:
        p = e.pair
        e.row_views = [self._row_view(r, e) for r in e.rows]
        if e.rows:
            e.tier = self._tier(e.rows)
        if p is not None and p.aligned:
            e.callee_set = self._callee_set(e)
        landings = [v["landing"] for v in e.row_views]
        if e.unpaired is not None:
            e.bucket, e.subclass = "P", e.unpaired.presence_state
        elif p is not None and not p.aligned:
            gap = p.export_gap_a or p.export_gap_b
            e.bucket = "R"
            e.subclass = "degenerate_block_source" if gap else "alignment_low_confidence"
        elif "A" in landings:
            e.bucket, e.subclass = "A", "matched_call_other_callee"
        elif "R" in landings or "P" in landings:
            e.bucket = "R"
            e.subclass = next(v["subclass"] for v in e.row_views if v["landing"] in ("R", "P"))
        elif "B" in landings:
            e.bucket, e.subclass = "B", self._best_b(e)
        elif e.rows:
            if _changed(p):
                e.bucket, e.subclass = "B", "sink_present_no_visible_delta"
        elif _changed(p):
            self._place_no_candidate(e)
        if e.bucket in ("A", "B"):
            self._tag_source_gap(e)
        self._ledger(e)

    def _best_b(self, e: _Entry) -> str:
        subs: list[str] = sorted(
            {v["subclass"] for v in e.row_views if v["landing"] == "B"}, key=_b_subclass_rank
        )
        return subs[0]

    def _place_no_candidate(self, e: _Entry) -> None:
        """An aligned, changed pair with no candidate: C, unless its callees name a sink the hunt
        does not recall (B ``recall_gap_sink``), or the check cannot run (C, unchecked)."""
        assert e.pair is not None
        if self.callee_block is not None:  # the check cannot run on this diff
            e.bucket, e.subclass = "C", "no_sink_candidate_unchecked"
            return
        names, unchecked = self._both_callees(e.pair)
        for family, sinks in RECALL_GAP_SINKS.items():
            if names & set(sinks):
                e.bucket, e.subclass = "B", f"recall_gap_sink:{family}"
                return
        e.bucket = "C"
        e.subclass = "no_sink_candidate_unchecked" if unchecked else "no_sink_candidate"

    def _both_callees(self, p: _Pair) -> tuple[set[str], bool]:
        """Every callee name of the pair's two functions, and whether that list may be incomplete
        (unreadable, not held, truncated, or the diff's sources are not current)."""
        names: set[str] = set()
        unchecked = self.callee_block is not None
        for side, addr in (("a", p.addr_a), ("b", p.addr_b)):
            if self.sides[side].error is not None:
                unchecked = True
                continue
            fn = self.sides[side].fn(addr)
            if fn is None or fn.callees is None:
                unchecked = True
                continue
            names.update(fn.callees)
            if fn.truncated is not False:
                unchecked = True
        return names, unchecked

    def _tag_source_gap(self, e: _Entry) -> None:
        if e.pair is None or self.callee_block is not None:
            return
        names, _ = self._both_callees(e.pair)
        for family, prefixes in SOURCE_GAP_PREFIXES.items():
            if any(n.startswith(prefixes) for n in names):
                e.facts.append(f"source_gap:{family}")

    def _tier(self, rows: list[SinkOverlayRow]) -> int | str:
        """The highest impact tier of the entry's candidates, each side's class read from its own
        candidate record; ``unknown`` when no class could be read."""
        tiers = [
            impact_tier(cls)
            for r in rows
            for cls in (self.class_of("a", r.a_ref), self.class_of("b", r.b_ref))
            if cls is not None
        ]
        return max(tiers) if tiers else UNKNOWN

    # ── one row ──

    def _row_view(self, r: SinkOverlayRow, e: _Entry) -> dict[str, Any]:
        callee = r.counterpart_callee or {}
        elsewhere = callee.get("same_callee_candidate_elsewhere")
        in_paired = self._sink_name_in_paired(r, e)
        landing, subclass = row_landing(
            r.presence,
            r.presence_reason,
            r.counterpart_call,
            confidence=r.alignment_confidence,
            elsewhere=elsewhere if isinstance(elsewhere, bool) else None,
            sink_name_in_paired_callees=in_paired if isinstance(in_paired, bool) else None,
            presence_state=e.unpaired.presence_state if e.unpaired is not None else None,
        )
        row = asdict(r)
        del row["diff_id"], row["binary"]  # the envelope's
        view: dict[str, Any] = {
            **row,
            "landing": landing,
            "subclass": subclass,
            "class_a": self.class_of("a", r.a_ref) if r.a_ref else None,
            "class_b": self.class_of("b", r.b_ref) if r.b_ref else None,
        }
        if r.a_ref and view["class_a"] is None:
            view["class_a"] = UNKNOWN
        if r.b_ref and view["class_b"] is None:
            view["class_b"] = UNKNOWN
        if r.counterpart_call == "present_different_callee":
            labels: dict[str, Any] = {
                "mechanism": "matched_call_other_callee",
                "side": _row_side(r),
                "other_callee": [
                    c.get("name") for c in callee.get("callees") or [] if isinstance(c, dict)
                ],
                "elsewhere": elsewhere if isinstance(elsewhere, bool) else None,
            }
            if r.a_ref and r.b_ref:  # the matched instruction holds a candidate of its own
                labels["other_sink_class"] = self._other_class(r)
            view["labels"] = labels
        if r.key_granularity in _DIRECT_GRANULARITIES or r.key_granularity.endswith("wrapper"):
            view["sink_name_in_paired_callees"] = in_paired
        if r.key_granularity == _WRAPPER_FUNCTION_LEVEL:
            view["facts"] = ["wrapper_granularity_blind"]
        return view

    def _other_class(self, r: SinkOverlayRow) -> str:
        """The class of the candidate at the matched instruction. A row carries its own candidate's
        class, so when the two sides' classes differ the other one is the one that is not the
        row's; when they agree it is that class."""
        ca, cb = self.class_of("a", r.a_ref), self.class_of("b", r.b_ref)
        if ca is not None and ca == cb:
            return ca
        if r.sink_class == ca and cb is not None:
            return cb
        if r.sink_class == cb and ca is not None:
            return ca
        return UNKNOWN

    def _sink_name_in_paired(self, r: SinkOverlayRow, e: _Entry) -> bool | str:
        """Does the paired function's extracted callee list hold this row's sink name? By exact
        name, ``FUN_<addr>`` never resolved. ``unknown`` for a wrapper row, an unpaired or
        undetermined pair, or when the lists cannot be read."""
        p = e.pair
        if r.key_granularity not in _DIRECT_GRANULARITIES:
            return UNKNOWN
        if p is None or not p.aligned or self.callee_block is not None:
            return UNKNOWN
        found: list[bool | None] = []
        for side, ref, other, other_addr in (
            ("a", r.a_ref, "b", p.addr_b),
            ("b", r.b_ref, "a", p.addr_a),
        ):
            if ref is None:
                continue
            sink = self.sink_of(side, ref)
            fn = self.sides[other].fn(other_addr)
            if sink is None or fn is None or fn.callees is None:
                found.append(None)
            elif sink in fn.callees:
                found.append(True)
            else:
                found.append(False if fn.truncated is False else None)
        if not found or any(v is None for v in found) or len(set(found)) != 1:
            return UNKNOWN
        return bool(found[0])

    # ── the second signal: the two callee sets ──

    def _callee_set(self, e: _Entry) -> dict[str, Any]:
        p = e.pair
        assert p is not None
        if self.callee_block == "source_stale":
            return {"state": "undetermined", "reason": "source_stale"}
        if self.callee_block == "analysis_db_unavailable":
            return {
                "state": "undetermined",
                "reason": "analysis_db_unavailable",
                "sides": list(self.unavailable),
            }
        fa, fb = self.sides["a"].fn(p.addr_a), self.sides["b"].fn(p.addr_b)
        if fa is None or fb is None:
            missing = [s for s, f in (("a", fa), ("b", fb)) if f is None]
            return {"state": "undetermined", "reason": "not_in_inventory", "sides": missing}
        for detail, hit in (
            ("unreadable", fa.callees is None or fb.callees is None),
            ("truncated", bool(fa.truncated) or bool(fb.truncated)),
            ("not_recorded", fa.truncated is None or fb.truncated is None),
        ):
            if hit:  # the list may be a prefix, so a name missing from it proves nothing
                return {"state": "undetermined", "reason": "callees_truncated", "detail": detail}
        ia, ua = self._identities("a", fa)
        ib, ub = self._identities("b", fb)
        if ua or ub:
            out: dict[str, Any] = {
                "state": "undetermined",
                "reason": "callee_identity_unresolved",
                "unresolved_a": sorted(ua),
                "unresolved_b": sorted(ub),
            }
            named_a = {n for k, n in ia.items() if k[0] == "name"}
            named_b = {n for k, n in ib.items() if k[0] == "name"}
            if named_a != named_b:
                out["named_callees_differ"] = {
                    "only_in_a": sorted(named_a - named_b),
                    "only_in_b": sorted(named_b - named_a),
                }
                self._one_hop(e, out["named_callees_differ"]["only_in_a"], "a")
                self._one_hop(e, out["named_callees_differ"]["only_in_b"], "b")
            return out
        if ia.keys() == ib.keys():
            e.facts.append("callee_set_unchanged")
            return {"state": "equal"}
        only_a = sorted(ia[k] for k in ia.keys() - ib.keys())
        only_b = sorted(ib[k] for k in ib.keys() - ia.keys())
        self._one_hop(e, only_a, "a")
        self._one_hop(e, only_b, "b")
        return {"state": "differs", "only_in_a": only_a, "only_in_b": only_b}

    def _identities(self, side: str, fn: _Fn) -> tuple[dict[tuple[str, ...], str], set[str]]:
        """(identity -> the name as printed, the names that cannot be identified) of one function's
        callees. A ``FUN_<addr>`` name is the function at that address, identified by its aligned
        pair; a stub the extractor could not name, or a function with no aligned pair, cannot be
        identified. Every other name is itself."""
        pair_of = self.diff.pair_of_a if side == "a" else self.diff.pair_of_b
        idents: dict[tuple[str, ...], str] = {}
        unresolved: set[str] = set()
        for name in fn.callees or ():
            m = _FUN_RE.fullmatch(name)
            if m is None:
                idents[("name", name)] = name
                continue
            addr = norm_hex(m.group(1))
            pair = pair_of.get(addr) if addr is not None else None
            if fn.unresolved is None or addr is None or addr in fn.unresolved:
                unresolved.add(name)
            elif pair is None or not pair.aligned:
                unresolved.add(name)
            else:
                idents[("pair", pair.addr_a, pair.addr_b)] = name
        return idents, unresolved

    def _one_hop(self, e: _Entry, names: list[str], side: str) -> None:
        """Mark a callee only one side calls that is a thin command wrapper of that side."""
        wrappers = self.wrappers[side]
        for name in names:
            m = _FUN_RE.fullmatch(name)
            addrs = (
                [a for a in [norm_hex(m.group(1))] if a is not None]
                if m is not None
                else self.sides[side].by_name.get(name, [])
            )
            for addr in addrs:
                if addr in wrappers:
                    e.facts.append(f"one_hop_sink:{wrappers[addr]}")
                    break

    # ── the ledger ──

    def _ledger(self, e: _Entry) -> None:
        spots: list[str] = []
        cs = e.callee_set or {}
        if cs.get("state") == "undetermined":
            reason = cs["reason"]
            if reason == "analysis_db_unavailable":
                spots += [f"analysis_db_unavailable:{s}" for s in cs.get("sides", [])]
            else:
                spots.append(reason)
        if e.subclass == "no_sink_candidate_unchecked":
            spots.append(e.subclass)
        if e.subclass.startswith("recall_gap_sink:"):
            spots.append(e.subclass)
        spots += [f for f in e.facts if f.startswith("source_gap:")]
        for v in e.row_views:
            if "wrapper_granularity_blind" in v.get("facts", ()):
                spots.append("wrapper_granularity_blind")
            if (v["subclass"] or "").startswith("unmapped_reason:"):
                spots.append("unmapped_reason")
            if v["presence_reason"] == "instruction_unmatched":
                spots.append("a_requires_matched_candidate_instruction")
        e.blind_spots = sorted(set(spots))


def _changed(p: _Pair | None) -> bool:
    """A pair whose similarity is below 1 (or unrecorded, which cannot be called identical)."""
    return p is not None and (p.similarity is None or p.similarity < 1.0)


def _b_subclass_rank(subclass: str) -> tuple[int, str]:
    return (0 if subclass.startswith(_SPS) else 1, subclass)


def _row_side(r: SinkOverlayRow) -> str:
    if r.a_ref and r.b_ref:
        return "both"
    return "a_only" if r.a_ref else "b_only"


# ── order ───────────────────────────────────────────────────────────────────────────────────


def _tier_value(tier: int | str) -> int:
    """A tier as a number to sort by, highest first: an unreadable tier is never sorted below a
    known one (an unknown is not a low)."""
    if tier == UNKNOWN:
        return 99
    if tier == NO_SINK:
        return -1
    assert isinstance(tier, int)
    return tier


def _rank(e: _Entry) -> dict[str, Any]:
    """The named components the entry is sorted by (segment first, then in the listed order)."""
    sim = e.pair.similarity if e.pair is not None else None
    sim_key = -1.0 if sim is None else sim  # an unrecorded similarity is never sorted last
    t = _tier_value(e.tier)
    b_rank = 0
    if e.bucket == "B":
        wrapper_b = any(
            v["landing"] == "B" and "wrapper_granularity_blind" in v.get("facts", ())
            for v in e.row_views
        )
        b_rank = 0 if e.subclass.startswith(_SPS) or wrapper_b else 1
    if e.bucket == "P":
        side = e.unpaired.side if e.unpaired is not None else ""
        return {"segment": 4, "tier": t, "side": side, "address": e.address}
    if e.bucket == "A":
        return {"segment": 1, "tier": t, "similarity": sim_key, "address": e.address}
    if e.tier != NO_SINK:
        return {
            "segment": 2,
            "tier": t,
            "lane": 0 if e.bucket == "R" else 1,
            "subclass_rank": b_rank,
            "similarity": sim_key,
            "address": e.address,
        }
    lane = 0 if e.bucket == "B" else (1 if e.bucket == "R" else 2)
    return {
        "segment": 3,
        "lane": lane,
        "subclass_rank": 0 if e.subclass == "no_sink_candidate_unchecked" else 1,
        "similarity": sim_key,
        "address": e.address,
    }


def _default_key(r: dict[str, Any]) -> tuple[Any, ...]:
    seg = r["segment"]
    if seg == 1:
        return (1, -r["tier"], 0, 0, r["similarity"], "", r["address"])
    if seg == 2:
        return (2, -r["tier"], r["lane"], r["subclass_rank"], r["similarity"], "", r["address"])
    if seg == 3:
        return (3, r["lane"], r["subclass_rank"], 0, r["similarity"], "", r["address"])
    return (4, -r["tier"], 0, 0, 0.0, r["side"], r["address"])


def _sort(entries: list[_Entry], sort_by: str | None) -> list[_Entry]:
    """The default order, or ``sort_by`` (one named component) ahead of it. P stays last either
    way: a function with no counterpart is not ordered among the pairs."""

    def key(e: _Entry) -> tuple[Any, ...]:
        r = e.rank
        p_last = 1 if r["segment"] == 4 else 0
        if sort_by == "tier":
            head: tuple[Any, ...] = (-r["tier"] if "tier" in r else 1,)
        elif sort_by == "similarity":
            head = (r.get("similarity", 0.0),)
        elif sort_by == "address":
            head = (r["address"],)
        else:
            head = ()
        return (p_last, *head, *_default_key(r))

    return sorted(entries, key=key)


# ── output ──────────────────────────────────────────────────────────────────────────────────


def _string_edges(atlas: sqlite3.Connection, diff_id: str) -> tuple[int, dict[str, Any]]:
    """(edge rows, entry key -> their summary) of the diff's string-keyed edge deltas, attached to
    the function a strcmp-gate edge is anchored at (``b:<addr>`` = a B function with no aligned
    pair). A secondary signal: it never places an entry."""
    rows = atlas.execute(
        "SELECT subject_key, delta_kind FROM dimension_delta "
        "WHERE diff_id = ? AND subject_kind != 'candidate' ORDER BY id",
        (diff_id,),
    ).fetchall()
    by_anchor: dict[str, dict[str, Any]] = {}
    for subject_key, delta_kind in rows:
        parts = subject_key.split("|")
        if len(parts) < 4 or parts[1] != "strcmp_gate":
            continue
        anchor = parts[-1]
        side, raw = ("b", anchor[2:]) if anchor.startswith("b:") else ("a", anchor)
        addr = norm_hex(raw) if raw else None
        if addr is None:
            continue
        s = by_anchor.setdefault(f"{side}:{addr}", {"by_delta_kind": {}, "changed": []})
        s["by_delta_kind"][delta_kind] = s["by_delta_kind"].get(delta_kind, 0) + 1
        if delta_kind == "layer_changed" and len(s["changed"]) < 20:
            s["changed"].append(subject_key)
    return len(rows), by_anchor


def _entry_json(e: _Entry) -> dict[str, Any]:
    out: dict[str, Any] = {
        "entry_id": e.entry_id,
        "bucket": e.bucket,
        "subclass": e.subclass,
        "subclasses": sorted({v["subclass"] for v in e.row_views if v["subclass"]}),
        "tier": e.tier,
        "rank_key": e.rank,
    }
    if e.pair is not None:
        p = e.pair
        out.update(
            {
                "addr_a": p.addr_a,
                "addr_b": p.addr_b,
                "name_a": p.name_a,
                "name_b": p.name_b,
                "similarity": p.similarity,
                "alignment_confidence": p.confidence,
                "alignment_state": p.state,
                "export_gap_a": p.export_gap_a,
                "export_gap_b": p.export_gap_b,
            }
        )
    else:
        assert e.unpaired is not None
        u = e.unpaired
        out.update(
            {
                "side": u.side,
                "addr": u.addr,
                "name": u.name,
                "presence_state": u.presence_state,
                "export_gap": u.export_gap,
            }
        )
    coclaimed = sorted(
        {f"a:{f}" for v in e.row_views for f in v["coclaimed_by"] or ()}
        | {f"b:{f}" for v in e.row_views for f in v["coclaimed_by_b"] or ()}
    )
    out.update(
        {
            "coclaimed_by": coclaimed or None,
            "callee_set": e.callee_set,
            "facts": sorted(set(e.facts)),
            "blind_spots": e.blind_spots,
            "string_edges": e.string_edges,
            "rows": e.row_views,
        }
    )
    return out


def _ledger(
    entries: list[_Entry], rows_by_spot: dict[str, int], unavailable: dict[str, str]
) -> list[dict[str, Any]]:
    """The blind-spot ledger: each counted spot with how many entries (or candidate rows) it
    covers and a sample of the entries; page through all of them with ``blind_spot=<key>``."""
    members: dict[str, list[str]] = {k: [] for k, n in rows_by_spot.items() if n}
    for e in entries:
        for spot in e.blind_spots:
            members.setdefault(spot, []).append(e.entry_id)
    out: list[dict[str, Any]] = []
    for spot in sorted(members):
        unit = "candidate_row" if spot in rows_by_spot else "entry"
        item: dict[str, Any] = {
            "key": spot,
            "count": rows_by_spot.get(spot, len(members[spot])),
            "unit": unit,
            "entries": len(members[spot]),  # the listed entries it covers
            "sample": members[spot][:10],
            "page_with": f"blind_spot={spot}",
        }
        side = spot.rpartition(":")[2] if spot.startswith("analysis_db_unavailable:") else None
        if side is not None:
            item["detail"] = unavailable.get(side)
        out.append(item)
    for key, why in _STRUCTURAL_BLIND_SPOTS.items():
        out.append({"key": key, "count": None, "unit": None, "note": why})
    return out


def _check_args(
    view: str,
    sort_by: str | None,
    bucket: str | None,
    tier: str | int | None,
    limit: Any,
    offset: Any,
    filtered: bool,
) -> str | None:
    if view not in VIEWS:
        return f"view must be one of {VIEWS}, got {view!r}"
    if sort_by is not None and sort_by not in SORT_BY:
        return f"sort_by must be one of {SORT_BY} or null, got {sort_by!r}"
    if bucket is not None and bucket not in BUCKETS:
        return f"bucket must be one of {BUCKETS} or null, got {bucket!r}"
    if tier is not None and str(tier) not in (NO_SINK, UNKNOWN) and not str(tier).isdigit():
        return f"tier must be a number, 'no_sink' or 'unknown', got {tier!r}"
    if view != "sink_patch" and (filtered or sort_by is not None):
        return "sort_by / bucket / subclass / tier / blind_spot apply to view='sink_patch' only"
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LIMIT:
        return f"limit must be an integer in 1..{MAX_LIMIT}, got {limit!r}"
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        return f"offset must be an integer >= 0, got {offset!r}"
    return None


def get_diff_patch_view(
    atlas: sqlite3.Connection,
    diff_id: str,
    *,
    view: str = "sink_patch",
    sort_by: str | None = None,
    bucket: str | None = None,
    subclass: str | None = None,
    tier: str | int | None = None,
    blind_spot: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> dict[str, Any]:
    """The function-level view of one diff (see the module docstring), one page of it.

    ``view``: ``sink_patch`` (function pairs, the default), ``string_edge`` (get_diff_deltas'
    rows), ``candidate_flat`` (get_diff_sink_overlay's rows, in its order). The filters and
    ``sort_by`` apply to ``sink_patch``; ``counts`` / ``not_listed`` / ``blind_spots`` always
    describe the whole diff. Pages are in a fixed order; follow ``next_offset`` until null."""
    filters = {"bucket": bucket, "subclass": subclass, "tier": tier, "blind_spot": blind_spot}
    filtered = any(v is not None for v in filters.values())
    error = _check_args(view, sort_by, bucket, tier, limit, offset, filtered)
    if error is not None:
        return {"diff_id": diff_id, "error": error}
    diff = _load_diff(atlas, diff_id)
    if diff is None:
        return {"diff_id": diff_id, "found": False, "error": "no such diff (see list_diffs)"}
    staleness = diff_source_staleness(atlas, diff_id)
    overlay = read_overlay_rows(atlas, diff_id, diff.run_a, diff.run_b)
    n_edges, edges_by_anchor = _string_edges(atlas, diff_id)

    banners: list[str] = []
    row_wide = sorted(
        {
            r.presence_reason
            for r in overlay.rows
            if r.presence_reason in _DIFF_WIDE or r.presence_reason in _RUN_PAIR
        }
    )
    for reason in sorted(set(diff.wide) | set(row_wide)):
        banners.append(f"diff_undetermined:{reason}")
    if diff.instruction_rows == 0:
        # No instruction pairs were stored for this diff: no candidate call can be matched to an
        # instruction, so A cannot occur here, whatever changed.
        banners.append("instruction_data_absent")
    if overlay.coverage is not None and overlay.coverage.get("coverage_violation"):
        banners.append("overlay_coverage_violation")

    entries: list[_Entry] = []
    not_listed = {"aligned_identical_all_persisted": 0, "aligned_identical_no_candidate": 0}
    withheld: dict[str, Any] | None = None
    unavailable: dict[str, str] = {}
    unattributed = 0
    if any(b.startswith("diff_undetermined:") for b in banners):
        by_reason: dict[str, int] = {}
        for r in overlay.rows:
            k = r.presence_reason or r.presence
            by_reason[k] = by_reason.get(k, 0) + 1
        withheld = {
            "function_pairs": len(diff.pairs),
            "unpaired_functions": len(diff.unpaired),
            "candidate_rows_by_reason": dict(sorted(by_reason.items())),
        }
    else:
        builder = _Builder(atlas, diff, overlay, staleness["source_stale"])
        entries, not_listed = builder.entries()
        unattributed = builder.unattributed
        unavailable = {s: str(builder.sides[s].error) for s in builder.unavailable}
        for e in entries:
            key = f"a:{e.pair.addr_a}" if e.pair is not None else e.entry_id
            e.string_edges = edges_by_anchor.get(key)
            e.rank = _rank(e)
    if unattributed:
        banners.append(f"overlay_rows_unattributed:{unattributed}")

    # Counted over every overlay row of the diff, listed entry or not.
    rows_by_spot = {
        "a_requires_matched_candidate_instruction": sum(
            1 for r in overlay.rows if r.presence_reason == "instruction_unmatched"
        ),
        "wrapper_granularity_blind": sum(
            1 for r in overlay.rows if r.key_granularity == _WRAPPER_FUNCTION_LEVEL
        ),
        "unmapped_reason": sum(
            1
            for e in entries
            for v in e.row_views
            if (v["subclass"] or "").startswith("unmapped_reason:")
        ),
    }
    counts = {
        "by_bucket": _count(e.bucket for e in entries),
        "by_subclass": _count(f"{e.bucket}|{e.subclass}" for e in entries),
        "by_tier": _count(str(e.tier) for e in entries),
        "by_row_subclass": _count(
            f"{v['landing']}|{v['subclass']}"
            for e in entries
            for v in e.row_views
            if v["landing"] != "persisted"
        ),
    }
    if withheld is not None:
        counts["withheld"] = withheld
    subject_counts = {
        "function_pair": len(entries),
        "candidate_row": len(overlay.rows),
        "string_edge": n_edges,
    }
    envelope: dict[str, Any] = {
        "diff_id": diff_id,
        "lens": {
            "view": view,
            "order": (
                "A; then the R and B entries carrying a sink candidate (tier, R before B, "
                "sink_presence_signal first, similarity, address); then the entries with none "
                "(recall_gap_sink, R, C); then P"
            ),
            "sort_by": sort_by or "default",
            "filters": filters,
            "switchable": "view / sort_by / bucket / subclass / tier / blind_spot",
        },
        "subject_unit": {
            "sink_patch": "function_pair",
            "string_edge": "string_edge",
            "candidate_flat": "candidate_row",
        }[view],
        "subject_counts": subject_counts,
        "available_views": {
            "sink_patch": "one entry per function pair (or function with no counterpart)",
            "string_edge": "the string-keyed edge deltas (get_diff_deltas)",
            "candidate_flat": "the candidate overlay rows (get_diff_sink_overlay)",
        },
        "legend": _LEGEND,
        "caveats": _CAVEATS,
        "baseline_state": overlay.baseline_state,
        **staleness,
        "banners": banners,
        "counts": counts,
        "not_listed": not_listed,
        "blind_spots": _ledger(entries, rows_by_spot, unavailable),
        "overlay_coverage": overlay.coverage,
    }
    if view == "string_edge":
        deltas = get_diff_deltas(atlas, diff_id, limit=limit, offset=offset)
        page = deltas["page"]
        envelope.update(
            {
                "entries": deltas["deltas"],
                "total_entries": page["count"],
                "next_offset": page["next_offset"],
            }
        )
        return envelope
    if view == "candidate_flat":
        flat = page_overlay(overlay.rows, limit=limit, offset=offset)
        envelope.update(
            {
                "entries": [asdict(r) for r in flat["rows"]],
                "total_entries": flat["total_rows"],
                "next_offset": flat["next_offset"],
            }
        )
        return envelope
    chosen = [e for e in entries if _matches(e, bucket, subclass, tier, blind_spot)]
    ordered = _sort(chosen, sort_by)
    end = offset + limit
    envelope.update(
        {
            "entries": [_entry_json(e) for e in ordered[offset:end]],
            "total_entries": len(ordered),
            "next_offset": end if end < len(ordered) else None,
        }
    )
    return envelope


def _matches(
    e: _Entry,
    bucket: str | None,
    subclass: str | None,
    tier: str | int | None,
    blind_spot: str | None,
) -> bool:
    if bucket is not None and e.bucket != bucket:
        return False
    if subclass is not None and subclass != e.subclass:
        if subclass not in {v["subclass"] for v in e.row_views}:
            return False
    if tier is not None and str(tier) != str(e.tier):
        return False
    return blind_spot is None or blind_spot in e.blind_spots


def _count(keys: Any) -> dict[str, int]:
    out: dict[str, int] = {}
    for k in keys:
        out[k] = out.get(k, 0) + 1
    return dict(sorted(out.items()))
