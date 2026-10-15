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
  B  a sink candidate whose cross-side reading stayed undetermined; a persisted candidate whose
     length constant changed (``sink_arg_constant_delta`` — visible even at similarity 1); a
     changed pair whose candidates all line up (``sink_present_no_visible_delta``); or a changed
     pair with no candidate that calls a sink the hunt does not recall
     (``recall_gap_sink:<family>``).
  R  the pair itself is undetermined (its alignment confidence is low, or its export could not hold
     one of the two functions as it is).
  C  a changed pair (similarity below 1) with no sink candidate on either side.
  P  a function with no counterpart (``presence_state`` from function_presence, ``absent`` when the
     function has no presence record at all).
A similarity-1 pair whose candidates all line up, or that has none, places no entry UNLESS a length
constant changed on one of its candidates (then it is B ``sink_arg_constant_delta``); the rest are
counted under ``not_listed`` by ``pseudocode_sameness`` (below), never dropped. Where each overlay
``presence_reason`` lands is ``row_landing``; a reason it does not know lands in B as
``unmapped_reason:<reason>`` and is counted, never dropped.

THE SECOND SIGNAL (``callee_set``): for an aligned pair, the two functions' extracted callee lists
compared as sets. A ``FUN_<addr>`` callee is compared by address through this diff's alignment,
never by name; one that cannot be mapped (or is a stub the extractor could not name) makes the
comparison undetermined. It never moves an entry between buckets: an entry with a sink candidate
is never C because its callees look unchanged.

TWO SIGNALS SIMILARITY IS BLIND TO (lib/query/sameness), read on the function-pair view only:
  ``pseudocode_sameness`` — an aligned pair's honest state, folding an address-normalised pseudocode
  comparison with ``callee_set``: ``identical`` (both agree, nothing left unverified),
  ``identical_text_unverified`` (the text matches but rests on something unchecked — an unknown
  image extent, a decompile marked incomplete, two body byte counts that differ; named in
  ``text_unverified_reasons``, with the ``hidden_region`` facts behind it),
  ``identical_callee_unverified`` (text matches, callees unverified), ``differs``, ``no_body`` (an
  import/PLT stub, not in the functions table) or ``unavailable`` (in the table, empty body). None
  of the unverified states is ever read as "unchanged". On every listed aligned entry as a fact; the
  similarity-1 pairs that place no entry are counted by it under ``not_listed``
  (``not_listed_page=<name>`` walks one category, ``aligned_pseudocode_differs`` above all). A pair
  whose texts differ carries ``pseudocode_delta``, the lexical shape of the difference. An
  undetermined pair carries ``proposed_pair_reading`` instead — the same reading as if it were
  paired, with whether its body is unique on each side — beside the entry, never its pairing; it
  moves no entry between buckets.
  ``sink_arg_constant_delta`` — a persisted candidate whose size constant moved (0x40 -> 0x3f),
  with the callee and from/to, direction-neutral. A changed size KIND is the weaker
  ``size_kind_shifted``.
  Reading pseudocode is the costly half, so it is computed in get_diff_patch_view (cached per
  diff + content + build), never in build_diff_view — annotate/promote and the progress block stay
  cheap. A pseudocode_delta is computed only for the page being rendered.

ORDER: A first, then the R and B entries that carry a sink candidate, then the entries with none,
then P; inside each, by the named components of ``rank_key`` (visible on every entry). ``tier`` is
the sink-impact tier of the entry's candidates (lib/query/sink_impact), ``no_sink`` without any.

JUDGEMENTS are a separate, writable layer (lib/query/diff_review, written by lib/overlay.py): the
view stays read-only and its facts never change because of one. Every entry carries its
``anchor_ref`` and ``review_state`` and the envelope ``review_progress`` and ``annotation``, with
or without any judgement; only with ``band`` on do they move entries, and then only among entries
the default order already holds together.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import asdict, dataclass, field, replace
from typing import Any

from treasure_map.lib.diff.layer0 import norm_hex
from treasure_map.lib.query import diff_review, sameness
from treasure_map.lib.query.coverage import CONCLUDED, NEEDS_RECHECK, NEEDS_RELABEL, OPEN
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
from treasure_map.lib.ro_db import ro_connect
from treasure_map.version import UNKNOWN_VERSION

VIEWS = ("sink_patch", "string_edge", "candidate_flat")
BUCKETS = ("A", "B", "C", "R", "P")
SORT_BY = ("tier", "similarity", "address", "significance")
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
    "size_constant_outside_sink_arg": (
        "sink_arg_constant_delta reads only a copy / formatter call's own length argument; a "
        "constant that changed inside an allocation or realloc length expression feeding the "
        "buffer is not seen"
    ),
    "local_buffer_size_unread": (
        "the size of a local array or source buffer is not compared (only the call's length "
        "argument is), so a changed buffer declaration with an unchanged length argument is not "
        "seen"
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
    instructions: int | None = None  # BinDiff's matched-instruction count, as stored

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
        conn = ro_connect(row[0])
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


@dataclass
class _Inst:
    """What one candidate's rows carry, folded: its sink classes and names (the first non-null,
    candidates of one ref agreeing)."""

    classes: set[str] = field(default_factory=set)
    sinks: set[str] = field(default_factory=set)


def _instance_index(atlas: sqlite3.Connection, run_id: str, refs: set[str]) -> dict[str, _Inst]:
    """evidence_ref -> its folded candidate facts, for ``refs``: every row of the run with that ref,
    whichever binary it was recorded under."""
    out: dict[str, _Inst] = {}
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
            inst = out.setdefault(ref, _Inst())
            if sink_class:
                inst.classes.add(sink_class)
            inst.sinks.add(sink or "")
    return out


# evidence_ref -> (size_kind, size_arg) for a run's size-bearing candidates, cached per run and the
# run row's build hash, hunt commit and last update: read once by json_extract, not the per-diff IN
# scan, so the length-constant signal does not re-scan the whole run for every diff of a pair. The
# run's stamps are in the key so a re-extraction or a re-hunt (same run id, new evidence) is not
# served a stale fact.
_SIZE_FACT_CACHE: dict[tuple[str, ...], dict[str, tuple[str, str | None]]] = {}


def _size_facts(atlas: sqlite3.Connection, run_id: str) -> dict[str, tuple[str, str | None]]:
    """evidence_ref -> (size_kind, size_arg) for the run's candidates that carry a size axis."""
    row = atlas.execute(
        "SELECT build_hash, hunt_commit, updated_at FROM run WHERE run_id = ?", (run_id,)
    ).fetchone()
    key = (run_id, *(str(v or "") for v in (row or (None, None, None))))
    hit = _SIZE_FACT_CACHE.get(key)
    if hit is not None:
        return hit
    out: dict[str, tuple[str, str | None]] = {}
    for ref, kind, arg in atlas.execute(
        "SELECT evidence_ref, json_extract(flow_evidence, '$.size_kind'), "
        "json_extract(flow_evidence, '$.size_flow.size_arg') FROM instance WHERE source_run_id = ?",
        (run_id,),
    ):
        if kind is not None and ref not in out:
            out[ref] = (kind, arg)
    _SIZE_FACT_CACHE[key] = out
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
            "alignment_state, export_gap_a, export_gap_b, instructions FROM function_alignment "
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
    # An undetermined pair's callee lists compared the same way, for its proposed reading only: it
    # adds no fact and moves nothing.
    proposed_callee_set: dict[str, Any] | None = None
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
        self.size_facts = {"a": _size_facts(atlas, diff.run_a), "b": _size_facts(atlas, diff.run_b)}
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
        self.placed: list[_Entry] = []

    # ── per-ref facts ──

    def class_of(self, side: str, ref: str | None) -> str | None:
        if ref is None:
            return None
        found = self.inst[side].get(ref)
        return _one(found.classes) if found is not None else None

    def sink_of(self, side: str, ref: str) -> str | None:
        found = self.inst[side].get(ref)
        return _one(found.sinks) if found is not None else None

    def size_fact(self, side: str, ref: str) -> tuple[str | None, str | None]:
        """(size_kind, size_arg) of a candidate's size axis, (None, None) when it has none."""
        return self.size_facts[side].get(ref, (None, None))

    # ── grouping the rows by function ──

    def entries(self) -> list[_Entry]:
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
        self.placed = [*by_pair.values(), *by_fn.values()]
        for e in self.placed:
            self._place(e)
        # A placed entry with no bucket is an aligned, similarity-1 pair that places no entry; the
        # read face names those by pseudocode_sameness (lib/query/sameness) — a read that reads
        # pseudocode, kept out of this build so annotate/promote never pay for it.
        return [e for e in self.placed if e.bucket]

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
            e.proposed_callee_set = self._callee_comparison(p)
        elif "A" in landings:
            e.bucket, e.subclass = "A", "matched_call_other_callee"
        elif "R" in landings or "P" in landings:
            e.bucket = "R"
            e.subclass = next(v["subclass"] for v in e.row_views if v["landing"] in ("R", "P"))
        elif "B" in landings:
            e.bucket, e.subclass = "B", self._best_b(e)
        elif any("sink_arg_constant_delta" in v for v in e.row_views):
            # A length constant changed on a persisted candidate — visible even at similarity 1,
            # where this pair would otherwise not be listed at all.
            e.bucket, e.subclass = "B", "sink_arg_constant_delta"
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
        """The highest impact tier of the entry's candidates; ``unknown`` when no class could be
        read.

        A row carries its own candidate's class (``sink_class``), so that side is never looked up:
        a candidate record that resolves to several classes cannot take away the class the row
        already states. Only the other side's candidate is read from its own record, and when that
        cannot be read (no record, or records that disagree) only that side drops out. A row naming
        a candidate on both sides does not record which of the two it carries, so both are read;
        the one that is its own adds nothing new."""
        tiers = [
            impact_tier(cls)
            for r in rows
            for cls in (
                r.sink_class or None,
                self.class_of("a", r.a_ref) if r.b_ref else None,
                self.class_of("b", r.b_ref) if r.a_ref else None,
            )
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
        if r.a_ref and r.b_ref:  # a persisted candidate: its two sides' length constants compare
            (ak, aa), (bk, bb) = self.size_fact("a", r.a_ref), self.size_fact("b", r.b_ref)
            delta = sameness.const_delta(ak, aa, bk, bb)
            if delta is not None:
                view["sink_arg_constant_delta"] = {
                    **delta,
                    "callee": self.sink_of("a", r.a_ref) or self.sink_of("b", r.b_ref),
                }
            shift = sameness.kind_shift(ak, bk)
            if shift is not None:  # mutually exclusive with a delta (same kind vs changed kind)
                view["size_kind_shifted"] = shift
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
        """An aligned pair's callee comparison, with the facts it adds to the entry: a callee only
        one side calls that is a thin command wrapper (``one_hop_sink``), and
        ``callee_set_unchanged``."""
        p = e.pair
        assert p is not None
        out = self._callee_comparison(p)
        named = out.get("named_callees_differ")
        if named is not None:
            self._one_hop(e, named["only_in_a"], "a")
            self._one_hop(e, named["only_in_b"], "b")
        elif out["state"] == "equal":
            e.facts.append("callee_set_unchanged")
        elif out["state"] == "differs":
            self._one_hop(e, out["only_in_a"], "a")
            self._one_hop(e, out["only_in_b"], "b")
        return out

    def _callee_comparison(self, p: _Pair) -> dict[str, Any]:
        """The two functions' callee lists compared as sets — no side effect, so an undetermined
        pair's proposed reading can use it without adding a fact to its entry."""
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
            return out
        if ia.keys() == ib.keys():
            return {"state": "equal"}
        only_a = sorted(ia[k] for k in ia.keys() - ib.keys())
        only_b = sorted(ib[k] for k in ib.keys() - ia.keys())
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
        # sink_presence_signal first, then sink_arg_constant_delta (a visible length change),
        # then the rest (sink_present_no_visible_delta and the undetermined B subclasses).
        if e.subclass.startswith(_SPS) or wrapper_b:
            b_rank = 0
        elif e.subclass == "sink_arg_constant_delta":
            b_rank = 1
        else:
            b_rank = 2
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


def _default_key(r: dict[str, Any], band: int = 0) -> tuple[Any, ...]:
    """The default order's key. ``band`` (the judgement band, 0 when it is off) sits after the
    first four components and before similarity, so it only ever reorders entries those four
    already hold together — never across a segment, a tier, a lane or a subclass rank."""
    seg = r["segment"]
    if seg == 1:
        return (1, -r["tier"], 0, 0, band, r["similarity"], "", r["address"])
    if seg == 2:
        return (
            2,
            -r["tier"],
            r["lane"],
            r["subclass_rank"],
            band,
            r["similarity"],
            "",
            r["address"],
        )
    if seg == 3:
        return (3, r["lane"], r["subclass_rank"], 0, band, r["similarity"], "", r["address"])
    return (4, -r["tier"], 0, 0, band, 0.0, r["side"], r["address"])


# ── the significance lens (sort_by="significance"): an opt-in order, never a relabel ──────────

# attention 0 floats, 1 is the similarity-ordered middle, 2 sinks; every entry stays listed.
ATTENTION_FLOAT, ATTENTION_MIDDLE, ATTENTION_SINK = 0, 1, 2


def _held_up(item: diff_review.Item | None) -> bool:
    """A judgement that must keep its entry off the bottom tier: judged changed_real, due a
    re-check or a relabel, or left inconclusive. A lens never buries what an agent marked."""
    if item is None:
        return False
    if item.state in (NEEDS_RECHECK, NEEDS_RELABEL, OPEN):
        return True
    return item.state == CONCLUDED and item.verdict == "changed_real"


def significance(
    e: _Entry,
    state: str | None,
    item: diff_review.Item | None,
    u_state: str | None = None,
) -> tuple[int, str]:
    """``(attention, basis)`` of one listed entry under the significance lens, from facts the view
    already holds (bucket, the rows' sink_arg_constant_delta, pseudocode_sameness, an undetermined
    pair's proposed reading ``u_state``, the entry's review state) — nothing re-derived, no verdict.
    In order:

      * bucket A, or a row carrying sink_arg_constant_delta -> 0 (wins over everything below);
      * B ``sink_present_no_visible_delta`` -> 1, labelled ``recheckable_no_visible_delta``: it
        stays where similarity puts it, neither floated nor sunk;
      * pseudocode ``identical``, a proposed ``identical_unique``, or bucket C -> 2 — unless the
        entry is R (an undetermined pair is never buried under the pairs that were read) or its
        judgement is held up (changed_real, needs_recheck / needs_relabel, inconclusive), which
        stops it at 1;
      * everything else -> 1, ordered by similarity, lowest first. ``identical_text_unverified``
        is never sunk outside C."""
    if e.bucket == "A":
        return ATTENTION_FLOAT, "matched_call_other_callee"
    if any("sink_arg_constant_delta" in v for v in e.row_views):
        return ATTENTION_FLOAT, "sink_arg_constant_delta"
    if e.subclass == "sink_present_no_visible_delta":
        return ATTENTION_MIDDLE, "recheckable_no_visible_delta"
    if state == sameness.IDENTICAL or u_state == sameness.U_IDENTICAL_UNIQUE or e.bucket == "C":
        basis = "pseudocode_identical" if state == sameness.IDENTICAL else "no_sink_candidate"
        if e.bucket == "R":
            return ATTENTION_MIDDLE, "undetermined_never_sunk"
        if _held_up(item):
            return ATTENTION_MIDDLE, "judged_never_sunk"
        return ATTENTION_SINK, basis
    if e.bucket == "P":
        return ATTENTION_MIDDLE, "no_counterpart"
    return ATTENTION_MIDDLE, "similarity"


def _sort(
    entries: list[_Entry],
    sort_by: str | None,
    band: dict[str, int] | None = None,
    attention: dict[str, int] | None = None,
    settled: dict[str, int] | None = None,
) -> list[_Entry]:
    """The default order, or ``sort_by`` (one named component) ahead of it. P stays last either
    way: a function with no counterpart is not ordered among the pairs. ``band`` maps an entry id
    to its judgement band (diff_review.band_bias); None leaves the order as it is.

    ``sort_by="significance"`` orders by ``(attention, band, settled, similarity, default key)`` —
    ``attention`` from :func:`significance`, the band only when it is on (judgements move nothing
    unless asked), ``settled`` (1 for an R entry whose proposed reading is ``identical_unique``,
    so it closes its tier, still ahead of every sunk entry), similarity lowest first, then the
    default order."""

    def key(e: _Entry) -> tuple[Any, ...]:
        r = e.rank
        p_last = 1 if r["segment"] == 4 else 0
        if sort_by == "significance":
            return (
                p_last,
                (attention or {}).get(e.entry_id, ATTENTION_MIDDLE),
                band.get(e.entry_id, 0) if band else 0,
                (settled or {}).get(e.entry_id, 0),
                r.get("similarity", -1.0),
                *_default_key(r, 0),
            )
        if sort_by == "tier":
            head: tuple[Any, ...] = (-r["tier"] if "tier" in r else 1,)
        elif sort_by == "similarity":
            head = (r.get("similarity", 0.0),)
        elif sort_by == "address":
            head = (r["address"],)
        else:
            head = ()
        return (p_last, *head, *_default_key(r, band.get(e.entry_id, 0) if band else 0))

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
    band: Any = False,
) -> str | None:
    if view not in VIEWS:
        return f"view must be one of {VIEWS}, got {view!r}"
    if not isinstance(band, bool):
        return f"band must be true or false, got {band!r}"
    if view != "sink_patch" and band:
        return "band applies to view='sink_patch' only"
    if sort_by is not None and sort_by not in SORT_BY:
        return f"sort_by must be one of {SORT_BY} or null, got {sort_by!r}"
    if bucket is not None and bucket not in BUCKETS:
        return f"bucket must be one of {BUCKETS} or null, got {bucket!r}"
    if tier is not None and str(tier) not in (NO_SINK, UNKNOWN) and not str(tier).isdigit():
        return f"tier must be a number, 'no_sink' or 'unknown', got {tier!r}"
    if view != "sink_patch" and (filtered or sort_by is not None):
        return (
            "sort_by / bucket / subclass / tier / blind_spot / body apply to view='sink_patch' only"
        )
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LIMIT:
        return f"limit must be an integer in 1..{MAX_LIMIT}, got {limit!r}"
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        return f"offset must be an integer >= 0, got {offset!r}"
    return None


@dataclass
class BuiltDiff:
    """One diff's view, built: what get_diff_patch_view reads, and what a judgement on one of its
    entries is checked against (lib/query/diff_annotations), so the two always see the same
    entries."""

    diff: _Diff
    staleness: dict[str, Any]
    overlay: _Overlay
    n_edges: int
    edges_by_anchor: dict[str, Any]
    banners: list[str]
    entries: list[_Entry]  # the listed entries
    placed: list[_Entry]  # every entry placed, listed or not; empty when withheld
    withheld: dict[str, Any] | None  # set when the whole diff is undetermined
    unavailable: dict[str, str]


def build_diff_view(atlas: sqlite3.Connection, diff_id: str) -> BuiltDiff | None:
    """Build one diff's view; None when there is no such diff."""
    diff = _load_diff(atlas, diff_id)
    if diff is None:
        return None
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
    placed: list[_Entry] = []
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
        entries = builder.entries()
        placed = builder.placed
        unattributed = builder.unattributed
        unavailable = {s: str(builder.sides[s].error) for s in builder.unavailable}
        for e in entries:
            key = f"a:{e.pair.addr_a}" if e.pair is not None else e.entry_id
            e.string_edges = edges_by_anchor.get(key)
            e.rank = _rank(e)
    if unattributed:
        banners.append(f"overlay_rows_unattributed:{unattributed}")
    return BuiltDiff(
        diff=diff,
        staleness=staleness,
        overlay=overlay,
        n_edges=n_edges,
        edges_by_anchor=edges_by_anchor,
        banners=banners,
        entries=entries,
        placed=placed,
        withheld=withheld,
        unavailable=unavailable,
    )


# ── pseudocode_sameness: a read-face reading, never built into build_diff_view ───────────────


@dataclass(frozen=True)
class _Read:
    """One pair's pseudocode reading: ``matches`` / ``reason`` / ``text_reasons`` as
    sameness.pair_reading gives them, the ``hidden_region`` facts behind a qualified match, and —
    for an undetermined pair whose two bodies were read — how often each body occurs on each side
    and where else it is."""

    matches: bool | None
    reason: str | None
    text_reasons: tuple[str, ...] = ()
    hidden_region: dict[str, Any] | None = None
    occurrences: dict[str, int] | None = None
    a_body_elsewhere_in_b: dict[str, Any] | None = None
    b_body_elsewhere_in_a: dict[str, Any] | None = None


_UNREAD = _Read(None, sameness.UNAVAILABLE)
_PairReads = dict[tuple[str, str], _Read]


@dataclass(frozen=True)
class _Readings:
    """Every pair's reading for one diff: the aligned pairs and the undetermined ones, apart (an
    undetermined pair's reading is a proposal, never its pseudocode_sameness). ``key`` is the cache
    key the pseudocode_delta cache extends; ``sources`` each side's (analysis.db path, content hash)
    for the delta's own read."""

    key: tuple[str, ...]
    sources: tuple[tuple[str | None, str | None], tuple[str | None, str | None]]
    aligned: _PairReads
    undetermined: _PairReads


# Process-wide caches of the expensive read, per (diff_id, sha_a, sha_b, build_hash_a,
# build_hash_b): each pair's small reading — never the bodies or the skeleton index. The callee-set
# state a reading folds with comes from the build and is re-read each call. The pseudocode_delta
# cache adds the pair's two addresses to that key.
_PSEUDO_READING_CACHE: dict[tuple[str, ...], _PairReads] = {}
_UNDETERMINED_READING_CACHE: dict[tuple[str, ...], _PairReads] = {}
_DELTA_CACHE: dict[tuple[Any, ...], dict[str, Any]] = {}
_ELSEWHERE_SAMPLE = 3  # addresses shown of a body found elsewhere


def _clear_view_caches() -> None:
    """Drop the process-wide pseudocode-reading, delta and size-fact caches (tests reuse one
    diff_id, run ids and build hash across databases)."""
    _PSEUDO_READING_CACHE.clear()
    _UNDETERMINED_READING_CACHE.clear()
    _DELTA_CACHE.clear()
    _SIZE_FACT_CACHE.clear()


def _run_source(atlas: sqlite3.Connection, run_id: str) -> tuple[str | None, str | None]:
    """(analysis_db_path, build_hash) of a run."""
    row = atlas.execute(
        "SELECT analysis_db_path, build_hash FROM run WHERE run_id = ?", (run_id,)
    ).fetchone()
    return (row[0] if row and row[0] else None, row[1] if row else None)


def _read_pair(
    ba: sameness.Bodies | None,
    bb: sameness.Bodies | None,
    p: _Pair,
    ra: sameness.ImageRanges,
    rb: sameness.ImageRanges,
) -> _Read:
    matches, reason, reasons = sameness.pair_reading(ba, bb, p.addr_a, p.addr_b, ra, rb)
    hidden = None
    if matches and ba is not None and bb is not None:
        hidden = sameness.hidden_region(
            ba[p.addr_a],
            bb[p.addr_b],
            reasons,
            similarity=p.similarity,
            instructions=p.instructions,
        )
    return _Read(matches, reason, reasons, hidden)


def _skeleton_index(bodies: sameness.Bodies) -> dict[str, list[str]]:
    """skeleton_key -> the entries of every function on one side with that body."""
    out: dict[str, list[str]] = {}
    for addr, body in bodies.items():
        text = body.get("pseudocode")
        if text:
            out.setdefault(sameness.skeleton_key(text), []).append(addr)
    return out


def _elsewhere(index: dict[str, list[str]], key: str, own: str) -> dict[str, Any]:
    others = sorted((a for a in index.get(key, []) if a != own), key=lambda a: int(a, 16))
    return {"count": len(others), "addrs": others[:_ELSEWHERE_SAMPLE]}


def _read_undetermined(
    ba: sameness.Bodies | None,
    bb: sameness.Bodies | None,
    pairs: list[_Pair],
    ra: sameness.ImageRanges,
    rb: sameness.ImageRanges,
) -> _PairReads:
    """Each undetermined pair read like an aligned one, plus — when both bodies were read — how
    often each body occurs on each side and where else it is. The skeleton index over both sides'
    functions is built only when some pair has two bodies to look up, and never kept."""
    out: _PairReads = {}
    index: dict[str, dict[str, list[str]]] | None = None
    for p in pairs:
        read = _read_pair(ba, bb, p, ra, rb)
        if read.matches is not None and ba is not None and bb is not None:
            if index is None:
                index = {"a": _skeleton_index(ba), "b": _skeleton_index(bb)}
            ka = sameness.skeleton_key(ba[p.addr_a]["pseudocode"])
            kb = sameness.skeleton_key(bb[p.addr_b]["pseudocode"])
            read = replace(
                read,
                occurrences={"a": len(index["a"].get(ka, [])), "b": len(index["b"].get(kb, []))},
                a_body_elsewhere_in_b=_elsewhere(index["b"], ka, p.addr_b),
                b_body_elsewhere_in_a=_elsewhere(index["a"], kb, p.addr_a),
            )
        out[(p.addr_a, p.addr_b)] = read
    return out


def _pseudo_readings(atlas: sqlite3.Connection, built: BuiltDiff) -> _Readings:
    """Every placed pair's pseudocode reading — aligned and undetermined apart. Reads both runs'
    analysis.db pseudocode and image extents once and caches by (diff_id, sha_a, sha_b,
    build_hash_a, build_hash_b): the build hash is in the key so a re-extraction that leaves the
    content hash alone but rewrites the pseudocode (or the extents) is not served a stale reading.
    This is the cost lib/query/sameness keeps out of build_diff_view (and so out of annotate /
    promote / the cross-scope progress block)."""
    d = built.diff
    pa, ha = _run_source(atlas, d.run_a)
    pb, hb = _run_source(atlas, d.run_b)
    key = (d.diff_id, d.sha_a or "", d.sha_b or "", ha or "", hb or "")
    aligned = _PSEUDO_READING_CACHE.get(key)
    undetermined = _UNDETERMINED_READING_CACHE.get(key)
    if aligned is None or undetermined is None:
        ba = sameness.read_function_bodies(pa, d.sha_a)
        bb = sameness.read_function_bodies(pb, d.sha_b)
        ra = sameness.read_image_ranges(pa, d.sha_a)
        rb = sameness.read_image_ranges(pb, d.sha_b)
        pairs = [e.pair for e in built.placed if e.pair is not None]
        if aligned is None:
            aligned = {
                (p.addr_a, p.addr_b): _read_pair(ba, bb, p, ra, rb) for p in pairs if p.aligned
            }
            _PSEUDO_READING_CACHE[key] = aligned
        if undetermined is None:
            undetermined = _read_undetermined(ba, bb, [p for p in pairs if not p.aligned], ra, rb)
            _UNDETERMINED_READING_CACHE[key] = undetermined
    return _Readings(key, ((pa, d.sha_a), (pb, d.sha_b)), aligned, undetermined)


def _aligned_read(e: _Entry, readings: _Readings) -> _Read | None:
    p = e.pair
    if p is None or not p.aligned:
        return None
    return readings.aligned.get((p.addr_a, p.addr_b), _UNREAD)


def _sameness_of(e: _Entry, readings: _Readings) -> str | None:
    """The pseudocode_sameness of one aligned pair; None when the entry is not an aligned pair (a
    function with no counterpart, or an undetermined pair)."""
    read = _aligned_read(e, readings)
    if read is None:
        return None
    return sameness.sameness_state(
        read.matches, (e.callee_set or {}).get("state"), read.reason, read.text_reasons
    )


def _proposed_of(e: _Entry, readings: _Readings) -> tuple[str, _Read] | None:
    """(state, reading) of an undetermined pair's proposed reading; None for any other entry."""
    p = e.pair
    if p is None or p.aligned:
        return None
    read = readings.undetermined.get((p.addr_a, p.addr_b), _UNREAD)
    state = sameness.undetermined_pair_state(
        read.matches,
        (e.proposed_callee_set or {}).get("state"),
        read.reason,
        read.text_reasons,
        read.occurrences,
    )
    return state, read


def _body_of(e: _Entry, readings: _Readings) -> str | None:
    """The ``body`` class of an identical_text_unverified entry (aligned, or an undetermined pair's
    proposed reading); None for any other entry — the ``body`` filter keeps no other entry."""
    state = _sameness_of(e, readings)
    read = _aligned_read(e, readings)
    if state is None:
        proposed = _proposed_of(e, readings)
        state, read = proposed if proposed is not None else (None, None)
    if state != sameness.IDENTICAL_TEXT_UNVERIFIED or read is None:
        return None
    return sameness.text_unverified_body(read.text_reasons)


def _hidden_region(read: _Read, p: _Pair) -> dict[str, Any] | None:
    """The reading's hidden_region with the pair's BinDiff counts as the alignment stores them now
    (the reading is cached by content, the alignment row is not)."""
    if read.hidden_region is None:
        return None
    return {
        **read.hidden_region,
        "bindiff_matched_instructions": p.instructions,
        "similarity": p.similarity,
    }


def _deltas(readings: _Readings, pairs: list[_Pair]) -> dict[tuple[str, str], dict[str, Any]]:
    """pseudocode_delta of each of ``pairs`` (pairs whose texts were read and differ), computed only
    for the page being rendered: the bodies are read once, and only when one of them is not cached;
    the result is cached per pair, the bodies are not kept."""
    out: dict[tuple[str, str], dict[str, Any]] = {}
    missing: list[_Pair] = []
    for p in pairs:
        hit = _DELTA_CACHE.get((readings.key, p.addr_a, p.addr_b))
        if hit is None:
            missing.append(p)
        else:
            out[(p.addr_a, p.addr_b)] = hit
    if missing:
        (pa, sha_a), (pb, sha_b) = readings.sources
        ba = sameness.read_function_bodies(pa, sha_a) or {}
        bb = sameness.read_function_bodies(pb, sha_b) or {}
        ra = sameness.read_image_ranges(pa, sha_a)
        rb = sameness.read_image_ranges(pb, sha_b)
        for p in missing:
            ta = (ba.get(p.addr_a) or {}).get("pseudocode")
            tb = (bb.get(p.addr_b) or {}).get("pseudocode")
            if not ta or not tb:  # the bodies moved since the reading: nothing to compare
                continue
            delta = sameness.pseudocode_delta(ta, tb, ra, rb, p.addr_a, p.addr_b)
            _DELTA_CACHE[(readings.key, p.addr_a, p.addr_b)] = delta
            out[(p.addr_a, p.addr_b)] = delta
    return out


def _delta_pair(e: _Entry, readings: _Readings) -> _Pair | None:
    """The entry's pair when its two texts were read and differ (a delta is owed), else None."""
    p = e.pair
    if p is None:
        return None
    reads = readings.aligned if p.aligned else readings.undetermined
    return p if reads.get((p.addr_a, p.addr_b), _UNREAD).matches is False else None


def _proposed_json(
    e: _Entry, state: str, read: _Read, deltas: dict[tuple[str, str], dict[str, Any]]
) -> dict[str, Any]:
    """An undetermined pair's ``proposed_pair_reading``: read as if it were paired, beside the
    entry and never as its pseudocode_sameness. ``occurrences`` and the two ``*_elsewhere_*`` are
    null unless both bodies were read."""
    p = e.pair
    assert p is not None
    out: dict[str, Any] = {"pairing": "undetermined", "state": state}
    if state == sameness.U_IDENTICAL_TEXT_UNVERIFIED:
        out["text_unverified_reasons"] = list(read.text_reasons)
    out.update(
        {
            "callee_set": e.proposed_callee_set,
            "occurrences": read.occurrences,
            "a_body_elsewhere_in_b": read.a_body_elsewhere_in_b,
            "b_body_elsewhere_in_a": read.b_body_elsewhere_in_a,
        }
    )
    hidden = _hidden_region(read, p)
    if hidden is not None:
        out["hidden_region"] = hidden
    delta = deltas.get((p.addr_a, p.addr_b))
    if delta is not None:
        out["pseudocode_delta"] = delta
    return out


def _not_listed_counts(built: BuiltDiff, readings: _Readings) -> dict[str, dict[str, Any]]:
    """The aligned, similarity-1 pairs that place no entry, counted by pseudocode_sameness. The
    'differs' count carries a ``page_with`` recipe: the view's filters only reach LISTED entries,
    so a dedicated ``not_listed_page`` is the way to walk these."""
    tally: dict[str, int] = {}
    for e in built.placed:
        if e.bucket:
            continue
        state = _sameness_of(e, readings)
        if state is not None:
            tally[state] = tally.get(state, 0) + 1
    out: dict[str, dict[str, Any]] = {
        name: {"count": tally.get(state, 0)} for state, name in sameness.NOT_LISTED_NAME.items()
    }
    differs = sameness.NOT_LISTED_NAME[sameness.DIFFERS]
    out[differs]["page_with"] = f"not_listed_page={differs}"
    return out


def _not_listed_page(
    built: BuiltDiff,
    readings: _Readings,
    name: str,
    *,
    limit: int,
    offset: int,
    body: str | None = None,
) -> dict[str, Any]:
    """One page of the not-listed pairs of a pseudocode_sameness category, by address. Lightweight:
    these are not entries, so they carry only their addresses, similarity and sameness state — plus
    the ``body`` class and reasons of a qualified match, and the pseudocode_delta of a text that
    differs. ``body`` keeps only the qualified matches of that class."""
    state = sameness.STATE_BY_NOT_LISTED_NAME[name]
    pairs = sorted(
        (
            e
            for e in built.placed
            if not e.bucket
            and _sameness_of(e, readings) == state
            and (body is None or _body_of(e, readings) == body)
        ),
        key=lambda e: (e.pair.addr_a, e.pair.addr_b) if e.pair is not None else ("", ""),
    )
    end = offset + limit
    page = [e for e in pairs[offset:end] if e.pair is not None]
    deltas = _deltas(
        readings,
        [
            e.pair
            for e in page
            if e.pair is not None and (_aligned_read(e, readings) or _UNREAD).matches is False
        ],
    )
    rows: list[dict[str, Any]] = []
    for e in page:
        assert e.pair is not None
        read = _aligned_read(e, readings) or _UNREAD
        row: dict[str, Any] = {
            "entry_id": e.entry_id,
            "addr_a": e.pair.addr_a,
            "addr_b": e.pair.addr_b,
            "similarity": e.pair.similarity,
            "pseudocode_sameness": state,
        }
        if state == sameness.IDENTICAL_TEXT_UNVERIFIED:
            row["body"] = sameness.text_unverified_body(read.text_reasons)
            row["text_unverified_reasons"] = list(read.text_reasons)
        delta = deltas.get((e.pair.addr_a, e.pair.addr_b))
        if delta is not None:
            row["pseudocode_delta"] = delta
        rows.append(row)
    return {
        "entries": rows,
        "total_entries": len(pairs),
        "next_offset": end if end < len(pairs) else None,
    }


_SIGNIFICANCE_LENS = (
    "sort_by='significance' reorders the listed entries, never relabels them: attention 0 = bucket "
    "A or a row carrying sink_arg_constant_delta; 2 = pseudocode_sameness identical, or bucket C "
    "(sunk, still listed and pageable); 1 = the rest, lowest similarity first, R and B entries "
    "ordered together. Attention 0 holds B entries too (a row's sink_arg_constant_delta) beside "
    "A. Never sunk: an R entry (attention 2 never holds one; one whose proposed_pair_reading is "
    "identical_unique closes attention 1 instead), a B sink_present_no_visible_delta (labelled "
    "recheckable_no_visible_delta), an identical_text_unverified entry outside bucket C, and an "
    "entry judged changed_real, inconclusive or due a re-check / relabel — none of them reaches "
    "attention 2, whether band is on or off. A bucket C entry is sunk even when its text match is "
    "identical_text_unverified; sunk_with_body_size_differs counts the sunk ones whose two body "
    "byte counts differ, with the filter that lists them, counted over the entries the current "
    "filters keep. Only with band=true does the judgement band order entries inside each "
    "attention tier. Each entry's ``significance`` names its tier and why. Not seen by this lens: "
    "a constant in an allocation expression or a local buffer's declared size (blind_spots); the "
    "target a DAT_ / PTR_ reference points at, once its address is blanked (a pseudocode match "
    "does not check it; a string label keeps its content in the name); a C++ catch handler "
    "(landing pad), which usually lies outside every function body, so its code is never "
    "decompiled and no reading compares it — a try/catch annotation that moved with its function "
    "says nothing about the handler; and anything in a binary the two runs hold byte-identical — "
    "that is in the scan's candidate map, not in any diff."
)


def _carries_scoped_sink_delta(e: _Entry) -> bool:
    """A changed pair whose change reaches a sink in scope: its matched call now calls another
    callee (bucket A), or a candidate row carries a changed length constant. Read from the ROW
    field, never the entry's subclass — an entry placed in B by another row keeps that subclass."""
    return e.bucket == "A" or any("sink_arg_constant_delta" in v for v in e.row_views)


def function_states(atlas: sqlite3.Connection, diff_id: str) -> dict[str, Any] | None:
    """One diff's functions split by what the view's own facts say about them — the counts a reader
    is shown first (get_diff_meta, the diff command). Consumes pseudocode_sameness and
    sink_arg_constant_delta exactly as get_diff_patch_view computes them; never a second reading.

    Every aligned pair is in exactly one of ``unchanged`` (identical: pseudocode AND callees),
    ``changed`` (split into ``with_scoped_sink_delta`` — bucket A, or a row carrying
    sink_arg_constant_delta — and ``no_scoped_signal``, which says no in-scope sink signal, NOT
    noise), ``unverified`` (identical_text_unverified + identical_callee_unverified + unavailable;
    ``identical_text_unverified_by_body`` splits the first by its body class) and ``no_body`` (an
    import / PLT stub, kept out of every other count). Pairs whose alignment is undetermined are
    counted beside them, and ``alignment_undetermined_reading`` splits them by their proposed
    reading (never into the aligned counts); functions with no counterpart are counted by
    presence_state, never "added"/"removed". A diff undetermined as a whole is ``withheld`` with
    its banners and NO counts — a blind spot, not zero changes. None when there is no such diff."""
    built = build_diff_view(atlas, diff_id)
    if built is None:
        return None
    if built.withheld is not None:
        return {"diff_id": diff_id, "withheld": True, "banners": list(built.banners)}
    d = built.diff
    one_sided: dict[str, dict[str, int]] = {}
    for u in d.unpaired.values():
        presence = u.presence_state or "unrecorded"
        side = one_sided.setdefault(u.side, {})
        side[presence] = side.get(presence, 0) + 1
    undetermined = sum(1 for p in d.pairs if not p.aligned)
    readings = _pseudo_readings(atlas, built)
    tally: dict[str, int] = {}
    by_body = {cls: 0 for cls in sameness.BODY_CLASSES}
    proposed = {state: 0 for state in sameness.U_STATES}
    scoped = 0
    for e in built.placed:
        reading = _proposed_of(e, readings)
        if reading is not None:
            proposed[reading[0]] += 1
        state = _sameness_of(e, readings)
        if state is None:
            continue
        tally[state] = tally.get(state, 0) + 1
        if state == sameness.DIFFERS and _carries_scoped_sink_delta(e):
            scoped += 1
        if state == sameness.IDENTICAL_TEXT_UNVERIFIED:
            by_body[_body_of(e, readings) or sameness.BODY_UNKNOWN] += 1
    changed = tally.get(sameness.DIFFERS, 0)
    unverified = {
        sameness.IDENTICAL_TEXT_UNVERIFIED: tally.get(sameness.IDENTICAL_TEXT_UNVERIFIED, 0),
        sameness.IDENTICAL_CALLEE_UNVERIFIED: tally.get(sameness.IDENTICAL_CALLEE_UNVERIFIED, 0),
        sameness.UNAVAILABLE: tally.get(sameness.UNAVAILABLE, 0),
    }
    return {
        "diff_id": diff_id,
        "withheld": False,
        "aligned": sum(tally.values()),
        "unchanged": tally.get(sameness.IDENTICAL, 0),
        "changed": {
            "total": changed,
            "with_scoped_sink_delta": scoped,
            "no_scoped_signal": changed - scoped,
        },
        "unverified": {"total": sum(unverified.values()), **unverified},
        "identical_text_unverified_by_body": by_body,
        "no_body": tally.get(sameness.NO_BODY, 0),
        "alignment_undetermined": undetermined,
        "alignment_undetermined_reading": proposed,
        "one_sided": {s: dict(sorted(v.items())) for s, v in sorted(one_sided.items())},
    }


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
    band: bool = False,
    not_listed_page: str | None = None,
    body: str | None = None,
) -> dict[str, Any]:
    """The function-level view of one diff (see the module docstring), one page of it.

    ``view``: ``sink_patch`` (function pairs, the default), ``string_edge`` (get_diff_deltas'
    rows), ``candidate_flat`` (get_diff_sink_overlay's rows, in its order). The filters and
    ``sort_by`` apply to ``sink_patch``; ``counts`` / ``not_listed`` / ``blind_spots`` always
    describe the whole diff. Pages are in a fixed order; follow ``next_offset`` until null.

    ``band`` (``sink_patch`` only, off by default) moves the judged entries inside the groups the
    default order already forms (diff_review.band_bias); off, the order is the base order. The
    judgement keys (``anchor_ref`` / ``review_state`` on each entry, ``review_progress`` and
    ``annotation`` on the envelope) are there either way.

    ``not_listed_page`` names one ``not_listed`` category (e.g. ``aligned_pseudocode_differs``) and
    returns ITS pairs instead of the listed entries — the only way to walk pairs no entry holds,
    since the filters reach listed entries alone. Each listed sink_patch entry that is an aligned
    pair also carries its ``pseudocode_sameness``; an undetermined pair carries its
    ``proposed_pair_reading`` instead.

    ``body`` (``structure_differs`` / ``unknown``) keeps only the identical_text_unverified entries
    of that body class — listed ones (an aligned pair's, or an undetermined pair's proposed
    reading) and, with ``not_listed_page``, the not-listed pairs of
    ``aligned_pseudocode_identical_text_unverified`` (with any other ``not_listed_page`` it is an
    error, not an empty page)."""
    if not_listed_page is not None and not_listed_page not in sameness.STATE_BY_NOT_LISTED_NAME:
        names = list(sameness.STATE_BY_NOT_LISTED_NAME)
        return {"diff_id": diff_id, "error": f"not_listed_page must be one of {names}"}
    if body is not None and body not in sameness.BODY_CLASSES:
        return {
            "diff_id": diff_id,
            "error": f"body must be one of {sameness.BODY_CLASSES} or null, got {body!r}",
        }
    qualified = sameness.NOT_LISTED_NAME[sameness.IDENTICAL_TEXT_UNVERIFIED]
    if body is not None and not_listed_page not in (None, qualified):
        return {
            "diff_id": diff_id,
            "error": (
                f"body applies to the listed entries and to not_listed_page={qualified!r} only"
            ),
        }
    filters = {
        "bucket": bucket,
        "subclass": subclass,
        "tier": tier,
        "blind_spot": blind_spot,
        "body": body,
    }
    filtered = any(v is not None for v in filters.values())
    error = _check_args(view, sort_by, bucket, tier, limit, offset, filtered, band)
    if error is not None:
        return {"diff_id": diff_id, "error": error}
    built = build_diff_view(atlas, diff_id)
    if built is None:
        return {"diff_id": diff_id, "found": False, "error": "no such diff (see list_diffs)"}
    overlay, banners, entries = built.overlay, built.banners, built.entries
    readings = _pseudo_readings(atlas, built)

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
    if built.withheld is not None:
        counts["withheld"] = built.withheld
    subject_counts = {
        "function_pair": len(entries),
        "candidate_row": len(overlay.rows),
        "string_edge": built.n_edges,
    }
    ledger = _ledger(entries, rows_by_spot, built.unavailable)
    chosen = [
        e
        for e in entries
        if _matches(e, bucket, subclass, tier, blind_spot)
        and (body is None or _body_of(e, readings) == body)
    ]
    review = ViewReview(atlas, built)
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
            "switchable": "view / sort_by / bucket / subclass / tier / blind_spot / body",
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
        **built.staleness,
        "banners": banners,
        "counts": counts,
        "not_listed": _not_listed_counts(built, readings),
        "blind_spots": ledger,
        "overlay_coverage": overlay.coverage,
        "review_progress": review.progress(chosen, filters, ledger),
        "annotation": review.annotation(),
    }
    if band:
        envelope["lens"]["band"] = (
            "on: inside each group the default order holds together (segment, tier, lane, "
            "subclass rank), entries due a re-check first, then change_inconclusive, then "
            "unjudged, then changed_real, then no_real_change"
        )
    if not_listed_page is not None:
        envelope.update(
            _not_listed_page(
                built, readings, not_listed_page, limit=limit, offset=offset, body=body
            )
        )
        return envelope
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
    proposed = {e.entry_id: r for e in chosen if (r := _proposed_of(e, readings)) is not None}
    lens: dict[str, tuple[int, str]] = {}
    settled: dict[str, int] = {}
    if sort_by == "significance":
        lens = {
            e.entry_id: significance(
                e,
                _sameness_of(e, readings),
                review.items.get(e.entry_id),
                proposed[e.entry_id][0] if e.entry_id in proposed else None,
            )
            for e in chosen
        }
        settled = {
            k: 1 for k, (state, _read) in proposed.items() if state == sameness.U_IDENTICAL_UNIQUE
        }
        envelope["lens"]["significance"] = _SIGNIFICANCE_LENS
        envelope["lens"]["sunk_with_body_size_differs"] = {
            "count": sum(
                1
                for e in chosen
                if lens[e.entry_id][0] == ATTENTION_SINK
                and _body_of(e, readings) == sameness.BODY_STRUCTURE_DIFFERS
            ),
            "filter": {"body": sameness.BODY_STRUCTURE_DIFFERS},
        }
    ordered = _sort(
        chosen,
        sort_by,
        review.bands() if band else None,
        {k: v[0] for k, v in lens.items()},
        settled,
    )
    end = offset + limit
    page = ordered[offset:end]
    page_deltas = _deltas(
        readings, [p for e in page if (p := _delta_pair(e, readings)) is not None]
    )

    def _render(e: _Entry) -> dict[str, Any]:
        out = review.entry_json(e, band)
        state = _sameness_of(e, readings)
        read = _aligned_read(e, readings)
        if state is not None and read is not None and e.pair is not None:
            out["pseudocode_sameness"] = state
            if state == sameness.IDENTICAL_TEXT_UNVERIFIED:
                out["text_unverified_reasons"] = list(read.text_reasons)
            hidden = _hidden_region(read, e.pair)
            if hidden is not None:
                out["hidden_region"] = hidden
            delta = page_deltas.get((e.pair.addr_a, e.pair.addr_b))
            if delta is not None:
                out["pseudocode_delta"] = delta
        if e.entry_id in proposed and e.pair is not None:
            out["proposed_pair_reading"] = _proposed_json(e, *proposed[e.entry_id], page_deltas)
        if e.entry_id in lens:
            attention, basis = lens[e.entry_id]
            out["rank_key"] = {**out["rank_key"], "attention": attention}
            out["significance"] = {"attention": attention, "basis": basis}
        return out

    envelope.update(
        {
            "entries": [_render(e) for e in page],
            "total_entries": len(ordered),
            "next_offset": end if end < len(ordered) else None,
        }
    )
    return envelope


class ViewReview:
    """The judgements on one built diff, read against it: each listed entry's anchor and review
    state, the progress over a scope of entries, and the annotation block."""

    def __init__(self, atlas: sqlite3.Connection, built: BuiltDiff) -> None:
        d = built.diff
        self.built = built
        self.binary = d.binary
        self.withheld = built.withheld is not None
        rows = diff_review.read_judgements(atlas, d.run_a, d.run_b)
        subjects = (
            diff_review.subjects_of(built.placed, d.run_a, d.run_b, d.binary) if d.binary else {}
        )
        self.judged, self.dangling = diff_review.judgements_for(
            rows,
            diff_id=d.diff_id,
            run_a=d.run_a,
            run_b=d.run_b,
            binary=d.binary,
            subjects=subjects,
            withheld=self.withheld,
            staleness=built.staleness,
        )
        self.anchor: dict[str, str | None] = {
            e.entry_id: (
                diff_review.entry_anchor(e, d.run_a, d.run_b, d.binary) if d.binary else None
            )
            for e in built.entries
        }
        position = {e.entry_id: i for i, e in enumerate(_sort(built.entries, None))}
        self.items: dict[str, diff_review.Item] = {}
        for e in built.entries:
            anchor = self.anchor[e.entry_id]
            judged = self.judged.get(anchor) if anchor is not None else None
            self.items[e.entry_id] = diff_review.Item(
                entry_id=e.entry_id,
                anchor_ref=anchor or "",
                bucket=e.bucket,
                subclass=e.subclass,
                tier=e.tier,
                state=diff_review.review_state(judged),
                verdict=judged.verdict if judged is not None else None,
                order=(position[e.entry_id],),
            )

    def bands(self) -> dict[str, int]:
        return {k: diff_review.band_bias(i.state, i.verdict) for k, i in self.items.items()}

    def entry_json(self, e: _Entry, band: bool) -> dict[str, Any]:
        out = _entry_json(e)
        item = self.items[e.entry_id]
        if band:
            bias = diff_review.band_bias(item.state, item.verdict)
            out["rank_key"] = {**e.rank, "band_bias": bias}
        out["anchor_ref"] = self.anchor[e.entry_id]
        out["review_state"] = item.state
        return out

    def progress(
        self, chosen: list[_Entry], filters: dict[str, Any], ledger: list[dict[str, Any]]
    ) -> dict[str, Any]:
        blind = {
            "ledger": [
                {"key": s["key"], "count": s["count"], "unit": s["unit"]}
                for s in ledger
                if s.get("count") is not None
            ],
            "structural": [s["key"] for s in ledger if s.get("count") is None],
            "banners": list(self.built.banners),
            "see": "blind_spots (top-level) — every key with its entries",
        }
        if self.withheld:
            return {
                "unit": "entry",
                "withheld": True,
                "banners": list(self.built.banners),
                "judgements_on_this_diff": len(self.judged),
                "blind_spots": blind,
                "complete": False,
                "note": (
                    "The whole diff is undetermined (banners), so it lists no entry and nothing "
                    "in it can be counted as looked at or not. Resolve what the banners name — "
                    "re-run the diff, or re-scan the run — and read this again."
                ),
            }
        chosen_ids = {e.entry_id for e in chosen}
        scope = [self.items[e.entry_id] for e in chosen]
        rest = [i for k, i in self.items.items() if k not in chosen_ids]
        numbers = diff_review.counts(scope)
        rest_numbers = diff_review.counts(rest)
        return {
            "unit": "entry",
            "scope": filters,
            **numbers,
            "next_page": diff_review.next_page(scope),
            "dangling_annotations": self.dangling,
            "outside_this_scope": {
                "not_looked_at": rest_numbers["not_looked_at"],
                "pages_remaining": rest_numbers["pages_remaining"],
            },
            "blind_spots": blind,
            "complete": numbers["not_looked_at"] == 0,
            "note": diff_review.PROGRESS_NOTE,
        }

    def annotation(self) -> dict[str, Any]:
        d = self.built.diff
        if self.withheld:
            return diff_review.annotation_unavailable(
                "the whole diff is undetermined (banners): nothing in it can be judged until "
                "that is resolved — re-run the diff, or re-scan the run the banners name",
                self.built.banners,
            )
        if not d.binary:
            return diff_review.annotation_unavailable(
                "this diff records no binary name, which every anchor carries — re-run the diff",
                self.built.banners,
            )
        return diff_review.annotation_block(d.diff_id, d.run_a, d.run_b, list(self.items.values()))


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
