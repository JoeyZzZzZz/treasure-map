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
  E  an aligned, similarity-1 pair that would otherwise place no entry, whose called function has a
     direct caller on the A side and none found (or none provable) on the B side — a caller-set edge
     fact (``callers_a`` / ``callers_b``) similarity is blind to. The ONE bucket this build adds.
A similarity-1 pair whose candidates all line up, or that has none, places no entry UNLESS a length
constant changed on one of its candidates (then it is B ``sink_arg_constant_delta``), or its
caller-set edge reads lost-or-undetermined (then it is E, above); the rest are counted under
``not_listed`` by ``pseudocode_sameness`` (below), never dropped. Where each overlay
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

ORDER: A first, then the R and B entries that carry a sink candidate (E among them when it carries
one, in its own lane), then the entries with none (recall_gap_sink, R, C, then the E with none),
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
from collections import OrderedDict
from dataclasses import asdict, dataclass, field, replace
from typing import Any, Generic, TypeVar

from treasure_map.lib.diff.layer0 import norm_hex
from treasure_map.lib.pattern import classes
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
BUCKETS = ("A", "B", "C", "R", "P", "E")
SORT_BY = ("tier", "similarity", "address", "significance")
NO_SINK = "no_sink"
UNKNOWN = "unknown"
MAX_LIMIT = 2000
# How many candidate rows an entry carries inline; the rest are paged with entry_id + rows_offset.
# A window over the rendered rows only: the entry's own rows, and every entry-level field read from
# them, stay whole.
ROWS_INLINE_LIMIT = 20
# The order an entry's rows are windowed in when they do not all fit: rows that did not persist
# first, then persisted rows carrying a size signal, then the rest, each group in its own order.
ROWS_ORDER = "presence_not_persisted_then_size_signal_then_rest"
_SIZE_SIGNALS = ("sink_arg_constant_delta", "size_kind_shifted")
_ROW_GROUPS = ("not_persisted", "size_signal", "rest")

# Sinks the hunt does not recall as candidates, by family. A changed pair with no candidate whose
# callees name one of these is B, never C: there the absence of a candidate is the hunt's blind
# spot, not a fact about the function. Matched by exact name.
RECALL_GAP_SINKS: dict[str, tuple[str, ...]] = {
    "wide_char_string": ("wcscpy", "wcscat", "vswprintf"),
    "argv_runner": ("_eval",),
    "exec_path_variant": ("execvpe",),
}
# The sink names a callee-set difference is read against (``sink_callee_swap``): the hunt's sink
# classes, as the extractor registry holds them, plus the sinks it does not recall. Matched by
# exact name; any other name (strlcpy, strdup, a FUN_<addr>) is not a sink here.
SINK_CALLEE_NAMES: frozenset[str] = (
    classes.FORMAT | classes.CMD | classes.COPY | classes.FMT_STRING | classes.PATH_SINK
).union(*RECALL_GAP_SINKS.values())
# The recall-gap sink names alone (flattened), for the caller-set edge's relevance ordering: an E
# entry with no candidate of its own whose callee is one of these leads its lane.
_RECALL_GAP_NAMES: frozenset[str] = frozenset(
    name for names in RECALL_GAP_SINKS.values() for name in names
)
# How many caller addresses callers_a prints as a sample (the count is always exact).
_CALLER_SAMPLE = 10

# A sink_callee_swap is narrow when both lists were read in full and neither side differs by more
# than this many names.
_SWAP_NARROW_NAMES = 2
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
    "caller_via_function_pointer_table": (
        "a function reached only through a PTR_FUN_ dispatch table or other function-pointer store "
        "is not in any caller's extracted callee list, so the caller-set reading (callers_a / "
        "callers_b) does not count it as a direct caller"
    ),
    "caller_via_data_reference": (
        "a function whose address is taken as data rather than called by name is not a direct "
        "caller in the callee lists, so the caller-set reading does not see that reference"
    ),
    "caller_inlined": (
        "a caller the compiler inlined holds no call to the function, so the caller-set reading "
        "cannot count it — a function that lost every direct caller may still be reached inlined"
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
    "E": (
        "An aligned, similarity-1 pair whose called function has a direct caller on the A side and "
        "none found — or none provable — on the B side (callers_a / callers_b). Evidence of a "
        "caller-set edge similarity cannot see, not a verdict: it does not say the function is "
        "dead, only that no direct call to it was read on the B side."
    ),
    "callers_b": (
        "The B side's direct callers of this pair's function, read by reverse-scanning extracted "
        "callee lists by exact name (any side, A / B / C / R / E). state none_found = no caller "
        "was read AND the B side's lists were complete; undetermined (reason given) = a caller may "
        "exist but could not be ruled out (a truncated or unreadable callee list, the function not "
        "in that scan's inventory, or stale sources). tmap's decompile can miss a call and a call "
        "through a pointer table or a data reference carries no name, so none_found is not proof "
        "the function is unreferenced. With pairing='proposed' the B side is an undetermined "
        "pairing, whose function may be the wrong one."
    ),
    "callee_set_differs": (
        "The extracted callee lists differ. tmap's decompile can miss a call, so this is not proof "
        "a call was added or removed."
    ),
    "sink_callee_swap": (
        "A sink name is in the callee-set difference of the two functions. tmap's decompile can "
        "miss a call, so this is not proof a call was added, removed or replaced. Only the hunt's "
        "sink names (and the sinks it does not recall) count; any other name does not. With "
        "pairing='proposed' the difference is read on an undetermined pairing, whose other side "
        "may be the wrong function."
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
    "E": (
        "similarity-1 pair whose function has a direct caller on the A side and none found (or "
        "none provable) on the B side — a caller-set edge (callers_a / callers_b)"
    ),
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
_K = TypeVar("_K")
_V = TypeVar("_V")


class _BoundedCache(Generic[_K, _V]):
    """A process-wide cache with a ceiling: least recently used entries go first. The MCP server
    is long-lived, and every diff it shows and every re-hunted run would otherwise leave an entry
    behind for good."""

    def __init__(self, maxsize: int) -> None:
        self._maxsize = maxsize
        self._data: OrderedDict[_K, _V] = OrderedDict()

    def get(self, key: _K) -> _V | None:
        if key not in self._data:
            return None
        self._data.move_to_end(key)
        return self._data[key]

    def __setitem__(self, key: _K, value: _V) -> None:
        self._data[key] = value
        self._data.move_to_end(key)
        while len(self._data) > self._maxsize:
            self._data.popitem(last=False)

    def __len__(self) -> int:
        return len(self._data)

    def clear(self) -> None:
        self._data.clear()


def _atlas_identity(atlas: sqlite3.Connection) -> str:
    """The atlas file this connection reads, so two atlases served by one process never share a
    cache entry that happens to carry the same run ids or diff id."""
    for row in atlas.execute("PRAGMA database_list"):
        if row[1] == "main":
            return str(row[2] or "")
    return ""


_SIZE_FACT_CACHE: _BoundedCache[tuple[str, ...], dict[str, tuple[str, str | None]]] = _BoundedCache(
    16
)
# evidence_ref function-entries that hold a candidate, per (run, binary): the caller-set edge's
# one-hop relevance lands on these. Keyed by the run's stamps so a re-hunt is not served stale.
_CANDIDATE_ENTRY_CACHE: _BoundedCache[tuple[str, ...], frozenset[str]] = _BoundedCache(16)


def _size_facts(atlas: sqlite3.Connection, run_id: str) -> dict[str, tuple[str, str | None]]:
    """evidence_ref -> (size_kind, size_arg) for the run's candidates that carry a size axis."""
    row = atlas.execute(
        "SELECT build_hash, hunt_commit, updated_at FROM run WHERE run_id = ?", (run_id,)
    ).fetchone()
    key = (_atlas_identity(atlas), run_id, *(str(v or "") for v in (row or (None, None, None))))
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
    # Read-face facts attached once readings are in hand (``_annotate_entries``): each side's body
    # status (sameness.pair_reading's ``bodies``, only when a side had no text), both sides' body
    # sizes (``sizes``, only when both bodies were read), and, for an anchored_differs pair at or
    # above the read-first floor, its ``line_number_form`` (a __FILE__/__LINE__ shift) — which
    # demotes it out of the read-first head only when its callee sets and sizes are also proven
    # equal (:func:`_demotable_line_number`). None until annotated.
    body_status: dict[str, Any] | None = None
    sizes: tuple[int | None, int | None] | None = None
    line_number_form: dict[str, Any] | None = None
    # The caller-set edge (S3): the A side's direct callers of the pair's function and the B side's
    # reading of the same, attached to any pair entry (A/B/C/R or the new E) when the A side has a
    # caller and the B side has none or cannot prove none; None when there is no such signal. A
    # render/significance fact only — NEVER part of diff_review.entry_facts, so it moves no existing
    # judgement to needs_recheck. ``pairing`` is ``aligned`` or ``proposed`` (an undetermined pair).
    # ``caller_relevance`` orders an E entry with no candidate row (0 candidate/recall-gap, 1 a
    # callee that is itself a candidate, 2 the rest); unused on every other entry.
    callers_a: dict[str, Any] | None = None
    callers_b: dict[str, Any] | None = None
    pairing: str | None = None
    caller_relevance: int = 2

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
        # side -> (callee_name -> {caller addr}, maybe_truncated): the same-binary reverse-caller
        # index, built once per side from the callee lists already in memory (_Side.raw), zero extra
        # SQL. ``maybe_truncated`` is True when ANY function's list was cut, unreadable or does not
        # record truncation, so a function with no caller there cannot be proven to have none.
        self._rev: dict[str, tuple[dict[str, set[str]], bool]] = {}

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
        if p is not None:
            # The caller-set edge is a field on any pair entry (A/B/C/R); on an aligned pair that
            # would otherwise place no entry it also PLACES the entry, in the one bucket this build
            # adds (E). Never on a pair that already has a bucket, so no anchor collides and
            # not_listed stays conserved.
            self._caller_signal(e)
            if not e.bucket and p.aligned and e.callers_b is not None:
                e.bucket = "E"
                e.subclass = (
                    "lost_every_direct_caller"
                    if e.callers_b["state"] == "none_found"
                    else "caller_signal_undetermined"
                )
                e.caller_relevance = self._e_relevance(e)
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

    # ── the caller-set edge (S3): callers_a / callers_b ──

    def _reverse_index(self, side: str) -> tuple[dict[str, set[str]], bool]:
        """side -> (callee name -> the addresses that call it, whether that list may be incomplete).
        Built once from _Side.raw — every function's own callee list, reversed, zero extra SQL. A
        name a function calls more than once maps to that caller once. ``maybe_truncated`` is True
        when a function's list was cut, unreadable, or does not record it, so an empty caller set
        cannot be read as a proven-empty one."""
        cached = self._rev.get(side)
        if cached is not None:
            return cached
        s = self.sides[side]
        index: dict[str, set[str]] = {}
        maybe_truncated = s.error is not None
        for addr in s.raw:
            fn = s.fn(addr)
            if fn is None or fn.callees is None:
                maybe_truncated = True
                continue
            if fn.truncated is not False:  # True (cut) or None (not recorded): a prefix, not proof
                maybe_truncated = True
            for callee in fn.callees:
                index.setdefault(callee, set()).add(addr)
        self._rev[side] = (index, maybe_truncated)
        return self._rev[side]

    def _direct_callers(self, side: str, addr: str) -> set[str]:
        """The addresses that directly call the function at ``addr`` on ``side``, by exact name —
        its extracted name and its ``FUN_<addr>`` form — itself excluded. Empty when none were read.
        Read by name, as lib/facts' reverse-caller scan is: a call through a register or a pointer
        table carries no name and is not here (a structural blind spot)."""
        index, _ = self._reverse_index(side)
        callers: set[str] = set()
        name = self.sides[side].names.get(addr)
        if name:
            callers |= index.get(name, set())
        callers |= index.get(f"FUN_{addr}", set())
        callers.discard(addr)  # a self-recursive call is not a caller from elsewhere
        return callers

    def _caller_signal(self, e: _Entry) -> None:
        """Attach the caller-set edge to a pair entry when the A side's function has a direct caller
        and the B side has none found (or none provable). Sets callers_a / callers_b / pairing, or
        leaves them None when there is no edge — the A side has no caller read, or the B side has
        one. Never writes an empty list as a fact; never emits 'blocked'."""
        p = e.pair
        if p is None:
            return
        # A caller must be READ for the edge to exist: a side that could not be read, or whose
        # function is not in that scan's inventory, yields no n_a — "has a caller" is never claimed
        # on absence.
        if self.sides["a"].error is not None or self.sides["a"].fn(p.addr_a) is None:
            return
        callers_a = self._direct_callers("a", p.addr_a)
        if not callers_a:
            return
        state = self._callers_b_state(p)
        if state is None:  # the B side has a caller too: no edge
            return
        e.callers_a = {"count": len(callers_a), "sample": sorted(callers_a)[:_CALLER_SAMPLE]}
        e.callers_b = state
        e.pairing = "aligned" if p.aligned else "proposed"

    def _callers_b_state(self, p: _Pair) -> dict[str, Any] | None:
        """The B side's reading of the pair's function's direct callers: None when a caller WAS read
        (no edge); {state: none_found} when none was read and the lists were complete and in
        inventory; else {state: undetermined, reason}. The order is honest: a stale or unavailable
        source, then a function the B scan does not hold, then a list that may be truncated, before
        a proven none_found."""
        if self.callee_block == "source_stale":
            return {"state": "undetermined", "reason": "source_stale"}
        if self.callee_block == "analysis_db_unavailable":
            return {"state": "undetermined", "reason": "analysis_db_unavailable"}
        if self.sides["b"].fn(p.addr_b) is None:
            return {"state": "undetermined", "reason": "not_in_inventory"}
        if self._direct_callers("b", p.addr_b):
            return None
        if self._reverse_index("b")[1]:  # the B side's lists may be incomplete
            return {"state": "undetermined", "reason": "callees_may_be_truncated"}
        return {"state": "none_found"}

    def _e_relevance(self, e: _Entry) -> int:
        """An E entry's ordering tier within its lane: 0 when it carries a candidate row of its own
        or calls a sink the hunt does not recall, 1 when a callee is itself a sink candidate (one
        hop from a candidate), else 2."""
        if e.tier != NO_SINK:
            return 0
        names = self._both_callees(e.pair)[0] if e.pair is not None else set()
        if names & _RECALL_GAP_NAMES:
            return 0
        return 1 if self._calls_candidate(e) else 2

    def _candidate_entries(self, side: str) -> frozenset[str]:
        """The function entries that hold a sink candidate on ``side``'s binary (one hop lands on
        one of these). Read from the instance table once per (run, binary) and cached across diffs
        and pages — the run's stamps are in the key so a re-hunt is not served a stale set."""
        run = self.diff.run_a if side == "a" else self.diff.run_b
        sha = self.diff.sha_a if side == "a" else self.diff.sha_b
        stamp = self.atlas.execute(
            "SELECT build_hash, hunt_commit, updated_at FROM run WHERE run_id = ?", (run,)
        ).fetchone()
        key = (
            _atlas_identity(self.atlas),
            run,
            sha or "",
            *(str(v or "") for v in (stamp or (None, None, None))),
        )
        hit = _CANDIDATE_ENTRY_CACHE.get(key)
        if hit is not None:
            return hit
        entries: set[str] = set()
        for (ref,) in self.atlas.execute(
            "SELECT evidence_ref FROM instance WHERE source_run_id = ? AND binary_content_hash = ?",
            (run, sha),
        ):
            fe = _func_entry_hex(ref) if ref else None
            if fe is not None:
                entries.add(fe)
        result = frozenset(entries)
        _CANDIDATE_ENTRY_CACHE[key] = result
        return result

    def _calls_candidate(self, e: _Entry) -> bool:
        """Whether either side's function calls a function that itself holds a sink candidate,
        resolved by address (a ``FUN_<addr>`` callee) or by name (``_Side.by_name``)."""
        p = e.pair
        if p is None:
            return False
        for side, addr in (("a", p.addr_a), ("b", p.addr_b)):
            s = self.sides[side]
            fn = s.fn(addr)
            if fn is None or not fn.callees:
                continue
            cands = self._candidate_entries(side)
            for name in fn.callees:
                m = _FUN_RE.fullmatch(name)
                addrs = (
                    [a for a in [norm_hex(m.group(1))] if a is not None]
                    if m is not None
                    else s.by_name.get(name, [])
                )
                if any(a in cands for a in addrs):
                    return True
        return False

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
            # The part of the difference that CAN be told: every callee identified on its side — a
            # name, or a FUN_<addr> through its aligned pair — printed as that side prints it. The
            # state stays undetermined: the unresolved names may hide more.
            if ia.keys() != ib.keys():
                out["named_callees_differ"] = {
                    "only_in_a": sorted(ia[k] for k in ia.keys() - ib.keys()),
                    "only_in_b": sorted(ib[k] for k in ib.keys() - ia.keys()),
                }
            return out
        # Both callee lists were read in full here (unreadable / truncated / not_recorded all
        # returned undetermined above), so ``callees_complete`` says an empty ``only_in_*`` is a
        # proven-empty difference, NOT a list that could not be extracted.
        if ia.keys() == ib.keys():
            return {"state": "equal", "callees_complete": True}
        only_a = sorted(ia[k] for k in ia.keys() - ib.keys())
        only_b = sorted(ib[k] for k in ib.keys() - ia.keys())
        return {
            "state": "differs",
            "only_in_a": only_a,
            "only_in_b": only_b,
            "callees_complete": True,
        }

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
        if e.callers_b is not None and e.callers_b["state"] == "undetermined":
            # The B side's caller set could not be proven empty — a countable blind spot on THIS
            # entry (the structural ones a caller is missed through are in _STRUCTURAL_BLIND_SPOTS).
            spots.append(f"callers_undetermined:{e.callers_b['reason']}")
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
    if e.bucket == "E":
        # The caller-set edge entry. With a candidate of its own it joins segment 2 in its own lane
        # (after R lane 0 and B lane 1); with none it joins segment 3 in its own lane, ordered by
        # caller_relevance. Lanes 2 / 3 are E's alone and leave the R/B lane meanings untouched.
        if e.tier != NO_SINK:
            return {
                "segment": 2,
                "tier": t,
                "lane": 2,
                "subclass_rank": 0,
                "similarity": sim_key,
                "address": e.address,
            }
        return {
            "segment": 3,
            "lane": 3,
            "subclass_rank": e.caller_relevance,
            "similarity": sim_key,
            "address": e.address,
        }
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


def _default_key(r: dict[str, Any], band: int = 0, e_mention: int = 0) -> tuple[Any, ...]:
    """The default order's key. ``band`` (the judgement band, 0 when it is off) sits after the
    first four components and before similarity, so it only ever reorders entries those four
    already hold together — never across a segment, a tier, a lane or a subclass rank. ``e_mention``
    (0 off) is the caller-set edge's B-no-mention key: it is passed ONLY in the significance order,
    and only for E entries, so it never changes the default order, the rank_key or ViewReview's
    position — the cheap layers that cannot read pseudocode and so cannot compute it. It sits inside
    E's own lane (segment 3 subclass rank's tie slot, or segment 2 just before the address), after
    the relevance tier and before the address."""
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
            e_mention,
            r["address"],
        )
    if seg == 3:
        return (
            3,
            r["lane"],
            r["subclass_rank"],
            e_mention,
            band,
            r["similarity"],
            "",
            r["address"],
        )
    return (4, -r["tier"], 0, 0, band, 0.0, r["side"], r["address"])


# ── the significance lens (sort_by="significance"): an opt-in order, never a relabel ──────────

# attention 0 floats, 1 is the similarity-ordered middle, 2 sinks; every entry stays listed.
ATTENTION_FLOAT, ATTENTION_MIDDLE, ATTENTION_SINK = 0, 1, 2

# ── an undetermined pair that is confidently paired and reads differs ──

# A function name a decompiler or disassembler makes up from an address or a role, rather than a
# symbol the binary carries. Matched against the WHOLE name: after the prefix only an optional
# underscore and hex digits (or '@') may follow, so a real symbol that merely starts like one —
# ``init_config``, ``inet_aton``, ``localtime_r`` — does not match.
_SYNTHETIC_NAME_RE = re.compile(
    r"^(?:thunk_)?(?:FUN|DAT|LAB|UNK|SUB|sub|EXT|SWITCH|switchD|caseD|UndefinedFunction|byte"
    r"|dword|word|uRam|iRam|param|local|auStack|aStack|unaff|in|extraout|register)"
    r"_?[0-9a-fA-F@]*$"
)
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")

# The read-first floor: an anchored_differs pair at or above this BinDiff similarity is counted
# among the pairs to read first. A trade-off that keeps that count short, not a boundary the data
# proves: a pair below it keeps its flag, is still ordered ahead of the unflagged entries, and is
# still listed by the anchored_differs filter.
ANCHORED_DIFFERS_SIM_FLOOR = 0.7


def _is_synthetic_name(name: str | None, own_addr: str) -> bool:
    """Whether ``name`` is made up rather than a symbol the binary carries: it matches
    ``_SYNTHETIC_NAME_RE`` as a whole, or the part after its last ``_`` is a hex number of 5+
    digits equal to the function's OWN entry address (a ``loc_<addr>``-style name of a family the
    pattern does not list). A missing or blank name counts as made up. Separate from ``_FUN_RE``,
    which identifies callees and must not change with this."""
    if name is None or not name.strip():
        return True
    n = name.strip()
    if _SYNTHETIC_NAME_RE.fullmatch(n):
        return True
    if "_" not in n:
        return False
    tail = n.rsplit("_", 1)[1]
    if len(tail) < 5 or not set(tail) <= _HEX_DIGITS:
        return False
    try:
        return int(tail, 16) == int(own_addr, 16)
    except ValueError:
        return False


def _anchor(p: _Pair) -> str | None:
    """How a pair's two sides are tied together, if at all: ``addr`` (both at one address),
    ``name`` (one real symbol name on both sides, each side's name judged against its own
    address), ``addr+name``, or None."""
    at_addr = p.addr_a == p.addr_b
    named = (
        p.name_a is not None
        and p.name_b is not None
        and p.name_a.strip() == p.name_b.strip()
        and not _is_synthetic_name(p.name_a, p.addr_a)
        and not _is_synthetic_name(p.name_b, p.addr_b)
    )
    if at_addr and named:
        return "addr+name"
    return "addr" if at_addr else "name" if named else None


def _anchored_differs(e: _Entry, u_state: str | None) -> bool:
    """An undetermined pair that is confidently paired and whose normalized pseudocode differs: no
    export gap on either side (a function the export did not hold as it is cannot be compared
    faithfully), anchored by address or by a real symbol name (:func:`_anchor`), and a proposed
    reading of ``differs``. No similarity bound: BinDiff's similarity 1 does not see a changed
    constant or buffer size. It orders and counts; it moves the entry nowhere and clears nothing
    else in R."""
    p = e.pair
    return (
        p is not None
        and not p.aligned
        and p.export_gap_a is None
        and p.export_gap_b is None
        and u_state == sameness.U_DIFFERS
        and _anchor(p) is not None
    )


def _micro_side(bodies: dict[str, Any] | None) -> bool:
    """Exactly one side a design-skipped micro-stub (under _DECOMPILE_MIN_SIZE bytes, not
    decompiled by design), the other a real body — the shape of a function gutted to, or grown from,
    a stub. Read off sameness.pair_reading's ``bodies``; False when there is no such block (both
    sides had text, or neither is a plain micro/ok pair)."""
    if not bodies:
        return False
    return {bodies["a"]["status"], bodies["b"]["status"]} == {sameness.SKIPPED_MICRO, "ok"}


def _anchored_micro_side(e: _Entry) -> bool:
    """An undetermined pair confidently paired (no export gap, anchored by address or real symbol)
    whose two sides are a micro-stub and a real body (:func:`_micro_side`). No callee check and no
    similarity floor: a function replaced by a stub (or the reverse) is worth reading whatever its
    similarity. It orders and labels; it moves the entry nowhere and clears nothing else in R."""
    p = e.pair
    return (
        p is not None
        and not p.aligned
        and p.export_gap_a is None
        and p.export_gap_b is None
        and _anchor(p) is not None
        and _micro_side(e.body_status)
    )


def _demotable_line_number(e: _Entry) -> bool:
    """Whether a pair's ``line_number_form`` demotes it out of the read-first head: its text changed
    only by a __FILE__/__LINE__ shift, AND its two callee SETS are proven equal (the proposed
    reading's ``callee_set`` state ``equal``, which is read from complete lists), AND both sides'
    body sizes are recorded and equal.

    The text alone cannot see a call added or dropped in a block the decompiler removed as dead;
    the callee set can. The set holds callees, not how often each is called, so a second call to a
    function already called is not in it — equal sizes narrow that (a dead block takes bytes), they
    do not rule it out. Whatever is not proven keeps the pair in the head, where its reading's
    ``demoted`` false, ``callee_set`` and ``size_bytes`` say which. The one predicate behind the
    read-first order, ``demoted`` and the function_states counts."""
    if e.line_number_form is None:
        return False
    if (e.proposed_callee_set or {}).get("state") != "equal":  # differs and undetermined stay
        return False
    if e.sizes is None:
        return False
    sa, sb = e.sizes
    return sa is not None and sb is not None and sa == sb


def _read_first_order(e: _Entry, u_state: str | None) -> int:
    """How far an undetermined pair floats inside attention 1: 2 = anchored_differs at or above
    ``ANCHORED_DIFFERS_SIM_FLOOR`` (the read-first head); 1 = anchored_differs below the floor, an
    anchored_differs pair whose only change is a ``line_number_form`` shift with its callee sets and
    sizes proven equal (:func:`_demotable_line_number`; demoted OUT of the head but still flagged),
    or an anchored micro-side pair; 0 = every other entry. A line-number shift without that proof
    stays at 2."""
    p = e.pair
    if p is None:
        return 0
    if _anchored_differs(e, u_state):
        if _demotable_line_number(e):
            return 1  # a __FILE__/__LINE__ shift: demoted out of the read-first head, still flagged
        return 2 if p.similarity is not None and p.similarity >= ANCHORED_DIFFERS_SIM_FLOOR else 1
    if _anchored_micro_side(e):
        return 1
    return 0


def _sink_callee_swap(e: _Entry) -> dict[str, Any] | None:
    """A sink name in the pair's callee-set difference, or None.

    The difference is the aligned pair's ``callee_set`` (``pairing`` aligned), or for an
    undetermined pair the one its proposed reading compares (``pairing`` proposed); a function with
    no counterpart has none. A ``differs`` set gives the whole difference (``callees_complete``); an
    undetermined set gives only its identified part (``named_callees_differ``), and any other
    undetermined set none at all — so an absent field never means "no sink changed". ``narrow``:
    both lists read in full, and neither side differs by more than two names (FUN_ names
    counted)."""
    p = e.pair
    if p is None:
        return None
    cs = (e.callee_set if p.aligned else e.proposed_callee_set) or {}
    if cs.get("state") == "differs":
        only_a, only_b, complete = cs["only_in_a"], cs["only_in_b"], True
    elif cs.get("state") == "undetermined" and "named_callees_differ" in cs:
        named = cs["named_callees_differ"]
        only_a, only_b, complete = named["only_in_a"], named["only_in_b"], False
    else:
        return None
    sinks_a = sorted(set(only_a) & SINK_CALLEE_NAMES)
    sinks_b = sorted(set(only_b) & SINK_CALLEE_NAMES)
    if not sinks_a and not sinks_b:
        return None
    small = len(only_a) <= _SWAP_NARROW_NAMES and len(only_b) <= _SWAP_NARROW_NAMES
    narrow = complete and small
    return {
        "pairing": "aligned" if p.aligned else "proposed",
        "callees_complete": complete,
        "sinks_only_in_a": sinks_a,
        "sinks_only_in_b": sinks_b,
        "names_only_in_a": len(only_a),
        "names_only_in_b": len(only_b),
        "narrow": narrow,
        "not_narrow": (
            None
            if narrow
            else ("callee_identity_unresolved" if not complete else "names_exceed_two")
        ),
    }


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
      * an aligned pair carrying ``one_side_skipped_micro`` (one side a design-skipped micro-stub,
        the other a real body) -> 1, labelled ``one_side_skipped_micro``: held at attention 1, never
        sunk to 2 as an otherwise identical / bucket-C pair would be;
      * pseudocode ``identical``, a proposed ``identical_unique``, or bucket C -> 2 — unless the
        entry is R (an undetermined pair is never buried under the pairs that were read) or its
        judgement is held up (changed_real, needs_recheck / needs_relabel, inconclusive), which
        stops it at 1; or, after both, a bucket C entry carrying a narrow
        :func:`_sink_callee_swap` -> 1, labelled ``sink_callee_swap_never_sunk`` (the only basis
        the swap ever takes: elsewhere it is a field, and orders entries inside attention 1
        through ``_sort``); or, last, the caller-set edge: an E entry -> 1 (basis
        ``lost_every_direct_caller_never_sunk`` for a proven-none B side, else
        ``caller_signal_undetermined_never_sunk``), and any other entry whose B side is a proven
        none_found -> 1, ``lost_every_direct_caller_never_sunk`` (an undetermined edge on an
        already-listed entry does not move it);
      * an undetermined pair flagged :func:`_anchored_micro_side` (micro-stub vs real body) -> 1,
        labelled ``anchored_micro_side``, BEFORE anchored_differs so a pair that is both reads as
        the micro side;
      * an undetermined pair flagged :func:`_anchored_differs` -> 1, labelled
        ``anchored_differs``: still attention 1 (an R entry never reaches 0 or 2 on it), ordered
        first inside it (``read_first`` in :func:`_sort`);
      * everything else -> 1, ordered by similarity, lowest first. ``identical_text_unverified``
        is never sunk outside C.

    The caller-set edge (S3): a bucket-E entry is always attention 1 (basis
    ``lost_every_direct_caller_never_sunk`` for a proven-none B side, else
    ``caller_signal_undetermined_never_sunk``) — read FIRST, since E is listed for that edge alone,
    so its basis never reads as the generic ``similarity`` fall-through. On a NON-E entry the edge
    only holds one off the bottom, in the identical / C branch below, and only for a proven
    none_found — never an undetermined edge on an already-listed entry."""
    if e.bucket == "E":
        cb = e.callers_b
        if cb is not None and cb["state"] == "none_found":
            return ATTENTION_MIDDLE, "lost_every_direct_caller_never_sunk"
        return ATTENTION_MIDDLE, "caller_signal_undetermined_never_sunk"
    if e.bucket == "A":
        return ATTENTION_FLOAT, "matched_call_other_callee"
    if any("sink_arg_constant_delta" in v for v in e.row_views):
        return ATTENTION_FLOAT, "sink_arg_constant_delta"
    if e.subclass == "sink_present_no_visible_delta":
        return ATTENTION_MIDDLE, "recheckable_no_visible_delta"
    if "one_side_skipped_micro" in e.facts:
        # an aligned pair gutted to (or grown from) a micro-stub on one side: held at attention 1,
        # never sunk to 2 as an identical / bucket-C pair would be.
        return ATTENTION_MIDDLE, "one_side_skipped_micro"
    if state == sameness.IDENTICAL or u_state == sameness.U_IDENTICAL_UNIQUE or e.bucket == "C":
        basis = "pseudocode_identical" if state == sameness.IDENTICAL else "no_sink_candidate"
        if e.bucket == "R":
            return ATTENTION_MIDDLE, "undetermined_never_sunk"
        if _held_up(item):
            return ATTENTION_MIDDLE, "judged_never_sunk"
        # After R and a held-up judgement, so neither basis is ever replaced by the swap: only a
        # bucket C entry that would otherwise sink is held at 1 by it.
        if e.bucket == "C" and (swap := _sink_callee_swap(e)) is not None and swap["narrow"]:
            return ATTENTION_MIDDLE, "sink_callee_swap_never_sunk"
        # The caller-set edge (S3) holds a NON-E entry off the bottom too, LAST so it never replaces
        # a basis above, and only when the B side is a proven none — an undetermined edge on an
        # already-listed entry does not move it (E, which IS listed for the edge, is handled first).
        if e.callers_b is not None and e.callers_b["state"] == "none_found":
            return ATTENTION_MIDDLE, "lost_every_direct_caller_never_sunk"
        return ATTENTION_SINK, basis
    if e.bucket == "P":
        return ATTENTION_MIDDLE, "no_counterpart"
    if _anchored_micro_side(e):
        # before anchored_differs so a pair that is both reads as the micro side.
        return ATTENTION_MIDDLE, "anchored_micro_side"
    if _anchored_differs(e, u_state):
        return ATTENTION_MIDDLE, "anchored_differs"
    return ATTENTION_MIDDLE, "similarity"


def _sort(
    entries: list[_Entry],
    sort_by: str | None,
    band: dict[str, int] | None = None,
    attention: dict[str, int] | None = None,
    settled: dict[str, int] | None = None,
    read_first: dict[str, int] | None = None,
    swap_lift: dict[str, int] | None = None,
    mention: dict[str, int] | None = None,
) -> list[_Entry]:
    """The default order, or ``sort_by`` (one named component) ahead of it. P stays last either
    way: a function with no counterpart is not ordered among the pairs. ``band`` maps an entry id
    to its judgement band (diff_review.band_bias); None leaves the order as it is.

    ``sort_by="significance"`` orders by ``(attention, swap_lift, read_first, band, settled,
    similarity, default key)`` — ``attention`` from :func:`significance`; ``swap_lift`` (1 for an
    attention-1 entry carrying a narrow :func:`_sink_callee_swap`, whatever its basis or
    judgement) first inside the tier; ``read_first`` (:func:`_read_first_order`, highest first) so
    that next the anchored_differs pairs at or above the floor come, then those below it, then the
    rest; the band only when it is on
    (judgements move nothing unless asked); ``settled`` (1 for an R entry whose proposed reading
    is ``identical_unique``, so it closes its tier, still ahead of every sunk entry); similarity
    lowest first; then the default order."""

    def key(e: _Entry) -> tuple[Any, ...]:
        r = e.rank
        p_last = 1 if r["segment"] == 4 else 0
        if sort_by == "significance":
            return (
                p_last,
                (attention or {}).get(e.entry_id, ATTENTION_MIDDLE),
                -(swap_lift or {}).get(e.entry_id, 0),
                -(read_first or {}).get(e.entry_id, 0),
                band.get(e.entry_id, 0) if band else 0,
                (settled or {}).get(e.entry_id, 0),
                r.get("similarity", -1.0),
                *_default_key(r, 0, (mention or {}).get(e.entry_id, 0)),
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
    swap = _sink_callee_swap(e)
    out.update(
        {
            "coclaimed_by": coclaimed or None,
            "callee_set": e.callee_set,
            **({"sink_callee_swap": swap} if swap is not None else {}),
            # The caller-set edge (S3): present only when it exists; a field on any pair entry,
            # never in diff_review.entry_facts, so it moves no existing judgement.
            **(
                {"pairing": e.pairing, "callers_a": e.callers_a, "callers_b": e.callers_b}
                if e.callers_b is not None
                else {}
            ),
            "facts": sorted(set(e.facts)),
            "blind_spots": e.blind_spots,
            "string_edges": e.string_edges,
            "rows": e.row_views,
        }
    )
    return out


def _row_group(view: dict[str, Any]) -> int:
    """The window group of one rendered row (an index into ``_ROW_GROUPS``)."""
    if view["presence"] != "persisted":
        return 0
    return 1 if any(k in view for k in _SIZE_SIGNALS) else 2


def _rows_window(
    views: list[dict[str, Any]], offset: int, n: int
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """One window of an entry's rendered rows, and the fields that say what lies outside it.

    Up to ``n`` rows fit as they are, in their own order. More than that are ordered by
    ``_row_group`` — a stable sort, so each group keeps its order — and ``offset`` picks the window.
    The counts are over EVERY row, so a row left out of the window is still counted; a group with no
    row is written as 0, never dropped. Returns a new list: ``views`` (the entry's own list) is
    never reordered or cut."""
    total = len(views)
    ordered = list(views) if total <= n else sorted(views, key=_row_group)
    page = ordered[offset : offset + n]
    end = offset + len(page)
    fields: dict[str, Any] = {
        "rows_total": total,
        "rows_next_offset": end if end < total else None,
    }
    if total > n:
        groups = [0] * len(_ROW_GROUPS)
        for v in views:
            groups[_row_group(v)] += 1
        fields["rows_order"] = ROWS_ORDER
        fields["rows_by_presence"] = _count(v["presence"] for v in views)
        fields["rows_by_order_group"] = dict(zip(_ROW_GROUPS, groups, strict=True))
    return page, fields


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
    entry_id: str | None = None,
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
    if view != "sink_patch" and (filtered or sort_by is not None or entry_id is not None):
        return (
            "sort_by / bucket / subclass / tier / blind_spot / body / entry_id apply to "
            "view='sink_patch' only"
        )
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LIMIT:
        return f"limit must be an integer in 1..{MAX_LIMIT}, got {limit!r}"
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        return f"offset must be an integer >= 0, got {offset!r}"
    return None


def _check_entry_args(
    entry_id: Any,
    rows_offset: Any,
    rows_limit: Any,
    offset: int,
    filters: dict[str, Any],
    not_listed_page: str | None,
) -> str | None:
    """The argument combinations of reading one entry, refused before anything is built — a
    combination this cannot honour is an error, never silently ignored."""
    if isinstance(rows_limit, bool) or not isinstance(rows_limit, int) or rows_limit < 1:
        return f"rows_limit must be an integer >= 1, got {rows_limit!r}"
    if rows_offset is not None and (
        isinstance(rows_offset, bool) or not isinstance(rows_offset, int) or rows_offset < 0
    ):
        return f"rows_offset must be an integer >= 0, got {rows_offset!r}"
    if entry_id is None:
        if rows_offset is not None:
            return "rows_offset pages one entry's rows: pass that entry's entry_id with it"
        return None
    if not isinstance(entry_id, str) or not entry_id:
        return f"entry_id must be an entry's entry_id or anchor_ref, got {entry_id!r}"
    if not_listed_page is not None:
        return "entry_id names a listed entry; it does not apply to not_listed_page"
    given = sorted(k for k, v in filters.items() if v is not None)
    if given:
        return f"entry_id reads one entry and takes no filter (got {', '.join(given)})"
    if offset != 0:
        return "entry_id reads one entry: page its rows with rows_offset, not offset"
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
    b_names: dict[str, str]  # the B side's function addr -> extracted name (the caller-set edge's
    # no-mention reading tokenises the B bodies for these names); empty when withheld


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
    b_names: dict[str, str] = {}
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
        b_names = dict(builder.sides["b"].names)
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
        b_names=b_names,
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
    # Each side's body status + size when there was no text to compare (sameness.pair_reading's
    # ``bodies``), else None: {a: {status, size_bytes}, b: {...}}. A read-face detail, not a state.
    bodies: dict[str, Any] | None = None
    # (size_bytes_a, size_bytes_b) when both sides' bodies were read — each None when not recorded
    # (sameness.read_function_bodies) — else None. Apart from ``bodies``, which exists only when a
    # side had no text: a line-number shift has text on both sides.
    sizes: tuple[int | None, int | None] | None = None


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
    # The B-side addresses of the E entries' functions that ANOTHER B function's pseudocode mentions
    # by name (the caller-set edge's no-mention ordering key); empty when the diff has no E entry.
    b_mentions: frozenset[str] = frozenset()


# Process-wide caches of the expensive read, per (diff_id, sha_a, sha_b, build_hash_a,
# build_hash_b): each pair's small reading — never the bodies or the skeleton index. The callee-set
# state a reading folds with comes from the build and is re-read each call. The pseudocode_delta
# cache adds the pair's two addresses to that key.
_PSEUDO_READING_CACHE: _BoundedCache[tuple[str, ...], _PairReads] = _BoundedCache(32)
_UNDETERMINED_READING_CACHE: _BoundedCache[tuple[str, ...], _PairReads] = _BoundedCache(32)
_DELTA_CACHE: _BoundedCache[tuple[Any, ...], dict[str, Any]] = _BoundedCache(4096)
# The no-mention index of the caller-set edge, on the SAME key as the pseudocode readings: computed
# when the B bodies are read (never a second read of them), so every page of one diff reads the
# same set in the same order.
_B_MENTIONS_CACHE: _BoundedCache[tuple[str, ...], frozenset[str]] = _BoundedCache(32)
_ELSEWHERE_SAMPLE = 3  # addresses shown of a body found elsewhere


def _clear_view_caches() -> None:
    """Drop the process-wide pseudocode-reading, delta and size-fact caches (tests reuse one
    diff_id, run ids and build hash across databases)."""
    _PSEUDO_READING_CACHE.clear()
    _UNDETERMINED_READING_CACHE.clear()
    _DELTA_CACHE.clear()
    _B_MENTIONS_CACHE.clear()
    _SIZE_FACT_CACHE.clear()
    _CANDIDATE_ENTRY_CACHE.clear()


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
    matches, reason, reasons, bodies = sameness.pair_reading(ba, bb, p.addr_a, p.addr_b, ra, rb)
    hidden = None
    if matches and ba is not None and bb is not None:
        hidden = sameness.hidden_region(
            ba[p.addr_a],
            bb[p.addr_b],
            reasons,
            similarity=p.similarity,
            instructions=p.instructions,
        )
    sizes = None
    if ba is not None and bb is not None:
        sizes = (
            (ba.get(p.addr_a) or {}).get("size_bytes"),
            (bb.get(p.addr_b) or {}).get("size_bytes"),
        )
    return _Read(matches, reason, reasons, hidden, bodies=bodies, sizes=sizes)


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
    # The atlas and the diff code that wrote the pairs are in the key too: one process can serve
    # two atlases with the same diff id, and a diff re-run by newer code can pair functions anew.
    dcv = atlas.execute(
        "SELECT diff_code_version FROM diff_meta WHERE diff_id = ?", (d.diff_id,)
    ).fetchone()
    key = (
        _atlas_identity(atlas),
        d.diff_id,
        str(dcv[0] or "") if dcv else "",
        d.sha_a or "",
        d.sha_b or "",
        ha or "",
        hb or "",
    )
    aligned = _PSEUDO_READING_CACHE.get(key)
    undetermined = _UNDETERMINED_READING_CACHE.get(key)
    mentions = _B_MENTIONS_CACHE.get(key)
    if aligned is None or undetermined is None or mentions is None:
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
        if mentions is None:
            mentions = _b_other_fn_mentions(bb, built)
            _B_MENTIONS_CACHE[key] = mentions
    return _Readings(key, ((pa, d.sha_a), (pb, d.sha_b)), aligned, undetermined, mentions)


def _b_other_fn_mentions(bb: sameness.Bodies | None, built: BuiltDiff) -> frozenset[str]:
    """The B-side addresses of the E entries' functions that ANOTHER B function's pseudocode
    mentions by an identifier token — the function's extracted name or its ``FUN_<addr>`` form,
    its OWN body excluded. The token index over every B body is built once and only when the diff
    has an E entry, so a diff with none pays nothing. Comment and string tokens are not mentions."""
    targets = [
        (e.pair.addr_b, built.b_names.get(e.pair.addr_b))
        for e in built.entries
        if e.bucket == "E" and e.pair is not None
    ]
    if not targets or not bb:
        return frozenset()
    tok2addr: dict[str, set[str]] = {}
    for addr, body in bb.items():
        text = body.get("pseudocode")
        if not text:
            continue
        for kind, tok in sameness._tokens(text):
            if kind == "ident":
                tok2addr.setdefault(tok, set()).add(addr)
    mentioned: set[str] = set()
    for addr_b, name in targets:
        wanted = {f"FUN_{addr_b}"}
        if name:
            wanted.add(name)
        if any(tok2addr.get(w, set()) - {addr_b} for w in wanted):
            mentioned.add(addr_b)
    return frozenset(mentioned)


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


def _u_state(e: _Entry, readings: _Readings) -> str | None:
    """The state of an undetermined pair's proposed reading; None for any other entry."""
    proposed = _proposed_of(e, readings)
    return proposed[0] if proposed is not None else None


# The 5-bucket cause of a pair whose reading is UNAVAILABLE (one side had no text), strongest gap
# first, so the keys PARTITION the UNAVAILABLE pairs (each counted exactly once).
_UNAVAILABLE_CAUSES = (
    "db_unavailable",
    "decompile_empty",
    "size_unknown",
    "one_side_skipped_micro",
    "both_skipped_micro",
)


def _cause_of(bodies: dict[str, Any] | None) -> str:
    """Which of :data:`_UNAVAILABLE_CAUSES` a UNAVAILABLE pair falls in, from its two sides' body
    status (sameness.pair_reading's ``bodies``): the first that matches, strongest gap first — so a
    micro + decompile_empty pair is ``decompile_empty`` and a db read failure on either side wins
    over everything. Falls back to ``db_unavailable`` only if the block is missing, which an
    UNAVAILABLE pair never leaves."""
    if not bodies:
        return "db_unavailable"
    a, b = bodies["a"]["status"], bodies["b"]["status"]
    sides = {a, b}
    if sameness.DB_UNAVAILABLE in sides:
        return "db_unavailable"
    if sameness.DECOMPILE_EMPTY in sides:
        return "decompile_empty"
    if sameness.SIZE_UNKNOWN in sides:
        return "size_unknown"
    if a == sameness.SKIPPED_MICRO and b == sameness.SKIPPED_MICRO:
        return "both_skipped_micro"
    return "one_side_skipped_micro"


def _annotate_entries(built: BuiltDiff, readings: _Readings) -> None:
    """Attach, once readings are in hand, the read-face facts that significance / _read_first_order
    read straight off the entry: each pair's per-side ``body_status`` (sameness.pair_reading's
    ``bodies``, consumed by the micro predicates and unavailable_by_cause), both sides' body
    ``sizes``, the ``one_side_skipped_micro`` fact on an aligned micro pair, and, on an
    anchored_differs pair at or above the read-first floor, its ``line_number_form`` (computed once
    through the delta cache), which demotes it out of the read-first head when its callee sets and
    sizes are proven equal too (:func:`_demotable_line_number`). Entries are rebuilt each call, so
    this re-annotates cleanly; call it before significance, _sort, _read_first_order or the
    function_states counts."""
    anchored: list[_Pair] = []
    for e in built.placed:
        p = e.pair
        if p is None:
            continue
        reads = readings.aligned if p.aligned else readings.undetermined
        read = reads.get((p.addr_a, p.addr_b))
        if read is None:
            continue
        e.body_status = read.bodies
        e.sizes = read.sizes
        if p.aligned:
            if _micro_side(read.bodies) and "one_side_skipped_micro" not in e.facts:
                e.facts.append("one_side_skipped_micro")
            continue
        proposed = _proposed_of(e, readings)
        if (
            proposed is not None
            and _anchored_differs(e, proposed[0])
            and p.similarity is not None
            and p.similarity >= ANCHORED_DIFFERS_SIM_FLOOR
        ):
            anchored.append(p)
    if not anchored:
        return
    deltas = _deltas(readings, anchored)
    want = {(p.addr_a, p.addr_b) for p in anchored}
    for e in built.placed:
        p = e.pair
        if p is not None and (p.addr_a, p.addr_b) in want:
            delta = deltas.get((p.addr_a, p.addr_b))
            e.line_number_form = delta.get("line_number_form") if delta else None


def _anchored_order(
    entries: list[_Entry], read_first: dict[str, int], band: dict[str, int] | None
) -> list[_Entry]:
    """The order of the anchored_differs filter when no ``sort_by`` is given: the read-first pairs
    (at or above the floor) first, then by similarity, highest first, then the default order."""

    def key(e: _Entry) -> tuple[Any, ...]:
        sim = e.pair.similarity if e.pair is not None else None
        return (
            -read_first.get(e.entry_id, 0),
            sim is None,
            -(sim or 0.0),
            *_default_key(e.rank, band.get(e.entry_id, 0) if band else 0),
        )

    return sorted(entries, key=key)


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
            # the two sides' own names feed line_number_form's "arg equals the function name" test;
            # a synthetic FUN_/loc_ name carries no such meaning, so it is passed as None.
            na = p.name_a if p.name_a and not _is_synthetic_name(p.name_a, p.addr_a) else None
            nb = p.name_b if p.name_b and not _is_synthetic_name(p.name_b, p.addr_b) else None
            delta = sameness.pseudocode_delta(ta, tb, ra, rb, p.addr_a, p.addr_b, na, nb)
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


def _page_bodies(readings: _Readings, page: list[_Entry]) -> dict[tuple[str, str], dict[str, Any]]:
    """Each paged pair's ``bodies`` block — per side its body ``status`` and ``size_bytes``, present
    only when a side had no text to compare (sameness.pair_reading) — with a design-skipped micro-
    stub side's stored disassembly inlined (``listing``, or ``listing: null`` with
    ``listing_note``). The listings are read only for the page being rendered, and only when a side
    of it is a micro-stub."""
    blocks: dict[tuple[str, str], dict[str, Any]] = {}
    want: dict[str, set[str]] = {"a": set(), "b": set()}
    for e in page:
        p = e.pair
        if p is None or not e.body_status:
            continue
        blocks[(p.addr_a, p.addr_b)] = e.body_status
        for side, addr in (("a", p.addr_a), ("b", p.addr_b)):
            if e.body_status[side]["status"] == sameness.SKIPPED_MICRO:
                want[side].add(addr)
    listings: dict[str, dict[str, dict[str, Any]]] = {"a": {}, "b": {}}
    for side, (path, sha) in zip(("a", "b"), readings.sources, strict=True):
        if want[side]:
            listings[side] = sameness.read_micro_listings(path, sha, want[side])
    return {
        key: {
            side: {**bodies[side], **listings[side].get(addr, {})}
            for side, addr in zip(("a", "b"), key, strict=True)
        }
        for key, bodies in blocks.items()
    }


def _proposed_json(
    e: _Entry,
    state: str,
    read: _Read,
    deltas: dict[tuple[str, str], dict[str, Any]],
    bodies: dict[tuple[str, str], dict[str, Any]],
) -> dict[str, Any]:
    """An undetermined pair's ``proposed_pair_reading``: read as if it were paired, beside the
    entry and never as its pseudocode_sameness. ``occurrences`` and the two ``*_elsewhere_*`` are
    null unless both bodies were read. A pair flagged :func:`_anchored_differs` also carries
    ``anchored_differs: true``, its ``anchor`` and ``in_read_first`` (at or above the floor),
    whatever the sort; one whose text changed only by a line-number shift carries that shape
    (``line_number_form``), ``demoted`` and both sides' ``size_bytes``: demoted (``in_read_first:
    false``, still flagged) when its callee sets and sizes are proven equal, else kept in the head
    with ``demoted: false``, its ``callee_set`` and ``size_bytes`` showing which was not. A
    micro-side R pair is NOT anchored_differs, so it carries no such block here. A pair with no text
    on a side carries ``bodies`` (:func:`_page_bodies`): which side is the micro-stub, its size and
    its listing."""
    p = e.pair
    assert p is not None
    out: dict[str, Any] = {"pairing": "undetermined", "state": state}
    if _anchored_differs(e, state):
        order = _read_first_order(e, state)
        out.update({"anchored_differs": True, "anchor": _anchor(p), "in_read_first": order == 2})
        if e.line_number_form is not None:
            # The text changed only by a __FILE__/__LINE__ shift. Demoted out of the read-first
            # head (in_read_first false) only when the callee sets and both sizes are proven equal
            # too; either way still flagged — anchored_differs=true pages it. line_number_form is
            # set only at or above the floor, so demoted == (not in_read_first).
            out["line_number_form"] = e.line_number_form
            out["demoted"] = _demotable_line_number(e)
            sa, sb = e.sizes if e.sizes is not None else (None, None)
            out["size_bytes"] = {"a": sa, "b": sb}
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
    if (p.addr_a, p.addr_b) in bodies:
        out["bodies"] = bodies[(p.addr_a, p.addr_b)]
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
    "(sunk, still listed and pageable) — except that a bucket C entry carrying a narrow "
    "sink_callee_swap stays at 1, basis sink_callee_swap_never_sunk (a wide one still sinks); 1 = "
    "the rest, lowest similarity first, R and B entries ordered together — except that, first "
    "inside attention 1, come the entries carrying a narrow sink_callee_swap (a sink name in a "
    "callee-set difference read in full, at most two names on either side; rank_key."
    "sink_callee_swap = 1), whatever their basis, which the swap does not replace (bucket C "
    "aside); then an undetermined pair flagged anchored_differs (no export gap, "
    "the same address or the same real symbol name on both sides, proposed reading differs): "
    f"those at or above similarity {ANCHORED_DIFFERS_SIM_FLOOR} first, "
    "then those below it, basis anchored_differs — except that a flagged pair whose text changed "
    "only by a __FILE__/__LINE__ line-number shift AND whose callee sets and body sizes are both "
    "proven equal is demoted out of that read-first head (demoted true; still flagged, "
    "anchored_differs=true pages it). A line-number shift without that proof stays in the head "
    "with demoted false: a call added or dropped in a block the decompiler removed is not in the "
    "text, and its callee_set and size_bytes show which was not proven equal. Equal callee sets "
    "and sizes narrow that, they do not rule it out: the set holds callees, not how often each is "
    "called. The flag clears nothing else in R: every other undetermined "
    "pair reading differs is still to be read. An undetermined pair anchored with one side a "
    "design-skipped micro-stub (under the decompile size floor, not decompiled by design — a "
    "binary property, NOT a read failure) and the other a real body gets basis anchored_micro_side "
    "(before anchored_differs when a pair is both), and an aligned pair of the same shape gets "
    "basis one_side_skipped_micro, both held at attention 1 rather than sunk. Such a pair's "
    "reading carries bodies: per side its status and size_bytes, and on the micro-stub side its "
    "stored disassembly inline (listing; listing null with listing_note "
    "not_exported_by_this_scan when the binary was extracted before tmap stored disassembly — a "
    "re-scan stores it — or not_stored, which get_disassembly explains). "
    "Attention 0 holds B entries too (a row's sink_arg_constant_delta) beside "
    "A. Never sunk: an R entry (attention 2 never holds one; one whose proposed_pair_reading is "
    "identical_unique closes attention 1 instead), a B sink_present_no_visible_delta (labelled "
    "recheckable_no_visible_delta), an identical_text_unverified entry outside bucket C, a bucket "
    "C entry with a narrow sink_callee_swap, an E entry or any entry whose B side lost every "
    "direct caller (caller-set edge: basis lost_every_direct_caller_never_sunk, or "
    "caller_signal_undetermined_never_sunk for an E whose B side could not be proven), and an "
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
    import / PLT stub, kept out of every other count). ``unavailable_by_cause`` splits the aligned
    ``unavailable`` count by why a side had no text (db_unavailable / decompile_empty / size_unknown
    / one_side_skipped_micro / both_skipped_micro) and its values SUM to that count — a design-
    skipped micro-stub told apart from a real decompile gap. Pairs whose alignment is undetermined
    are counted beside them, and ``alignment_undetermined_reading`` splits them by their proposed
    reading (never into the aligned counts); of those reading differs,
    ``alignment_undetermined_anchored_differs`` counts the pairs flagged anchored_differs at or
    above the read-first floor that are not demoted (the read-first head),
    ``alignment_undetermined_anchored_differs_line_number_form`` the ones at or above the floor
    demoted because their text changed only by a __FILE__/__LINE__ shift and their callee sets and
    body sizes are proven equal (still flagged),
    ``alignment_undetermined_anchored_differs_line_number_kept`` the head pairs whose text changed
    only by such a shift but whose callee sets or sizes are not proven equal (part of the head
    count), and ``alignment_undetermined_anchored_differs_all`` every flagged pair, below the floor
    included.
    ``alignment_undetermined_anchored_micro_side`` counts undetermined pairs anchored with one side
    a micro-stub and the other a real body; ``alignment_undetermined_unavailable_by_cause`` splits
    the proposed-unavailable pairs the same way, summing to their reading count. Functions with no
    counterpart are counted by presence_state,
    never "added"/"removed". A diff undetermined as a whole is ``withheld`` with its banners and NO
    counts — a blind spot, not zero changes. None when there is no such diff."""
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
    _annotate_entries(built, readings)
    tally: dict[str, int] = {}
    by_body = {cls: 0 for cls in sameness.BODY_CLASSES}
    proposed = {state: 0 for state in sameness.U_STATES}
    scoped = 0
    anchored = anchored_all = line_number_form = line_number_kept = micro = 0
    unavail_cause = {k: 0 for k in _UNAVAILABLE_CAUSES}  # aligned pairs reading unavailable
    u_unavail_cause = {k: 0 for k in _UNAVAILABLE_CAUSES}  # undetermined pairs proposed unavailable
    for e in built.placed:
        reading = _proposed_of(e, readings)
        if reading is not None:
            ustate = reading[0]
            proposed[ustate] += 1
            # ``_all`` is every flagged pair; read it off _anchored_differs, NOT a non-zero
            # read_first order — an anchored_micro_side pair also orders 1 and must not inflate it.
            if _anchored_differs(e, ustate):
                anchored_all += 1
                p = e.pair
                at_floor = (
                    p is not None
                    and p.similarity is not None
                    and p.similarity >= ANCHORED_DIFFERS_SIM_FLOOR
                )
                if at_floor and _demotable_line_number(e):
                    line_number_form += 1  # flagged, demoted out of the read-first head (L)
                elif at_floor:
                    anchored += 1  # the read-first head (N, == read_first order 2)
                    if e.line_number_form is not None:
                        # a line-number shift whose callee sets or sizes are not proven equal:
                        # kept in the head (K, part of N)
                        line_number_kept += 1
            # a separate count, NOT mutually exclusive with anchored_differs: a pair that is both
            # is listed by the anchored_micro_side filter, so it is counted here too (basis micro).
            if _anchored_micro_side(e):
                micro += 1
            if ustate == sameness.U_UNAVAILABLE:
                u_unavail_cause[_cause_of(e.body_status)] += 1
        state = _sameness_of(e, readings)
        if state is None:
            continue
        tally[state] = tally.get(state, 0) + 1
        if state == sameness.DIFFERS and _carries_scoped_sink_delta(e):
            scoped += 1
        if state == sameness.IDENTICAL_TEXT_UNVERIFIED:
            by_body[_body_of(e, readings) or sameness.BODY_UNKNOWN] += 1
        if state == sameness.UNAVAILABLE:
            unavail_cause[_cause_of(e.body_status)] += 1
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
        "unavailable_by_cause": unavail_cause,
        "no_body": tally.get(sameness.NO_BODY, 0),
        "alignment_undetermined": undetermined,
        "alignment_undetermined_reading": proposed,
        "alignment_undetermined_anchored_differs": anchored,
        "alignment_undetermined_anchored_differs_line_number_form": line_number_form,
        "alignment_undetermined_anchored_differs_line_number_kept": line_number_kept,
        "alignment_undetermined_anchored_differs_all": anchored_all,
        "alignment_undetermined_anchored_micro_side": micro,
        "alignment_undetermined_unavailable_by_cause": u_unavail_cause,
        "one_sided": {s: dict(sorted(v.items())) for s, v in sorted(one_sided.items())},
    }


def anchored_differs_banner(states: dict[str, Any] | None) -> str | None:
    """The read-first banner of one diff's :func:`function_states`, or None when no undetermined
    pair is flagged anchored_differs or anchored_micro_side (or the diff is withheld, which has no
    counts). It names the read-first head (AFTER line-number shifts with proven-equal callee sets
    and sizes are demoted out of it), the pairs so demoted, the line-number shifts kept in the head
    for want of that proof, the anchored micro-side pairs, and — ALWAYS — that the flagged pairs do
    not stand for the rest of R, and, whenever any pair is flagged anchored_differs, that the head
    pairs are not yet told apart (a demotion or none)."""
    if not states or states.get("withheld"):
        return None
    flagged = int(states.get("alignment_undetermined_anchored_differs_all") or 0)
    micro = int(states.get("alignment_undetermined_anchored_micro_side") or 0)
    if flagged <= 0 and micro <= 0:
        return None
    first = int(states.get("alignment_undetermined_anchored_differs") or 0)
    lnf = int(states.get("alignment_undetermined_anchored_differs_line_number_form") or 0)
    kept = int(states.get("alignment_undetermined_anchored_differs_line_number_kept") or 0)
    differs = int((states.get("alignment_undetermined_reading") or {}).get(sameness.U_DIFFERS, 0))
    parts: list[str] = []
    if flagged > 0:
        parts.append(
            f"anchored_differs: {first} undetermined pairs are confidently paired (same address or "
            "same real symbol), their normalized pseudocode differs, and they sit at or above the "
            f"read-first similarity floor ({ANCHORED_DIFFERS_SIM_FLOOR}) — read these first: "
            'get_diff_patch_view(bucket="R", anchored_differs=true).'
        )
        if lnf:
            parts.append(
                f"{lnf} more anchored pairs were demoted out of the head because their text "
                "changed only by a __FILE__/__LINE__ line-number shift and both sides' callee sets "
                "and body sizes are equal — still flagged (anchored_differs=true pages them)."
            )
        if kept:
            parts.append(
                f"{kept} of the head pairs changed only by such a line-number shift in the text, "
                "but stay in the head: their callee sets or body sizes are not proven equal "
                "(demoted=false; read their callee_set and size_bytes)."
            )
        parts.append(
            f"The {first} head pairs are NOT yet told apart: each still holds build info, a "
            "structure shift, a moved string or a real change, unresolved."
        )
    if micro:
        parts.append(
            f"{micro} anchored pairs have one side a design-skipped micro-stub and the other a "
            "real body (a pair may also be flagged anchored_differs): "
            'get_diff_patch_view(bucket="R", anchored_micro_side=true).'
        )
    rest = (
        f"the rest of the R bucket: {differs} undetermined pairs read 'differs' in total. Walk the "
        'remainder with get_diff_patch_view(bucket="R", sort_by="significance") to the end.'
    )
    if flagged > 0:
        parts.append(
            f"{flagged} anchored pairs differ in total (incl. below the floor); this does NOT "
            f"clear {rest}"
        )
    else:
        parts.append(f"This does NOT clear {rest}")
    return " ".join(parts)


def _resolve_entry(built: BuiltDiff, entry_id: str) -> _Entry | str:
    """The listed entry ``entry_id`` names — by its entry_id, or by its anchor_ref — or why none.

    Read the way promote reads its entry (lib/query/diff_annotations), whose wording the refusals
    share: an anchor of another run pair or binary, or a candidate anchor, is refused by what it
    is. An entry that is placed but not listed is named as such, with where it is counted."""
    d = built.diff
    for e in built.entries:
        if e.entry_id == entry_id:
            return e
    if "#" in entry_id:
        if not d.binary:
            return (
                f"diff {d.diff_id!r} records no binary name, which every anchor carries — re-run "
                "it, or name the entry by its entry_id"
            )
        parts = diff_review.split_anchor(entry_id, d.run_a, d.run_b)
        if parts is None:
            return (
                f"{entry_id!r} is not an anchor of this diff's run pair "
                f"({diff_review.run_pair(d.run_a, d.run_b)}#<subject>#<key>) — copy it from the "
                "entry's anchor_ref"
            )
        kind, key = parts
        named = diff_review.key_binary(kind, key)
        if kind != "candidate" and named != d.binary:
            return f"{entry_id!r} names binary {named!r}, but diff {d.diff_id!r} is of {d.binary!r}"
        if kind == "candidate":
            return (
                "entry_id takes an entry (its entry_id or anchor_ref), not a candidate anchor — a "
                "candidate is read in its entry's rows"
            )
        for e in built.entries:
            if diff_review.entry_anchor(e, d.run_a, d.run_b, d.binary) == entry_id:
                return e
    for e in built.placed:
        if e.bucket:
            continue
        anchor = diff_review.entry_anchor(e, d.run_a, d.run_b, d.binary) if d.binary else None
        if entry_id in (e.entry_id, anchor):
            return (
                f"{entry_id!r} is placed but not listed: it is counted under not_listed by its "
                "pseudocode_sameness — walk it with not_listed_page"
            )
    return f"{entry_id!r} is not an entry get_diff_patch_view lists for this diff now"


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
    anchored_differs: bool = False,
    anchored_micro_side: bool = False,
    entry_id: str | None = None,
    rows_offset: int | None = None,
    rows_limit: int = ROWS_INLINE_LIMIT,
) -> dict[str, Any]:
    """The function-level view of one diff (see the module docstring), one page of it.

    ``view``: ``sink_patch`` (function pairs, the default), ``string_edge`` (get_diff_deltas'
    rows), ``candidate_flat`` (get_diff_sink_overlay's rows, in its order). The filters and
    ``sort_by`` apply to ``sink_patch``; ``counts`` / ``not_listed`` / ``blind_spots`` always
    describe the whole diff. Pages are in a fixed order; follow ``next_offset`` until null.

    Each sink_patch entry carries at most ``rows_limit`` (default ``ROWS_INLINE_LIMIT``) of its
    candidate rows, with ``rows_total`` and ``rows_next_offset``. When there are more, they are
    windowed in ``rows_order`` and ``rows_by_presence`` / ``rows_by_order_group`` count every row,
    so what lies outside the window is counted, not dropped. ``entry_id`` (an entry's entry_id or
    anchor_ref) returns that one listed entry, and ``rows_offset`` pages its rows; the entry-level
    fields are read from all of its rows either way.

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
    error, not an empty page).

    ``anchored_differs`` (``sink_patch`` only, listed entries only, bucket R or unset) keeps only
    the undetermined pairs flagged anchored_differs — with no similarity bound, so similarity 1
    and the pairs below the read-first floor are kept too — ordered read-first ones (at or above
    the floor) first, then by similarity, highest first; a ``sort_by`` orders them instead. The
    flag is a fact about these pairs, not a reading of the rest of R. A pair whose only change is a
    __FILE__/__LINE__ shift is kept here too (it stays flagged), just not in the read-first head.

    ``anchored_micro_side`` (same scope) keeps only the undetermined pairs anchored with exactly one
    side a design-skipped micro-stub and the other a real body — the shape of a function gutted to,
    or grown from, a stub, which no similarity or callee reading would surface. A fact about these
    pairs, not a reading of the rest of R."""
    if not isinstance(anchored_differs, bool):
        return {
            "diff_id": diff_id,
            "error": f"anchored_differs must be true or false, got {anchored_differs!r}",
        }
    if not isinstance(anchored_micro_side, bool):
        return {
            "diff_id": diff_id,
            "error": f"anchored_micro_side must be true or false, got {anchored_micro_side!r}",
        }
    for name, on in (
        ("anchored_differs", anchored_differs),
        ("anchored_micro_side", anchored_micro_side),
    ):
        if on and view != "sink_patch":
            return {"diff_id": diff_id, "error": f"{name} applies to view='sink_patch' only"}
        if on and not_listed_page is not None:
            return {
                "diff_id": diff_id,
                "error": f"{name} applies to the listed entries, not to not_listed_page",
            }
        if on and bucket is not None and bucket != "R":
            return {
                "diff_id": diff_id,
                "error": f"{name} keeps bucket R entries only, got bucket={bucket!r}",
            }
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
        "anchored_differs": True if anchored_differs else None,
        "anchored_micro_side": True if anchored_micro_side else None,
    }
    filtered = any(v is not None for v in filters.values())
    error = _check_args(view, sort_by, bucket, tier, limit, offset, filtered, band, entry_id)
    if error is None:
        error = _check_entry_args(
            entry_id, rows_offset, rows_limit, offset, filters, not_listed_page
        )
    if error is not None:
        return {"diff_id": diff_id, "error": error}
    filters["entry_id"] = entry_id
    built = build_diff_view(atlas, diff_id)
    if built is None:
        return {"diff_id": diff_id, "found": False, "error": "no such diff (see list_diffs)"}
    one: _Entry | None = None
    if entry_id is not None:
        if built.withheld is not None:
            return {
                "diff_id": diff_id,
                "error": (
                    "the whole diff is undetermined (banners): it lists no entry until that is "
                    "resolved"
                ),
                "banners": built.banners,
            }
        found = _resolve_entry(built, entry_id)
        if isinstance(found, str):
            return {"diff_id": diff_id, "error": found}
        one = found
        n_rows = len(one.row_views)
        if rows_offset and rows_offset >= n_rows:
            return {
                "diff_id": diff_id,
                "error": f"rows_offset {rows_offset} is past the entry's last row",
                "rows_total": n_rows,
            }
    overlay, banners, entries = built.overlay, built.banners, built.entries
    readings = _pseudo_readings(atlas, built)
    _annotate_entries(built, readings)

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
    chosen = (
        [one]
        if one is not None
        else [
            e
            for e in entries
            if _matches(e, bucket, subclass, tier, blind_spot)
            and (body is None or _body_of(e, readings) == body)
            and (not anchored_differs or _anchored_differs(e, _u_state(e, readings)))
            and (not anchored_micro_side or _anchored_micro_side(e))
        ]
    )
    review = ViewReview(atlas, built)
    unknown_filter = _unknown_filter_value(entries, subclass, blind_spot)
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
            "switchable": (
                "view / sort_by / bucket / subclass / tier / blind_spot / body / anchored_differs "
                "/ anchored_micro_side"
            ),
            # A value no entry of this diff carries is named, with the ones that do exist — an
            # empty page alone reads the same whether the value was misspelled or absent.
            **({"filter_note": unknown_filter} if unknown_filter else {}),
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
    if anchored_differs:
        envelope["lens"]["anchored_differs"] = (
            "on: only the undetermined pairs flagged anchored_differs (no export gap, the same "
            "address or the same real symbol name on both sides, proposed reading differs), at "
            "any similarity; those at or above the read-first floor "
            f"({ANCHORED_DIFFERS_SIM_FLOOR}) first, then by similarity, highest first, unless "
            "sort_by orders them. Not the rest of R: the other undetermined pairs reading differs "
            "are counted in get_diff_meta's functions.alignment_undetermined_reading"
        )
    if anchored_micro_side:
        envelope["lens"]["anchored_micro_side"] = (
            "on: only the undetermined pairs anchored (no export gap, the same address or the same "
            "real symbol name on both sides) with exactly one side a design-skipped micro-stub "
            "(under the decompile size floor, not decompiled by design) and the other a real body "
            "— a function gutted to, or grown from, a stub. A fact about these pairs, not a "
            "reading of the rest of R; counted in get_diff_meta's "
            "functions.alignment_undetermined_anchored_micro_side"
        )
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
    swap_lift: dict[str, int] = {}
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
        # After the attention is known (a bucket C entry reaches 1 through its swap). Every
        # attention-1 entry with a narrow swap leads its tier, whatever its basis — a judgement
        # changes the basis it reads, never its place.
        swap_lift = {
            e.entry_id: 1
            for e in chosen
            if lens[e.entry_id][0] == ATTENTION_MIDDLE
            and (swap := _sink_callee_swap(e)) is not None
            and swap["narrow"]
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
    read_first: dict[str, int] = {}
    for e in chosen:
        if e.entry_id in proposed and (order := _read_first_order(e, proposed[e.entry_id][0])):
            read_first[e.entry_id] = order
    # The caller-set edge's no-mention key: 0 when no OTHER B function names this E entry's function
    # (read first inside its lane), 1 when one does. E entries only; it reaches the order through
    # _default_key under significance alone, so it never touches the default order or the rank_key.
    mention = {
        e.entry_id: (0 if e.pair is not None and e.pair.addr_b not in readings.b_mentions else 1)
        for e in chosen
        if e.bucket == "E"
    }
    bands = review.bands() if band else None
    if anchored_differs and sort_by is None:
        ordered = _anchored_order(chosen, read_first, bands)
    else:
        ordered = _sort(
            chosen,
            sort_by,
            bands,
            {k: v[0] for k, v in lens.items()},
            settled,
            read_first,
            swap_lift,
            mention,
        )
    end = offset + limit
    page = ordered[offset:end]
    page_deltas = _deltas(
        readings, [p for e in page if (p := _delta_pair(e, readings)) is not None]
    )
    page_bodies = _page_bodies(readings, page)

    def _render(e: _Entry) -> dict[str, Any]:
        out = review.entry_json(e, band)
        # out["rows"] IS e.row_views (the entry's own list, which promote and the judgement basis
        # read whole): it is REPLACED by the window's new list, never cut or sorted in place.
        out["rows"], window = _rows_window(e.row_views, rows_offset or 0, rows_limit)
        out.update(window)
        if one is not None:
            out["rows_offset"] = rows_offset or 0
        if e.bucket == "E":
            # Whether another B function names this one (the no-mention ordering key, as an honest
            # field). A read-face fact: the index is in readings, never in the cheap build layer.
            out["b_other_fn_mentions"] = e.pair is not None and e.pair.addr_b in readings.b_mentions
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
            if (e.pair.addr_a, e.pair.addr_b) in page_bodies:
                out["bodies"] = page_bodies[(e.pair.addr_a, e.pair.addr_b)]
        if e.entry_id in proposed and e.pair is not None:
            out["proposed_pair_reading"] = _proposed_json(
                e, *proposed[e.entry_id], page_deltas, page_bodies
            )
        if e.entry_id in lens:
            attention, basis = lens[e.entry_id]
            out["rank_key"] = {
                **out["rank_key"],
                "attention": attention,
                "sink_callee_swap": swap_lift.get(e.entry_id, 0),
            }
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


def _unknown_filter_value(
    entries: list[_Entry], subclass: str | None, blind_spot: str | None
) -> str | None:
    """A note when a subclass / blind_spot filter names a value no entry of this diff carries.
    These vocabularies are open (a subclass can carry a sink or reason name), so an absent value
    is not refused — it may be right and simply not occur here — but it is said, with the values
    that do occur."""
    notes = []
    if subclass is not None:
        present = sorted(
            {e.subclass for e in entries if e.subclass}
            | {v["subclass"] for e in entries for v in e.row_views if v["subclass"]}
        )
        if subclass not in present:
            notes.append(
                f"subclass {subclass!r} occurs in no entry of this diff (present: "
                f"{', '.join(present) or 'none'})"
            )
    if blind_spot is not None:
        present = sorted({b for e in entries for b in e.blind_spots})
        if blind_spot not in present:
            notes.append(
                f"blind_spot {blind_spot!r} occurs in no entry of this diff (present: "
                f"{', '.join(present) or 'none'})"
            )
    return "; ".join(notes) or None


def _count(keys: Any) -> dict[str, int]:
    out: dict[str, int] = {}
    for k in keys:
        out[k] = out.get(k, 0) + 1
    return dict(sorted(out.items()))
