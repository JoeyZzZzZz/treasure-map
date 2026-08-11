# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Triage read view — a multi-dimensional, honestly-annotated map of atlas candidate instances.

Pure read path over the atlas. Each candidate is a point on the map carrying a three-state
annotation on every dimension layer (controllability / source_writability / reachability /
filtering / sink_impact / writer / completeness). There is NO collapsed score: a single composable
sort spec (``sort_candidates`` / ``apply_view``) projects the layers into a lens. The DEFAULT lens
spines on sink-impact, bands by impact x controllability, and sinks ONLY provably-safe
candidates — a '?' never sinks (the demotion iron law). Every lens rides that same iron law, so no
angle can bury a candidate by "not yet known".

Nothing here is a verdict or a written-back value; the review-status words (to-verify / reachable /
gated) remain a presentation-only relabel of the raw reachability_status, kept for the status
filter. tmap annotates facts; the security judgement is the consumer's.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from treasure_map.lib.pattern.classes import CMD, FMT_STRING
from treasure_map.lib.query.nvram import _web_settable
from treasure_map.lib.query.sink_impact import (
    CONSTRAINED_MARKERS,
    NVRAM_GETTERS,
    PROVABLY_CONSTANT_MARKERS,
    impact_tier,
)
from treasure_map.lib.query.string_edges import edges_reaching_callee

logger = logging.getLogger(__name__)

# Presentation-only relabel of the raw reachability_status schema values. This maps the
# mechanism state to a word the reviewer can act on; it is NEVER written back to the atlas
# and the stored field keeps its original confirmed/blocked/unknown value.
REVIEW_STATUS_BY_REACHABILITY: dict[str, str] = {
    "confirmed": "reachable",  # a clean source->sink flow was seen within one function
    "unknown": "to-verify",  # the triage body: a lead that warrants manual reverse-engineering
    "blocked": "gated",  # a filter/guard was identified on the path (likely dormant/false)
}

# The map's default lens label + the honest phase-1 caveats. Surfaced verbatim in every candidate
# listing so a consumer never reads the map as complete: the demotion gate, the optimistic 'free',
# the nvram double-optimism, the near-always-'?' filtering, and the no-reduction contract.
DEFAULT_LENS_LABEL = (
    "current lens: sink-impact x controllability-exposure, only PROVEN-SAFE sinks leave the first "
    "screen — switchable (--sort-by / --filter / --view)"
)
PHASE1_CAVEATS: tuple[str, ...] = (
    "demotion gate ~= only provably-constant this phase; proven-blocked / filter-dominates almost "
    "never fire, so junk that is merely 'washed' is NOT sunk",
    "'free' is OPTIMISTIC: convergence-transforms are not subtracted yet, so a value washed by "
    "inet_ntop / a whitelist / a fixed-width parse — or a PATH sanitized by basename / realpath / "
    "a traversal check — can still read as free",
    "proven-'controllable' via web_settable proves only the KEY is user-settable (SaTC front-end x "
    "back-end cross), NOT that the getter->sink path is transform-free — a sanitizer between the "
    "getter and the sink can still neutralize it; and the all-binary cross may be slightly wide",
    "filtering is ~= always '?': tmap does a generic name-match only and cannot prove a sanitizer "
    "covers the path — it does NOT save you from reading the filter code",
    "triage RE-RANKS the view, it does not reduce candidates: only provably-safe items leave the "
    "first screen; every candidate stays listed and queryable",
)


@dataclass(frozen=True)
class Dimension:
    """One map layer's honest three-state annotation for a candidate — a FACT, never a verdict.

    ``state`` is the glyph-level certainty: ``proven`` (✓ established — RESERVED for a positive
    proof: a SaTC front↔back cross, a provably-constant argument, a sound rootfs entry edge; NEVER
    an optimistic fallback or a coarse zero-discrimination pattern label), ``likely`` (~ an
    optimistic-but-unconfirmed reading, e.g. a router_defaults-member controllability or the
    optimistic 'free' text-level fallback — carries ``value`` but never claims proof),
    ``structural`` (~ a structural lead from the coarse pattern layer, e.g. an A2 external_input
    source — a fact about shape that points somewhere to look, NOT a controllability proof),
    ``excluded`` (✗ established not-applicable / ruled out), ``unknown`` (? not established —
    ``note`` says what is missing and why). ``value`` is the concrete reading (``free`` / ``cmd``);
    ``source`` names where it came from; ``note`` carries the reason for a ? or an honest caveat.
    The red line: a ? is NEVER rendered as ✓, and neither ~ (``likely`` nor ``structural``) ever as
    ✓ — an unproven reading must never read as proven (proven is the one word tmap must not spend
    on a value it has not proven)."""

    name: str
    state: str  # "proven" | "likely" | "structural" | "excluded" | "unknown"
    value: str
    source: str
    note: str = ""
    # Optional structured evidence rows behind this layer's reading — e.g. the web_form_fields
    # {field_keyword, source_asset, source_rule, match_kind} rows behind a source_writability
    # ``web_settable`` value, so an agent drills in to CONFIRM the web reach or DEMOTE a keyword
    # collision without re-deriving. Empty for layers that carry no drill-down rows. Evidence, never
    # a verdict — it never changes ``state``/``value``.
    evidence: tuple[dict[str, Any], ...] = ()


def state_value_label(d: Dimension) -> str:
    """One dimension as a compact ``state:value`` label (the honest certainty prefix + reading, e.g.
    ``likely:free`` / ``structural:param``). The single source of the ``state:value`` format — the
    MCP compact row and the explain rollup's labeled fields both read it, so a bare value never
    reaches a consumer without its state."""
    return f"{d.state}:{d.value}"


@dataclass(frozen=True)
class TriageCandidate:
    """One candidate = a point on the map, with a three-state annotation on every dimension layer.

    A lead, never a confirmed result. There is NO collapsed score: ``dimensions`` carries the
    honest per-layer facts (controllability / source_writability / reachability / filtering /
    sink_impact / writer / completeness), and the composable sort spec (see ``sort_candidates``)
    projects them into a lens. ``review_status`` is the presentation relabel of the raw
    ``reachability_status`` schema value (both untouched, kept for the status filter).
    """

    review_status: str
    reachability_status: str
    function: str | None
    sink_anchor: str | None
    source_class: str
    sink_class: str
    blocking_mechanism: str | None
    origin: str
    source_run_id: str | None
    evidence_ref: str | None
    # Which binary to open in the decompiler. Read straight from the atlas (NOT a read-time
    # join back to analysis.db), so a candidate is locatable even when the source build is gone.
    binary_path: str | None
    # entry-reach mechanistic label (entry:web / entry:script / entry:web+script / unknown) parsed
    # from the stored flow_evidence.entry_reach.sites by site kind — a derived, evidence-backed
    # signal, NOT a reachability verdict. Feeds the reachability dimension.
    entry_reach: str = "unknown"
    # source_kind (free_string / charset_safe / charset_maybe / unknown) parsed from the stored
    # flow_evidence — the FINE-GRAINED controllability signal the coarse source_class folds away.
    # Feeds the controllability dimension. ``unknown`` when the evidence carries no source_kind.
    source_kind: str = "unknown"
    # An exposure SHAPE (e.g. bare_sink = a raw command/format sink with no recognized in-function
    # source), kept OUT of blocking_mechanism so a danger form is never read as a mitigation. None
    # when no shape is flagged. A surfaced fact, never a verdict.
    exposure_shape: str | None = None
    # The pattern's structural fingerprint (the same key cross_firmware_patterns / pattern_density
    # group by), surfaced so a consumer can pivot from a recurring pattern to its instances.
    structural_fingerprint: str | None = None
    # The nvram key feeding the sink argument, when the def-use provenance resolved the source to an
    # nvram getter: its web-settability drives the controllability annotation. None when the
    # source is not a resolved nvram getter. A surfaced fact, never a verdict.
    nvram_source_key: str | None = None
    # The honest three-state map layers. Every dimension is a first-class, queryable /
    # sortable / filterable annotation here — NOT buried in flow_evidence JSON to dig out.
    dimensions: tuple[Dimension, ...] = field(default_factory=tuple)

    def dim(self, name: str) -> Dimension:
        """The named dimension layer; a ``unknown`` placeholder if it was not computed (defensive —
        every candidate normally carries all layers)."""
        for d in self.dimensions:
            if d.name == name:
                return d
        return Dimension(name, "unknown", "unknown", "not computed")


def _entry_reach_sites(flow_evidence: str | None) -> list[dict[str, Any]]:
    """The ``entry_reach.sites`` list (rootfs invocation evidence) from the stored flow_evidence; []
    when the evidence is missing, unparsable, or carries no sites. Each site carries a ``kind``
    (``web_endpoint`` / ``script_call``) — the fact the evidence layer already recorded."""
    if not flow_evidence:
        return []
    try:
        data = json.loads(flow_evidence)
    except (ValueError, TypeError):
        return []
    reach = data.get("entry_reach") if isinstance(data, dict) else None
    sites = reach.get("sites") if isinstance(reach, dict) else None
    if not isinstance(sites, list):
        return []
    return [s for s in sites if isinstance(s, dict)]


# The entry kinds a site may carry, in the FIXED order they are joined into a label. Order is
# load-bearing: it keeps ``entry:web+script`` spelled exactly as it always was, so a stored value,
# a filter string, and a cross-version comparison all keep matching.
_ENTRY_KIND_LABELS: tuple[tuple[str, str], ...] = (
    ("web_endpoint", "web"),
    ("script_call", "script"),
    ("exec_edge", "exec"),
)


def _entry_reach_status(flow_evidence: str | None) -> str:
    """Classify the entry evidence into an HONEST, multi-valued MECHANISTIC label, reading each
    ``entry_reach.sites`` entry's ``kind`` (the fact the evidence layer recorded) — NOT collapsing
    every site to a single misleading "found":

      ``entry:web``         a web-asset endpoint references this binary (boundary match)
      ``entry:script``      a boot/rootfs script invokes this binary (exact tail match)
      ``entry:exec``        another binary's code launches this binary (a resolved launch edge)
      ``entry:web+script``  several kinds of reference exist — reported TOGETHER in a fixed order,
                            none preferred over the others (collapsing to one recreates "found")
      ``unknown``           no site found: a coverage gap, NEVER "unreachable"

    This is a MECHANISTIC label ("the binary name appears on this kind of edge"), NOT a
    reachability verdict — it does not decide whether an attacker's input actually arrives here.
    The caveats live in ``_dim_reachability``'s note. It answers the entry level only; entry->sink
    flow is a separate, unmodeled question. Conservative: no parseable site reports ``unknown``."""
    kinds = {s.get("kind") for s in _entry_reach_sites(flow_evidence)}
    present = [label for kind, label in _ENTRY_KIND_LABELS if kind in kinds]
    return f"entry:{'+'.join(present)}" if present else "unknown"


def _entry_web_triggers(flow_evidence: str | None, *, limit: int = 3) -> tuple[str, ...]:
    """Short ``"METHOD endpoint"`` labels for the web_endpoint entry sites, so an entry:web reading
    shows WHICH endpoint triggered it (the consumer confirms the dispatch themselves — a textual
    reference is not proof). Capped at ``limit``; script sites carry no endpoint and are omitted."""
    out: list[str] = []
    for s in _entry_reach_sites(flow_evidence):
        if s.get("kind") != "web_endpoint":
            continue
        ep = s.get("endpoint") or s.get("path") or ""
        method = s.get("method") or ""
        label = f"{method} {ep}".strip() if method else str(ep)
        if label and label not in out:
            out.append(label)
        if len(out) >= limit:
            break
    return tuple(out)


def _source_kind_from_evidence(flow_evidence: str | None) -> str:
    """Surface ``source_kind`` from the stored flow_evidence JSON; ``unknown`` when absent.

    A pure read of the value the evidence layer already recorded (free_string / charset_safe /
    charset_maybe / unknown) — this does NOT recompute the classification, it only exposes it.
    Conservative: any missing / unparsable evidence, or an absent / non-string source_kind, reports
    ``unknown`` (never fabricates a class)."""
    if not flow_evidence:
        return "unknown"
    try:
        data = json.loads(flow_evidence)
    except (ValueError, TypeError):
        return "unknown"
    kind = data.get("source_kind") if isinstance(data, dict) else None
    return kind if isinstance(kind, str) and kind else "unknown"


def _sink_provenance_records(flow_evidence: str | None) -> list[dict[str, Any]]:
    """The full sink_arg_provenance list (Ghidra def-use fact) from the stored flow_evidence.

    A pure read of what the analysis layer already recorded; empty list when the evidence is
    absent, unparsable, or carries no provenance. Never recomputes or invents provenance."""
    if not flow_evidence:
        return []
    try:
        data = json.loads(flow_evidence)
    except (ValueError, TypeError):
        return []
    prov = data.get("sink_arg_provenance") if isinstance(data, dict) else None
    if not isinstance(prov, list):
        return []
    return [r for r in prov if isinstance(r, dict)]


# call_return callees that FORWARD a source-argument value unchanged (strcpy/memcpy-family REPLACE
# the destination with a source argument), so a constant source argument makes the RESULT a proven
# constant even though the destination-pointer argument reads as unresolved (has_unresolved_args
# flags the DST buffer, not the value). strcat/strncat are EXCLUDED — they append, so the value is
# not solely the constant source. Generic libc names, not a vendor list.
_VALUE_FORWARDING_COPIES: frozenset[str] = frozenset(
    {"strcpy", "strncpy", "strlcpy", "strdup", "strndup", "memcpy", "memmove"}
)
# printf conversions that consume a POINTER argument (the value is an address, its pointee unknown).
_STRING_PTR_CONVERSIONS = frozenset({"s", "p"})


def _is_hex_literal(value: Any) -> bool:
    """True if ``value`` is a 0x-form hex literal string (e.g. "0x432f"). Belt-and-suspenders for
    provenance produced before the extractor emitted value_kind: a bare 0x value is ambiguous."""
    if not isinstance(value, str) or len(value) <= 2 or value[:2].lower() != "0x":
        return False
    return all(c in "0123456789abcdefABCDEF" for c in value[2:])


def _is_ambiguous_0x(source: dict[str, Any]) -> bool:
    """True if a constant source's value is an ambiguous 0x — the extractor confirmed a constant
    value 0x… but could NOT tell an integer literal from a pointer address (DataType unavailable:
    a two-firmware probe found 0 pointers over 13162 such constants). Trusts the extractor's
    ``value_kind`` when present; falls back to detecting a bare 0x value for older provenance."""
    vk = source.get("value_kind")
    if vk == "ambiguous_0x":
        return True
    if vk == "literal_string":
        return False
    return _is_hex_literal(source.get("value"))


def _conversion_char(spec: Any) -> str | None:
    """The conversion character of a spec like "%s"/"%ld"/"%d" (the last letter), or None."""
    if not isinstance(spec, str):
        return None
    for ch in reversed(spec):
        if ch.isalpha():
            return ch.lower()
    return None


def _classify_source(conn: sqlite3.Connection, source: Any, spec: Any = None) -> str:
    """One value source's controllability: 'controllable' | 'const' | 'unknown'. THE single
    classifier both the triage verdict (M3) and the explain rollup call — so a candidate carries one
    controllability reading, never two that disagree.

    - constant: a literal string -> 'const'; an ambiguous_0x -> 'const' under an integer spec, else
      'unknown' (a constant pointer whose pointee is unknown; no spec -> cannot disambiguate).
    - call_return: dispatched through the EXTENSIBLE classifier registry (see
      _CALL_RETURN_CLASSIFIERS). This phase the registry carries ONE controllable class — a
      WEB-SETTABLE nvram key in const_args (SaTC cross, getter-name-agnostic) — plus a constant
      value-forwarding copy. An UNCLASSIFIED call_return (getpid, an unknown FUN_, a getenv/recv a
      a FUTURE class will cover) -> 'unknown': NEITHER proven constant NOR proven controllable, it
      falls through to the source_kind chain honestly. This is the de-optimism: an arbitrary
      call_return is no longer assumed controllable.
    - param / stack_buf(as a leaf) / unresolved / indirect_unresolved / missing / None -> 'unknown'.
    Nothing here assumes constant on incomplete data — the demotion iron law lives in this default.
    """
    if not isinstance(source, dict):
        return "unknown"
    kind = source.get("kind")
    if kind == "constant":
        if not _is_ambiguous_0x(source):
            return "const"  # a confirmed literal-string constant (value known, not controllable)
        conv = _conversion_char(spec)
        if conv is None or conv in _STRING_PTR_CONVERSIONS:
            return "unknown"  # %s/%p -> constant pointer, pointee unknown; no spec -> undecidable
        return "const"  # %d/%x/%u/... -> the 0x is a KNOWN integer literal
    if kind == "call_return":
        for classifier in _CALL_RETURN_CLASSIFIERS:
            verdict = classifier(conn, source)
            if verdict is not None:
                return verdict
        return "unknown"  # unclassified call_return -> fall through to the source_kind chain
    return "unknown"


def _source_web_settable_key(conn: sqlite3.Connection, source: Any) -> str | None:
    """The FIRST web_settable='yes' key among a call_return source's const_args, else None.

    Getter-name-AGNOSTIC: the SaTC cross (front-end editable x back-end nvram key) decides, so a
    custom getter wrapper — not in any known getter list — still yields its web-settable key. This
    is why the single verdict sees keys the old NVRAM_GETTERS-gated path missed."""
    if not isinstance(source, dict) or source.get("kind") != "call_return":
        return None
    for k in source.get("const_args") or []:
        if isinstance(k, str) and k and _web_settable(conn, k).get("web_settable") == "yes":
            return k
    return None


# ── the EXTENSIBLE call_return source-classification registry (⑦) ──────────────────────────────
# Each classifier maps a call_return source to a controllability class ('controllable' / 'const') or
# None (not my class -> try the next). THIS PHASE carries exactly two rows: a web-settable nvram key
# (the SaTC cross) and a value-forwarding copy of a constant. A FUTURE phase (item A: call_return
# generalization — the WAN pre-auth surface) adds rows here WITHOUT touching _classify_source or the
# verdict:  getenv + const_args HTTP_*/QUERY_STRING -> controllable ; recv / recvfrom -> external
# (a WAN-daemon entry) ; getpeername + inet_ntop -> constrained. Hardcoding "only nvram" into the
# classifier would force a rewrite then; a registry makes it additive. First non-None wins.


def _cr_web_settable_nvram(conn: sqlite3.Connection, source: dict[str, Any]) -> str | None:
    """Class #1 (this phase): a const_args key that is web_settable='yes' -> controllable. The
    getter's identity does not matter — the SaTC cross decides."""
    return "controllable" if _source_web_settable_key(conn, source) is not None else None


def _cr_value_forwarding_copy(conn: sqlite3.Connection, source: dict[str, Any]) -> str | None:
    """A strcpy-family copy of a constant literal -> const (the RESULT is the forwarded literal; the
    unresolved destination pointer is irrelevant to the value)."""
    keys = [k for k in (source.get("const_args") or []) if isinstance(k, str) and k]
    if source.get("callee") in _VALUE_FORWARDING_COPIES and keys:
        return "const"
    return None


_CallReturnClassifier = Callable[[sqlite3.Connection, dict[str, Any]], "str | None"]
_CALL_RETURN_CLASSIFIERS: tuple[_CallReturnClassifier, ...] = (
    _cr_web_settable_nvram,
    _cr_value_forwarding_copy,
)


def _writer_args_class(conn: sqlite3.Connection, fmt: Any, varargs: Any) -> str:
    """One writer's format-argument controllability: 'controllable' | 'const' | 'unknown'.

    Reuses _classify_source per vararg (spec-aware), with an arity shortfall (fmt consumes more than
    were extracted) contributing an 'unknown' — never conclude 'const' on incomplete data. A
    literal-format write with no args is 'const'; an origin-less writer (no fmt, no args) is
    'unknown'. Precedence controllable > unknown > const."""
    varargs = varargs if isinstance(varargs, list) else []
    arity = _fmt_arity(fmt) if isinstance(fmt, str) else len(varargs)
    considered = varargs[:arity] if isinstance(fmt, str) else varargs
    classes = [
        _classify_source(
            conn,
            va.get("source") if isinstance(va, dict) else None,
            va.get("spec") if isinstance(va, dict) else None,
        )
        for va in considered
    ]
    if isinstance(fmt, str) and len(varargs) < arity:
        classes.append("unknown")
    if "controllable" in classes:
        return "controllable"
    if "unknown" in classes:
        return "unknown"
    if classes:
        return "const"
    return "const" if isinstance(fmt, str) else "unknown"


# Command-exec sinks whose command spans MULTIPLE argv arguments (execl("/bin/sh","sh","-c",cmd)):
# a single constant arg record (arg0="/bin/sh") does NOT prove the command constant — the real
# command is in a later arg the provenance may not have captured. Never demote these to 'constant'
# on a partial (arg0-only) view (the demotion iron law: a variadic exec seen only at arg0 ->
# unknown, never constant — the agent's blood-earned counter-example). system/popen take the whole
# command in one arg, so they are NOT here — a single constant record legitimately proves them.
_MULTI_ARG_COMMAND_SINKS: frozenset[str] = frozenset(
    {"execl", "execlp", "execle", "execv", "execvp", "execvpe"}
)


def _judged_writers(prov: dict[str, Any]) -> list[dict[str, Any]]:
    """The stack_buf writers whose source decides THIS sink's controllability.

    Dominance propagation: only a CHK-dominating writer (``dominates_sink``) lies on EVERY path to
    the sink, so only it forwards a value that actually reaches the sink argument. A non-dominating
    writer is a mutually-exclusive branch — it may carry a controllable source that flows to a
    DIFFERENT sink (e.g. a wrs_cc_t query into sqlite3_exec, not into this system() call), and must
    NOT light up this sink.

    ★ Boundary — no dominating writer marked (dominating empty) -> FALL BACK to ALL writers. A
    missing dominance mark is analysis-incomplete (a truncated/MULTIEQUAL def-use) or pre-field
    provenance (older data without ``dominates_sink`` -> w.get() is None -> falsy), NOT proof that
    no writer reaches the sink. Evidence-absent never infers safe (the asymmetric burden): the
    fallback preserves the pre-fix behavior (judge all writers = a possible over-promote, safe),
    never collapsing to unknown (a possible under-promote = a hidden bug). This safety rests on the
    load-bearing invariant that CHK marks ``dominates_sink`` true ONLY when it truly kills every
    other reaching definition — if that mark is ever over-asserted, a real controllable
    non-dominating writer would be wrongly dropped (property test #8 guards this direction)."""
    writers = [w for w in (prov.get("writers") or []) if isinstance(w, dict)]
    dominating = [w for w in writers if w.get("dominates_sink")]
    return dominating if dominating else writers


def _record_class(conn: sqlite3.Connection, rec: dict[str, Any]) -> str:
    """One sink record's controllability: 'controllable' | 'const' | 'unknown'.

    constant / call_return sink arg -> _classify_source directly. A stack_buf is judged over its
    DOMINATING writers only (see _judged_writers — a non-dominating branch writer may inject into a
    different sink, so it does not decide this one): controllable if any judged writer is
    controllable, 'const' only if EVERY judged writer is const, else 'unknown'. With no writer at
    all -> 'unknown'. Unresolved / indirect_unresolved -> 'unknown'. A multi-arg exec sink is NEVER
    'const' on partial provenance (the iron law) — a would-be 'const' is downgraded to 'unknown'."""
    prov = rec.get("provenance")
    prov = prov if isinstance(prov, dict) else {}
    kind = prov.get("kind")
    if kind in ("constant", "call_return"):
        cls = _classify_source(conn, prov)
    elif kind == "stack_buf":
        judged = _judged_writers(prov)
        if not judged:
            cls = "unknown"
        else:
            wclasses = [_writer_args_class(conn, w.get("fmt"), w.get("varargs")) for w in judged]
            if "controllable" in wclasses:
                cls = "controllable"
            else:
                cls = "const" if all(c == "const" for c in wclasses) else "unknown"
    else:
        cls = "unknown"
    # Iron law: a variadic exec proven constant only at arg0 is NOT a constant command.
    if cls == "const" and rec.get("sink") in _MULTI_ARG_COMMAND_SINKS:
        return "unknown"
    return cls


def _scoped_records(flow_evidence: str | None, sink_anchor: str | None) -> list[dict[str, Any]]:
    """The sink_arg_provenance records for the candidate's ANCHORED sink (rec.sink == sink_anchor).

    Falls back to ALL records when the anchor matches none — a LIBERAL fallback: it may promote a
    constant sibling, but it never HIDES a controllable key by a failed anchor match (the demotion
    iron law is asymmetric — a wrong promote is safe, a wrong demote hides a bug)."""
    recs = _sink_provenance_records(flow_evidence)
    if sink_anchor:
        scoped = [r for r in recs if r.get("sink") == sink_anchor]
        if scoped:
            return scoped
    return recs


def _verdict_from_provenance(
    conn: sqlite3.Connection, flow_evidence: str | None, sink_anchor: str | None
) -> str | None:
    """The single controllability verdict from the anchored sink's def-use provenance:
    'controllable' (a web-settable / external source reaches the sink arg), 'const' (EVERY record
    PRESENT is a proven constant), or None (undetermined -> the caller falls back to the top-level
    source_kind).

    ★ A pure classifier over the records it is handed — 'const' here means "all-constant over what
    is present", and says NOTHING about whether the right sink is among them. The other half of the
    demotion iron law, that the anchored sink must be present at all, is enforced by the CALLER
    (_anchor_missed in _dim_controllability) because it gates two constant exits, not just this
    one. Reading a 'const' from here as a completeness claim is exactly the mistake that gate
    exists to stop."""
    recs = _scoped_records(flow_evidence, sink_anchor)
    if not recs:
        return None
    classes = [_record_class(conn, r) for r in recs]
    if "controllable" in classes:
        return "controllable"
    if all(c == "const" for c in classes):
        return "const"
    return None


# The sinks the extractor builds a def-use record for. ExportFunctions computes one
# sink_arg_provenance record per COMMAND / FORMAT-STRING sink call and nothing else, so this set is
# a mirror of that lexicon. A copy sink (strcpy/memcpy/…) or a path sink (fopen/…) never gets a
# record, which means "no record for this sink" says NOTHING about them — it only says def-use does
# not cover that sink class.
_DEF_USE_SINKS: frozenset[str] = CMD | FMT_STRING


def _anchor_missed(flow_evidence: str | None, sink_anchor: str | None) -> bool:
    """True ONLY when the def-use provenance SHOULD carry the anchored sink but does NOT.

    This is the COMPLETENESS half of the demotion iron law, which until now lived only in prose.
    The shape it catches: a candidate whose real sink sits behind a thin forwarding wrapper. The
    provenance is per-function and per-DIRECT-callee, so the caller's records hold the caller's own
    OTHER sinks and not the wrapped one — the value actually handed to the real sink was never
    looked at. Any "this argument is a constant" reading built on those records, or on a marker
    computed from that same caller body, rests on never having seen the sink at all.

    Three guards, with deliberately different roles:

    (a) DEFENSIVE, and structurally redundant today. The anchor must be a sink def-use covers at
        all. Under the current evidence writer a copy/path candidate always ends up with EMPTY
        provenance, so (b) already stops every one of them and this guard fires on nothing (a real
        atlas measures its marginal contribution at exactly 0). It is kept because the redundancy
        is not guaranteed: if the writer ever gives a copy/path candidate a NON-empty provenance
        carrying some unrelated def-use sink's record, (b) would pass and only this guard would
        stop a wrong escape reading. It guards a structural possibility, not a present instance.
    (b) LOAD-BEARING. The provenance must be non-empty. Empty means no def-use was captured here
        at all — which is the ordinary state for a copy or path candidate, and which
        _verdict_from_provenance already answers with None. Reading empty as "the sink escaped"
        would sweep in thousands of candidates whose constant reading is perfectly sound (on a real
        atlas, dropping this guard alone widens the set ~90-fold).
    (c) LOAD-BEARING — the escape signal itself. Records exist, yet none of them is the anchored
        sink.

    ★ Necessary, not sufficient. It proves "I have at least one record for the sink I am judging",
    NOT "the provenance is complete". A record that exists but was internally truncated is a deeper
    gap this does not address.

    ★ Boundary: a firmware-specific sink added to the extractor's lexicon at scan time is not in
    (a)'s set, so an escape on such a sink is not caught here — that leaves the pre-existing
    behaviour untouched rather than making it worse."""
    if not sink_anchor:
        return False
    if sink_anchor not in _DEF_USE_SINKS:  # (a) defensive
        return False
    records = _sink_provenance_records(flow_evidence)
    if not records:  # (b) load-bearing
        return False
    return not any(r.get("sink") == sink_anchor for r in records)  # (c) load-bearing


def _web_settable_keys_reaching_sink(
    conn: sqlite3.Connection, flow_evidence: str | None, sink_anchor: str | None
) -> list[str]:
    """The web-settable keys that reach the anchored sink argument (order-preserving, deduped) —
    surfaced so the controllability note names the key and the source_writability layer can show it.
    """
    out: list[str] = []
    seen: set[str] = set()

    def add(k: str | None) -> None:
        if k and k not in seen:
            seen.add(k)
            out.append(k)

    for rec in _scoped_records(flow_evidence, sink_anchor):
        prov = rec.get("provenance")
        prov = prov if isinstance(prov, dict) else {}
        add(_source_web_settable_key(conn, prov))
        # Only DOMINATING writers reach the sink (same filter as the verdict, _judged_writers) — so
        # the note never names a key sitting in a non-dominating branch the verdict already ignored.
        for w in _judged_writers(prov):
            for va in w.get("varargs") or []:
                if isinstance(va, dict):
                    add(_source_web_settable_key(conn, va.get("source")))
    return out


def _likely_settable_keys_reaching_sink(
    conn: sqlite3.Connection,
    flow_evidence: str | None,
    sink_anchor: str | None,
    wrapper_names: frozenset[str],
) -> list[str]:
    """nvram keys reaching the anchored sink argument that are web_settable=='likely' (M2: an
    in_router_defaults member — the middle tier below a proven SaTC 'yes').

    Two gates, both DELIBERATELY narrower than the proven 'yes' path (``_source_web_settable_key``,
    which is getter-agnostic because a front-end x back-end cross is a hard fact on any const
    string):
      1. GETTER/WRAPPER-gated. 'likely' is only router_defaults membership — a weaker signal that
         includes read-only internal keys — so it is trusted ONLY for a key genuinely READ from
         nvram (a direct getter or an A2 thin wrapper, via ``_nvram_key_from_source``), never any
         const literal that merely happens to sit in router_defaults. This gate is exactly what M1's
         wrapper attribution buys: without it the likely tier could not tell an nvram read from an
         incidental string.
      2. DOMINANCE-filtered (``_judged_writers``, the SAME filter as the verdict): a likely key in a
         non-dominating branch flows to a different sink and must not light this one.
    Order-preserving, deduped. Empty when nothing qualifies (the caller then falls through the
    controllability chain — never a false 'safe')."""
    out: list[str] = []
    seen: set[str] = set()

    def consider(source: Any) -> None:
        k = _nvram_key_from_source(source, wrapper_names)
        if k and k not in seen and _web_settable(conn, k).get("web_settable") == "likely":
            seen.add(k)
            out.append(k)

    for rec in _scoped_records(flow_evidence, sink_anchor):
        prov = rec.get("provenance")
        prov = prov if isinstance(prov, dict) else {}
        consider(prov)
        for w in _judged_writers(prov):
            for va in w.get("varargs") or []:
                if isinstance(va, dict):
                    consider(va.get("source"))
    return out


# The explain-summary vocabulary for a writer's format-argument controllability, mapped from the
# single _writer_args_class so the explain rollup and the triage verdict never disagree.
_ARGS_CLASS_TO_STATE: dict[str, str] = {
    "controllable": "has_controllable",
    "const": "all_constant",
    "unknown": "undetermined",
}


def _sink_provenance_summary(
    conn: sqlite3.Connection, flow_evidence: str | None
) -> tuple[dict[str, Any], ...]:
    """Per-sink summary of sink_arg_provenance (summary-first: the FULL writer/vararg detail is
    fetched on demand via ``get_sink_provenance``, so a multi-sink candidate never blows the token
    budget). One compact dict per sink: idx / name / addr / kind / resolved / writer_count? /
    nearest_dominating_writer?. A surfaced fact only — never a verdict, never a score input."""
    out: list[dict[str, Any]] = []
    for rec in _sink_provenance_records(flow_evidence):
        prov = rec.get("provenance")
        prov = prov if isinstance(prov, dict) else {}
        kind = prov.get("kind", "unknown")
        summary: dict[str, Any] = {
            "sink_idx": rec.get("sink_idx"),
            "sink": rec.get("sink"),
            "sink_addr": rec.get("sink_addr"),
            "kind": kind,
            # "resolved" states only whether def-use reached a concrete origin; a false value is an
            # honest boundary marker, NEVER a downweight or a "safe" verdict.
            "resolved": kind not in ("indirect_unresolved", "unresolved"),
        }
        if "writer_count" in prov:
            summary["writer_count"] = prov.get("writer_count")
        writers = prov.get("writers")
        if isinstance(writers, list):
            # How many writers are on EVERY path to the sink (sound CHK-dominating). Distinguishes
            # "already resolved to 1-3 dominating writers" from the raw writer_count, which also
            # counts the mutually-exclusive branch writers (noise) — a high writer_count with a low
            # dominating_writer_count is resolved, not ambiguous.
            summary["dominating_writer_count"] = sum(
                1 for w in writers if isinstance(w, dict) and w.get("dominates_sink")
            )
        if prov.get("nearest_dominating_writer"):
            ndw = prov.get("nearest_dominating_writer")
            summary["nearest_dominating_writer"] = ndw
            # Inline ONLY the nearest dominating writer's format string: an all-constant fmt is
            # often judgeable (not controllable) with zero extra fetch; one fmt stays compact.
            if isinstance(writers, list):
                for w in writers:
                    if isinstance(w, dict) and w.get("writer") == ndw and w.get("fmt") is not None:
                        summary["nearest_dominating_writer_fmt"] = w.get("fmt")
                        # Three-state, web-settable-aware: are the inlined command's format args
                        # constant / controllable / undetermined? By the SAME classifier the
                        # triage verdict uses (so explain and triage agree), so a call_return like
                        # getpid reads 'undetermined', not the old optimistic 'has_controllable'.
                        summary["fmt_args_provenance"] = _ARGS_CLASS_TO_STATE[
                            _writer_args_class(conn, w.get("fmt"), w.get("varargs"))
                        ]
                        break
        out.append(summary)
    return tuple(out)


def _fmt_arity(fmt: str) -> int:
    """Number of arguments a printf-style format string consumes: one per conversion specifier
    (``%%`` excluded), plus one for each ``*`` width/precision taken from an argument. Mirrors the
    ExportFunctions specifier scan so the read-side trim never drops a genuinely-consumed arg."""
    n = 0
    i = 0
    length = len(fmt)
    while i < length:
        if fmt[i] != "%":
            i += 1
            continue
        j = i + 1
        if j < length and fmt[j] == "%":  # literal %%
            i = j + 1
            continue
        stars = 0
        while j < length and fmt[j] in "-+ 0#":  # flags
            j += 1
        while j < length and (fmt[j].isdigit() or fmt[j] == "*"):  # width
            if fmt[j] == "*":
                stars += 1
            j += 1
        if j < length and fmt[j] == ".":  # precision
            j += 1
            while j < length and (fmt[j].isdigit() or fmt[j] == "*"):
                if fmt[j] == "*":
                    stars += 1
                j += 1
        while j < length and fmt[j] in "hljztL":  # length modifiers
            j += 1
        if j >= length:
            break
        n += 1 + stars  # the conversion char + any *-supplied width/precision
        i = j + 1
    return n


def _trim_writer_varargs(writer: dict[str, Any]) -> dict[str, Any]:
    """Drop varargs the format string never consumes. A snprintf/echo call site may pass more stack
    slots than its fmt uses (uninitialized-slot noise the decompiler surfaces); leaving them in
    reads as 'unresolved inputs' and wrongly inflates controllability. Only trims when a fmt is
    present and there are demonstrably more varargs than it consumes."""
    fmt = writer.get("fmt")
    varargs = writer.get("varargs")
    if not isinstance(fmt, str) or not isinstance(varargs, list):
        return writer
    arity = _fmt_arity(fmt)
    if len(varargs) <= arity:
        return writer
    out = dict(writer)
    out["varargs"] = varargs[:arity]
    # honest marker: args past the format's arity were dropped as fmt-unconsumed, NOT lost origin.
    out["varargs_trimmed_to_fmt_arity"] = True
    return out


def _present_provenance(prov: dict[str, Any], *, dominating_only: bool) -> dict[str, Any]:
    """Read-side presentation of a stack_buf provenance: dominating writers first (so the agent
    reads the sound ones without scanning the branch-noise tail), fmt-arity vararg trim applied, and
    optionally only the dominating writers. Non-stack_buf provenance is returned unchanged."""
    writers = prov.get("writers")
    if not isinstance(writers, list):
        return prov
    trimmed = [_trim_writer_varargs(w) if isinstance(w, dict) else w for w in writers]
    dom = [w for w in trimmed if isinstance(w, dict) and w.get("dominates_sink")]
    non = [w for w in trimmed if not (isinstance(w, dict) and w.get("dominates_sink"))]
    out = dict(prov)
    out["writers"] = dom if dominating_only else dom + non
    return out


def _present_record(rec: dict[str, Any], *, dominating_only: bool) -> dict[str, Any]:
    prov = rec.get("provenance")
    if not isinstance(prov, dict):
        return rec
    out = dict(rec)
    out["provenance"] = _present_provenance(prov, dominating_only=dominating_only)
    return out


def get_sink_provenance(
    conn: sqlite3.Connection,
    evidence_ref: str,
    sink_idx: int | None = None,
    *,
    dominating_only: bool = False,
) -> dict[str, Any]:
    """Full sink_arg_provenance detail for a candidate (the on-demand companion to the explain
    summary). Returns every sink's record when ``sink_idx`` is None, otherwise the one record with
    that idx. Writers are presented dominating-first with fmt-arity vararg trimming; pass
    ``dominating_only`` to return only the sound dominating writers. Read-only; a surfaced def-use
    fact, never a verdict. Unknown ref / idx is reported honestly, never as an empty-but-successful
    result."""
    row = conn.execute(
        "SELECT flow_evidence FROM instance WHERE evidence_ref = ? ORDER BY instance_id LIMIT 1",
        (evidence_ref,),
    ).fetchone()
    if row is None:
        return {"evidence_ref": evidence_ref, "found": False, "note": "no_such_evidence_ref"}
    records = _sink_provenance_records(row[0])
    if not records:
        return {"evidence_ref": evidence_ref, "found": False, "note": "no_sink_provenance"}
    if sink_idx is None:
        return {
            "evidence_ref": evidence_ref,
            "found": True,
            "records": [_present_record(r, dominating_only=dominating_only) for r in records],
        }
    for rec in records:
        if rec.get("sink_idx") == sink_idx:
            return {
                "evidence_ref": evidence_ref,
                "found": True,
                "sink_idx": sink_idx,
                "record": _present_record(rec, dominating_only=dominating_only),
            }
    return {
        "evidence_ref": evidence_ref,
        "found": False,
        "sink_idx": sink_idx,
        "note": "sink_idx_out_of_range",
        "available_sink_idx": [r.get("sink_idx") for r in records],
    }


# ── nvram fact transport: recover the nvram key feeding the sink from stored provenance ──


def _nvram_wrapper_names(conn: sqlite3.Connection) -> frozenset[str]:
    """The thin nvram-wrapper function names A2 recognised, read back from the atlas.

    A2 marks a caller's constant-key call THROUGH a thin nvram wrapper as an indirect key edge and
    stores the wrapper's name in ``nvram_key_flow.via_wrapper``. The candidate-layer source
    attribution never consumed that capability — so a key read via a wrapper (the COMMON case on
    this class of firmware, where almost every nvram access goes through a shared accessor rather
    than a bare nvram_get) was attributed to nothing and its sink collapsed to unknown. Reusing the
    SAME wrapper set here (not re-recognising wrappers — the one A2 capability the candidate layer
    lacked, isomorphic to the dominance case: a lower layer computed it, this one didn't read it)
    closes that gap. Name-only match, cross-binary: an over-match over-promotes a key (the SAFE
    direction — a wrong promote stays visible, a wrong demote hides a bug), it never hides one; the
    downstream web_settable gate, not this set, is what actually decides controllability."""
    try:
        rows = conn.execute(
            "SELECT DISTINCT via_wrapper FROM nvram_key_flow WHERE via_wrapper IS NOT NULL"
        ).fetchall()
    except sqlite3.OperationalError:
        return frozenset()
    return frozenset(r[0] for r in rows if r[0])


def _nvram_key_from_source(source: Any, wrapper_names: frozenset[str] = frozenset()) -> str | None:
    """The nvram key if ``source`` is a call_return reading nvram — via a direct getter OR a thin
    wrapper (``wrapper_names``, from A2) — else None.

    The key is the accessor's first constant string argument (``const_args[0]``) — the exact shape
    the def-use extractor records for ``nvram_get("wan_proto")`` AND for a thin wrapper forwarding a
    caller-supplied constant key (a real thin forwarder passes that key straight to one nvram
    accessor, so the wrapper's const_args[0] IS the key — A2's is_thin test is what earns that
    equivalence; a non-thin function that computes its own key is never in ``wrapper_names``). An
    accessor with no resolved const key yields None (honest: the key was not recovered), never a
    fabricated key."""
    if not isinstance(source, dict) or source.get("kind") != "call_return":
        return None
    callee = source.get("callee")
    if callee not in NVRAM_GETTERS and callee not in wrapper_names:
        return None
    const_args = source.get("const_args")
    if isinstance(const_args, list) and const_args and isinstance(const_args[0], str):
        return const_args[0] or None
    return None


def _nvram_source_key(
    flow_evidence: str | None, wrapper_names: frozenset[str] = frozenset()
) -> str | None:
    """Scan the stored sink_arg_provenance for a resolved nvram-accessor source and return its key.

    Looks at each sink's top-level provenance AND the varargs of its stack-buffer writers (where an
    nvram value most often enters, via ``snprintf("...%s...", nvram_get(key))`` or a wrapper of it).
    Returns the first resolved key; None when no sink's value came from a recognised nvram getter or
    thin wrapper (``wrapper_names``). A surfaced FIELD (which key is involved) — deliberately broad
    (not dominance-scoped): naming a key here only makes the candidate visible in the nvram-source
    view and its source_writability layer; the controllability VERDICT is judged separately and is
    dominance-scoped, so a broad field can never over-assert control."""
    for rec in _sink_provenance_records(flow_evidence):
        prov = rec.get("provenance")
        prov = prov if isinstance(prov, dict) else {}
        key = _nvram_key_from_source(prov, wrapper_names)
        if key is not None:
            return key
        for w in prov.get("writers") or []:
            if not isinstance(w, dict):
                continue
            for va in w.get("varargs") or []:
                if isinstance(va, dict):
                    key = _nvram_key_from_source(va.get("source"), wrapper_names)
                    if key is not None:
                        return key
    return None


def _flow_path_obj(flow_evidence: str | None) -> dict[str, Any]:
    """The stored flow_evidence.flow_path dict (sink_arg / one_hop / wrapper markers); {} when
    absent or unparsable."""
    if not flow_evidence:
        return {}
    try:
        data = json.loads(flow_evidence)
    except (ValueError, TypeError):
        return {}
    fp = data.get("flow_path") if isinstance(data, dict) else None
    return fp if isinstance(fp, dict) else {}


def _flow_list(flow_evidence: str | None, key: str) -> list[Any]:
    """A top-level LIST stored on flow_evidence under ``key``; [] when absent or unparsable (so a
    candidate written before the field existed simply carries none)."""
    if not flow_evidence:
        return []
    try:
        data = json.loads(flow_evidence)
    except (ValueError, TypeError):
        return []
    val = data.get(key) if isinstance(data, dict) else None
    return val if isinstance(val, list) else []


def _sanitizer_records(flow_evidence: str | None) -> list[dict[str, Any]]:
    """The stored flow_evidence.sanitizer_seen list; [] when absent or unparsable."""
    if not flow_evidence:
        return []
    try:
        data = json.loads(flow_evidence)
    except (ValueError, TypeError):
        return []
    san = data.get("sanitizer_seen") if isinstance(data, dict) else None
    return [s for s in san if isinstance(s, dict)] if isinstance(san, list) else []


# ── the seven map layers: each an honest three-state Dimension, never a verdict ──


def _dim_controllability(
    conn: sqlite3.Connection,
    *,
    flow_evidence: str | None,
    sink_anchor: str | None,
    source_kind: str,
    blocking_mechanism: str | None,
    wrapper_names: frozenset[str] = frozenset(),
) -> Dimension:
    """Attacker byte-freedom over the sink argument, from the SINGLE verdict: controllable / free /
    constrained / constant / unknown. A ``controllable`` reading carries a certainty in ``state``:
    ``proven`` (a hard SaTC cross) or ``likely`` (a weaker router_defaults signal, M2).

    Detection FALLBACK CHAIN (⑤), in precedence order — 'single verdict' means PROVENANCE-FIRST,
    source_kind as a fallback, NOT source_kind abandoned:
      1. controllable/proven — provenance shows a proven WEB-SETTABLE key (SaTC front x back cross)
         reaching the sink argument. The strongest controllability the map asserts.
      2. controllable/likely — a key READ from nvram (getter or A2 thin wrapper) that reaches the
         sink is a router_defaults member but NOT a proven cross (M2). Gated to a genuine nvram read
         and dominance-scoped (via _likely_settable_keys_reaching_sink); ranked below
         proven-controllable and above the optimistic 'free'. Placed before the constant steps: a
         dynamic nvram key reaching the arg cannot co-occur with a proven-constant reading — and if
         the data ever conflicts, promoting is the safe direction.
      3. constant     — a provably-constant marker, OR every source in the provenance is a proven
         constant. Checked BEFORE the source_kind fallback so a provenance-DEEP all-const candidate
         (e.g. an ipsec strcpy of a literal) reads constant, not free. ★ BOTH of these exits are
         gated on _anchor_missed: the anchored sink must have left a def-use record here, or the
         reading falls through to the fallback. That is the demotion iron law's completeness half,
         and it is now code rather than a claim in this docstring — a sink hidden behind a thin
         wrapper leaves the caller's records describing OTHER sinks, and both exits would otherwise
         read "constant" off evidence that never saw the sink being judged.
      4. free (likely) — FALLBACK to the text-level source_kind=free_string, carried at state=likely
         (OPTIMISTIC, never proven — no positive evidence backs it, only the absence of a narrowing
         signal). This is the ONLY path that keeps a provenance-SHALLOW legit argv-free candidate (a
         nanddump/mtdinfo printf whose only signal is source_kind) as 'free' instead of collapsing
         it to unknown — do NOT drop it, but do NOT dress the optimism as a proof.
      5. constrained  — a charset-safe / numeric-shape source.
      6. unknown      — nothing established; a ? never sinks.
    (An 'external -> free' step for a provenance external marker is reserved for a future phase; the
    extractor emits no such marker today, so argv-free rides step 4.) The provenance verdict is
    computed by _verdict_from_provenance — the SAME classifier the explain rollup uses, so a
    candidate carries one controllability reading, never two that disagree."""
    prov_verdict = _verdict_from_provenance(conn, flow_evidence, sink_anchor)
    if prov_verdict == "controllable":
        keys = _web_settable_keys_reaching_sink(conn, flow_evidence, sink_anchor)
        via = f"web-settable key '{keys[0]}'" if keys else "a user-settable source"
        return Dimension(
            "controllability",
            "proven",
            "controllable",
            f"sink_arg_provenance: {via} reaches the sink argument",
            "PROVEN controllable: a user-settable source (SaTC front-end x back-end cross) reaches "
            "the sink argument — the strongest controllability the map asserts, ranked above the "
            "'free' fallback",
        )
    likely_keys = _likely_settable_keys_reaching_sink(
        conn, flow_evidence, sink_anchor, wrapper_names
    )
    if likely_keys:
        return Dimension(
            "controllability",
            "likely",
            "controllable",
            f"sink_arg_provenance: nvram key '{likely_keys[0]}' (a router_defaults member) reaches "
            "the sink argument",
            "LIKELY controllable: an nvram key read (via a getter or a thin wrapper) into the sink "
            "argument is a router_defaults member — an optimistic web-settable signal, not a "
            "proven SaTC front x back cross. A lead to confirm: ranked below proven-controllable, "
            "above optimistic 'free'. It may instead be a read-only internal default, and the "
            "getter value may be shape-constrained — confirm web-settability and an untransformed "
            "value",
        )
    # ★ THE COMPLETENESS GATE. Both constant exits below are suppressed when the anchored sink left
    # no def-use record here, because neither of them can be trusted in that state:
    #   * the marker exit is computed from the CALLER's own body, which for an escaped sink never
    #     contains the real call — it can prove a constant is present in the caller (a format
    #     string, say) but not that the value handed to the wrapped sink is one. A constant shell
    #     around an attacker-filled conversion reads exactly like a constant here.
    #   * the provenance exit reads "every record is constant" over records that are the caller's
    #     OTHER sinks, so it comes out true vacuously.
    # Suppressing them drops the candidate to the source_kind fallback — the safe direction. Both
    # controllable steps above stay OPEN under the same condition: promoting on partial evidence
    # costs a review, demoting on it hides a real one. If a future constant marker can prove the
    # WRAPPED argument constant on its own, it belongs on an explicit allow-list with that proof
    # written out; none does today.
    const_trustworthy = not _anchor_missed(flow_evidence, sink_anchor)
    if const_trustworthy and blocking_mechanism in PROVABLY_CONSTANT_MARKERS:
        return Dimension(
            "controllability",
            "proven",
            "constant",
            f"blocking_mechanism={blocking_mechanism}",
            "provably-constant sink argument (compile-time constant, not attacker-controllable) — "
            "the only 'safe' controllability tmap asserts this phase; this is what sinks a "
            "candidate out of the first screen. Asserted only with a def-use record for the "
            "anchored sink in hand: with none, this exit is suppressed and the reading falls back",
        )
    if const_trustworthy and prov_verdict == "const":
        return Dimension(
            "controllability",
            "proven",
            "constant",
            "sink_arg_provenance: every source resolves to a proven constant, and the anchored "
            "sink is among the records read",
            "provably-constant via def-use (all sources constant literals, none unresolved) — "
            "demotes out of the first screen. TWO separate completeness rules hold it up, at two "
            "different levels: per RECORD, a variadic exec seen only at arg0 reads unknown, never "
            "constant; per CANDIDATE, the anchored sink must have left at least one record here at "
            "all, so a sink that escaped behind a thin wrapper can never be called constant on the "
            "strength of the caller's other sinks. Neither proves the provenance COMPLETE — a "
            "record that exists but was internally truncated is a deeper gap",
        )
    if source_kind == "free_string":
        return Dimension(
            "controllability",
            "likely",
            "free",
            "source_kind=free_string (provenance-shallow fallback)",
            "OPTIMISTIC fallback (state=likely, NOT proven): no provenance verdict, so the "
            "text-level source_kind carries the reading, keeping a legit argv-free candidate (e.g. "
            "a nanddump printf) 'free' instead of collapsing to unknown. Convergence-transforms "
            "are not subtracted, so a value washed by inet_ntop / a whitelist / a fixed-width "
            "parse may still read as free; this is an unproven read, confirm byte-freedom by hand",
        )
    if source_kind == "charset_safe":
        return Dimension(
            "controllability",
            "proven",
            "constrained",
            "source_kind=charset_safe",
            "sink argument built inline by a charset-safe converter (MAC / IP / base64 shape)",
        )
    if blocking_mechanism in CONSTRAINED_MARKERS:
        return Dimension(
            "controllability",
            "proven",
            "constrained",
            f"blocking_mechanism={blocking_mechanism}",
            "the value was constrained to a safe charset / numeric shape",
        )
    return Dimension(
        "controllability",
        "unknown",
        "unknown",
        f"source_kind={source_kind}",
        "controllable direction not established — NOT proven safe, NOT proven controllable; a ? "
        "never sinks",
    )


def _dim_source_writability(
    nvram_key: str | None, web_settable: dict[str, Any] | None
) -> Dimension:
    """If the source is an nvram key, can the web UI set it? By the SaTC front↔back cross —
    web_settable (proven) / web_settable (likely, M2) / uncertain. There is NO 'not_settable':
    inferring 'not settable' from a missing front-end field or a missing back-end constant key is a
    false-negative (a key written via a dynamic-key op is absent from the constant set yet still
    settable). The ``likely`` state (router_defaults membership) carries the same value word
    ``web_settable`` with an honest caveat in ``state``/``note`` — it never masquerades as proven. ✗
    not-applicable when the source is not a resolved nvram key."""
    if nvram_key is None or web_settable is None:
        return Dimension(
            "source_writability",
            "excluded",
            "n/a",
            "source is not a resolved nvram key",
            "web-settability applies only when the sink source is a resolved nvram key",
        )
    st = web_settable.get("web_settable")
    src = web_settable.get("source") or ""
    # The web_form_fields rows behind the front-end match (field / asset / rule / match_kind), so an
    # agent drills in to confirm the web reach or demote a keyword collision. Carried on every state
    # (empty when the front end contributed nothing); it never changes the verdict.
    ev = tuple(web_settable.get("evidence") or ())
    if st == "yes":
        return Dimension(
            "source_writability",
            "proven",
            "web_settable",
            f"SaTC cross[{nvram_key}]",
            f"key '{nvram_key}' is a user-editable web key ({src})",
            evidence=ev,
        )
    if st == "likely":
        return Dimension(
            "source_writability",
            "likely",
            "web_settable",
            f"router_defaults[{nvram_key}]",
            f"key '{nvram_key}' is LIKELY web-settable — a router_defaults member ({src}); an "
            "optimistic signal, NOT a proven SaTC cross (may be a read-only internal default)",
            evidence=ev,
        )
    return Dimension(
        "source_writability",
        "unknown",
        "uncertain",
        "SaTC cross",
        f"'{nvram_key}' not proven web-settable — uncertain, NOT 'not settable' ({src})"
        if src
        else "web-settability uncertain (surface not fully collected)",
        evidence=ev,
    )


# The two mandatory reachability caveats (contract C7 note). Kept as constants so the dimension
# note, the explain view, and the seam tests read one source of truth. Neither ever collapses into
# state/value — they stay in the note. The standard-flow caveat is the always-true honest note (a
# textual reference is not a dispatch proof); the completeness caveat names the unmodeled bridge.
_REACH_CAVEAT_STANDARD_FLOW = (
    "an entry edge references this binary — a rootfs reference or another binary's launch "
    "callsite, NOT proof the input arrives from it; confirm the endpoint/script/caller actually "
    "dispatches here"
)
_REACH_CAVEAT_COMPLETENESS = (
    "service-dispatch / IPC bridges (notify_rc / rc_service: httpd->rc) are NOT modeled, so a "
    "binary reachable only via that bridge shows entry:script or unknown, never entry:web — "
    "entry:web is an INCOMPLETE slice of the web-reachable set, and entry:script is not evidence "
    "of lower reachability"
)


def _edge_leads(
    edges: tuple[dict[str, Any], ...], flow_evidence: str | None
) -> tuple[dict[str, Any], ...]:
    """The structured string-key leads for this candidate — machine-readable, unambiguous.

    Merges the two sources, which answer two different hop depths:
      * hops=0 — this function IS an edge callee (read straight from the atlas edge table).
      * hops=1 — this function sits one direct call below an edge callee (precomputed at hunt time
        onto flow_evidence, since the atlas holds no call graph), carrying ``through``.

    ★ IRON LAW: a lead is a FACT, never a reachability verdict. It NEVER changes the dimension's
    state/value — it rides in ``evidence`` so an agent reads the key without parsing prose.
    """
    leads: list[dict[str, Any]] = [
        {
            "via": "string_keyed_edge",
            "key": e.get("key"),
            "hops": 0,
            "from_function": e.get("from_function"),
            "mechanism": e.get("mechanism"),
        }
        for e in edges
        if e.get("key")
    ]
    for lead in _flow_list(flow_evidence, "reachability_leads"):
        if isinstance(lead, dict) and lead.get("key"):
            leads.append(lead)
    return tuple(leads)


def _one_hop_lead_note(leads: tuple[dict[str, Any], ...]) -> str:
    """The one-hop line. ★ Deliberately LOOSER than the zero-hop wording, and never reuse that one:
    zero hop means the key dispatches straight HERE, but one hop only means the edge callee CALLS
    this function — an edge callee is often a fat handler, so the key's data may never arrive. Say
    that outright: a fan-out handler otherwise mass-produces leads that read as proven."""
    one_hop = [x for x in leads if x.get("hops") == 1]
    if not one_hop:
        return ""
    shown = one_hop[:3]
    parts = [f"key='{x.get('key')}' through {x.get('through') or '?'}" for x in shown]
    more = f" (+{len(one_hop) - len(shown)} more)" if len(one_hop) > len(shown) else ""
    return (
        " Also: a STRING-KEYED EDGE lands one call above this function — "
        + "; ".join(parts)
        + more
        + ". STRUCTURAL one hop only: the edge callee CALLS this function, but whether the "
        "key-selected data ARRIVES here is NOT proven (an edge callee is often a fat handler that "
        "calls much unrelated to the key it matched). reachability STAYS unknown — confirm the "
        "hop yourself. See the layer's evidence for the structured leads."
    )


def _string_keyed_edge_note(edges: tuple[dict[str, Any], ...]) -> str:
    """A one-line summary of the string-keyed edge(s) whose callee is this candidate's function — a
    KEY LEAD, never a reachability verdict. Empty when there are none. ★ IRON LAW: this text ADDS a
    lead to the note; it must NEVER change the reachability state to proven/reachable — tmap
    ENUMERATES the edge (a fact), the agent JUDGES reachability."""
    if not edges:
        return ""
    shown = edges[:3]
    parts = [
        f"key='{e.get('key') or '?'}' from {e.get('from_function') or '?'} "
        f"[{e.get('mechanism') or '?'}]"
        for e in shown
    ]
    more = f" (+{len(edges) - len(shown)} more)" if len(edges) > len(shown) else ""
    return (
        " Also: this function is the callee of a STRING-KEYED EDGE — "
        + "; ".join(parts)
        + more
        + ". That is a key lead you confirm (an attacker-influenceable string key dispatches "
        "here); reachability STAYS unknown — tmap enumerates the edge, it does not judge "
        "reachability. Use get_string_keyed_edges to drill in; check the edge's completeness."
    )


def _dim_reachability(
    entry_reach: str,
    web_triggers: tuple[str, ...] = (),
    string_keyed_edges: tuple[dict[str, Any], ...] = (),
    flow_evidence: str | None = None,
) -> Dimension:
    """Which kind of entry edge references this binary? A MECHANISTIC label — entry:web /
    entry:script / entry:exec / their ``+`` combinations / unknown — NEVER a reachability verdict
    (it does not decide whether the input arrives) and never a claim about an authentication
    boundary. ``state`` is proven for any SOUND entry reference (the boundary-matched web edge, the
    exact-tail script edge, and a launch edge whose target resolved to this very binary are all
    sound REFERENCES — soundness of the reference, never of the dataflow behind it); unknown for a
    coverage gap. A ? is NEVER 'unreachable' and never sinks.
    The two caveats (standard-flow + completeness) always ride in ``note`` and never collapse into
    state/value (contract C7). This answers the ENTRY level only — entry->sink flow within a
    function is a separate, unmodeled question.

    ★ IRON LAW: a string-keyed edge — whether it dispatches straight here (0 hops) or lands one call
    above (1 hop) — is APPENDED to the note as a key lead and mirrored into ``evidence`` as a
    structured row. It NEVER changes ``state``/``value``. A candidate with no entry stays unknown
    even when an edge points at it; the edge is a fact the agent confirms, not a grant. The two hop
    depths get deliberately DIFFERENT wording — see _one_hop_lead_note."""
    edge_note = _string_keyed_edge_note(string_keyed_edges)
    leads = _edge_leads(string_keyed_edges, flow_evidence)
    edge_note += _one_hop_lead_note(leads)
    if entry_reach.startswith("entry:"):
        trig = f" ({', '.join(web_triggers)})" if web_triggers else ""
        note = (
            f"{entry_reach}{trig}: {_REACH_CAVEAT_STANDARD_FLOW}. Completeness: "
            f"{_REACH_CAVEAT_COMPLETENESS}. Entry-level only — tmap does not connect entry->sink "
            "within a function (sink-level reachability unknown)."
        )
        return Dimension(
            "reachability",
            "proven",
            entry_reach,
            "flow_evidence.entry_reach.sites (rootfs script / web-asset / launch-edge reference)",
            note + edge_note,
            leads,
        )
    return Dimension(
        "reachability",
        "unknown",
        "unknown",
        "flow_evidence.entry_reach.sites",
        "no script/web/launch entry found — reported unknown (a coverage gap), NOT unreachable: "
        "cross-binary launch edges are enumerated but INCOMPLETE (a caller behind a thin command "
        "wrapper is invisible to that pass, and a token that could not be read resolves to "
        "nothing), and a service-dispatch/IPC bridge (notify_rc) is not modeled at all; a ? never "
        "sinks" + edge_note,
        leads,
    )


def _dim_filtering(flow_evidence: str | None) -> Dimension:
    """Is there sanitization on the path? Near-always '?' this phase: tmap does a generic
    name-match only and cannot prove a sanitizer covers the path, so it claims neither present
    or proven-absent — it does not save the agent from reading the filter code."""
    san = _sanitizer_records(flow_evidence)
    if any(s.get("on_path") for s in san):
        note = (
            "a sanitizer-shaped call sits on the path, but coverage is UNJUDGED (a static read "
            "cannot prove it covers the path) — still '?', read the filter code yourself"
        )
    elif san:
        note = (
            "sanitizer-shaped calls exist but none on the sink's path (generic name-match; a "
            "custom guard may still exist) — '?'"
        )
    else:
        note = (
            "no sanitizer-shaped callee recognized (generic name-match only; a custom guard may "
            "still exist) — '?', tmap does not save you from reading the filter code"
        )
    return Dimension("filtering", "unknown", "unknown", "flow_evidence.sanitizer_seen", note)


def _dim_sink_impact(sink_class: str, overrides: dict[str, int] | None = None) -> Dimension:
    """What sink is this + its potential-impact tier. The value is the OPEN-set sink_class;
    the tier is a visible, OVERRIDABLE judgement (default cmd=fmt>copy>log)."""
    tier = impact_tier(sink_class, overrides)
    tname = {3: "high", 2: "medium", 1: "low"}.get(tier, "lowest (unmapped class)")
    return Dimension(
        "sink_impact",
        "proven",
        sink_class or "unknown",
        "sink callee classification",
        f"impact tier {tier} ({tname}); default order cmd=fmt>copy>log — a visible, OVERRIDABLE "
        "judgement, not a magnitude-of-harm claim",
    )


def _dim_writer(flow_evidence: str | None) -> Dimension:
    """Who writes the sink argument's value? located / via_wrapper / not_traced, from the def-use
    provenance. A ? (not_traced) never sinks."""
    if _flow_path_obj(flow_evidence).get("sink_via_wrapper"):
        return Dimension(
            "writer",
            "proven",
            "via_wrapper",
            "flow_evidence.flow_path.wrapper",
            "the value is forwarded one hop through a thin wrapper to the real sink",
        )
    for rec in _sink_provenance_records(flow_evidence):
        prov = rec.get("provenance")
        prov = prov if isinstance(prov, dict) else {}
        if prov.get("kind") == "constant":
            return Dimension(
                "writer",
                "proven",
                "located",
                "sink_arg_provenance (constant)",
                "the sink argument resolves to a constant writer",
            )
        if prov.get("nearest_dominating_writer"):
            return Dimension(
                "writer",
                "proven",
                "located",
                f"sink_arg_provenance (dominating writer {prov.get('nearest_dominating_writer')})",
                "a sound dominating writer for the sink argument was located",
            )
    return Dimension(
        "writer",
        "unknown",
        "not_traced",
        "sink_arg_provenance",
        "no dominating writer resolved (unresolved / untraced stack buffer) — who writes the value "
        "was not established; a ? never sinks",
    )


def _dim_completeness() -> Dimension:
    """Was the containing function fully decompiled? '?' this phase: the per-function A4 signal
    lives in analysis.db, and triage is atlas-only. Honestly deferred, never faked complete."""
    return Dimension(
        "completeness",
        "unknown",
        "unknown",
        "A4 per-function decompile completeness (not wired into the atlas-only triage this phase)",
        "cross-check partially_incomplete_binaries at the listing top level (A4) for this binary — "
        "a partial binary means some of its functions never decompiled",
    )


def _dim_source(source_class: str, source_kind: str) -> Dimension:
    """The ORTHOGONAL source axis: is the sink argument fed by A2-confirmed external input (a
    request/POST param)? ``source_class == external_input`` => ``structural:param`` — a structural
    command/exec-injection lead whose controllability is UNPROVEN (no key-side web_settable
    evidence), WEAKER than an nvram 'likely' reading. NOT ``proven``: the A2 pattern layer is coarse
    (it fires on nearly EVERY external-input candidate across ALL sink classes — cmd, fmt_string,
    path_sink — so it is ~zero discrimination, not a cmd-only signal) and a source is not a
    controllability proof — ``proven`` is reserved for a positive proof, so the state word matches
    the note's own 'UNPROVEN' instead of contradicting it.

    Orthogonal to controllability, and consumes the COARSE ``source_class`` (A2 pattern layer), NOT
    the fine flow_evidence marker: it is built whenever A2 marked external_input, EVEN when the
    certainty verdict fell to unknown/free — so the param signal is never swallowed by the certainty
    fallback chain (source=param and controllability=unknown:unknown co-exist). It NEVER claims
    controllable: a source is not a controllability proof (asymmetry — mark weak, never overclaim).
    ``charset`` (from source_kind) carries the injection feasibility. Non-external => unknown (not
    carried; the demotion-visible rule leaves a real source untouched)."""
    if source_class == "external_input":
        return Dimension(
            "source",
            "structural",
            "param",
            "pattern.source_class = external_input (A2)",
            "external input reaches the sink (a POST/request param); NOT proven web-controllable "
            f"(no key-side web_settable evidence). charset={source_kind}. A STRUCTURAL lead "
            "(state=structural, NOT proven): controllability UNPROVEN — weaker than an nvram "
            "'likely' reading, and the A2 pattern layer is coarse (near-zero discrimination — it "
            "fires on nearly every external-input candidate in ANY sink class: cmd, fmt_string, "
            "path_sink). Confirm the concrete request field and reachability by hand.",
        )
    return Dimension(
        "source",
        "unknown",
        "unknown",
        "pattern.source_class",
        "source is not an A2-confirmed external input — the param signal does not apply; "
        "controllability stands on its own evidence",
    )


def _build_dimensions(
    conn: sqlite3.Connection,
    *,
    flow_evidence: str | None,
    source_class: str,
    source_kind: str,
    blocking_mechanism: str | None,
    sink_class: str,
    entry_reach: str,
    web_triggers: tuple[str, ...],
    nvram_key: str | None,
    sink_anchor: str | None,
    wrapper_names: frozenset[str] = frozenset(),
    string_keyed_edges: tuple[dict[str, Any], ...] = (),
) -> tuple[Dimension, ...]:
    """The honest map layers for one candidate. web_settable is the SaTC front↔back cross, looked
    up once when the source resolved to an nvram key (shared by source_writability); the
    controllability layer runs the single verdict over the anchored sink's def-use provenance. The
    orthogonal ``source`` layer consumes the coarse ``source_class`` and is INDEPENDENT of the
    controllability verdict (never a certainty-chain step)."""
    web_settable = _web_settable(conn, nvram_key) if nvram_key else None
    return (
        _dim_controllability(
            conn,
            flow_evidence=flow_evidence,
            sink_anchor=sink_anchor,
            source_kind=source_kind,
            blocking_mechanism=blocking_mechanism,
            wrapper_names=wrapper_names,
        ),
        _dim_source(source_class, source_kind),
        _dim_source_writability(nvram_key, web_settable),
        _dim_reachability(entry_reach, web_triggers, string_keyed_edges, flow_evidence),
        _dim_filtering(flow_evidence),
        _dim_sink_impact(sink_class),
        _dim_writer(flow_evidence),
        _dim_completeness(),
    )


def _candidate(
    conn: sqlite3.Connection,
    row: sqlite3.Row,
    wrapper_names: frozenset[str] = frozenset(),
) -> TriageCandidate:
    reach = row["reachability_status"]
    fe = _row_get(row, "flow_evidence")
    entry_reach = _entry_reach_status(fe)
    web_triggers = _entry_web_triggers(fe)
    source_kind = _source_kind_from_evidence(fe)
    sink_class = row["sink_class"]
    blocking = row["blocking_mechanism"]
    sink_anchor = row["sink_anchor"]
    # The resolved nvram key for the source_writability layer: a recognized nvram accessor — a
    # direct getter (NVRAM_GETTERS) OR an A2 thin wrapper (wrapper_names) — first, else the first
    # web-settable key the verdict found reaching the sink. Wrapper-aware (M1) so a key read through
    # a shared accessor (the common case) still shows in source_writability and the nvram-source
    # view, coherent with the controllability reading.
    nvram_key = _nvram_source_key(fe, wrapper_names)
    if nvram_key is None:
        web_keys = _web_settable_keys_reaching_sink(conn, fe, sink_anchor)
        nvram_key = web_keys[0] if web_keys else None
    # ★ Reachability lead (iron-law-safe): is this candidate's function the callee of a string-keyed
    # edge (a strcmp ladder / static table gates it behind an attacker-influenceable key)? Scoped to
    # this candidate's binary (basename of binary_path == the edge's short binary name) so a
    # same-named function in another binary does not bleed in. This ANNOTATES the reachability note
    # with the key lead; it NEVER flips reachability to proven — the agent judges reachability.
    function = row["source_anchor"]
    binary_path = row["binary_path"]
    binary_name = Path(binary_path).name if binary_path else None
    string_keyed_edges = tuple(edges_reaching_callee(conn, binary_name, function))
    return TriageCandidate(
        review_status=REVIEW_STATUS_BY_REACHABILITY.get(reach, reach),
        reachability_status=reach,
        function=row["source_anchor"],
        sink_anchor=row["sink_anchor"],
        source_class=row["source_class"],
        sink_class=sink_class,
        blocking_mechanism=blocking,
        origin=row["origin"],
        source_run_id=row["source_run_id"],
        evidence_ref=row["evidence_ref"],
        binary_path=row["binary_path"],
        entry_reach=entry_reach,
        source_kind=source_kind,
        exposure_shape=_row_get(row, "exposure_shape"),
        structural_fingerprint=_row_get(row, "structural_fingerprint"),
        nvram_source_key=nvram_key,
        dimensions=_build_dimensions(
            conn,
            flow_evidence=fe,
            source_class=row["source_class"],
            source_kind=source_kind,
            blocking_mechanism=blocking,
            sink_class=sink_class,
            entry_reach=entry_reach,
            web_triggers=web_triggers,
            nvram_key=nvram_key,
            sink_anchor=sink_anchor,
            wrapper_names=wrapper_names,
            string_keyed_edges=string_keyed_edges,
        ),
    )


def _row_get(row: sqlite3.Row, key: str) -> str | None:
    """Read an optional column from a sqlite Row (returns None when the column is not selected)."""
    return row[key] if key in row.keys() else None


# Display order of the presentation review statuses (highest-intent first). Shared by the CLI
# renderer and the MCP candidate list so the two fold/show the same statuses.
_SECTION_ORDER = ("to-verify", "reachable", "gated")


def sink_matches(candidate: TriageCandidate, sink: str) -> bool:
    """True if a --sink value names this candidate's sink — by concrete callee (system / popen /
    syslog / strcpy …) OR by sink class (cmd / fmt_string / copy / format). Case-insensitive."""
    needle = sink.lower()
    return (candidate.sink_anchor or "").lower() == needle or candidate.sink_class.lower() == needle


def shown_statuses(status: str | None, *, include_gated: bool, sink: str | None) -> set[str]:
    """Which review statuses to display, matching the CLI triage semantics exactly.

    A --sink filter or status='all' shows every status (so a recalled-but-low sink is never hidden
    by the default fold); an explicit status shows only that one; otherwise the default shows
    to-verify + reachable, with gated folded unless include_gated."""
    if status == "all" or sink is not None:
        return set(_SECTION_ORDER)
    if status is not None:
        return {status}
    base = {"to-verify", "reachable"}
    if include_gated:
        base.add("gated")
    return base


def filter_candidates(
    candidates: list[TriageCandidate],
    *,
    sink: str | None = None,
    status: str | None = None,
    include_gated: bool = False,
) -> list[TriageCandidate]:
    """Apply the shared sink/status/include_gated filters to a ranked list (input order kept)."""
    statuses = shown_statuses(status, include_gated=include_gated, sink=sink)
    return [
        c
        for c in candidates
        if c.review_status in statuses and (sink is None or sink_matches(c, sink))
    ]


# ── composable sort spec: ONE sort function projected into lenses ──
#
# A view = {filter predicate, spine axis}. Everything else RIDES under every view, not overridable:
#  - the composite secondary key (impact x controllability-certainty), same meaning in any lens
#  - the only-UP tertiary keys (found / located / complete promote; their ? never demotes)
#  - the demotion IRON LAW: only a PROVEN-SAFE fact sinks a candidate; a ? NEVER sinks
# The agent changes only the spine (--sort-by) and the filters; the iron law is fixed. This is what
# makes every lens safe: no angle can bury a candidate by "not yet known".

# Controllability bands, high rank first. proven-controllable (a hard SaTC cross) is the top band;
# likely-controllable (M2: a router_defaults-member nvram key reaching the sink — value
# 'controllable' with state 'likely') sits just below it via _LIKELY_CONTROLLABLE_RANK, ABOVE the
# optimistic 'free' (source_kind=free_string): a real-but-unconfirmed nvram key outranks an
# optimistic guess, and both outrank unknown. constant stays the bottom (the demotion iron law sinks
# it via _is_proven_safe). Within a sink-impact tier this is the certainty tiebreak; impact is the
# outer axis, so a likely-controllable cmd still outranks a proven-safe log — harm is respected.
_CONTROLLABILITY_RANK: dict[str, int] = {
    "controllable": 5,
    "free": 3,
    "constrained": 2,
    "unknown": 1,
    "constant": 0,
}
# A 'controllable' reading with state=='likely' (M2) ranks here — between proven-controllable (5)
# and 'free' (3). The value word stays 'controllable' (so a controllability=controllable filter sees
# both proven and likely); only state distinguishes the certainty, and only the sort consumes it.
_LIKELY_CONTROLLABLE_RANK = 4


def _controllability_rank(dim: Dimension) -> int:
    """The sort rank for a controllability dimension: proven-controllable (5) >
    likely-controllable (4) > free (3) > constrained (2) > unknown (1) > constant (0). The
    likely/proven split reads the certainty from ``state``; every other value reads from the map."""
    if dim.value == "controllable" and dim.state == "likely":
        return _LIKELY_CONTROLLABLE_RANK
    return _CONTROLLABILITY_RANK.get(dim.value, 1)


# Command/exec-injection FEASIBILITY of an external_input source, by its charset (source_kind),
# strongest first — the honest layering within the orthogonal param signal (spec M2). free_string
# (no charset constraint, metachars pass) is most feasible; charset_safe (a converter constrained
# the value inline) is least — proven-safe against injection, so the param float excludes it.
_CHARSET_FEASIBILITY_RANK: dict[str, int] = {
    "free_string": 3,
    "charset_maybe": 2,
    "unknown": 1,
    "charset_safe": 0,
}


def _is_param_source(c: TriageCandidate) -> bool:
    """True when A2 marked this candidate's source external_input (source=structural:param). The
    param float / charset tiebreak / filter all route through this ONE predicate, so demoting the
    source state from proven to structural leaves the sort and filter behaviour untouched."""
    d = c.dim("source")
    return d.state == "structural" and d.value == "param"


def _param_float(c: TriageCandidate) -> int:
    """1 when an A2 external_input reaches the sink with an UNCONSTRAINED-or-unknown charset — a
    structural command/exec-injection lead that floats ABOVE same-certainty non-param peers (lifting
    the 59 external_input×unknown out of the unknown pile, and the 41 ×free_string to the top of the
    'free' band). Placed AFTER the certainty key so it NEVER overrides controllability (a
    proven/likely-controllable candidate still wins its tier — guardrail 3). Gated OUT for
    charset_safe (the param-internal demotion iron law: a converter-constrained value cannot inject,
    so it is never floated)."""
    if not _is_param_source(c):
        return 0
    return 1 if c.source_kind in ("free_string", "charset_maybe", "unknown") else 0


def _charset_rank(c: TriageCandidate) -> int:
    """Injection-feasibility tiebreak WITHIN the floated param band (free_string > charset_maybe >
    unknown > charset_safe); 0 for a non-param candidate (they are separated earlier by
    ``_param_float``, so this only orders param candidates among themselves)."""
    if not _is_param_source(c):
        return 0
    return _CHARSET_FEASIBILITY_RANK.get(c.source_kind, 1)


def _reach_is_entry(reach: str) -> bool:
    """A reachability value that names at least one found rootfs entry edge (entry:web /
    entry:script / entry:web+script). ``unknown`` (a coverage gap) is not an entry. This is the
    only-up promote predicate: an entry promotes; an ``unknown`` is strictly NEUTRAL — never
    demoted (the reachability asymmetry: a proven entry lifts, a ? never sinks)."""
    return reach.startswith("entry:")


def _reach_rank(reach: str) -> int:
    """Reachability SPINE rank: any found entry edge (2) ranks above ``unknown`` (1). Every entry:*
    is EQUAL — reachability does not tiebreak web above script (it is an orthogonal filter axis, not
    a verdict). This preserves the pre-split found>unknown ordering exactly, so reachability never
    changes the default sort order (contract C5)."""
    return 2 if _reach_is_entry(reach) else 1


_VALID_SPINES = frozenset({"impact", "sink_impact", "reachability", "controllability", "by-sink"})


def _is_proven_safe(c: TriageCandidate) -> bool:
    """Does the candidate carry a PROVEN-SAFE fact (the only thing that may sink it)?

    This phase the sole reliably-provable safe fact is a compile-time-constant controllability:
    proven-blocked reachability and filter-dominates are not computable yet. When they are,
    OR them in here — the sort and every view inherit the change with no other edit."""
    return c.dim("controllability").value == "constant"


def _sort_atoms(c: TriageCandidate, overrides: dict[str, int] | None) -> dict[str, int]:
    reach = c.dim("reachability").value
    return {
        "proven_safe": int(_is_proven_safe(c)),
        "impact": impact_tier(c.sink_class, overrides),
        "controllability": _controllability_rank(c.dim("controllability")),
        # orthogonal param signal (spec M2): floats an external_input lead above same-certainty
        # peers, then layers by charset feasibility — both AFTER certainty (guardrail 3).
        "param_float": _param_float(c),
        "charset_rank": _charset_rank(c),
        "reach_rank": _reach_rank(reach),
        "reach_promote": 1 if _reach_is_entry(reach) else 0,
        "writer_promote": 1 if c.dim("writer").value == "located" else 0,
        "completeness_promote": 1 if c.dim("completeness").value == "complete" else 0,
    }


def _sort_key(
    c: TriageCandidate, *, spine: str, overrides: dict[str, int] | None
) -> tuple[Any, ...]:
    a = _sort_atoms(c, overrides)
    # [0] iron law: not-safe (0) before proven-safe (1) — proven-safe always sinks, in EVERY lens.
    key: list[Any] = [a["proven_safe"]]
    # [1..] the spine (the pivot axis; negated so higher rank ranks earlier)
    if spine == "reachability":
        key.append(-a["reach_rank"])
    elif spine == "controllability":
        key.append(-a["controllability"])
    elif spine == "by-sink":
        key.append(-a["impact"])
        key.append(c.sink_class or "")  # group by exact class within a tier
    else:  # impact / sink_impact / default
        key.append(-a["impact"])
    # composite secondary (rides under every lens): band by impact, then controllability-certainty
    key.append(-a["impact"])
    key.append(-a["controllability"])
    # orthogonal param float (spec M2, rides under every lens): AFTER certainty so a
    # proven/likely-controllable candidate always outranks a source=param one in the same tier
    # (guardrail 3); floats external_input leads above same-certainty peers, then layers by charset.
    key.append(-a["param_float"])
    key.append(-a["charset_rank"])
    # tertiary only-UP promotes (a proven positive lifts; its ? stays put, never demotes)
    key.append(-a["reach_promote"])
    key.append(-a["writer_promote"])
    key.append(-a["completeness_promote"])
    # deterministic tiebreak
    key.append(c.function or "")
    key.append(c.evidence_ref or "")
    return tuple(key)


def sort_candidates(
    candidates: list[TriageCandidate],
    *,
    spine: str = "impact",
    impact_overrides: dict[str, int] | None = None,
) -> list[TriageCandidate]:
    """Project the candidate map into one lens. ``spine`` picks the pivot axis (default ``impact``);
    the composite key, the only-up tertiary keys, and the demotion iron law ride under EVERY spine
    and are not overridable. ``impact_overrides`` (from ``parse_impact_order``) re-orders the impact
    tiers only — the ordering STRUCTURE (impact then controllability) stays fixed."""
    sp = spine if spine in _VALID_SPINES else "impact"
    return sorted(candidates, key=lambda c: _sort_key(c, spine=sp, overrides=impact_overrides))


# The --filter LENS set: the dimensions a user can filter/sort candidates by. This is NOT the
# authoritative dimension universe -- `source` is deliberately absent (it is an orthogonal
# param/source axis, not a filterable lens). Anything that must COVER every dimension (a consumer,
# the layer-2 universe guard) must anchor on _CANONICAL_DIMENSION_NAMES below, never on this set.
_DIMENSION_NAMES = frozenset(
    {
        "controllability",
        "source_writability",
        "reachability",
        "filtering",
        "sink_impact",
        "writer",
        "completeness",
    }
)

# The authoritative dimension universe: every dimension _build_dimensions() actually emits. Written
# out by hand ON PURPOSE -- it must NOT be derived as `{d.name for d in _build_dimensions(...)}`,
# because a derived anchor is self-referential: deleting a `_dim_*` would drop the name from BOTH
# the code and the anchor, so a coverage guard would stay green while a dimension silently vanished
# (zero interception). A consumer/guard that must not let a dimension disappear by absence anchors
# on THIS list; test_triage_explain asserts it equals {d.name for d in ex.dimensions}, so a drift
# between this hand-list and the real assembly is caught mechanically.
_CANONICAL_DIMENSION_NAMES = frozenset(
    {
        "controllability",
        "source",
        "source_writability",
        "reachability",
        "filtering",
        "sink_impact",
        "writer",
        "completeness",
    }
)


def _entry_kinds(reach: str) -> frozenset[str]:
    """The entry kinds named by a reachability value: ``entry:web+script`` -> {web, script},
    ``entry:web`` -> {web}, ``unknown`` -> {}."""
    if not reach.startswith("entry:"):
        return frozenset()
    return frozenset(reach[len("entry:") :].split("+"))


def _reach_filter_match(cand_value: str, filter_value: str) -> bool:
    """Reachability filter matching — an orthogonal LENS axis that never reduces the map's contents,
    only the view. ``entry:web`` matches entry:web AND entry:web+script (the candidate has web among
    its kinds); ``entry:script`` matches entry:script AND entry:web+script; ``entry:web+script``
    matches only both; ``unknown`` matches unknown. ``found`` is a backward-compatible alias for any
    found entry edge."""
    if filter_value in ("unknown", ""):
        return cand_value == "unknown"
    if filter_value == "found":  # legacy alias: any found entry edge
        return _reach_is_entry(cand_value)
    want = _entry_kinds(filter_value)
    return bool(want) and want <= _entry_kinds(cand_value)


def _matches(c: TriageCandidate, dim: str, value: str) -> bool:
    """Does candidate ``c`` match ``dim=value``? The SINGLE predicate behind both the reducing
    ``filter_by_dimension`` (used by ``--only`` and the legacy filters) and the circle-and-weight
    float. ``source=nvram`` = a resolved nvram source key; ``sink_impact/sink_class/sink`` read the
    sink_class field; reachability matches by entry kind (see ``_reach_filter_match``); an unknown
    dimension name matches everything (a no-op, mirroring the old ``filter_by_dimension``)."""
    v = value.lower()
    if dim == "source":
        # 'source' carries two orthogonal lenses: ``source=nvram`` = a resolved nvram source key;
        # ``source=param`` = the A2 external_input signal (the source Dimension). Any other value is
        # a no-op (matches all), mirroring the permissive legacy behaviour.
        if v == "nvram":
            return c.nvram_source_key is not None
        if v == "param":
            return _is_param_source(c)
        return True
    if dim in ("sink_impact", "sink_class", "sink"):
        return (c.sink_class or "").lower() == v
    if dim == "reachability":
        return _reach_filter_match(c.dim("reachability").value.lower(), v)
    if dim in _DIMENSION_NAMES:
        return c.dim(dim).value.lower() == v
    return True


def filter_by_dimension(
    candidates: list[TriageCandidate], dim: str, value: str
) -> list[TriageCandidate]:
    """REDUCE to the candidates matching ``dim=value`` — used by ``--only`` (the explicit prune) and
    the legacy filters. See ``_matches`` for the per-dimension predicate. An unknown dimension name
    is a no-op (returns all). NOTE ``--filter`` no longer routes here: it FLOATS (see ``apply_view``
    / ``_float_by_dimension``) so it never reduces the corpus."""
    return [c for c in candidates if _matches(c, dim, value)]


# Values that mean "not established" — an unknown STATE renders as one of these, and a null/empty
# ground-truth field collapses to one too. One set covers the explicit-unknown AND the implicit-null
# case, so there is no drifting seam between "scan for state==unknown" and "hand-check for null".
_UNRESOLVED_VALUES: frozenset[str] = frozenset({"unknown", "?", "undetermined", ""})


def _is_resolved(c: TriageCandidate, dim: str) -> bool:
    """Does ``c`` carry a RESOLVED ground-truth value on ``dim`` — no unknown state, no null/empty/
    '?' value? The ground-truth sink dimensions read the sink_class field directly (a null there is
    unresolved); an optimistic dimension reads its layer's state+value (an ``unknown`` state, or a
    proven layer whose value is still ``unknown`` — e.g. sink_impact over a null sink_class — is
    unresolved). ``source`` attribution is optimistic (unknown when unresolved), never a truth."""
    if dim in ("sink_impact", "sink_class", "sink"):
        sc = (c.sink_class or "").lower()
        return bool(sc) and sc not in _UNRESOLVED_VALUES
    if dim == "source":
        return False
    if dim in _DIMENSION_NAMES:
        d = c.dim(dim)
        return d.state != "unknown" and bool(d.value) and d.value.lower() not in _UNRESOLVED_VALUES
    return False


def reducible(dim: str, candidates: list[TriageCandidate]) -> bool:
    """Is ``dim`` REDUCIBLE (safe for an ``--only`` prune) on THIS corpus? True iff EVERY candidate
    carries a resolved ground-truth value on it (see ``_is_resolved``). Optimistic dimensions (any
    unknown state) and null-bearing dimensions are NOT reducible — pruning them would silently hide
    candidates the analysis could not classify (the UI version of the recall red line: "no match"
    is not "absent", as "untraced" is not "safe"). Computed PER CORPUS, never a static whitelist: a
    firmware whose sink_class carries a null flips sink_class out automatically, so a coverage gap
    cannot smuggle a prune back in on the next image."""
    return bool(candidates) and all(_is_resolved(c, dim) for c in candidates)


# The dimension names a filter may name. Extends the canonical set with the two sink spellings
# ``_matches`` also honours — anchoring on _CANONICAL alone would reject ``sink_class``, which is a
# live, selective filter. (Referencing _CANONICAL here is fine: what must never be derived is the
# canonical set itself, from _build_dimensions(); this only reads it.)
_FILTERABLE_DIMENSION_NAMES = frozenset(_CANONICAL_DIMENSION_NAMES | {"sink_class", "sink"})


def unknown_dimension_refusal(filters: list[tuple[str, str]]) -> str | None:
    """The refusal message when a filter names a dimension that does not exist, else None.

    Without this, an unknown name is not an error and not an empty result — ``_matches`` returns
    True for anything it does not recognise, so every candidate lands in the matched band and the
    count comes back equal to the whole corpus. That reads like "they all match" rather than "there
    is no such dimension", which is the worst of the three possible answers.

    This catches a bad NAME only. A real dimension given a value it has no rule for (``source`` with
    anything other than nvram/param, say) still matches everything — a separate gap, not closed
    here."""
    for dim, _ in filters:
        if dim not in _FILTERABLE_DIMENSION_NAMES:
            return (
                f"filter dimension {dim!r} does not exist; valid dimensions are: "
                f"{', '.join(sorted(_FILTERABLE_DIMENSION_NAMES))}"
            )
    return None


def only_refusal(
    only_filters: list[tuple[str, str]], candidates: list[TriageCandidate]
) -> str | None:
    """The refusal message when an ``--only`` prune targets a non-reducible dimension on this
    corpus, else None. Shared by the CLI and MCP so both refuse identically and steer the caller to
    ``--filter`` (float, which never hides a candidate)."""
    for dim, value in only_filters:
        if not reducible(dim, candidates):
            n = len(candidates)
            k = sum(1 for c in candidates if not _is_resolved(c, dim))
            return (
                f"--only {dim}={value} refused: {k} of {n} candidates have unknown/null {dim} — "
                f"pruning would silently hide them. Use --filter {dim}={value} (float) instead."
            )
    return None


# Preset lenses: {filter, spine, desc}. Each is a starting {filter, spine} plus a when-to-use note
# (``desc``) so a consumer knows which lens fits which hunting goal — the iron law + composite key
# ride under all of them. A convergence-transform ("close-the-gap") lens is deliberately deferred to
# a later phase; the value set stays open, so a new preset is one row here.
VIEWS: dict[str, dict[str, Any]] = {
    "default": {
        "filter": None,
        "spine": "impact",
        "desc": "Balanced starting lens: high-impact sinks first, controllability-certainty first "
        "within a tier. Use when you don't yet know where to look.",
    },
    "by-sink": {
        "filter": None,
        "spine": "by-sink",
        "desc": "Sweep one sink class systematically: use when walking every sink of a kind (e.g. "
        "read every system()/exec command sink). Controllable first within a class; constant junk "
        "sinks to the bottom.",
    },
    "nvram-source": {
        "filter": ("source", "nvram"),
        "spine": "impact",
        "desc": "Hunt nvram-mediated bugs — the router-bug hotspot. FLOATS nvram-source candidates "
        "to the first screen (web_settable becomes the most informative controllability signal); "
        "the corpus stays WHOLE — an unattributed source is unknown, never a proven non-nvram, so "
        "nothing is pruned (a wrapper-read key that resolves late must not be hidden now).",
    },
    "reachable-first": {
        "filter": ("reachability", "found"),
        "spine": "impact",
        "desc": "FLOATS candidates with a direct rootfs entry reference — a web-asset endpoint or "
        "a boot script naming the binary — to the first screen; the corpus stays WHOLE, nothing is "
        "pruned (renamed from 'reachable-only', which now aliases here). A MECHANISTIC reference, "
        "NOT call-graph reachability: an INCOMPLETE slice that misses candidates reachable only "
        "via an unmodeled service-dispatch bridge (notify_rc / rc_service), so do not read the "
        "top as 'all reachable candidates'. Split by kind with "
        "reachability=entry:web / entry:script.",
    },
}

# Deprecated view aliases: an old name resolves to its canonical preset so existing callers
# (--view / MCP view=) keep working without a hard break. reachable-only -> reachable-first, because
# after step 2.5 that lens FLOATS (never prunes), so "only" was a misnomer.
_VIEW_ALIASES: dict[str, str] = {"reachable-only": "reachable-first"}


def canonical_view(view: str | None) -> str | None:
    """Resolve a (possibly deprecated) view name to its canonical VIEWS key; passthrough
    otherwise."""
    return _VIEW_ALIASES.get(view, view) if view is not None else None


def _float_by_dimension(
    candidates: list[TriageCandidate], filters: list[tuple[str, str]]
) -> list[TriageCandidate]:
    """Circle-and-weight one or more ``--filter`` dimensions: candidates matching ALL of them (AND)
    FLOAT to the top band, but the corpus is NEVER reduced — every candidate stays listed (the
    triage iron law: re-rank, never reduce). A hard PARTITION, not a soft weight: matches sit in a
    distinct top band, non-matches below (so a high-impact non-match never sits above a matched
    row), with the demotion iron law still riding — a proven-safe candidate stays sunk even when it
    matches. Stable, so the lens order within each band is preserved."""

    def band(c: TriageCandidate) -> int:
        if _is_proven_safe(c):
            return 2  # proven-safe sinks in every lens, matched or not
        return 0 if all(_matches(c, d, v) for d, v in filters) else 1

    return sorted(candidates, key=band)


def filter_match_count(candidates: list[TriageCandidate], filters: list[tuple[str, str]]) -> int:
    """How many candidates match ALL of the given ``--filter`` (dim, value) pairs (AND) — a COUNT
    only, never a reduction. Lets a consumer annotate the lens header (matched M of the whole corpus
    N) while the corpus stays whole."""
    return sum(1 for c in candidates if all(_matches(c, d, v) for d, v in filters))


def reachability_match_count(candidates: list[TriageCandidate], values: list[str]) -> int:
    """Back-compat shim: reachability match count via the general ``filter_match_count``."""
    return filter_match_count(candidates, [("reachability", v) for v in values])


def apply_view(
    candidates: list[TriageCandidate],
    *,
    view: str | None = None,
    sort_by: str | None = None,
    dim_filters: list[tuple[str, str]] | None = None,
    only_filters: list[tuple[str, str]] | None = None,
    impact_overrides: dict[str, int] | None = None,
) -> list[TriageCandidate]:
    """Resolve a ``view`` preset (+ explicit ``sort_by`` / ``dim_filters`` / ``only_filters``) into
    a sorted lens. The demotion iron law rides regardless of the chosen spine — no lens buries a ?.

    Filter epistemology (the semantics follow the dimension, not a one-size predicate):
    - ``dim_filters`` (``--filter``) and a preset ``view``'s own filter are a circle-and-weight
      FLOAT: matches lift to the first screen but the corpus is NEVER reduced (re-rank, never
      reduce). This is the ONLY safe mode for optimistic dimensions, whose predicate can miss.
    - ``only_filters`` (``--only``) is the explicit prune: it reduces the view to the matching
      subset. Accepted ONLY on a reducible ground-truth dimension — validate with ``only_refusal``
      before calling (this function does not re-check; a caller that skips validation may prune an
      optimistic dimension and silently hide candidates)."""
    spine = "impact"
    float_filters: list[tuple[str, str]] = []
    view = canonical_view(view)  # resolve a deprecated alias (reachable-only -> reachable-first)
    if view and view in VIEWS:
        preset = VIEWS[view]
        spine = preset["spine"]
        if preset["filter"]:
            float_filters.append(preset["filter"])
    if sort_by:
        spine = sort_by
    if dim_filters:
        float_filters.extend(dim_filters)
    out = list(candidates)
    for d, val in only_filters or []:  # explicit prune (eligibility validated by the caller)
        out = filter_by_dimension(out, d, val)
    out = sort_candidates(out, spine=spine, impact_overrides=impact_overrides)
    if float_filters:
        out = _float_by_dimension(out, float_filters)
    return out


def triage(conn: sqlite3.Connection, *, run_id: str | None = None) -> list[TriageCandidate]:
    """Return the atlas candidate map — each candidate with its honest dimension layers — ordered by
    the DEFAULT lens: sink-impact spine, impact x controllability composite, only-up tertiary
    keys, and the demotion iron law (only a proven-safe fact sinks; a ? never sinks). Re-project
    with ``sort_candidates`` / ``apply_view``. Read-only; nothing is written back.

    run_id, if given, restricts to one firmware run (source_run_id); otherwise all runs.
    """
    sql = (
        "SELECT i.reachability_status, i.blocking_mechanism, i.exposure_shape, i.origin, "
        "i.source_anchor, i.sink_anchor, i.source_run_id, i.evidence_ref, i.binary_path, "
        "i.flow_evidence, p.source_class, p.sink_class, p.structural_fingerprint "
        "FROM instance i JOIN pattern p ON p.pattern_id = i.pattern_id"
    )
    params: list[str] = []
    if run_id is not None:
        sql += " WHERE i.source_run_id = ?"
        params.append(run_id)
    rows = conn.execute(sql, params).fetchall()
    # Compute the A2 thin-nvram-wrapper set ONCE per run (not per candidate) and thread it down —
    # the candidate-layer source attribution reuses it to recognise wrapper-read keys (M1).
    wrapper_names = _nvram_wrapper_names(conn)
    candidates = [_candidate(conn, r, wrapper_names) for r in rows]
    return sort_candidates(candidates, spine="impact")


# ── single-candidate explanation (the dimension layers; honest bounds; where to verify) ──
#
# This view presents every dimension layer's honest three-state annotation (state + value +
# source), the lens caveats, and where to verify by hand. There is NO score to decompose — the
# dimensions ARE the explanation. It does NOT declare a candidate real, does NOT claim
# cross-function reachability, and prints NO triggering input.


@dataclass(frozen=True)
class CandidateExplanation:
    """A read-only, single-candidate map view. A lead with stated bounds, never a verdict.

    ``dimensions`` carries every layer's honest three-state annotation; ``caveats`` states the
    phase-1 optimism/blind-spots. No score, no score breakdown — the layers are the fact."""

    candidate: TriageCandidate
    call_sequence_shape: str | None
    # Every map layer's honest annotation (state / value / source / note) — the explanation itself.
    dimensions: tuple[Dimension, ...]
    # The current lens label + the honest phase-1 caveats, surfaced so the explain view never reads
    # as complete (optimistic 'free', near-always-'?' filtering, no-reduction contract).
    lens_label: str
    caveats: tuple[str, ...]
    claims_does: tuple[str, ...]
    claims_does_not: tuple[str, ...]
    verify_steps: tuple[str, ...]
    # Signals promoted to the explain TOP LEVEL so a consumer reads them without descending into
    # ``candidate``: the coarse source class, the fine source_kind, the controllability annotation,
    # and the sink-impact class. ``controllability`` / ``sink_impact`` echo the BARE dimension value
    # (kept for back-compat with a consumer that reads the flat field); a bare ``free`` read alone
    # loses the ``likely`` state, so ``*_labeled`` carry the honest ``state:value`` (the full
    # state+value+note always lives in ``dimensions`` — these are a convenience echo, never a second
    # source of truth). Read the labeled sibling, or the dimension, for the certainty.
    source_class: str
    source_kind: str
    controllability: str
    sink_impact: str
    controllability_labeled: str
    sink_impact_labeled: str
    # Summary-first sink_arg_provenance (Ghidra def-use fact) at the explain TOP LEVEL: one compact
    # entry per command/format sink in this candidate's function (idx / kind / resolved /
    # nearest_dominating_writer). The full writer + fmt + vararg detail is fetched on demand with
    # ``get_sink_provenance`` so a many-sink candidate never overruns the token budget. A surfaced
    # fact only; nothing here feeds recall or a grade.
    sink_arg_provenance_summary: tuple[dict[str, Any], ...]


def _verify_steps(candidate: TriageCandidate) -> tuple[str, ...]:
    fn = candidate.function or "the function"
    ref = candidate.evidence_ref or "<evidence_ref>"
    sink = candidate.sink_anchor or "the sink"
    where = f" in {candidate.binary_path}" if candidate.binary_path else ""
    return (
        f"Open {fn}{where} ({ref}) in Ghidra and confirm whether the argument reaching {sink} "
        "comes from a truly externally-controllable input.",
        f"Trace callers: which functions call {fn}, and whether any passes controllable data in "
        "(cross-function flow is not done by the tool — verify by hand).",
        "Confirm the path is genuinely unsanitized (the tool's filter check is a generic name "
        "match and can miss a custom guard).",
    )


def explain_candidate(conn: sqlite3.Connection, evidence_ref: str) -> CandidateExplanation | None:
    """Return a single-candidate explanation for the instance with this evidence_ref, or None.

    Read-only. Presents every dimension layer's honest three-state annotation, the lens caveats,
    the honest claim bounds, and a manual-verification checklist. Returns None when no instance
    carries the given evidence_ref (the caller turns that into a friendly error).
    """
    rows = conn.execute(
        "SELECT i.reachability_status, i.blocking_mechanism, i.exposure_shape, i.origin, "
        "i.source_anchor, i.sink_anchor, i.source_run_id, i.evidence_ref, i.binary_path, "
        "i.flow_evidence, p.source_class, p.sink_class, p.call_sequence_shape, "
        "p.structural_fingerprint "
        "FROM instance i JOIN pattern p ON p.pattern_id = i.pattern_id "
        "WHERE i.evidence_ref = ? "
        "ORDER BY i.instance_id",
        (evidence_ref,),
    ).fetchall()
    if not rows:
        return None
    if len(rows) > 1:
        # evidence_ref is meant to anchor one instance (run + function + sink); a duplicate is
        # not expected. Defend deterministically: take the lowest instance_id, never a random one.
        logger.warning(
            "evidence_ref %s matched %d instances; using the lowest instance_id",
            evidence_ref,
            len(rows),
        )
    row = rows[0]

    candidate = _candidate(conn, row, _nvram_wrapper_names(conn))
    claims_does = (
        "present each dimension layer as an observed FACT about this candidate (controllability, "
        "source-writability, reachability, filtering, sink impact, writer, completeness) with its "
        "three-state, value, and source.",
    )
    claims_does_not = (
        "declare the candidate attackable, reachable, or real — every layer is a fact; the "
        "judgement is yours;",
        "trace cross-function flow (who calls this function is not followed here);",
        "prove safety on a '?' layer — a '?' is a coverage gap, never 'safe'.",
    )
    return CandidateExplanation(
        candidate=candidate,
        call_sequence_shape=row["call_sequence_shape"],
        dimensions=candidate.dimensions,
        lens_label=DEFAULT_LENS_LABEL,
        caveats=PHASE1_CAVEATS,
        claims_does=claims_does,
        claims_does_not=claims_does_not,
        verify_steps=_verify_steps(candidate),
        source_class=candidate.source_class,
        source_kind=candidate.source_kind,
        controllability=candidate.dim("controllability").value,
        sink_impact=candidate.dim("sink_impact").value,
        controllability_labeled=state_value_label(candidate.dim("controllability")),
        sink_impact_labeled=state_value_label(candidate.dim("sink_impact")),
        sink_arg_provenance_summary=_sink_provenance_summary(conn, _row_get(row, "flow_evidence")),
    )
