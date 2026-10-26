# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The short face of every MCP tool: one card per tool, and what is rendered from it.

A tool's docstring is its FULL reference — kept whole and served by get_tool_reference. What a
client is sent as the tool's description is short instead, rendered from the tool's card here: a
first line naming the parameters a call needs, the card's summary, and a pointer back to the full
reference. Clients cut long descriptions (and long server instructions) at a fixed length, so the
part a reader most needs has to come first and the whole of it has to fit.

A card is DOCUMENTATION. At run time it is used for exactly three things: rendering text (the
first line, get_tool_reference), naming what is still missing when a call carries an unknown
parameter, and telling whether a tool's own error was a usage error worth answering with a
minimal call. It never decides whether a call may run — every tool still checks its own
arguments, in its own order, with its own structured error.

A leaf: it imports nothing from the server, so the server and the tests can both read it.
"""

from __future__ import annotations

import difflib
from collections.abc import Collection, Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class WhenRule:
    """``param`` taking one of ``values`` (each listed, never a wildcard) also needs ``needs``."""

    param: str
    values: tuple[str, ...]
    needs: tuple[str, ...]


@dataclass(frozen=True)
class ToolCard:
    """One tool's short description and the call rules its first line states.

    ``required``: always needed. ``any_of``: at least one group must be given whole (empty = no
    such rule); ``exactly_one``: the groups exclude each other. ``truthy``: switches that count as
    given only when true. ``when``: a value of one parameter that needs others. ``aliases``: an old
    name -> its new name. ``tightened``: a parameter this server now refuses to go without, with
    why. ``example``: a minimal call. ``boundary``: phrases the short and the full description
    must both keep. ``note``: said in brackets at the end of the first line."""

    summary: str
    example: str
    required: tuple[str, ...] = ()
    any_of: tuple[tuple[str, ...], ...] = ()
    exactly_one: bool = False
    truthy: tuple[str, ...] = ()
    when: tuple[WhenRule, ...] = ()
    aliases: Mapping[str, str] = field(default_factory=dict)
    tightened: Mapping[str, str] = field(default_factory=dict)
    boundary: tuple[str, ...] = ()
    note: str | None = None


def is_given(value: Any) -> bool:
    """Whether a parameter value counts as given: anything but None, False and a blank string.

    By identity, so ``0`` is given (``offset=0``, ``sink_idx=0`` are real values). FastMCP fills
    every parameter with its default, and every parameter a card names defaults to None or False,
    so a default never reads as given."""
    return (
        value is not None
        and value is not False
        and not (isinstance(value, str) and not value.strip())
    )


def _group_text(group: tuple[str, ...], truthy: tuple[str, ...]) -> str:
    return " + ".join(f"{p}=true" if p in truthy else p for p in group)


def render_requires(card: ToolCard) -> str:
    """The first line of a tool's description: what a call needs, from the card's rules."""
    parts: list[str] = []
    if card.required:
        parts.append(", ".join(card.required))
    if card.any_of:
        groups = [_group_text(g, card.truthy) for g in card.any_of]
        if card.exactly_one:
            parts.append("exactly one of " + " / ".join(groups))
        elif card.required:
            parts.append("and " + ", or ".join(groups))
        else:
            parts.append(", or ".join(groups))
    for rule in card.when:
        parts.append(
            f"{rule.param}={'|'.join(rule.values)} also needs {_group_text(rule.needs, ())}"
        )
    body = "; ".join(parts) if parts else "none"
    if card.note:
        body += f" ({card.note})"
    return f"Required: {body}."


def reference_call(name: str) -> str:
    return f'get_tool_reference(name="{name}")'


def render_description(name: str, card: ToolCard) -> str:
    """What a client is sent as the tool's description: the first line, the summary, the pointer."""
    return f"{render_requires(card)}\n{card.summary}\nFull reference: {reference_call(name)}."


def _given_names(card: ToolCard, arguments: Mapping[str, Any]) -> set[str]:
    """The parameter names a call gave, an old name counting as its new one."""
    given = {k for k, v in arguments.items() if is_given(v)}
    for p in card.truthy:
        if arguments.get(p) is not True:
            given.discard(p)
    for old, new in card.aliases.items():
        if old in given:
            given.add(new)
    return given


def missing_parts(card: ToolCard, arguments: Mapping[str, Any]) -> list[str]:
    """What the card says this call still lacks, each as a short phrase (empty = nothing)."""
    given = _given_names(card, arguments)
    out = [p for p in card.required if p not in given]
    if card.any_of and not any(all(p in given for p in g) for g in card.any_of):
        out.append(" or ".join(_group_text(g, card.truthy) for g in card.any_of))
    for rule in card.when:
        if arguments.get(rule.param) in rule.values:
            lacking = [p for p in rule.needs if p not in given]
            if lacking:
                out.append(" + ".join(lacking) + f" (for {rule.param}={arguments[rule.param]})")
    return out


# ── unknown parameters: what a misspelled or borrowed name most likely meant ─────────────────


@dataclass(frozen=True)
class _Synonym:
    candidates: tuple[str, ...]
    only: frozenset[str] = frozenset()  # empty = every tool


def _syn(*candidates: str, only: Collection[str] = ()) -> _Synonym:
    return _Synonym(tuple(candidates), frozenset(only))


_DIFF_SCOPED = ("list_diffs", "list_diff_blindspots", "get_diff_sink_overlay")

# A name an agent passes by habit or by borrowing it from another tool -> the names it most likely
# meant, in order. Only the candidates the tool accepts (and the call did not already pass) are
# offered; an entry with ``only`` applies to those tools alone.
_PARAM_SYNONYMS: dict[str, tuple[_Synonym, ...]] = {
    **{k: (_syn("text", "value"),) for k in ("string", "str", "query")},
    "text": (_syn("value"),),
    "value": (_syn("text"),),
    **{k: (_syn("function", "from_function", "callee"),) for k in ("func", "function_name", "fn")},
    "function": (_syn("from_function", "callee"),),
    "addr": (_syn("function", "address"),),
    "address": (_syn("function"),),
    "name": (_syn("function"),),
    "binary": (_syn("target"),),
    "bin": (_syn("target", "binary"),),
    "run": (_syn("run_id"),),
    "run_name": (_syn("run_id"),),
    "run_a_id": (_syn("run_a"),),
    "run_b_id": (_syn("run_b"),),
    "run_a": (_syn("run_a_id"),),
    "run_b": (_syn("run_b_id"),),
    "run_id": (
        _syn(
            "run_a_id",
            "run_b_id",
            "run_pair",
            "diff_id",
            "run_a",
            "run_b",
            only=(*_DIFF_SCOPED, "get_file_diff", "annotate_diff", "annotate_diff_batch"),
        ),
    ),
    "run_pair": (_syn("run_a_id", "run_b_id", "diff_id", "run_a", "run_b", only=_DIFF_SCOPED),),
    "diff_id": (_syn("run_pair", only=("get_file_diff",)),),
    "pair": (_syn("run_pair"),),
    "runs": (_syn("run_pair"),),
    "ref": (_syn("evidence_ref", "anchor_ref", "candidate_anchor"),),
    "anchor": (_syn("anchor_ref", "candidate_anchor"),),
    "evidence_ref": (_syn("anchor_ref", only=("annotate_diff",)),),
    "anchor_ref": (_syn("entry_id", only=("promote",)),),
    "tool": (_syn("name"),),
    "tool_name": (_syn("name"),),
}

# Close spellings that are different parameters, so a near match must not be offered for them.
_CLOSE_MATCH_VETO = frozenset({("stride", "side"), ("side", "stride")})
_CLOSE_MATCH_CUTOFF = 0.8


def suggest(tool: str, wrong: str, accepted: Collection[str], passed: Collection[str]) -> list[str]:
    """The names ``wrong`` most likely meant on ``tool``: from the synonym table first, else one
    close spelling. A name the call already passed is never offered (it was not what was meant)."""
    pool = [a for a in accepted if a not in passed]
    for syn in _PARAM_SYNONYMS.get(wrong, ()):
        if syn.only and tool not in syn.only:
            continue
        hits = [c for c in syn.candidates if c in pool]
        if hits:
            return hits
    close = difflib.get_close_matches(wrong, pool, n=1, cutoff=_CLOSE_MATCH_CUTOFF)
    if close and (wrong, close[0]) not in _CLOSE_MATCH_VETO:
        return close
    return []


_ECHO_NAME_CHARS = 64
_ECHO_NAMES = 5


def _quote_list(names: list[str]) -> str:
    quoted = [repr(n) for n in names]
    if len(quoted) == 1:
        return quoted[0]
    return ", ".join(quoted[:-1]) + " or " + quoted[-1]


def unknown_param_message(
    tool: str,
    unknown: Collection[str],
    arguments: Mapping[str, Any],
    card: ToolCard,
    accepted: tuple[str, ...],
) -> str:
    """The refusal for a call that names parameters ``tool`` does not take. Names only — a value
    the call carried is never echoed back."""
    order = [k for k in arguments if k in unknown]
    shown = order[:_ECHO_NAMES]
    offered: list[str] = []
    items: list[str] = []
    for name in shown:
        hits = suggest(tool, name, accepted, arguments)
        offered.extend(h for h in hits if h not in offered)
        item = repr(name[:_ECHO_NAME_CHARS])
        if hits:
            item += f" — did you mean {_quote_list(hits)}?"
        items.append(item)
    rest = len(order) - len(shown)
    head = f"{tool}: unknown parameter{'s' if len(order) > 1 else ''} " + "; ".join(items)
    if rest:
        head += f"; and another {rest}"
    if not head.endswith("?"):
        head += "."
    lines = [head, f"Accepted parameters: {', '.join(accepted) or 'none'}.", render_requires(card)]
    # What is still missing once each offered name is read as given (it is what the call meant).
    as_meant = {k: v for k, v in arguments.items() if k not in unknown}
    as_meant.update(dict.fromkeys(offered, "<offered>"))
    missing = missing_parts(card, as_meant)
    if missing:
        lines.append(f"Also missing: {'; '.join(missing)}.")
    lines.append(f"Minimal call: {card.example}")
    lines.append(f"Full reference: {reference_call(tool)}.")
    return "\n".join(lines)


# ── the cards ────────────────────────────────────────────────────────────────────────────────

_RUN_OR_REF = (("run_id",), ("evidence_ref",))
_FN_LOOKUP = (("run_id", "function"), ("evidence_ref",))
_BIN_LOOKUP = (("run_id", "binary"), ("evidence_ref",))
_AMBIGUOUS = "``reason='ambiguous'``"
_TIGHT_BINARY = {
    "binary": "without binary (or an evidence_ref that supplies one) the answer was an "
    "empty not-found that read as a fact about the firmware"
}
_NO_BINARY = (
    "Without binary (or an evidence_ref that supplies one) it is an error naming the run, not an "
    "empty answer."
)
_SAFE_BASIS = WhenRule("verdict", ("safe",), ("block_source", "block_point", "block_why"))

TOOL_CARDS: dict[str, ToolCard] = {
    "list_candidates": ToolCard(
        required=("run_id",),
        example='list_candidates(run_id="<run_id>")',
        boundary=(
            "there is NO collapsed score",
            "a '?' never sinks",
            "A dimension NOT shown on a row is state=unknown (a coverage gap, NOT proven safe)",
            "DERIVED facts, NOT a verdict",
        ),
        summary=(
            "One firmware's map of recall candidates, each with a three-state annotation on every "
            "dimension layer — there is NO collapsed score. The default lens spines on sink-impact "
            "and sinks only provably-safe candidates; a '?' never sinks. Switch the lens with "
            'sort_by, view (presets, listed in available_views), filters ("dim=value,...": '
            "matches float, the corpus is never reduced), only (prune to a sink_class / "
            "sink_impact sweep) and impact_order; overlay=true re-ranks by your own annotations. "
            "Paged by limit / offset and by response size (next_offset resumes). Rows are compact: "
            "A dimension NOT shown on a row is state=unknown (a coverage gap, NOT proven safe) — "
            "explain_candidate gives the full note. DERIVED facts, NOT a verdict."
        ),
    ),
    "list_runs": ToolCard(
        example="list_runs()",
        boundary=("differing build_hash for the same firmware means a STALE scan",),
        summary=(
            "Every firmware run (scan) in this atlas with its lineage: scan_status, build_hash, "
            "scanned_at, counts and resolved. A differing build_hash for the same firmware means a "
            "STALE scan. Pick a run_id for the fact tools here."
        ),
    ),
    "explain_candidate": ToolCard(
        required=("evidence_ref",),
        example='explain_candidate(evidence_ref="<evidence_ref>")',
        boundary=("no score", "(no fabrication)"),
        summary=(
            "One candidate in full: every dimension layer's three-state annotation, the lens "
            "caveats, the claim bounds and where to verify — no score. "
            "sink_arg_provenance_summary says where each sink argument's value comes from. A ref "
            "no instance carries returns a not-found record (no fabrication). Echoes "
            "resolved_run + run_lineage, and coverage says whether a conclusion has been recorded."
        ),
    ),
    "get_sink_provenance": ToolCard(
        required=("evidence_ref",),
        example='get_sink_provenance(evidence_ref="<evidence_ref>")',
        boundary=("never a verdict, and an unreachable origin is stated",),
        summary=(
            "The full sink-argument def-use record behind explain_candidate's summary: per sink "
            "the writer set (dominating first, nearest_dominating_writer), each writer's format "
            "string and vararg sources, getter const_args, plus a source_origin companion. Omit "
            "sink_idx for every sink of the function, pass one for one sink; dominating_only keeps "
            "only the dominating writers. A Ghidra def-use FACT — never a verdict, and an "
            "unreachable origin is stated (resolved: false), never dropped."
        ),
    ),
    "get_nvram_key_flow": ToolCard(
        required=("key",),
        example='get_nvram_key_flow(key="<nvram_key>")',
        boundary=("never an exact connection", 'never read an empty result as "unused"'),
        summary=(
            "Who WRITES and who READS one nvram key across binaries: writers / readers are exact "
            "constant-key matches (a writer carries value_source), template_matches the "
            "parametric templates the key satisfies (e.g. wl%d_ssid) — a possible match, never an "
            "exact connection. completeness is may_be_incomplete when unresolved-key operations "
            'exist: never read an empty result as "unused". run_id narrows to one firmware; '
            "without it every scanned firmware is spanned and each row names its run."
        ),
    ),
    "get_string_keyed_edges": ToolCard(
        example='get_string_keyed_edges(run_id="<run_id>")',
        boundary=(
            "These are ENUMERATED FACTS, NOT a reachability verdict",
            "Empty is NOT proof of unreachability",
        ),
        summary=(
            "String-keyed dispatch edges: a string key that gates or dispatches to a callee (a "
            'same-variable strcmp ladder, or a {string, func_ptr} table) — "what does key X '
            'reach?", "is function Y reached through one?". Filter by key, callee, '
            "from_function, binary, run_id; each edge carries the callee anchor, ladder_size / "
            "table_addr and a completeness. These are ENUMERATED FACTS, NOT a reachability "
            "verdict. Empty is NOT proof of unreachability."
        ),
    ),
    "launched_by": ToolCard(
        required=("target",),
        example='launched_by(target="<binary_short_name>")',
        boundary=(
            "These are ENUMERATED FACTS, NOT a reachability verdict",
            "An EMPTY result is NOT proof that nothing launches the binary",
        ),
        summary=(
            "Which binaries' code launches target (a binary's short name, or a script path under "
            'the firmware root) — the cross-binary "A execs B" edge. Each edge carries the '
            "launcher (binary + function + address), the API, whether a shell wraps it and the "
            "command template; target_layer says exec_image or shell_command. run_id stays inside "
            "one firmware. These are ENUMERATED FACTS, NOT a reachability verdict. An EMPTY result "
            "is NOT proof that nothing launches the binary: read exec_argv_status."
        ),
    ),
    "start_diff_review": ToolCard(
        required=("diff_id",),
        example='start_diff_review(diff_id="<run_a>::<run_b>::<binary>")',
        boundary=("START HERE for one diff", "nothing computed of its own"),
        summary=(
            "START HERE for one diff: the entries to read first and the calls to read and judge "
            "them, composed from get_diff_patch_view and get_diff_meta, nothing computed of its "
            "own. diff_id = {run_a}::{run_b}::{binary} (list_diffs gives the ids). Returns "
            "workflow, meta, headline (the first entry in full), view (a summary page of up to "
            "limit entries, cut to fit beside the rest), read_next and non_binary. A diff with a "
            "proven-stale side is refused."
        ),
    ),
    "get_diff_patch_view": ToolCard(
        required=("diff_id",),
        example='get_diff_patch_view(diff_id="<diff_id>", detail="summary")',
        boundary=(
            "evidence, never a verdict or a score",
            'A withheld hunk is never "no change"',
            'absent is not "no sink changed"',
            "A differing list is NOT proof a call was made or dropped",
        ),
        summary=(
            "One diff's function-level view: an entry per function pair that changed, sorted into "
            "buckets (A, B, R = undetermined pair, C, P = no counterpart, E = caller-set edge), "
            "plus a blind_spots ledger — evidence, never a verdict or a score. Default order: "
            "significance; also sort_by, the bucket / subclass / tier / blind_spot filters and "
            "limit / offset (follow next_offset). rows_limit=0 scans every entry with its summary "
            "and inline_hunk; detail='summary' gives counts only; entry_id (+ rows_offset) reads "
            "one entry in full. pseudocode_sameness, pseudocode_delta and inline_hunk show what "
            'changed; A withheld hunk is never "no change". callee_set: A differing list is NOT '
            'proof a call was made or dropped. sink_callee_swap: absent is not "no sink '
            'changed". Every entry carries anchor_ref + review_state for annotate_diff.'
        ),
    ),
    "get_diff_deltas": ToolCard(
        required=("diff_id",),
        example='get_diff_deltas(diff_id="<diff_id>")',
        boundary=(
            "NOT a change/quality verdict",
            "is NOT 'unchanged'",
            "An EMPTY result is NOT 'no changes'",
        ),
        summary=(
            "The tri-state dimension deltas one diff produced; filter by binary, dimension, "
            "delta_kind, page with limit / offset. A delta is a PROJECTION of two annotations, NOT "
            "a change/quality verdict; delta_undetermined is NOT 'unchanged' — read its "
            "undetermined_reason. An EMPTY result is NOT 'no changes': get_diff_capabilities says "
            "which dimensions this diff can delta. verbose=true adds the note and legend."
        ),
    ),
    "get_diff_sink_overlay": ToolCard(
        any_of=(("diff_id",), ("run_a", "run_b")),
        exactly_one=True,
        example='get_diff_sink_overlay(diff_id="<diff_id>")',
        boundary=(
            "EVIDENCE ONLY, never a fix-status verdict",
            "No row ever says a call is gone or new",
            "``presence_undetermined`` is NOT 'unchanged'",
        ),
        summary=(
            "Candidate-level sink overlay: the A and B sink candidates lined up, each row with a "
            "presence — persisted or presence_undetermined, with its presence_reason. EVIDENCE "
            "ONLY, never a fix-status verdict. No row ever says a call is gone or new; "
            "``presence_undetermined`` is NOT 'unchanged'. Scope: diff_id, or run_a + run_b (every "
            "diff of the pair plus the candidates no diff covers; slow). detail='summary' gives "
            "counts, detail='rows' a page (limit / offset); filter by binary, sink_class, "
            "presence, reason, side (a_only / b_only / both), min_alignment_confidence. coverage "
            "says whether every candidate is represented."
        ),
    ),
    "same_shape_siblings": ToolCard(
        required=("diff_id",),
        any_of=(("evidence_ref",), ("candidate_anchor",)),
        exactly_one=True,
        example='same_shape_siblings(diff_id="<diff_id>", evidence_ref="<evidence_ref>")',
        boundary=(
            "counts, never a verdict",
            "a member that could not be read is never counted as not listed",
        ),
        summary=(
            "For one sink call of a diff (evidence_ref, or candidate_anchor): the other calls of "
            "the same shape in the same binary on the same side, and where each landed in this "
            "diff — counts, never a verdict. The group carries group_ref (pass it to annotate_diff "
            "when a judgement leaned on the group), shape, member_count, by_landing and "
            "states_unreadable: a member that could not be read is never counted as not listed. "
            "sibling_set_bounds names what can make the group look smaller; members_offset pages "
            "the members."
        ),
    ),
    "get_diff_meta": ToolCard(
        required=("diff_id",),
        example='get_diff_meta(diff_id="<diff_id>")',
        boundary=(
            "do not read it as 'no change'",
            "NOT 'noise'",
            "is a BLIND SPOT, never 'no change'",
        ),
        summary=(
            "The meta facts of one diff: binary scope, tool versions, alignment and presence "
            "counts, and functions split by the view's own facts (unchanged / changed / "
            "unverified / no_body / alignment_undetermined / one_sided). version_skew=1: every "
            "delta is version_skew undetermined — do not read it as 'no change'. "
            "changed.no_scoped_signal is NOT 'noise'. diff_ok=0: the binary did not diff, and an "
            "empty get_diff_deltas for it is a BLIND SPOT, never 'no change'. Also banners, "
            "source_stale and the run pair's non_binary counts."
        ),
    ),
    "get_function_alignment": ToolCard(
        required=("diff_id", "function"),
        aliases={"addr": "function"},
        note="addr is its old name, accepted for this version",
        example='get_function_alignment(diff_id="<diff_id>", function="<name_or_address>")',
        boundary=(
            "Returns an ALIGNMENT FACT, never a verdict",
            "No match here is NOT proof the function was added or removed",
            "listing every candidate, never one picked",
        ),
        summary=(
            "The BinDiff-aligned counterpart of one function in a diff: function takes a name or "
            "an address in any form; side='a' resolves an A-side function to its B-side match, "
            "side='b' the reverse. Returns an ALIGNMENT FACT, never a verdict: "
            "alignment_confidence (trust in the pairing) and similarity (how much the pair "
            "differs). A name matching several functions on a side (an import stub and its body) "
            "returns reason='ambiguous' listing every candidate, never one picked. No match here "
            "is NOT proof the function was added or removed; presence lists the side's unmatched "
            "functions. addr is the old name of function (accepted for this version; it adds "
            "param_renamed)."
        ),
    ),
    "get_diff_capabilities": ToolCard(
        required=("diff_id",),
        example='get_diff_capabilities(diff_id="<diff_id>")',
        boundary=(
            "is an EXPLICIT non-judgement",
            "which is NOT the same as 'nothing changed'",
        ),
        summary=(
            "Per-dimension capability state of one diff: which dimensions each side could analyse "
            "(state_a / state_b) and whether the diff can delta them. delta_supported=0 is an "
            "EXPLICIT non-judgement: the dimension is visible but this diff produces no "
            "per-subject delta for it. Read it beside an empty get_diff_deltas — 'this diff does "
            "not delta that dimension', which is NOT the same as 'nothing changed'."
        ),
    ),
    "list_diffs": ToolCard(
        example='list_diffs(run_a_id="<run_a>", run_b_id="<run_b>")',
        boundary=(
            "Similarity 1 is NOT 'unchanged'",
            "not 'nothing changed'",
            "row is a BLIND SPOT",
        ),
        summary=(
            "The version diffs in the atlas, one row per binary diffed between two runs (filter by "
            "run_a_id / run_b_id, the before / after roles): matched_pairs, version_skew, "
            "functions counts and diff status; with both run ids, coverage names what no diff of "
            "the pair sees. Similarity 1 is NOT 'unchanged' (BinDiff is blind to constants and "
            "buffer sizes). An EMPTY list means no diff has been run for that filter, not 'nothing "
            "changed'. A diff_ok=0 row is a BLIND SPOT with no counts. source_stale says whether a "
            "diff is current."
        ),
    ),
    "list_diff_blindspots": ToolCard(
        example='list_diff_blindspots(run_a_id="<run_a>", run_b_id="<run_b>")',
        boundary=("UNKNOWN is not SAFE", "never proof the binary is undiffable"),
        summary=(
            "The binaries a full diff could NOT analyse between two runs (diff_ok=0), each with "
            "diff_status_reason, diff_attempts, suspected_hard and source_stale; plus partial — "
            "diffs that succeeded but whose export could not hold some functions as they are. "
            "UNKNOWN is not SAFE: a binary missing from the deltas may have failed to diff. "
            "suspected_hard is a hint, never proof the binary is undiffable. run_a_id / run_b_id "
            "are the before / after roles."
        ),
    ),
    "get_file_diff": ToolCard(
        required=("run_pair",),
        example='get_file_diff(run_pair="<run_a>::<run_b>")',
        boundary=(
            "not proof it was created or deleted",
            "Credential material and a sensitive config value are never given",
            "that sha256 is also the material's",
        ),
        summary=(
            "The non-binary files of two runs (run_pair = {run_a}::{run_b}, any two runs from "
            "list_runs) compared by path: scripts, configs, credentials, web assets. change: "
            "a_only / b_only (recorded on one side only — not proof it was created or deleted), "
            "content_differs, same, undetermined. A page lists the differing files (filter kind / "
            "change) with their structured row differences and hunk_stats; path reads one file "
            "(offset pages its lists, hunk_offset its line difference); detail='summary' gives "
            "counts. Credential material and a sensitive config value are never given; every file "
            "carries its file-level sha256, and for a file whose whole content is one credential "
            "that sha256 is also the material's. Judge a file with annotate_diff(anchor_ref, ..., "
            "run_pair=...)."
        ),
    ),
    "cross_firmware_patterns": ToolCard(
        example="cross_firmware_patterns()",
        boundary=("DERIVED, NOT a verdict",),
        summary=(
            "Per-pattern recurrence across the atlas: device_spread (the distinct firmware runs a "
            "pattern appears in) and pattern_breadth (distinct fine fingerprints); a candidate "
            "whose pattern recurs across many firmware images is worth reviewing sooner. Instances "
            "from stock binaries count too. Paged by limit / offset. DERIVED, NOT a verdict."
        ),
    ),
    "pattern_density": ToolCard(
        example="pattern_density()",
        boundary=("DERIVED counts only, NOT a verdict",),
        summary=(
            "Candidate-instance density per (run, sink_class, fingerprint); a count that differs "
            "for the same fingerprint across runs is an early recurrence signal. Paged by limit / "
            "offset. DERIVED counts only, NOT a verdict."
        ),
    ),
    "get_pseudocode": ToolCard(
        any_of=_FN_LOOKUP,
        example='get_pseudocode(run_id="<run_id>", function="<name_or_address>")',
        boundary=(
            "the segments joined in order are the text exactly",
            "An empty text comes with ``pseudocode_status``",
            _AMBIGUOUS,
        ),
        summary=(
            "Decompiler pseudocode of one function (function = a name or an address in any form), "
            "the default read view. binary is a selector (sha256 or a >=8-hex prefix, full path or "
            f"short name); a short name naming several binaries returns {_AMBIGUOUS} with each "
            "candidate — an answer, not an error. Paged by line (offset = paging.next_offset); the "
            "segments joined in order are the text exactly. An empty text comes with "
            "``pseudocode_status`` (skipped_micro inlines the disassembly). A miss says whether "
            "the function lives in another run."
        ),
    ),
    "get_callees": ToolCard(
        any_of=_FN_LOOKUP,
        example='get_callees(run_id="<run_id>", function="<name_or_address>")',
        boundary=(_AMBIGUOUS,),
        summary=(
            "Direct callee names of one function (a name or an address), intra-binary edges "
            "flagged resolved to follow. binary is a selector; a short name naming several "
            f"binaries returns {_AMBIGUOUS} with each candidate. When function resolves, its "
            "binary is used."
        ),
    ),
    "get_xrefs": ToolCard(
        any_of=_FN_LOOKUP,
        example='get_xrefs(run_id="<run_id>", function="<name_or_address>")',
        boundary=(
            "NEVER proof F is dispatched/reachable",
            "A stored value, not proof of a call",
            _AMBIGUOUS,
        ),
        summary=(
            "Cross-reference edges of one function F: direction='callers' / 'callees' "
            "(cross-binary edges included) or 'address_taken' (where F's entry address is stored "
            "as data — a dispatch-table slot or a literal pool — and which function took it): a "
            "FACT, NEVER proof F is dispatched/reachable. An empty caller set may mean an indirect "
            "call; entry_words then lists the data words that hold the entry value, and next "
            "names a get_data_table call. A stored value, not proof of a call. A short binary name "
            f"naming several binaries returns {_AMBIGUOUS}."
        ),
    ),
    "get_strings": ToolCard(
        any_of=(("run_id", "binary"), ("run_id", "value"), ("evidence_ref",)),
        tightened={
            "binary": "with neither binary nor value (and no evidence_ref that supplies a "
            "binary) the answer was an empty not-found"
        },
        example='get_strings(run_id="<run_id>", binary="<binary>")',
        boundary=(
            "``function`` does NOT scope the results",
            "a string NOT found there is NOT proven absent",
            _AMBIGUOUS,
        ),
        summary=(
            "Recorded strings of one binary, or searched by value (substring) across the run with "
            "each hit's address and binary. ``function`` does NOT scope the results (there is no "
            "string-to-function index). Paged losslessly by byte size (offset = "
            "paging.next_offset). A binary's string export is capped: truncated / "
            "search_may_be_incomplete say so, and a string NOT found there is NOT proven absent. "
            "Without binary or value it is an error naming the run. A short binary name naming "
            f"several binaries returns {_AMBIGUOUS}."
        ),
    ),
    "get_functions_referencing_string": ToolCard(
        required=("text",),
        any_of=_RUN_OR_REF,
        example='get_functions_referencing_string(text="<string>", run_id="<run_id>")',
        boundary=("a TEXT match, not a resolved symbol reference", _AMBIGUOUS),
        summary=(
            "Which functions' pseudocode TEXT contains a string (substring); binary narrows the "
            "scan. Capped (truncated). HONEST BOUND: a TEXT match, not a resolved symbol reference "
            "— it may sit in a comment or an unrelated literal; confirm each hit. "
            "get_string_reference_anchors is the parsed sibling. A short binary name naming "
            f"several binaries returns {_AMBIGUOUS}."
        ),
    ),
    "get_string_reference_anchors": ToolCard(
        required=("text",),
        any_of=_RUN_OR_REF,
        example='get_string_reference_anchors(text="<exact_string>", run_id="<run_id>")',
        boundary=(
            "matches the string value EXACTLY",
            'NOT "this string is unreferenced"',
            _AMBIGUOUS,
        ),
        summary=(
            "Where a string is referenced by RESOLVED Ghidra data references — the parsed sibling "
            "of get_functions_referencing_string: no comment noise, but only defined strings and "
            "recovered references, and text matches the string value EXACTLY (find the literal "
            "with get_strings(value=...) first). Each anchor: ref_at, ref_in_func, "
            'ref_in_func_addr, segment. no_resolved_dataref is NOT "this string is '
            'unreferenced"; string_refs_not_exported is unknown. A short binary name naming '
            f"several binaries returns {_AMBIGUOUS}."
        ),
    ),
    "get_imports_exports": ToolCard(
        any_of=_BIN_LOOKUP,
        tightened=_TIGHT_BINARY,
        example='get_imports_exports(run_id="<run_id>", binary="<binary>")',
        boundary=(_AMBIGUOUS,),
        summary=(
            "Import and export symbol tables of one binary (the cross-binary edge endpoints). "
            "binary is a selector (sha256 or a >=8-hex prefix, full path or short name); a short "
            f"name naming several binaries returns {_AMBIGUOUS} listing each. {_NO_BINARY}"
        ),
    ),
    "get_data_bytes": ToolCard(
        required=("address",),
        any_of=_BIN_LOOKUP,
        tightened=_TIGHT_BINARY,
        example='get_data_bytes(address="0x<hex>", run_id="<run_id>", binary="<binary>")',
        boundary=(
            "BYTES ONLY — no interpretation travels with them",
            'none of them means "the bytes are zero"',
            "possibly INSTRUCTIONS",
            _AMBIGUOUS,
        ),
        summary=(
            "The RAW bytes a data segment stores at address (hex, any form Ghidra shows; length "
            "bytes) — what a bare DAT_ name hides. BYTES ONLY — no interpretation travels with "
            "them; ascii is a mechanical rendering. The misses (uninitialized_bss, "
            "address_not_in_any_data_block, data_blocks_not_exported) differ on purpose and none "
            'of them means "the bytes are zero". bytes_from_executable_segment: treat the run as '
            f"possibly INSTRUCTIONS until confirmed data. {_NO_BINARY} A short binary name naming "
            f"several binaries returns {_AMBIGUOUS}."
        ),
    ),
    "get_data_table": ToolCard(
        required=("address",),
        any_of=_BIN_LOOKUP,
        tightened=_TIGHT_BINARY,
        example='get_data_table(address="0x<hex>", run_id="<run_id>", binary="<binary>")',
        boundary=("RECORDS BY ENTRY-WORD SPACING, not a declared layout", _AMBIGUOUS),
        summary=(
            "The records of a data table around address, cut by the spacing of the words that "
            "hold a function's entry address — where get_xrefs' entry_words.next points. stride / "
            "field_offset (an int or a hex string) override the inferred ones; paged by record "
            "(limit / offset, follow next_offset). RECORDS BY ENTRY-WORD SPACING, not a declared "
            f"layout: how the code uses a slot is yours to trace. {_NO_BINARY} A short binary "
            f"name naming several binaries returns {_AMBIGUOUS}."
        ),
    ),
    "get_script_callsites": ToolCard(
        any_of=_BIN_LOOKUP,
        tightened=_TIGHT_BINARY,
        example='get_script_callsites(run_id="<run_id>", binary="<binary>")',
        boundary=("entry-reach evidence",),
        summary=(
            "Rootfs scripts that invoke one binary — entry-reach evidence (script + line + args), "
            "paged by offset. Each site's via says where the command came from (literal / "
            "function_arg / variable / inline) and via_line the line it was derived from; via is "
            f"a mechanical provenance label, not a reachability verdict. {_NO_BINARY}"
        ),
    ),
    "get_disassembly": ToolCard(
        any_of=_FN_LOOKUP,
        example='get_disassembly(run_id="<run_id>", function="<name_or_address>")',
        boundary=("never zeroed", _AMBIGUOUS),
        summary=(
            "The disassembly listing Ghidra produced for one function (addresses line up with the "
            "pseudocode), paged by offset, or available: false with its reason (an older scan, or "
            "the listing export failed). Each instruction carries its bytes from the stored "
            "segments; where none covers it the bytes are null with a reason, never zeroed. A "
            f"short binary name naming several binaries returns {_AMBIGUOUS}."
        ),
    ),
    "annotate": ToolCard(
        required=("evidence_ref", "verdict", "rationale"),
        when=(_SAFE_BASIS,),
        example=(
            'annotate(evidence_ref="<evidence_ref>", verdict="suspicious", '
            'rationale="<why + next step + confidence>")'
        ),
        boundary=(
            "This is YOUR decision, not a tool fact",
            "re-annotating OVERWRITES",
            "worth keeping past THIS session",
        ),
        summary=(
            "Record YOUR OWN judgement on one candidate onto the overlay; the base map is "
            "unchanged. This is YOUR decision, not a tool fact. verdict: inconclusive, suspicious "
            "(floats), excluded (sinks), safe (sinks; needs block_source + block_point + "
            "block_why) or exploitable (floats above suspicious; chain + verification_gaps "
            "recommended). rationale: why + next step + confidence. Call it for a conclusion worth "
            "keeping past THIS session, not on every read. One annotation per candidate: "
            "re-annotating OVERWRITES."
        ),
    ),
    "annotate_diff": ToolCard(
        required=("anchor_ref", "verdict"),
        any_of=(("diff_id",), ("run_pair",)),
        exactly_one=True,
        when=(
            WhenRule("verdict", ("no_real_change",), ("why_unchanged", "checked")),
            WhenRule("verdict", ("changed_real", "change_inconclusive"), ("rationale",)),
        ),
        example=(
            'annotate_diff(anchor_ref="<anchor_ref>", verdict="change_inconclusive", '
            'rationale="<why + next step>", diff_id="<diff_id>")'
        ),
        boundary=(
            "never a blind write",
            "Plain-text notes are kept but do not count",
            "re-annotating OVERWRITES",
        ),
        summary=(
            "Record YOUR OWN judgement on one diff entry (get_diff_patch_view) or one non-binary "
            "file (get_file_diff): did this change do something real. anchor_ref must name "
            "something the view lists now — never a blind write. verdict: changed_real (may carry "
            "evidence), no_real_change (why_unchanged + checked, at least one anchor read in the "
            "current view; Plain-text notes are kept but do not count) or change_inconclusive. "
            "rationale is required except for no_real_change (it defaults to why_unchanged). "
            "group_ref records a same-shape group the judgement leaned on. One judgement per "
            "anchor: re-annotating OVERWRITES. Many entries at once: annotate_diff_batch."
        ),
    ),
    "annotate_diff_batch": ToolCard(
        required=("annotations",),
        any_of=(("diff_id",), ("run_pair",)),
        exactly_one=True,
        example=(
            'annotate_diff_batch(annotations=[{"anchor_ref": "<anchor_ref>", '
            '"verdict": "change_inconclusive", "rationale": "<why>"}], diff_id="<diff_id>")'
        ),
        boundary=("all of them or none", "Only those seven keys"),
        summary=(
            "Record YOUR judgements on many entries of one diff at once — all of them or none. "
            "annotations is 1..200 objects with annotate_diff's per-entry fields and no diff_id: "
            "anchor_ref + verdict, optionally rationale, checked, why_unchanged, evidence, "
            "group_ref. Only those seven keys — a stray key fails that item. Every item is "
            "validated first; if any fails nothing is written and the failures come back merged "
            "by message with their indexes. The same anchor_ref twice refuses the batch."
        ),
    ),
    "promote": ToolCard(
        required=("diff_id", "entry_id", "row_ref", "verdict", "rationale"),
        when=(
            _SAFE_BASIS,
            WhenRule("verdict", ("exploitable",), ("chain", "verification_gaps")),
        ),
        example=(
            'promote(diff_id="<diff_id>", entry_id="<entry_id>", row_ref="<a_ref>", '
            'verdict="suspicious", rationale="<why>")'
        ),
        boundary=(
            "Refused, with the facts that refused it",
            "it reads ``source_diff_stale`` there",
        ),
        summary=(
            "Carry a judgement reached on a diff entry onto ONE of its candidates, as that "
            "candidate's own annotation: entry_id (the entry's entry_id or anchor_ref), row_ref "
            "(a row's a_ref or b_ref); verdict, rationale and the basis fields are annotate's, and "
            "exploitable needs chain + verification_gaps here. Refused, with the facts that "
            "refused it, unless the row lands A, persisted or P unmatched_analysis_complete, the "
            "counterpart is determined and the diff is current (allow_stale_source overrides, and "
            "is recorded). The annotation carries promoted_from; once that diff is no longer "
            "current, it reads ``source_diff_stale`` there."
        ),
    ),
    "list_overlays": ToolCard(
        example='list_overlays(run_id="<run_id>")',
        boundary=(
            "These are AGENT decisions on the overlay, not tool facts",
            "never a clean bill",
            "Stale rows are surfaced, never dropped",
        ),
        summary=(
            "Your overlay annotations — the resume view — filtered by verdict and run_id (both "
            "AND together). Each row carries its live basis_state: unchanged, changed (re-review; "
            "the delta names what moved), unverifiable (an honest can't-say, never a clean bill) "
            "or anchor_unresolved; a promoted one carries promoted_from. Stale rows are surfaced, "
            "never dropped. These are AGENT decisions on the overlay, not tool facts. "
            "anchor_kind='diff_subject' lists your diff judgements instead (run_id is then a run "
            "pair, with review_progress)."
        ),
    ),
    "clear_overlay": ToolCard(
        any_of=(("run_id",), ("evidence_ref",), ("anchor_ref",), ("clear_all",)),
        truthy=("clear_all",),
        example='clear_overlay(evidence_ref="<evidence_ref>")',
        boundary=("The base map is untouched", "it cannot be undone"),
        summary=(
            "Delete overlay annotations and report how many went. The base map is untouched. Pass "
            "ONE scope: run_id (one firmware), evidence_ref (one candidate) or, with "
            "anchor_kind='diff_subject', anchor_ref (one diff judgement; run_id is then a run "
            "pair). No scope deletes nothing unless clear_all=true, which wipes every annotation "
            "of that kind — it cannot be undone."
        ),
    ),
    "list_verified_exploits": ToolCard(
        example="list_verified_exploits()",
        boundary=("WITHHELD unless reveal=True", "on reveal it rides your own care"),
        summary=(
            "The private exploit records a person wrote: distinct_exploits and records, each with "
            "its pattern and a has_exploit_evidence flag. The full exploit_note is WITHHELD unless "
            "reveal=True; reveal=True is a discipline path, not a protected one — on reveal it "
            "rides your own care."
        ),
    ),
    "legal_notice": ToolCard(
        example="legal_notice()",
        summary="The tool's intended-use / legal notice.",
    ),
    "get_tool_reference": ToolCard(
        example='get_tool_reference(name="get_diff_patch_view")',
        boundary=("nothing in it can be out of date",),
        summary=(
            "This server's own reference. name=<tool>: that tool's full description, its required "
            "parameters (as the first line and as rules), a minimal call and every parameter; "
            "name='guide': the full working guide; name='parameters': the parameter-name table; "
            "no name: every tool with its required parameters. It reads only this server's own "
            "constants, so nothing in it can be out of date."
        ),
    ),
}


# ── parameter names: what each means and where it differs between tools ──────────────────────


def _param(
    name: str, meaning: str, used_in: tuple[str, ...], verdict: str, reason: str | None = None
) -> dict[str, Any]:
    row: dict[str, Any] = {"name": name, "meaning": meaning, "used_in": list(used_in)}
    row["conclusion"] = verdict
    if reason is not None:
        row["reason"] = reason
    return row


_FN_READERS = ("get_pseudocode", "get_callees", "get_xrefs", "get_strings", "get_disassembly")
_BINARY_READERS = (
    "get_pseudocode",
    "get_callees",
    "get_xrefs",
    "get_strings",
    "get_functions_referencing_string",
    "get_string_reference_anchors",
    "get_imports_exports",
    "get_data_bytes",
    "get_data_table",
    "get_script_callsites",
    "get_disassembly",
)
_DIFF_TOOLS = (
    "start_diff_review",
    "get_diff_patch_view",
    "get_diff_deltas",
    "get_diff_sink_overlay",
    "same_shape_siblings",
    "get_diff_meta",
    "get_function_alignment",
    "get_diff_capabilities",
    "annotate_diff",
    "annotate_diff_batch",
    "promote",
)
_BASIS = ("annotate", "promote")
_CONSISTENT = "consistent"
_KEPT = "kept"
_DISTINCT = "distinct"
_SINGLE = "single tool"

# Every parameter of every tool. ``conclusion``: consistent (one meaning everywhere), distinct (a
# different name for a different thing), kept (a known difference left as it is, with the reason),
# single tool, or new.
PARAMETER_NAMES: list[dict[str, Any]] = [
    _param(
        "run_id",
        "one run's id (from list_runs)",
        (
            "list_candidates",
            "get_nvram_key_flow",
            "get_string_keyed_edges",
            "launched_by",
            *_BINARY_READERS,
            "list_overlays",
            "clear_overlay",
        ),
        _KEPT,
        "with anchor_kind='diff_subject', list_overlays and clear_overlay take a run pair "
        "({run_a}::{run_b}) in run_id; their descriptions say so, and parameters are not renamed",
    ),
    _param(
        "evidence_ref",
        "a candidate's anchor; resolves its run, binary and function by itself",
        (
            "explain_candidate",
            "get_sink_provenance",
            "same_shape_siblings",
            *_BINARY_READERS,
            "annotate",
            "clear_overlay",
        ),
        _CONSISTENT,
    ),
    _param(
        "binary",
        "a binary selector: sha256, a >=8-hex prefix, a full path or a short name",
        ("get_string_keyed_edges", "get_diff_deltas", "get_diff_sink_overlay", *_BINARY_READERS),
        _CONSISTENT,
    ),
    _param(
        "function",
        "a function's name or address, in any form",
        (*_FN_READERS, "get_function_alignment"),
        _CONSISTENT,
    ),
    _param(
        "addr",
        "the old name of function",
        ("get_function_alignment",),
        _KEPT,
        "accepted for this version only, so a call written for the old name keeps working",
    ),
    _param(
        "text",
        "the string to look for",
        ("get_functions_referencing_string", "get_string_reference_anchors"),
        _KEPT,
        "a substring in get_functions_referencing_string, the exact value in "
        "get_string_reference_anchors; the same idea as get_strings' value under another name, "
        "and each is offered for the other",
    ),
    _param(
        "value",
        "a string's content, as a substring",
        ("get_strings",),
        _KEPT,
        "the same idea as text under another name; parameters are not renamed, and each is "
        "offered for the other",
    ),
    _param(
        "address",
        "a DATA address (hex, any form Ghidra shows)",
        ("get_data_bytes", "get_data_table"),
        _DISTINCT,
        "a data address, not a function: a function's address goes in function",
    ),
    _param(
        "target",
        "a launched binary's short name or a script path, not a sha256 selector",
        ("launched_by",),
        _DISTINCT,
        "matched against launch edges, not the binary selector; binary is offered as target",
    ),
    _param(
        "from_function",
        "the dispatching function of a string-keyed edge",
        ("get_string_keyed_edges",),
        _DISTINCT,
        "one end of an edge; function is offered as from_function or callee",
    ),
    _param(
        "callee",
        "the function a string-keyed edge dispatches to",
        ("get_string_keyed_edges",),
        _DISTINCT,
        "the other end of an edge",
    ),
    _param(
        "key",
        "an nvram key / a string key",
        ("get_nvram_key_flow", "get_string_keyed_edges"),
        _CONSISTENT,
        "the same name for a key in both, each tool's own kind of key",
    ),
    _param("diff_id", "one binary's diff ({run_a}::{run_b}::{binary})", _DIFF_TOOLS, _CONSISTENT),
    _param(
        "run_pair",
        "two runs, {run_a}::{run_b}",
        ("get_file_diff", "annotate_diff", "annotate_diff_batch"),
        _CONSISTENT,
    ),
    _param(
        "run_a",
        "the before run's id",
        ("get_diff_sink_overlay",),
        _KEPT,
        "list_diffs and list_diff_blindspots call it run_a_id; parameters are not renamed, and "
        "each is offered for the other",
    ),
    _param(
        "run_b",
        "the after run's id",
        ("get_diff_sink_overlay",),
        _KEPT,
        "list_diffs and list_diff_blindspots call it run_b_id; offered for each other",
    ),
    _param(
        "run_a_id",
        "the before run's id",
        ("list_diffs", "list_diff_blindspots"),
        _KEPT,
        "get_diff_sink_overlay calls it run_a; offered for each other",
    ),
    _param(
        "run_b_id",
        "the after run's id",
        ("list_diffs", "list_diff_blindspots"),
        _KEPT,
        "get_diff_sink_overlay calls it run_b; offered for each other",
    ),
    _param(
        "anchor_ref",
        "the anchor of one diff subject (an entry, a candidate row, a file)",
        ("annotate_diff", "clear_overlay"),
        _CONSISTENT,
    ),
    _param(
        "entry_id",
        "a diff entry's entry_id or its anchor_ref",
        ("get_diff_patch_view", "promote"),
        _CONSISTENT,
    ),
    _param(
        "candidate_anchor",
        "a diff candidate row's anchor",
        ("same_shape_siblings",),
        _SINGLE,
    ),
    _param("row_ref", "a diff row's a_ref or b_ref", ("promote",), _SINGLE),
    _param(
        "group_ref",
        "a same-shape group from same_shape_siblings",
        ("annotate_diff",),
        _SINGLE,
    ),
    _param(
        "anchor_kind",
        "evidence_ref (candidate annotations) or diff_subject (diff judgements)",
        ("list_overlays", "clear_overlay"),
        _CONSISTENT,
    ),
    _param(
        "verdict",
        "a judgement's verdict",
        ("annotate", "annotate_diff", "promote", "list_overlays"),
        _KEPT,
        "candidate verdicts on annotate / promote / list_overlays, diff verdicts on "
        "annotate_diff — a different set of values; a verdict of the other set is refused, "
        "naming the right tool",
    ),
    _param(
        "rationale",
        "why, the next step and the confidence",
        ("annotate", "annotate_diff", "promote"),
        _CONSISTENT,
        "annotate_diff lets no_real_change leave it out (it defaults to why_unchanged)",
    ),
    *[
        _param(p, "a candidate judgement's basis field", _BASIS, _CONSISTENT)
        for p in (
            "block_source",
            "block_point",
            "block_why",
            "chain",
            "verification_gaps",
            "shared_prereq",
        )
    ],
    _param(
        "sink_class",
        "a sink class",
        ("list_candidates", "get_diff_sink_overlay"),
        _CONSISTENT,
    ),
    _param(
        "sort_by",
        "the order of a listing",
        ("list_candidates", "get_diff_patch_view"),
        _KEPT,
        "different values per tool (impact / controllability / ... on list_candidates, "
        "significance / candidate_tier / ... on get_diff_patch_view); an unknown value is an "
        "error listing the values that exist",
    ),
    _param(
        "view",
        "a view preset",
        ("list_candidates", "get_diff_patch_view"),
        _KEPT,
        "lens presets on list_candidates, sink_patch / string_edge / candidate_flat on "
        "get_diff_patch_view; an unknown value is an error listing the values that exist",
    ),
    _param(
        "detail",
        "how much of each item a page carries",
        ("get_diff_patch_view", "get_diff_sink_overlay", "get_file_diff"),
        _KEPT,
        "full / summary on get_diff_patch_view and get_file_diff, summary / rows on "
        "get_diff_sink_overlay — a different switch, as its description says",
    ),
    _param(
        "verbose",
        "whether the navigational text comes along",
        ("list_candidates", "get_diff_deltas"),
        _KEPT,
        "defaults to true on list_candidates and false on get_diff_deltas",
    ),
    _param(
        "side",
        "which side of a diff",
        ("get_diff_sink_overlay", "get_function_alignment"),
        _KEPT,
        "a / b on get_function_alignment, the a_only / b_only / both row filter on "
        "get_diff_sink_overlay; an unknown value is an error listing the values that exist",
    ),
    _param(
        "offset",
        "where a page starts: pass the next_offset (or paging.next_offset) the previous page gave",
        (
            "list_candidates",
            "get_diff_patch_view",
            "get_diff_deltas",
            "get_diff_sink_overlay",
            "get_file_diff",
            "cross_firmware_patterns",
            "pattern_density",
            "get_pseudocode",
            "get_strings",
            "get_data_table",
            "get_disassembly",
            "get_script_callsites",
        ),
        _KEPT,
        "the unit is each tool's own (rows, lines, bytes, records); copy the value a page gives",
    ),
    _param(
        "limit",
        "how many items a page holds at most",
        (
            "list_candidates",
            "launched_by",
            "start_diff_review",
            "get_diff_patch_view",
            "get_diff_deltas",
            "get_diff_sink_overlay",
            "get_file_diff",
            "cross_firmware_patterns",
            "pattern_density",
            "get_string_reference_anchors",
            "get_data_table",
        ),
        _KEPT,
        "the unit and the range are each tool's own",
    ),
    *[
        _param(p, "the cursor of one sub-list's pages", (tool,), _CONSISTENT)
        for p, tool in (
            ("rows_offset", "get_diff_patch_view"),
            ("members_offset", "same_shape_siblings"),
            ("hunk_offset", "get_file_diff"),
            ("not_listed_page", "get_diff_patch_view"),
        )
    ],
    *[
        _param(p, meaning, (tool,), _SINGLE)
        for p, meaning, tool in (
            ("sink", "a sink callee or class", "list_candidates"),
            ("status", "to-verify / reachable / all", "list_candidates"),
            ("fingerprint", "a structural fingerprint", "list_candidates"),
            ("filters", "dimension filters that float matches", "list_candidates"),
            ("only", "a dimension filter that prunes the view", "list_candidates"),
            ("impact_order", "the impact tiers' order", "list_candidates"),
            ("overlay", "re-rank by your own annotations", "list_candidates"),
            ("sink_idx", "one sink of the function", "get_sink_provenance"),
            ("dominating_only", "only the dominating writers", "get_sink_provenance"),
            ("bucket", "an entry bucket", "get_diff_patch_view"),
            ("subclass", "an entry's or a row's subclass", "get_diff_patch_view"),
            ("tier", "a sink-impact tier", "get_diff_patch_view"),
            ("blind_spot", "a key of the blind_spots ledger", "get_diff_patch_view"),
            ("band", "order judged entries inside each group", "get_diff_patch_view"),
            ("body", "a body class of the text-unverified entries", "get_diff_patch_view"),
            ("anchored_differs", "only the anchored_differs pairs", "get_diff_patch_view"),
            ("anchored_micro_side", "only the anchored micro-side pairs", "get_diff_patch_view"),
            ("rows_limit", "how many rows an entry carries inline", "get_diff_patch_view"),
            ("dimension", "a delta dimension", "get_diff_deltas"),
            ("delta_kind", "a delta kind", "get_diff_deltas"),
            ("presence", "a row presence", "get_diff_sink_overlay"),
            ("min_alignment_confidence", "a confidence floor", "get_diff_sink_overlay"),
            ("reason", "an exact presence_reason", "get_diff_sink_overlay"),
            ("kind", "a non-binary file kind", "get_file_diff"),
            ("change", "a file change", "get_file_diff"),
            ("path", "one file's path", "get_file_diff"),
            ("direction", "callers / callees / address_taken", "get_xrefs"),
            ("length", "how many bytes to read", "get_data_bytes"),
            ("stride", "a table record's size", "get_data_table"),
            ("field_offset", "where the entry word sits in a record", "get_data_table"),
            ("checked", "the anchors a no_real_change read", "annotate_diff"),
            ("why_unchanged", "why the change does nothing real", "annotate_diff"),
            ("evidence", "the anchors a changed_real rests on", "annotate_diff"),
            ("annotations", "the items of a batch", "annotate_diff_batch"),
            ("allow_stale_source", "promote from a diff that is not current", "promote"),
            ("clear_all", "delete every annotation of the kind", "clear_overlay"),
            ("reveal", "return the full exploit notes", "list_verified_exploits"),
        )
    ],
    _param("name", "a tool's name, or guide / parameters", ("get_tool_reference",), "new"),
]
