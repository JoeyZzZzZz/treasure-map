# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Flow evidence for a command-sink candidate — structured, per-candidate mechanism facts.

This module produces EVIDENCE, never a judgement. It reports all facts it can establish plus
explicit blind spots: it hands a reviewer the reliable facts it finds intra-procedurally (the
source classification, the one-hop value flow, which sanitizer-shaped calls exist and whether
they sit on the sink's path, which rootfs entry points were found to invoke the binary) AND the
boundary where its tracing stops — but it NEVER decides "sanitized / not sanitized" or
"triggerable / not". Each field is a neutral mechanism fact.

Hard rules (do not relax):
- `sanitizer_seen` records only that a sanitizer-shaped call exists and whether it lies on the
  sink's flow path. Coverage is ALWAYS reported as ``unjudged`` — a single static read cannot
  decide that a sanitizer covers a path (the same sanitizer can guard one branch and miss
  another), so it must not claim to.
- `source_kind` classifies the source mechanism (charset_safe / free_string / unknown); it is
  NOT a safety verdict.
- `entry_reach` lists the call sites found; "no site found" is reported as ``unknown``, never as
  "unreachable" (a binary may be invoked at runtime, via another binary's exec, or over IPC).
  One site kind is an INFERENCE, not a reference: a CGI file placed inside a directory tree a
  NAMED CGI is served from carries ``basis: "inferred"`` and the co-location it was inferred
  from, so a reader can demote a sibling that is in fact dead. Every other site is a direct
  textual/structural reference and carries no ``basis``.
- `trace_boundary` states honestly where the structured trace stopped and why.

Nothing here GRADES recall, the review-ordering score, or reachability — it is read-only evidence
attached to the candidate, and a later layer consumes it (the reachability dim is graded in the
triage read layer, from the site kinds this module records). What the evidence says does bear on
that grade: an entry site is what lifts a candidate's reachability out of ``unknown``, which moves
it in the review ordering. So adding a site here is a ranking change by construction — which is
why the inferred kind above states the inference in its own field instead of hiding inside a
reference.
"""

from __future__ import annotations

import posixpath
import re
import sqlite3
from collections.abc import Mapping
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from treasure_map.lib.hunt.downweight import (
    _CHARSET_COPY_EXTRA,
    _CHARSET_SAFE,
    _charset_inline_constrained,
)
from treasure_map.lib.pattern.classes import (
    FMT_STRING_ARG,
    FORMAT_ARG,
    NO_HELPERS,
    SOURCE,
    ArgRef,
    SourceHelpers,
    all_format_calls_literal,
    call_args_at,
    call_offsets,
    format_string_ref,
)
from treasure_map.lib.reachability.copy_size import (
    SIZE_CONST,
    SIZE_SIZEOF,
    SIZE_UNTRACED,
    CopySize,
    classify_copy_size,
    classify_format_size,
    objsize_fact,
)
from treasure_map.lib.reachability.filters import _is_validator_name
from treasure_map.lib.reachability.taint import (
    _CALLER_SUPPLIED_RE,
    _derives_map,
    _seed_sets,
    flows_into,
    free_taint_reaches,
)

# Decompiler markers for values an intra-procedural read cannot soundly follow: globals / shared
# state / a prior call's un-threaded output. Their presence on the path is a trace boundary.
_GLOBAL_IPC_RE = re.compile(r"\b(?:DAT_[0-9a-fA-F]+|g_\w+|extraout_\w+|_?_bss_\w+)\b")
# An indirect call through a function pointer: (*fp)(...) or (\*\w+)(...).
_INDIRECT_CALL_RE = re.compile(r"\(\s*\*\s*\w+\s*\)\s*\(")


def _charset_converter_called(pseudocode: str) -> bool:
    """Existence check: a charset-safe converter is CALLED somewhere in this function body. NOT a
    flow claim — it does not assert the converter's result actually reaches the sink."""
    return any(re.search(rf"\b{re.escape(c)}\s*\(", pseudocode) for c in _CHARSET_SAFE)


# A call to any source, by exact name: ``name(`` (optional whitespace before the parenthesis). One
# alternation read in one pass; at a given start at most one name can be followed by ``(`` (a name
# that is a prefix of another is followed by the longer name's remaining characters instead).
_SOURCE_CALL_RE = re.compile(r"\b(" + "|".join(re.escape(s) for s in sorted(SOURCE)) + r")\s*\(")


@lru_cache(maxsize=64)
def _helper_call_re(names: frozenset[str]) -> re.Pattern[str] | None:
    """The same ``name(`` alternation as ``_SOURCE_CALL_RE``, over one binary's helper names (None
    when it has none). Built per helper set — the module-wide pattern holds the fixed names only,
    and a binary's helpers must never be folded into it."""
    if not names:
        return None
    return re.compile(r"\b(" + "|".join(re.escape(s) for s in sorted(names)) + r")\s*\(")


@lru_cache(maxsize=256)
def _sources_called_in(pseudocode: str, helpers: SourceHelpers = NO_HELPERS) -> tuple[str, ...]:
    """``free_sources_called`` per body text and binary helper set: a caller with several calls to
    one wrapper yields one candidate per call, all reading the same body. The helpers are part of
    the key — the same body names a source in one binary and not in another."""
    found = {m.group(1) for m in _SOURCE_CALL_RE.finditer(pseudocode)}
    helper_re = _helper_call_re(helpers.names)
    if helper_re is not None:
        found |= {m.group(1) for m in helper_re.finditer(pseudocode)}
    return tuple(sorted(found))


def free_sources_called(pseudocode: str, helpers: SourceHelpers = NO_HELPERS) -> list[str]:
    """The free-input sources (network/env/config/json getters, and the binary's own value-getter
    ``helpers``) CALLED in the function body, by name, sorted. A name counts only when it is written
    as a call (``name(``), so a getter whose name is a prefix of another's (``config_get`` /
    ``config_getall``) is not read into it.

    NOT a flow claim: a name here was called somewhere in the function, which says nothing about
    whether its value reaches any sink."""
    return list(_sources_called_in(pseudocode, helpers))


def _free_source_called(pseudocode: str, helpers: SourceHelpers = NO_HELPERS) -> bool:
    """Existence check: a free-input source is CALLED in the function body (``free_sources_called``
    is not empty). NOT a flow claim — used only for the conservative wrapper-candidate fallback."""
    return bool(free_sources_called(pseudocode, helpers))


def _source_kind(
    pseudocode: str,
    sink_arg: str | None,
    *,
    conservative_free: bool = False,
    helpers: SourceHelpers = NO_HELPERS,
) -> str:
    """Classify the source reaching the sink argument (mechanism, not a verdict).

    Order matters — a free source wins over a charset converter so a genuinely dangerous candidate
    is never washed into a "maybe safe" lead just because some converter is also called in the
    function:
      charset_safe  — the converter builds the sink argument INLINE (downweighted elsewhere).
      free_string   — a free source (network/env/config/json/parameter) reaches the sink argument.
      charset_maybe — NOT inline and NO free source, but a charset-safe converter is called in the
                      function: the value MAY be charset-constrained through an intermediate
                      variable, but it is not value-tracked here — a lead, not proven safe.
      unknown       — none of the above could be established.

    ``conservative_free`` (set for wrapper-propagated candidates, where the value reaches the
    forwarded argument possibly through intermediate variables an intra read cannot fully follow):
    a free source merely CALLED in the function is enough to classify free_string even when the
    flow is not fully traced. This is the deliberate, asymmetric "do not miss a danger" direction —
    the mirror of charset's "do not drop a suspect" (charset_maybe). A free source still wins over a
    charset converter, so a real free string is never washed into charset_maybe."""
    if sink_arg is None:
        return "unknown"
    if _charset_inline_constrained(pseudocode, sink_arg):
        return "charset_safe"
    if free_taint_reaches(pseudocode, sink_arg, safe_vars=set(), helpers=helpers):
        return "free_string"
    if conservative_free and _free_source_called(pseudocode, helpers):
        return "free_string"  # free source present; flow not fully traced -> report, don't miss
    if _charset_converter_called(pseudocode):
        return "charset_maybe"
    return "unknown"


def _real_vars(
    pseudocode: str, deps: Mapping[str, AbstractSet[str]], helpers: SourceHelpers = NO_HELPERS
) -> set[str]:
    """The function's real variables — values that are written, depended on, caller-supplied, or
    source-seeded. Used to filter format-literal noise (e.g. the `echo`/`s` of `"echo %s"`) out of
    the reported flow so the evidence lists actual flow variables, not parsed string fragments."""
    strong, weak, par = _seed_sets(pseudocode, helpers)
    real = set(deps.keys()) | strong | weak | par
    for srcs in deps.values():
        real |= srcs & set(deps.keys())  # intermediate vars that themselves have dependencies
    real |= set(_CALLER_SUPPLIED_RE.findall(pseudocode))
    return real


def _flow_path(
    pseudocode: str,
    sink_arg: str | None,
    deps: Mapping[str, AbstractSet[str]],
    helpers: SourceHelpers = NO_HELPERS,
) -> dict[str, Any]:
    """The sink argument and its ONE-HOP backward dependencies (the intermediate values feeding
    it directly), filtered to real variables. Reliable range only — direct args + one intermediate
    variable; deeper links are summarized by ``trace_boundary``, not invented here."""
    if sink_arg is None:
        return {"sink_arg": None, "one_hop": []}
    real = _real_vars(pseudocode, deps, helpers)
    one_hop = sorted(v for v in deps.get(sink_arg, set()) if v in real)
    return {"sink_arg": sink_arg, "one_hop": one_hop}


def _sanitizer_seen(callees: list[str], pseudocode: str, path: set[str]) -> list[dict[str, Any]]:
    """Sanitizer-shaped callees and whether each is applied to a value on the sink's path.

    Records existence + on_path only; coverage is ALWAYS ``unjudged`` (a static read cannot
    decide a sanitizer actually covers the path). Never feeds a score or a blocked verdict."""
    seen: list[dict[str, Any]] = []
    for callee in callees:
        name = callee.strip()
        if not name or not _is_validator_name(name):
            continue
        on_path = any(
            re.search(rf"\b{re.escape(name)}\s*\([^;{{}}]*\b{re.escape(var)}\b", pseudocode)
            is not None
            for var in path
        )
        seen.append({"name": name, "on_path": on_path, "coverage": "unjudged"})
    return seen


# Forms whose value is read through memory this function's text does not show the writer of.
_LOADED_FORMS = frozenset({"load", "const_addr"})


def _trace_boundary(
    pseudocode: str,
    sink_arg: str | None,
    source_kind: str,
    deps: Mapping[str, AbstractSet[str]],
    ref: ArgRef | None = None,
    located: bool = True,
) -> str:
    """Honest statement of where the structured trace stops and why.

    sink_arg_unlocated — the sink call or its argument could not be located in the text.
    reached_sink      — the source was resolved to the bottom WITHIN this function (an inline
                        charset converter, an inline free source, or a literal).
    charset_via_intermediate_untraced — a charset-safe converter is in the function but the value
                        reaches the sink through an intermediate variable that was NOT followed
                        (the `charset_maybe` lead: looked through a converter, did not trace it).
    one_hop_limit     — source not resolved; one intermediate buffer followed, stopped at the cap.
    two_hop_untraced  — source not resolved; >=2 intermediate buffers (beyond the cap).
    indirect_call     — an indirect (function-pointer) call is present (a value may arrive through
                        it; intra read cannot follow it).
    ipc_global        — a global / shared-state / un-threaded value is present.
    copy_alias_untraced — a bounded copy the dependency graph does not track moved a value, so the
                        structured flow chain may be incomplete.
    loaded_through_pointer — the argument is read through a pointer, an index or a field (or is a
                        number cast to a pointer): what was stored there is not in this read.
    sink_arg_unparsed — there is an argument, but no variable could be read out of it.

    ``ref`` is the argument as ``classes.arg_ref`` read it (its form and lead); ``located`` False
    when there was no argument to read. Without a ``ref`` the argument is taken as the variable
    ``sink_arg`` names, or as a literal when there is none (the reading before forms existed).

    Honest by design — it NEVER claims `reached_sink` when a converter was seen but the value ran
    through an intermediate variable (that would pretend not to have seen the converter). A
    present-but-maybe-unrelated indirect call / global / untracked copy is reported as a boundary
    rather than silently claiming a clean resolution."""
    if not located:
        return "sink_arg_unlocated"
    if ref is None:
        ref = ArgRef("var", sink_arg, lead="var") if sink_arg is not None else ArgRef("literal")
    if ref.form == "literal":
        return "reached_sink"
    if source_kind == "charset_maybe":
        return "charset_via_intermediate_untraced"
    if _INDIRECT_CALL_RE.search(pseudocode):
        return "indirect_call"
    if _GLOBAL_IPC_RE.search(pseudocode):
        return "ipc_global"
    if any(re.search(rf"\b{re.escape(c)}\s*\(", pseudocode) for c in _CHARSET_COPY_EXTRA):
        # A bounded copy the global dependency graph does not track moved a value; the structured
        # chain may be shorter than reality, so flag the alias rather than overclaim resolution.
        return "copy_alias_untraced"
    if ref.form in _LOADED_FORMS or ref.lead == "load":
        return "loaded_through_pointer"
    if ref.form == "none" or sink_arg is None:
        return "sink_arg_unparsed"
    if source_kind in ("charset_safe", "free_string"):
        return "reached_sink"  # the source was resolved within the intra-procedural read
    depth = _chain_depth(deps, sink_arg)
    if depth <= 1:
        return "reached_sink"
    if depth == 2:
        return "one_hop_limit"
    return "two_hop_untraced"


def _chain_depth(deps: Mapping[str, AbstractSet[str]], start: str) -> int:
    """Longest backward chain length from ``start`` over the dependency edges (cycle-safe)."""
    best = {start: 0}
    stack = [start]
    seen = {start}
    longest = 0
    while stack:
        cur = stack.pop()
        for nxt in deps.get(cur, ()):
            cand = best[cur] + 1
            longest = max(longest, cand)
            if nxt not in seen or cand > best.get(nxt, 0):
                best[nxt] = cand
                seen.add(nxt)
                if cand < 8:  # depth guard; the answer only needs the <=2 vs >2 distinction
                    stack.append(nxt)
    return longest


def build_flow_evidence(
    *,
    pseudocode: str,
    callees: list[str],
    sink_arg: str | None,
    entry_sites: list[dict[str, Any]] | None,
    wrapper: dict[str, Any] | None = None,
    sink_ref: ArgRef | None | Literal["unset"] = "unset",
    helpers: SourceHelpers = NO_HELPERS,
) -> dict[str, Any]:
    """Assemble the five-field flow evidence for one command-sink candidate (JSON-serializable).
    ``helpers`` is the candidate's binary's value-getter helpers (read as weak sources).

    Pure and deterministic. ``entry_sites`` is the rootfs invocation evidence gathered separately
    (see ``EntryIndex.sites_for``); None or [] means none was found — reported as ``unknown``,
    NOT as "unreachable".

    ``wrapper`` is set for a factor-① wrapper-propagated candidate (the real sink is one hop away
    inside a thin wrapper): it carries the wrapper's name + wrapped_sink, and here ``sink_arg`` is
    the argument the function forwards to that wrapper. When set, flow_path marks the wrapper hop
    and trace_boundary states `reached_sink_via_one_hop_wrapper` — honest about following exactly
    one hop. ``source_kind`` still classifies the forwarded argument (the dangerous value).

    ``sink_ref`` is the sink argument as ``classes.arg_ref`` read it, None when it could not be
    located: its form is recorded (``flow_path.sink_arg_form``) and decides the trace boundary for a
    literal, a value loaded through a pointer, or one no variable could be read from. Left unset,
    the boundary reads ``sink_arg`` alone, as before forms were recorded."""
    deps = _derives_map(pseudocode, helpers)
    path = (
        ({sink_arg} | flows_into(pseudocode, sink_arg, helpers)) if sink_arg is not None else set()
    )
    # Wrapper-propagated candidates reach the forwarded argument possibly through intermediate
    # variables, so a present-but-not-fully-traced free source is reported conservatively.
    source_kind = _source_kind(
        pseudocode, sink_arg, conservative_free=wrapper is not None, helpers=helpers
    )
    flow_path = _flow_path(pseudocode, sink_arg, deps, helpers)
    if sink_ref != "unset":
        ref = sink_ref if isinstance(sink_ref, ArgRef) else None
        flow_path = {**flow_path, "sink_arg_form": ref.form if ref is not None else None}
    if wrapper is not None:
        flow_path = {**flow_path, "sink_via_wrapper": True, "wrapper": wrapper}
        trace_boundary = "reached_sink_via_one_hop_wrapper"
    elif sink_ref == "unset":
        trace_boundary = _trace_boundary(pseudocode, sink_arg, source_kind, deps)
    else:
        trace_boundary = _trace_boundary(
            pseudocode,
            sink_arg,
            source_kind,
            deps,
            ref=sink_ref if isinstance(sink_ref, ArgRef) else None,
            located=isinstance(sink_ref, ArgRef),
        )
    return {
        "source_kind": source_kind,
        "flow_path": flow_path,
        "sanitizer_seen": _sanitizer_seen(callees, pseudocode, path),
        "entry_reach": {
            "status": "found" if entry_sites else "unknown",
            "sites": entry_sites or [],
        },
        "trace_boundary": trace_boundary,
    }


def _size_trace_boundary(
    pseudocode: str,
    kind: str,
    size_var: str | None,
    deps: Mapping[str, AbstractSet[str]],
    form: str | None = None,
    lead: str | None = None,
) -> str:
    """Honest statement of where the size trace stops and why (mirror of ``_trace_boundary``).

    reached_sink        — the length resolved within the function (a constant, a sizeof, or a
                          length variable with no further backward chain).
    size_arg_untraced   — the length argument could not be resolved here.
    indirect_call       — an indirect (function-pointer) call is present; a length may arrive
                          through it and an intra read cannot follow it.
    copy_alias_untraced — a bounded copy the dependency graph does not track moved a value, so the
                          structured size chain may be incomplete.
    loaded_through_pointer — the length (or the strcpy source) is read through a pointer, an index
                          or a field, or is a number cast to a pointer: what was stored there is not
                          in this read.
    size_arg_unparsed   — the strcpy source is there, but no variable could be read out of it.
    one_hop_limit       — the length came through one intermediate variable, stopped at the cap.
    two_hop_untraced    — the length came through >=2 intermediates (beyond the cap).

    ``form`` / ``lead`` are the length argument's (``CopySize``)."""
    if kind in (SIZE_CONST, SIZE_SIZEOF):
        return "reached_sink"
    if kind == SIZE_UNTRACED:
        return "size_arg_untraced"
    if _INDIRECT_CALL_RE.search(pseudocode):
        return "indirect_call"
    if any(re.search(rf"\b{re.escape(c)}\s*\(", pseudocode) for c in _CHARSET_COPY_EXTRA):
        return "copy_alias_untraced"
    if form in _LOADED_FORMS or lead == "load":
        return "loaded_through_pointer"
    if form == "none":
        return "size_arg_unparsed"
    if size_var is None:
        return "reached_sink"
    depth = _chain_depth(deps, size_var)
    if depth <= 1:
        return "reached_sink"
    if depth == 2:
        return "one_hop_limit"
    return "two_hop_untraced"


def _size_flow(cs: CopySize, one_hop: list[str]) -> dict[str, Any]:
    """A size record's ``size_flow``: the length text, its root variable and one-hop sources, and —
    when the argument was read — its form (``size_arg_form``) and, for a length read through a
    pointer / index / field, the access path the clamp search matched on (``size_arg_path``)."""
    out: dict[str, Any] = {"size_arg": cs.size_text, "size_var": cs.size_var, "one_hop": one_hop}
    if cs.form is not None:
        out["size_arg_form"] = cs.form
    if cs.lead == "load" and cs.path is not None:
        out["size_arg_path"] = cs.path
    return out


def _attach_objsize(
    out: dict[str, Any],
    pseudocode: str,
    sink_name: str,
    occurrence: int,
    stub_names: Mapping[int, str] | None,
) -> None:
    """Add the fortified call's destination-object-size fact (``objsize``) to a size record.

    Only a _chk sink carries the key; every other record is left exactly as it was. The fact is
    surfaced, not judged: ``size_kind`` and everything ranked from it are untouched by it."""
    fact = objsize_fact(pseudocode, sink_name, occurrence=occurrence, stub_names=stub_names)
    if fact is not None:
        out["objsize"] = fact


def build_size_evidence(
    *,
    pseudocode: str,
    sink_name: str,
    entry_sites: list[dict[str, Any]] | None = None,
    callsite_index: int | None = None,
    occurrence: int = 0,
    stub_names: Mapping[int, str] | None = None,
    helpers: SourceHelpers = NO_HELPERS,
) -> dict[str, Any]:
    """Assemble the size-flow evidence for one copy-sink candidate (JSON-serializable).

    Pure and deterministic. Like ``build_flow_evidence`` this is EVIDENCE, never a judgement: it
    classifies the write-length source (mechanism), reports the reliable one-hop size flow, lists
    any upper-bound/guard shapes seen (each ``coverage=unjudged`` — presence only, never a
    dominance claim), and states honestly where the size trace stops. It NEVER decides
    "bounded / not" — that judgement is the agent's.

    ``entry_reach`` carries the same rootfs-invocation evidence as the command-sink path so a copy
    candidate ranks evenly with cmd/fmt on entry reachability (None/[] is reported ``unknown``,
    NEVER "unreachable").

    ``callsite_index`` / ``occurrence`` say WHICH copy call this is, and the length is read from
    that call. The record names it back in ``copy_callsite`` because sibling candidates from one
    function are otherwise indistinguishable on screen — same function, same callee, different
    length — and a reader with no way to tell them apart is being handed two facts and told to
    guess which call each belongs to. ``callsite_index=None`` means the call could not be located
    in the text at all: the record then says ``anchor: "function"`` and leaves the ordinals null,
    rather than printing a 0 that would read as "the first call" for a call nobody found."""
    cs = classify_copy_size(pseudocode, sink_name, occurrence=occurrence, stub_names=stub_names)
    deps = _derives_map(pseudocode, helpers)
    if cs.size_var is not None:
        real = _real_vars(pseudocode, deps, helpers)
        one_hop = sorted(v for v in deps.get(cs.size_var, set()) if v in real)
    else:
        one_hop = []
    anchored = callsite_index is not None
    out: dict[str, Any] = {
        "size_kind": cs.kind,
        "copy_callsite": {
            "sink": sink_name,
            "index": callsite_index,
            "occurrence": occurrence if anchored else None,
            "anchor": "callsite" if anchored else "function",
        },
        "size_flow": _size_flow(cs, one_hop),
        "clamp_seen": [{"shape": s, "coverage": "unjudged"} for s in cs.clamps],
        "entry_reach": {
            "status": "found" if entry_sites else "unknown",
            "sites": entry_sites or [],
        },
        "trace_boundary": _size_trace_boundary(
            pseudocode, cs.kind, cs.size_var, deps, cs.form, cs.lead
        ),
    }
    _attach_objsize(out, pseudocode, sink_name, occurrence, stub_names)
    return out


# How much could be said about the FORMAT STRING of a buffer-formatter call. A separate axis from
# the write length on purpose: the length comes from the callee's SIGNATURE and is known for every
# call, while the format string may be a literal, a variable, or absent entirely. Collapsing the
# two would let "we could not read the format" quietly become "there is no cap", which is a false
# statement about the call.
FMT_LITERAL_WITH_ARGS = "literal_with_args"  # a literal carrying % — the expansions are readable
FMT_LITERAL_CONSTANT = "literal_constant"  # a literal with no % — nothing expands into the buffer
FMT_UNRESOLVED = "unresolved"  # a variable format, or a callee with no format string at all


def _format_string_resolution(
    pseudocode: str, sink_name: str, occurrence: int, stub_names: Mapping[int, str] | None = None
) -> str:
    """Which of the three states this call's format string is in. Never a judgement about risk."""
    pos = FORMAT_ARG.get(sink_name)
    if pos is None:
        return FMT_UNRESOLVED  # strcat / strncat carry no format string to read
    offsets = call_offsets(pseudocode, sink_name, stub_names)
    if occurrence < 0 or occurrence >= len(offsets):
        return FMT_UNRESOLVED
    args = call_args_at(pseudocode, offsets[occurrence]) or []
    if pos >= len(args):
        return FMT_UNRESOLVED
    fmt = args[pos].strip()
    if not (fmt.startswith('"') or fmt.startswith('L"')):
        return FMT_UNRESOLVED
    return FMT_LITERAL_WITH_ARGS if "%" in fmt else FMT_LITERAL_CONSTANT


def build_format_size_evidence(
    *,
    pseudocode: str,
    sink_name: str,
    entry_sites: list[dict[str, Any]] | None = None,
    callsite_index: int | None = None,
    occurrence: int = 0,
    stub_names: Mapping[int, str] | None = None,
    helpers: SourceHelpers = NO_HELPERS,
) -> dict[str, Any]:
    """The write-length evidence for one buffer-formatter candidate (JSON-serializable).

    The same shape ``build_size_evidence`` produces for a copy, so one reader handles both, plus
    one field the copy axis has no equivalent for: ``format_string``, saying how much could be read
    of the format. That is deliberately NOT folded into ``size_kind`` — the length comes from the
    callee's signature and is known for every call, while the format string may be unreadable, and
    letting the second overwrite the first is how ``snprintf(dst, 64, fmt_var, ...)`` would come
    back claiming no cap exists.

    EVIDENCE, never a verdict. Nothing here says the destination is too small; the call does not
    carry the destination's size, and inventing one is the failure this whole axis is written
    around."""
    fs = classify_format_size(pseudocode, sink_name, occurrence=occurrence, stub_names=stub_names)
    deps = _derives_map(pseudocode, helpers)
    if fs.size_var is not None:
        real = _real_vars(pseudocode, deps, helpers)
        one_hop = sorted(v for v in deps.get(fs.size_var, set()) if v in real)
    else:
        one_hop = []
    anchored = callsite_index is not None
    out: dict[str, Any] = {
        "size_kind": fs.kind,
        "copy_callsite": {
            "sink": sink_name,
            "index": callsite_index,
            "occurrence": occurrence if anchored else None,
            "anchor": "callsite" if anchored else "function",
        },
        "format_string": _format_string_resolution(pseudocode, sink_name, occurrence, stub_names)
        if anchored
        else FMT_UNRESOLVED,
        "size_flow": _size_flow(fs, one_hop),
        # A formatter's length is a cap or an append amount, not a clamped variable, so the
        # clamp search the copy axis runs does not apply. Present and empty rather than absent:
        # the reader treats a missing key as "no picture at all".
        "clamp_seen": [],
        "entry_reach": {
            "status": "found" if entry_sites else "unknown",
            "sites": entry_sites or [],
        },
        "trace_boundary": _size_trace_boundary(
            pseudocode, fs.kind, fs.size_var, deps, fs.form, fs.lead
        ),
    }
    _attach_objsize(out, pseudocode, sink_name, occurrence, stub_names)
    return out


def build_fmtstr_evidence(
    *,
    pseudocode: str,
    callees: list[str],
    sink_name: str,
    entry_sites: list[dict[str, Any]] | None,
    stub_names: Mapping[int, str] | None = None,
    occurrence: int | None = None,
    helpers: SourceHelpers = NO_HELPERS,
) -> dict[str, Any]:
    """Assemble the flow evidence for one format-string-injection candidate (JSON-serializable).

    The danger axis is the FORMAT argument (per-sink position). This reuses the command-sink flow
    evidence on that argument (source_kind / flow_path / sanitizer_seen / entry_reach /
    trace_boundary) and adds two format-specific facts: which positional argument is the format
    string, and whether every call passes a literal format (it must NOT, or this would not be a
    candidate — recorded for transparency). EVIDENCE, never a verdict — it does not
    decide the format is truly controllable."""
    fmt_ref = format_string_ref(pseudocode, sink_name, stub_names, occurrence)
    fmt_arg = fmt_ref.root if fmt_ref is not None else None
    ev = build_flow_evidence(
        pseudocode=pseudocode,
        callees=callees,
        sink_arg=fmt_arg,
        entry_sites=entry_sites,
        sink_ref=fmt_ref,
        helpers=helpers,
    )
    ev["fmt_arg_pos"] = FMT_STRING_ARG.get(sink_name)
    ev["fmt_arg_literal"] = all_format_calls_literal(pseudocode, sink_name, stub_names)
    return ev


def _ref_at_boundary(name: str, ep: str) -> bool:
    """True when ``name`` sits on a word/path-segment boundary inside endpoint ``ep``.

    A bare substring test falsely matches a short binary name buried inside a longer word — e.g.
    ``"rc"`` inside ``per(rc)ent``. We require the character on each side of ``name`` to be a
    non-alphanumeric (string edge, ``/``, ``.``, ``-``, ``?``, ``=``, ``&``, space, …), so ``rc``
    matches ``/rc.cgi`` and ``rc?x=1`` but not ``percent`` or ``search``. ``_`` counts as a
    word-internal character (``start_rc`` does NOT match ``rc``): the web side stays deliberately
    strict — narrow-but-real beats wide-but-false. Case-sensitive, matching Python ``in``."""
    return re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", ep) is not None


# The file extension a served CGI file is recognised by. Deliberately the only test for "this is
# a CGI": a web server's handler map lives in its config, which the default hunt does not read, so
# a mapping-based test is not computable here. Extension-only also keeps the helper files that sit
# in a web directory (a shared library, an extensionless data file) out of the inference — they are
# not request targets, and a wrong extension leaves the candidate at ``unknown``, never at a
# claimed reachability.
CGI_SUFFIX = ".cgi"

# Rootfs-relative directories that must NEVER become a served root, by path and in full (a
# descendant of one is fine: ``usr/www`` is a real web root, ``usr`` is not). An anchor misplaced
# in one of these — a web asset naming a short binary name that also happens to be a system
# binary's — would otherwise hand web reachability to every CGI in a system tree. The filesystem
# root is in here as the empty string: a binary directly at the rootfs root roots the whole image.
_NEVER_SERVED_ROOTS: frozenset[str] = frozenset(
    {
        "",
        ".",
        "bin",
        "sbin",
        "lib",
        "lib32",
        "lib64",
        "libexec",
        "etc",
        "dev",
        "proc",
        "sys",
        "tmp",
        "var",
        "run",
        "opt",
        "mnt",
        "media",
        "boot",
        "home",
        "root",
        "srv",
        "usr",
        "usr/bin",
        "usr/sbin",
        "usr/lib",
        "usr/lib32",
        "usr/lib64",
        "usr/libexec",
        "usr/local",
        "usr/local/bin",
        "usr/local/sbin",
        "usr/local/lib",
    }
)


@dataclass(frozen=True)
class ServedRoot:
    """A directory tree a NAMED CGI is served from: the evidence that lets a CGI file placed in it
    be read as web-reachable without being named anywhere itself.

    ``directory`` is spelled exactly as the binaries table spells it — an absolute host path in a
    normal scan, and whatever that table holds otherwise, because it is what a membership test
    compares; ``rel_directory`` is the same directory relative to the rootfs, and ``seed`` the
    name of the named CGI it was derived from — the two that go into the inferred site's note, so
    the reader sees WHICH co-location was inferred from and can disagree with it."""

    directory: str
    rel_directory: str
    seed: str


def _inventory_relative_paths(conn: sqlite3.Connection) -> dict[str, tuple[str, ...]]:
    """``sha256 -> rootfs-relative paths`` from the file inventory, for placing a binary inside the
    image. Empty for an analysis.db without the inventory (every served root is then undecidable
    and none is derived — see :func:`served_cgi_roots`)."""
    try:
        rows = conn.execute(
            "SELECT sha256, path FROM file_inventory WHERE sha256 IS NOT NULL AND path IS NOT NULL"
        ).fetchall()
    except sqlite3.OperationalError:
        return {}
    out: dict[str, list[str]] = {}
    for sha, path in rows:
        out.setdefault(str(sha), []).append(str(path))
    return {sha: tuple(sorted(paths)) for sha, paths in out.items()}


def _rootfs_relative(binary_path: str, candidates: tuple[str, ...]) -> str | None:
    """Where ``binary_path`` sits relative to the rootfs, chosen from the inventory paths that
    share its content; None when none of them spells this file's path.

    The binaries table records an absolute host path and the inventory a rootfs-relative one, so
    the two are joined by content and confirmed by suffix. One content can live at several paths;
    the longest suffix match is the most specific, and the name order breaks a tie so the choice
    is the same on every re-hunt (the site this feeds is stored text an overlay judgement's basis
    compares). A binaries table that spells the path rootfs-relative ITSELF has no suffix to
    match, so an exact equality counts too — otherwise the inference would be silently off for
    such a database rather than honestly unavailable."""
    relative_table = not binary_path.startswith("/")
    matches = [
        r
        for r in candidates
        if binary_path.endswith("/" + r.lstrip("/"))
        or (relative_table and r.lstrip("/") == binary_path)
    ]
    if not matches:
        return None
    return sorted(matches, key=lambda r: (-len(r), r))[0]


def served_cgi_roots(conn: sqlite3.Connection, index: EntryIndex) -> tuple[ServedRoot, ...]:
    """The directory trees a NAMED CGI is served from, over EVERY binary in the image.

    A global prescan, run once before any candidate is looked at: a single binary's own view
    cannot see that a sibling CGI one directory up is named by a web asset, so this cannot be
    computed inside :meth:`EntryIndex.sites_for`.

    ★ Load-bearing limits on what may seed a root, each one a tree that must NOT be served:
      * ONLY a real ``web_endpoint`` name match seeds (``index`` is the probe built for exactly
        this question — it holds the web assets and nothing else, so a ``script_call`` or an
        ``exec_edge`` reference cannot seed, and neither can an inferred site: this is one pass
        with no feedback into its own input). A system directory holds hundreds of
        script-launched binaries; seeded there, the inference would cover all of them.
      * The web server's OWN directory is not a served root by virtue of being a web server's —
        only the directory of a binary a web asset NAMES is, which is a request target.
      * A system directory is refused outright (``_NEVER_SERVED_ROOTS``), as is a binary whose
        place in the image cannot be established from the inventory: unplaceable means
        unguardable, so it is dropped rather than trusted.
    Nothing is invented when no root survives — the candidates stay ``unknown``."""
    try:
        bins = conn.execute("SELECT name, path, sha256 FROM current_binaries").fetchall()
    except sqlite3.OperationalError:
        return ()
    inventory = _inventory_relative_paths(conn)
    roots: dict[str, tuple[str, str]] = {}
    for name, path, sha in ((r[0], r[1], r[2]) for r in bins):
        if not path or not any(
            s.get("kind") == "web_endpoint" for s in index.sites_for(name, path)
        ):
            continue
        relative = _rootfs_relative(str(path), inventory.get(str(sha), ()))
        if relative is None:
            continue
        rel_directory = posixpath.dirname(relative.lstrip("/"))
        if rel_directory in _NEVER_SERVED_ROOTS:
            continue
        directory, seed = posixpath.dirname(str(path)), posixpath.basename(str(path))
        kept = roots.get(directory)
        # One root, one seed in the note, picked by name so two named CGIs in a directory do not
        # make the stored site text depend on the row order.
        if kept is None or seed < kept[1]:
            roots[directory] = (rel_directory, seed)
    return tuple(
        ServedRoot(directory, rel_directory, seed)
        for directory, (rel_directory, seed) in sorted(roots.items())
    )


class EntryIndex:
    """In-memory index of rootfs entry evidence (L0.5 ``script_calls`` + ``web_endpoints``).

    Loaded ONCE per analysis.db, then queried per candidate binary — so entry-reach evidence does
    not re-scan the tables for every candidate. Read-only; holds only neutral rootfs evidence."""

    def __init__(
        self,
        script_calls: list[
            tuple[str | None, str | None, int | None, str | None, str | None, int | None]
        ],
        web_endpoints: list[tuple[str | None, str | None, str | None, str | None, str | None]],
        exec_sites: dict[str, list[dict[str, Any]]] | None = None,
        served_roots: tuple[ServedRoot, ...] = (),
    ) -> None:
        self._script_calls = script_calls
        self._web_endpoints = web_endpoints
        # A DIFFERENT source from the two above: not a rootfs file, but another BINARY's launch
        # callsite, computed during the hunt (the call provenance lives in the analysis DB, not in
        # a table this index can read). Optional on purpose — an index built without it degrades to
        # exactly the previous behaviour instead of failing, so an older caller keeps working.
        self._exec_sites = exec_sites or {}
        # The image-wide prescan (:func:`served_cgi_roots`), which no per-binary view can compute.
        # Empty by default, and an index built without it behaves exactly as it did before the
        # inference existed — the prescan is the ONLY producer, so a script or exec reference can
        # never arrive here as a root.
        self._served_roots = served_roots

    def sites_for(self, binary_name: str | None, binary_path: str | None) -> list[dict[str, Any]]:
        """Every entry site referencing the binary (all sites). Each script site carries the script
        path, line, and coarse argument pattern (literal / var_expansion / piped) so the parameter
        source is visible. [] means none found — the caller reports ``unknown``, NOT "unreachable".

        Three kinds of reference, kept distinct so the reader knows which one they are looking at:
        a rootfs script that invokes the binary, a web asset that names it, and another binary that
        launches it (an ``exec_edge`` site). All three are textual/structural references, and none
        of them is proof that input arrives — the caller must not collapse them into a verdict.

        A fourth kind is an INFERENCE from placement, not a reference: a CGI file inside a
        directory tree a named CGI is served from (:func:`served_cgi_roots`). It is offered only to
        a binary no web asset names, carries ``basis: "inferred"`` with the co-location it rests
        on, and carries no endpoint — there is no request for it to quote. The reachability grade
        it produces is the same one a named site produces (that is the point: a request-reachable
        CGI should not sort below an unreachable one), so the distinction lives in the site, and a
        reader who finds the sibling dead demotes it from there.
        """
        names = {n for n in (binary_name, Path(binary_path).name if binary_path else None) if n}
        if not names:
            return []
        sites: list[dict[str, Any]] = []
        web_named = False
        for script, command, line, args_pattern, via, via_line in self._script_calls:
            cmd = command or ""
            # References the binary when the command token is, or ends in, the binary name
            # (handles bare-name and absolute-path forms in the script).
            if cmd.rsplit("/", 1)[-1] in names or cmd in names:
                site: dict[str, Any] = {
                    "kind": "script_call",
                    "script": script,
                    "line": line,
                    "arg_source": args_pattern,
                }
                # ★ Only a command the line does not name itself says where it came from. A
                # literal site stays the exact dict it always was: it is stored inside the
                # candidate's flow_evidence, which an overlay judgement's basis compares as text,
                # so a re-scan of unchanged content must not move it.
                if via not in (None, "literal"):
                    site["via"] = via
                    site["via_line"] = via_line
                sites.append(site)
        for asset, asset_type, method, endpoint, source in self._web_endpoints:
            ep = endpoint or ""
            # Path/word-boundary match, NOT bare substring: a short binary name ("rc") must sit on
            # a segment boundary of the endpoint, so per(rc)ent does not spuriously attach.
            if any(_ref_at_boundary(n, ep) for n in names):
                web_named = True
                sites.append(
                    {
                        "kind": "web_endpoint",
                        "asset": asset,
                        "asset_type": asset_type,
                        "method": method,
                        "endpoint": ep,
                        "arg_source": source,
                    }
                )
        # ★ Exec sites are keyed by the launched binary's PATH, because that is what identifies
        # the file — two binaries in one firmware can share a short name, and a site attached to
        # the name would be offered to both. The short names stay in the lookup set so a key that
        # is a script path's basename, or a name-keyed site from another producer, still matches;
        # the path is tried first and is what a same-name pair is separated by.
        for key in (binary_path, *sorted(names)):
            if key:
                sites.extend(self._exec_sites.get(key, ()))
        # ★ The inference goes LAST, after every direct reference, and only to a binary no web
        # asset names: a named CGI keeps exactly the site list it had, so the one place the two
        # can be told apart stays clean.
        inferred = None if web_named else self._served_site(binary_path)
        if inferred is not None:
            sites.append(inferred)
        return sites

    def _served_site(self, binary_path: str | None) -> dict[str, Any] | None:
        """The inferred ``web_endpoint`` site for a CGI file placed in a served tree; None when
        the binary is not a CGI file, sits in no served tree, or has no recorded path (a tree is a
        statement about placement, and an unplaced file has none)."""
        if not binary_path or not binary_path.endswith(CGI_SUFFIX):
            return None
        under = [r for r in self._served_roots if binary_path.startswith(r.directory + "/")]
        if not under:
            return None
        # The most specific tree the file sits in, so the note names the nearest served directory;
        # the path order breaks a tie, keeping the stored text the same on every re-hunt.
        root = sorted(under, key=lambda r: (-len(r.directory), r.directory))[0]
        return {
            "kind": "web_endpoint",
            "basis": "inferred",
            "note": (
                f"co-located with proven CGI {root.seed} under served root {root.rel_directory}"
            ),
        }


def load_entry_index(
    conn: sqlite3.Connection, exec_sites: dict[str, list[dict[str, Any]]] | None = None
) -> EntryIndex:
    """Load the L0.5 entry-evidence tables once (read-only). Missing tables yield an empty index
    (an older analysis.db without L0.5 simply produces ``entry_reach=unknown`` everywhere).

    ``exec_sites`` comes from a different source than the two tables here — it is computed during
    the hunt from the call provenance, keyed by the binary being launched. Omitting it degrades to
    the rootfs-only index rather than failing, so the two sources stay independent.

    The served-root prescan runs here, on this same connection and before the index any candidate
    is read with exists: it needs every binary at once, which is exactly what this one-per-
    analysis.db load has in front of it. It is seeded from a PROBE index holding the web assets
    alone, so only a real endpoint name match can produce a root (see :func:`served_cgi_roots`)."""
    # ★ An older analysis.db has no via / via_line columns, and this read is read-only so no
    # migration adds them. Asking for them there would raise, and the except below would turn
    # every script entry into "none found" — so the columns are asked for only when present.
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(script_calls)")}
    except sqlite3.OperationalError:
        cols = set()
    via_cols = "c.via, c.via_line" if {"via", "via_line"} <= cols else "NULL, NULL"
    try:
        sc = conn.execute(
            f"SELECT f.path, c.command, c.line_number, c.args_pattern, {via_cols} "  # noqa: S608
            "FROM script_calls c JOIN non_binary_files f ON f.id = c.file_id "
            "ORDER BY f.path, c.line_number, c.id"
        ).fetchall()
    except sqlite3.OperationalError:
        sc = []
    try:
        we = conn.execute(
            "SELECT f.path, e.asset_type, e.method, e.path, e.source "
            "FROM web_endpoints e JOIN non_binary_files f ON f.id = e.file_id "
            "ORDER BY e.path"
        ).fetchall()
    except sqlite3.OperationalError:
        we = []
    script_calls = [(r[0], r[1], r[2], r[3], r[4], r[5]) for r in sc]
    web_endpoints = [(r[0], r[1], r[2], r[3], r[4]) for r in we]
    return EntryIndex(
        script_calls,
        web_endpoints,
        exec_sites=exec_sites,
        served_roots=served_cgi_roots(conn, EntryIndex([], web_endpoints)),
    )
