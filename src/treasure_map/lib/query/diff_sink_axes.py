# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The secondary sink facts a diff view hands on beside a candidate row, and the guard links.

READ-ONLY and DERIVED: every value here is what a candidate's own hunt record (``instance.
flow_evidence``) already holds, read through the triage readers, cut to a bounded size. Nothing is
recomputed, ranked or judged.

AXES (``sink_axes``, one object per side of a row): ``bound`` (the write length: ``size_kind``,
``size_flow``, the clamp shapes seen, ``trace_boundary``, ``format_string`` / ``objsize`` when the
record has them), ``source`` (``source_kind``), ``flow_path`` (the sink argument and its one-hop
sources, with ``trace_boundary``), ``sanitizer`` (the sanitizer-shaped calls seen, coverage always
``unjudged``) and ``def_use`` (the sink argument provenance records of this call). An axis is given
when the RECORD carries its field, whatever the sink class; the class only picks the reason an axis
is not given (``unavailable``): ``no_evidence`` (no row, or no readable record), ``ambiguous_ref``
(several rows share the ref and disagree on this axis), ``class_unknown``,
``not_recorded_for_class`` (this class's records do not hold the field) or ``not_in_record`` (they
do, this one does not). ``unavailable`` says the fact was not recorded or not single — never that
the thing it would describe is absent.

GUARD LINKS (``guard_links``, on a row with a B-side candidate): whether an introduced comparison's
variable (lib/query/sameness's guard scan) is, BY NAME, the candidate's sink argument
(``sink_arg``, from ``flow_path``) or its length variable (``size_arg``, from ``size_flow``), or one
of their one-hop sources. ``yes`` = the name is one of them; ``no`` = the one-hop reading was
complete and the name is not; ``unknown`` = anything else. A name match only: where the comparison
sits, whether it lies on the way to the sink, dominates it or suffices is not read.

A recorded sink argument or length variable counts as a variable only when the B body's text holds
it as an identifier and it is not a type name (:data:`TYPE_NAMES`): a record can hold a fragment
of the argument instead — the type of a cast (``*(char **)(p + 8)`` read as ``char``), the digits
of a hex constant, a word of a string. Such a link reads as if no variable were recorded: never
``no``.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from treasure_map.lib.callsite_ref import callsite_abs_addr
from treasure_map.lib.query.triage import (
    _as_evidence,
    _flow_list,
    _flow_path_obj,
    _sanitizer_records,
    _source_kind_from_evidence,
    _writer_scoped_records,
)

AXES = ("bound", "source", "flow_path", "sanitizer", "def_use")
# The axes each sink class's hunt records hold. Used ONLY to name why an axis is not given; an
# axis the record does carry is given whatever its class.
DECLARED_AXES: dict[str, tuple[str, ...]] = {
    "cmd": ("source", "flow_path", "sanitizer", "def_use"),
    "fmt_string": ("source", "flow_path", "sanitizer", "def_use"),
    "path_sink": ("source", "flow_path", "sanitizer"),
    "copy": ("bound",),
    "format": ("bound",),
}
UNKNOWN_CLASS = "unknown"
# List fields of an axis (one_hop, clamp_seen, sanitizer.seen, def_use.records) are cut to this
# many, with a ``*_total``; a guard link always reads the whole lists.
AXIS_LIST_LIMIT = 5
# A def_use record's ``value`` is cut to this many characters (``value_len`` gives the length).
VALUE_LIMIT = 200
# How many of a pair's introduced comparisons an entry shows inline.
GUARD_INLINE_LIMIT = 20
# The link each guard is read against, and the axis whose field it reads.
LINKS = (("sink_arg", "flow_path"), ("size_arg", "bound"))
# Names that are types, never a variable: C's type keywords, the common typedefs and the
# decompiler's own built-in types (a cast in its output writes them).
TYPE_NAMES = frozenset(
    {
        "char",
        "short",
        "int",
        "long",
        "float",
        "double",
        "void",
        "signed",
        "unsigned",
        "bool",
        "_Bool",
        "size_t",
        "ssize_t",
        "wchar_t",
        "byte",
        "sbyte",
        "uchar",
        "ushort",
        "uint",
        "ulong",
        "longlong",
        "ulonglong",
        "word",
        "dword",
        "qword",
        "code",
        "undefined",
        "float10",
        "longdouble",
        "wchar16",
        "wchar32",
    }
)
# ... and these forms: ``int8_t`` .. ``uint64_t``, the decompiler's odd-width ``int3`` /
# ``uint5`` .., ``undefined1`` .. ``undefined8``.
_TYPE_NAME_FORMS = re.compile(r"u?int(?:8|16|32|64)_t|u?int[35-7]|undefined[1-8]")
_SOURCE_RESOLVED_UNTRACED = ("free_string", "charset_safe")
_REACHED = "reached_sink"
_REF_CHUNK = 500
_ABSENT: Any = object()


@dataclass(frozen=True)
class RowAxes:
    """One instance row of a candidate, parsed once and cut to what the view gives: ``axes`` holds
    the axes its record carries (output-ready), ``links`` each guard link's whole inputs (None when
    the record lacks the field the link reads). ``parsed`` is False for a row with no readable
    record."""

    parsed: bool
    axes: dict[str, Any]
    links: dict[str, tuple[Any, ...] | None]


class AxisCache(Protocol):
    def get(self, key: tuple[str, ...]) -> tuple[RowAxes, ...] | None: ...

    def __setitem__(self, key: tuple[str, ...], value: tuple[RowAxes, ...]) -> None: ...


def _names(raw: Any) -> list[str]:
    return [x for x in raw if isinstance(x, str)] if isinstance(raw, list) else []


def _bound(fe: Mapping[str, Any]) -> dict[str, Any]:
    flow = fe.get("size_flow")
    sf: Mapping[str, Any] = flow if isinstance(flow, dict) else {}
    one_hop = _names(sf.get("one_hop"))
    clamps = _flow_list(fe, "clamp_seen")
    out: dict[str, Any] = {
        "size_kind": fe.get("size_kind"),
        "size_arg": sf.get("size_arg"),
        "size_var": sf.get("size_var"),
        "one_hop": one_hop[:AXIS_LIST_LIMIT],
        "one_hop_total": len(one_hop),
        "trace_boundary": fe.get("trace_boundary"),
        "clamp_seen": clamps[:AXIS_LIST_LIMIT],
        "clamp_seen_total": len(clamps),
    }
    for key in ("format_string", "objsize"):
        if key in fe:
            out[key] = fe[key]
    return out


def _flow(fe: Mapping[str, Any], fp: dict[str, Any]) -> dict[str, Any]:
    one_hop = _names(fp.get("one_hop"))
    via = fp.get("sink_via_wrapper") is True
    out: dict[str, Any] = {
        "sink_arg": fp.get("sink_arg"),
        "one_hop": one_hop[:AXIS_LIST_LIMIT],
        "one_hop_total": len(one_hop),
        "trace_boundary": fe.get("trace_boundary"),
        "via_wrapper": via,
    }
    if via:
        wrapper = fp.get("wrapper")
        out["wrapped_sink"] = wrapper.get("wrapped_sink") if isinstance(wrapper, dict) else None
    return out


def _def_use_record(rec: dict[str, Any]) -> dict[str, Any]:
    raw = rec.get("provenance")
    prov: Mapping[str, Any] = raw if isinstance(raw, dict) else {}
    value = prov.get("value")
    out: dict[str, Any] = {
        "sink_idx": rec.get("sink_idx"),
        "arg_idx": rec.get("arg_idx"),
        "sink": rec.get("sink"),
        "sink_addr": rec.get("sink_addr"),
        "kind": prov.get("kind"),
        "value_kind": prov.get("value_kind"),
        "value": value,
    }
    if isinstance(value, str) and len(value) > VALUE_LIMIT:
        out["value"] = value[:VALUE_LIMIT]
        out["value_len"] = len(value)
    if "recovered_by" in rec:
        out["recovered_by"] = rec["recovered_by"]
    return out


def _def_use(fe: Mapping[str, Any], sink_anchor: str | None, ref: str) -> dict[str, Any]:
    """The records ``_writer_scoped_records`` scopes to this candidate — strictly, never falling
    back to a sibling call's — and the scope it applied, in its own branch order: no sink anchor ->
    ``unscoped`` (every record of the function); no call address in the ref -> ``sink_name`` (the
    function's records of a sink of that name, not of this call); else ``callsite``."""
    addr = callsite_abs_addr(ref)
    scope = "unscoped" if not sink_anchor else ("sink_name" if addr is None else "callsite")
    recs = _writer_scoped_records(fe, sink_anchor, callsite_addr=addr)
    return {
        "scope": scope,
        "records": [_def_use_record(r) for r in recs[:AXIS_LIST_LIMIT]],
        "records_total": len(recs),
    }


def parse_row(ref: str, sink_anchor: str | None, flow_evidence: str | None) -> RowAxes:
    """One instance row, parsed and cut. The raw record is not kept."""
    fe = _as_evidence(flow_evidence)
    if not fe:
        return RowAxes(False, {}, {"sink_arg": None, "size_arg": None})
    axes: dict[str, Any] = {}
    links: dict[str, tuple[Any, ...] | None] = {"sink_arg": None, "size_arg": None}
    tb = fe.get("trace_boundary")
    if "size_kind" in fe or "size_flow" in fe:
        axes["bound"] = _bound(fe)
        flow = fe.get("size_flow")
        sf: Mapping[str, Any] = flow if isinstance(flow, dict) else {}
        links["size_arg"] = (sf.get("size_var"), tuple(_names(sf.get("one_hop"))), tb)
    if "source_kind" in fe:
        axes["source"] = {"source_kind": _source_kind_from_evidence(fe)}
    if isinstance(fe.get("flow_path"), dict):
        fp = _flow_path_obj(fe)
        axes["flow_path"] = _flow(fe, fp)
        links["sink_arg"] = (
            fp.get("sink_arg"),
            tuple(_names(fp.get("one_hop"))),
            tb,
            _source_kind_from_evidence(fe),
        )
    if "sanitizer_seen" in fe:
        seen = _sanitizer_records(fe)
        axes["sanitizer"] = {"seen": seen[:AXIS_LIST_LIMIT], "seen_total": len(seen)}
    if "sink_arg_provenance" in fe:
        axes["def_use"] = _def_use(fe, sink_anchor, ref)
    return RowAxes(True, axes, links)


def fetch(
    atlas: sqlite3.Connection,
    run_id: str,
    refs: Iterable[str],
    cache: AxisCache,
    prefix: tuple[str, ...],
) -> dict[str, tuple[RowAxes, ...]]:
    """ref -> its instance rows in run ``run_id``, parsed and cut (an empty tuple for a ref with no
    row), cached under ``prefix + (ref,)`` — the caller's key for this atlas and this run's stamps,
    so a re-hunt is never served the earlier rows. Only the refs not cached are read."""
    out: dict[str, tuple[RowAxes, ...]] = {}
    missing: list[str] = []
    for ref in sorted(set(refs)):
        hit = cache.get((*prefix, ref))
        if hit is None:
            missing.append(ref)
        else:
            out[ref] = hit
    for i in range(0, len(missing), _REF_CHUNK):
        chunk = missing[i : i + _REF_CHUNK]
        marks = ", ".join("?" * len(chunk))
        found: dict[str, list[RowAxes]] = {ref: [] for ref in chunk}
        # ``+source_run_id`` keeps the planner on the evidence_ref index: a run-wide scan per page
        # would read every row of the run for a few refs.
        for ref, anchor, flow in atlas.execute(
            "SELECT evidence_ref, sink_anchor, flow_evidence FROM instance "
            f"WHERE +source_run_id = ? AND evidence_ref IN ({marks}) ORDER BY instance_id",
            (run_id, *chunk),
        ):
            found[ref].append(parse_row(ref, anchor, flow))
        for ref, rows in found.items():
            cache[(*prefix, ref)] = out[ref] = tuple(rows)
    return out


def _missing_reason(axis: str, cls: str | None) -> str:
    if cls is None or cls == UNKNOWN_CLASS:
        return "class_unknown"
    if axis not in DECLARED_AXES.get(cls, ()):
        return "not_recorded_for_class"
    return "not_in_record"


def _single(
    rows: tuple[RowAxes, ...], values: list[Any], axis: str, cls: str | None
) -> tuple[bool, Any]:
    """(True, the value every row agrees on) or (False, why there is none), in the reasons' order:
    no readable row; rows that disagree; else the field is absent from the record. ``values`` holds
    each row's value, ``_ABSENT`` where the row has none (or no readable record)."""
    if not any(r.parsed for r in rows):
        return False, "no_evidence"
    first = values[0]
    for v in values[1:]:
        if (v is _ABSENT) != (first is _ABSENT) or (v is not _ABSENT and v != first):
            return False, "ambiguous_ref"
    if first is _ABSENT:
        return False, _missing_reason(axis, cls)
    return True, first


def side_axes(rows: tuple[RowAxes, ...], cls: str | None) -> dict[str, Any]:
    """One side's ``sink_axes``: each axis its record gives, in ``AXES`` order, and the others
    grouped under ``unavailable`` by reason."""
    out: dict[str, Any] = {"class": cls}
    unavailable: dict[str, list[str]] = {}
    for axis in AXES:
        values = [r.axes.get(axis, _ABSENT) if r.parsed else _ABSENT for r in rows]
        ok, value = _single(rows, values, axis, cls)
        if ok:
            out[axis] = value
        else:
            unavailable.setdefault(value, []).append(axis)
    out["unavailable"] = unavailable
    return out


def _sink_arg(inputs: tuple[Any, ...], var: str) -> str:
    """yes = the variable is the sink argument or one of its one-hop sources; no = the one-hop
    reading was complete (a sink argument, the trace stopped at the sink, and not because the
    source was classified without reading the chain — free_string / charset_safe stop there with
    no depth read) and the variable is none of them; else unknown. A wrapper-forwarded candidate
    never reads no (its trace stops one hop past the call)."""
    sink_arg, one_hop, boundary, source_kind = inputs
    names = set(one_hop) | ({sink_arg} if sink_arg else set())
    if var in names:
        return "yes"
    if sink_arg and boundary == _REACHED and source_kind not in _SOURCE_RESOLVED_UNTRACED:
        return "no"
    return "unknown"


def _size_arg(inputs: tuple[Any, ...], var: str) -> str:
    """yes = the variable is the length variable or one of its one-hop sources; no = there is a
    length variable, the size trace stopped at the sink (one hop at most, no indirect call or
    untracked copy) and the variable is none of them; else unknown — a constant or sizeof length
    has no length variable, so it is unknown too."""
    size_var, one_hop, boundary = inputs
    if not size_var:
        return "unknown"
    if var in {size_var, *one_hop}:
        return "yes"
    return "no" if boundary == _REACHED else "unknown"


_VERDICT: dict[str, Callable[[tuple[Any, ...], str], str]] = {
    "sink_arg": _sink_arg,
    "size_arg": _size_arg,
}


@dataclass(frozen=True)
class LinkRow:
    """What one rendered row with a B-side candidate brings to the guard links: whether that
    candidate lies in the entry's B function (``same_function``), its rows, and its class."""

    same_function: bool
    rows: tuple[RowAxes, ...]
    cls: str | None


def is_type_name(name: str) -> bool:
    """Whether ``name`` is a type (:data:`TYPE_NAMES` and its forms), never a variable."""
    return name in TYPE_NAMES or _TYPE_NAME_FORMS.fullmatch(name) is not None


def _as_variable(inputs: tuple[Any, ...], b_names: frozenset[str]) -> tuple[Any, ...]:
    """A link's inputs with its recorded variable (the first) set to None unless it is a variable of
    the B body: a name its text holds as an identifier, and not a type name."""
    name = inputs[0]
    if isinstance(name, str) and name in b_names and not is_type_name(name):
        return inputs
    return (None, *inputs[1:])


def _row_verdicts(
    row: LinkRow, guards: list[dict[str, Any]], b_names: frozenset[str]
) -> dict[str, Any]:
    """link -> ``{"unavailable": reason}``, or the verdict of each guard (in the scan's order). The
    rows agree or not on what they RECORDED; the verdict then reads the recorded variable only as a
    variable of the B body (:func:`_as_variable`)."""
    if not row.same_function:
        return {link: {"unavailable": "other_function"} for link, _axis in LINKS}
    out: dict[str, Any] = {}
    for link, axis in LINKS:
        values = [_ABSENT if r.links[link] is None else r.links[link] for r in row.rows]
        ok, inputs = _single(row.rows, values, axis, row.cls)
        if not ok:
            out[link] = {"unavailable": inputs}
        else:
            inputs = _as_variable(inputs, b_names)
            out[link] = {"verdicts": [_VERDICT[link](inputs, g["var"]) for g in guards]}
    return out


def _nonzero(counts: Any) -> dict[str, Any]:
    return {k: v for k, v in counts.items() if v} if isinstance(counts, dict) else {}


def entry_guards(
    scan: Mapping[str, Any], rows: list[LinkRow | None]
) -> tuple[dict[str, Any], list[dict[str, Any] | None]]:
    """(the entry's guard fields, each rendered row's ``guard_links`` or None), for one pair's guard
    scan and its rendered rows (None for a row with no B-side candidate).

    ``guards`` shows at most ``GUARD_INLINE_LIMIT`` of the stored list, in B order. With rows to
    link (``shown_rule`` ``linked_first_then_b_order``) the guards any row links ``yes`` are taken
    first — the first ``GUARD_INLINE_LIMIT`` of them in B order when there are more, the rest
    counted in ``linked_not_shown`` — and the others fill the list in B order; with none
    (``b_order``) the first ones are taken. A selection by a mechanism fact, never a ranking;
    another window of the same entry's rows can show another selection. ``guard_links`` index into
    the shown list.

    ``guard_scan`` gives no field its reader can derive: a count that is 0 (``linked_not_shown``,
    ``renumbered_in_a``, a ``by_const_class`` / ``other_comparisons`` key — the whole object when
    every key is 0) and ``shown_rule`` with nothing shown are left out; the stored count is
    min(``var_const_total``, ``GUARD_STORE_LIMIT``) and the shown one ``len(guards)``. A scan done
    with nothing found still carries ``guards: []``; a ``not_extracted`` one carries no ``guards``
    key."""
    if scan.get("state") != "done":
        withheld = {"guard_scan": {"state": scan.get("state"), "reason": scan.get("reason")}}
        return withheld, [None] * len(rows)
    stored: list[dict[str, Any]] = list(scan.get("guards") or [])
    b_names: frozenset[str] = scan.get("b_names") or frozenset()
    verdicts = [None if r is None else _row_verdicts(r, stored, b_names) for r in rows]
    if any(r is not None for r in rows):
        rule = "linked_first_then_b_order"
        linked = sorted(
            {
                i
                for v in verdicts
                if v is not None
                for state in v.values()
                for i, word in enumerate(state.get("verdicts", ()))
                if word == "yes"
            }
        )
        chosen = linked[:GUARD_INLINE_LIMIT]
        linked_not_shown = len(linked) - len(chosen)
        taken = set(linked)
        chosen += [i for i in range(len(stored)) if i not in taken][
            : GUARD_INLINE_LIMIT - len(chosen)
        ]
        chosen.sort()
    else:
        rule = "b_order"
        chosen = list(range(min(GUARD_INLINE_LIMIT, len(stored))))
        linked_not_shown = 0
    guard_scan: dict[str, Any] = {
        "state": "done",
        "coverage": "unjudged",
        "var_const_total": scan.get("var_const_total"),
    }
    for key, value in (
        ("by_const_class", _nonzero(scan.get("by_const_class"))),
        ("shown_rule", rule if chosen else None),
        ("linked_not_shown", linked_not_shown),
        ("renumbered_in_a", scan.get("renumbered_in_a")),
        ("other_comparisons", _nonzero(scan.get("other_comparisons"))),
    ):
        if value:
            guard_scan[key] = value
    fields: dict[str, Any] = {"guard_scan": guard_scan, "guards": [stored[i] for i in chosen]}
    position = {i: n for n, i in enumerate(chosen)}
    links: list[dict[str, Any] | None] = []
    for v in verdicts:
        if v is None or not chosen:
            links.append(None)
            continue
        row_links: dict[str, Any] = {}
        for link, _axis in LINKS:
            state = v[link]
            if "unavailable" in state:
                row_links[link] = state
                continue
            groups: dict[str, list[int]] = {"yes": [], "no": [], "unknown": []}
            for i in chosen:
                groups[state["verdicts"][i]].append(position[i])
            row_links[link] = groups
        links.append(row_links)
    return fields, links
