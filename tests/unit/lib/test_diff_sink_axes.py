# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The secondary sink axes and the guard links (lib/query/diff_sink_axes), as pure functions over
hand-written hunt records. No database except where the fetch itself is under test; the view's
wiring is exercised in test_patch_view."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from treasure_map.lib.query import diff_sink_axes as ax
from treasure_map.lib.query import sameness as sm

# A per-callsite ref in the real shape: the call is at 0x401000 + 0x10.
REF = "runB#deadbeef:00401000@cmd@0x10"
FN_REF = "runB#deadbeef:00401000@cmd"  # function-level: no call address
# The names the fixtures' records hold as sink arguments / length variables, all of them names
# the B body holds (a guard link reads a recorded name only as a variable of that body).
B_NAMES = frozenset({"pcVar2", "local_118", "n", "m", "len"})


def _rows(*records: dict[str, Any] | None, ref: str = REF, anchor: str | None = "system") -> Any:
    return tuple(
        ax.parse_row(ref, anchor, json.dumps(r) if r is not None else None) for r in records
    )


def _cmd(**over: Any) -> dict[str, Any]:
    rec: dict[str, Any] = {
        "source_kind": "unknown",
        "flow_path": {"sink_arg": "pcVar2", "one_hop": ["local_118"]},
        "sanitizer_seen": [],
        "trace_boundary": "reached_sink",
        "sink_arg_provenance": [],
    }
    rec.update(over)
    return rec


def _copy(**over: Any) -> dict[str, Any]:
    rec: dict[str, Any] = {
        "size_kind": "variable",
        "size_flow": {"size_arg": "n", "size_var": "n", "one_hop": ["len"]},
        "clamp_seen": [],
        "trace_boundary": "reached_sink",
    }
    rec.update(over)
    return rec


def _scan(*names: str, b_names: frozenset[str] = B_NAMES) -> dict[str, Any]:
    """A done guard scan of ``names`` (one ``== 0`` guard each, in this order), in the shape
    sameness gives it: ``b_names`` (the B body's identifiers) whenever there is a guard."""
    guards = [
        {"var": n, "const": "0", "relation": "==", "const_class": "zero", "line_b": i + 1}
        for i, n in enumerate(names)
    ]
    scan: dict[str, Any] = {
        "state": "done",
        "var_const_total": len(guards),
        "by_const_class": {"zero": len(guards), "nonzero": 0},
        "other_comparisons": {"var_var": 0, "call": 0, "field": 0, "other": 0},
        "guards": guards,
    }
    if guards:
        scan["b_names"] = b_names | set(names)
    return scan


def _links(record: dict[str, Any], var: str, cls: str = "cmd") -> dict[str, Any]:
    _fields, links = ax.entry_guards(_scan(var), [ax.LinkRow(True, _rows(record), cls)])
    (one,) = links
    assert one is not None
    return one


# ── sink_arg ─────────────────────────────────────────────────────────────────────────────────


def test_a_one_hop_source_named_by_the_guard_is_yes() -> None:
    """L1: the guard's variable is the sink argument's one-hop source -> sink_arg yes."""
    assert _links(_cmd(), "local_118")["sink_arg"] == {"yes": [0], "no": [], "unknown": []}
    assert _links(_cmd(), "pcVar2")["sink_arg"] == {"yes": [0], "no": [], "unknown": []}


def test_a_complete_one_hop_reading_that_misses_the_name_is_no() -> None:
    """L2: a sink argument, the trace stopped at the sink, a source classified by reading the
    chain, and the name is neither the argument nor a one-hop source -> no."""
    assert _links(_cmd(), "iVar9")["sink_arg"] == {"yes": [], "no": [0], "unknown": []}


def test_a_source_classified_without_reading_the_chain_is_unknown() -> None:
    """L3: free_string / charset_safe stop the trace at the sink without reading its depth, so a
    missed name there is unknown, never no.

    MUTATION M1 (verified RED, 1 failed): drop the source_kind condition of no -> RED."""
    for kind in ("free_string", "charset_safe"):
        got = _links(_cmd(source_kind=kind), "iVar9")["sink_arg"]
        assert got == {"yes": [], "no": [], "unknown": [0]}, kind


def test_no_sink_argument_is_unknown() -> None:
    """L4: with no sink argument the trace reads reached_sink without having traced anything ->
    unknown.

    MUTATION M2 (verified RED, 1 failed): drop the "sink argument present" condition of no ->
    RED."""
    rec = _cmd(flow_path={"sink_arg": None, "one_hop": []})
    assert _links(rec, "iVar9")["sink_arg"] == {"yes": [], "no": [], "unknown": [0]}


def test_a_wrapper_forwarded_candidate_is_only_yes_or_unknown() -> None:
    """L5: a candidate whose sink is one hop away in a thin wrapper never reads no."""
    rec = _cmd(
        flow_path={
            "sink_arg": "pcVar2",
            "one_hop": [],
            "sink_via_wrapper": True,
            "wrapper": {"name": "run_it", "wrapped_sink": "system"},
        },
        trace_boundary="reached_sink_via_one_hop_wrapper",
    )
    assert _links(rec, "pcVar2")["sink_arg"]["yes"] == [0]
    assert _links(rec, "iVar9")["sink_arg"] == {"yes": [], "no": [], "unknown": [0]}


# ── size_arg ─────────────────────────────────────────────────────────────────────────────────


def test_the_length_link_reads_size_flow() -> None:
    """L6: a) the length variable's one-hop source -> yes; b) a length variable, the size trace at
    the sink, the name missed -> no; c) no length variable -> unknown; d) a length variable but the
    trace went two hops -> unknown.

    MUTATION M10 (verified RED, 1 failed): drop the reached_sink condition of the length link's
    no -> (d) reads no -> RED."""
    assert _links(_copy(), "len", "copy")["size_arg"] == {"yes": [0], "no": [], "unknown": []}
    assert _links(_copy(), "iVar9", "copy")["size_arg"] == {"yes": [], "no": [0], "unknown": []}
    const = _copy(size_kind="const", size_flow={"size_arg": "0x40", "size_var": None})
    assert _links(const, "iVar9", "copy")["size_arg"] == {"yes": [], "no": [], "unknown": [0]}
    deep = _copy(trace_boundary="two_hop_untraced")
    assert _links(deep, "iVar9", "copy")["size_arg"] == {"yes": [], "no": [], "unknown": [0]}


def test_the_link_reads_the_whole_one_hop_list_not_the_shown_one() -> None:
    """L8: seven one-hop names, the guard's is the seventh: yes — while the axis shows five.

    MUTATION M15 (verified RED, 1 failed): link against the cut list -> RED."""
    hops = [f"local_{i}" for i in range(7)]
    rec = _cmd(flow_path={"sink_arg": "pcVar2", "one_hop": hops})
    assert _links(rec, "local_6")["sink_arg"]["yes"] == [0]
    side = ax.side_axes(_rows(rec), "cmd")
    assert side["flow_path"]["one_hop"] == hops[:5]
    assert side["flow_path"]["one_hop_total"] == 7


def test_a_candidate_in_another_function_links_nothing() -> None:
    """L10: the row's B-side candidate lies outside the pair's B function -> other_function on both
    links, whatever its record would say.

    MUTATION M16 (verified RED, 1 failed): drop the same-function check -> sink_arg reads yes ->
    RED."""
    _f, (links,) = ax.entry_guards(_scan("pcVar2"), [ax.LinkRow(False, _rows(_cmd()), "cmd")])
    assert links == {
        "sink_arg": {"unavailable": "other_function"},
        "size_arg": {"unavailable": "other_function"},
    }


def test_a_field_the_record_holds_is_read_whatever_the_class() -> None:
    """L11 (data, not class): a copy record that carries flow_path is linked on sink_arg — the
    class only names why a field is missing.

    MUTATION M3 (verified RED, 1 failed): make copy / format's sink_arg unavailable by class ->
    RED."""
    rec = {**_copy(), "flow_path": {"sink_arg": "pcVar2", "one_hop": []}, "source_kind": "unknown"}
    got = _links(rec, "pcVar2", "copy")
    assert got["sink_arg"] == {"yes": [0], "no": [], "unknown": []}
    assert ax.side_axes(_rows(rec), "copy")["flow_path"]["sink_arg"] == "pcVar2"
    assert _links(_copy(), "pcVar2", "copy")["sink_arg"] == {
        "unavailable": "not_recorded_for_class"
    }


# ── which guards are shown ───────────────────────────────────────────────────────────────────


def test_a_linked_guard_is_shown_ahead_of_the_rest_and_the_list_stays_in_b_order() -> None:
    """L9: 25 guards, the 23rd named by the row's sink argument: it is shown (20 of 25), its yes
    index points at it, and the shown list keeps B order.

    MUTATION M14 (verified RED, 1 failed): cut to the first 20 before linking -> RED."""
    names = [f"v{i}" for i in range(25)]
    names[22] = "pcVar2"
    fields, (links,) = ax.entry_guards(_scan(*names), [ax.LinkRow(True, _rows(_cmd()), "cmd")])
    shown = [g["var"] for g in fields["guards"]]
    assert len(shown) == 20 and "pcVar2" in shown
    assert shown == sorted(shown, key=names.index)  # B order
    assert links is not None
    assert [shown[i] for i in links["sink_arg"]["yes"]] == ["pcVar2"]
    scan = fields["guard_scan"]
    assert scan["var_const_total"] == 25
    assert scan["shown_rule"] == "linked_first_then_b_order"
    # Derivable or zero counts are left out: stored = min(total, 200), shown = len(guards).
    assert not {"stored", "shown", "linked_not_shown"} & set(scan)


def test_more_linked_guards_than_fit_are_the_first_in_b_order_and_counted() -> None:
    """L9b: 30 guards, every one named in the sink argument's one-hop sources: the first 20 in B
    order, linked_not_shown 10.

    MUTATION M19 (verified RED, 1 failed): do not count the linked ones left out -> RED; take the
    last ones -> RED."""
    names = [f"local_{i}" for i in range(30)]
    rec = _cmd(flow_path={"sink_arg": "pcVar2", "one_hop": names})
    fields, (links,) = ax.entry_guards(_scan(*names), [ax.LinkRow(True, _rows(rec), "cmd")])
    assert [g["var"] for g in fields["guards"]] == names[:20]
    assert fields["guard_scan"].get("linked_not_shown") == 10
    assert links is not None and links["sink_arg"]["yes"] == list(range(20))


def test_with_no_row_to_link_the_first_are_shown_in_b_order() -> None:
    """G8 / L9c (selection side): no row -> b_order, the first 20 of 25 shown, nothing linked."""
    names = [f"v{i}" for i in range(25)]
    fields, links = ax.entry_guards(_scan(*names), [])
    assert links == []
    assert [g["var"] for g in fields["guards"]] == names[:20]
    assert fields["guard_scan"].get("shown_rule") == "b_order"
    assert "linked_not_shown" not in fields["guard_scan"]
    assert set(fields) == {"guard_scan", "guards"}  # the B body is read by the envelope's recipe


def test_a_scan_not_extracted_gives_its_reason_and_no_guards_key() -> None:
    fields, links = ax.entry_guards(
        {"state": "not_extracted", "reason": "too_large"},
        [ax.LinkRow(True, _rows(_cmd()), "cmd")],
    )
    assert fields == {"guard_scan": {"state": "not_extracted", "reason": "too_large"}}
    assert links == [None]


def test_a_scan_that_found_nothing_gives_only_what_cannot_be_derived() -> None:
    """A done scan with no guard and no other comparison: ``guard_scan`` is its state, coverage and
    total alone (no zero count, no shown_rule), ``guards`` is ``[]`` — told apart from
    ``not_extracted``, which has no ``guards`` key — and a row with a B-side candidate gets no
    links (there is no shown guard to link).

    MUTATION (verified RED, 1 failed): give guard_links whenever a row has a B-side candidate,
    shown guards or not -> RED.
    MUTATION (verified RED, 1 failed): keep the zero-valued by_const_class keys -> RED."""
    empty = _scan()
    fields, links = ax.entry_guards(empty, [ax.LinkRow(True, _rows(_cmd()), "cmd")])
    assert fields == {
        "guard_scan": {"state": "done", "coverage": "unjudged", "var_const_total": 0},
        "guards": [],
    }
    assert links == [None]
    counted = {**empty, "other_comparisons": {"var_var": 2, "call": 0, "field": 0, "other": 1}}
    fields, _links = ax.entry_guards(counted, [])
    assert fields["guard_scan"].get("other_comparisons") == {"var_var": 2, "other": 1}
    assert "by_const_class" not in fields["guard_scan"]


def test_a_renumbered_count_is_given_only_when_there_is_one() -> None:
    """``renumbered_in_a`` (sameness marks the guards; the scan counts them) is carried into
    guard_scan when it is above 0, and the shown guard keeps its mark."""
    scan = _scan("uVar13")
    scan["guards"][0]["renumbered_in_a"] = {"a_name": "uVar9"}
    scan["renumbered_in_a"] = 1
    fields, _links = ax.entry_guards(scan, [])
    assert fields["guard_scan"].get("renumbered_in_a") == 1
    assert fields["guards"][0].get("renumbered_in_a") == {"a_name": "uVar9"}
    fields, _links = ax.entry_guards(_scan("uVar13"), [])
    assert "renumbered_in_a" not in fields["guard_scan"]


# ── a recorded name that is no variable of the B body ────────────────────────────────────────


def _real_scan(a: str, b: str) -> dict[str, Any]:
    scan = sm.pseudocode_delta_and_guards(a, b, None, None, "1000", "2000")[1]
    assert scan["guards"], "the fixture must introduce a guard"
    return scan


def _verdict(scan: dict[str, Any], record: dict[str, Any], cls: str, link: str) -> Any:
    _f, (links,) = ax.entry_guards(scan, [ax.LinkRow(True, _rows(record), cls)])
    assert links is not None
    return links[link]


def test_a_type_name_read_from_a_cast_is_no_variable() -> None:
    """The hunt read ``remove(*(char **)(param_1 + 0xb8))``'s argument as ``char`` (the cast's
    type, with no one-hop source) and its trace reached the sink: the B body's new
    ``if (param_1 == 0)`` is unknown on sink_arg, never no — the one hop was not read. ``char`` IS
    an identifier of the B text (inside the cast), so only the type-name table tells it apart.
    The same for a length variable read as ``size_t``.

    MUTATION (verified RED, 1 failed): drop the type-name table (keep the B-names check) ->
    sink_arg reads no -> RED."""
    a = "void f(int param_1) {\n  remove(*(char **)(param_1 + 0xb8));\n}"
    b = a.replace("{\n", "{\n  if (param_1 == 0) return;\n", 1)
    scan = _real_scan(a, b)
    assert [g["var"] for g in scan["guards"]] == ["param_1"]
    assert "char" in scan["b_names"]
    rec = _cmd(flow_path={"sink_arg": "char", "one_hop": []})
    assert _verdict(scan, rec, "path_sink", "sink_arg") == {"yes": [], "no": [], "unknown": [0]}
    sized = "void f(int param_1) {\n  if (param_1 == 0) return;\n"
    sized += "  memcpy(d, s, (size_t)param_1);\n}"
    scan = _real_scan(a, sized)
    rec = _copy(size_flow={"size_arg": "(size_t)param_1", "size_var": "size_t", "one_hop": []})
    assert _verdict(scan, rec, "copy", "size_arg") == {"yes": [], "no": [], "unknown": [0]}


def test_a_word_of_a_string_or_a_hex_tail_is_no_variable() -> None:
    """A sink argument read as ``killall`` (a word of the string ``"killall worker"``) and a length
    variable read as ``x800`` (the tail of ``0x800``) are no identifiers of the B text — a string
    and a number token — so their links are unknown, never no.

    MUTATION (verified RED, 1 failed): drop the B-names check (keep the type-name table) ->
    both read no -> RED."""
    a = 'void f(int param_1) {\n  system("killall worker");\n  memcpy(d, s, 0x800);\n}'
    b = "void f(int param_1) {\n  if (param_1 == 0) return;\n" + a.split("{\n", 1)[1]
    scan = _real_scan(a, b)
    assert not {"killall", "worker", "x800"} & scan["b_names"]
    word = _cmd(flow_path={"sink_arg": "killall", "one_hop": []})
    assert _verdict(scan, word, "cmd", "sink_arg") == {"yes": [], "no": [], "unknown": [0]}
    tail = _copy(size_flow={"size_arg": "0x800", "size_var": "x800", "one_hop": []})
    assert _verdict(scan, tail, "copy", "size_arg") == {"yes": [], "no": [], "unknown": [0]}


def test_a_recorded_variable_of_the_b_body_still_reads_no() -> None:
    """The check never touches a real variable: ``pcVar2`` (and a length variable ``n``), held by
    the B text and missed by the guard, is no as before (L2 / L6b on a real scan)."""
    a = "void f(char *pcVar2, int n) {\n  system(pcVar2);\n  memcpy(d, s, n);\n}"
    b = "void f(char *pcVar2, int n) {\n  if (iVar9 == 0) return;\n" + a.split("{\n", 1)[1]
    scan = _real_scan(a, b)
    assert _verdict(scan, _cmd(), "cmd", "sink_arg") == {"yes": [], "no": [0], "unknown": []}
    assert _verdict(scan, _copy(), "copy", "size_arg") == {"yes": [], "no": [0], "unknown": []}


def test_the_type_names_are_types() -> None:
    for name in ("char", "size_t", "uint", "undefined4", "uint32_t", "int8_t", "code", "uint3"):
        assert ax.is_type_name(name), name
    for name in ("pcVar2", "local_10", "param_1", "uVar3", "sVar1", "n", "integer", "undefined9"):
        assert not ax.is_type_name(name), name


# ── the axes ─────────────────────────────────────────────────────────────────────────────────


def test_each_side_is_read_by_its_own_record() -> None:
    """X1: a copy side with a constant length and a format side with a capped one each give their
    own bound (the format side's format_string too); the rest is not recorded for those classes."""
    a = _rows(
        {
            "size_kind": "const",
            "size_flow": {"size_arg": "0x100", "size_var": None, "one_hop": []},
            "clamp_seen": [],
            "trace_boundary": "reached_sink",
        }
    )
    b = _rows(
        {
            "size_kind": "cap_const",
            "format_string": "literal_with_args",
            "size_flow": {"size_arg": "0x1000", "size_var": None, "one_hop": []},
            "clamp_seen": [],
            "trace_boundary": "reached_sink",
        }
    )
    sa, sb = ax.side_axes(a, "copy"), ax.side_axes(b, "format")
    assert (sa["bound"]["size_kind"], sb["bound"]["size_kind"]) == ("const", "cap_const")
    assert "format_string" not in sa["bound"]
    assert sb["bound"]["format_string"] == "literal_with_args"
    rest = {"not_recorded_for_class": ["source", "flow_path", "sanitizer", "def_use"]}
    assert sa["unavailable"] == sb["unavailable"] == rest


def test_each_reason_an_axis_is_not_given() -> None:
    """X2: no_evidence (no row / no readable record), ambiguous_ref (two rows of one ref disagree on
    THIS axis — another axis they agree on is given), class_unknown, not_recorded_for_class,
    not_in_record.

    MUTATION M17 (verified RED, 2 failed — this test and the links one below): read the first row
    of a ref -> ambiguous_ref is lost -> RED."""
    assert ax.side_axes((), "cmd")["unavailable"] == {"no_evidence": list(ax.AXES)}
    assert ax.side_axes(_rows(None), "cmd")["unavailable"] == {"no_evidence": list(ax.AXES)}
    two = _rows(_copy(), _copy(size_kind="const"))
    side = ax.side_axes(two, "copy")
    assert side["unavailable"].get("ambiguous_ref") == ["bound"]
    assert "bound" not in side
    agree = _rows(_cmd(), _cmd(sanitizer_seen=[{"name": "check_it", "on_path": True}]))
    side = ax.side_axes(agree, "cmd")
    assert side["unavailable"] == {
        "ambiguous_ref": ["sanitizer"],
        "not_recorded_for_class": ["bound"],
    }
    assert side["flow_path"]["sink_arg"] == "pcVar2"
    assert ax.side_axes(_rows(_cmd()), "unknown")["unavailable"] == {"class_unknown": ["bound"]}
    bare = {k: v for k, v in _cmd().items() if k != "sanitizer_seen"}
    assert ax.side_axes(_rows(bare), "cmd")["unavailable"] == {
        "not_recorded_for_class": ["bound"],
        "not_in_record": ["sanitizer"],
    }


def test_one_row_with_the_field_and_one_without_is_ambiguous() -> None:
    """X2 (presence): two rows of one ref, one carrying the sanitizer field and one not, are
    ambiguous on that axis in either order — not "given" from the row that has it.

    MUTATION (verified RED, 1 failed): compare only rows that both carry the field -> the axis
    is given -> RED."""
    bare = {k: v for k, v in _cmd().items() if k != "sanitizer_seen"}
    for rows in (_rows(_cmd(), bare), _rows(bare, _cmd())):
        side = ax.side_axes(rows, "cmd")
        assert side["unavailable"].get("ambiguous_ref") == ["sanitizer"]
        assert "sanitizer" not in side


def test_a_link_is_ambiguous_only_when_its_own_inputs_differ() -> None:
    """X2 (links): two rows whose length variables differ -> size_arg ambiguous_ref; two rows that
    differ only in their clamp shapes -> size_arg read as usual (while the bound axis itself is
    ambiguous)."""
    vary = _rows(_copy(), _copy(size_flow={"size_arg": "m", "size_var": "m", "one_hop": []}))
    _f, (links,) = ax.entry_guards(_scan("len"), [ax.LinkRow(True, vary, "copy")])
    assert links is not None and links["size_arg"] == {"unavailable": "ambiguous_ref"}
    clamps = _rows(_copy(), _copy(clamp_seen=[{"shape": "min", "coverage": "unjudged"}]))
    _f, (links,) = ax.entry_guards(_scan("len"), [ax.LinkRow(True, clamps, "copy")])
    assert links is not None and links["size_arg"] == {"yes": [0], "no": [], "unknown": []}
    assert ax.side_axes(clamps, "copy")["unavailable"].get("ambiguous_ref") == ["bound"]


def _prov(sink: str, addr: str, value: Any = "x", idx: int = 0) -> dict[str, Any]:
    return {
        "sink_idx": idx,
        "arg_idx": 0,
        "sink": sink,
        "sink_addr": addr,
        "provenance": {"kind": "constant", "value": value, "value_kind": "literal_string"},
    }


def test_def_use_is_scoped_strictly_in_the_readers_own_order() -> None:
    """X3: no sink anchor -> unscoped (every record); no call address -> sink_name; else callsite,
    with NO fallback — a call whose own records are absent gets none, not a sibling's. Each record
    keeps sink_idx / arg_idx; a value past VALUE_LIMIT is cut with value_len.

    MUTATION M7 (verified RED, 1 failed): scope with _scoped_records (which falls back) -> the
    sibling's records appear -> RED."""
    own = _prov("system", "0x401010", idx=3)
    sibling = _prov("system", "0x401080", idx=4)
    other = _prov("printf", "0x401090", idx=5)
    rec = _cmd(sink_arg_provenance=[own, sibling, other])
    unscoped = ax.side_axes(_rows(rec, anchor=None), "cmd")["def_use"]
    assert unscoped["scope"] == "unscoped" and unscoped["records_total"] == 3
    by_name = ax.side_axes(_rows(rec, ref=FN_REF), "cmd")["def_use"]
    assert by_name["scope"] == "sink_name"
    assert [r["sink_idx"] for r in by_name["records"]] == [3, 4]
    at_call = ax.side_axes(_rows(rec), "cmd")["def_use"]
    assert at_call["scope"] == "callsite"
    assert at_call["records"] == [
        {
            "sink_idx": 3,
            "arg_idx": 0,
            "sink": "system",
            "sink_addr": "0x401010",
            "kind": "constant",
            "value_kind": "literal_string",
            "value": "x",
        }
    ]
    only_sibling = _cmd(sink_arg_provenance=[sibling])
    alone = ax.side_axes(_rows(only_sibling), "cmd")["def_use"]
    assert alone == {"scope": "callsite", "records": [], "records_total": 0}
    long = _cmd(sink_arg_provenance=[_prov("system", "0x401010", value="y" * 250)])
    (cut,) = ax.side_axes(_rows(long), "cmd")["def_use"]["records"]
    assert cut["value"] == "y" * ax.VALUE_LIMIT and cut["value_len"] == 250


def test_lists_are_cut_with_their_totals() -> None:
    """X4: one_hop / clamp_seen / sanitizer.seen / def_use.records are cut to AXIS_LIST_LIMIT, each
    with its total."""
    n = ax.AXIS_LIST_LIMIT + 2
    copy = _copy(
        size_flow={"size_arg": "n", "size_var": "n", "one_hop": [f"h{i}" for i in range(n)]},
        clamp_seen=[{"shape": f"s{i}", "coverage": "unjudged"} for i in range(n)],
    )
    bound = ax.side_axes(_rows(copy), "copy")["bound"]
    assert (len(bound["one_hop"]), bound["one_hop_total"]) == (ax.AXIS_LIST_LIMIT, n)
    assert (len(bound["clamp_seen"]), bound["clamp_seen_total"]) == (ax.AXIS_LIST_LIMIT, n)
    cmd = _cmd(
        sanitizer_seen=[
            {"name": f"chk{i}", "on_path": False, "coverage": "unjudged"} for i in range(n)
        ],
        sink_arg_provenance=[_prov("system", "0x401010", idx=i) for i in range(n)],
    )
    side = ax.side_axes(_rows(cmd), "cmd")
    assert (len(side["sanitizer"]["seen"]), side["sanitizer"]["seen_total"]) == (
        ax.AXIS_LIST_LIMIT,
        n,
    )
    assert (len(side["def_use"]["records"]), side["def_use"]["records_total"]) == (
        ax.AXIS_LIST_LIMIT,
        n,
    )


def test_a_wrapper_hop_names_the_wrapped_sink() -> None:
    rec = _cmd(
        flow_path={
            "sink_arg": "pcVar2",
            "one_hop": [],
            "sink_via_wrapper": True,
            "wrapper": {"name": "run_it", "wrapped_sink": "system"},
        }
    )
    fp = ax.side_axes(_rows(rec), "cmd")["flow_path"]
    assert (fp["via_wrapper"], fp["wrapped_sink"]) == (True, "system")
    assert "wrapped_sink" not in ax.side_axes(_rows(_cmd()), "cmd")["flow_path"]


class _Dict(dict):  # type: ignore[type-arg]
    """A plain cache standing in for the view's bounded one."""


def test_the_fetch_reads_each_uncached_ref_once_and_keeps_every_row() -> None:
    """The fetch groups a ref's rows (two rows of one ref stay two), names a ref with no row (an
    empty tuple: no_evidence), and serves a cached ref without reading it again."""
    db = sqlite3.connect(":memory:")
    db.execute(
        "CREATE TABLE instance (instance_id INTEGER PRIMARY KEY, source_run_id TEXT, "
        "evidence_ref TEXT, sink_anchor TEXT, flow_evidence TEXT)"
    )
    db.execute("CREATE INDEX i_ref ON instance(evidence_ref)")
    for flow in (_cmd(), _cmd(source_kind="free_string")):
        db.execute(
            "INSERT INTO instance (source_run_id, evidence_ref, sink_anchor, flow_evidence) "
            "VALUES ('runB', ?, 'system', ?)",
            (REF, json.dumps(flow)),
        )
    db.execute(
        "INSERT INTO instance (source_run_id, evidence_ref, sink_anchor, flow_evidence) "
        "VALUES ('runA', ?, 'system', ?)",
        (REF, json.dumps(_cmd())),
    )
    cache = _Dict()
    got = ax.fetch(db, "runB", [REF, "runB#none"], cache, ("atlas", "runB"))
    assert len(got[REF]) == 2 and got["runB#none"] == ()
    assert ax.side_axes(got[REF], "cmd")["unavailable"]["ambiguous_ref"] == ["source"]
    db.execute("DELETE FROM instance")
    again = ax.fetch(db, "runB", [REF], cache, ("atlas", "runB"))
    assert len(again[REF]) == 2  # served from the cache
