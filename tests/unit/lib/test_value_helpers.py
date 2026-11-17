# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Criterion A (E-2a H8): which of a binary's own functions hand on a known source's value.

Two layers tested apart: ``helper_slots`` (criterion A over one body) and ``build_helper_tables``
(the M3 population gate plus criterion A, per binary). Then the end-to-end effect through the hunt:
a candidate fed by a recognised helper moves on all three dimensions E-2a changes (A-E2a-7 /
A-E2a-8), and a candidate that is not fed by one does not.

Synthetic names throughout: ``FUN_<addr>`` is the decompiler's own name for an unnamed function —
the gate is defined on exactly that shape — and the sources / sinks are standard libc. No run,
model or vendor string appears.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.diff.loader import FuncRow
from treasure_map.lib.hunt import run_analyzer2
from treasure_map.lib.hunt.value_helpers import build_helper_tables, helper_slots
from treasure_map.lib.pattern.classes import RETURN_SLOT

from .test_analyzer2 import _make_db

R = RETURN_SLOT


# ── criterion A over one body ───────────────────────────────────────────────────────────────────

_CRITERION = [
    # rule 2(a): a returned source value, through a temporary
    (
        "return_via_temp",
        'char * h(char *param_1){ char *pcVar1; pcVar1 = getenv("k"); return pcVar1; }',
        {R},
    ),
    # rule 2(b): a source call returned directly, and wrapped in one copy layer
    ("return_source_call", 'char * h(void){ return getenv("k"); }', {R}),
    ("return_strdup_source", 'char * h(void){ return strdup(getenv("k")); }', {R}),
    (
        "return_cast_strdup_source",
        'char * h(void){ return (char *)strdup(getenv("k")); }',
        {R},
    ),
    (
        "return_strdup_via_temp",
        "char * h(void){ char *pcVar1; char *pcVar2; "
        'pcVar1 = getenv("k"); pcVar2 = strdup(pcVar1); return pcVar2; }',
        {R},
    ),
    # rule 3: a source value written into an out-parameter
    (
        "write_out_param_2",
        "void h(char *param_1,char *param_2){ char *pcVar1; "
        'pcVar1 = getenv("k"); strcpy(param_2,pcVar1); }',
        {1},
    ),
    # rule 2 exclusion: a judgement is never a value
    (
        "predicate_direct",
        "char h(void){ char *pcVar1; pcVar1 = getenv(\"k\"); return pcVar1[0] == '1'; }",
        set(),
    ),
    (
        "predicate_via_temp",
        "int h(void){ char *pcVar1; int iVar1; "
        "pcVar1 = getenv(\"k\"); iVar1 = pcVar1[0] == '1'; return iVar1; }",
        set(),
    ),
    (
        "strcmp_via_temp",
        "int h(void){ char *pcVar1; int iVar1; "
        'pcVar1 = getenv("k"); iVar1 = strcmp(pcVar1,"1"); return iVar1; }',
        set(),
    ),
    # not value getters at all
    (
        "setter",
        "int h(char *param_1){ char acStack_80[128]; "
        'snprintf(acStack_80,0x80,"%s=%s",param_1,"x"); setenv(acStack_80,"1",1); '
        "return 0; }",
        set(),
    ),
    (
        "path_join",
        "char * h(char *param_1){ char acStack_80[128]; "
        'snprintf(acStack_80,0x80,"%s/%s","/etc",param_1); return acStack_80; }',
        set(),
    ),
    ("match", 'int h(char *param_1){ if (strcmp(param_1,"on") == 0) return 1; return 0; }', set()),
    (
        "local_const_table",
        'char * h(int param_1){ if (param_1 == 0) return "a"; return "b"; }',
        set(),
    ),
    ("pure_forward", "int h(char *param_1){ return other(param_1); }", set()),
    # covers the seeding-table boundary: a source the taint layer does not seed
    (
        "unseeded_source",
        "int h(char *param_1,void *param_2){ uci_lookup_ptr(param_1,param_2,0,1); return 0; }",
        set(),
    ),
    # rule 3 exclusion: a parameter that is a source's KEY is not an out-parameter, even when the
    # value is then written into it
    (
        "key_param_is_not_an_out_param",
        "void h(char *param_1,char *param_2){ char *pcVar1; "
        "pcVar1 = getenv(param_2); strcpy(param_2,pcVar1); }",
        set(),
    ),
    # a call the decompiler wrapped across two lines is ONE statement
    (
        "writer_wrapped_across_lines",
        "void h(char *param_1,char *param_2){ char *pcVar1; "
        'pcVar1 = getenv("k"); snprintf(param_2,0x40,"%s",\n               pcVar1); }',
        {1},
    ),
    (
        "return_wrapped_across_lines",
        "char * h(char *param_1){ return strdup(getenv(\n                      param_1)); }",
        {R},
    ),
    # a field read through the value is the value read through, not a comparison
    (
        "return_field_of_the_value",
        'char * h(void){ char *pcVar1; pcVar1 = getenv("k"); return pcVar1->name; }',
        {R},
    ),
]


@pytest.mark.parametrize(("name", "body", "want"), _CRITERION, ids=[c[0] for c in _CRITERION])
def test_criterion_a_reads_the_slots_a_body_hands_a_source_value_through(
    name: str, body: str, want: set[int]
) -> None:
    """Each fixture classifies as its table says: a returned or written source value gives its
    slot, a judgement or a non-getter gives the empty set.

    MUTATION (verified RED, each clause): drop the judgement exclusion (``_is_judgement`` returns
    False) -> the predicate / strcmp fixtures are read as return getters -> RED; drop the rule-2(a)
    reach check -> return_via_temp falls to the empty set -> RED; drop the rule-2(b) nested
    recognition -> the two directly-returned source calls fall to the empty set -> RED; drop the
    out-parameter rule -> write_out_param_2 is empty -> RED. (Rule 1, membership, is redundant with
    rules 2/3 — both need a source-seeded value — so deleting it turns no fixture red; it is kept
    as a cheap, documenting precondition, not claimed as an independent tooth.)

    MUTATION (verified RED, 1 failed): drop the key exclusion (``_source_key_params`` returns an
    empty set) -> key_param_is_not_an_out_param reads {1}.
    MUTATION (verified RED, 2 failed): split statements at every ``;`` / ``{`` / ``}`` / line break
    regardless of parentheses (the earlier splitter) -> the two wrapped fixtures read empty.
    MUTATION (verified RED, 1 failed): let ``_is_judgement`` read the ``>`` of ``->`` as a
    comparison -> return_field_of_the_value reads empty."""
    assert set(helper_slots(body)) == want


def test_the_return_slot_and_an_out_parameter_slot_do_not_cross(tmp_path: Path) -> None:
    """A writer into param 2 gives exactly ``{1}`` — a 0-based out-parameter position, never
    ``RETURN_SLOT`` — and a returned value gives exactly ``{RETURN_SLOT}``, never ``{1}``.

    MUTATION (verified RED): read the out position as ``index`` rather than ``index - 1`` -> slot 2
    -> RED; add ``RETURN_SLOT`` for any writer -> the two cross -> RED."""
    write = helper_slots(
        "void h(char *param_1,char *param_2){ char *pcVar1; "
        'pcVar1 = getenv("k"); strcpy(param_2,pcVar1); }'
    )
    ret = helper_slots(
        'char * h(char *param_1){ char *pcVar1; pcVar1 = getenv("k"); return pcVar1; }'
    )
    assert set(write) == {1} and R not in write
    assert set(ret) == {R} and 1 not in ret


# ── the population gate, then criterion A ───────────────────────────────────────────────────────

_HELPER = 'char * FUN_00001000(char *param_1){ char *pcVar1; pcVar1 = getenv("k"); return pcVar1; }'
_CALL2 = (
    'void FUN_00002000(void){ char *a; char *b; a = FUN_00001000("wan"); b = FUN_00001000("lan"); }'
)
_CALL1 = 'void FUN_00002000(void){ char *a; a = FUN_00001000("wan"); }'
_CALL_NO_RET = 'void FUN_00002000(void){ FUN_00001000("wan"); FUN_00001000("lan"); }'


def _fn(fid: int, name: str, pc: str, binary_id: int = 1) -> FuncRow:
    return FuncRow(
        func_id=fid,
        binary_id=binary_id,
        binary_name="b",
        binary_path=None,
        binary_sha256=None,
        name=name,
        address=f"{fid:08x}",
        pseudocode=pc,
        pseudocode_hash=f"h{fid}",
        callees="[]",
    )


def _table_slots(funcs: list[FuncRow]) -> set[tuple[str, int]]:
    tables = build_helper_tables(funcs)
    return set().union(*(t.slots for t in tables.values())) if tables else set()


# A helper that writes into an out-parameter and passes the gate (memcpy satisfies the body shape).
_OUT_WRITER = (
    "int FUN_00001000(char *param_1,char *param_2){ char *pcVar1; pcVar1 = getenv(param_1); "
    "strcpy(param_2,pcVar1); memcpy(param_2,pcVar1,4); return 0; }"
)
# A getter by criterion A whose body has none of the shapes gate 4 reads: a non-void return, but no
# getter-named variable returned and no memcpy / strdup in the window.
_INT_GETTER = 'int FUN_00001000(char *param_1){ int iVar1; iVar1 = getenv("k"); return iVar1; }'
_CAST_GETTER = (
    'char * FUN_00001000(char *param_1){ char *pcVar1; pcVar1 = getenv("k"); '
    "return (char *)pcVar1; }"
)
# One key where the return is taken in a CONDITION, the other in a plain statement.
_CALL_IN_CONDITION = (
    "void FUN_00002000(void){ char *p; char *q; "
    'if ((p = (char *)FUN_00001000("wan")) != (char *)0x0) { q = FUN_00001000("lan"); } }'
)

_GATE = [
    ("two_keys_in", [_HELPER, _CALL2], {("FUN_00001000", R)}),
    ("return_taken_in_a_condition_counts", [_HELPER, _CALL_IN_CONDITION], {("FUN_00001000", R)}),
    ("cast_return_reads_as_getter_shape", [_CAST_GETTER, _CALL2], {("FUN_00001000", R)}),
    ("no_getter_shape_out", [_INT_GETTER, _CALL2], set()),
    ("out_parameter_slot_not_admitted", [_OUT_WRITER, _CALL2], set()),
    ("one_key_out", [_HELPER, _CALL1], set()),
    ("no_return_taken_out", [_HELPER, _CALL_NO_RET], set()),
    (
        "named_callee_out",
        [_HELPER.replace("FUN_00001000", "cfg_get"), _CALL2.replace("FUN_00001000", "cfg_get")],
        set(),
    ),
    (
        "bare_void_return_out",
        [
            # memcpy makes the body-shape clause pass, so only the bare-void clause excludes it
            'void FUN_00001000(char *param_1){ char *pcVar1; pcVar1 = getenv("k"); '
            "strcpy(param_1,pcVar1); memcpy(param_1,pcVar1,4); return; }",
            _CALL2,
        ],
        set(),
    ),
]


@pytest.mark.parametrize(("name", "bodies", "want"), _GATE, ids=[c[0] for c in _GATE])
def test_the_population_gate_admits_only_the_measured_shape(
    name: str, bodies: list[str], want: set[tuple[str, int]]
) -> None:
    """The gate: a helper is in the table only when it is a ``FUN_<addr>`` name, called with at
    least two distinct string keys where its return is taken, with a non-bare-void getter body.

    MUTATION (verified RED, each clause): drop the ``FUN_<addr>`` check -> named_callee admitted
    -> RED; lower the two-key threshold to one -> one_key admitted -> RED; count callsites that do
    not take the return -> no_return_taken admitted -> RED; drop the bare-void filter ->
    bare_void_return admitted -> RED.

    MUTATION (verified RED, 1 failed): judge "takes the return" per whole statement again (only a
    statement that is itself ``x = FUN_…(…)``) -> return_taken_in_a_condition_counts drops out.
    MUTATION (verified RED, 1 failed): drop the getter-shape half of gate 4 (a non-void body
    passes) -> no_getter_shape admitted. MUTATION (verified RED, 1 failed): no cast before the
    returned variable -> cast_return_reads_as_getter_shape drops out.
    MUTATION (verified RED, 1 failed): admit every slot (drop the ``slot == RETURN_SLOT`` filter)
    -> out_parameter_slot_not_admitted carries ("FUN_00001000", 1)."""
    funcs = [_fn(i + 1, _name_of(b), b) for i, b in enumerate(bodies)]
    assert _table_slots(funcs) == want
    assert all(slot == R for _name, slot in _table_slots(funcs))


def test_the_gate_fixtures_are_getters_by_criterion_a() -> None:
    """The two exclusions above are made by the GATE, not by criterion A: both bodies do hand on a
    source value (precondition, so a gate mutation is what turns them red)."""
    assert set(helper_slots(_INT_GETTER)) == {R}
    assert set(helper_slots(_OUT_WRITER)) == {1}


def _name_of(body: str) -> str:
    import re

    m = re.search(r"\b([A-Za-z_]\w*)\s*\(", body[: body.find("{")] if "{" in body else body)
    return m.group(1) if m else "f"


# ── end to end: the three dimensions move for a candidate a real helper feeds ────────────────────


def _func(name: str, pc: str, callees: list[str]) -> dict[str, object]:
    return {"name": name, "pseudocode": pc, "hash": f"h_{name}", "callees": callees}


# A command candidate whose only in-function input is the binary's OWN value getter.
_FED_CALLER = (
    "void handle(char *param_1){ char *pcVar1; char acStack_90[128]; "
    'pcVar1 = FUN_00001000("wan"); snprintf(acStack_90,0x80,"ping %s",pcVar1); '
    "system(acStack_90); }"
)
# Two distinct keys where the getter's return is taken, so the gate admits it.
_GATE_KEYS = (
    'void keys(void){ char *a; char *b; a = FUN_00001000("lan"); b = FUN_00001000("dmz"); }'
)


def _hunt_handle(tmp_path: Path, *, with_helper: bool) -> dict[str, object]:
    funcs = [_func("handle", _FED_CALLER, ["FUN_00001000", "snprintf", "system"])]
    if with_helper:
        funcs = [
            _func("FUN_00001000", _HELPER, ["getenv"]),
            funcs[0],
            _func("keys", _GATE_KEYS, ["FUN_00001000"]),
        ]
    d = Path(tempfile.mkdtemp(dir=tmp_path))
    db = _make_db(d, [{"name": "svcd", "path": "usr/sbin/svcd", "funcs": funcs}])
    atlas = d / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_h8")
    conn = open_atlas(atlas)
    try:
        row = conn.execute(
            "SELECT p.source_class, p.structural_fingerprint, i.exposure_shape, i.flow_evidence "
            "FROM instance i JOIN pattern p ON p.pattern_id = i.pattern_id "
            "WHERE i.source_anchor = 'handle' AND p.sink_class = 'cmd'"
        ).fetchone()
    finally:
        conn.close()
    fe = json.loads(row[3] or "{}")
    return {
        "source_class": row[0],
        "fingerprint": row[1],
        "exposure_shape": row[2],
        "source_kind": fe.get("source_kind"),
        "source_names": fe.get("source_names"),
    }


def test_a_candidate_a_real_helper_feeds_moves_on_all_three_dimensions(tmp_path: Path) -> None:
    """A-E2a-8: the same candidate, hunted with the helper present in its binary and without it,
    moves on exactly the three dimensions H8 changes — the pattern (its structural fingerprint),
    the exposure shape (no longer a bare sink), and the flow evidence (source_kind free_string,
    the helper named in source_names). The criterion builds the table from the fixture body, no
    hand-written table.

    MUTATION (verified RED): build the helper table from an empty criterion (``helper_slots``
    returns the empty set) -> no table -> the two runs are identical -> RED."""
    with_helper = _hunt_handle(tmp_path, with_helper=True)
    without = _hunt_handle(tmp_path, with_helper=False)
    assert with_helper["source_class"] == "external_input"
    assert without["source_class"] == "unknown"
    assert with_helper["exposure_shape"] is None
    assert without["exposure_shape"] == "bare_sink"
    assert with_helper["source_kind"] == "free_string"
    assert without["source_kind"] == "unknown"
    assert with_helper["source_names"] == [{"name": "FUN_00001000", "strength": "weak"}]
    assert without["source_names"] is None
    assert with_helper["fingerprint"] != without["fingerprint"]


def test_the_moved_fingerprint_re_keys_both_b_class_readers(tmp_path: Path) -> None:
    """A-E2a-7: the fingerprint the criterion moved is a different key for the two readers that
    consume it — ``same_shape_siblings.f2_key`` and ``views.density`` — so they re-group with no
    code change of their own.

    MUTATION (verified RED): leave the candidate's source_class unlabelled (the criterion builds no
    table) -> the fingerprint does not move -> the keys are equal -> RED."""
    from treasure_map.lib.query.same_shape_siblings import f2_key
    from treasure_map.lib.query.views import density

    with_helper = _hunt_handle(tmp_path, with_helper=True)
    without = _hunt_handle(tmp_path, with_helper=False)
    fp_with = str(with_helper["fingerprint"])
    fp_without = str(without["fingerprint"])
    assert fp_with != fp_without
    assert f2_key(fp_with, "system", "free_string") != f2_key(fp_without, "system", "unknown")
    # views.density keys per (run, sink_class, fingerprint): the two land in different buckets
    d = Path(tempfile.mkdtemp(dir=tmp_path))
    db = _make_db(
        d,
        [
            {
                "name": "svcd",
                "path": "usr/sbin/svcd",
                "funcs": [
                    _func("FUN_00001000", _HELPER, ["getenv"]),
                    _func("handle", _FED_CALLER, ["FUN_00001000", "snprintf", "system"]),
                    _func("keys", _GATE_KEYS, ["FUN_00001000"]),
                ],
            }
        ],
    )
    atlas = d / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_h8")
    conn = open_atlas(atlas)
    try:
        fingerprints = {r.structural_fingerprint for r in density(conn)}
    finally:
        conn.close()
    assert fp_with in fingerprints


# ── the ordering a helper table may move, and the ordering it must not ─────────────────────────

# B: same binary as the helper, never calls it; its command is built from a global, so its source
# reads unknown — the reading a stray helper label would flip.
_PLAIN_CALLER = (
    "void plain(void){ char acStack_90[128]; "
    'snprintf(acStack_90,0x80,"ping %s",DAT_00412000); system(acStack_90); }'
)
# C: another binary, fed from its own parameter — different facts from B.
_OTHER_CALLER = (
    "void other(char *param_1){ char acStack_90[128]; "
    'snprintf(acStack_90,0x80,"ping %s",param_1); system(acStack_90); }'
)


def _hunt_three(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, table: bool
) -> dict[str, dict[str, object]]:
    from treasure_map.lib.hunt import analyzer2
    from treasure_map.lib.query import triage
    from treasure_map.lib.query.triage import _sort_atoms

    if not table:
        monkeypatch.setattr(analyzer2, "build_helper_tables", lambda funcs: {})
    d = Path(tempfile.mkdtemp(dir=tmp_path))
    db = _make_db(
        d,
        [
            {
                "name": "svcd",
                "path": "usr/sbin/svcd",
                "funcs": [
                    _func("FUN_00001000", _HELPER, ["getenv"]),
                    _func("handle", _FED_CALLER, ["FUN_00001000", "snprintf", "system"]),
                    _func("keys", _GATE_KEYS, ["FUN_00001000"]),
                    _func("plain", _PLAIN_CALLER, ["snprintf", "system"]),
                ],
            },
            {
                "name": "otherd",
                "path": "usr/sbin/otherd",
                "funcs": [_func("other", _OTHER_CALLER, ["snprintf", "system"])],
            },
        ],
    )
    atlas = d / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="run_h8")
    monkeypatch.undo()
    conn = open_atlas(atlas)
    try:
        stored = {
            r[0]: (r[1], r[2], r[3], r[4])
            for r in conn.execute(
                "SELECT i.evidence_ref, p.source_class, p.structural_fingerprint, "
                "i.exposure_shape, i.flow_evidence FROM instance i "
                "JOIN pattern p ON p.pattern_id = i.pattern_id"
            )
        }
        ranked = triage(conn, run_id="run_h8")
    finally:
        conn.close()
    out: dict[str, dict[str, object]] = {}
    for rank, c in enumerate(ranked):
        ref = str(c.evidence_ref)
        out[ref] = {
            "rank": rank,
            "function": c.function,
            "source_kind": c.source_kind,
            "atoms": _sort_atoms(c, None),
            "stored": stored.get(ref),
        }
    return out


def test_a_helper_table_moves_only_the_candidates_it_feeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same firmware hunted with and without its helper table. The candidate the helper feeds
    (``handle``) moves as H8 intends: its source class unknown -> external_input, param_float
    0 -> 1 and the charset rank of its source kind (the command candidate's source_kind turns
    free_string). Every other candidate — ``plain`` in the SAME binary that never
    calls the helper, ``other`` in another binary with different facts — keeps its stored three
    dimensions byte for byte, its sort atoms, and its order relative to the rest.

    MUTATION (verified RED, 1 failed): let a binary's helper table label every function of that
    binary (in ``shapes.classify``: ``| frozenset(helpers.names)`` in place of ``| frozenset(names &
    helpers.names)``) -> ``plain`` is relabelled and its sort atoms change."""
    from treasure_map.lib.query.triage import _CHARSET_FEASIBILITY_RANK

    on = _hunt_three(tmp_path, monkeypatch, table=True)
    off = _hunt_three(tmp_path, monkeypatch, table=False)
    assert set(on) == set(off)
    fed = [ref for ref, v in on.items() if v["function"] == "handle"]
    rest = [ref for ref in on if ref not in fed]
    assert fed, "the fed candidate is missing from the fixture"
    assert {on[r]["function"] for r in rest} >= {"plain", "other"}, "the controls are missing"
    cmd = [ref for ref in fed if "@cmd" in ref]
    assert cmd, "the fed command candidate is missing from the fixture"
    for ref in cmd:
        assert (off[ref]["source_kind"], on[ref]["source_kind"]) == ("unknown", "free_string")
    for ref in fed:
        stored_off, stored_on = off[ref]["stored"], on[ref]["stored"]
        assert isinstance(stored_off, tuple) and isinstance(stored_on, tuple)
        assert (stored_off[0], stored_on[0]) == ("unknown", "external_input")
        assert (off[ref]["atoms"]["param_float"], on[ref]["atoms"]["param_float"]) == (0, 1)
        assert off[ref]["atoms"]["charset_rank"] == 0
        assert on[ref]["atoms"]["charset_rank"] == _CHARSET_FEASIBILITY_RANK.get(
            str(on[ref]["source_kind"]), 1
        )
    for ref in rest:
        assert on[ref]["stored"] == off[ref]["stored"], on[ref]["function"]
        assert on[ref]["atoms"] == off[ref]["atoms"], on[ref]["function"]
    order_on = sorted(rest, key=lambda r: int(on[r]["rank"]))  # type: ignore[call-overload]
    order_off = sorted(rest, key=lambda r: int(off[r]["rank"]))  # type: ignore[call-overload]
    assert order_on == order_off
