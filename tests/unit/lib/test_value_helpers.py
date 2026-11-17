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
    as a cheap, documenting precondition, not claimed as an independent tooth.)"""
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


_GATE = [
    ("two_keys_in", [_HELPER, _CALL2], {("FUN_00001000", R)}),
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
    bare_void_return admitted -> RED."""
    funcs = [_fn(i + 1, _name_of(b), b) for i, b in enumerate(bodies)]
    assert _table_slots(funcs) == want


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
