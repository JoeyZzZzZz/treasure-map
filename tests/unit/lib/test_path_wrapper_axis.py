# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The PATH axis of one-hop thin-wrapper propagation (lib/hunt/wrapper_propagation + facts).

A caller that hands a path to a thin wrapper around a path sink (fopen / unlink / rename / …) is
recovered as a path-sink candidate one hop away, the way the command and format axes recover theirs:
one candidate per call, intra-binary, always ``unknown``. What is particular to this axis, and
pinned here: the path is read at the wrapper's own forwarded POSITIONS (not at argument 0), a
two-path sink is constant only when every path is a literal, a name that is itself a path sink or
is carried by several functions of one binary is not registered, and a wrapper whose position
cannot be established is still recovered with nothing read.

Synthetic, vendor-neutral pseudocode and hermetic databases.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import TypeVar

import pytest

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.diff.loader import FuncRow
from treasure_map.lib.hunt import run_analyzer2
from treasure_map.lib.hunt import wrapper_propagation as wp
from treasure_map.lib.hunt.facts import is_thin_path_wrapper, path_wrapper_param_positions
from treasure_map.lib.hunt.wrapper_propagation import (
    find_wrapper_propagated_candidates,
    path_wrapper_arg_ref,
    path_wrapper_calls_literal,
)
from treasure_map.lib.storage.connection import open_db

T = TypeVar("T")

# ── fixtures ──────────────────────────────────────────────────────────────────────────────────

# A path wrapper whose path is its FIRST parameter.
READ_FILE = ("read_file", 'void read_file(char *param_1){ fopen(param_1,"r"); }', ["fopen"])
# A path wrapper whose path is its SECOND parameter; the first is the open mode.
OPEN_AT = (
    "open_at",
    "void open_at(char *param_1,char *param_2){ fopen(param_2,param_1); }",
    ["fopen"],
)
# A two-path wrapper: both of rename's paths come from the caller.
MOVE_FILE = (
    "move_file",
    "void move_file(char *param_1,char *param_2){ rename(param_1,param_2); }",
    ["rename"],
)
# A two-path wrapper that fills rename's destination itself: the caller supplies only the source.
MOVE_TO_DEST = (
    "move_to_dest",
    "void move_to_dest(char *param_1){ char *pcVar1; pcVar1 = dest_dir(); "
    "rename(param_1,pcVar1); }",
    ["dest_dir", "rename"],
)
# A path wrapper whose printed signature declares no parameter: the path is the decompiler's
# caller-supplied placeholder, so the wrapper is recognised but its position is unknown.
DROP_FILE = ("drop_file", "void drop_file(void){ unlink(param_1); }", ["unlink"])


def _row(
    func_id: int,
    spec: tuple[str, str, list[str]],
    *,
    binary_id: int = 1,
    binary: str = "cfgd",
) -> FuncRow:
    name, pseudocode, callees = spec
    return FuncRow(
        func_id=func_id,
        binary_id=binary_id,
        binary_name=binary,
        binary_path=f"usr/sbin/{binary}",
        binary_sha256=hashlib.sha256(binary.encode()).hexdigest(),
        name=name,
        address=f"{0x1000 * func_id:08x}",
        pseudocode=pseudocode,
        pseudocode_hash=f"h{func_id}",
        callees=json.dumps(callees),
    )


def _caller(name: str, body: str, callees: list[str]) -> tuple[str, str, list[str]]:
    return name, f"void {name}(void){{ {body} }}", callees


def _path(cands: list[wp.WrapperCandidate]) -> list[wp.WrapperCandidate]:
    return [c for c in cands if c.sink_class == "path_sink"]


def _one(items: list[T]) -> T:
    """The single item, asserted (an empty or longer list is a failed assertion, not an unpack
    error)."""
    assert len(items) == 1, items
    return items[0]


# ── the recogniser and its positions ──────────────────────────────────────────────────────────


def test_a_parameter_forwarded_into_a_path_position_is_a_path_wrapper() -> None:
    """Positive and negative together: the same sink handed a parameter the body rebuilds first, or
    a local buffer, is not a wrapper — the path is built here, not forwarded.

    Mutation: drop the ``_arg_is_forwarded_verbatim`` check from ``is_thin_path_wrapper`` -> RED
    (1 failed, AssertionError: the rebuilt parameter reads as forwarded)."""
    assert is_thin_path_wrapper(READ_FILE[1], READ_FILE[2]) == (True, "fopen")
    assert is_thin_path_wrapper(OPEN_AT[1], OPEN_AT[2]) == (True, "fopen")
    rebuilt = 'void f(char *param_1){ snprintf(param_1,64,"/tmp/%s",g); fopen(param_1,"r"); }'
    assert is_thin_path_wrapper(rebuilt, ["snprintf", "fopen"]) == (False, None)
    local = 'void f(char *param_1){ char b[64]; snprintf(b,64,"/tmp/%s",param_1); fopen(b,"r"); }'
    assert is_thin_path_wrapper(local, ["snprintf", "fopen"]) == (False, None)


def test_positions_are_the_wrappers_own_signature_slots() -> None:
    """Every forwarded path position, by signature slot: OPEN_AT's path is slot 1, MOVE_FILE has
    two, and MOVE_TO_DEST forwards one while filling the other path itself.

    Mutation: return only the recognising parameter's slot from ``path_wrapper_param_positions``
    -> RED (1 failed, AssertionError: MOVE_FILE reads (0,)).
    Mutation: never clear ``fully_forwarded`` for a value of the wrapper's own -> RED (1 failed,
    AssertionError: MOVE_TO_DEST reads fully forwarded)."""
    assert path_wrapper_param_positions(READ_FILE[1], "fopen") == ((0,), True)
    assert path_wrapper_param_positions(OPEN_AT[1], "fopen") == ((1,), True)
    assert path_wrapper_param_positions(MOVE_FILE[1], "rename") == ((0, 1), True)
    assert path_wrapper_param_positions(MOVE_TO_DEST[1], "rename") == ((0,), False)
    # recognised, but the parameter it forwards has no slot in the printed signature
    assert is_thin_path_wrapper(DROP_FILE[1], DROP_FILE[2]) == (True, "unlink")
    assert path_wrapper_param_positions(DROP_FILE[1], "unlink") == (None, False)


# ── A-E4-20: read the path where the wrapper takes it, not at argument 0 ────────────────────


def test_a_path_at_position_one_is_read_at_position_one() -> None:
    """A-E4-20. ``open_at("rb", pcVar1)``: argument 0 is the open mode (a literal), the path is the
    variable at position 1. The reader returns that variable, not the literal.

    Mutation: read argument 0 in ``_path_args_at`` (``args[0]`` for ``args[p]``) -> RED (1 failed,
    AssertionError: the literal mode is read as the path)."""
    caller = 'void load_one(void){ char *pcVar1; pcVar1 = name_of(); open_at("rb",pcVar1); }'
    ref = path_wrapper_arg_ref(caller, "open_at", (1,), None, 0)
    assert ref is not None
    assert (ref.form, ref.root) == ("var", "pcVar1")
    # the position is what matters: read at argument 0, the same call yields the literal mode
    ref0 = path_wrapper_arg_ref(caller, "open_at", (0,), None, 0)
    assert ref0 is not None and ref0.form == "literal"


def test_a_constant_argument_zero_does_not_make_the_path_constant(tmp_path: Path) -> None:
    """A-E4-20, through the hunt. The command axis's note reads argument 0 — on this fixture it
    finds the literal mode and says ``const_sink_arg`` (asserted below, so the divergence the test
    rests on is real). The path axis reads position 1, finds a variable, and attaches no note; the
    candidate's flow evidence names that variable as the sink argument.

    Mutation: give the path axis the command note (``wrapper_propagation_form_note``) in analyzer2
    -> RED (1 failed, AssertionError: blocking_mechanism 'const_sink_arg').
    Mutation: read the path axis with ``_wrapper_sink_arg_ref`` (argument 0) -> RED (1 failed,
    AssertionError: sink_arg None, the literal mode was read)."""
    from treasure_map.lib.hunt.downweight import wrapper_propagation_form_note

    body = 'char *pcVar1; pcVar1 = name_of(); open_at("rb",pcVar1);'
    caller = _caller("load_one", body, ["name_of", "open_at"])
    assert wrapper_propagation_form_note(caller[1], "open_at", "pcVar1", None, 0) == (
        "const_sink_arg"
    )
    atlas = _hunt(tmp_path, [OPEN_AT, caller])
    row = _one(_wrapper_rows(atlas, "load_one"))
    assert row["blocking_mechanism"] is None
    ev = json.loads(row["flow_evidence"])
    assert ev["flow_path"]["sink_arg"] == "pcVar1"
    assert ev["flow_path"]["sink_arg_form"] == "var"
    assert ev["flow_path"]["wrapper"]["path_arg_positions"] == [1]


# ── A-E4-21: a name that is itself a path sink is not registered ─────────────────────────────


def test_a_function_named_after_a_path_sink_is_not_registered() -> None:
    """A-E4-21. The C library's ``open64`` calling ``open`` has the body of a path wrapper, but its
    callers already hold a direct path candidate for that very call. The same body under another
    name IS registered — the name is the only difference, both sides asserted.

    Mutation: drop ``f.name in PATH_SINK`` from the path registry's refusal -> RED (1 failed,
    AssertionError: a path candidate through open64)."""
    body = (
        "int {n}(char *param_1,int param_2){{ int iVar1; "
        "iVar1 = open(param_1,param_2); return iVar1; }}"
    )
    libc = ("open64", body.format(n="open64"), ["open"])
    mine = ("open_file", body.format(n="open_file"), ["open"])
    assert is_thin_path_wrapper(libc[1], libc[2]) == (True, "open")  # the body qualifies
    use = _caller(
        "use",
        "char *p; p = name_of(); open64(p,0); open_file(p,0);",
        ["name_of", "open64", "open_file"],
    )
    cands = _path(find_wrapper_propagated_candidates([_row(1, libc), _row(2, mine), _row(3, use)]))
    assert [(c.func.name, c.wrapper_name) for c in cands] == [("use", "open_file")]


# ── A-E4-22: a two-path call is constant only when every path is a literal ───────────────────


def test_one_literal_beside_one_variable_is_not_a_constant_path() -> None:
    """A-E4-22. ``move_file("/tmp/a", pcVar1)`` into ``rename(param_1, param_2)``: one forwarded
    path is a literal, the other a variable — not a constant path, as ``rename("/tmp/x", param_1)``
    is not one for a direct sink. Both literals is constant (the other side of the tooth).

    Mutation: test only the first forwarded position in ``path_wrapper_calls_literal``
    (``call[:1]``) -> RED (1 failed, AssertionError: the mixed call reads constant)."""
    mixed = 'char *pcVar1; pcVar1 = name_of(); move_file("/tmp/a.cfg",pcVar1);'
    fixed = 'move_file("/tmp/a.cfg","/tmp/b.cfg");'
    assert not path_wrapper_calls_literal(mixed, "move_file", (0, 1), True)
    assert path_wrapper_calls_literal(fixed, "move_file", (0, 1), True)


def test_a_path_the_wrapper_fills_itself_keeps_a_literal_caller_off_constant() -> None:
    """A-E4-22, the hop's own half: ``move_to_dest("/tmp/a")`` forwards a literal source, but the
    wrapper hands ``rename`` a destination of its own, so the call is not a constant path. The
    caller's argument alone would say constant (asserted), so the wrapper's fact is what decides.

    Mutation: ignore ``fully_forwarded`` in ``path_wrapper_calls_literal`` -> RED (1 failed,
    AssertionError: the call reads constant)."""
    caller = 'move_to_dest("/tmp/a.cfg");'
    assert path_wrapper_calls_literal(caller, "move_to_dest", (0,), True)
    assert not path_wrapper_calls_literal(caller, "move_to_dest", (0,), False)


def test_the_two_path_rule_through_the_hunt(tmp_path: Path) -> None:
    """A-E4-22 end to end: only the call whose every path is a literal, through a wrapper that
    forwards every path, carries ``const_sink_arg`` — and it then reads constant, exactly as a
    direct literal path does.

    Mutation: test only the first forwarded position in ``path_wrapper_calls_literal`` -> RED
    (1 failed, AssertionError: mv_mixed carries const_sink_arg)."""
    funcs = [
        MOVE_FILE,
        MOVE_TO_DEST,
        _caller(
            "mv_mixed",
            'char *p; p = name_of(); move_file("/tmp/a.cfg",p);',
            ["name_of", "move_file"],
        ),
        _caller("mv_fixed", 'move_file("/tmp/a.cfg","/tmp/b.cfg");', ["move_file"]),
        _caller("mv_dest", 'move_to_dest("/tmp/a.cfg");', ["move_to_dest"]),
        _caller("direct_fixed", 'fopen("/etc/a.cfg","r");', ["fopen"]),
    ]
    atlas = _hunt(tmp_path, funcs)
    blocking = {
        fn: _wrapper_rows(atlas, fn)[0]["blocking_mechanism"]
        for fn in ("mv_mixed", "mv_fixed", "mv_dest")
    }
    assert blocking == {"mv_mixed": None, "mv_fixed": "const_sink_arg", "mv_dest": None}
    assert (
        _controllability(atlas, "mv_fixed") == _controllability(atlas, "direct_fixed") == "constant"
    )
    assert _controllability(atlas, "mv_mixed") != "constant"


# ── A-E4-23: a name several functions of one binary carry is not registered ───────────────────


def test_same_named_functions_in_one_binary_register_no_path_wrapper() -> None:
    """A-E4-23. Two ``load_file`` overloads in one binary take the path at different positions; a
    registry keyed by name would keep whichever came last and read every caller at its position.
    Neither is registered. With one of them alone the caller IS recovered, and a same-named
    function in ANOTHER binary does not block it (the count is per binary). A body-less row of the
    same name counts too, as the runner pass's link step counts it.

    Mutation: drop the more-than-one-function refusal from the path registry -> RED (1 failed,
    AssertionError: a candidate read at the last overload's position (1,))."""
    one = ("load_file", 'void load_file(char *param_1){ fopen(param_1,"r"); }', ["fopen"])
    two = (
        "load_file",
        'void load_file(int param_1,char *param_2){ fopen(param_2,"r"); }',
        ["fopen"],
    )
    use = _caller("use", "char *p; p = name_of(); load_file(p);", ["name_of", "load_file"])
    assert (
        _path(find_wrapper_propagated_candidates([_row(1, one), _row(2, two), _row(3, use)])) == []
    )
    alone = _one(_path(find_wrapper_propagated_candidates([_row(1, one), _row(3, use)])))
    assert (alone.func.name, alone.path_param_positions) == ("use", (0,))
    elsewhere = _row(2, two, binary_id=2, binary="libother.so")
    kept = _one(_path(find_wrapper_propagated_candidates([_row(1, one), elsewhere, _row(3, use)])))
    assert kept.path_param_positions == (0,)
    bodiless = FuncRow(**{**_row(2, one).__dict__, "pseudocode": None})
    assert _path(find_wrapper_propagated_candidates([_row(1, one), bodiless, _row(3, use)])) == []


# ── A-E4-24: same shape as the other two axes ────────────────────────────────────────────────


def test_one_candidate_per_call_each_reading_its_own_call() -> None:
    """A-E4-24. Two calls to one path wrapper are two candidates, in text order, each read at its
    own call — the variable and the literal are not merged into one function-level reading.

    Mutation: emit only occurrence 0 per wrapper in ``_axis_candidates`` -> RED (1 failed,
    AssertionError: one candidate)."""
    body = 'char *p; p = name_of(); read_file(p); read_file("/etc/b.cfg");'
    use = _caller("two_calls", body, ["name_of", "read_file"])
    cands = _path(find_wrapper_propagated_candidates([_row(1, READ_FILE), _row(2, use)]))
    assert [(c.func.name, c.occurrence) for c in cands] == [("two_calls", 0), ("two_calls", 1)]
    forms = [path_wrapper_arg_ref(use[1], "read_file", (0,), None, c.occurrence) for c in cands]
    assert [(r.form, r.root) for r in forms if r is not None] == [("var", "p"), ("literal", None)]
    # one variable call keeps the literal sibling off "constant": the rule is the function's
    assert not path_wrapper_calls_literal(use[1], "read_file", (0,), True)


def test_a_path_wrapper_in_another_binary_is_not_followed() -> None:
    """A-E4-24. The wrapper lives in a different binary: a cross-binary hop, not propagated. The
    same pair in one binary is (both sides).

    Mutation: look the wrapper up by name alone in ``_axis_candidates`` -> RED (1 failed,
    AssertionError: a cross-binary candidate)."""
    use = _caller("use", "char *p; p = name_of(); read_file(p);", ["name_of", "read_file"])
    lib = _row(1, READ_FILE, binary_id=2, binary="libfile.so")
    assert _path(find_wrapper_propagated_candidates([lib, _row(2, use)])) == []
    assert len(_path(find_wrapper_propagated_candidates([_row(1, READ_FILE), _row(2, use)]))) == 1


def test_an_unknown_position_still_yields_its_candidate_with_nothing_read(tmp_path: Path) -> None:
    """A-E4-24. ``drop_file`` is recognised but its path position is unknown. Its caller is still
    recovered — one candidate per call, ``unknown`` — and nothing of the call is read: no sink
    argument, no form, no constant note although argument 0 is a literal, and the record says no
    position was read.

    Mutation: skip registering a wrapper whose position is None -> RED (1 failed, AssertionError:
    no candidate).
    Mutation: read argument 0 when the position is None (``positions or (0,)`` in
    ``path_wrapper_arg_ref``) -> RED (1 failed, AssertionError: sink_arg_form 'literal')."""
    drop_tmp = _caller("drop_tmp", 'drop_file("/tmp/x.pid");', ["drop_file"])
    c = _one(_path(find_wrapper_propagated_candidates([_row(1, DROP_FILE), _row(2, drop_tmp)])))
    assert (c.func.name, c.occurrence, c.path_param_positions) == ("drop_tmp", 0, None)
    atlas = _hunt(tmp_path, [DROP_FILE, drop_tmp])
    row = _one(_wrapper_rows(atlas, "drop_tmp"))
    ev = json.loads(row["flow_evidence"])
    assert row["reachability_status"] == "unknown"
    assert row["blocking_mechanism"] is None
    assert ev["flow_path"]["sink_arg"] is None
    assert ev["flow_path"]["sink_arg_form"] is None
    assert ev["flow_path"]["wrapper"]["path_arg_positions"] is None


def test_every_path_candidate_is_unknown_and_level_zero(tmp_path: Path) -> None:
    """A-E4-24. The real sink is across a call boundary, so no path candidate is graded beyond
    ``unknown`` / L0 — whatever its argument.

    Mutation: write ``confirmed`` for a path-axis wrapper instance in analyzer2 -> RED (1 failed,
    AssertionError)."""
    funcs = [
        READ_FILE,
        _caller("free_one", 'char *p; p = getenv("CFG"); read_file(p);', ["getenv", "read_file"]),
        _caller("fixed_one", 'read_file("/etc/a.cfg");', ["read_file"]),
    ]
    atlas = _hunt(tmp_path, funcs)
    rows = [r for fn in ("free_one", "fixed_one") for r in _wrapper_rows(atlas, fn)]
    assert len(rows) == 2
    assert {(r["reachability_status"], r["provenance_level"]) for r in rows} == {("unknown", "L0")}


# ── A-E4-25: the command and format axes are not touched ─────────────────────────────────────


def test_the_path_axis_leaves_the_other_two_axes_candidate_for_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A-E4-25 (structural). The path registry's two refusals are the path axis's own: a command
    wrapper carried by two functions of one binary, and a format wrapper whose name is a path sink,
    keep exactly the command and format candidates they had. Compared against the same input with
    the path axis switched off; the fixture does produce path candidates, so the axis is live.

    Mutation: apply the path refusal before the command / format registration in ``_registries``
    -> RED (1 failed, AssertionError: the cmd and fmt candidates vanish)."""
    do_cmd_a = ("do_cmd", "void do_cmd(char *param_1){ system(param_1); }", ["system"])
    do_cmd_b = ("do_cmd", 'void do_cmd(char *param_1){ popen(param_1,"r"); }', ["popen"])
    fmt_named_remove = ("remove", "void remove(char *param_1){ printf(param_1); }", ["printf"])
    use = _caller(
        "use",
        "char *p; p = name_of(); do_cmd(p); remove(p); read_file(p);",
        ["name_of", "do_cmd", "remove", "read_file"],
    )
    rows = [
        _row(i + 1, s) for i, s in enumerate([do_cmd_a, do_cmd_b, fmt_named_remove, READ_FILE, use])
    ]

    def other_axes(cands: list[wp.WrapperCandidate]) -> list[tuple[object, ...]]:
        return [
            (c.sink_class, c.func.func_id, c.wrapper_name, c.occurrence, c.format_param_index)
            for c in cands
            if c.sink_class != "path_sink"
        ]

    with_path = find_wrapper_propagated_candidates(rows)
    assert _path(with_path), "fixture must exercise the path axis"
    monkeypatch.setattr(wp, "is_thin_path_wrapper", lambda *_a, **_k: (False, None))
    without_path = find_wrapper_propagated_candidates(rows)
    assert _path(without_path) == []
    assert other_axes(with_path) == other_axes(without_path)
    assert [c[0] for c in other_axes(with_path)] == ["cmd", "fmt_string"]


# ── wiring: the path_via_wrapper class is read like the other two ─────────────────────────────


def test_path_via_wrapper_is_minted_and_read_like_the_other_wrapper_classes(tmp_path: Path) -> None:
    """The new class needs no reader of its own: the ref parser takes any ``<axis>_via_wrapper``,
    the writer layer and the diff axes key on the wrapper marker in the evidence, and the pattern
    row carries the axis's own shape. Each asserted on a candidate the hunt wrote.

    Mutation: mint the path axis with the command axis's labels (``_WRAPPER_AXIS["cmd"]`` for the
    path pair in ``_WRAPPER_AXIS_LABELS``) -> RED (1 failed, AssertionError)."""
    from treasure_map.lib.callsite_ref import (
        callsite_abs_addr,
        is_wrapper_class,
        ref_suffix_parts,
        wrapper_call_abs_addr,
    )
    from treasure_map.lib.hunt.analyzer2 import _WRAPPER_AXIS_LABELS
    from treasure_map.lib.hunt.refs import _WRAPPER_AXIS, build_evidence_ref, callsite_offset_suffix
    from treasure_map.lib.query import diff_sink_axes

    assert _WRAPPER_AXIS_LABELS == {
        **_WRAPPER_AXIS,
        "path_sink": ("wrapper-path", "path_via_wrapper"),
    }
    use = _caller("use", "char *p; p = name_of(); read_file(p);", ["name_of", "read_file"])
    atlas = _hunt(tmp_path, [READ_FILE, use])
    row = _one(_wrapper_rows(atlas, "use"))
    ref = row["evidence_ref"]
    assert ref.endswith("@path_via_wrapper#0")  # the fixture predates the bridge: legacy ordinal
    parts = ref_suffix_parts(ref)
    assert parts is not None and parts[0] == "path_via_wrapper" and is_wrapper_class(parts[0])
    # an addressed ref names the call to the WRAPPER, never a sink call
    addressed = build_evidence_ref(
        "run_p", suffix=callsite_offset_suffix("path_via_wrapper", "0x000010"), address="00002000"
    )
    assert wrapper_call_abs_addr(addressed) == 0x2010
    assert callsite_abs_addr(addressed) is None
    conn = open_atlas(atlas)
    try:
        pat = conn.execute(
            "SELECT p.sink_class, p.call_sequence_shape FROM instance i "
            "JOIN pattern p ON p.pattern_id = i.pattern_id WHERE i.evidence_ref = ?",
            (ref,),
        ).fetchone()
    finally:
        conn.close()
    assert (pat["sink_class"], pat["call_sequence_shape"]) == ("path_sink", "wrapper-path:fopen")
    assert _cand(atlas, "use").dim("writer").value == "via_wrapper"
    axes = diff_sink_axes.parse_row(ref, row["sink_anchor"], row["flow_evidence"]).axes
    assert axes["flow_path"]["via_wrapper"] is True
    assert axes["flow_path"]["wrapped_sink"] == "fopen"


# ── helpers: a hermetic analysis.db, a hunt, and what it wrote ────────────────────────────────


def _hunt(tmp_path: Path, funcs: list[tuple[str, str, list[str]]]) -> Path:
    db_path = tmp_path / "analysis.db"
    conn = open_db(db_path)
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256, ghidra_ok) VALUES (1, 'cfgd', "
        "'usr/sbin/cfgd', ?, 1)",
        (hashlib.sha256(b"cfgd").hexdigest(),),
    )
    for i, (name, pseudocode, callees) in enumerate(funcs, start=1):
        conn.execute(
            "INSERT INTO functions (id, binary_id, name, address, pseudocode, pseudocode_hash, "
            "callees) VALUES (?, 1, ?, ?, ?, ?, ?)",
            (i, name, f"{0x1000 * i:08x}", pseudocode, f"h_{name}", json.dumps(callees)),
        )
    conn.commit()
    conn.close()
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db_path, atlas, source_run_id="run_p")
    return atlas


def _wrapper_rows(atlas: Path, fn: str) -> list[sqlite3.Row]:
    """``fn``'s path-via-wrapper instances, in write order."""
    conn = open_atlas(atlas)
    try:
        return conn.execute(
            "SELECT * FROM instance WHERE source_anchor = ? AND evidence_ref LIKE ? "
            "ORDER BY instance_id",
            (fn, "%@path_via_wrapper%"),
        ).fetchall()
    finally:
        conn.close()


def _cand(atlas: Path, fn: str):  # type: ignore[no-untyped-def]
    from treasure_map.lib.query import triage as run_triage

    conn = open_atlas(atlas)
    try:
        return next(c for c in run_triage(conn) if c.function == fn)
    finally:
        conn.close()


def _controllability(atlas: Path, fn: str) -> str:
    return str(_cand(atlas, fn).dim("controllability").value)
