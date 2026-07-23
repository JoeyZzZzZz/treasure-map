# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for layer-2 dimension delta (project A/B layer annotations, never judge quality).

Hermetic: a synthetic atlas with run_capability + string_keyed_edge + function_alignment rows.
★ Fixture rule (else guards are un-testable): aligned callees have DIFFERENT A/B addresses, so a
a 'compare raw addr, skip alignment' regression is observable (it would flip unchanged->changed).
"""

from __future__ import annotations

from pathlib import Path

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import (
    FunctionAlignmentRow,
    RunCapabilityRow,
    StringKeyedEdgeRow,
)
from treasure_map.lib.atlas.writer import (
    add_function_alignment,
    add_run_capabilities,
    add_string_keyed_edges,
)
from treasure_map.lib.diff import layer2
from treasure_map.lib.diff.layer2 import (
    DECLARED_DELTA_DIMENSIONS,
    declared_delta_dimension_names,
    run_layer2_delta,
)
from treasure_map.lib.query.triage import _DIMENSION_NAMES  # authoritative triage dimension set

_SKE = "reachability.string_keyed_edge"


def _edge(
    run,
    key,
    from_addr,
    callee_addr,
    *,
    mechanism="strcmp_gate",
    callee_name="h",  # type: ignore[no-untyped-def]
    callee_kind="direct",
    completeness="complete",
    from_function="FUN_x",
    table_addr=None,
):
    return StringKeyedEdgeRow(
        source_run_id=run,
        binary="lib.so",
        from_function=from_function,
        key=key,
        mechanism=mechanism,
        callee_name=callee_name,
        callee_addr=callee_addr,
        callee_kind=callee_kind,
        from_func_addr=from_addr,
        table_addr=table_addr,
        completeness_status=completeness,
    )


def _atlas(tmp_path: Path):  # type: ignore[no-untyped-def]
    return open_atlas(tmp_path / "atlas.db")


def _cap(con, run, dim, present):  # type: ignore[no-untyped-def]
    add_run_capabilities(con, [RunCapabilityRow(run_id=run, capability=dim, present=present)])


def _diff_meta(con, diff="d", *, skew=0, run_a="ra", run_b="rb"):  # type: ignore[no-untyped-def]
    # layer-0 always writes a diff_meta row before layer-2 runs; seed it (version_skew drives the
    # iron-law-6 degradation). ABSENCE of this row -> version_skew treated as 1 (empty!=absent).
    con.execute(
        "INSERT OR REPLACE INTO diff_meta (diff_id, run_a_id, run_b_id, version_skew) "
        "VALUES (?, ?, ?, ?)",
        (diff, run_a, run_b, skew),
    )
    con.commit()


def _align(con, diff, pairs, *, skew=0):  # type: ignore[no-untyped-def]
    # pairs = list of (addr_a, addr_b, confidence, state)
    add_function_alignment(
        con,
        [
            FunctionAlignmentRow(
                diff_id=diff, addr_a=a, addr_b=b, alignment_confidence=c, alignment_state=s
            )
            for a, b, c, s in pairs
        ],
    )
    _diff_meta(con, diff, skew=skew)  # a real diff always has a diff_meta row (version_skew=0 here)


def _deltas(con, diff, dim=_SKE):  # type: ignore[no-untyped-def]
    return con.execute(
        "SELECT subject_key, delta_kind, undetermined_scope, undetermined_reason "
        "FROM dimension_delta WHERE diff_id=? AND dimension=?",
        (diff, dim),
    ).fetchall()


def _capstate(con, diff):  # type: ignore[no-untyped-def]
    return {
        r[0]: (r[1], r[2], r[3])
        for r in con.execute(
            "SELECT dimension, state_a, state_b, delta_supported FROM dimension_capability_state "
            "WHERE diff_id=?",
            (diff,),
        )
    }


# ── capability three-state + no hardcoded sub-dim names ──────────────────────────────────


def test_capability_three_state_missing_row_is_registration_unknown(tmp_path: Path) -> None:
    con = _atlas(tmp_path)
    # a DISCOVERED analysis sub-dim (not hardcoded in layer-2): registered present=1 on ra, 0 on rb
    _cap(con, "ra", "reachability.auth_boundary", 1)
    _cap(con, "rb", "reachability.auth_boundary", 0)
    _cap(con, "ra", _SKE, 1)  # rb has NO string_keyed_edge row -> registration_unknown
    run_layer2_delta(con, diff_id="d", run_a_id="ra", run_b_id="rb")
    cs = _capstate(con, "d")
    assert cs["reachability.auth_boundary"][:2] == ("present", "declared_absent")  # 1 / 0
    assert cs[_SKE][:2] == ("present", "registration_unknown")  # present on ra, NO row on rb
    con.close()


def test_no_hardcoded_analysis_subdim_names_in_source() -> None:
    # ★ the analysis sub-dimension namespace is open-ended, discovered from run_capability;
    # unmodeled names like auth_boundary must never be a literal in the layer-2 code.
    src = Path(layer2.__file__).read_text()
    assert "auth_boundary" not in src
    assert "dispatch_resolved" not in src


# ── edge delta main path + G1 (align by address, func anchor) ────────────────────────────


def _seed_matched(con, *, b_callee="2100", a_complete="complete", b_complete="complete", skew=0):  # type: ignore[no-untyped-def]
    _cap(con, "ra", _SKE, 1)
    _cap(con, "rb", _SKE, 1)
    add_string_keyed_edges(
        con, [_edge("ra", "cmd_reboot", "1000", "2000", completeness=a_complete)]
    )
    add_string_keyed_edges(
        con,
        [
            _edge(
                "rb", "cmd_reboot", "1100", b_callee, from_function="FUN_y", completeness=b_complete
            )
        ],
    )
    # ★ callee A addr 2000 != B addr 2100: alignment is load-bearing, not cosmetic
    _align(
        con, "d", [("1000", "1100", 0.98, "aligned"), ("2000", "2100", 0.98, "aligned")], skew=skew
    )


def test_edge_unchanged_when_aligned_callees_equal(tmp_path: Path) -> None:
    con = _atlas(tmp_path)
    _seed_matched(con)  # A callee 2000 aligns to 2100 == B callee 2100
    run_layer2_delta(con, diff_id="d", run_a_id="ra", run_b_id="rb")
    (row,) = _deltas(con, "d")
    assert row[1] == "layer_unchanged"
    con.close()


def test_edge_changed_when_callee_set_differs(tmp_path: Path) -> None:
    con = _atlas(tmp_path)
    _seed_matched(con, b_callee="9999")  # B points at a different function -> changed
    run_layer2_delta(con, diff_id="d", run_a_id="ra", run_b_id="rb")
    (row,) = _deltas(con, "d")
    assert row[1] == "layer_changed"
    con.close()


def test_g1_aligns_by_address_not_by_name(tmp_path: Path) -> None:
    # ★ from_function NAME differs (FUN_x vs FUN_y, address-derived) but from_func_addr aligns ->
    # unchanged. The name is never used for cross-version comparison.
    con = _atlas(tmp_path)
    _seed_matched(con)
    run_layer2_delta(con, diff_id="d", run_a_id="ra", run_b_id="rb")
    (row,) = _deltas(con, "d")
    assert row[1] == "layer_unchanged"  # names differ, addresses align
    assert "FUN_x" not in row[0] and "FUN_y" not in row[0]  # subject_key uses addr, not name
    con.close()


def test_g1_gate_identity_includes_func_anchor_no_collision(tmp_path: Path) -> None:
    # ★ same key in two DIFFERENT from_func_addr -> two independent subjects, never a UNIQUE
    # collision / collapse / blanket key_ambiguous (measured: this happens for ~29% of gate keys).
    con = _atlas(tmp_path)
    _cap(con, "ra", _SKE, 1)
    _cap(con, "rb", _SKE, 1)
    add_string_keyed_edges(
        con,
        [
            _edge("ra", "shared_key", "1000", "2000"),
            _edge("ra", "shared_key", "3000", "4000"),  # same key, different func
        ],
    )
    add_string_keyed_edges(
        con,
        [
            _edge("rb", "shared_key", "1100", "2100"),
            _edge("rb", "shared_key", "3100", "4100"),
        ],
    )
    _align(
        con,
        "d",
        [
            ("1000", "1100", 0.98, "aligned"),
            ("3000", "3100", 0.98, "aligned"),
            ("2000", "2100", 0.98, "aligned"),
            ("4000", "4100", 0.98, "aligned"),
        ],
    )
    run_layer2_delta(con, diff_id="d", run_a_id="ra", run_b_id="rb")
    rows = _deltas(con, "d")
    assert len(rows) == 2  # two distinct subjects, not one collapsed / not an error
    assert len({r[0] for r in rows}) == 2  # distinct subject_keys
    assert all(r[1] == "layer_unchanged" for r in rows)
    con.close()


def test_static_table_addr_drift_is_not_a_change(tmp_path: Path) -> None:
    # ★ static_string_table: table_addr drifts across builds but key+callee unchanged -> unchanged.
    con = _atlas(tmp_path)
    _cap(con, "ra", _SKE, 1)
    _cap(con, "rb", _SKE, 1)
    add_string_keyed_edges(
        con,
        [
            _edge(
                "ra",
                "ej_dump",
                None,
                "2000",
                mechanism="static_string_table",
                from_function=None,
                table_addr="d000",
            )
        ],
    )
    add_string_keyed_edges(
        con,
        [
            _edge(
                "rb",
                "ej_dump",
                None,
                "2100",
                mechanism="static_string_table",
                from_function=None,
                table_addr="e000",
            )
        ],
    )  # table moved
    _align(con, "d", [("2000", "2100", 0.98, "aligned")])
    run_layer2_delta(con, diff_id="d", run_a_id="ra", run_b_id="rb")
    (row,) = _deltas(con, "d")
    assert row[1] == "layer_unchanged"  # table_addr not part of identity
    con.close()


# ── G2 callee alignability (structural, not by kind) ─────────────────────────────────────


def test_g2_callee_unalignable_is_structural_not_kind(tmp_path: Path) -> None:
    # ★ three unalignable shapes ALL -> delta_undetermined(callee_unalignable), none layer_changed:
    #   (a) callee_addr missing; (b) undefined_text, no alignment row; (c) a novel unlisted kind.
    for tag, kw in (
        ("a", {"callee_addr": None}),
        ("b", {"callee_kind": "undefined_text", "callee_addr": "7777"}),  # 7777 not in alignment
        ("c", {"callee_kind": "brand_new_kind_9", "callee_addr": "8888"}),  # 8888 not in alignment
    ):
        con = open_atlas(tmp_path / f"a_{tag}.db")
        _cap(con, "ra", _SKE, 1)
        _cap(con, "rb", _SKE, 1)
        add_string_keyed_edges(con, [_edge("ra", "k", "1000", **kw)])  # type: ignore[arg-type]
        add_string_keyed_edges(con, [_edge("rb", "k", "1100", "2100")])
        _align(con, "d", [("1000", "1100", 0.98, "aligned")])  # func aligns; callee does not
        run_layer2_delta(con, diff_id="d", run_a_id="ra", run_b_id="rb")
        (row,) = _deltas(con, "d")
        assert row[1] == "delta_undetermined", tag
        assert row[3] == "callee_unalignable", tag  # never layer_changed
        con.close()


def test_g2_partial_callee_unalignable_blocks_the_whole_edge(tmp_path: Path) -> None:
    # ★ one alignable + one unalignable callee -> the WHOLE edge is undetermined, never compared on
    # the alignable half into a layer_changed.
    con = _atlas(tmp_path)
    _cap(con, "ra", _SKE, 1)
    _cap(con, "rb", _SKE, 1)
    add_string_keyed_edges(
        con,
        [
            _edge("ra", "k", "1000", "2000"),  # alignable
            _edge("ra", "k", "1000", None),  # unalignable (no addr) -> blocks
        ],
    )
    add_string_keyed_edges(con, [_edge("rb", "k", "1100", "2100")])
    _align(con, "d", [("1000", "1100", 0.98, "aligned"), ("2000", "2100", 0.98, "aligned")])
    run_layer2_delta(con, diff_id="d", run_a_id="ra", run_b_id="rb")
    (row,) = _deltas(con, "d")
    assert row[1] == "delta_undetermined" and row[3] == "callee_unalignable"
    con.close()


# ── G3 completeness (three-value) ────────────────────────────────────────────────────────


def test_g3_completeness_partial_blocks_a_new_edge(tmp_path: Path) -> None:
    # ★ A region 'partial' (NOT just 'incomplete'), B 'complete' + an extra edge -> undetermined,
    # never "new edge": B's extra edge may be one A silently missed in a partial region.
    for a_status in ("incomplete", "partial"):
        con = open_atlas(tmp_path / f"c_{a_status}.db")
        _cap(con, "ra", _SKE, 1)
        _cap(con, "rb", _SKE, 1)
        # A: one edge in func 1000, region self-reported not-complete
        add_string_keyed_edges(con, [_edge("ra", "k1", "1000", "2000", completeness=a_status)])
        # B: same edge + an EXTRA edge in the same (aligned) region
        add_string_keyed_edges(
            con,
            [
                _edge("rb", "k1", "1100", "2100", completeness="complete"),
                _edge("rb", "k2", "1100", "5100", completeness="complete"),  # the "new" edge
            ],
        )
        _align(
            con,
            "d",
            [
                ("1000", "1100", 0.98, "aligned"),
                ("2000", "2100", 0.98, "aligned"),
                ("5000", "5100", 0.98, "aligned"),
            ],
        )
        run_layer2_delta(con, diff_id="d", run_a_id="ra", run_b_id="rb")
        kinds = {r[0]: (r[1], r[3]) for r in _deltas(con, "d")}
        # the k1 subject (A partial) is undetermined by completeness, never unchanged/changed
        k1 = next(v for k, v in kinds.items() if "k1" in k)
        assert k1 == ("delta_undetermined", "completeness_not_complete"), a_status
        con.close()


# ── layer-2b: candidate dims visible as capability rows, not silent, not per-subject placeholder ─


def test_layer2b_candidate_dims_are_capability_rows_not_delta_rows(tmp_path: Path) -> None:
    con = _atlas(tmp_path)
    _cap(con, "ra", _SKE, 1)
    _cap(con, "rb", _SKE, 1)
    run_layer2_delta(con, diff_id="d", run_a_id="ra", run_b_id="rb")
    cs = _capstate(con, "d")
    # controllability etc. present in capability_state with delta_supported=0
    assert cs["controllability"] == ("present", "present", 0)
    assert cs["filtering"][2] == 0 and cs["sink_impact"][2] == 0
    # ... and NOT as placeholder per-subject rows in dimension_delta
    dd = con.execute(
        "SELECT COUNT(*) FROM dimension_delta WHERE dimension IN "
        "('controllability','filtering','source_writability','sink_impact')"
    ).fetchone()[0]
    assert dd == 0
    con.close()


def test_three_kinds_of_no_delta_are_distinguishable(tmp_path: Path) -> None:
    # ★ (present,present,1)=normal ; (present,present,0)=analysis exists, delta not built
    # (entry_mechanism) ; (analysis missing)=no analysis. Three genuinely different rows.
    con = _atlas(tmp_path)
    _cap(con, "ra", _SKE, 1)
    _cap(con, "rb", _SKE, 1)
    _cap(con, "ra", "reachability.auth_boundary", 0)  # declared_absent A
    run_layer2_delta(con, diff_id="d", run_a_id="ra", run_b_id="rb")
    cs = _capstate(con, "d")
    assert cs[_SKE] == ("present", "present", 1)  # normal
    assert cs["reachability.entry_mechanism"] == ("present", "present", 0)  # analysis, no delta
    assert cs["reachability.auth_boundary"][0] != "present"  # analysis missing (declared_absent)
    con.close()


def test_declared_dimensions_and_handlers_are_bidirectional() -> None:
    # ★ each declared delta_supported dim has a handler; each handler is declared. Prevents the
    # declaration table and the implementation drifting apart.
    handlers = set(layer2._DELTA_HANDLERS)
    supported = {d.name for d in DECLARED_DELTA_DIMENSIONS if d.delta_supported}
    assert handlers == supported
    assert handlers <= declared_delta_dimension_names()


def test_union_view_shows_full_universe_base_table_has_no_placeholder(tmp_path: Path) -> None:
    # ★ query the view once -> see every unsupported/absent dimension as a capability row; the base
    # dimension_delta still carries NO per-subject placeholder for them (honest base, visible view).
    con = _atlas(tmp_path)
    _cap(con, "ra", _SKE, 1)
    _cap(con, "rb", _SKE, 1)
    run_layer2_delta(con, diff_id="d", run_a_id="ra", run_b_id="rb")
    view_dims = {
        r[0]
        for r in con.execute(
            "SELECT dimension FROM dimension_delta_full WHERE diff_id=? AND "
            "subject_kind='dimension'",
            ("d",),
        )
    }
    assert {"controllability", "filtering", "reachability.entry_mechanism"} <= view_dims
    # base table: no 'dimension'-subject placeholder rows exist at all
    base = con.execute(
        "SELECT COUNT(*) FROM dimension_delta WHERE subject_kind='dimension'"
    ).fetchone()[0]
    assert base == 0
    con.close()


def test_capability_scope_is_constant_per_subject_no_mixing(tmp_path: Path) -> None:
    # ★ when a delta-supported dim has the analysis on ONE side only, EVERY present-side subject is
    # scope='capability' identically -- never a data/capability mix (that would mean it is really a
    # per-subject data gap). Present side (ra) MUST have real edges (else the assertion is vacuous).
    con = _atlas(tmp_path)
    _cap(con, "ra", _SKE, 1)  # rb has NO row -> registration_unknown -> asymmetry
    add_string_keyed_edges(
        con,
        [
            _edge("ra", "k1", "1000", "2000"),
            _edge("ra", "k2", "3000", "4000"),
        ],
    )
    run_layer2_delta(con, diff_id="d", run_a_id="ra", run_b_id="rb")
    rows = _deltas(con, "d")
    assert len(rows) == 2  # both present-side subjects surfaced (not vacuous)
    scopes = {r[2] for r in rows}
    assert scopes == {"capability"}  # no mixing: every subject capability-scoped
    assert all(r[3] == "capability_registration_unknown" for r in rows)
    con.close()


# ── reverse-validation: prove each guard can go RED (has teeth), not tautologically true ──


def test_reverse_callee_alignment_is_load_bearing(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # ★ if callees were compared by RAW address (skipping function_alignment), the unchanged fixture
    # (A callee 2000 vs B callee 2100) FLIPS to layer_changed. Proves the alignment step is real and
    # that the unchanged test has teeth.
    def broken(callees, a2b, side):  # type: ignore[no-untyped-def]
        return frozenset(str(c.get("addr")) for c in callees if c.get("addr")), None, None

    monkeypatch.setattr(layer2, "_aligned_callee_set", broken)
    con = _atlas(tmp_path)
    _seed_matched(con)  # would be layer_unchanged with real alignment
    run_layer2_delta(con, diff_id="d", run_a_id="ra", run_b_id="rb")
    (row,) = _deltas(con, "d")
    assert row[1] == "layer_changed"  # broken -> flips; the real alignment step mattered
    con.close()


def test_reverse_completeness_guard_has_teeth(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # ★ disable G3 -> the partial-region subject stops being undetermined (would become a verdict).
    # Proves the completeness guard is what produces the honest undetermined, not something else.
    monkeypatch.setattr(layer2, "_completeness_guard", lambda *a, **k: None)
    con = _atlas(tmp_path)
    _cap(con, "ra", _SKE, 1)
    _cap(con, "rb", _SKE, 1)
    add_string_keyed_edges(con, [_edge("ra", "k1", "1000", "2000", completeness="partial")])
    add_string_keyed_edges(con, [_edge("rb", "k1", "1100", "2100", completeness="complete")])
    _align(con, "d", [("1000", "1100", 0.98, "aligned"), ("2000", "2100", 0.98, "aligned")])
    run_layer2_delta(con, diff_id="d", run_a_id="ra", run_b_id="rb")
    (row,) = _deltas(con, "d")
    assert row[1] != "delta_undetermined"  # without G3 it is NOT undetermined -> G3 had teeth
    con.close()


def test_reverse_missing_row_mapped_to_declared_absent_would_be_wrong(tmp_path: Path) -> None:
    # ★ the three-state resolver: a MISSING row must be registration_unknown, never declared_absent.
    # A broken mapping (missing -> declared_absent) would erase the empty!=absent distinction. Shown
    # by contrast: the real resolver returns registration_unknown where a broken one would not.
    con = _atlas(tmp_path)
    assert (
        layer2._analysis_capability(con, "nobody", "x.never_registered") == "registration_unknown"
    )
    _cap(con, "r", "x.declared", 0)
    assert layer2._analysis_capability(con, "r", "x.declared") == "declared_absent"  # 0 != missing
    con.close()


# ── Item 1: every triage dimension is VISIBLE (no gap-by-absence) + a mechanical coverage guard ──


def test_all_seven_triage_dimensions_are_visible(tmp_path: Path) -> None:
    # ★ writer / completeness were silently absent (gap-by-absence). Every canonical triage dim
    # must appear in the capability universe: verbatim, or covered by a sub-dimension prefix.
    con = _atlas(tmp_path)
    _cap(con, "ra", _SKE, 1)
    _cap(con, "rb", _SKE, 1)
    run_layer2_delta(con, diff_id="d", run_a_id="ra", run_b_id="rb")
    dims = set(_capstate(con, "d"))
    for name in _DIMENSION_NAMES:
        covered = name in dims or any(d.startswith(f"{name}.") for d in dims)
        assert covered, f"triage dimension {name!r} is invisible in the layer-2 universe"
    cs = _capstate(con, "d")
    assert cs["writer"] == ("present", "present", 0)  # visible, delta_supported=0
    assert cs["completeness"] == ("present", "present", 0)


def test_writer_completeness_appear_in_view_as_delta_not_implemented(tmp_path: Path) -> None:
    con = _atlas(tmp_path)
    _cap(con, "ra", _SKE, 1)
    _cap(con, "rb", _SKE, 1)
    run_layer2_delta(con, diff_id="d", run_a_id="ra", run_b_id="rb")
    view = {
        r[0]: r[1]
        for r in con.execute(
            "SELECT dimension, undetermined_reason FROM dimension_delta_full "
            "WHERE diff_id='d' AND subject_kind='dimension'"
        )
    }
    assert view["writer"] == "delta_not_implemented"
    assert view["completeness"] == "delta_not_implemented"
    # ★ base table still has NO per-subject placeholder rows for them (honest base, visible view)
    n = con.execute(
        "SELECT COUNT(*) FROM dimension_delta WHERE dimension IN ('writer','completeness')"
    ).fetchone()[0]
    assert n == 0
    con.close()


def test_coverage_guard_has_teeth(tmp_path: Path) -> None:
    # ★ reverse-validation: the real set covers every triage dim; dropping ANY declared entry's
    # entry's coverage makes _uncovered_triage_dimension return the now-uncovered name (goes red).
    declared = declared_delta_dimension_names()
    assert (
        layer2._uncovered_triage_dimension(_DIMENSION_NAMES, declared) is None
    )  # forward: covered
    for name in _DIMENSION_NAMES:
        reduced = frozenset(d for d in declared if d != name and not d.startswith(f"{name}."))
        assert layer2._uncovered_triage_dimension(_DIMENSION_NAMES, reduced) is not None, name


def test_no_declared_dimension_is_a_phantom_top_level(tmp_path: Path) -> None:
    # reverse spelling guard: every declared top-level name (before '.') is a real triage dimension.
    for d in declared_delta_dimension_names():
        top = d.split(".", 1)[0]
        assert top in _DIMENSION_NAMES, f"declared {d!r} points at non-existent triage dim {top!r}"


# ── Item 2: iron law 6 (version skew) degrades edge deltas; reverse proves the guard acts ──


def test_version_skew_degrades_every_edge_subject(tmp_path: Path) -> None:
    # ★ tool_version differs (diff_meta.version_skew=1): 'edge changed' vs 'detector changed' is
    # indistinguishable, so EVERY edge subject is delta_undetermined(reason=version_skew) -- and NOT
    # one layer_changed / layer_unchanged escapes.
    con = _atlas(tmp_path)
    _seed_matched(con, skew=1)
    run_layer2_delta(con, diff_id="d", run_a_id="ra", run_b_id="rb")
    rows = _deltas(con, "d")
    assert rows and all(r[1] == "delta_undetermined" for r in rows)
    assert all(r[2] == "data" and r[3] == "version_skew" for r in rows)
    con.close()


def test_version_skew_zero_restores_the_verdict(tmp_path: Path) -> None:
    # ★ reverse-validation: the SAME fixture with version_skew=0 restores layer_unchanged -- proves
    # skew guard genuinely gates the verdict, not that everything is always undetermined.
    con = _atlas(tmp_path)
    _seed_matched(con, skew=0)  # identical edges/alignment, only the skew flag differs
    run_layer2_delta(con, diff_id="d", run_a_id="ra", run_b_id="rb")
    (row,) = _deltas(con, "d")
    assert row[1] == "layer_unchanged"  # not undetermined -> the guard was the only difference
    con.close()


def test_missing_diff_meta_is_treated_as_skew(tmp_path: Path) -> None:
    # ★ empty != absent on the version axis: a MISSING diff_meta row means "cannot confirm same
    # version", which is NOT "confirmed same version" -> degrade as skew, never a silent verdict.
    con = _atlas(tmp_path)
    _seed_matched(con, skew=0)
    con.execute("DELETE FROM diff_meta WHERE diff_id='d'")  # remove the row entirely
    con.commit()
    run_layer2_delta(con, diff_id="d", run_a_id="ra", run_b_id="rb")
    (row,) = _deltas(con, "d")
    assert row[1] == "delta_undetermined" and row[3] == "version_skew"
    con.close()
