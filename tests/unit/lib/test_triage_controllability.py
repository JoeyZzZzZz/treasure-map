# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the SINGLE controllability verdict (M3) + its band order (M4).

The verdict is computed from sink_arg_provenance (not the collapsed top-level source_kind), crosses
each vararg key against the SaTC web_settable, and is scoped to the candidate's anchored sink. These
tests are written to the PROPERTIES that survive the merge (a web-settable key ⇒ controllable; a
variadic exec seen only at arg0 ⇒ never constant), NOT to a specific known bug's rank (no overfit).
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import (
    InstanceRow,
    NvramDefaultRow,
    NvramFlowRow,
    WebFormFieldRow,
)
from treasure_map.lib.atlas.writer import (
    add_instance,
    add_nvram_default_rows,
    add_nvram_flow_rows,
    add_web_form_field_rows,
    upsert_pattern,
)
from treasure_map.lib.query import sort_candidates, triage

_FID = [0]


def _seed_cross(conn: sqlite3.Connection) -> None:
    """A minimal SaTC cross: fb_comment/wl_ssid editable + a back-end key; firmver back-end only
    (a read-only hidden display); wrs_cc_t editable + back-end."""
    add_web_form_field_rows(
        conn,
        [
            WebFormFieldRow("run_1", "fb_comment", "Feedback.asp", "textarea"),
            WebFormFieldRow("run_1", "wl_ssid", "Advanced_Wireless.asp", "input"),
            WebFormFieldRow("run_1", "wrs_cc_t", "Protection.asp", "input"),
        ],
    )
    add_nvram_flow_rows(
        conn,
        [
            NvramFlowRow("run_1", "fb_comment", "constant", "httpd", "save", "write"),
            NvramFlowRow("run_1", "wl0_ssid", "constant", "httpd", "save", "write"),
            NvramFlowRow("run_1", "wrs_cc_t", "constant", "wrs", "load", "read"),
            NvramFlowRow("run_1", "firmver", "constant", "httpd", "show", "read"),
        ],
    )


def _pattern(conn: sqlite3.Connection, fp: str, *, sink_class: str = "cmd") -> int:
    return upsert_pattern(
        conn,
        source_class="unknown",
        sink_class=sink_class,
        call_sequence_shape="source->...->sink",
        structural_fingerprint=fp,
        fingerprint_algo_version="callseq-v1",
    )


def _inst(
    conn: sqlite3.Connection,
    pattern_id: int,
    *,
    sink_anchor: str,
    flow_evidence: dict[str, object] | None = None,
    blocking: str | None = None,
    source_kind: str | None = None,
) -> str:
    _FID[0] += 1
    ev: dict[str, object] = dict(flow_evidence or {})
    if source_kind is not None:
        ev["source_kind"] = source_kind
    ref = f"run_1#fn{_FID[0]}@{sink_anchor}"
    add_instance(
        conn,
        InstanceRow(
            pattern_id=pattern_id,
            pseudocode_hash=f"h{_FID[0]}",
            source_anchor=f"fn{_FID[0]}",
            sink_anchor=sink_anchor,
            source_run_id="run_1",
            reachability_status="unknown",
            blocking_mechanism=blocking,
            provenance_level="L0",
            evidence_ref=ref,
            scope_origin="intra",
            origin="unknown",
            flow_evidence=json.dumps(ev) if ev else None,
        ),
    )
    return ref


def _getter_vararg(key: str, callee: str = "FUN_custom") -> dict[str, object]:
    """A stack_buf writer vararg: a getter call_return carrying an nvram key in const_args."""
    return {
        "pos": 3,
        "spec": "%s",
        "source": {
            "kind": "call_return",
            "callee": callee,
            "const_args": [key],
            "arg_count": 1,
            "has_unresolved_args": False,
        },
    }


def _stack_buf_prov(sink: str, varargs: list[dict[str, object]]) -> dict[str, object]:
    return {
        "sink_arg_provenance": [
            {
                "sink": sink,
                "sink_idx": 0,
                "provenance": {
                    "kind": "stack_buf",
                    "nearest_dominating_writer": "snprintf@0x1",
                    "writers": [
                        {
                            "writer": "snprintf@0x1",
                            "dominates_sink": True,
                            "fmt": "%s",
                            "varargs": varargs,
                        }
                    ],
                },
            }
        ]
    }


def _atlas(tmp_path: Path) -> sqlite3.Connection:
    conn = open_atlas(tmp_path / "atlas.db")
    _seed_cross(conn)
    return conn


def _find(cands: list, ref: str):  # type: ignore[type-arg]
    return next((c for c in cands if c.evidence_ref == ref), None)


def _ctrl(c) -> str:  # type: ignore[no-untyped-def]
    return c.dim("controllability").value


# ── M5.7 + M5.12: a web-settable key reaching the sink ⇒ controllable ──────────────────


def test_web_settable_key_reaching_sink_is_controllable(tmp_path: Path) -> None:
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp_fb", sink_class="fmt_string")
    ref = _inst(
        conn,
        p,
        sink_anchor="fprintf",
        flow_evidence=_stack_buf_prov("fprintf", [_getter_vararg("fb_comment")]),
        source_kind="unknown",  # top-level source_kind is collapsed — the verdict must not need it
    )
    conn.close()
    c = _find(triage(open_atlas(tmp_path / "atlas.db")), ref)
    assert _ctrl(c) == "controllable"  # SEAM PROPERTY: survives the merge


def test_non_web_settable_getter_key_is_not_promoted(tmp_path: Path) -> None:
    # firmver: a back-end key but not an editable front-end field -> web_settable=uncertain (④: no
    # 'no' state) -> NOT controllable -> falls through to source_kind.
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp_fw", sink_class="fmt_string")
    ref = _inst(
        conn,
        p,
        sink_anchor="fprintf",
        flow_evidence=_stack_buf_prov("fprintf", [_getter_vararg("firmver")]),
        source_kind="unknown",
    )
    conn.close()
    c = _find(triage(open_atlas(tmp_path / "atlas.db")), ref)
    assert _ctrl(c) != "controllable"
    assert _ctrl(c) == "unknown"  # a non-settable getter return: neither const nor controllable


def test_getpid_call_return_is_not_optimistically_controllable(tmp_path: Path) -> None:
    # The de-optimism: an arbitrary call_return (getpid) is NO LONGER assumed controllable.
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp_pid", sink_class="cmd")
    pid_va = {
        "pos": 3,
        "spec": "%d",
        "source": {"kind": "call_return", "callee": "getpid", "const_args": [], "arg_count": 0},
    }
    ref = _inst(
        conn,
        p,
        sink_anchor="system",
        flow_evidence=_stack_buf_prov("system", [pid_va]),
        source_kind="unknown",
    )
    conn.close()
    c = _find(triage(open_atlas(tmp_path / "atlas.db")), ref)
    assert _ctrl(c) != "controllable"


# ── M5.8: a value-forwarding copy of a constant literal ⇒ constant (fix free≠constant) ─


def test_strcpy_of_constant_is_constant_despite_unresolved_dst(tmp_path: Path) -> None:
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp_ipsec", sink_class="cmd")
    prov = {
        "sink_arg_provenance": [
            {
                "sink": "popen",
                "sink_idx": 0,
                "provenance": {
                    "kind": "call_return",
                    "callee": "strcpy",
                    "const_args": ["ipsec statusall"],
                    "arg_count": 2,
                    "has_unresolved_args": True,  # the DST buffer — irrelevant to the copied value
                },
            }
        ]
    }
    # top-level source_kind=free_string once read 'free'; the verdict must now read constant.
    ref = _inst(conn, p, sink_anchor="popen", flow_evidence=prov, source_kind="free_string")
    conn.close()
    c = _find(triage(open_atlas(tmp_path / "atlas.db")), ref)
    assert _ctrl(c) == "constant"  # one verdict — no free/constant contradiction


# ── M5.9: the demotion iron law — a variadic exec seen only at arg0 ⇒ NEVER constant ───


def test_variadic_exec_seen_only_at_arg0_is_unknown_not_constant(tmp_path: Path) -> None:
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp_execl", sink_class="cmd")
    # execl("/bin/sh","sh","-c",param) — the extractor captured ONLY arg0 as a constant.
    prov = {
        "sink_arg_provenance": [
            {
                "sink": "execl",
                "sink_idx": 0,
                "provenance": {
                    "kind": "constant",
                    "value": "/bin/sh",
                    "value_kind": "literal_string",
                },
            }
        ]
    }
    ref = _inst(conn, p, sink_anchor="execl", flow_evidence=prov, source_kind="unknown")
    conn.close()
    c = _find(triage(open_atlas(tmp_path / "atlas.db")), ref)
    assert _ctrl(c) != "constant"  # MUST NOT demote — param is an uncaptured command arg
    assert _ctrl(c) == "unknown"


def test_system_single_constant_arg_is_still_constant(tmp_path: Path) -> None:
    # Contrast to execl: system() takes the WHOLE command in one arg, so a single constant IS proof.
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp_sys", sink_class="cmd")
    prov = {
        "sink_arg_provenance": [
            {
                "sink": "system",
                "sink_idx": 0,
                "provenance": {
                    "kind": "constant",
                    "value": "/sbin/reboot",
                    "value_kind": "literal_string",
                },
            }
        ]
    }
    ref = _inst(conn, p, sink_anchor="system", flow_evidence=prov, source_kind="unknown")
    conn.close()
    c = _find(triage(open_atlas(tmp_path / "atlas.db")), ref)
    assert _ctrl(c) == "constant"


# ── scoping: a constant sink is NOT contaminated by a sibling sink's web-settable key ──


def test_verdict_is_scoped_to_the_anchored_sink(tmp_path: Path) -> None:
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp_two", sink_class="cmd")
    # One function, TWO sinks: system(constant) + fprintf(fb_comment). The @cmd candidate anchors on
    # system (constant) and must stay constant; the fb_comment reaches only the fprintf sibling.
    prov = {
        "sink_arg_provenance": [
            {
                "sink": "system",
                "sink_idx": 0,
                "provenance": {
                    "kind": "constant",
                    "value": "/usr/sbin/netstat -r",
                    "value_kind": "literal_string",
                },
            },
            {
                "sink": "fprintf",
                "sink_idx": 1,
                "provenance": {
                    "kind": "stack_buf",
                    "nearest_dominating_writer": "snprintf@0x2",
                    "writers": [
                        {
                            "writer": "snprintf@0x2",
                            "dominates_sink": True,
                            "fmt": "%s",
                            "varargs": [_getter_vararg("fb_comment")],
                        }
                    ],
                },
            },
        ]
    }
    cmd_ref = _inst(conn, p, sink_anchor="system", flow_evidence=prov, blocking="const_sink_arg")
    conn.close()
    c = _find(triage(open_atlas(tmp_path / "atlas.db")), cmd_ref)
    assert _ctrl(c) == "constant"  # scoped to system — NOT promoted by the fprintf sibling


# ── M4: proven-controllable ranks ABOVE optimistic 'free' ──────────────────────────────


def test_controllable_ranks_above_free(tmp_path: Path) -> None:
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp_ctrl", sink_class="cmd")
    q = _pattern(conn, "fp_free", sink_class="cmd")
    ctrl_ref = _inst(
        conn,
        p,
        sink_anchor="system",
        flow_evidence=_stack_buf_prov("system", [_getter_vararg("wrs_cc_t")]),
    )
    free_ref = _inst(conn, q, sink_anchor="system", source_kind="free_string")
    conn.close()
    cands = triage(open_atlas(tmp_path / "atlas.db"))
    ranked = sort_candidates(cands, spine="impact")
    order = [c.evidence_ref for c in ranked]
    assert _ctrl(_find(cands, ctrl_ref)) == "controllable"
    assert _ctrl(_find(cands, free_ref)) == "free"
    assert order.index(ctrl_ref) < order.index(free_ref)  # controllable band above free band


def test_proven_controllable_ranks_above_param_unknown_same_tier(tmp_path: Path) -> None:
    # ★ param guardrail 3 (spec M3b): the orthogonal source=param float NEVER overrides certainty —
    # in the same impact tier (cmd) a proven-controllable nvram candidate outranks an external_input
    # source=param one whose controllability is only unknown. param lifts a lead to "worth a look";
    # it does not vault it past a proven-controllable verdict.
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp_ctrl", sink_class="cmd")  # source_class=unknown -> NOT a param source
    ctrl_ref = _inst(
        conn,
        p,
        sink_anchor="system",
        flow_evidence=_stack_buf_prov("system", [_getter_vararg("wrs_cc_t")]),
    )
    ext_pid = upsert_pattern(
        conn,
        source_class="external_input",
        sink_class="cmd",
        call_sequence_shape="source->sink",
        structural_fingerprint="fp_param",
        fingerprint_algo_version="callseq-v1",
    )
    _FID[0] += 1
    param_ref = f"run_1#fn{_FID[0]}@system"
    add_instance(
        conn,
        InstanceRow(
            pattern_id=ext_pid,
            pseudocode_hash=f"h{_FID[0]}",
            source_anchor=f"fn{_FID[0]}",
            sink_anchor="system",
            source_run_id="run_1",
            reachability_status="unknown",
            blocking_mechanism=None,
            provenance_level="L0",
            evidence_ref=param_ref,
            scope_origin="intra",
            origin="unknown",
            flow_evidence=None,
        ),
    )
    conn.close()
    cands = triage(open_atlas(tmp_path / "atlas.db"))
    order = [c.evidence_ref for c in sort_candidates(cands, spine="impact")]
    ctrl, param = _find(cands, ctrl_ref), _find(cands, param_ref)
    assert _ctrl(ctrl) == "controllable"
    assert param.dim("source").value == "param" and _ctrl(param) == "unknown"
    assert order.index(ctrl_ref) < order.index(param_ref)  # certainty wins over the param float


# ── M5.13 demotion audit + M5.14 re-rank invariant ─────────────────────────────────────


def test_no_constant_candidate_hides_a_web_settable_key(tmp_path: Path) -> None:
    # DEMOTION AUDIT: every candidate the verdict marks 'constant' must carry NO web-settable key at
    # its anchored sink (else it would have been 'controllable' — the precedence guarantees it).
    from treasure_map.lib.query.triage import _row_get, _web_settable_keys_reaching_sink

    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp_c", sink_class="cmd")
    _inst(
        conn,
        p,
        sink_anchor="popen",
        flow_evidence={
            "sink_arg_provenance": [
                {
                    "sink": "popen",
                    "sink_idx": 0,
                    "provenance": {
                        "kind": "call_return",
                        "callee": "strcpy",
                        "const_args": ["ipsec statusall"],
                        "arg_count": 2,
                        "has_unresolved_args": True,
                    },
                }
            ]
        },
    )
    _inst(
        conn,
        p,
        sink_anchor="fprintf",
        flow_evidence=_stack_buf_prov("fprintf", [_getter_vararg("fb_comment")]),
    )
    atlas = open_atlas(tmp_path / "atlas.db")
    cands = triage(atlas)
    for c in cands:
        if c.dim("controllability").value != "constant":
            continue
        row = atlas.execute(
            "SELECT flow_evidence FROM instance WHERE evidence_ref = ?", (c.evidence_ref,)
        ).fetchone()
        keys = _web_settable_keys_reaching_sink(
            atlas, _row_get(row, "flow_evidence"), c.sink_anchor
        )
        assert keys == [], f"constant candidate {c.evidence_ref} hides web-settable key {keys}"
    atlas.close()


def test_reranking_never_reduces_candidate_count(tmp_path: Path) -> None:
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp_a", sink_class="cmd")
    _inst(
        conn,
        p,
        sink_anchor="fprintf",
        flow_evidence=_stack_buf_prov("fprintf", [_getter_vararg("fb_comment")]),
    )
    _inst(conn, p, sink_anchor="system", source_kind="free_string")
    _inst(conn, p, sink_anchor="popen", blocking="const_sink_arg")
    conn.close()
    cands = triage(open_atlas(tmp_path / "atlas.db"))
    assert len(cands) == 3
    assert len(sort_candidates(cands, spine="controllability")) == len(cands)


# ── ⑤ detection fallback chain: source_kind=free_string is NOT abandoned ────────────────


def test_provenance_shallow_free_string_stays_free_not_unknown(tmp_path: Path) -> None:
    # The 263-argv protection: a candidate with NO provenance depth (no web-key, not provably const)
    # and source_kind=free_string must read 'free' via the fallback, NOT collapse to unknown.
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp_argv", sink_class="cmd")
    ref = _inst(conn, p, sink_anchor="system", source_kind="free_string")  # no provenance
    conn.close()
    c = _find(triage(open_atlas(tmp_path / "atlas.db")), ref)
    assert _ctrl(c) == "free"


def test_optimistic_free_fallback_is_likely_never_proven(tmp_path: Path) -> None:
    # ★ HONESTY (proven-devaluation fix): the source_kind=free_string fallback is OPTIMISTIC — the
    # convergence-transforms are not subtracted, so a washed value can still read 'free'. Its state
    # must be 'likely' (optimistic, unconfirmed), NEVER 'proven'. The value stays 'free' (ranking
    # and the controllability=free filter untouched); only the certainty word changes so the note
    # (which already says OPTIMISTIC) stops being contradicted by a 'proven' label.
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp_free", sink_class="cmd")  # source_class=unknown: isolate controllability
    ref = _inst(conn, p, sink_anchor="system", source_kind="free_string")  # no provenance depth
    conn.close()
    d = _find(triage(open_atlas(tmp_path / "atlas.db")), ref).dim("controllability")
    assert (d.state, d.value) == ("likely", "free")  # optimistic lead, never a proof
    assert "OPTIMISTIC" in d.note  # the note says optimistic; the state word now agrees


def test_proven_note_never_calls_its_own_reading_optimistic_or_unproven(tmp_path: Path) -> None:
    # ★ HONESTY invariant (terminology consistency): a state=='proven' dimension's OWN note must
    # never say 'optimistic' / 'unproven' — those two words are RESERVED for the demoted leads (the
    # likely 'free', the structural 'param'), so 'proven' can never read as a self-contradiction.
    # Built with a REAL proven-controllable (SaTC cross) + a proven-constant, so a regression that
    # re-imports either word into a proven note (e.g. a comparative 'above the optimistic free') is
    # caught — and a real proof is still present, guarding against over-correction.
    conn = _atlas(tmp_path)
    ctrl_ev = _stack_buf_prov("system", [_getter_vararg("fb_comment")])  # fb_comment: seeded cross
    _inst(conn, _pattern(conn, "fp_ctrl"), sink_anchor="system", flow_evidence=ctrl_ev)
    _inst(conn, _pattern(conn, "fp_const"), sink_anchor="system", blocking="const_sink_arg")
    _inst(conn, _pattern(conn, "fp_free"), sink_anchor="system", source_kind="free_string")
    proven_dims = 0
    for c in triage(open_atlas(tmp_path / "atlas.db")):
        for d in c.dimensions:
            if d.state == "proven":
                proven_dims += 1
                note = d.note.lower()
                assert "optimistic" not in note and "unproven" not in note, (
                    f"proven {d.name} note self-contradicts: {d.note!r}"
                )
    assert proven_dims  # real proofs (controllable + constant) present — not over-corrected


def test_provenance_deep_const_beats_source_kind_free_fallback(tmp_path: Path) -> None:
    # Ordering: a provenance-DEEP all-const candidate (ipsec strcpy) reads constant, even though its
    # top-level source_kind is free_string — the provenance verdict is checked before the fallback.
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp_deep", sink_class="cmd")
    prov = {
        "sink_arg_provenance": [
            {
                "sink": "popen",
                "sink_idx": 0,
                "provenance": {
                    "kind": "call_return",
                    "callee": "strcpy",
                    "const_args": ["fixed cmd"],
                    "arg_count": 2,
                    "has_unresolved_args": True,
                },
            }
        ]
    }
    ref = _inst(conn, p, sink_anchor="popen", flow_evidence=prov, source_kind="free_string")
    conn.close()
    c = _find(triage(open_atlas(tmp_path / "atlas.db")), ref)
    assert _ctrl(c) == "constant"  # const (step 2) wins over the free_string fallback (step 3)


# ── ⑥ promotion-recall: the fixed label set crosses YES (else the rule is named) ────────


def test_promotion_recall_label_set_crosses_yes(tmp_path: Path) -> None:
    # ⑥: the promote path now rides on M1 recall. A fixed label set of known-editable keys must all
    # cross to web_settable=yes once seeded (both sides present). A miss would be a silent埋没 the
    # demotion audit cannot catch (it is a missed promote, not a bad demote).
    from treasure_map.lib.query.nvram import _web_settable

    conn = open_atlas(tmp_path / "atlas.db")
    labels = ["fb_comment", "wl_ssid", "wl0_ssid", "ddns_hostname_x"]
    add_web_form_field_rows(
        conn,
        [
            WebFormFieldRow("run_1", k if k != "wl0_ssid" else "wl_ssid", "F.asp", "input")
            for k in labels
        ],
    )
    add_nvram_flow_rows(
        conn, [NvramFlowRow("run_1", k, "constant", "httpd", "save", "write") for k in labels]
    )
    for k in labels:
        assert _web_settable(conn, k)["web_settable"] == "yes", f"{k} did not cross YES"
    conn.close()


def test_promotion_recall_x_suffix_variant_is_uncertain_with_named_rule(tmp_path: Path) -> None:
    # ⑥ known gap, NAMED not hidden: http_username's editable field is the _x mirror
    # (http_username_x) -> uncertain this phase (never a false 'no'). Rule to add: an X_x suffix.
    from treasure_map.lib.query.nvram import _web_settable

    conn = open_atlas(tmp_path / "atlas.db")
    add_web_form_field_rows(conn, [WebFormFieldRow("run_1", "http_username_x", "F.asp", "input")])
    add_nvram_flow_rows(
        conn, [NvramFlowRow("run_1", "http_username", "constant", "httpd", "cred", "read")]
    )
    assert _web_settable(conn, "http_username")["web_settable"] == "uncertain"
    conn.close()


# ── ⑦ callee classification is an extensible registry (nvram is class #1) ────────────────


def test_call_return_classifier_registry_is_extensible(tmp_path: Path) -> None:
    # ⑦: adding a FUTURE call_return class (e.g. getenv->controllable) is a registry row, with the
    # verdict logic unchanged. Prove the registry is the extension seam and classification is data.
    import importlib

    mod = importlib.import_module("treasure_map.lib.query.triage")  # the module (not the function)

    conn = open_atlas(tmp_path / "atlas.db")
    getenv_src = {"kind": "call_return", "callee": "getenv", "const_args": ["HTTP_USER_AGENT"]}
    assert mod._classify_source(conn, getenv_src) == "unknown"  # unclassified this phase

    def _cr_getenv(_conn: object, source: dict) -> str | None:  # type: ignore[type-arg]
        return "controllable" if source.get("callee") == "getenv" else None

    original = mod._CALL_RETURN_CLASSIFIERS
    mod._CALL_RETURN_CLASSIFIERS = (*original, _cr_getenv)
    try:
        assert mod._classify_source(conn, getenv_src) == "controllable"  # one row, logic unchanged
    finally:
        mod._CALL_RETURN_CLASSIFIERS = original
    conn.close()


# ── 支配传导 (dominance propagation): only a dominating writer decides a stack_buf sink ──


def _writer(fmt: str, varargs: list, *, dominates: bool) -> dict:  # type: ignore[type-arg]
    return {"writer": "snprintf@0x1", "dominates_sink": dominates, "fmt": fmt, "varargs": varargs}


def _writer_no_dom_field(fmt: str, varargs: list) -> dict:  # type: ignore[type-arg]
    # a writer with NO dominates_sink field at all (pre-field / older provenance)
    return {"writer": "snprintf@0x2", "fmt": fmt, "varargs": varargs}


def _const_va(value: str = "fixed") -> dict:  # type: ignore[type-arg]
    return {
        "pos": 3,
        "spec": "%s",
        "source": {"kind": "constant", "value": value, "value_kind": "literal_string"},
    }


def _param_va() -> dict:  # type: ignore[type-arg]
    return {"pos": 3, "spec": "%s", "source": {"kind": "param", "name": "p"}}


def _stack_buf_multi(sink: str, writers: list) -> dict:  # type: ignore[type-arg]
    return {
        "sink_arg_provenance": [
            {"sink": sink, "sink_idx": 0, "provenance": {"kind": "stack_buf", "writers": writers}}
        ]
    }


def test_dominating_const_beats_nondominating_controllable_is_const(tmp_path: Path) -> None:
    # M2 case 3 (the wrs_cc_t core): a DOMINATING const writer + a NON-dominating writer carrying a
    # web-settable key -> const, NOT controllable. The non-dominating key flows to a different sink.
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp_case3", sink_class="cmd")
    prov = _stack_buf_multi(
        "system",
        [
            _writer("fixed cmd %s", [_const_va()], dominates=True),  # dominating: all const
            _writer(
                "SELECT %s", [_getter_vararg("fb_comment")], dominates=False
            ),  # web key, non-dom
        ],
    )
    ref = _inst(conn, p, sink_anchor="system", flow_evidence=prov, source_kind="unknown")
    conn.close()
    c = _find(triage(open_atlas(tmp_path / "atlas.db")), ref)
    assert _ctrl(c) == "constant"  # only the dominating (const) writer decided the sink


def test_all_dominating_writers_non_controllable_is_not_controllable(tmp_path: Path) -> None:
    # ★ seam property #8 (wrs_cc_t shape): if every DOMINATING writer lacks a controllable source,
    # the verdict is not controllable — even though a controllable web key sits in a non-dominating
    # writer. Guards against the dominance filter being bypassed / reverted to ANY-writer.
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp_wrs", sink_class="cmd")
    prov = _stack_buf_multi(
        "system",
        [
            _writer(
                "echo [BWMON]%s", [_param_va()], dominates=True
            ),  # dominating: unknown (DPI echo)
            _writer("SELECT %s", [_getter_vararg("wrs_cc_t")], dominates=False),  # web key, non-dom
        ],
    )
    ref = _inst(conn, p, sink_anchor="system", flow_evidence=prov, source_kind="unknown")
    conn.close()
    c = _find(triage(open_atlas(tmp_path / "atlas.db")), ref)
    assert _ctrl(c) != "controllable"


def test_dominating_web_key_is_controllable_despite_nondominating_noise(tmp_path: Path) -> None:
    # ★ seam property #7 (Chain 3 shape): the UNIQUE dominating writer's vararg is a web_settable
    # =YES key -> controllable, even with non-dominating noise writers present. Guards against a
    # future regression to ANY-writer (which would still pass) AND over-filtering that drops it.
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp_chain3", sink_class="fmt_string")
    prov = _stack_buf_multi(
        "fprintf",
        [
            _writer("Feedback: %s", [_getter_vararg("fb_comment")], dominates=True),  # web key, dom
            _writer("noise %s", [_const_va()], dominates=False),  # non-dominating const noise
        ],
    )
    ref = _inst(conn, p, sink_anchor="fprintf", flow_evidence=prov, source_kind="unknown")
    conn.close()
    c = _find(triage(open_atlas(tmp_path / "atlas.db")), ref)
    assert _ctrl(c) == "controllable"


def test_no_dominating_writer_falls_back_to_all_not_unknown(tmp_path: Path) -> None:
    # M2 case 2 (evidence-absent never infers safe): NO writer is marked dominating -> fall back to
    # ALL writers, so a web key still lights controllable instead of collapsing to unknown/safe.
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp_fallback", sink_class="cmd")
    prov = _stack_buf_multi(
        "system", [_writer("%s", [_getter_vararg("fb_comment")], dominates=False)]
    )
    ref = _inst(conn, p, sink_anchor="system", flow_evidence=prov, source_kind="unknown")
    conn.close()
    c = _find(triage(open_atlas(tmp_path / "atlas.db")), ref)
    assert _ctrl(c) == "controllable"  # fallback preserved the pre-fix behavior, did not hide it


def test_pre_field_provenance_without_dominates_sink_falls_back(tmp_path: Path) -> None:
    # graceful degradation: older provenance whose writers have NO dominates_sink field at all ->
    # w.get() is None -> falsy -> dominating empty -> fall back to all writers (old semantics).
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp_prefield", sink_class="cmd")
    prov = _stack_buf_multi("system", [_writer_no_dom_field("%s", [_getter_vararg("fb_comment")])])
    ref = _inst(conn, p, sink_anchor="system", flow_evidence=prov, source_kind="unknown")
    conn.close()
    c = _find(triage(open_atlas(tmp_path / "atlas.db")), ref)
    assert _ctrl(c) == "controllable"


def test_single_dominating_writer_behavior_unchanged(tmp_path: Path) -> None:
    # M2 case 5: a single dominating writer -> dominating == [that one] == judged, no change.
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp_single", sink_class="fmt_string")
    prov = _stack_buf_multi(
        "fprintf", [_writer("Feedback: %s", [_getter_vararg("fb_comment")], dominates=True)]
    )
    ref = _inst(conn, p, sink_anchor="fprintf", flow_evidence=prov, source_kind="unknown")
    conn.close()
    c = _find(triage(open_atlas(tmp_path / "atlas.db")), ref)
    assert _ctrl(c) == "controllable"


# ── Phase 4: wrapper-aware source attribution (M1) + in_router_defaults likely recall (M2/M3) ──
#
# The false-low fix: a real web-controllable command injection (the OAuth class) reads its nvram key
# through a THIN WRAPPER, not a bare getter. Candidate-layer attribution used to recognise only
# direct getters, so the wrapper-read key was attributed to nothing and the sink collapsed to
# unknown. M1 reuses A2's already-materialised wrapper set (nvram_key_flow.via_wrapper); M2 adds a
# ``likely`` web_settable tier for a router_defaults member; M3 ranks likely-controllable below
# proven-controllable and above optimistic 'free'.


def _register_wrapper(conn: sqlite3.Connection, callee: str, key: str) -> None:
    """Materialise ``callee`` as an A2 thin nvram wrapper reading ``key`` — the atlas shape triage
    reads back as ``wrapper_names`` (SELECT DISTINCT via_wrapper). The read edge also makes ``key``
    a back-end nvram key (so it is a genuine nvram read, exactly as M1's gate requires)."""
    add_nvram_flow_rows(
        conn,
        [NvramFlowRow("run_1", key, "constant", "httpd", "wrap_read", "read", via_wrapper=callee)],
    )


def _seed_default(conn: sqlite3.Connection, *keys: str) -> None:
    """Make ``keys`` router_defaults members (and locate+complete the table, so any OTHER key reads
    a definite in_router_defaults=False rather than 'uncertain')."""
    add_nvram_default_rows(conn, [NvramDefaultRow("run_1", k) for k in keys])


def test_wrapper_read_key_resolves_nvram_source_key(tmp_path: Path) -> None:
    # ★ SEAM #12: a wrapper-read nvram candidate whose getter-return const_args[0] is the key ⇒
    # nvram_source_key is non-None. Guards against M1 regressing to direct-getter-only attribution.
    conn = _atlas(tmp_path)
    _register_wrapper(conn, "FUN_000b2e80", "oauth_auth_code")
    p = _pattern(conn, "fp_wrap", sink_class="cmd")
    ref = _inst(
        conn,
        p,
        sink_anchor="system",
        flow_evidence=_stack_buf_prov(
            "system", [_getter_vararg("oauth_auth_code", callee="FUN_000b2e80")]
        ),
        source_kind="unknown",
    )
    conn.close()
    c = _find(triage(open_atlas(tmp_path / "atlas.db")), ref)
    assert c.nvram_source_key == "oauth_auth_code"  # wrapper-read key attributed, not None


def test_unregistered_callee_leaves_nvram_source_key_unresolved(tmp_path: Path) -> None:
    # The honest boundary of M1: an nvram-shaped call_return whose callee is NEITHER a known getter
    # NOR an A2 thin wrapper is not trusted as an nvram read -> nvram_source_key stays None (the
    # pre-fix state, kept honest — we do not fabricate a key from any incidental const string).
    conn = _atlas(tmp_path)  # no wrapper registered
    p = _pattern(conn, "fp_unreg", sink_class="cmd")
    ref = _inst(
        conn,
        p,
        sink_anchor="system",
        flow_evidence=_stack_buf_prov(
            "system", [_getter_vararg("some_key", callee="FUN_not_a_wrapper")]
        ),
        source_kind="unknown",
    )
    conn.close()
    c = _find(triage(open_atlas(tmp_path / "atlas.db")), ref)
    assert c.nvram_source_key is None


def test_router_defaults_member_wrapper_key_is_likely_controllable(tmp_path: Path) -> None:
    # M2/M3 verdict: a wrapper-read key that is a router_defaults member but NOT a proven SaTC cross
    # -> controllability value 'controllable' with state 'likely' (the OAuth shape).
    conn = _atlas(tmp_path)
    _register_wrapper(conn, "FUN_000b2e80", "oauth_auth_code")
    _seed_default(conn, "oauth_auth_code")
    p = _pattern(conn, "fp_oauth", sink_class="cmd")
    ref = _inst(
        conn,
        p,
        sink_anchor="system",
        flow_evidence=_stack_buf_prov(
            "system", [_getter_vararg("oauth_auth_code", callee="FUN_000b2e80")]
        ),
        source_kind="unknown",
    )
    conn.close()
    c = _find(triage(open_atlas(tmp_path / "atlas.db")), ref)
    d = c.dim("controllability")
    assert (d.state, d.value) == ("likely", "controllable")
    swr = c.dim("source_writability")
    assert (swr.state, swr.value) == ("likely", "web_settable")


def test_source_writability_dimension_carries_web_evidence() -> None:
    # explain_candidate drill-down: the source_writability dimension exposes the web_form_fields
    # rows behind a web_settable reading, so an agent confirms the web reach or demotes a keyword
    # collision without re-deriving. Evidence rides along; the verdict (state/value) is unchanged.
    from treasure_map.lib.query.triage import _dim_source_writability

    ev = [
        {
            "field_keyword": "fb_comment",
            "source_asset": "Feedback_Info.asp",
            "source_rule": "textarea",
            "match_kind": "exact",
        }
    ]
    d = _dim_source_writability(
        "fb_comment", {"web_settable": "yes", "source": "x", "evidence": ev}
    )
    assert (d.state, d.value) == ("proven", "web_settable")  # verdict unchanged by evidence
    assert d.evidence == tuple(ev)  # the concrete drill-down rows are surfaced


def test_wrapper_read_non_default_key_stays_unknown(tmp_path: Path) -> None:
    # ★ M4.5 guardrail: a wrapper-read key that is NOT a router_defaults member (table located) must
    # NOT be promoted to likely -- the in_router_defaults gate holds internal keys out. It falls
    # through to unknown, never a false 'likely' (the log_wlstat_dir / productid case).
    conn = _atlas(tmp_path)
    _register_wrapper(conn, "FUN_000b2e80", "log_wlstat_dir")
    _seed_default(conn, "http_passwd")  # table located+complete; log_wlstat_dir is NOT a member
    p = _pattern(conn, "fp_internal", sink_class="cmd")
    ref = _inst(
        conn,
        p,
        sink_anchor="system",
        flow_evidence=_stack_buf_prov(
            "system", [_getter_vararg("log_wlstat_dir", callee="FUN_000b2e80")]
        ),
        source_kind="unknown",
    )
    conn.close()
    c = _find(triage(open_atlas(tmp_path / "atlas.db")), ref)
    d = c.dim("controllability")
    assert (d.state, d.value) == ("unknown", "unknown")  # gate held: no false promote


def test_proven_controllable_outranks_likely_controllable(tmp_path: Path) -> None:
    # M3.8: within the SAME sink-impact tier, a proven SaTC cross (state proven) ranks above a
    # likely router_defaults key (state likely) -- the certainty tiebreak, proven micro-leads.
    conn = _atlas(tmp_path)
    _register_wrapper(conn, "FUN_000b2e80", "oauth_auth_code")
    _seed_default(conn, "oauth_auth_code")
    pv = _pattern(conn, "fp_proven", sink_class="cmd")
    lk = _pattern(conn, "fp_likely", sink_class="cmd")
    proven_ref = _inst(
        conn,
        pv,
        sink_anchor="system",
        flow_evidence=_stack_buf_prov("system", [_getter_vararg("fb_comment")]),
    )
    likely_ref = _inst(
        conn,
        lk,
        sink_anchor="system",
        flow_evidence=_stack_buf_prov(
            "system", [_getter_vararg("oauth_auth_code", callee="FUN_000b2e80")]
        ),
    )
    conn.close()
    cands = triage(open_atlas(tmp_path / "atlas.db"))
    order = [c.evidence_ref for c in sort_candidates(cands, spine="impact")]
    assert _ctrl(_find(cands, proven_ref)) == "controllable"
    assert _find(cands, proven_ref).dim("controllability").state == "proven"
    assert _find(cands, likely_ref).dim("controllability").state == "likely"
    assert order.index(proven_ref) < order.index(likely_ref)


def test_likely_controllable_outranks_free(tmp_path: Path) -> None:
    # M3: within the same sink-impact tier, likely-controllable (a real-but-unconfirmed nvram key)
    # outranks the optimistic 'free' (source_kind=free_string). A router_defaults RCE lead beats a
    # bare argv guess -- harm plus a real key both point up.
    conn = _atlas(tmp_path)
    _register_wrapper(conn, "FUN_000b2e80", "oauth_auth_code")
    _seed_default(conn, "oauth_auth_code")
    lk = _pattern(conn, "fp_lk", sink_class="cmd")
    fr = _pattern(conn, "fp_fr", sink_class="cmd")
    likely_ref = _inst(
        conn,
        lk,
        sink_anchor="system",
        flow_evidence=_stack_buf_prov(
            "system", [_getter_vararg("oauth_auth_code", callee="FUN_000b2e80")]
        ),
    )
    free_ref = _inst(conn, fr, sink_anchor="system", source_kind="free_string")
    conn.close()
    cands = triage(open_atlas(tmp_path / "atlas.db"))
    order = [c.evidence_ref for c in sort_candidates(cands, spine="impact")]
    assert _find(cands, likely_ref).dim("controllability").state == "likely"
    assert _ctrl(_find(cands, free_ref)) == "free"
    assert order.index(likely_ref) < order.index(free_ref)


def test_likely_cmd_outranks_optimistic_free_lower_impact(tmp_path: Path) -> None:
    # M3 harm-respect (impact is the OUTER axis): a likely-controllable cmd sink outranks an
    # optimistic-'free' LOG sink -- a high-impact unconfirmed lead beats a low-impact one, so the
    # worst bug never falls off the top screen. (Both are unproven leads: likely-controllable and
    # the optimistic 'free' fallback -- impact, not a 'proven' band, governs.)
    conn = _atlas(tmp_path)
    _register_wrapper(conn, "FUN_000b2e80", "oauth_auth_code")
    _seed_default(conn, "oauth_auth_code")
    lk = _pattern(conn, "fp_lkcmd", sink_class="cmd")
    lg = _pattern(conn, "fp_provenlog", sink_class="log")
    likely_ref = _inst(
        conn,
        lk,
        sink_anchor="system",
        flow_evidence=_stack_buf_prov(
            "system", [_getter_vararg("oauth_auth_code", callee="FUN_000b2e80")]
        ),
    )
    log_ref = _inst(conn, lg, sink_anchor="syslog", source_kind="free_string")
    conn.close()
    cands = triage(open_atlas(tmp_path / "atlas.db"))
    order = [c.evidence_ref for c in sort_candidates(cands, spine="impact")]
    assert _find(cands, likely_ref).dim("controllability").state == "likely"
    assert order.index(likely_ref) < order.index(log_ref)  # impact outer axis: cmd over log


def test_proven_controllable_not_regressed_by_likely_tier(tmp_path: Path) -> None:
    # NO-REGRESSION: adding the likely tier must not change a proven SaTC cross's reading. Even
    # with router_defaults seeded (so the key is ALSO a member), a proven cross stays
    # proven-controllable, never demoted to likely (the 'yes' branch precedes the likely branch).
    conn = _atlas(tmp_path)
    _seed_default(conn, "fb_comment")  # fb_comment is BOTH a proven cross AND a defaults member
    p = _pattern(conn, "fp_noreg", sink_class="fmt_string")
    ref = _inst(
        conn,
        p,
        sink_anchor="fprintf",
        flow_evidence=_stack_buf_prov("fprintf", [_getter_vararg("fb_comment")]),
        source_kind="unknown",
    )
    conn.close()
    c = _find(triage(open_atlas(tmp_path / "atlas.db")), ref)
    d = c.dim("controllability")
    assert (d.state, d.value) == ("proven", "controllable")  # proven wins over likely


# ── detector B iron law: a string-keyed edge is a KEY LEAD, never a reachability grant ──


def test_string_keyed_edge_never_flips_reachability_to_proven() -> None:
    # ★ THE IRON LAW, asserted directly on the dimension: a detected string-keyed edge (this
    # function is a dispatch callee) is a KEY LEAD, never a reachability verdict. With NO entry
    # reference, reachability STAYS unknown even when an edge points at the function — tmap
    # ENUMERATES the edge (a fact); the agent JUDGES reachability. Neutral key only.
    from treasure_map.lib.query.triage import _dim_reachability

    edge = {
        "key": "oauth_auth_code",
        "from_function": "handle_dispatch",
        "mechanism": "strcmp_gate",
    }
    d = _dim_reachability("unknown", (), (edge,))
    assert d.state == "unknown"  # NOT proven / reachable — the edge does not grant reach
    assert d.value == "unknown"
    assert "oauth_auth_code" in d.note  # the key lead is surfaced for the agent
    assert "STAYS unknown" in d.note  # explicit: enumerated edge, not a reachability judgement


def test_string_keyed_edge_note_rides_on_proven_entry_without_causing_it() -> None:
    # When an entry reference already makes reachability 'proven' (the ENTRY reason), the edge lead
    # still rides in the note — but the edge did NOT cause the proven state (entry sourced it).
    from treasure_map.lib.query.triage import _dim_reachability

    edge = {"key": "reboot", "from_function": "router", "mechanism": "strcmp_gate"}
    d = _dim_reachability("entry:web", ("Form.asp",), (edge,))
    assert (d.state, d.value) == (
        "proven",
        "entry:web",
    )  # from the entry ref, unchanged by the edge
    assert "reboot" in d.note  # the edge lead still surfaces


def test_no_string_keyed_edge_leaves_reachability_note_edge_free() -> None:
    # The annotation is purely ADDITIVE: with no edge, no edge note is appended.
    from treasure_map.lib.query.triage import _dim_reachability

    d = _dim_reachability("unknown", (), ())
    assert d.state == "unknown"
    assert "STRING-KEYED EDGE" not in d.note


def _one_hop_ev(*leads: dict[str, object]) -> str:
    return json.dumps({"reachability_leads": list(leads)})


def test_one_hop_lead_is_structured_and_carries_the_data_arrival_caveat() -> None:
    # ★ THE new capability: the flagship sink sits one call BELOW the edge callee. It gets a
    # structured lead {via, key, hops:1, through} an agent reads without parsing prose, and a note
    # that says outright the hop is STRUCTURAL — the edge callee calls it, but whether the
    # key-selected data arrives is unproven (its edge callee is a fat handler).
    from treasure_map.lib.query.triage import _dim_reachability

    ev = _one_hop_ev(
        {"via": "string_keyed_edge", "key": "oauth_auth_code", "hops": 1, "through": "FUN_000b643c"}
    )
    d = _dim_reachability("unknown", (), (), ev)
    assert d.state == "unknown" and d.value == "unknown"  # ★ IRON LAW: a lead is not a grant
    lead = next(x for x in d.evidence if x["hops"] == 1)
    assert lead["key"] == "oauth_auth_code"
    assert lead["through"] == "FUN_000b643c"
    assert lead["via"] == "string_keyed_edge"
    assert "NOT proven" in d.note  # the data-arrival caveat is mandatory on a 1-hop lead
    assert "STAYS unknown" in d.note
    assert "reached" not in d.note.lower()  # never the word that reads as a verdict


def test_fanout_edge_callee_hands_its_key_to_every_candidate_below() -> None:
    # A fat edge callee calls several sinks; each of them gets the same key lead through it.
    from treasure_map.lib.query.triage import _dim_reachability

    for sink in ("FUN_000b32a0", "FUN_000b2ec0"):
        ev = _one_hop_ev(
            {
                "via": "string_keyed_edge",
                "key": "oauth_auth_code",
                "hops": 1,
                "through": "FUN_000b643c",
            }
        )
        d = _dim_reachability("unknown", (), (), ev)
        assert d.state == "unknown", sink
        assert d.evidence[0]["through"] == "FUN_000b643c"


def test_zero_hop_keeps_its_tight_wording_and_gains_a_structured_lead() -> None:
    # REGRESSION GUARD: zero hop already worked in prose. Its tight wording ("dispatches HERE") must
    # not be loosened into the 1-hop caveat, and it now also carries hops:0 structurally.
    from treasure_map.lib.query.triage import _dim_reachability

    edge = {
        "key": "oauth_auth_code",
        "from_function": "handle_dispatch",
        "mechanism": "strcmp_gate",
    }
    d = _dim_reachability("unknown", (), (edge,))
    assert d.state == "unknown"
    assert "callee of a STRING-KEYED EDGE" in d.note  # the existing tight 0-hop wording, unchanged
    assert "one call above" not in d.note  # the loose 1-hop wording must NOT leak onto 0 hop
    assert d.evidence[0]["hops"] == 0
    assert d.evidence[0]["key"] == "oauth_auth_code"


def test_zero_and_one_hop_leads_coexist_without_changing_state() -> None:
    from treasure_map.lib.query.triage import _dim_reachability

    edge = {"key": "k0", "from_function": "d", "mechanism": "strcmp_gate"}
    ev = _one_hop_ev({"via": "string_keyed_edge", "key": "k1", "hops": 1, "through": "E"})
    d = _dim_reachability("unknown", (), (edge,), ev)
    assert d.state == "unknown" and d.value == "unknown"
    assert {x["hops"] for x in d.evidence} == {0, 1}


def test_lead_free_candidate_carries_no_lead_evidence() -> None:
    # Purely additive: no edge, no leads, and the note is untouched.
    from treasure_map.lib.query.triage import _dim_reachability

    d = _dim_reachability("unknown", (), (), json.dumps({"source_kind": "free_string"}))
    assert d.evidence == ()
    assert "one call above" not in d.note


def test_static_string_table_edge_also_stays_unknown() -> None:
    # The iron law is mechanism-agnostic: a detector-A static {string -> funcptr} table entry is a
    # key lead exactly like a strcmp gate — the candidate stays reachability=unknown.
    from treasure_map.lib.query.triage import _dim_reachability

    edge = {"key": "nvram_dump", "from_function": None, "mechanism": "static_string_table"}
    d = _dim_reachability("unknown", (), (edge,))
    assert d.state == "unknown"
    assert d.value == "unknown"
    assert "nvram_dump" in d.note


# ── the completeness gate: a sink that left no def-use record here cannot be called constant ──
#
# The shape all of these are about: the candidate's real sink sits behind a thin forwarding
# wrapper, so the caller's provenance describes the caller's OWN other sinks and never the wrapped
# one. Both constant exits would otherwise read "constant" off evidence that never saw the sink
# being judged — an error in the one direction the map forbids, since a wrong 'safe' sinks a real
# lead out of the first screen and nobody looks again.


def _const_record(sink: str, value: str = "/bin/echo hello") -> dict[str, object]:
    """One def-use record whose sink argument is a plain readable string constant."""
    return {
        "sink": sink,
        "sink_idx": 0,
        "provenance": {"kind": "constant", "value": value, "value_kind": "literal_string"},
    }


def _dim_of(conn: sqlite3.Connection, ref: str) -> tuple[str, str]:
    (cand,) = [c for c in triage(conn) if c.evidence_ref == ref]
    dim = cand.dim("controllability")
    return dim.state, dim.value


def test_escaped_sink_is_not_called_constant_off_its_siblings(tmp_path: Path) -> None:
    # G1 — the gate itself, on the provenance exit. The anchor is `system`; every record present
    # belongs to some OTHER sink the caller logs through. "All records are constant" is true and
    # meaningless: the value handed to `system` was never looked at.
    #
    # MUTATION (verified RED, 1 failed): in triage._dim_controllability drop the gate from the
    # provenance exit — `if prov_verdict == "const":` in place of
    # `if const_trustworthy and prov_verdict == "const":` -> this candidate reads
    # ('proven', 'constant') again.
    conn = open_atlas(tmp_path / "atlas.db")
    try:
        pid = _pattern(conn, "fp_g1")
        ref = _inst(
            conn,
            pid,
            sink_anchor="system",
            flow_evidence={
                "sink_arg_provenance": [_const_record("syslog", "cfg %s"), _const_record("syslog")]
            },
        )
        assert _dim_of(conn, ref) != ("proven", "constant")
    finally:
        conn.close()


def test_escaped_sink_with_a_constant_marker_is_not_called_constant(tmp_path: Path) -> None:
    # G5 — the SAME gate on the OTHER exit, end to end. This is the one a gate written only at the
    # provenance classifier misses entirely: `const_sink_arg` is computed from the caller's body,
    # which for an escaped sink holds a constant shell (a format string) around the conversion the
    # attacker fills. The marker is true about the caller and says nothing about the wrapped sink.
    #
    # MUTATION (verified RED, 1 failed): in triage._dim_controllability gate only the provenance
    # exit — restore `if blocking_mechanism in PROVABLY_CONSTANT_MARKERS:` without the
    # `const_trustworthy and` prefix -> this candidate reads ('proven', 'constant') again.
    conn = open_atlas(tmp_path / "atlas.db")
    try:
        pid = _pattern(conn, "fp_g5")
        ref = _inst(
            conn,
            pid,
            sink_anchor="system",
            blocking="const_sink_arg",
            flow_evidence={"sink_arg_provenance": [_const_record("syslog")]},
        )
        assert _dim_of(conn, ref) != ("proven", "constant")
    finally:
        conn.close()


def test_gate_never_suppresses_a_controllable_reading(tmp_path: Path) -> None:
    # G2 — the gate is one-directional. With the anchor missed, the liberal fallback may still show
    # a controllable source among the sibling records; that reading must survive untouched.
    # Promoting on partial evidence costs a review, demoting on it hides a real lead.
    #
    # MUTATION (verified RED, 1 failed): in triage._dim_controllability move the gate above the
    # controllable steps — insert `if _anchor_missed(flow_evidence, sink_anchor): return
    # _dim_unknown_controllability()` right after `prov_verdict = ...` (or simply return the
    # source_kind fallback there) -> this candidate stops reading ('proven', 'controllable').
    conn = open_atlas(tmp_path / "atlas.db")
    try:
        _seed_cross(conn)
        pid = _pattern(conn, "fp_g2")
        prov = _stack_buf_prov("syslog", [_getter_vararg("fb_comment")])
        ref = _inst(conn, pid, sink_anchor="system", flow_evidence=prov)
        assert _dim_of(conn, ref) == ("proven", "controllable")
    finally:
        conn.close()


def test_constant_still_asserted_when_the_anchored_sink_is_present(tmp_path: Path) -> None:
    # G3 — the gate must not become a blanket ban. With a record FOR the anchored sink, the
    # constant reading is exactly as sound as it was, and the thousands of legitimately-constant
    # candidates keep sinking out of the first screen.
    #
    # MUTATION (verified RED, 1 failed): in triage._dim_controllability hard-suppress the exits —
    # `const_trustworthy = False` in place of `not _anchor_missed(...)` -> this candidate stops
    # reading ('proven', 'constant').
    conn = open_atlas(tmp_path / "atlas.db")
    try:
        pid = _pattern(conn, "fp_g3")
        ref = _inst(
            conn,
            pid,
            sink_anchor="system",
            flow_evidence={"sink_arg_provenance": [_const_record("system")]},
        )
        assert _dim_of(conn, ref) == ("proven", "constant")
    finally:
        conn.close()


def test_variadic_iron_law_is_untouched_by_the_gate(tmp_path: Path) -> None:
    # G4 — the two completeness rules are at different levels and must both keep working. Here the
    # anchor IS present (the gate passes), and the RECORD-level rule still refuses to call a
    # variadic exec constant on the strength of arg0 alone.
    #
    # MUTATION (verified RED, 1 failed): in triage._record_class drop the variadic downgrade —
    # delete `if cls == "const" and rec.get("sink") in _MULTI_ARG_COMMAND_SINKS: return "unknown"`
    # -> this candidate reads ('proven', 'constant').
    conn = open_atlas(tmp_path / "atlas.db")
    try:
        pid = _pattern(conn, "fp_g4")
        ref = _inst(
            conn,
            pid,
            sink_anchor="execl",
            flow_evidence={"sink_arg_provenance": [_const_record("execl", "/bin/sh")]},
        )
        assert _dim_of(conn, ref) != ("proven", "constant")
    finally:
        conn.close()


def test_a_sink_class_def_use_does_not_cover_is_never_read_as_an_escape() -> None:
    # G6 — the DEFENSIVE guard, and the only one with no real-atlas instance behind it. Def-use
    # records exist for command and format sinks only, so "no record for fopen" means def-use does
    # not cover path sinks — never that a sink escaped.
    #
    # ★ The fixture carries a NON-EMPTY provenance on purpose. With an empty one the non-empty
    # guard would return False first and this test would pass without the def-use-sink guard ever
    # running — a guard that proves nothing. The assertion below pins that the records really are
    # non-empty, so the pass can only come from the guard under test.
    #
    # MUTATION (verified RED, 1 failed): in triage._anchor_missed delete
    # `if sink_anchor not in _DEF_USE_SINKS: return False` -> this path candidate is read as an
    # escape.
    from treasure_map.lib.query.triage import _anchor_missed, _sink_provenance_records

    evidence = json.dumps({"sink_arg_provenance": [_const_record("system")]})
    assert _sink_provenance_records(evidence), "fixture must be non-empty or G6 proves nothing"
    assert _anchor_missed(evidence, "fopen") is False


def test_absent_provenance_is_not_read_as_an_escape() -> None:
    # G7 — the LOAD-BEARING non-empty guard, anchored on a shape a real atlas is full of: a
    # command/format sink whose candidate carries no def-use records at all. That is "nothing was
    # captured here", which the classifier already answers with None — reading it as an escape
    # would widen the gate by roughly two orders of magnitude and start demoting candidates whose
    # constant reading is perfectly sound.
    #
    # MUTATION (verified RED, 1 failed): in triage._anchor_missed delete
    # `if not records: return False` -> these candidates are read as escapes.
    from treasure_map.lib.query.triage import _anchor_missed

    assert _anchor_missed(json.dumps({"sink_arg_provenance": []}), "vfprintf") is False
    assert _anchor_missed(json.dumps({"source_kind": "unknown"}), "system") is False
    assert _anchor_missed(None, "system") is False
