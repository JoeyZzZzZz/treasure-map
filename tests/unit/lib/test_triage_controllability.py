# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
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
from treasure_map.lib.atlas.models import InstanceRow, NvramFlowRow, WebFormFieldRow
from treasure_map.lib.atlas.writer import (
    add_instance,
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
