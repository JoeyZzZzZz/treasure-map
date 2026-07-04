# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for lib/hunt/evidence — structured flow evidence for a command-sink candidate.

Synthetic, vendor-neutral pseudocode + an in-memory entry index. The module produces EVIDENCE,
never a judgement: these tests pin the give-enough-give-all behaviour (reliable flow + all entry
sites) and the honest blind spots (sanitizer coverage always unjudged, entry-not-found is
unknown not unreachable, trace boundary states where it stopped), and guard that nothing here
feeds the score / recall / grade.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from treasure_map.lib.hunt.evidence import (
    EntryIndex,
    build_flow_evidence,
    build_fmtstr_evidence,
    build_size_evidence,
    load_entry_index,
)

_SRC = Path(__file__).resolve().parents[3] / "src" / "treasure_map"


def _ev(pc: str, callees: list[str], sink_arg: str | None = "cmd", entry_sites=None):
    return build_flow_evidence(
        pseudocode=pc, callees=callees, sink_arg=sink_arg, entry_sites=entry_sites
    )


# ── source_kind: classification, not a verdict ───────────────────────────────────────


def test_source_kind_charset_safe_inline() -> None:
    # Inline converter directly in the sink builder -> resolved to a charset source.
    pc = (
        "void f(struct ether_addr* x){ char cmd[128]; "
        'snprintf(cmd,128,"arp -s %s",ether_ntoa(x)); system(cmd); }'
    )
    assert _ev(pc, ["ether_ntoa", "snprintf", "system"])["source_kind"] == "charset_safe"


def test_source_kind_charset_maybe_via_intermediate() -> None:
    # 0x13578 shape: a charset converter is in the function but the value reaches the sink through
    # an intermediate variable -> NOT value-tracked here. Marked charset_maybe (a lead), not safe,
    # and the boundary is stated honestly.
    pc = (
        "void f(struct ether_addr* x){ char b[32]; char cmd[128]; char* p=ether_ntoa(x); "
        'strncpy(b,p,32); snprintf(cmd,128,"echo %s",b); system(cmd); }'
    )
    ev = _ev(pc, ["ether_ntoa", "strncpy", "snprintf", "system"])
    assert ev["source_kind"] == "charset_maybe"
    assert ev["trace_boundary"] == "charset_via_intermediate_untraced"


def test_free_source_wins_over_charset_converter() -> None:
    # ★ a genuinely dangerous candidate is NEVER washed into charset_maybe: when a free source AND
    # a charset converter both flow toward the sink, source_kind is free_string (free wins).
    pc = (
        "void f(struct ether_addr* x){ char* s=ether_ntoa(x); char* v=nvram_get(0); "
        'char cmd[96]; snprintf(cmd,96,"%s %s",s,v); system(cmd); }'
    )
    assert _ev(pc, ["ether_ntoa", "nvram_get", "snprintf", "system"])["source_kind"] == (
        "free_string"
    )


def test_source_kind_free_string() -> None:
    pc = (
        "void g(void){ char* v=nvram_get(0); char cmd[128]; "
        'snprintf(cmd,128,"echo %s",v); system(cmd); }'
    )
    assert _ev(pc, ["nvram_get", "snprintf", "system"])["source_kind"] == "free_string"


def test_source_kind_unknown_when_unresolved() -> None:
    pc = 'void f(void){ char cmd[128]; char* v=helper(); snprintf(cmd,128,"x %s",v); system(cmd); }'
    assert _ev(pc, ["helper", "snprintf", "system"])["source_kind"] == "unknown"


def test_json_string_getter_is_a_free_source() -> None:
    # json_object_get_string is now a registered free source (a common modern IoT request path).
    pc = (
        "void f(void){ char* s=json_object_get_string(o); char cmd[128]; "
        'snprintf(cmd,128,"echo %s",s); system(cmd); }'
    )
    assert _ev(pc, ["json_object_get_string", "snprintf", "system"])["source_kind"] == "free_string"


# ── conservative source_kind for wrapper candidates (free wins; symmetric to charset_maybe) ──

_WRAPPER = {"name": "do_cmd", "wrapped_sink": "system"}


def _evw(pc: str, callees: list[str], sink_arg: str):
    return build_flow_evidence(
        pseudocode=pc, callees=callees, sink_arg=sink_arg, entry_sites=None, wrapper=_WRAPPER
    )


def test_wrapper_free_source_via_intermediate_is_free_string() -> None:
    # ★ 0x6b90 shape: json -> intermediate var -> snprintf -> forwarded to wrapper. The free source
    # is reported as free_string (conservative — do not miss a danger), so it floats high.
    pc = (
        "void f(void){ char* s=json_object_get_string(o); char cmd[128]; "
        'snprintf(cmd,128,"route %s",s); do_cmd(cmd); }'
    )
    ev = _evw(pc, ["json_object_get_string", "snprintf", "do_cmd"], "cmd")
    assert ev["source_kind"] == "free_string"
    assert ev["flow_path"]["sink_via_wrapper"] is True


def test_wrapper_free_source_through_untracked_copy_is_free_string() -> None:
    # Even when the value runs through a bounded copy the graph cannot follow (strlcpy), a free
    # source called in the function makes the wrapper candidate free_string (not missed).
    pc = (
        "void f(void){ char b[64]; char* s=json_object_get_string(o); strlcpy(b,s,64); do_cmd(b); }"
    )
    assert _evw(pc, ["json_object_get_string", "strlcpy", "do_cmd"], "b")["source_kind"] == (
        "free_string"
    )


def test_wrapper_charset_via_intermediate_is_not_upgraded() -> None:
    # ★ charset (no free source) through an intermediate stays charset_maybe — the conservative
    # free rule does not wrongly upgrade a safe converter value.
    pc = (
        "void f(struct ether_addr* m){ char b[32]; char* p=ether_ntoa(m); "
        "strncpy(b,p,32); do_cmd(b); }"
    )
    assert _evw(pc, ["ether_ntoa", "strncpy", "do_cmd"], "b")["source_kind"] == "charset_maybe"


def test_wrapper_mixed_free_and_charset_is_free_string() -> None:
    # Free wins over a co-present charset converter (real danger first).
    pc = (
        "void f(struct ether_addr* m){ char* s=json_object_get_string(o); char* p=ether_ntoa(m); "
        'char c[96]; snprintf(c,96,"%s %s",p,s); do_cmd(c); }'
    )
    callees = ["json_object_get_string", "ether_ntoa", "snprintf", "do_cmd"]
    assert _evw(pc, callees, "c")["source_kind"] == "free_string"


def test_direct_candidate_charset_via_intermediate_unaffected() -> None:
    # The conservative free rule is wrapper-only: a DIRECT candidate (no wrapper) keeps the B-fix
    # behaviour — charset through an intermediate stays charset_maybe.
    pc = (
        "void f(struct ether_addr* m){ char b[32]; char* p=ether_ntoa(m); strncpy(b,p,32); "
        'char cmd[128]; snprintf(cmd,128,"echo %s",b); system(cmd); }'
    )
    assert (
        _ev(pc, ["ether_ntoa", "strncpy", "snprintf", "system"])["source_kind"] == "charset_maybe"
    )


# ── flow_path: real one-hop variables only (no format-literal noise) ─────────────────


def test_flow_path_one_hop_drops_literal_noise() -> None:
    pc = (
        "void f(struct ether_addr* x){ char b[32]; char cmd[128]; char* p=ether_ntoa(x); "
        'strncpy(b,p,32); snprintf(cmd,128,"echo %s",b); system(cmd); }'
    )
    fp = _ev(pc, ["ether_ntoa", "strncpy", "snprintf", "system"])["flow_path"]
    assert fp["sink_arg"] == "cmd"
    # 'b' is the real intermediate; the 'echo' / 's' tokens parsed from "echo %s" must be filtered.
    assert fp["one_hop"] == ["b"]


def test_flow_path_gives_all_real_one_hop_vars() -> None:
    # give-all within the reliable one-hop range: both buffers feeding the command are listed.
    pc = (
        "void f(struct ether_addr* x, struct ether_addr* y){ char ba[32]; char bb[32]; "
        "char cmd[128]; char* p; p=ether_ntoa(x); strncpy(ba,p,32); p=ether_ntoa(y); "
        'strncpy(bb,p,32); snprintf(cmd,128,"echo %s %s",ba,bb); system(cmd); }'
    )
    fp = _ev(pc, ["ether_ntoa", "strncpy", "snprintf", "system"])["flow_path"]
    assert fp["one_hop"] == ["ba", "bb"]


# ── sanitizer_seen: existence + on_path, coverage ALWAYS unjudged ────────────────────


def test_sanitizer_on_path_marked_but_coverage_unjudged() -> None:
    pc = (
        "void f(char* param_1){ char cmd[128]; if(check_injection(param_1)){ "
        'snprintf(cmd,128,"echo %s",param_1); system(cmd);} }'
    )
    san = _ev(pc, ["check_injection", "snprintf", "system"])["sanitizer_seen"]
    assert san == [{"name": "check_injection", "on_path": True, "coverage": "unjudged"}]


def test_sanitizer_off_path_still_unjudged() -> None:
    # The sanitizer guards an unrelated variable; on_path is False, coverage is STILL unjudged
    # (never "covered"/"not covered" — that judgement is the agent's).
    pc = (
        "void f(char* param_1, char* other){ char cmd[128]; validate_token(other); "
        'snprintf(cmd,128,"echo %s",param_1); system(cmd); }'
    )
    san = _ev(pc, ["validate_token", "snprintf", "system"])["sanitizer_seen"]
    assert len(san) == 1
    assert san[0]["name"] == "validate_token"
    assert san[0]["on_path"] is False
    assert san[0]["coverage"] == "unjudged"


def test_no_sanitizer_seen_is_empty() -> None:
    pc = 'void f(char* param_1){ char cmd[128]; snprintf(cmd,128,"echo %s",param_1); system(cmd); }'
    assert _ev(pc, ["snprintf", "system"])["sanitizer_seen"] == []


# ── entry_reach: found sites listed in full; none found == unknown (not unreachable) ──


def test_entry_reach_unknown_when_no_sites() -> None:
    pc = 'void f(char* param_1){ char cmd[128]; snprintf(cmd,128,"echo %s",param_1); system(cmd); }'
    er = _ev(pc, ["snprintf", "system"], entry_sites=None)["entry_reach"]
    assert er["status"] == "unknown"
    assert er["sites"] == []


def test_entry_reach_lists_all_sites() -> None:
    sites = [
        {
            "kind": "script_call",
            "script": "/etc/init.d/rcS",
            "line": 12,
            "arg_source": "var_expansion",
        },
        {"kind": "script_call", "script": "/etc/init.d/rcS", "line": 40, "arg_source": "literal"},
    ]
    pc = 'void f(char* param_1){ char cmd[128]; snprintf(cmd,128,"echo %s",param_1); system(cmd); }'
    er = _ev(pc, ["snprintf", "system"], entry_sites=sites)["entry_reach"]
    assert er["status"] == "found"
    assert er["sites"] == sites  # give-all: every site preserved


# ── trace_boundary: honest about where the structured trace stops ────────────────────


def test_trace_boundary_resolved_is_reached_sink() -> None:
    pc = (
        "void g(void){ char* v=nvram_get(0); char cmd[128]; "
        'snprintf(cmd,128,"echo %s",v); system(cmd); }'
    )
    assert _ev(pc, ["nvram_get", "snprintf", "system"])["trace_boundary"] == "reached_sink"


def test_trace_boundary_indirect_call() -> None:
    pc = 'void f(void){ char cmd[128]; char* v=(*fp)(); snprintf(cmd,128,"x %s",v); system(cmd); }'
    assert _ev(pc, ["snprintf", "system"])["trace_boundary"] == "indirect_call"


def test_trace_boundary_global_ipc() -> None:
    pc = 'void f(void){ char cmd[128]; snprintf(cmd,128,"x %s",DAT_00012345); system(cmd); }'
    assert _ev(pc, ["snprintf", "system"])["trace_boundary"] == "ipc_global"


def test_trace_boundary_copy_alias_untraced() -> None:
    # An unknown-source value moved by strlcpy (a bounded copy the dependency graph does not track)
    # -> the structured chain is incomplete, flagged honestly. (A charset converter here would make
    # it charset_maybe instead; this fixture has no converter, so the source stays unknown.)
    pc = (
        "void f(void){ char b[32]; char cmd[128]; strlcpy(b,helper(),32); "
        'snprintf(cmd,128,"echo %s",b); system(cmd); }'
    )
    assert _ev(pc, ["helper", "strlcpy", "snprintf", "system"])["trace_boundary"] == (
        "copy_alias_untraced"
    )


def test_evidence_is_deterministic() -> None:
    pc = (
        "void f(struct ether_addr* x){ char b[32]; char cmd[128]; char* p=ether_ntoa(x); "
        'strncpy(b,p,32); snprintf(cmd,128,"echo %s",b); system(cmd); }'
    )
    callees = ["ether_ntoa", "strncpy", "snprintf", "system"]
    assert _ev(pc, callees) == _ev(pc, callees)


# ── EntryIndex: matching script calls + web endpoints by binary name ─────────────────


def test_entry_index_matches_script_call_by_command_token() -> None:
    idx = EntryIndex(
        script_calls=[
            ("/etc/init.d/netd", "/sbin/netd", 5, "var_expansion"),  # absolute path form
            ("/etc/init.d/other", "busybox", 9, "literal"),  # unrelated
        ],
        web_endpoints=[],
    )
    sites = idx.sites_for("netd", "/usr/sbin/netd")
    assert len(sites) == 1
    assert sites[0]["kind"] == "script_call"
    assert sites[0]["line"] == 5
    assert sites[0]["arg_source"] == "var_expansion"


def test_entry_index_matches_web_endpoint_by_path() -> None:
    idx = EntryIndex(
        script_calls=[],
        web_endpoints=[("www/index.html", "cgi", "POST", "/cgi-bin/netd.cgi", "form")],
    )
    sites = idx.sites_for("netd", None)
    assert len(sites) == 1
    assert sites[0]["kind"] == "web_endpoint"
    assert sites[0]["method"] == "POST"


def test_entry_index_no_match_is_empty() -> None:
    idx = EntryIndex(script_calls=[("/s", "telnetd", 1, "literal")], web_endpoints=[])
    assert idx.sites_for("httpd", None) == []


def test_load_entry_index_missing_tables_is_empty() -> None:
    # An analysis.db without L0.5 tables yields an empty index (entry_reach=unknown everywhere),
    # never an error.
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    idx = load_entry_index(conn)
    assert idx.sites_for("anything", None) == []
    conn.close()


# ── copy-sink SIZE evidence: classification + reliable flow + honest boundary ────────


def test_size_evidence_const_resolves() -> None:
    ev = build_size_evidence(pseudocode="memcpy(dst, src, 0x20);", sink_name="memcpy")
    assert ev["size_kind"] == "const"
    assert ev["size_flow"]["size_var"] is None
    assert ev["clamp_seen"] == []
    assert ev["trace_boundary"] == "reached_sink"


def test_size_evidence_variable_keeps_var_and_flow() -> None:
    pc = "n = recv(fd, src, 0x400); memcpy(dst, src, n);"
    ev = build_size_evidence(pseudocode=pc, sink_name="memcpy")
    assert ev["size_kind"] == "variable"
    assert ev["size_flow"]["size_var"] == "n"
    assert ev["clamp_seen"] == []


def test_size_evidence_clamp_seen_is_unjudged() -> None:
    pc = "n = get_len(); if (0x100 < n) goto fail; memcpy(dst, src, n);"
    ev = build_size_evidence(pseudocode=pc, sink_name="memcpy")
    assert ev["size_kind"] == "clamp"
    assert ev["clamp_seen"]  # at least one shape
    assert all(c["coverage"] == "unjudged" for c in ev["clamp_seen"])  # never a dominance claim


def test_size_evidence_source_len_is_suspect() -> None:
    ev = build_size_evidence(pseudocode="strncpy(dst, src, strlen(src));", sink_name="strncpy")
    assert ev["size_kind"] == "source_len"


def test_size_evidence_untraced_when_absent() -> None:
    ev = build_size_evidence(pseudocode='snprintf(c, 64, "%s", x);', sink_name="memcpy")
    assert ev["size_kind"] == "untraced"
    assert ev["trace_boundary"] == "size_arg_untraced"


# ── format-string evidence: flow on the format arg + format-position facts ───────────


def test_fmtstr_evidence_records_position_and_source() -> None:
    # syslog format is arg1; a free source reaches it -> free_string, plus format-position facts.
    pc = "void f(void){ char* v=nvram_get(0); syslog(3, v); }"
    ev = build_fmtstr_evidence(
        pseudocode=pc, callees=["nvram_get", "syslog"], sink_name="syslog", entry_sites=None
    )
    assert ev["source_kind"] == "free_string"
    assert ev["fmt_arg_pos"] == 1
    assert ev["fmt_arg_literal"] is False  # a candidate's format must be non-literal
    assert "trace_boundary" in ev and "sanitizer_seen" in ev


def test_fmtstr_evidence_printf_position_zero() -> None:
    ev = build_fmtstr_evidence(
        pseudocode="printf(user);", callees=["printf"], sink_name="printf", entry_sites=None
    )
    assert ev["fmt_arg_pos"] == 0
    assert ev["fmt_arg_literal"] is False


# ── ★ blind-spot guard: evidence never feeds recall / score / grade ──────────────────


def test_evidence_signals_do_not_feed_score_or_grade() -> None:
    # The INTERPRETIVE evidence signals (a converter/sanitizer judgement-shaped read) are material
    # for an agent, never a score/grade input. The read-side score, the form-note downweight, and
    # the grader must not consume them nor import the evidence module.
    #
    # Two evidence facts are SURFACED by the read-side triage (and ONLY there — never the grader or
    # the form-note downweight):
    #   - entry_reach (round R-L4·mcp, factor 6b): a rootfs entry point was found to invoke the
    #     binary — a FACT the read-side ranking MAY use as a second-level ordering key.
    #   - source_kind (缺口③): the fine-grained controllability class — surfaced to the agent next
    #     to source_class but NEVER scored. review_score consumes source_class, not source_kind, and
    #     test_source_kind_does_not_affect_score pins that it changes no review order.
    # The purely interpretive fields below are surfaced by NO ranking-layer file.
    never_surfaced = ("sanitizer_seen", "trace_boundary", "size_kind")
    for rel in ("lib/query/triage.py", "lib/hunt/downweight.py", "lib/reachability/grader.py"):
        text = (_SRC / rel).read_text()
        assert "hunt.evidence" not in text and "import evidence" not in text, (
            f"{rel} unexpectedly imports the evidence module"
        )
        for field in never_surfaced:
            assert field not in text, f"{rel} unexpectedly references evidence field {field!r}"
    # The grader and the downweight must consume NONE of the evidence signals — not even the two the
    # triage surfaces (entry_reach / source_kind) nor the raw flow_evidence. Only the presentation-
    # layer triage ranking may surface a fact, and it does so without letting it feed the score.
    for rel in ("lib/hunt/downweight.py", "lib/reachability/grader.py"):
        text = (_SRC / rel).read_text()
        for field in ("entry_reach", "source_kind", "flow_evidence"):
            assert field not in text, f"{rel} unexpectedly references {field!r}"
