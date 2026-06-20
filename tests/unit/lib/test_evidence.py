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

from treasure_map.lib.hunt.evidence import EntryIndex, build_flow_evidence, load_entry_index

_SRC = Path(__file__).resolve().parents[3] / "src" / "treasure_map"


def _ev(pc: str, callees: list[str], sink_arg: str | None = "cmd", entry_sites=None):
    return build_flow_evidence(
        pseudocode=pc, callees=callees, sink_arg=sink_arg, entry_sites=entry_sites
    )


# ── source_kind: classification, not a verdict ───────────────────────────────────────


def test_source_kind_charset_safe_one_hop() -> None:
    pc = (
        "void f(struct ether_addr* x){ char b[32]; char cmd[128]; char* p=ether_ntoa(x); "
        'strncpy(b,p,32); snprintf(cmd,128,"echo %s",b); system(cmd); }'
    )
    assert _ev(pc, ["ether_ntoa", "strncpy", "snprintf", "system"])["source_kind"] == "charset_safe"


def test_source_kind_free_string() -> None:
    pc = (
        "void g(void){ char* v=nvram_get(0); char cmd[128]; "
        'snprintf(cmd,128,"echo %s",v); system(cmd); }'
    )
    assert _ev(pc, ["nvram_get", "snprintf", "system"])["source_kind"] == "free_string"


def test_source_kind_unknown_when_unresolved() -> None:
    pc = 'void f(void){ char cmd[128]; char* v=helper(); snprintf(cmd,128,"x %s",v); system(cmd); }'
    assert _ev(pc, ["helper", "snprintf", "system"])["source_kind"] == "unknown"


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
    # strlcpy is a bounded copy the dependency graph does not track -> the structured chain may be
    # incomplete, so the boundary is flagged honestly even though the source resolved.
    pc = (
        "void f(struct ether_addr* x){ char b[32]; char cmd[128]; strlcpy(b,ether_ntoa(x),32); "
        'snprintf(cmd,128,"echo %s",b); system(cmd); }'
    )
    assert _ev(pc, ["ether_ntoa", "strlcpy", "snprintf", "system"])["trace_boundary"] == (
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


# ── ★ blind-spot guard: evidence never feeds recall / score / grade ──────────────────


def test_evidence_signals_do_not_feed_score_or_grade() -> None:
    # The flow evidence (and its sanitizer signal) is material for an agent, never a score/grade
    # input. The read-side score, the form-note downweight, and the grader must not consume the
    # evidence fields nor import the evidence module.
    fields = ("flow_evidence", "sanitizer_seen", "entry_reach", "trace_boundary", "source_kind")
    for rel in ("lib/query/triage.py", "lib/hunt/downweight.py", "lib/reachability/grader.py"):
        text = (_SRC / rel).read_text()
        assert "hunt.evidence" not in text and "import evidence" not in text, (
            f"{rel} unexpectedly imports the evidence module"
        )
        for field in fields:
            assert field not in text, f"{rel} unexpectedly references evidence field {field!r}"
