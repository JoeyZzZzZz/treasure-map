# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for lib/facts — the shared read-only fact layer (CLI + MCP).

Hermetic: a synthetic, vendor-neutral analysis.db. Proves each reader returns anchored facts,
the no-anchor-no-output contract (a miss is a 'not found' record, never a guess), the ambiguous
disambiguation, and that the disassembly reader degrades honestly rather than emit addresses.
"""

from __future__ import annotations

import json
from pathlib import Path

from treasure_map.lib import facts
from treasure_map.lib.storage.connection import open_db


def _mkdb(tmp_path: Path) -> Path:
    db = tmp_path / "analysis.db"
    conn = open_db(db)
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256) VALUES (1, 'webd', 'usr/sbin/webd', ?)",
        ("a" * 64,),
    )
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256) VALUES (2, 'libfoo.so', 'lib/libfoo.so', ?)",
        ("b" * 64,),
    )
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, address, size_bytes, pseudocode, callees, "
        "is_exported) VALUES (1, 1, 'handle_req', '0x1000', 64, 'void handle_req(){ helper(); "
        "do_cmd(buf); }', ?, 0)",
        (json.dumps(["helper", "do_cmd"]),),
    )
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, address, size_bytes, pseudocode, callees, "
        "is_exported) VALUES (2, 1, 'helper', '0x2000', 32, 'int helper(){ return 0; }', '[]', 0)"
    )
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, address, pseudocode, callees, is_exported) "
        "VALUES (3, 2, 'foo_entry', '0x500', 'int foo_entry(){}', '[]', 1)"
    )
    # a function whose address is stored in the real zero-padded 8-hex form (00038de8), with no
    # caller of any kind: exercises address normalization (item 1) and the indirect-call note (2).
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, address, pseudocode, callees, is_exported) "
        "VALUES (4, 1, 'netool_handler', '00038de8', 'int netool_handler(){}', '[]', 0)"
    )
    # cross-binary xref: webd.handle_req -> libfoo.foo_entry
    conn.execute(
        "INSERT INTO xrefs (caller_binary_id, caller_func_id, callee_binary_id, callee_func_id, "
        "xref_type) VALUES (1, 1, 2, 3, 'import_export')"
    )
    conn.execute(
        "INSERT INTO strings (binary_id, value, address, category) "
        "VALUES (1, '/tmp/state', '0x1010', 'path')"
    )
    conn.execute(
        "INSERT INTO strings (binary_id, value, address, category) "
        "VALUES (1, '/var/run/netool_socket', '00073d5c', 'path')"
    )
    conn.execute(
        "INSERT INTO imports (binary_id, func_name, lib_soname) "
        "VALUES (1, 'foo_entry', 'libfoo.so')"
    )
    conn.execute(
        "INSERT INTO exports (binary_id, func_name, address) VALUES (2, 'foo_entry', '0x500')"
    )
    conn.execute(
        "INSERT INTO non_binary_files (id, kind, name, path) "
        "VALUES (1, 'shell_script', 'webd.sh', 'etc/init.d/webd.sh')"
    )
    conn.execute(
        "INSERT INTO script_calls (file_id, command, raw_line, line_number, args_pattern) "
        "VALUES (1, 'webd', 'webd -c /etc/webd.conf', 12, 'literal')"
    )
    conn.execute(
        "INSERT INTO components (id, binary_id, product, version, cpe, source) "
        "VALUES (1, 1, 'genlib', '1.2.3', 'cpe:/a:gen:genlib:1.2.3', 'string_match')"
    )
    conn.execute(
        "INSERT INTO cve_matches (component_id, binary_id, cve_id, cvss_score, severity) "
        "VALUES (1, 1, 'synthetic-cve', 9.8, 'critical')"
    )
    conn.commit()
    conn.close()
    return db


def _ro(tmp_path: Path):
    return facts.open_analysis_ro(_mkdb(tmp_path))


def test_get_pseudocode_by_name_carries_anchor(tmp_path: Path) -> None:
    conn = _ro(tmp_path)
    r = facts.get_pseudocode(conn, func="handle_req")
    assert r["found"] is True
    assert r["anchor"] == {"binary": "webd", "function": "handle_req", "address": "0x1000"}
    assert "do_cmd" in r["pseudocode"]
    assert r["callees"] == ["helper", "do_cmd"]
    conn.close()


def test_get_pseudocode_by_address(tmp_path: Path) -> None:
    conn = _ro(tmp_path)
    assert facts.get_pseudocode(conn, func="0x2000")["anchor"]["function"] == "helper"
    conn.close()


def test_get_pseudocode_missing_is_not_found(tmp_path: Path) -> None:
    conn = _ro(tmp_path)
    r = facts.get_pseudocode(conn, func="nonexistent")
    assert r["found"] is False  # no fabrication
    conn.close()


def test_get_callees_marks_intra_binary_resolution(tmp_path: Path) -> None:
    conn = _ro(tmp_path)
    r = facts.get_callees(conn, func="handle_req")
    by_name = {c["name"]: c["resolved_in_binary"] for c in r["callees"]}
    assert by_name["helper"] is True  # helper exists in the same binary -> navigable
    assert by_name["do_cmd"] is False  # not a recorded function in this binary
    conn.close()


def test_get_xrefs_callers_and_callees_cross_binary(tmp_path: Path) -> None:
    conn = _ro(tmp_path)
    callees = facts.get_xrefs(conn, func="handle_req", direction="callees")
    assert callees["edges"][0]["anchor"] == {
        "binary": "libfoo.so",
        "function": "foo_entry",
        "address": "0x500",
    }
    callers = facts.get_xrefs(conn, func="foo_entry", binary="libfoo.so", direction="callers")
    assert callers["edges"][0]["anchor"]["function"] == "handle_req"
    conn.close()


def test_get_strings_and_imports_exports(tmp_path: Path) -> None:
    conn = _ro(tmp_path)
    values = {s["value"] for s in facts.get_strings(conn, binary="webd")["strings"]}
    assert "/tmp/state" in values
    ie = facts.get_imports_exports(conn, binary="webd")
    assert ie["imports"][0]["func_name"] == "foo_entry"
    conn.close()


def _trunc_db(tmp_path: Path) -> Path:
    """A DB with one TRUNCATED binary (rc: stored a prefix of 5000) and one complete (httpd)."""
    db = tmp_path / "trunc.db"
    conn = open_db(db)
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256, strings_total, strings_truncated) "
        "VALUES (1, 'rc', 'sbin/rc', ?, 5000, 1)",
        ("a" * 64,),
    )
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256, strings_total, strings_truncated) "
        "VALUES (2, 'httpd', 'usr/sbin/httpd', ?, 2, 0)",
        ("b" * 64,),
    )
    conn.execute("INSERT INTO strings (binary_id, value, address) VALUES (1, 'sw_mode', '0x10')")
    conn.execute("INSERT INTO strings (binary_id, value, address) VALUES (2, 'lan_ip', '0x20')")
    conn.execute("INSERT INTO strings (binary_id, value, address) VALUES (2, 'wan_ip', '0x24')")
    conn.commit()
    conn.close()
    return db


def test_get_strings_by_binary_surfaces_truncation(tmp_path: Path) -> None:
    # A truncated binary must NEVER read as a complete list: absence of a string is not proof.
    conn = facts.open_analysis_ro(_trunc_db(tmp_path))
    trunc = facts.get_strings(conn, binary="rc")
    assert trunc["truncated"] is True
    assert trunc["total"] == 5000
    assert trunc["stored"] == 1
    note = trunc["truncation_note"]
    assert "TRUNCATED" in note and "NOT proven absent" in note
    # a complete binary is honestly marked NOT truncated, with no scary note
    full = facts.get_strings(conn, binary="httpd")
    assert full["truncated"] is False
    assert full["total"] == 2
    assert "truncation_note" not in full
    conn.close()


def test_get_strings_by_value_search_flags_truncated_binaries(tmp_path: Path) -> None:
    # A content search that finds nothing must warn if a scanned binary was capped — the string
    # could be a dropped tail entry, so "no hit" is not "absent".
    conn = facts.open_analysis_ro(_trunc_db(tmp_path))
    res = facts.get_strings(conn, value="oauth_missing")
    assert res["strings"] == []
    assert res["search_may_be_incomplete"] is True
    assert res["truncated_binaries"] == ["rc"]
    vnote = res["truncation_note"]
    assert "rc" in vnote and "does NOT prove the string is absent" in vnote
    # narrowing the search to the COMPLETE binary carries no incompleteness warning
    scoped = facts.get_strings(conn, value="lan_ip", binary="httpd")
    assert scoped["strings"] and "search_may_be_incomplete" not in scoped
    conn.close()


def _callee_trunc_db(tmp_path: Path) -> Path:
    """A binary with a wide dispatcher whose callee list was truncated at the cap, plus a target
    function it reaches — exercises the callee/caller silent-drop guards."""
    db = tmp_path / "ct.db"
    conn = open_db(db)
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256) VALUES (1, 'rc', 'sbin/rc', ?)",
        ("a" * 64,),
    )
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, address, callees, callees_truncated, "
        "pseudocode, is_exported) VALUES (1, 1, 'dispatch', '0x1000', ?, 1, 'void d(){}', 0)",
        (json.dumps(["handler_a", "handler_b"]),),
    )
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, address, callees, callees_truncated, "
        "pseudocode, is_exported) VALUES (2, 1, 'handler_a', '0x2000', '[]', 0, 'int h(){}', 0)"
    )
    conn.commit()
    conn.close()
    return db


def test_get_callees_flags_truncated_dispatcher(tmp_path: Path) -> None:
    conn = facts.open_analysis_ro(_callee_trunc_db(tmp_path))
    res = facts.get_callees(conn, func="dispatch", binary="rc")
    assert res["callees_truncated"] is True
    assert "TRUNCATED" in res["note"] and "complete set" in res["note"]
    # a normal function is honestly NOT truncated and carries no scary note
    ok = facts.get_callees(conn, func="handler_a", binary="rc")
    assert ok["callees_truncated"] is False and "note" not in ok
    conn.close()


def test_get_pseudocode_carries_callee_truncation(tmp_path: Path) -> None:
    conn = facts.open_analysis_ro(_callee_trunc_db(tmp_path))
    res = facts.get_pseudocode(conn, func="dispatch", binary="rc")
    assert res["callees_truncated"] is True and "TRUNCATED" in res["note"]
    conn.close()


def test_get_xrefs_callers_warns_when_binary_has_truncated_callees(tmp_path: Path) -> None:
    # handler_a's callers are reverse-resolved from callee lists; the dispatcher's list was
    # truncated and could have dropped handler_a, so the caller set may be incomplete — say so.
    conn = facts.open_analysis_ro(_callee_trunc_db(tmp_path))
    res = facts.get_xrefs(conn, func="handler_a", direction="callers", binary="rc")
    assert "TRUNCATED callee list" in res["note"]
    assert "not proof of no caller" in res["note"]
    conn.close()


def test_get_script_callsites_is_entry_evidence(tmp_path: Path) -> None:
    conn = _ro(tmp_path)
    sites = facts.get_script_callsites(conn, binary="webd")["callsites"]
    assert sites[0]["script"] == "etc/init.d/webd.sh"
    assert sites[0]["line_number"] == 12
    assert sites[0]["args_pattern"] == "literal"
    conn.close()


def test_get_components_cves(tmp_path: Path) -> None:
    conn = _ro(tmp_path)
    r = facts.get_components_cves(conn, binary="webd")
    assert r["components"][0]["product"] == "genlib"
    assert r["cve_matches"][0]["cve_id"] == "synthetic-cve"
    conn.close()


def test_get_pseudocode_address_forms_all_resolve(tmp_path: Path) -> None:
    # The real schema stores 00038de8; a consumer may type the address any of these ways.
    conn = _ro(tmp_path)
    # 0x38de8 == 232936 decimal; all forms must resolve to the same stored 00038de8.
    for form in ("0x38de8", "38de8", "00038de8", "232936", "FUN_00038de8"):
        r = facts.get_pseudocode(conn, func=form)
        assert r["found"] is True, form
        assert r["anchor"]["function"] == "netool_handler", form
    conn.close()


def test_get_pseudocode_binary_path_resolves(tmp_path: Path) -> None:
    # binary accepts the short name OR the full path a candidate listing returns.
    conn = _ro(tmp_path)
    assert facts.get_pseudocode(conn, func="handle_req", binary="usr/sbin/webd")["found"] is True
    assert facts.get_pseudocode(conn, func="handle_req", binary="webd")["found"] is True
    conn.close()


def test_get_xrefs_callers_recovered_from_callee_lists(tmp_path: Path) -> None:
    # The xref table has no intra-binary edge; helper's caller is recovered by reverse-scanning
    # functions.callees (handle_req lists "helper").
    conn = _ro(tmp_path)
    r = facts.get_xrefs(conn, func="helper", direction="callers")
    callers = {(e["anchor"]["function"], e["xref_type"]) for e in r["edges"]}
    assert ("handle_req", "intra_callees") in callers
    assert "note" not in r  # callers were found, so no indirect-call note
    conn.close()


def test_get_xrefs_no_callers_is_honest_about_indirect(tmp_path: Path) -> None:
    # netool_handler has no caller of any kind -> none found, with the indirect-call note so a
    # true unresolved (dispatch-table) caller is not mistaken for "genuinely uncalled".
    conn = _ro(tmp_path)
    r = facts.get_xrefs(conn, func="netool_handler", direction="callers")
    assert r["edges"] == []
    assert "indirect" in r["note"] and "dispatch-table" in r["note"]
    conn.close()


def test_get_strings_by_value_locates_with_binary_and_note(tmp_path: Path) -> None:
    conn = _ro(tmp_path)
    r = facts.get_strings(conn, value="netool_socket")
    (hit,) = r["strings"]
    assert hit["value"] == "/var/run/netool_socket"
    assert hit["address"] == "00073d5c"
    assert hit["binary"] == "webd"
    # honest boundary: reverse "which function references this string" is not provided
    assert "not indexed" in r["note"]
    conn.close()


def _strings_db(tmp_path: Path) -> Path:
    """One binary 'rc' with a function spanning [0x1000, 0x1100) and three 'oauth' strings — two
    inside that range, one outside — to exercise func-scoped value search and byte-pagination."""
    db = tmp_path / "s.db"
    conn = open_db(db)
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256) VALUES (1, 'rc', 'sbin/rc', ?)",
        ("a" * 64,),
    )
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, address, size_bytes, pseudocode) "
        "VALUES (1, 1, 'dispatch', '0x1000', 256, 'void d(){}')"
    )
    conn.execute(
        "INSERT INTO strings (binary_id, value, address) VALUES (1, 'oauth_in_a', '0x1010')"
    )
    conn.execute(
        "INSERT INTO strings (binary_id, value, address) VALUES (1, 'oauth_in_b', '0x1080')"
    )
    conn.execute(
        "INSERT INTO strings (binary_id, value, address) VALUES (1, 'oauth_out', '0x2000')"
    )
    conn.commit()
    conn.close()
    return db


def test_get_strings_value_mode_honours_func(tmp_path: Path) -> None:
    # ★ M6: value mode now scopes to a function's address range (func was previously DROPPED, so
    # "a substring inside this function" could not be asked — forcing a full-binary page).
    conn = facts.open_analysis_ro(_strings_db(tmp_path))
    scoped = facts.get_strings(conn, binary="rc", func="dispatch", value="oauth")
    assert {s["value"] for s in scoped["strings"]} == {
        "oauth_in_a",
        "oauth_in_b",
    }  # out-of-range cut
    # without func the same search returns all three — func is what narrows it
    allv = facts.get_strings(conn, binary="rc", value="oauth")
    assert {s["value"] for s in allv["strings"]} == {"oauth_in_a", "oauth_in_b", "oauth_out"}
    conn.close()


def test_get_strings_value_mode_unresolved_func_is_surfaced(tmp_path: Path) -> None:
    # a func that does not resolve is REPORTED (not-found), never silently ignored (the old bug).
    conn = facts.open_analysis_ro(_strings_db(tmp_path))
    miss = facts.get_strings(conn, binary="rc", func="no_such_fn", value="oauth")
    assert miss["found"] is False
    conn.close()


def test_get_strings_byte_pagination_reaches_the_tail_losslessly(tmp_path: Path) -> None:
    # ★ M6: a large result is paged LOSSLESSLY by byte size — the tail is REACHABLE via
    # paging.next_offset, NOTHING summarized. A tiny max_chars forces one row per page.
    conn = facts.open_analysis_ro(_strings_db(tmp_path))
    p1 = facts.get_strings(conn, binary="rc", max_chars=1)
    assert p1["paging"]["truncated"] is True
    assert p1["paging"]["returned"] == 1  # at least one row despite the 1-char budget
    assert p1["paging"]["next_offset"] == 1
    assert p1["paging"]["total_matched"] == 3
    assert "no summary" in p1["paging"]["how_to_get_rest"]
    # walk pages to the tail, collecting every value — lossless, nothing dropped or summarized
    seen = list(p1["strings"])
    off = p1["paging"]["next_offset"]
    while off is not None:
        pg = facts.get_strings(conn, binary="rc", max_chars=1, offset=off)
        seen += pg["strings"]
        off = pg["paging"]["next_offset"]
    assert {s["value"] for s in seen} == {"oauth_in_a", "oauth_in_b", "oauth_out"}
    conn.close()


def test_get_strings_default_returns_full_page_no_summary(tmp_path: Path) -> None:
    # the default byte budget is generous, so a small binary returns in ONE page with no summary and
    # a terminal next_offset=None — pagination is a tail-safety net, not always-on chunking.
    conn = facts.open_analysis_ro(_strings_db(tmp_path))
    r = facts.get_strings(conn, binary="rc")
    assert r["paging"]["truncated"] is False and r["paging"]["next_offset"] is None
    assert len(r["strings"]) == 3  # every row, no summarization
    conn.close()


def test_list_incomplete_binaries_flags_failed_not_codefree(tmp_path: Path) -> None:
    # ★ Red-line: a code binary Ghidra failed on (0 functions, status != ok_empty) is surfaced as
    # incomplete; a legitimately code-free ok_empty object and a binary with functions are not.
    from treasure_map.lib.storage.connection import open_db

    db = tmp_path / "incomplete.db"
    conn = open_db(db)
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256, ghidra_status, last_seen_at) "
        "VALUES (1, 'rc', 'sbin/rc', 'x', 'failed', '2026-01-01')"
    )
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256, ghidra_status, last_seen_at) "
        "VALUES (2, 'data.so', 'lib/data.so', 'y', 'ok_empty', '2026-01-01')"
    )
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256, ghidra_status, last_seen_at) "
        "VALUES (3, 'httpd', 'usr/sbin/httpd', 'z', 'ok', '2026-01-01')"
    )
    conn.execute("INSERT INTO functions (binary_id, name) VALUES (3, 'main')")
    conn.commit()
    conn.close()
    ro = facts.open_analysis_ro(db)
    assert facts.list_incomplete_binaries(ro) == ["rc"]
    ro.close()


def test_list_partially_incomplete_binaries_counts_failed_decompiles(tmp_path: Path) -> None:
    # ★ Red-line: a binary analyzed 'ok' with functions is still INCOMPLETE if some >=10-byte
    # functions never decompiled (empty pseudocode). A <10-byte thunk with no pseudocode is
    # legitimate and must NOT be counted; a fully-decompiled binary must NOT appear at all.
    from treasure_map.lib.storage.connection import open_db

    db = tmp_path / "partial.db"
    conn = open_db(db)
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256, ghidra_status, last_seen_at) "
        "VALUES (1, 'rc', 'sbin/rc', 'x', 'ok', '2026-01-01')"
    )
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256, ghidra_status, last_seen_at) "
        "VALUES (2, 'httpd', 'usr/sbin/httpd', 'z', 'ok', '2026-01-01')"
    )
    conn.executemany(
        "INSERT INTO functions (binary_id, name, size_bytes, pseudocode) VALUES (?, ?, ?, ?)",
        [
            (1, "handle_req", 200, "int handle_req(void){return 0;}"),  # decompiled
            (1, "big_fail_a", 120, ""),  # >=10, empty  -> failed decompile
            (1, "big_fail_b", 88, None),  # >=10, NULL  -> failed decompile
            (1, "thunk", 4, ""),  # <10, empty  -> legitimate micro-func, not counted
            (2, "main", 300, "int main(void){return 0;}"),  # httpd fully decompiled
        ],
    )
    conn.commit()
    conn.close()
    ro = facts.open_analysis_ro(db)
    rows = facts.list_partially_incomplete_binaries(ro)
    ro.close()
    # only rc is partially incomplete (2 of its 4 functions failed); httpd is absent (fully done)
    assert rows == [{"binary": "rc", "functions_total": 4, "functions_empty": 2}]


def test_get_disassembly_degrades_honestly(tmp_path: Path) -> None:
    conn = _ro(tmp_path)
    r = facts.get_disassembly(conn, func="handle_req")
    assert r["found"] is True
    assert r["available"] is False  # never emit possibly-misaligned addresses
    assert r["anchor"]["function"] == "handle_req"  # but the anchor is still given
    conn.close()


# ── get_functions_referencing_string: pseudocode-text reverse lookup (缺口①) ────────────


def _mk_refdb(tmp_path: Path) -> Path:
    """Two binaries: 'caller' invokes the target string, 'other' does not, and 'commented' mentions
    it ONLY inside a comment — the fixture for the text-match honesty test."""
    db = tmp_path / "refs.db"
    conn = open_db(db)
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256) VALUES (1, 'webd', 'sbin/webd', ?)",
        ("a" * 64,),
    )
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256) VALUES (2, 'apid', 'sbin/apid', ?)",
        ("b" * 64,),
    )
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, address, pseudocode, callees) "
        "VALUES (1, 1, 'caller', '0x100', 'void caller(){ set_iperf3_svr(v); }', '[]')"
    )
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, address, pseudocode, callees) "
        "VALUES (2, 1, 'other', '0x200', 'void other(){ do_thing(); }', '[]')"
    )
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, address, pseudocode, callees) VALUES "
        "(3, 2, 'commented', '0x300', 'void commented(){ /* calls set_iperf3_svr later */ x(); }', "
        "'[]')"
    )
    conn.commit()
    conn.close()
    return db


def test_referencing_string_matches_only_referencing_functions(tmp_path: Path) -> None:
    conn = facts.open_analysis_ro(_mk_refdb(tmp_path))
    try:
        r = facts.get_functions_referencing_string(conn, text="set_iperf3_svr")
    finally:
        conn.close()
    names = {f["function"] for f in r["functions"]}
    assert names == {"caller", "commented"}  # 'other' never mentions the text
    assert r["found"] is True and r["truncated"] is False
    # each hit carries its anchor (binary + function + address) + the matching line
    (caller_hit,) = [f for f in r["functions"] if f["function"] == "caller"]
    assert caller_hit["binary"] == "webd" and caller_hit["address"] == "0x100"


def test_referencing_string_binary_filter(tmp_path: Path) -> None:
    conn = facts.open_analysis_ro(_mk_refdb(tmp_path))
    try:
        webd = facts.get_functions_referencing_string(conn, text="set_iperf3_svr", binary="webd")
        apid = facts.get_functions_referencing_string(conn, text="set_iperf3_svr", binary="apid")
        by_path = facts.get_functions_referencing_string(
            conn, text="set_iperf3_svr", binary="sbin/apid"
        )
    finally:
        conn.close()
    assert {f["function"] for f in webd["functions"]} == {"caller"}
    assert {f["function"] for f in apid["functions"]} == {"commented"}
    assert {f["function"] for f in by_path["functions"]} == {"commented"}  # full path resolves too


def test_referencing_string_hit_in_comment_is_a_text_match(tmp_path: Path) -> None:
    # Honest boundary: the text sits ONLY in a comment of 'commented', yet it matches — proving this
    # is a pseudocode TEXT substring match, not a resolved symbol reference. The result says so.
    conn = facts.open_analysis_ro(_mk_refdb(tmp_path))
    try:
        r = facts.get_functions_referencing_string(conn, text="set_iperf3_svr", binary="apid")
    finally:
        conn.close()
    (hit,) = r["functions"]
    assert hit["function"] == "commented"
    assert "calls set_iperf3_svr later" in hit["match_line"]  # the matched line snippet
    assert r["match_kind"] == "pseudocode_text_substring"
    assert "text" in r["note"].lower() and "not a resolved symbol" in r["note"].lower()


def test_referencing_string_underscore_is_literal_not_wildcard(tmp_path: Path) -> None:
    # LIKE treats '_' as a single-char wildcard; the reverse lookup escapes it so a name full of
    # underscores does not over-match. 'set_iperf3_svr' must NOT match 'setXiperf3Ysvr'.
    db = tmp_path / "esc.db"
    conn = open_db(db)
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256) VALUES (1, 'webd', 'sbin/webd', ?)",
        ("a" * 64,),
    )
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, address, pseudocode, callees) "
        "VALUES (1, 1, 'exact', '0x1', 'void exact(){ set_iperf3_svr(v); }', '[]')"
    )
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, address, pseudocode, callees) "
        "VALUES (2, 1, 'wild', '0x2', 'void wild(){ setXiperf3Ysvr(v); }', '[]')"
    )
    conn.commit()
    conn.close()
    ro = facts.open_analysis_ro(db)
    try:
        r = facts.get_functions_referencing_string(ro, text="set_iperf3_svr")
    finally:
        ro.close()
    assert {f["function"] for f in r["functions"]} == {"exact"}  # underscore matched literally


def test_referencing_string_limit_and_truncation(tmp_path: Path) -> None:
    db = tmp_path / "many.db"
    conn = open_db(db)
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256) VALUES (1, 'webd', 'sbin/webd', ?)",
        ("a" * 64,),
    )
    for i in range(60):  # 60 functions all mentioning the marker -> default cap of 50 truncates
        conn.execute(
            "INSERT INTO functions (id, binary_id, name, address, pseudocode, callees) "
            "VALUES (?, 1, ?, ?, ?, '[]')",
            (i + 1, f"fn_{i:02d}", f"0x{i:04x}", f"void fn_{i:02d}(){{ common_marker(); }}"),
        )
    conn.commit()
    conn.close()
    ro = facts.open_analysis_ro(db)
    try:
        capped = facts.get_functions_referencing_string(ro, text="common_marker")
        small = facts.get_functions_referencing_string(ro, text="common_marker", limit=5)
    finally:
        ro.close()
    assert capped["returned"] == 50 and capped["limit"] == 50 and capped["truncated"] is True
    assert small["returned"] == 5 and small["truncated"] is True


def test_referencing_string_empty_text_is_rejected(tmp_path: Path) -> None:
    # An empty/whitespace search is refused rather than matched against every function ('%%').
    conn = facts.open_analysis_ro(_mk_refdb(tmp_path))
    try:
        r = facts.get_functions_referencing_string(conn, text="   ")
    finally:
        conn.close()
    assert r["found"] is False
