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
    assert facts.get_strings(conn, binary="webd")["strings"][0]["value"] == "/tmp/state"
    ie = facts.get_imports_exports(conn, binary="webd")
    assert ie["imports"][0]["func_name"] == "foo_entry"
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


def test_get_disassembly_degrades_honestly(tmp_path: Path) -> None:
    conn = _ro(tmp_path)
    r = facts.get_disassembly(conn, func="handle_req")
    assert r["found"] is True
    assert r["available"] is False  # never emit possibly-misaligned addresses
    assert r["anchor"]["function"] == "handle_req"  # but the anchor is still given
    conn.close()
