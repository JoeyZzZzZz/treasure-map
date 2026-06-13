# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the call-sequence pattern primitive (R-pattern).

Hermetic: synthetic, vendor-neutral analysis databases, no network, no LLM. Proves the
two shape detectors (positive + negative), the OSS-exclusion lesson, the coarse
fingerprint, read-only safety, and a boundary check that the package stays vendor- and
judgment-vocabulary-free.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path

from treasure_map.lib.pattern import scan
from treasure_map.lib.pattern.classes import CMD, COPY, FORMAT, SOURCE
from treasure_map.lib.pattern.fingerprint import FINGERPRINT_ALGO_VERSION
from treasure_map.lib.pattern.oss import GENERIC_OSS_NAMES, is_oss_binary
from treasure_map.lib.storage.connection import open_db

_PATTERN_PKG = Path(__file__).resolve().parents[3] / "src" / "treasure_map" / "lib" / "pattern"


def _make_db(tmp_path: Path, binaries: list[dict[str, object]]) -> Path:
    """Build an analysis.db. Each binary: {name, oss?, funcs:[{name,pseudocode,callees}]}."""
    db_path = tmp_path / "analysis.db"
    conn = open_db(db_path)
    fid = 0
    for bid, spec in enumerate(binaries, start=1):
        conn.execute(
            "INSERT INTO binaries (id, name, sha256) VALUES (?, ?, ?)",
            (bid, spec["name"], str(bid).zfill(64)),
        )
        if spec.get("oss"):
            conn.execute(
                "INSERT INTO components (binary_id, product, version) VALUES (?, ?, ?)",
                (bid, "thirdparty", "1.0"),
            )
        for func in spec.get("funcs", []):  # type: ignore[union-attr]
            fid += 1
            conn.execute(
                "INSERT INTO functions (id, binary_id, name, pseudocode, callees) "
                "VALUES (?, ?, ?, ?, ?)",
                (fid, bid, func["name"], func["pseudocode"], json.dumps(func["callees"])),
            )
    conn.commit()
    conn.close()
    return db_path


# ── Pattern A — command-injection shape ─────────────────────────────────────────────


def test_pattern_a_positive(tmp_path: Path) -> None:
    db = _make_db(
        tmp_path,
        [
            {
                "name": "webd",
                "funcs": [
                    {
                        "name": "handle_req",
                        "pseudocode": 'snprintf(cmd,128,"/usr/bin/tool %s",arg); system(cmd);',
                        "callees": ["recv", "snprintf", "system"],
                    }
                ],
            }
        ],
    )
    res = scan(db)

    assert res.stats.pattern_a == 1
    assert res.stats.pattern_b == 0
    (m,) = res.matches
    assert m.pattern_kind == "cmd_injection_shape"
    assert m.source_class == "external_input"
    assert m.sink_class == "cmd"
    assert m.call_sequence_shape == "source->format->cmd"
    assert m.fingerprint_algo_version == FINGERPRINT_ALGO_VERSION
    assert m.structural_fingerprint  # non-empty stable hash
    assert m.evidence == "/usr/bin/tool %s"  # the matched shell-ish format literal
    assert m.func_ref.binary_name == "webd"
    assert m.func_ref.func_name == "handle_req"


def test_pattern_a_negative_non_shellish_literal(tmp_path: Path) -> None:
    db = _make_db(
        tmp_path,
        [
            {
                "name": "webd",
                "funcs": [
                    {
                        "name": "build_kv",
                        "pseudocode": 'snprintf(buf,64,"name=%s",arg); system(buf);',
                        "callees": ["recv", "snprintf", "system"],
                    }
                ],
            }
        ],
    )
    res = scan(db)
    # Same call classes, but the %s literal is not shell-ish → the predicate gates it.
    assert res.matches == ()
    assert res.stats.pattern_a == 0


# ── Pattern B — overflow shape ──────────────────────────────────────────────────────


def test_pattern_b_positive(tmp_path: Path) -> None:
    db = _make_db(
        tmp_path,
        [
            {
                "name": "appsvcd",
                "funcs": [
                    {
                        "name": "load_name",
                        "pseudocode": "char dst[32]; read(fd,src,n); strcpy(dst,src);",
                        "callees": ["read", "strcpy"],
                    }
                ],
            }
        ],
    )
    res = scan(db)

    assert res.stats.pattern_b == 1
    (m,) = res.matches
    assert m.pattern_kind == "overflow_shape"
    assert m.sink_class == "copy"
    assert m.call_sequence_shape == "source->copy"
    assert m.evidence == "strcpy"


# ── OSS exclusion (the iteration-1 lesson) ──────────────────────────────────────────


def test_oss_binary_in_components_is_excluded(tmp_path: Path) -> None:
    db = _make_db(
        tmp_path,
        [
            {
                "name": "busybox",  # public OSS, also recorded in components
                "oss": True,
                "funcs": [
                    {
                        "name": "applet",
                        "pseudocode": 'snprintf(c,128,"/bin/sh -c %s",a); system(c);',
                        "callees": ["recv", "snprintf", "system"],  # perfect Pattern-A shape
                    }
                ],
            }
        ],
    )
    res = scan(db)

    assert res.matches == ()  # the perfect shape is suppressed because it is OSS
    assert res.stats.oss_binaries_excluded == 1
    assert res.stats.custom_functions == 0


def test_custom_kept_alongside_oss(tmp_path: Path) -> None:
    db = _make_db(
        tmp_path,
        [
            {
                "name": "busybox",
                "oss": True,
                "funcs": [
                    {
                        "name": "applet",
                        "pseudocode": 'system("/bin/sh -c %s");',
                        "callees": ["recv", "snprintf", "system"],
                    }
                ],
            },
            {
                "name": "webd",  # custom → kept
                "funcs": [
                    {
                        "name": "handle",
                        "pseudocode": 'snprintf(c,64,"/usr/sbin/svc %s",a); system(c);',
                        "callees": ["recv", "snprintf", "system"],
                    }
                ],
            },
        ],
    )
    res = scan(db)

    assert res.stats.oss_binaries_excluded == 1
    assert res.stats.custom_functions == 1
    assert len(res.matches) == 1
    assert res.matches[0].func_ref.binary_name == "webd"


def test_empty_callees_are_skipped(tmp_path: Path) -> None:
    db = _make_db(
        tmp_path,
        [
            {
                "name": "webd",
                "funcs": [
                    {"name": "noop", "pseudocode": "return;", "callees": []},
                    {"name": "plain", "pseudocode": "foo(); bar();", "callees": ["foo", "bar"]},
                ],
            }
        ],
    )
    res = scan(db)
    # '[]' callees are filtered by the query; the plain function scans but matches nothing.
    assert res.matches == ()
    assert res.stats.functions_scanned == 1  # only the non-empty-callee row survives the filter


# ── read-only safety ────────────────────────────────────────────────────────────────


def test_scan_does_not_modify_input(tmp_path: Path) -> None:
    db = _make_db(
        tmp_path,
        [
            {
                "name": "webd",
                "funcs": [
                    {
                        "name": "h",
                        "pseudocode": 'snprintf(c,64,"/usr/bin/x %s",a); system(c);',
                        "callees": ["recv", "snprintf", "system"],
                    }
                ],
            }
        ],
    )
    before = db.read_bytes()
    scan(db)
    assert db.read_bytes() == before


def test_scan_rejects_missing_db(tmp_path: Path) -> None:
    import pytest

    with pytest.raises(sqlite3.OperationalError):
        scan(tmp_path / "nope.db")  # read-only mode does not create the file


# ── OSS heuristics (fallback when not in components) ────────────────────────────────


def test_oss_name_and_lib_heuristics() -> None:
    empty: set[str] = set()
    assert is_oss_binary("dropbear", known_components=empty)  # generic OSS name
    assert is_oss_binary("openssl-1.1.1", known_components=empty)  # version-stripped name
    assert is_oss_binary("libcrypto.so.1.1", known_components=empty)  # lib* + soname
    assert not is_oss_binary("webd", known_components=empty)  # custom → kept
    assert not is_oss_binary("appsvcd", known_components=empty)
    # Data-driven membership wins regardless of name.
    assert is_oss_binary("appsvcd", known_components={"appsvcd"})


# ── fingerprint stability ───────────────────────────────────────────────────────────


def test_fingerprint_stable_and_shape_distinct(tmp_path: Path) -> None:
    db = _make_db(
        tmp_path,
        [
            {
                "name": "webd",
                "funcs": [
                    {
                        "name": "a",
                        "pseudocode": 'snprintf(c,64,"/usr/bin/x %s",a); system(c);',
                        "callees": ["recv", "snprintf", "system"],
                    },
                    {
                        "name": "b",
                        "pseudocode": "strcpy(d,s);",
                        "callees": ["recv", "strcpy"],
                    },
                ],
            }
        ],
    )
    res = scan(db)
    by_kind = {m.pattern_kind: m.structural_fingerprint for m in res.matches}
    # Same shape is deterministic; different shapes differ.
    assert by_kind["cmd_injection_shape"] != by_kind["overflow_shape"]
    again = scan(db)
    by_kind2 = {m.pattern_kind: m.structural_fingerprint for m in again.matches}
    assert by_kind == by_kind2


# ── BOUNDARY: no vendor names, no vuln/judgment vocab, no section refs ───────────────


def test_pattern_package_is_boundary_clean() -> None:
    label_vocab = re.compile(
        r"\b(vuln\w*|exploit\w*|payload|finding|incomplete_patch|fix_quality|priority)\b",
        re.IGNORECASE,
    )
    section_ref = re.compile(r"§|PRD\s")
    for path in _PATTERN_PKG.glob("*.py"):
        text = path.read_text()
        assert not label_vocab.search(text), f"vuln/judgment label in {path.name}"
        assert not section_ref.search(text), f"section/private-doc ref in {path.name}"


def test_call_class_and_oss_sets_are_generic_identifiers() -> None:
    ident = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
    for name in SOURCE | FORMAT | CMD | COPY:
        assert ident.match(name), f"non-identifier call-class entry: {name!r}"
    oss_ident = re.compile(r"^[a-z0-9_]+$")
    for name in GENERIC_OSS_NAMES:
        assert oss_ident.match(name), f"unexpected OSS-list entry: {name!r}"
