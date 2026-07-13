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
from treasure_map.lib.pattern.classes import (
    CMD,
    COPY,
    FMT_STRING,
    FORMAT,
    PATH_SINK,
    SOURCE,
    all_format_calls_literal,
    all_path_calls_literal,
    format_string_ident,
    path_arg_ident,
)
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


def test_pattern_a_non_shellish_literal_falls_back_to_bare_cmd(tmp_path: Path) -> None:
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
    # The %s literal is not shell-ish, so the rich cmd_injection shape does NOT match — but the
    # command sink is NOT silently dropped (recall before precision): it falls back to a
    # bare_cmd candidate, to be ranked low downstream rather than omitted.
    assert res.stats.pattern_a == 0
    assert res.stats.bare_cmd == 1
    (m,) = res.matches
    assert m.pattern_kind == "bare_cmd_shape"
    assert m.sink_class == "cmd"


def test_bare_cmd_with_no_source_is_listed(tmp_path: Path) -> None:
    # A command sink with no recognized source and no constructed shell command: still a candidate
    # (the controlled value may arrive via a caller). Never silently omitted.
    db = _make_db(
        tmp_path,
        [
            {
                "name": "svcd",
                "funcs": [
                    {
                        "name": "do_reboot",
                        "pseudocode": "system(param_1);",
                        "callees": ["system"],
                    }
                ],
            }
        ],
    )
    res = scan(db)
    (m,) = res.matches
    assert m.pattern_kind == "bare_cmd_shape"
    assert m.source_class == "unknown"  # no in-function source recognized
    assert m.call_sequence_shape == "cmd"


def test_bare_copy_with_no_source_is_listed(tmp_path: Path) -> None:
    db = _make_db(
        tmp_path,
        [
            {
                "name": "svcd",
                "funcs": [{"name": "cpy", "pseudocode": "strcpy(d,s);", "callees": ["strcpy"]}],
            }
        ],
    )
    res = scan(db)
    (m,) = res.matches
    assert m.pattern_kind == "overflow_shape"
    assert m.source_class == "unknown"
    assert m.call_sequence_shape == "copy"


def test_widened_source_recognizes_getopt(tmp_path: Path) -> None:
    # getopt-family option parsing is a recognized (weak) source: a command sink in such a
    # function is source-classified external_input, not bare.
    db = _make_db(
        tmp_path,
        [
            {
                "name": "toold",
                "funcs": [
                    {
                        "name": "main_opt",
                        "pseudocode": (
                            'getopt_long(argc,argv,"m:",0,0); '
                            'snprintf(c,64,"/bin/x %s",optarg); system(c);'
                        ),
                        "callees": ["getopt_long", "snprintf", "system"],
                    }
                ],
            }
        ],
    )
    res = scan(db)
    (m,) = res.matches
    assert m.pattern_kind == "cmd_injection_shape"
    assert m.source_class == "external_input"  # getopt_long recognized as a source


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


# ── Pattern fmtstr — format-string-injection shape (recall gated by literal exemption) ──


def _fmt_match(tmp_path: Path, name: str, pseudocode: str, callees: list[str]):
    db = _make_db(
        tmp_path,
        [{"name": "logd", "funcs": [{"name": name, "pseudocode": pseudocode, "callees": callees}]}],
    )
    return [m for m in scan(db).matches if m.sink_class == "fmt_string"]


def test_fmtstr_non_literal_format_is_recalled(tmp_path: Path) -> None:
    # printf(user) — the format argument is a variable -> a format-string-injection candidate.
    (m,) = _fmt_match(tmp_path, "log_it", "printf(user);", ["printf"])
    assert m.pattern_kind == "fmt_string_shape"
    assert m.sink_class == "fmt_string"
    assert m.evidence == "printf"


def test_fmtstr_literal_format_is_exempt(tmp_path: Path) -> None:
    # printf("%s", user) — fixed format string -> NOT a candidate (the FP gate: the common case).
    assert _fmt_match(tmp_path, "log_it", 'printf("%s", user);', ["printf"]) == []


def test_fmtstr_syslog_cve_shape_is_recalled(tmp_path: Path) -> None:
    # The public format-string-injection shape: syslog(level, buf) with a non-literal format ->
    # recalled. syslog's format is arg1 (arg0 is the level) — the danger axis is read correctly.
    (m,) = _fmt_match(tmp_path, "do_log", "syslog(3, buf);", ["syslog"])
    assert m.evidence == "syslog"


def test_fmtstr_syslog_literal_is_exempt(tmp_path: Path) -> None:
    assert _fmt_match(tmp_path, "do_log", 'syslog(3, "msg %s", x);', ["syslog"]) == []


def test_fmtstr_position_correct_fprintf_literal_not_recalled(tmp_path: Path) -> None:
    # ★ format position: fprintf's format is arg1. fprintf(fp, "lit") has a non-literal arg0 (fp)
    # but a LITERAL format -> must NOT be recalled (arg0 is not the danger axis).
    assert _fmt_match(tmp_path, "wr", 'fprintf(fp, "lit");', ["fprintf"]) == []


def test_fmtstr_position_correct_fprintf_variable_recalled(tmp_path: Path) -> None:
    (m,) = _fmt_match(tmp_path, "wr", "fprintf(fp, buf);", ["fprintf"])
    assert m.evidence == "fprintf"


def test_fmtstr_bare_no_source_still_listed(tmp_path: Path) -> None:
    # Source presence is a scoring signal, not a gate: non-literal format, no source, still listed.
    (m,) = _fmt_match(tmp_path, "wr", "vprintf(fmt, ap);", ["vprintf"])
    assert m.source_class == "unknown"
    assert m.call_sequence_shape == "fmt_string"


def test_fmtstr_mixed_calls_recalled_conservatively(tmp_path: Path) -> None:
    # One literal call + one variable call to the same sink -> recalled (never miss the risky one).
    (m,) = _fmt_match(tmp_path, "wr", 'syslog(3, "ok"); syslog(3, buf);', ["syslog"])
    assert m.evidence == "syslog"


def test_fmtstr_helpers_literal_and_ident() -> None:
    assert all_format_calls_literal('printf("%s", x);', "printf") is True
    assert all_format_calls_literal("printf(user);", "printf") is False
    assert all_format_calls_literal('fprintf(fp, "lit");', "fprintf") is True
    assert all_format_calls_literal("fprintf(fp, buf);", "fprintf") is False
    assert format_string_ident("syslog(3, buf);", "syslog") == "buf"
    assert format_string_ident('syslog(3, "lit");', "syslog") is None
    # mixed: returns the first NON-literal format identifier
    assert format_string_ident('printf("ok"); printf(other);', "printf") == "other"


def test_fmtstr_sink_set_disjoint_from_other_classes() -> None:
    assert not (FMT_STRING & (CMD | COPY | FORMAT | SOURCE))


# ── Path/file sinks — the recall extension ──────────────────────────────────────────


def _path_match(tmp_path: Path, name: str, pseudocode: str, callees: list[str]):
    db = _make_db(
        tmp_path,
        [{"name": "svcd", "funcs": [{"name": name, "pseudocode": pseudocode, "callees": callees}]}],
    )
    return [m for m in scan(db).matches if m.sink_class == "path_sink"]


def test_path_sink_recalled(tmp_path: Path) -> None:
    # fopen with a variable path -> a path-sink candidate (the previously zero-coverage class).
    (m,) = _path_match(tmp_path, "open_it", 'fopen(path, "r");', ["fopen"])
    assert m.pattern_kind == "path_sink_shape"
    assert m.sink_class == "path_sink"
    assert m.source_class == "unknown"  # no in-function source -> still listed (not a gate)


def test_path_sink_with_source_labels_external_input(tmp_path: Path) -> None:
    (m,) = _path_match(
        tmp_path, "open_it", 'recv(fd, buf, 64); fopen(buf, "r");', ["recv", "fopen"]
    )
    assert m.source_class == "external_input"
    assert m.call_sequence_shape == "source->path_sink"


def test_path_sink_anchor_is_deterministic(tmp_path: Path) -> None:
    # Several path sinks in one function -> anchor to the alphabetically-first (stable evidence).
    (m,) = _path_match(tmp_path, "fs_op", 'unlink(a); fopen(b, "w");', ["unlink", "fopen"])
    assert m.evidence == "fopen"  # sorted(cc.path_sink)[0]


def test_path_helpers_literal_ident_and_position() -> None:
    # all_path_calls_literal: constant path only when EVERY call's path arg is a literal.
    assert all_path_calls_literal('fopen("/tmp/x", "w");', "fopen") is True
    assert all_path_calls_literal('fopen(p, "w");', "fopen") is False
    # ★ per-sink position: openat's path is arg1 (arg0 is the dirfd). A literal at arg1 is constant;
    # blindly reading arg0 (the dirfd) would misjudge it.
    assert all_path_calls_literal('openat(AT_FDCWD, "/etc/x", 0);', "openat") is True
    assert all_path_calls_literal("openat(AT_FDCWD, p, 0);", "openat") is False
    # path_arg_ident: leading identifier of the first NON-literal path arg (per-sink position).
    assert path_arg_ident('fopen(p, "r");', "fopen") == "p"
    assert path_arg_ident('fopen("/tmp/x", "r");', "fopen") is None
    assert path_arg_ident("openat(AT_FDCWD, buf, 0);", "openat") == "buf"


def test_path_sink_set_disjoint_from_other_classes() -> None:
    assert not (PATH_SINK & (CMD | COPY | FORMAT | FMT_STRING | SOURCE))


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
    for name in SOURCE | FORMAT | CMD | COPY | FMT_STRING | PATH_SINK:
        assert ident.match(name), f"non-identifier call-class entry: {name!r}"
    oss_ident = re.compile(r"^[a-z0-9_]+$")
    for name in GENERIC_OSS_NAMES:
        assert oss_ident.match(name), f"unexpected OSS-list entry: {name!r}"
