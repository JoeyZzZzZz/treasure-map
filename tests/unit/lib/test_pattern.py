# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the call-sequence pattern primitive (R-pattern).

Hermetic: synthetic, vendor-neutral analysis databases, no network, no LLM. Proves each shape
detector (positive + negative), that every sink axis emits one candidate per CALLSITE with a
function-level recall floor beneath it, the OSS-exclusion lesson, the coarse fingerprint,
read-only safety, and a boundary check that the package stays vendor- and
judgment-vocabulary-free.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path

import treasure_map.lib.pattern.shapes as shapes
from treasure_map.lib.pattern import scan
from treasure_map.lib.pattern.classes import (
    CMD,
    COPY,
    FMT_STRING,
    FORMAT,
    PATH_SINK,
    PATH_SINK_ARG,
    SOURCE,
    SOURCE_STRONG,
    SOURCE_WEAK,
    all_format_calls_literal,
    all_path_calls_literal,
    call_offsets,
    format_string_ident,
    path_arg_ident,
    sink_callsites,
)
from treasure_map.lib.pattern.fingerprint import FINGERPRINT_ALGO_VERSION
from treasure_map.lib.pattern.models import FuncRef, PatternStats
from treasure_map.lib.pattern.scanner import DETECTORS, shape_scan_invariant_holds
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


# ── The command axis — two kinds, one detector ──────────────────────────────────────


def test_cmd_injection_shape_positive(tmp_path: Path) -> None:
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
    # The snprintf is separately a buffer-formatter WRITE candidate — a different shape on a
    # different axis, at its own ref. This test is about the command shape, so it takes that one.
    (m,) = [m for m in res.matches if m.sink_class == "cmd"]
    assert m.pattern_kind == "cmd_injection_shape"
    assert m.source_class == "external_input"
    assert m.sink_class == "cmd"
    assert m.call_sequence_shape == "source->format->cmd"
    assert m.fingerprint_algo_version == FINGERPRINT_ALGO_VERSION
    assert m.structural_fingerprint  # non-empty stable hash
    # Evidence is the command sink AT THIS CALLSITE, as it is for every other per-callsite shape.
    # The shell-ish literal is what made this an injection rather than a bare sink, and it says so
    # through pattern_kind / call_sequence_shape above — which are the fields that get persisted.
    # The literal text itself never was: nothing outside this detector ever read it.
    assert m.evidence == "system"
    assert m.sink_callsite_index == 0 and m.sink_callsite_occurrence == 0
    assert m.func_ref.binary_name == "webd"
    assert m.func_ref.func_name == "handle_req"


def test_a_non_shellish_literal_falls_back_to_the_bare_cmd_kind(tmp_path: Path) -> None:
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
    (m,) = [m for m in res.matches if m.sink_class == "cmd"]
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
    (m,) = [m for m in res.matches if m.sink_class == "cmd"]
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
    (m,) = [m for m in res.matches if m.sink_class == "cmd"]
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


def test_each_path_sink_callsite_gets_its_own_candidate(tmp_path: Path) -> None:
    """Several path calls in one function are several candidates, each anchored at ITS OWN callee.

    This replaces a guard that pinned the opposite — one candidate per function, anchored at the
    alphabetically-first callee. Anchoring by sort order meant the row a reader got was not the
    call they were looking at, and the function's remaining path calls had no row anywhere.

    The fixture makes the two rules DIVERGE rather than agree: source order here is unlink then
    fopen, while the retired sort order would have put fopen first. A fixture where they coincide
    would pass under either rule.

    MUTATION (measured: 5 failed): make pattern_path emit one function-level match again (force its
    callsite list empty) -> this test plus the site-coverage, ordinal-order, which-shapes-are-
    per-call and fingerprint-sibling guards all go red together."""
    matches = _path_match(tmp_path, "fs_op", 'unlink(a); fopen(b, "w");', ["unlink", "fopen"])
    assert [(m.sink_callsite_index, m.evidence, m.sink_callsite_occurrence) for m in matches] == [
        (0, "unlink", 0),
        (1, "fopen", 0),
    ]


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


# ── every binary is scanned ─────────────────────────────────────────────────────────


def test_component_table_binary_is_scanned(tmp_path: Path) -> None:
    """★ Being recorded in the components table is a LABEL, not a reason not to look.

    The scan used to skip such a binary outright, so a perfect shape inside it produced nothing
    at all — a recall decision taken by name at scan time, whose only trace was a CLI counter.
    Which project a binary came from belongs on the read side, where it can be weighed against
    everything else known about the candidate; it cannot be a reason never to look.

    MUTATION: skip `busybox` in the scanner loop -> RED here (empty match set) AND `scan()` raises,
    because the two counts no longer partition what was admitted. Measured RED at 1 failed.
    """
    db = _make_db(
        tmp_path,
        [
            {
                "name": "busybox",  # widely-shipped stock binary, also recorded in components
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

    assert {m.func_ref.binary_name for m in res.matches} == {"busybox"}
    assert res.stats.functions_with_callees == 1
    assert res.stats.callee_parse_failed == 0
    assert shape_scan_invariant_holds(res.stats)


def test_every_binary_scanned_alongside(tmp_path: Path) -> None:
    """A stock binary, a shared library and a custom one all reach the detectors.

    ``lib*`` was the other half of the old heuristic, and it is the half that cost the most: a
    wrapper in a shared library forwards a caller's argument to a sink exactly as one anywhere
    else does.

    MUTATION: skip names starting with `lib` in the scanner loop -> RED (the set loses
    libfoo.so.1) AND `scan()` raises. Measured RED at 1 failed.
    """
    db = _make_db(
        tmp_path,
        [
            {
                "name": "busybox",
                "oss": True,
                "funcs": [
                    {
                        "name": "applet",
                        "pseudocode": 'snprintf(c,64,"/bin/sh -c %s",a); system(c);',
                        "callees": ["recv", "snprintf", "system"],
                    }
                ],
            },
            {
                "name": "libfoo.so.1",
                "funcs": [
                    {
                        "name": "forward",
                        "pseudocode": 'snprintf(c,64,"/usr/sbin/svc %s",a); system(c);',
                        "callees": ["recv", "snprintf", "system"],
                    }
                ],
            },
            {
                "name": "webd",
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

    assert {m.func_ref.binary_name for m in res.matches} == {"webd", "busybox", "libfoo.so.1"}
    assert res.stats.functions_with_callees == 3
    assert res.stats.callee_parse_failed == 0
    assert shape_scan_invariant_holds(res.stats)


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


def test_call_class_sets_are_generic_identifiers() -> None:
    ident = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
    for name in SOURCE | FORMAT | CMD | COPY | FMT_STRING | PATH_SINK:
        assert ident.match(name), f"non-identifier call-class entry: {name!r}"


# ── a function whose callees will not parse is a counted gap, never a silent drop ────


def test_scan_counts_callee_parse_failures(tmp_path: Path) -> None:
    """★ The pre-filter already excludes a literal ``'[]'``, so an empty parse result means the
    stored value was MALFORMED. That is a data gap about those functions, not a decision about
    them — and the two look identical from the outside unless the gap is counted.

    The scan does not raise here: bad data is expected and is reported. Raising is reserved for
    the invariant being broken, which can only be a skip in the code.

    MUTATION: make the parse-failure branch a bare ``continue`` again (no counter) -> RED on the
    counts AND `scan()` raises, because the partition no longer adds up. Measured RED at 1 failed.
    """
    db_path = tmp_path / "malformed.db"
    conn = open_db(db_path)
    conn.execute("INSERT INTO binaries (id, name, sha256) VALUES (1, 'webd', ?)", ("a" * 64,))
    rows = [
        (
            1,
            "handle",
            'snprintf(c,64,"/usr/sbin/svc %s",a); system(c);',
            json.dumps(["recv", "snprintf", "system"]),
        ),
        # both pass the `callees != '[]'` pre-filter and both fail to parse into a list
        (2, "broken_shape", "void broken_shape(void){}", '{"not":"a list"}'),
        (3, "broken_json", "void broken_json(void){}", "not-json-at-all"),
    ]
    for fid, name, pc, callees in rows:
        conn.execute(
            "INSERT INTO functions (id, binary_id, name, address, pseudocode, callees) "
            "VALUES (?, 1, ?, ?, ?, ?)",
            (fid, name, f"0x{fid:04x}", pc, callees),
        )
    conn.commit()
    conn.close()

    res = scan(db_path)

    assert res.stats.functions_scanned == 3
    assert res.stats.functions_with_callees == 1
    assert res.stats.callee_parse_failed == 2
    assert shape_scan_invariant_holds(res.stats)
    # the readable function still produced its candidate — a gap elsewhere is not a scan failure
    assert {m.func_ref.func_name for m in res.matches} == {"handle"}


def test_shape_scan_invariant_pure() -> None:
    """The predicate itself, away from any database: what was admitted is exactly what was either
    scanned or counted as a gap.

    Shared with Gate D on purpose — a gate that re-implements the rule it enforces can drift from
    the code and then agrees with it about nothing in particular.

    MUTATION: make ``shape_scan_invariant_holds`` return True -> RED here, and the recall-integrity
    self-test's violating side turns green. Measured RED at 1 failed.
    """

    def _stats(scanned: int, with_callees: int, parse_failed: int) -> PatternStats:
        return PatternStats(
            functions_scanned=scanned,
            functions_with_callees=with_callees,
            callee_parse_failed=parse_failed,
            pattern_a=0,
            pattern_b=0,
        )

    assert shape_scan_invariant_holds(_stats(3, 1, 2)) is True
    assert shape_scan_invariant_holds(_stats(3, 1, 0)) is False  # one went missing
    assert shape_scan_invariant_holds(_stats(3, 2, 2)) is False  # one counted twice


# ── Pattern B — one candidate per copy CALLSITE ──────────────────────────────────────
#
# The unit a copy candidate describes is a CALL, not a function. One row per function made the
# function's other copies unrepresented, and picked which one to show by which callee name sorted
# first — so a function copying a fixed 4 bytes and then a caller-supplied length reported the
# fixed one, for both.

# MC-2 fixtures. A and C must be RED before the fix (1 candidate each); B is the control that must
# stay GREEN either way, so a mutation that breaks emission is not mistaken for the fix working.
_COPY_A = "memcpy(dst, src, 4); memcpy(other, src, len);"  # 1 fixed + 1 variable
_COPY_B = "memcpy(dst, src, 4);"  # 1 fixed only — the control
_COPY_C = "memcpy(a, src, 4); memcpy(b, src, n); memcpy(c, src, m);"  # 1 fixed + 2 variable

# MC-1 counts callsites with its OWN matcher rather than by calling the enumerator under test. The
# NAMES come from the shared COPY set (a test carrying its own copy of the vocabulary would go
# quietly stale the day a callee is added); the counting is the test's.
_VISIBLE_COPY_CALL = re.compile(rf"\b(?:{'|'.join(sorted(COPY))})\s*\(")


def _copy_matches(tmp_path: Path, pseudocode: str, callees: list[str] | None = None) -> list:  # type: ignore[type-arg]
    """The copy candidates one function yields, scanned through the real pipeline."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    db = _make_db(
        tmp_path,
        [
            {
                "name": "svcd",
                "funcs": [
                    {
                        "name": "handler",
                        "pseudocode": pseudocode,
                        "callees": callees or ["memcpy"],
                    }
                ],
            }
        ],
    )
    return [m for m in scan(db).matches if m.sink_class == "copy"]


def test_each_copy_callsite_gets_its_own_candidate(tmp_path: Path) -> None:
    """MC-2. Two copies in a function are two candidates; one copy is still one.

    Before per-callsite emission all three fixtures produced exactly one candidate, anchored at the
    function and reporting the FIRST copy's length. The second and third calls had no row anywhere
    — not a low-ranked row, no row — so no ordering change could have surfaced them.

    MUTATION (must go RED on A and C, and stay GREEN on B): return a single function-level match
    from pattern_b again (``return [_match(..., sorted(cc.copy)[0])]``). Measured: A 2 -> 1, C
    3 -> 1, B 1 -> 1."""
    assert len(_copy_matches(tmp_path / "a", _COPY_A)) == 2
    assert len(_copy_matches(tmp_path / "b", _COPY_B)) == 1
    assert len(_copy_matches(tmp_path / "c", _COPY_C)) == 3


def test_copy_candidate_count_equals_the_visible_callsites(tmp_path: Path) -> None:
    """MC-1 site coverage: as many candidates as there are copy calls to see, no more, no fewer.

    Counted here with this test's own matcher over the same text, so the check is not the
    enumerator agreeing with itself. Covers the multi-callee case, where the two ordinals a match
    carries (position among ALL copy calls vs among calls to ITS callee) stop being the same
    number.

    MUTATION (must go RED): emit per callee NAME instead of per callsite (one match per entry of
    ``cc.copy``) — 4 visible calls, 2 candidates."""
    bodies = {
        "one": _COPY_B,
        "two": _COPY_A,
        "three": _COPY_C,
        "mixed": "memcpy(a,b,4); strcpy(x,y); memcpy(c,d,n); strncpy(e,f,g);",
    }
    for label, body in bodies.items():
        matches = _copy_matches(tmp_path / label, body, ["memcpy", "strcpy", "strncpy"])
        assert len(matches) == len(_VISIBLE_COPY_CALL.findall(body)), label


def test_callsite_ordinals_run_in_source_order_across_callee_names(tmp_path: Path) -> None:
    """The two ordinals are different numbers and each says what it says.

    ``sink_callsite_index`` orders every copy call in the function, across callee names, so it names
    a callsite the same way on every re-scan. ``sink_callsite_occurrence`` counts within ONE callee,
    which is the number the size reader indexes with — hand it the index instead and the third call
    below (index 2, but only the SECOND memcpy) reads a call that is not there.

    MUTATION (must go RED): order the sites by callee name instead of by position, or set
    occurrence = index."""
    matches = _copy_matches(
        tmp_path / "ord", "memcpy(a,b,4); strcpy(x,y); memcpy(c,d,n);", ["memcpy", "strcpy"]
    )
    assert [(m.sink_callsite_index, m.evidence, m.sink_callsite_occurrence) for m in matches] == [
        (0, "memcpy", 0),
        (1, "strcpy", 0),
        (2, "memcpy", 1),
    ]


def test_copy_callee_never_spelled_out_still_yields_one_candidate(tmp_path: Path) -> None:
    """A callee the decompiled body never writes as a call is still a candidate — the recall floor.

    ``pcVar1 = memcpy;`` followed by an indirect call through the pointer is a real and common
    decompilation: the callee list names the copy, the text contains no ``memcpy(``. Enumerating
    callsites there yields nothing, and a detector that emitted per callsite and stopped would have
    traded the split for a silent recall loss — measured at 49 of 1380 copy-carrying functions on
    one real firmware.

    Such a candidate carries NO callsite ordinal. That is the honest label: it is the function-level
    match it always was, and calling it "callsite 0" would claim a call nobody located.

    MUTATION (must go RED): ``return []`` when the enumerator finds no site."""
    matches = _copy_matches(tmp_path / "ptr", "code *pcVar1; pcVar1 = memcpy; (*pcVar1)(d, s, n);")
    assert len(matches) == 1
    assert matches[0].sink_callsite_index is None
    assert matches[0].sink_callsite_occurrence is None
    assert matches[0].evidence == "memcpy"


def test_per_callsite_siblings_share_one_fingerprint_and_one_scanned_function(
    tmp_path: Path,
) -> None:
    """MC-4 + the recurrence ledgers: more candidates, same shape, same one function scanned.

    Two things ride on this. The fingerprint is over the SHAPE, so the siblings fold into one
    pattern row — which is why the recurrence ledgers (distinct pseudocode hashes, distinct runs)
    read the same after this split as before it and need no re-baselining. And the three function
    counters live outside the detector loop, so a function that yields three candidates is still
    one function scanned: Gate D's partition is untouched by how many candidates come out.

    MUTATION (must go RED): add the callsite ordinal to the fingerprint basis, or move any of the
    three counters inside the detector loop."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    db = _make_db(
        tmp_path,
        [{"name": "svcd", "funcs": [{"name": "h", "pseudocode": _COPY_C, "callees": ["memcpy"]}]}],
    )
    res = scan(db)
    copies = [m for m in res.matches if m.sink_class == "copy"]
    assert len(copies) == 3
    assert len({m.structural_fingerprint for m in copies}) == 1
    assert res.stats.pattern_b == 3  # candidates
    assert res.stats.functions_scanned == 1  # ...from one function
    assert shape_scan_invariant_holds(res.stats)


def test_every_sink_axis_now_emits_one_candidate_per_callsite(tmp_path: Path) -> None:
    """Every sink axis is read on a property of the CALL, so every one of them emits per callsite.

    This assertion has now inverted twice, which is the reason it is written as a census of all
    three axes rather than as "the others are function-level". It first pinned four shapes as
    function-level; then path_sink and fmt_string moved; now the command axis has moved too. A
    sentence that names which side each axis is on keeps meaning something across those moves,
    while "the others" silently becomes false.

    Two system() calls, two non-literal printf calls and two fopen calls: six candidates, two per
    axis. Before the splits this fixture produced three — one per axis — and the second call of
    each pair had no row anywhere.

    MUTATION (measured): revert pattern_path to one match per function -> 5 failed, path_sink
    reads 1 here instead of 2. Revert pattern_cmd instead -> 5 failed, cmd reads 1 instead of 2.
    Each axis fails this same assertion from its own side, which is what makes it a census rather
    than a statement about one shape."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    db = _make_db(
        tmp_path,
        [
            {
                "name": "svcd",
                "funcs": [
                    {
                        "name": "many",
                        "pseudocode": (
                            "system(a); system(b); printf(x); printf(y); "
                            'fopen(p,"r"); fopen(q,"r");'
                        ),
                        "callees": ["system", "printf", "fopen"],
                    }
                ],
            }
        ],
    )
    res = scan(db)
    per_class = {}
    for m in res.matches:
        per_class[m.sink_class] = per_class.get(m.sink_class, 0) + 1
    assert per_class == {"cmd": 2, "fmt_string": 2, "path_sink": 2}


# ── a buffer formatter writing into a destination is a candidate per CALLSITE ─────────
#
# snprintf / sprintf / vsnprintf / vsprintf / strcat / strncat all build a string INTO a buffer.
# The class comment said they were "handled as copy/overflow" and nothing handled them, so the
# whole family produced no candidates at all — a formatter that overruns its destination had no
# row anywhere. These emit one per call, on the same write-length axis a copy uses.

_VISIBLE_FORMAT_CALL = re.compile(rf"\b(?:{'|'.join(sorted(FORMAT))})\s*\(")


def _format_matches(tmp_path: Path, pseudocode: str, callees: list[str] | None = None) -> list:  # type: ignore[type-arg]
    tmp_path.mkdir(parents=True, exist_ok=True)
    db = _make_db(
        tmp_path,
        [
            {
                "name": "svcd",
                "funcs": [
                    {
                        "name": "handler",
                        "pseudocode": pseudocode,
                        "callees": callees or sorted(FORMAT),
                    }
                ],
            }
        ],
    )
    return [m for m in scan(db).matches if m.sink_class == "format"]


def test_every_formatter_callsite_is_a_candidate(tmp_path: Path) -> None:
    """MC-a1, precise arm: as many candidates as there are formatter calls to see.

    Counted with this test's own matcher over the same text, so it is not the enumerator agreeing
    with itself. The vocabulary comes from the shared FORMAT set — a test carrying its own copy of
    the callee names would go stale the day one is added.

    MUTATION (must go RED): emit once per function, or once per callee NAME instead of per call."""
    bodies = {
        "one": 'sprintf(d, "%s", x);',
        "mixed": 'sprintf(a, "%s", x); snprintf(b, 64, "%s", y); strcat(c, s); strncat(e, s, 8);',
        "repeat": 'snprintf(a, 16, "%s", x); snprintf(b, n, "%s", y); snprintf(c, 32, "z");',
    }
    for label, body in bodies.items():
        matches = _format_matches(tmp_path / label, body)
        assert len(matches) == len(_VISIBLE_FORMAT_CALL.findall(body)), label


def test_a_formatter_the_body_never_spells_out_still_yields_one_candidate(
    tmp_path: Path,
) -> None:
    """MC-a1, fallback arm: the recall floor, counted against the CALLEE list rather than the text.

    A regex denominator cannot express this case — the text holds zero calls and one candidate is
    correct — which is why the site-coverage check has two arms instead of one equation that would
    be red by construction here.

    MUTATION (must go RED): return [] when the enumerator finds no site."""
    matches = _format_matches(
        tmp_path / "ptr", "code *pcVar1; pcVar1 = sprintf; (*pcVar1)(d, s);", ["sprintf"]
    )
    assert len(matches) == 1
    assert matches[0].sink_callsite_index is None
    assert matches[0].evidence == "sprintf"


def test_whether_a_formatter_is_a_candidate_does_not_depend_on_its_destination(
    tmp_path: Path,
) -> None:
    """★ Existence is decided by "is this a write sink", never by how much can be said about it.

    A ``param_`` destination is a buffer the CALLER owns — the cross-function overflow this scan
    cannot see the size of, and on one real firmware the second most common destination shape.
    Gating emission on a recognizable stack array would drop exactly the calls whose length is
    hardest to reason about, and would do it silently: there would be no row to notice missing.
    The same for a heap pointer or a global.

    Asserted on the CALLSITE ANCHOR and not on the count, because the count alone cannot tell the
    two apart: a destination filter would empty the callsite list, the recall floor would fire, and
    one function-level candidate would come back looking like a hit. The anchored index is what says
    the call itself was seen.

    MUTATION (must go RED): require the destination to look like a stack buffer."""
    for label, dst in (
        ("stack", "acStack_64"),
        ("param", "param_1"),
        ("heap", "puVar3"),
        ("global", "DAT_00410000"),
        ("member", "*(char *)(param_1 + 0x18)"),
    ):
        matches = _format_matches(tmp_path / label, f'sprintf({dst}, "%s", x);', ["sprintf"])
        assert len(matches) == 1, label
        assert matches[0].sink_callsite_index == 0, label  # the CALL was seen, not a fallback
        assert matches[0].sink_callsite_occurrence == 0, label


def test_a_formatter_building_a_shell_command_is_still_a_command_candidate(
    tmp_path: Path,
) -> None:
    """MC-a3. The write-length axis is added alongside the command axis, not instead of it.

    A sprintf that assembles a shell string feeds the command-injection shape through the same
    callee set. Emitting it as a write candidate must not take it out of that shape: the two are
    different questions about one call, and they land at different refs.

    MUTATION (must go RED): route FORMAT away from the cmd shape (drop cc.fmt from pattern_cmd's
    template gate, or stop classifying FORMAT into cc.fmt)."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    db = _make_db(
        tmp_path,
        [
            {
                "name": "webd",
                "funcs": [
                    {
                        "name": "run",
                        "pseudocode": 'snprintf(cmd, 128, "/usr/bin/tool %s", arg); system(cmd);',
                        "callees": ["snprintf", "system"],
                    }
                ],
            }
        ],
    )
    by_class = {m.sink_class for m in scan(db).matches}
    assert by_class == {"cmd", "format"}


# ── a path sink is a candidate per CALLSITE ──────────────────────────────────────────
#
# The axis a path sink is read on is its PATH ARGUMENT, which belongs to the call. One row per
# function was anchored at whichever callee sorted first, so a constant path could stand in for a
# controllable one in the same function — and take the demotion a hard-coded path earns with it.

_VISIBLE_PATH_CALL = re.compile(rf"\b(?:{'|'.join(sorted(PATH_SINK))})\s*\(")


def test_path_candidate_count_equals_the_visible_callsites(tmp_path: Path) -> None:
    """Site coverage: as many candidates as there are path calls to see, no more, no fewer.

    Counted with this test's own matcher over the same text, so the check is not the enumerator
    agreeing with itself. The vocabulary comes from the shared PATH_SINK set — a test carrying its
    own copy of the callee names would go stale the day one is added.

    MUTATION (measured: 5 failed, this among them): emit once per function instead of per call.
    The "repeat" body below holds three calls to two names, so emitting per callee NAME fails it
    too — which a body with one call per name could not tell apart."""
    bodies = {
        "one": 'fopen(p, "r");',
        "mixed": 'fopen(p, "r"); unlink(q); mkdir(d); rename(a, b);',
        "repeat": 'fopen(a, "r"); unlink(b); fopen(c, "w");',
    }
    for label, body in bodies.items():
        matches = _path_match(tmp_path / label, "fs", body, sorted(PATH_SINK))
        assert len(matches) == len(_VISIBLE_PATH_CALL.findall(body)), label


def test_path_callsite_ordinals_run_in_source_order_across_callee_names(tmp_path: Path) -> None:
    """The two ordinals are different numbers and each says what it says.

    ``sink_callsite_index`` orders every path call in the function across callee names, so it names
    a callsite the same way on every re-scan. ``sink_callsite_occurrence`` counts within ONE callee,
    which is the number a per-call argument reader indexes with — hand it the index instead and the
    third call below (index 2, but only the SECOND fopen) reads a call that is not there.

    MUTATION (measured: 5 failed, this among them): force pattern_path back to a function-level
    match -> no ordinals at all. Ordering the sites by callee name, or setting occurrence = index,
    breaks the same assertion on its other axis."""
    matches = _path_match(
        tmp_path / "ord", "fs", 'fopen(a, "r"); unlink(b); fopen(c, "w");', ["fopen", "unlink"]
    )
    assert [(m.sink_callsite_index, m.evidence, m.sink_callsite_occurrence) for m in matches] == [
        (0, "fopen", 0),
        (1, "unlink", 0),
        (2, "fopen", 1),
    ]


def test_path_callee_never_spelled_out_still_yields_one_candidate(tmp_path: Path) -> None:
    """The recall floor: a callee the body never writes as a call is still a candidate.

    Enumerating callsites yields nothing here, and a detector that emitted per callsite and stopped
    would have traded the split for a silent recall loss. Such a candidate carries NO callsite
    ordinal — calling it "callsite 0" would claim a call nobody located.

    MUTATION (measured: 1 failed, this test alone): ``return []`` when the enumerator finds no
    site -> the candidate disappears and nothing else in the file notices, which is the point."""
    matches = _path_match(tmp_path / "ptr", "fs", "code *p; p = fopen; (*p)(x);", ["fopen"])
    assert len(matches) == 1
    assert matches[0].sink_callsite_index is None
    assert matches[0].sink_callsite_occurrence is None
    assert matches[0].evidence == "fopen"


# ── a format-string sink is a candidate per RISKY CALLSITE ───────────────────────────


def test_only_the_non_literal_format_callsite_is_a_candidate(tmp_path: Path) -> None:
    """★ The precision gain, and the FP gate surviving it.

    The literal-format exemption now applies PER CALL. A function that logs a fixed format three
    times and a constructed one once yields exactly ONE candidate, anchored at the risky call —
    where before it yielded one candidate anchored at the sink NAME, which told a reader only that
    somewhere among the four calls one was risky.

    Asserted on the ANCHOR, not on the count: a detector that kept the function-level behaviour also
    returns one candidate here, and only the ordinal tells the two apart.

    MUTATION (measured: 2 failed): use all_format_calls_literal (the whole-function test) per site
    instead of format_call_is_risky -> every call of a mixed function becomes a candidate, failing
    this guard and the older mixed-calls one."""
    matches = _fmt_match(
        tmp_path, "log_it", 'printf("a"); printf("b"); printf("c"); printf(user);', ["printf"]
    )
    assert len(matches) == 1
    assert (matches[0].sink_callsite_index, matches[0].sink_callsite_occurrence) == (3, 3)


def test_every_format_callsite_literal_is_still_exempt(tmp_path: Path) -> None:
    """The FP gate: a function whose every format call is a literal yields NOTHING.

    This is the suppression the whole recall rides on — the common syslog/printf must not flood the
    candidate set — and it must not be weakened by moving the test per call.

    MUTATION (measured: 6 failed): treat a literal format as risky in format_call_is_risky -> this
    guard, the new per-call one, and four older exemption / mixed-call guards all go red. A
    suppression that stopped suppressing fails broadly, which is the shape to expect."""
    assert _fmt_match(tmp_path, "log_it", 'printf("a"); printf("b");', ["printf"]) == []


def test_format_string_risky_sink_never_spelled_out_still_yields_one_candidate(
    tmp_path: Path,
) -> None:
    """The recall floor on the format axis, and the reason it is not an exemption.

    ``pcVar1 = syslog;`` and an indirect call: the callee list names the sink, the text holds no
    ``syslog(``. No callsite can be located, so no per-site candidate can be emitted — but nothing
    was proven safe either, so the function-level candidate stands, with no ordinal.

    MUTATION (measured: 1 failed, this test alone): ``return []`` when no risky site is located,
    instead of falling back -> the candidate vanishes with nothing else going red."""
    matches = _fmt_match(tmp_path, "log_it", "code *p; p = syslog; (*p)(3, x);", ["syslog"])
    assert len(matches) == 1
    assert matches[0].sink_callsite_index is None
    assert matches[0].evidence == "syslog"


def test_path_and_format_siblings_share_one_fingerprint(tmp_path: Path) -> None:
    """More candidates, same SHAPE — so the recurrence ledgers read the same after the split.

    The fingerprint basis excludes the callsite anchor, so per-callsite siblings fold into one
    pattern row. This is what keeps breadth / device-spread accounting from being re-baselined by a
    change that only splits rows apart, and it is the same property the copy split relies on.

    MUTATION (measured: 2 failed): add the callsite ordinal to the fingerprint basis -> this guard
    and the copy-sibling one both go red, i.e. the split would have re-baselined the ledgers."""
    body = 'fopen(a,"r"); fopen(b,"w"); fopen(c,"a");'
    paths = _path_match(tmp_path / "p", "fs", body, ["fopen"])
    assert len(paths) == 3
    assert len({m.structural_fingerprint for m in paths}) == 1
    fmts = _fmt_match(tmp_path / "f", "lg", "printf(x); printf(y);", ["printf"])
    assert len(fmts) == 2
    assert len({m.structural_fingerprint for m in fmts}) == 1


# ── a command sink is a candidate per CALLSITE ───────────────────────────────────────
#
# The injection shape and the bare-sink shape were two detectors kept mutually exclusive by hand,
# but they describe ONE atom: a command sink being called, in a function that did or did not build
# a shell template. One enumerator now walks the callsites, and the template signal only picks
# which KIND each candidate carries. The kinds and the shape strings are untouched on purpose —
# the structural fingerprint is keyed on them.

_VISIBLE_CMD_CALL = re.compile(rf"\b(?:{'|'.join(sorted(CMD))})\s*\(")


def _cmd_match(tmp_path: Path, name: str, pseudocode: str, callees: list[str]) -> list:  # type: ignore[type-arg]
    tmp_path.mkdir(parents=True, exist_ok=True)
    db = _make_db(
        tmp_path,
        [{"name": "svcd", "funcs": [{"name": name, "pseudocode": pseudocode, "callees": callees}]}],
    )
    return [m for m in scan(db).matches if m.sink_class == "cmd"]


def test_each_command_callsite_gets_its_own_candidate(tmp_path: Path) -> None:
    """★ The collapse this undoes: two constructed commands, two system() calls, one row.

    A function that builds a shell string, runs it, builds a second and runs that one produced a
    SINGLE candidate. The second system() had no row anywhere, and the row that did exist was
    anchored at the function, so nothing said which of the two calls it described.

    Both siblings keep cmd_injection_shape and share one fingerprint: the split adds rows, never
    shapes, so the recurrence ledgers read the same afterwards as before.

    MUTATION (measured: 5 failed): emit once per function again (force the callsite list empty) ->
    this guard, the bare-sink one, the exec-masking one, the per-axis census and the injection
    positive case all go red together."""
    body = (
        'sprintf(a, "/bin/sh -c %s", x); system(a); sprintf(b, "/usr/sbin/tool %s", y); system(b);'
    )
    matches = _cmd_match(tmp_path, "run_two", body, ["sprintf", "system"])
    assert [(m.sink_callsite_index, m.evidence, m.sink_callsite_occurrence) for m in matches] == [
        (0, "system", 0),
        (1, "system", 1),
    ]
    assert {m.pattern_kind for m in matches} == {"cmd_injection_shape"}
    assert len({m.structural_fingerprint for m in matches}) == 1


def test_a_bare_command_sink_is_a_candidate_per_call(tmp_path: Path) -> None:
    """The same for the no-template case, counted against this test's own matcher.

    MUTATION (measured: 5 failed, this among them): emit once per function again. Emitting per
    callee NAME instead of per call fails it too — the body below calls one name three times."""
    body = "system(a); system(b); system(c);"
    matches = _cmd_match(tmp_path, "run_all", body, ["system"])
    assert len(matches) == len(_VISIBLE_CMD_CALL.findall(body)) == 3
    assert {m.pattern_kind for m in matches} == {"bare_cmd_shape"}
    assert [m.sink_callsite_occurrence for m in matches] == [0, 1, 2]
    assert len({m.structural_fingerprint for m in matches}) == 1


def test_the_command_kinds_and_shape_strings_are_unchanged(tmp_path: Path) -> None:
    """★ THE NO-CHURN CONSTRAINT, as an assertion on the exact strings.

    The structural fingerprint is keyed on (pattern kind, sink class, source class, call-sequence
    shape). Merging the two command kinds into one — or renaming either shape string — would move
    every command fingerprint at once, and the ledgers counting how widely a shape recurs would
    quietly start from zero. Splitting rows apart does not do that; renaming does, which is why
    the merge happened in the enumerator and stopped there.

    MUTATION (measured): emit one unified kind for both branches -> 5 failed: this guard, the
    injection positive case, the source-widening guard and the fingerprint-distinctness guard.
    Renaming the injection shape strings instead -> 2 failed: this guard and the positive case.
    Both halves of the churn are caught, and by older guards as well as this one."""
    tpl = 'sprintf(c, "/bin/sh -c %s", b); '
    cases = {
        ("cmd_injection_shape", "source->format->cmd"): (
            f"recv(s, b, 9); {tpl}system(c);",
            ["recv", "sprintf", "system"],
        ),
        ("cmd_injection_shape", "format->cmd"): (f"{tpl}system(c);", ["sprintf", "system"]),
        ("bare_cmd_shape", "source->cmd"): ("recv(s, b, 9); system(b);", ["recv", "system"]),
        ("bare_cmd_shape", "cmd"): ("system(b);", ["system"]),
    }
    for (kind, shape), (body, callees) in cases.items():
        (m,) = _cmd_match(tmp_path / kind / shape.replace(">", "_"), "f", body, callees)
        assert (m.pattern_kind, m.call_sequence_shape) == (kind, shape)


def test_a_shell_sink_is_no_longer_masked_by_a_coexisting_exec_sink(tmp_path: Path) -> None:
    """★ An anchoring hazard retired rather than worked around.

    With one row per function the concrete sink had to be picked from the callee list, and the
    writer preferred a shell sink precisely because an exec-family name sorting first would anchor
    the row at the non-shell call — letting the shell one be downweighted as though it were not
    there. Every command callsite now has its own row, so there is nothing left to mask, and the
    preference is no longer load-bearing.

    MUTATION (measured: 5 failed, this among them): emit once per function -> one of these two
    calls loses its row, and which one survives is decided by the anchor rule rather than by the
    code."""
    matches = _cmd_match(tmp_path, "both", "execv(p, argv); system(cmd);", ["execv", "system"])
    assert [(m.sink_callsite_index, m.evidence) for m in matches] == [(0, "execv"), (1, "system")]


def test_command_callee_never_spelled_out_still_yields_one_candidate(tmp_path: Path) -> None:
    """The recall floor on the command axis, same as every other per-callsite shape keeps.

    MUTATION (measured: 1 failed, this test alone): ``return []`` when the enumerator finds no
    site -> the candidate disappears with nothing else going red."""
    matches = _cmd_match(tmp_path, "ptr", "code *p; p = system; (*p)(c);", ["system"])
    assert len(matches) == 1
    assert matches[0].sink_callsite_index is None
    assert matches[0].sink_callsite_occurrence is None
    assert matches[0].evidence == "system"


# ── the call-location authority, and calls the decompiler named after a stub ─────────
#
# On a stripped binary the decompiler routinely renders a libc call as FUN_<stub-addr>(...), so the
# text holds no `system(` at all. A resolved stub table turns those back into calls to the import,
# and the authority merges them into the SAME source order as the textual ones — so "the Nth call"
# means one thing no matter how each call happened to be rendered.

_STUB_BODY = "memcpy(a, b, 4); FUN_004125b0(c); memcpy(d, e, n);"


def test_call_offsets_without_a_stub_table_is_unchanged() -> None:
    """★ The additive property every existing caller depends on.

    Threading a resolution through must not move the answer for callers that have none. With no
    mapping the stub call below is not a call to anything this function knows about.

    MUTATION (measured: 5 failed): count FUN_<addr> calls even when no table was given -> this
    guard plus the enumerator's and all three delegate guards go red, because every reader that
    passes no table starts seeing calls that were never there for it."""
    offsets = call_offsets(_STUB_BODY, "memcpy")
    assert len(offsets) == 2
    assert all(_STUB_BODY[o] == "(" for o in offsets)
    assert call_offsets(_STUB_BODY, "system") == ()


def test_a_stub_rendered_call_joins_in_source_order() -> None:
    """With the table, the stub call IS a call to the import — and lands where it is written.

    Ordering is the whole point: the stub call sits between the two memcpys, so a merge that
    appended instead of sorting would put it last and every ordinal after it would shift.

    MUTATION (measured: 1 failed, this test alone): concatenate without sorting -> the merged
    offsets stop ascending and the stub call is reported last instead of second."""
    offsets = call_offsets(_STUB_BODY, "system", {0x4125B0: "system"})
    assert len(offsets) == 1
    assert offsets[0] == _STUB_BODY.index("FUN_004125b0(") + len("FUN_004125b0")
    merged = call_offsets(_STUB_BODY, "memcpy", {0x4125B0: "memcpy"})
    assert len(merged) == 3
    assert list(merged) == sorted(merged)  # the stub call is second, not appended last


def test_a_stub_address_mapping_to_another_import_is_not_this_callee() -> None:
    """Never fabricate a callsite: a stub that resolves elsewhere is not a call to this name.

    A wrong `system` is a manufactured candidate — the one outcome worse than an unresolved sink —
    so the address must match THIS name, not merely be present in the table.

    MUTATION (measured: 2 failed): treat any address present in the table as a match -> this guard
    and the enumerator's both go red, because the stub counts as a system call while the table
    says it is memcpy."""
    assert call_offsets(_STUB_BODY, "system", {0x4125B0: "memcpy"}) == ()
    assert call_offsets(_STUB_BODY, "system", {0x999999: "system"}) == ()  # address not in the text


def test_sink_callsites_enumerates_stub_rendered_calls_too() -> None:
    """The emitter sees them, with both ordinals right across callee names.

    The stub call is the SECOND of three calls but the FIRST (and only) call to system, so index
    and occurrence must disagree here — a fixture where they coincide could not tell a correct
    enumerator from one that returns the index for both.

    MUTATION (measured: 1 failed, this test alone): drop the stub_names forward in sink_callsites
    -> only the two memcpys are enumerated and the recovered sink has no callsite at all."""
    sites = sink_callsites(_STUB_BODY, {"memcpy", "system"}, {0x4125B0: "system"})
    assert [(s.index, s.sink_name, s.occurrence) for s in sites] == [
        (0, "memcpy", 0),
        (1, "system", 0),
        (2, "memcpy", 1),
    ]
    # ...and with no table the recovered call is simply not there (the pre-change answer).
    assert [s.sink_name for s in sink_callsites(_STUB_BODY, {"memcpy", "system"})] == [
        "memcpy",
        "memcpy",
    ]


def test_a_stub_rendered_path_call_can_only_turn_constant_off() -> None:
    """★ The prove-safe direction, where an unseen call is the dangerous kind of invisible.

    ``all_path_calls_literal`` marks a path compile-time-constant only when EVERY call passes a
    literal. A call the reader cannot see is a call it cannot check — so a stub-rendered call
    carrying a variable path would leave the answer at "constant" and sink a controllable path out
    of sight. With the table that call is seen, and seeing it can only ever turn constant OFF.

    The fixture makes the two answers DIVERGE rather than agree: literal-only without the table,
    variable-carrying with it.

    MUTATION (measured: 1 failed, this test alone): drop the stub_names forward in
    all_path_calls_literal -> the second assertion reads True, i.e. a variable path is reported as
    a fixed one and the candidate is sunk as provably safe."""
    body = 'fopen("/etc/svc.conf", "r"); FUN_004125b0(p, "w");'
    assert all_path_calls_literal(body, "fopen") is True  # only the textual call is visible
    assert all_path_calls_literal(body, "fopen", {0x4125B0: "fopen"}) is False


def test_a_stub_rendered_format_call_is_judged_with_the_others() -> None:
    """The same for the format-literal exemption, which is the gate the whole recall rides on.

    A function whose only NON-literal format call was rendered as a stub reads "every call is
    literal" and is exempted — the exemption firing on a call nobody looked at.

    MUTATION (measured: 1 failed, this test alone): drop the stub_names forward in
    all_format_calls_literal -> the exemption survives a non-literal call, which is the gate
    firing on a call nobody looked at."""
    body = 'printf("ready\\n"); FUN_00412560(user);'
    assert all_format_calls_literal(body, "printf") is True
    assert all_format_calls_literal(body, "printf", {0x412560: "printf"}) is False


def test_the_danger_axis_identifiers_come_from_the_stub_call_too() -> None:
    """The two ``*_ident`` readers name the value whose controllability matters.

    Without the table they find nothing here (every visible call is literal) and the candidate
    would carry no identifier to trace; with it they name the variable the stub call passes.

    MUTATION (measured: 1 failed each, this test alone): drop the stub_names forward in
    format_string_ident, or in path_arg_ident -> that reader returns None while a variable really
    is reaching the sink. Both were measured separately; each fails only this guard."""
    fmt_body = 'printf("ready\\n"); FUN_00412560(user);'
    assert format_string_ident(fmt_body, "printf") is None
    assert format_string_ident(fmt_body, "printf", {0x412560: "printf"}) == "user"
    path_body = 'fopen("/etc/svc.conf", "r"); FUN_004125b0(chosen, "w");'
    assert path_arg_ident(path_body, "fopen") is None
    assert path_arg_ident(path_body, "fopen", {0x4125B0: "fopen"}) == "chosen"


# ── sink-alias completion: same-signature aliases of covered sinks are recalled ─────────
#
# The vocabulary change these tests cover adds large-file (*64) and same-shape aliases to the path
# and copy sink sets. The delta is kept as a test-local constant so a base/alias position table can
# be checked against it, and so the old vocabulary can be reconstructed for the ref-identity self
# tests below (the old vocabulary is recomputed on the same body).
_ADDED_PATH_ALIASES = frozenset({"fopen64", "freopen64", "openat64", "creat", "truncate64"})
_ADDED_COPY_ALIASES = frozenset({"mempcpy", "wmemcpy"})
# Aliases that copy their path position from an already-covered base; the *64 pair are their base's
# large-file variant, openat64 shares openat's dirfd-first signature. creat / truncate64 are NOT
# here: they are new base members with a directly-specified position, checked separately.
_PATH_ALIAS_BASE = {"fopen64": "fopen", "freopen64": "freopen", "openat64": "openat"}


def test_new_path_aliases_are_each_recalled_with_a_variable_path(tmp_path: Path) -> None:
    """Every added path alias, called with a variable path, is one path-sink candidate anchored at
    that callee — the recall floor the whole class rests on (previously these names matched no sink
    set, so a controllable path through them produced zero candidates).

    openat64 is called with its path at arg1 (a dirfd first), the rest at arg0."""
    calls = {
        "fopen64": 'fopen64(p, "r");',
        "freopen64": 'freopen64(p, "r", fh);',
        "openat64": "openat64(AT_FDCWD, p, 0);",
        "creat": "creat(p, 0644);",
        "truncate64": "truncate64(p, 0);",
    }
    for name, body in calls.items():
        (m,) = _path_match(tmp_path / name, "fn", body, [name])
        assert m.sink_class == "path_sink"
        assert m.evidence == name, name


def test_new_copy_aliases_are_each_recalled_with_a_variable_length(tmp_path: Path) -> None:
    """mempcpy / wmemcpy called with a variable length are each one copy candidate anchored at that
    callee. Before the vocabulary change neither name was a copy sink, so an overflowing length
    through them had no row anywhere."""
    for name in ("mempcpy", "wmemcpy"):
        matches = _copy_matches(tmp_path / name, f"{name}(dst, src, n);", [name])
        assert [m.evidence for m in matches] == [name], name


def test_path_alias_positions_track_their_base_and_new_members_are_arg0() -> None:
    """The value check the arg-position gate rests on: an alias must read the SAME argument its base
    reads, or a caller-controlled path would be judged at the wrong position. The *64 / openat64
    aliases copy their base's position; the two new base members (creat, truncate64) specify arg0
    directly and are asserted against that literal, not against a base.

    MUTATION (must go RED): set openat64 to 0 (its path is arg1, after the dirfd), or point any
    based alias at a different index from its base."""
    for alias, base in _PATH_ALIAS_BASE.items():
        assert PATH_SINK_ARG[alias] == PATH_SINK_ARG[base], (alias, base)
    assert PATH_SINK_ARG["creat"] == 0
    assert PATH_SINK_ARG["truncate64"] == 0
    # every path sink, aliases included, has a registered position and none is orphaned.
    assert set(PATH_SINK_ARG) == PATH_SINK


def test_path_alias_arg_is_read_at_its_own_position_not_a_neighbour() -> None:
    """Reading the wrong argument is the failure that turns a live sink into a false-safe one: a
    ``fopen64(path, "r")`` read at arg1 sees the "r" literal and would be washed to a constant path.
    The path arg (arg0 for fopen64, arg1 for openat64 after the dirfd) must be the one read.

    MUTATION (must go RED): read arg0 for openat64 (the dirfd), or drop fopen64 from PATH_SINK_ARG
    so it takes no position -> path_arg_ident returns None on a variable path."""
    # fopen64: the mode literal at arg1 must NOT wash a variable path at arg0 into 'constant'.
    assert path_arg_ident('fopen64(chosen, "r");', "fopen64") == "chosen"
    assert path_arg_ident('fopen64("/etc/x", "r");', "fopen64") is None
    assert all_path_calls_literal('fopen64(chosen, "r");', "fopen64") is False
    assert all_path_calls_literal('fopen64("/etc/x", "r");', "fopen64") is True
    # openat64: the path is arg1; arg0 is the dirfd and must not be read as the path.
    assert path_arg_ident("openat64(AT_FDCWD, chosen, 0);", "openat64") == "chosen"
    assert all_path_calls_literal("openat64(AT_FDCWD, chosen, 0);", "openat64") is False
    assert all_path_calls_literal('openat64(AT_FDCWD, "/etc/x", 0);', "openat64") is True
    # creat / truncate64: path at arg0.
    assert path_arg_ident("creat(chosen, 0644);", "creat") == "chosen"
    assert path_arg_ident("truncate64(chosen, 0);", "truncate64") == "chosen"


def test_alias_names_do_not_cross_match_by_substring() -> None:
    """A copy name is a substring of another (``memcpy`` inside ``wmemcpy``), so the call locator
    must match on a word boundary or memcpy's callsite count would absorb wmemcpy's calls and the
    Nth-call anchor would point at the wrong line.

    MUTATION (must go RED): drop the \\b word boundary in call_offsets' regex -> memcpy is found
    inside wmemcpy and mempcpy."""
    assert call_offsets("wmemcpy(d, s, n);", "memcpy") == ()
    assert call_offsets("mempcpy(d, s, n);", "memcpy") == ()
    assert len(call_offsets("wmemcpy(d, s, n);", "wmemcpy")) == 1
    assert len(call_offsets("mempcpy(d, s, n);", "mempcpy")) == 1
    # and the base is still found when spelled on its own.
    assert len(call_offsets("memcpy(d, s, n); wmemcpy(e, t, m);", "memcpy")) == 1


def _ordinal_map(text: str, names: frozenset[str]) -> dict[int, tuple[str, int]]:
    """index -> (sink_name, occurrence) for one body under one sink vocabulary — the identity the
    ref-identity comparison uses between the old and new vocabularies."""
    return {s.index: (s.sink_name, s.occurrence) for s in sink_callsites(text, names)}


def test_adding_a_copy_alias_repoints_a_same_name_ordinal() -> None:
    """Same-name, DIFFERENT call: an added alias spelled before two calls to an existing sink pushes
    both of that sink's ordinals up by one, so ``@copy#1`` keeps its callee name (``memcpy``) yet
    names a different call than before. A comparison that looked only at the sink name would pass
    this unchanged -- the name at #1 is ``memcpy`` on both sides -- so the ref identity has to be
    (name, occurrence), never the name alone. #0 additionally re-points by name (memcpy -> mempcpy);
    both forms live in one fixture.

    Synthetic, not copied from a real ref: the old vocabulary is COPY minus this batch's additions,
    recomputed on the same body.

    MUTATION (must go RED): order sink_callsites by callee name instead of source position, or drop
    the occurrence from the identity so #1's memcpy-before and memcpy-after compare equal."""
    text = "mempcpy(w, x, y); memcpy(a, b, c); memcpy(d, e, f);"
    old = _ordinal_map(text, COPY - _ADDED_COPY_ALIASES)
    new = _ordinal_map(text, COPY)
    assert old == {0: ("memcpy", 0), 1: ("memcpy", 1)}
    assert new == {0: ("mempcpy", 0), 1: ("memcpy", 0), 2: ("memcpy", 1)}
    assert new[0][0] != old[0][0]  # #0 re-points by NAME: memcpy -> mempcpy
    assert new[1][0] == old[1][0] == "memcpy"  # #1 keeps the callee name...
    assert new[1][1] != old[1][1]  # ...but names a different call (occurrence 1 -> 0)


def test_function_level_fallback_ref_repoints_when_the_first_name_changes() -> None:
    """The third re-point form: a function whose path callees are all indirect (no textual call to
    locate) yields ONE function-level candidate carrying the BARE ``@path_sink`` ref, whose evidence
    is the alphabetically-first path callee. An added alias that sorts first becomes that evidence,
    so the bare ref -- which has no ``#N`` -- names a different sink while its string is unchanged.
    The identity comparison must cover bare refs too, not only the ``#N`` ones.

    MUTATION (must go RED): anchor the fallback at a fixed name instead of sorted(cc)[0], or exclude
    the no-ordinal refs from the identity comparison."""
    fr = FuncRef(binary_name="b", func_name="f", func_id=1)
    callees = ["open", "fopen64"]
    body = "code *p; p = fopen64; (*p)(name, mode);"  # no textual open( / fopen64( to locate
    saved = shapes.PATH_SINK
    try:
        shapes.PATH_SINK = saved - _ADDED_PATH_ALIASES
        (old,) = shapes.pattern_path(fr, callees, body)
        shapes.PATH_SINK = saved
        (new,) = shapes.pattern_path(fr, callees, body)
    finally:
        shapes.PATH_SINK = saved
    assert old.sink_callsite_index is None and new.sink_callsite_index is None  # bare refs
    assert old.evidence == "open"  # sorted({open})[0]
    assert new.evidence == "fopen64"  # sorted({open, fopen64})[0] -> the bare ref re-points


def test_a_newly_locatable_alias_flips_a_function_off_its_bare_ref() -> None:
    """ref-disappearance mechanism: a function whose only copy is an indirect pointer
    (``p = memcpy;`` then a call through ``p``, no textual ``memcpy(``) produced ONE function-level
    candidate with the bare ``@copy`` ref under the old vocabulary. If a newly added alias is
    spelled as a call, the new
    vocabulary locates a callsite and the function switches to the per-callsite ``@copy#0``, so the
    bare ``@copy`` string is gone. The hard gate counts how often this happens on real firmware,
    because each such function's bare ref is one a stored judgement could have been keyed by.

    MUTATION (must go RED): make sink_callsites invent a site for a callee spelled only as a value
    (no call parens) -> the old vocabulary no longer yields the empty/fallback state."""
    text = "code *p; p = memcpy; (*p)(d, s, n); mempcpy(d2, s2, n2);"
    old = sink_callsites(text, COPY - _ADDED_COPY_ALIASES)
    new = sink_callsites(text, COPY)
    assert old == ()  # no locatable call -> function-level fallback -> bare @copy
    assert [(s.index, s.sink_name, s.occurrence) for s in new] == [(0, "mempcpy", 0)]


# ── libc ABI aliases of the recognized sources ─────────────────────────────────────────
#
# The delta is a test-local constant so the old vocabulary can be reconstructed: adding a source
# name re-labels a candidate, it never creates one, and both halves need checking.
_ADDED_SOURCE_ALIASES = frozenset(
    {"__isoc99_sscanf", "__isoc99_fscanf", "__isoc99_scanf", "fgets_unlocked", "__getdelim"}
)
# Same-family names deliberately NOT listed: no call to any of them exists in the corpus this set
# was closed over, and listing a source nobody calls claims a reading that was never observed.
_UNLISTED_SOURCE_CANDIDATES = frozenset(
    {
        "__isoc99_vsscanf",
        "vsscanf",
        "__isoc99_vfscanf",
        "vfscanf",
        "__isoc99_vscanf",
        "vscanf",
        "fread_unlocked",
    }
)
# One body per alias: the alias reads input, a copy sink then gives the function a candidate to
# carry the source label. Without the alias recognized the same body is source_class=unknown.
_SOURCE_ALIAS_BODY = {
    "__isoc99_sscanf": '__isoc99_sscanf(inp, "%s", buf);',
    "__isoc99_fscanf": '__isoc99_fscanf(fh, "%s", buf);',
    "__isoc99_scanf": '__isoc99_scanf("%s", buf);',
    "fgets_unlocked": "fgets_unlocked(buf, 64, fh);",
    "__getdelim": "__getdelim(&line, &cap, 10, fh);",
}


def test_each_libc_source_alias_is_recognized_as_a_source(tmp_path: Path) -> None:
    """Each added alias, on its own, labels its function's candidate external_input.

    Per alias rather than once for the set: a single shared assertion passes while four of the five
    names do nothing, which is exactly the shape of a vocabulary entry that was never wired.

    MUTATION (must go RED, one per alias): drop that alias from SOURCE_WEAK -> its body reads
    source_class=unknown again while the other four stay green."""
    for alias, read in _SOURCE_ALIAS_BODY.items():
        db = _make_db(
            tmp_path / alias,
            [
                {
                    "name": "svcd",
                    "funcs": [
                        {
                            "name": "handler",
                            "pseudocode": f"{read} memcpy(dst, buf, n);",
                            "callees": [alias, "memcpy"],
                        }
                    ],
                }
            ],
        )
        (m,) = [x for x in scan(db).matches if x.sink_class == "copy"]
        assert m.source_class == "external_input", alias
        assert m.call_sequence_shape == "source->copy", alias


def _all_matches(fr: FuncRef, callees: list[str], body: str) -> list:  # type: ignore[type-arg]
    """Every detector's matches for one function, in detector order."""
    return [m for det in DETECTORS for m in det(fr, callees, body, None)]


def test_a_source_alias_relabels_a_candidate_and_never_creates_one() -> None:
    """Recognising a source is NOT a recall change. No detector gates emission on the source class
    -- every one of them gates on its own sink -- so adding a source name must leave the candidate
    set, its callsite ordinals and its sink evidence identical, and move only the two shape fields
    (source_class, call_sequence_shape) plus the fingerprint they feed. A source that added or
    dropped a row would change what is on the board, not just how it is labelled.

    MUTATION (must go RED): gate any detector on cc.source (e.g. ``if not cc.source: return []``)
    -> the candidate sets stop matching; or fold the source into the callsite anchor -> the ordinal
    comparison breaks."""
    fr = FuncRef(binary_name="b", func_name="handler", func_id=1)
    callees = ["__isoc99_sscanf", "memcpy", "system", "fopen"]
    body = '__isoc99_sscanf(inp, "%s", buf); memcpy(dst, buf, n); system(cmd); fopen(path, "r");'
    saved = shapes.SOURCE
    try:
        shapes.SOURCE = saved - _ADDED_SOURCE_ALIASES
        old = _all_matches(fr, callees, body)
        shapes.SOURCE = saved
        new = _all_matches(fr, callees, body)
    finally:
        shapes.SOURCE = saved

    def anchors(ms: list) -> list:  # type: ignore[type-arg]
        return [
            (
                m.sink_class,
                m.pattern_kind,
                m.evidence,
                m.sink_callsite_index,
                m.sink_callsite_occurrence,
            )
            for m in ms
        ]

    assert len(new) == len(old) > 0
    assert anchors(new) == anchors(old)  # no candidate added, dropped, or re-anchored
    assert {m.source_class for m in old} == {"unknown"}
    assert {m.source_class for m in new} == {"external_input"}
    for o, n in zip(old, new, strict=True):
        assert n.call_sequence_shape == f"source->{o.call_sequence_shape}"
        assert n.structural_fingerprint != o.structural_fingerprint  # the two fields feed it


def test_source_alias_vocabulary_stays_weak_and_unspeculative() -> None:
    """The added names are WEAK sources (their bases are), and the same-family names that no call
    in the corpus reaches stay out. Encoded as set relations so a later edit that promotes one to
    STRONG, or quietly adds an unobserved name, fails here instead of shipping.

    MUTATION (must go RED): move any alias into SOURCE_STRONG, or add one of the unlisted names."""
    assert _ADDED_SOURCE_ALIASES <= SOURCE_WEAK
    assert not (_ADDED_SOURCE_ALIASES & SOURCE_STRONG)
    assert _ADDED_SOURCE_ALIASES <= SOURCE  # the union R-pattern reads
    assert not (_UNLISTED_SOURCE_CANDIDATES & SOURCE)
    # every alias sits beside a base that is itself a recognized weak source
    for alias, base in {
        "__isoc99_sscanf": "sscanf",
        "__isoc99_fscanf": "fscanf",
        "__isoc99_scanf": "scanf",
        "fgets_unlocked": "fgets",
        "__getdelim": "getdelim",
    }.items():
        assert base in SOURCE_WEAK, (alias, base)
