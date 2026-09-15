# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
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
from treasure_map.lib.pattern.models import PatternStats
from treasure_map.lib.pattern.scanner import shape_scan_invariant_holds
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
    # The snprintf is separately a buffer-formatter WRITE candidate — a different shape on a
    # different axis, at its own ref. This test is about the command shape, so it takes that one.
    (m,) = [m for m in res.matches if m.sink_class == "cmd"]
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


def test_the_command_shapes_are_the_ones_that_stay_function_level(tmp_path: Path) -> None:
    """Which shapes are per-callsite and which are per-function, pinned as one statement.

    The write-length shapes (copy, format), the format argument (fmt_string) and the path argument
    (path_sink) all belong to a CALL, and each emits one candidate per callsite. The command shapes
    are the ones still about the FUNCTION: their evidence is a constructed shell literal that the
    function builds, not a property of one call, so two system() calls here remain one candidate.

    This test said the opposite until path_sink and fmt_string moved: it pinned all four non-copy
    shapes as function-level. That is why it is phrased as "which side is each shape on" rather than
    "the others are function-level" — the sentence has to keep meaning something when a shape moves.

    MUTATION (measured: 5 failed, this among them): revert pattern_path to one match per function
    -> path_sink reads 1 here instead of 2. Making a command shape emit per call is the same
    assertion read from its other side."""
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
    # Two system() calls -> ONE cmd candidate (the function-level shape). Two non-literal printf
    # calls -> two fmt_string candidates; two fopen calls -> two path_sink candidates.
    assert per_class == {"cmd": 1, "fmt_string": 2, "path_sink": 2}


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

    MUTATION (must go RED): route FORMAT away from the cmd shape (drop cc.fmt from pattern_a's
    gate, or stop classifying FORMAT into cc.fmt)."""
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
