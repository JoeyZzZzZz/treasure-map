# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""A recorded diff is re-diffed, and read as stale, when what it was computed from has moved.

What a diff reads besides the bytes — the binary's extraction, the hunt output for it, the diff code
— is stamped on the diff (lib/diff/currency). These tests cover the stamps' storage and migration,
the full diff's re-diff decision and attempt count, the run-pair currency refusals, the read
side's ``source_stale`` on every diff surface, keeping a stored candidate baseline across a re-diff,
and a golden diff that pins what the diff code writes for a fixed input.

Synthetic data only. The toolchain steps (BinExport, BinDiff) are stubbed to hand back a crafted
``.BinDiff`` and hand-encoded BinExport files; everything from the layer-0 parse on runs for real.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import DiffMetaRow
from treasure_map.lib.atlas.writer import add_diff_meta, begin_run, finish_run
from treasure_map.lib.config.config import Config
from treasure_map.lib.diff import code_version, currency, driver, toolchain
from treasure_map.lib.diff.driver import DiffToolchainError
from treasure_map.lib.diff.layer0 import make_diff_id
from treasure_map.lib.errors import ConfigError
from treasure_map.lib.query import diff_align
from treasure_map.lib.query import sink_overlay as so
from treasure_map.lib.storage.connection import open_db
from treasure_map.version import UNKNOWN_VERSION

_PV = "pv1"
_GV = "11.4.3"
_COMMIT = "facefeed"
_SCHEMA = (
    Path(__file__).resolve().parents[3]
    / "src"
    / "treasure_map"
    / "lib"
    / "storage"
    / "atlas_schema.sql"
)
_FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "fixtures"
    / "layer0"
    / "shapes_before_vs_shapes_after.BinDiff"
)
_NEW_DIFF_META_COLS = (
    "extraction_pass_a",
    "extraction_pass_b",
    "hunt_inputs_hash_a",
    "hunt_inputs_hash_b",
    "scanned_at_a",
    "scanned_at_b",
    "hunt_instances_a",
    "hunt_instances_b",
    "diff_code_version",
    "baseline_dropped",
)

# ── a minimal BinExport2 encoder (protobuf wire format), as in test_callsite_facts ───────────────


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _key(fieldno: int, wire_type: int) -> bytes:
    return _varint(fieldno << 3 | wire_type)


def _ld(fieldno: int, body: bytes) -> bytes:
    return _key(fieldno, 2) + _varint(len(body)) + body


def _insn(address: int, targets: tuple[int, ...] = ()) -> bytes:
    """One instruction at an explicit address with its call targets and 4 raw bytes."""
    body = _key(1, 0) + _varint(address)
    body += b"".join(_key(2, 0) + _varint(t) for t in targets)
    body += _ld(5, b"\x00\x00\x00\x00")
    return _ld(5, body)


# ── a two-run world: one analysis.db per run, a hunt's output in the atlas ────────────────────────


def _sha(c: str) -> str:
    return c * 64


@dataclass
class _World:
    tmp: Path
    atlas: sqlite3.Connection
    so_sha: dict[str, str] = field(default_factory=dict)
    fail: set[str] = field(default_factory=set)  # binary names whose BinDiff step fails
    hunts: int = 0


_TOKENS = json.dumps([{"call_token": "system", "op_addr": "0x1010", "opcode": 7, "text_off": 0}])


def _analysis(w: _World, side: str, rows: dict[str, tuple[str, str | None]]) -> Path:
    """``rows``: {binary name -> (sha256, pass_version)}; a None pass = never extracted."""
    path = w.tmp / f"{side}.db"
    conn = open_db(path)
    for i, (name, (sha, pv)) in enumerate(rows.items(), start=1):
        so_path = w.tmp / f"{side}-{name}-{sha[:8]}"
        so_path.write_bytes(b"\x7fELF")
        w.so_sha[str(so_path)] = sha
        conn.execute(
            "INSERT INTO binaries (id, name, path, sha256, arch, pass_version, ghidra_version, "
            "ghidra_ok, last_seen_at) VALUES (?, ?, ?, ?, 'ARM:LE:32:v7', ?, ?, 1, "
            "'2026-01-01T00:00:00')",
            (i, name, str(so_path), sha, pv, _GV if pv else None),
        )
        conn.execute(
            "INSERT INTO functions (binary_id, name, address, pseudocode, size_bytes, call_tokens) "
            "VALUES (?, 'caller', '0x1000', 'void caller(void){ system(x); }', 64, ?)",
            (i, _TOKENS),
        )
    conn.commit()
    conn.close()
    return path


def _hunt(w: _World, run: str, binaries: dict[str, str], hunt_commit: str | None) -> None:
    """Write what a hunt writes for a run: a candidate and an edge per binary, the capability."""
    a = w.atlas
    if a.execute("SELECT COUNT(*) FROM pattern").fetchone()[0] == 0:
        a.execute(
            "INSERT INTO pattern (source_class, sink_class, call_sequence_shape, "
            "structural_fingerprint, fingerprint_algo_version) VALUES "
            "('external_input', 'cmd', 's->s', 'fp', 'v1')"
        )
    pid = a.execute("SELECT pattern_id FROM pattern").fetchone()[0]
    for name, sha in binaries.items():
        a.execute(
            "INSERT INTO instance (pattern_id, evidence_ref, source_run_id, binary_content_hash, "
            "binary_path, sink_anchor) VALUES (?, ?, ?, ?, ?, 'system')",
            (pid, f"{run}#{sha[:8]}:00001000@cmd@0x000010", run, sha, name),
        )
        a.execute(
            "INSERT INTO string_keyed_edge (source_run_id, binary, from_function, from_func_addr, "
            "key, mechanism, callee_name, callee_addr, callee_kind, completeness_status) VALUES "
            "(?, ?, 'caller', '00001000', 'mode', 'strcmp_gate', 'handler', '00002000', 'direct', "
            "'complete')",
            (run, name),
        )
    a.execute(
        "INSERT INTO run_capability (run_id, capability, present) "
        "VALUES (?, 'reachability.string_keyed_edge', 1)",
        (run,),
    )
    n = a.execute("SELECT COUNT(*) FROM instance WHERE source_run_id = ?", (run,)).fetchone()[0]
    finish_run(a, run, hunt_commit=hunt_commit, hunt_instances=n)


def _world(
    tmp_path: Path,
    a: dict[str, tuple[str, str | None]],
    b: dict[str, tuple[str, str | None]],
    *,
    hunt_commit: str | None = None,
) -> _World:
    w = _World(tmp_path, open_atlas(tmp_path / "atlas.db"))
    for side, rows in (("a", a), ("b", b)):
        run = f"run_{side}"
        db = _analysis(w, side, rows)
        begin_run(w.atlas, run, analysis_db_path=str(db), tool_version="0.0.1", ghidra_version=_GV)
        _hunt(w, run, {n: s for n, (s, _pv) in rows.items()}, hunt_commit)
    return w


def _two(tmp_path: Path, **kw: Any) -> _World:
    """liba changed between the runs; both extracted by the running pipeline."""
    return _world(tmp_path, {"liba": (_sha("a"), _PV)}, {"liba": (_sha("b"), _PV)}, **kw)


def _bindiff(path: Path, sha_a: str, sha_b: str) -> Path:
    path.unlink(missing_ok=True)
    con = sqlite3.connect(path)
    con.execute(
        "CREATE TABLE function (id INTEGER PRIMARY KEY, address1 BIGINT, name1 TEXT, "
        "address2 BIGINT, name2 TEXT, similarity DOUBLE, confidence DOUBLE, "
        "basicblocks INTEGER, edges INTEGER, instructions INTEGER)"
    )
    con.execute(
        "INSERT INTO function VALUES (1, ?, 'caller', ?, 'caller', 0.98, 0.97, 3, 2, 20)",
        (0x1000, 0x1000),
    )
    con.execute(
        "CREATE TABLE basicblock (id INT, functionid INT, address1 BIGINT, address2 BIGINT)"
    )
    con.execute("INSERT INTO basicblock VALUES (1, 1, ?, ?)", (0x1000, 0x1000))
    con.execute("CREATE TABLE instruction (basicblockid INT, address1 BIGINT, address2 BIGINT)")
    con.execute("INSERT INTO instruction VALUES (1, ?, ?)", (0x1010, 0x1010))
    con.execute("CREATE TABLE file (id INT, filename TEXT, hash CHARACTER(40))")
    con.executemany(
        "INSERT INTO file VALUES (?, ?, ?)", [(1, "before", sha_a), (2, "after", sha_b)]
    )
    con.commit()
    con.close()
    return path


def _stub(
    monkeypatch: pytest.MonkeyPatch,
    w: _World,
    *,
    build: str = _PV,
    commit: str = _COMMIT,
) -> None:
    """Stub the toolchain, and make ``build`` / ``commit`` the running extraction pipeline and
    install."""
    monkeypatch.setattr(driver, "_check_toolchain", lambda config: None)
    monkeypatch.setattr(driver, "_current_pass_version", lambda: build)
    monkeypatch.setattr(driver, "_installed_commit", lambda: commit)

    def binexport(so_path: Path, cfg: Any, out: Path, side: str, timeout: int) -> Path:
        (out / f"{side}.so").write_text(str(so_path))
        p = out / f"{side}.BinExport"
        p.write_bytes(_insn(0x1010, (0x9000,)))
        return p

    def bindiff(ea: Path, eb: Path, out: Path, timeout: int) -> Path:
        so_a, so_b = (out / "a.so").read_text(), (out / "b.so").read_text()
        if Path(so_a).name.split("-")[1] in w.fail:
            raise DiffToolchainError(
                "BinDiff failed (rc=1) Could not find basic block 0000beef",
                kind=driver.FAIL_BINDIFF_FLOWGRAPH,
            )
        return _bindiff(out / "x.BinDiff", w.so_sha[so_a], w.so_sha[so_b])

    monkeypatch.setattr(driver, "_run_binexport", binexport)
    monkeypatch.setattr(driver, "_run_bindiff", bindiff)


def _full(w: _World, **kw: Any) -> driver.FullDiffSummary:
    return driver.run_full_diff(w.atlas, "run_a", "run_b", config=Config(), **kw)


def _plan(w: _World, **kw: Any) -> driver.FullDiffPlan:
    return driver.plan_full_diff(w.atlas, "run_a", "run_b", **kw)


def _did(binary: str = "liba") -> str:
    return make_diff_id("run_a", "run_b", binary)


def _row(w: _World, binary: str = "liba") -> sqlite3.Row:
    row = w.atlas.execute("SELECT * FROM diff_meta WHERE diff_id = ?", (_did(binary),)).fetchone()
    assert row is not None
    return row  # type: ignore[no-any-return]


def _set_binary(w: _World, side: str, name: str, column: str, value: str | None) -> None:
    """Change one binaries column of a side's analysis.db (what a re-extraction does)."""
    conn = sqlite3.connect(w.tmp / f"{side}.db")
    conn.execute(f"UPDATE binaries SET {column} = ? WHERE name = ?", (value, name))  # noqa: S608
    conn.commit()
    conn.close()


def _rehunt(w: _World, run: str) -> None:
    """Record that a hunt ran: it rewrites run.scanned_at (its output is changed separately)."""
    w.hunts += 1
    w.atlas.execute(
        "UPDATE run SET scanned_at = ? WHERE run_id = ?", (f"2030-01-01 00:00:{w.hunts:02d}", run)
    )
    w.atlas.commit()


# ── the stamp columns, on a fresh atlas and on one from before them ─────────────────────────────


def test_a_fresh_atlas_has_the_stamp_columns(tmp_path: Path) -> None:
    conn = open_atlas(tmp_path / "atlas.db")
    try:
        info = {r[1]: (r[2], r[3], r[4]) for r in conn.execute("PRAGMA table_info(diff_meta)")}
    finally:
        conn.close()
    assert set(_NEW_DIFF_META_COLS) <= set(info)
    assert info["baseline_dropped"] == ("INTEGER", 1, "0")
    assert info["hunt_instances_a"][0] == "INTEGER" and info["diff_code_version"][0] == "TEXT"


def _old_schema() -> str:
    """The atlas schema as it was before the stamps: the lines declaring them in diff_meta removed
    (dimension_delta has same-named columns of its own, which stay)."""
    lines = _SCHEMA.read_text().splitlines()
    start = lines.index("CREATE TABLE IF NOT EXISTS diff_meta (")
    end = lines.index(");", start)
    block = [
        ln for ln in lines[start:end] if not (ln.split() and ln.split()[0] in _NEW_DIFF_META_COLS)
    ]
    assert (end - start) - len(block) == len(_NEW_DIFF_META_COLS)
    return "\n".join(lines[:start] + block + lines[end:])


def test_an_atlas_from_before_the_stamps_opens_and_keeps_its_rows(tmp_path: Path) -> None:
    """MUTATION (verified RED): drop the stamp loop from ``connection._migrate`` -> the old atlas
    reopens without the columns."""
    db = tmp_path / "atlas.db"
    old = sqlite3.connect(db)
    old.executescript(_old_schema())
    cols = {r[1] for r in old.execute("PRAGMA table_info(diff_meta)")}
    assert cols.isdisjoint(_NEW_DIFF_META_COLS)  # really the old shape
    old.execute(
        "INSERT INTO diff_meta (diff_id, run_a_id, run_b_id, binary_a, binary_b, diff_ok, "
        "sha256_a, sha256_b) VALUES ('run_a::run_b::liba', 'run_a', 'run_b', 'liba', 'liba', 1, "
        "'aa', 'bb')"
    )
    old.commit()
    old.close()
    for _ in range(2):  # a second open is a no-op
        conn = open_atlas(db)
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(diff_meta)")}
            assert set(_NEW_DIFF_META_COLS) <= cols
            row = conn.execute("SELECT * FROM diff_meta").fetchone()
            assert row["diff_ok"] == 1 and row["sha256_a"] == "aa"
            assert row["diff_code_version"] is None and row["baseline_dropped"] == 0
        finally:
            conn.close()


# ── the extraction stamps are compared by plain equality ─────────────────────────────────────────


@pytest.mark.parametrize(
    ("side", "column", "value"),
    [
        ("a", "pass_version", "pv2"),
        ("b", "pass_version", "pv2"),
        ("a", "ghidra_version", "12.0"),
        ("b", "ghidra_version", "12.0"),
    ],
)
def test_a_reextracted_binary_is_rediffed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, side: str, column: str, value: str
) -> None:
    """MUTATION (verified RED): leave the extraction stamps out of ``_inputs_unchanged`` -> the
    re-extracted binary stays already_ok."""
    w = _two(tmp_path)
    _stub(monkeypatch, w)
    _full(w)
    assert _plan(w).already_ok == ("liba",)
    _set_binary(w, side, "liba", column, value)
    assert _plan(w).to_diff == ("liba",)


def test_equal_extraction_stamps_are_current_including_none_and_unknown(tmp_path: Path) -> None:
    """None == None and 'unknown' == 'unknown': the same answer twice is not a change."""
    w = _two(tmp_path)
    _set_binary(w, "b", "liba", "pass_version", None)
    _set_binary(w, "b", "liba", "ghidra_version", UNKNOWN_VERSION)
    dbs = {r: str(w.tmp / f"{r[-1]}.db") for r in ("run_a", "run_b")}
    st_a = currency.side_stamp(w.atlas, "run_a", dbs["run_a"], _sha("a"), "liba")
    st_b = currency.side_stamp(w.atlas, "run_b", dbs["run_b"], _sha("b"), "liba")
    assert (st_b.extraction_pass, st_b.ghidra_version) == (None, UNKNOWN_VERSION)
    add_diff_meta(
        w.atlas,
        DiffMetaRow(
            diff_id=_did(),
            run_a_id="run_a",
            run_b_id="run_b",
            binary_a="liba",
            binary_b="liba",
            diff_ok=1,
            diff_attempts=1,
            sha256_a=_sha("a"),
            sha256_b=_sha("b"),
            ghidra_version_a=st_a.ghidra_version,
            ghidra_version_b=st_b.ghidra_version,
            extraction_pass_a=st_a.extraction_pass,
            extraction_pass_b=st_b.extraction_pass,
            hunt_inputs_hash_a=st_a.hunt_inputs_hash,
            hunt_inputs_hash_b=st_b.hunt_inputs_hash,
            diff_code_version=code_version.diff_code_version(),
            export_code_hash_a=st_a.export_code_hash,
            export_code_hash_b=st_b.export_code_hash,
        ),
    )
    assert _plan(w).already_ok == ("liba",)


def test_a_binary_never_extracted_is_a_blind_spot_not_a_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MUTATION (verified RED): drop the extraction check from ``preflight`` -> libz is diffed."""
    w = _world(
        tmp_path,
        {"liba": (_sha("a"), _PV), "libz": (_sha("c"), _PV)},
        {"liba": (_sha("b"), _PV), "libz": (_sha("d"), None)},
    )
    _stub(monkeypatch, w)
    fs = _full(w)
    by = {o.binary: o for o in fs.outcomes}
    assert by["liba"].error is None
    assert by["libz"].error is not None and by["libz"].reason == "extraction_unstamped"
    spots = diff_align.list_diff_blindspots(w.atlas, "run_a", "run_b")["blindspots"]
    assert [(s["binary"], s["diff_status_reason"]) for s in spots] == [
        ("libz", "extraction_unstamped")
    ]


def test_the_never_extracted_blind_spot_converges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Its stamps compare equal on every attempt (None == None), so the count climbs to the cap and
    the binary stops being retried instead of being re-diffed forever."""
    w = _world(tmp_path, {"libz": (_sha("c"), _PV)}, {"libz": (_sha("d"), None)})
    _stub(monkeypatch, w)
    for expect in (1, 2, 3):
        _full(w)
        assert _row(w, "libz")["diff_attempts"] == expect
    assert _plan(w).hard_failed == ("libz",)
    assert _full(w).outcomes == ()


def test_a_mixed_run_hash_warns_and_does_not_loop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    w = _two(tmp_path)
    w.atlas.execute("UPDATE run SET build_hash = 'mixed:2' WHERE run_id = 'run_b'")
    w.atlas.commit()
    _stub(monkeypatch, w)
    fs = _full(w)
    assert [o.error for o in fs.outcomes] == [None]
    assert any("run_b" in m for m in fs.warnings)
    assert _plan(w).already_ok == ("liba",)


# ── the hunt-input digest covers what the diff reads, and nothing else ───────────────────────────


def _degraded_candidate(w: _World, addr: str) -> None:
    pid = w.atlas.execute("SELECT pattern_id FROM pattern").fetchone()[0]
    w.atlas.execute(
        "INSERT INTO instance (pattern_id, evidence_ref, source_run_id, binary_content_hash, "
        "flow_evidence) VALUES (?, 'run_a#x:00001000@cmd', 'run_a', ?, ?)",
        (pid, _sha("a"), json.dumps({"callsite_addr": addr})),
    )


_DIGEST_CASES: list[tuple[str, str, bool]] = [
    (
        "a degraded candidate's recovered call site moved",
        'UPDATE instance SET flow_evidence = \'{"callsite_addr": "00001024"}\' '
        "WHERE evidence_ref = 'run_a#x:00001000@cmd'",
        True,
    ),
    (
        "an edge's function address",
        "UPDATE string_keyed_edge SET from_func_addr = '00003000'",
        True,
    ),
    ("an edge's callee", "UPDATE string_keyed_edge SET callee_name = 'other'", True),
    (
        "a capability row added",
        "INSERT INTO run_capability (run_id, capability, present) "
        "VALUES ('run_a', 'reachability.exec_argv_edge', 1)",
        True,
    ),
    ("a capability row removed", "DELETE FROM run_capability WHERE run_id = 'run_a'", True),
    ("a capability flipped absent", "UPDATE run_capability SET present = 0", True),
    ("the run's tool version", "UPDATE run SET tool_version = '0.0.2'", True),
    ("a candidate's reachability", "UPDATE instance SET reachability_status = 'blocked'", False),
    ("an edge column the diff never reads", "UPDATE string_keyed_edge SET ladder_size = 9", False),
    (
        "an edge of another binary",
        "INSERT INTO string_keyed_edge (source_run_id, binary, key, callee_name) "
        "VALUES ('run_a', 'libother', 'mode', 'handler')",
        False,
    ),
    (
        "a candidate in a binary of other content",
        "INSERT INTO instance (pattern_id, evidence_ref, source_run_id, binary_content_hash) "
        "VALUES (1, 'run_a#x:00005000@cmd@0x000010', 'run_a', 'ffff')",
        False,
    ),
    ("the other run's candidate", "DELETE FROM instance WHERE source_run_id = 'run_b'", False),
]


@pytest.mark.parametrize(
    ("what", "sql", "changes"), _DIGEST_CASES, ids=[c[0] for c in _DIGEST_CASES]
)
def test_the_hunt_digest_covers_exactly_what_the_diff_reads(
    tmp_path: Path, what: str, sql: str, changes: bool
) -> None:
    """MUTATION (verified RED, one case each): drop the run_capability part of
    ``hunt_inputs_digest`` -> the three capability cases stay equal; select every edge column
    instead of ``_EDGE_COLS`` -> the ladder_size case changes."""
    w = _two(tmp_path)
    _degraded_candidate(w, "00001020")

    def digest() -> str:
        return currency.hunt_inputs_digest(w.atlas, "run_a", _sha("a"), "liba")

    before = digest()
    assert before == digest()  # deterministic
    w.atlas.execute(sql)
    assert (digest() != before) is changes, what


# ── the diff code version, and content stays its own axis ────────────────────────────────────────


def test_a_diff_from_other_diff_code_is_rediffed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    w = _two(tmp_path)
    _stub(monkeypatch, w)
    _full(w)
    w.atlas.execute("UPDATE diff_meta SET diff_code_version = '0-000000000000'")
    w.atlas.commit()
    assert _plan(w).to_diff == ("liba",)
    assert _plan(w, assume_current=True).already_ok == ("liba",)


def test_content_change_rediffs_even_when_assuming_current(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    w = _two(tmp_path)
    _stub(monkeypatch, w)
    _full(w)
    w.atlas.execute("UPDATE diff_meta SET sha256_b = ?", (_sha("e"),))
    w.atlas.commit()
    assert _plan(w, assume_current=True).to_diff == ("liba",)


def test_the_stamps_are_read_inside_the_write_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The stamps and the hunt output the diff consumes are read under one write lock, so a hunt
    cannot commit between them.

    MUTATION (verified RED): drop the BEGIN IMMEDIATE from ``_persist_success`` -> the stamps are
    read outside any transaction."""
    w = _two(tmp_path)
    _stub(monkeypatch, w)
    seen: list[bool] = []
    real = driver._current_stamps

    def spy(atlas: sqlite3.Connection, *a: Any) -> currency.DiffStamps:
        seen.append(atlas.in_transaction)
        return real(atlas, *a)

    monkeypatch.setattr(driver, "_current_stamps", spy)
    _full(w)
    assert seen == [True]


# ── the attempt count continues only at the same content AND inputs ──────────────────────────────


def test_attempts_continue_only_at_the_same_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MUTATION (verified RED): ignore the stamps in ``layer0._next_attempts`` -> the count keeps
    climbing (3) after the hunt output changed."""
    w = _two(tmp_path)
    w.fail.add("liba")
    _stub(monkeypatch, w)
    _full(w)
    _full(w)
    assert _row(w)["diff_attempts"] == 2
    w.atlas.execute(
        "UPDATE string_keyed_edge SET callee_name = 'other' WHERE source_run_id='run_b'"
    )
    _rehunt(w, "run_b")
    assert _plan(w).to_diff == ("liba",)
    _full(w)
    assert _row(w)["diff_attempts"] == 1


def test_a_successful_rediff_after_an_input_change_restarts_the_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    w = _two(tmp_path)
    _stub(monkeypatch, w)
    for expect in (1, 2):  # the same diff again continues the count
        driver.run_version_diff(w.atlas, "run_a", "run_b", "liba", config=Config())
        assert _row(w)["diff_attempts"] == expect
    _set_binary(w, "a", "liba", "pass_version", "pv2")
    driver.run_version_diff(w.atlas, "run_a", "run_b", "liba", config=Config())
    assert _row(w)["diff_attempts"] == 1


def test_a_capped_failure_from_before_the_stamps_is_retried_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed row at the cap written before the stamps existed has them NULL: it is retried once,
    then counts again from 1 against the stamped attempt."""
    w = _two(tmp_path)
    w.fail.add("liba")
    _stub(monkeypatch, w)
    add_diff_meta(
        w.atlas,
        DiffMetaRow(
            diff_id=_did(),
            run_a_id="run_a",
            run_b_id="run_b",
            binary_a="liba",
            binary_b="liba",
            diff_ok=0,
            diff_status="failed",
            diff_attempts=3,
            sha256_a=_sha("a"),
            sha256_b=_sha("b"),
        ),
    )
    assert _plan(w).to_diff == ("liba",)
    _full(w)
    assert _row(w)["diff_attempts"] == 1
    assert _plan(w).retry == ("liba",)
    _full(w)
    assert _row(w)["diff_attempts"] == 2


# ── every diff read surface says whether the diff is still current ───────────────────────────────


def _surfaces(w: _World) -> dict[str, tuple[Any, Any]]:
    """(source_stale, source_stale_reason) of liba's diff on every read surface."""
    from treasure_map.mcp_app import make_tools

    did = _did()
    out: dict[str, tuple[Any, Any]] = {}

    def take(name: str, d: dict[str, Any]) -> None:
        out[name] = (d["source_stale"], d["source_stale_reason"])

    take("list_diffs", diff_align.list_diffs(w.atlas)["diffs"][0])
    take("get_diff_deltas", diff_align.get_diff_deltas(w.atlas, did))
    take("get_diff_meta", diff_align.get_diff_meta(w.atlas, did))
    take("get_function_alignment", diff_align.align_by_a(w.atlas, did, "0x1000"))
    take("get_diff_capabilities", diff_align.get_diff_capabilities(w.atlas, did))
    tools = make_tools(w.tmp / "atlas.db")
    take("get_diff_sink_overlay", tools["get_diff_sink_overlay"](diff_id=did))
    take("get_diff_patch_view", tools["get_diff_patch_view"](did))
    pair = tools["get_diff_sink_overlay"](run_a="run_a", run_b="run_b", detail="rows")
    rows = [r for r in pair["rows"] if r["diff_id"] == did]
    assert rows
    for r in rows:
        take("get_diff_sink_overlay rows", r)
    return out


def test_every_diff_read_surface_carries_source_stale(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MUTATION (verified RED): drop the staleness from ``get_diff_capabilities`` -> KeyError on
    that surface (each surface's attachment is a separate line; this one stands for them)."""
    w = _two(tmp_path)
    _stub(monkeypatch, w)
    _full(w)
    w.atlas.commit()
    surfaces = _surfaces(w)
    assert len(surfaces) == 8
    assert set(surfaces.values()) == {(False, None)}
    _set_binary(w, "b", "liba", "pass_version", "pv2")
    assert set(_surfaces(w).values()) == {(True, "extraction_changed")}


def test_a_failed_diff_in_the_blind_spot_list_carries_it_too(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    w = _two(tmp_path)
    w.fail.add("liba")
    _stub(monkeypatch, w)
    _full(w)
    (spot,) = diff_align.list_diff_blindspots(w.atlas)["blindspots"]
    assert (spot["source_stale"], spot["source_stale_reason"]) == (False, None)
    w.atlas.execute("UPDATE diff_meta SET diff_code_version = '0-000000000000'")
    (spot,) = diff_align.list_diff_blindspots(w.atlas)["blindspots"]
    assert (spot["source_stale"], spot["source_stale_reason"]) == (True, "diff_logic_changed")


def _sha_gone(w: _World) -> None:
    _set_binary(w, "b", "liba", "sha256", _sha("e"))


def _code(w: _World) -> None:
    w.atlas.execute("UPDATE diff_meta SET diff_code_version = '0-000000000000'")


def _extraction(w: _World) -> None:
    _set_binary(w, "a", "liba", "pass_version", "pv2")


def _ghidra(w: _World) -> None:
    _set_binary(w, "a", "liba", "ghidra_version", "12.0")


def _hunt_output(w: _World) -> None:
    w.atlas.execute(
        "UPDATE string_keyed_edge SET callee_name = 'other' WHERE source_run_id='run_a'"
    )
    _rehunt(w, "run_a")


def _unstamped(w: _World) -> None:
    w.atlas.execute("UPDATE diff_meta SET diff_code_version = NULL")


def _unreadable(w: _World) -> None:
    (w.tmp / "a.db").rename(w.tmp / "a.db.moved")


class _TwoNameCache:
    """Each run holds its side's binary under its own name; every other axis matches."""

    def for_run(self, run_id: str | None) -> dict[str, set[str]] | None:
        return {"run_a": {"liba": {_sha("a")}}, "run_b": {"libb": {_sha("b")}}}.get(run_id or "")

    def extraction(self, run_id: str) -> dict[str, tuple[str | None, str | None]]:
        return {_sha("a" if run_id == "run_a" else "b"): (_PV, "11.4.3")}

    def hunt_marks(self, run_id: str) -> tuple[str | None, int | None, int]:
        return ("t0", 1, 1)


def test_each_side_is_looked_up_by_its_own_binary_name() -> None:
    """MUTATION (verified RED): look side b up by ``binary_a`` -> its binary reads as gone."""
    meta = {
        "run_a_id": "run_a",
        "run_b_id": "run_b",
        "binary_a": "liba",
        "binary_b": "libb",
        "sha256_a": _sha("a"),
        "sha256_b": _sha("b"),
        "diff_code_version": code_version.diff_code_version(),
        "export_builder_a": None,
        "export_builder_b": None,
        "export_code_hash_a": code_version.export_code_hash(None),
        "export_code_hash_b": code_version.export_code_hash(None),
        "toolchain_ghidra": None,
        "toolchain_binexport": None,
        "toolchain_bindiff": None,
        **{
            f"{c}_{s}": v
            for s in "ab"
            for c, v in (
                ("extraction_pass", _PV),
                ("ghidra_version", "11.4.3"),
                ("scanned_at", "t0"),
                ("hunt_instances", 1),
                ("hunt_inputs_hash", "x"),
            )
        },
    }
    assert diff_align.diff_staleness(_TwoNameCache(), meta) == (False, None)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("changes", "expect"),
    [
        ((_sha_gone, _code, _extraction), (True, "source_content_changed")),
        ((_code, _extraction, _hunt_output), (True, "diff_logic_changed")),
        ((_extraction, _ghidra, _hunt_output), (True, "extraction_changed")),
        ((_ghidra, _hunt_output), (True, "ghidra_changed")),
        ((_hunt_output,), (True, "hunt_inputs_changed")),
        ((_unstamped,), (None, "generation_unstamped")),
        ((_unreadable,), (None, "source_unavailable")),
        ((_unreadable, _hunt_output), (True, "hunt_inputs_changed")),
        ((_unreadable, _code), (True, "diff_logic_changed")),
    ],
)
def test_the_highest_ranked_reason_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changes: tuple[Any, ...], expect: Any
) -> None:
    """MUTATION (verified RED): swap extraction_changed and ghidra_changed in ``_REASON_RANK`` ->
    the third case reports ghidra_changed."""
    w = _two(tmp_path)
    _stub(monkeypatch, w)
    _full(w)
    for change in changes:
        change(w)
    w.atlas.commit()
    got = diff_align.list_diffs(w.atlas)["diffs"][0]
    assert (got["source_stale"], got["source_stale_reason"]) == expect


def test_a_rehunt_that_reproduces_the_output_leaves_the_diff_current(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    w = _two(tmp_path)
    _stub(monkeypatch, w)
    _full(w)
    _rehunt(w, "run_a")
    _rehunt(w, "run_b")
    assert diff_align.list_diffs(w.atlas)["diffs"][0]["source_stale"] is False
    assert _plan(w).already_ok == ("liba",)


def test_the_fast_path_skips_the_digest_only_while_its_guards_hold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MUTATION (verified RED): drop the live-row comparison from ``_hunt_inputs_changed`` -> a
    candidate deleted outside a hunt keeps the fast path and the diff reads current."""
    w = _two(tmp_path)
    _stub(monkeypatch, w)
    _full(w)
    calls: list[str] = []
    real = diff_align.hunt_inputs_digest

    def counting(*a: Any) -> str:
        calls.append(a[1])
        return real(*a)

    monkeypatch.setattr(diff_align, "hunt_inputs_digest", counting)
    assert diff_align.list_diffs(w.atlas)["diffs"][0]["source_stale"] is False
    assert calls == []  # nothing moved: no digest recomputed
    _rehunt(w, "run_a")
    assert diff_align.list_diffs(w.atlas)["diffs"][0]["source_stale"] is False
    assert calls == ["run_a"]  # the hunt ran: recomputed, and it reproduced the same output
    calls.clear()
    w.atlas.execute("DELETE FROM instance WHERE source_run_id = 'run_b'")  # outside a hunt
    got = diff_align.list_diffs(w.atlas)["diffs"][0]
    assert "run_b" in calls
    assert (got["source_stale"], got["source_stale_reason"]) == (True, "hunt_inputs_changed")


def test_assume_current_keeps_the_diff_and_the_reader_still_flags_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    w = _two(tmp_path)
    _stub(monkeypatch, w)
    _full(w)
    _extraction(w)
    fs = _full(w, assume_current=True)
    assert fs.plan.already_ok == ("liba",) and fs.outcomes == ()
    got = diff_align.list_diffs(w.atlas)["diffs"][0]
    assert (got["source_stale"], got["source_stale_reason"]) == (True, "extraction_changed")


def _compared(w: _World) -> dict[str, Any]:
    row = _row(w)
    return {c: row[c] for c in currency.COMPARED_COLUMNS}


def _marks(w: _World) -> tuple[Any, ...]:
    row = _row(w)
    return tuple(row[f"{c}_{s}"] for c in ("scanned_at", "hunt_instances") for s in "ab")


def _counting_digest(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []
    real = diff_align.hunt_inputs_digest

    def counting(*a: Any) -> str:
        calls.append(a[1])
        return real(*a)

    monkeypatch.setattr(diff_align, "hunt_inputs_digest", counting)
    return calls


def test_a_diff_left_as_it_is_takes_the_runs_new_hunt_marks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ A re-scan rewrites run.scanned_at even when the hunt reproduces its output. The full diff
    leaves the diff as it is (already ok) and brings its recorded hunt marks up to the runs' new
    ones, so a later read takes the fast path instead of recomputing both digests every time — and
    nothing the re-diff decision compares is written.

    MUTATION (verified RED): skip the restamp in run_full_diff -> nothing is restamped and
    list_diffs would recompute the digest -> RED."""
    w = _two(tmp_path)
    _stub(monkeypatch, w)
    _full(w)
    compared = _compared(w)
    _rehunt(w, "run_a")
    _rehunt(w, "run_b")
    fs = _full(w)
    assert fs.outcomes == () and fs.plan.already_ok == ("liba",)
    assert (fs.hunt_marks_restamped, fs.hunt_marks_left) == (("liba",), ())
    now = w.atlas.execute("SELECT run_id, scanned_at, hunt_instances FROM run").fetchall()
    marks = {r[0]: (r[1], r[2]) for r in now}
    assert _marks(w) == (*(marks[r][0] for r in ("run_a", "run_b")), 1, 1)
    assert _compared(w) == compared
    calls = _counting_digest(monkeypatch)
    got = diff_align.list_diffs(w.atlas)["diffs"][0]
    assert calls == []
    assert (got["source_stale"], got["source_stale_reason"]) == (False, None)
    assert _full(w).hunt_marks_restamped == ()  # marks already current: nothing to rewrite


def test_a_side_whose_hunt_output_moved_keeps_its_marks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A moved digest is not restamped: the full diff re-runs that diff (it is not already ok), and
    restamping it directly leaves the side as it was, so a reader still recomputes the digest and
    reads it stale. Nothing compared is written.

    MUTATION (verified RED): drop the guards (restamp unconditionally) -> the side is restamped,
    its marks move and a reader would take the fast path to source_stale false; write the side's
    hunt_inputs_hash before the guards -> the compared columns move."""
    w = _two(tmp_path)
    _stub(monkeypatch, w)
    _full(w)
    _hunt_output(w)
    plan = _plan(w)
    assert (plan.to_diff, plan.already_ok) == (("liba",), ())
    compared, marks = _compared(w), _marks(w)
    assert driver._restamp_hunt_marks(w.atlas, "run_a", "run_b", ("liba",)) == ((), ("liba",))
    assert _marks(w) == marks
    assert _compared(w) == compared
    got = diff_align.list_diffs(w.atlas)["diffs"][0]
    assert (got["source_stale"], got["source_stale_reason"]) == (True, "hunt_inputs_changed")


def test_assume_current_leaves_the_hunt_marks_as_they_were(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With assume_current the plan did not compare the inputs, so the marks are not touched.

    MUTATION (verified RED): restamp regardless of assume_current -> the marks move."""
    w = _two(tmp_path)
    _stub(monkeypatch, w)
    _full(w)
    marks = _marks(w)
    _rehunt(w, "run_a")
    fs = _full(w, assume_current=True)
    assert (fs.hunt_marks_restamped, fs.hunt_marks_left) == ((), ())
    assert _marks(w) == marks


def test_a_run_pair_overlay_marks_each_row_by_its_own_diff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MUTATION (verified RED): mark every run-pair row with the first diff's staleness -> libb's
    rows read stale."""
    from treasure_map.mcp_app import make_tools

    w = _world(
        tmp_path,
        {"liba": (_sha("a"), _PV), "libb": (_sha("c"), _PV)},
        {"liba": (_sha("b"), _PV), "libb": (_sha("d"), _PV)},
    )
    _stub(monkeypatch, w)
    _full(w)
    _set_binary(w, "a", "liba", "pass_version", "pv2")
    tools = make_tools(w.tmp / "atlas.db")
    pair = tools["get_diff_sink_overlay"](run_a="run_a", run_b="run_b", detail="rows")
    by_diff = {r["diff_id"]: (r["source_stale"], r["source_stale_reason"]) for r in pair["rows"]}
    assert by_diff == {
        _did("liba"): (True, "extraction_changed"),
        _did("libb"): (False, None),
    }
    summary = tools["get_diff_sink_overlay"](run_a="run_a", run_b="run_b")
    assert summary["diff_staleness"] == {
        "diffs": 2,
        "stale": 1,
        "unverified": 0,
        "current": 1,
        "by_reason": {"extraction_changed": 1},
    }


# ── the run pair is refused only on a proven mismatch ────────────────────────────────────────────


def _out_of_date_extraction(w: _World) -> dict[str, str]:
    w.atlas.execute("UPDATE run SET build_hash = 'pv0' WHERE run_id = 'run_b'")
    return {}


def _other_hunt_commit(w: _World) -> dict[str, str]:
    w.atlas.execute("UPDATE run SET hunt_commit = 'deadbeef' WHERE run_id = 'run_b'")
    return {}


def _reextracted_after_the_hunt(w: _World) -> dict[str, str]:
    w.atlas.execute("UPDATE run SET build_hash = ? WHERE run_id = 'run_b'", (_PV,))
    _set_binary(w, "b", "liba", "pass_version", "pv2")
    return {}


@pytest.mark.parametrize(
    "make_stale", [_out_of_date_extraction, _other_hunt_commit, _reextracted_after_the_hunt]
)
@pytest.mark.parametrize("single", [False, True])
def test_a_provably_out_of_date_run_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, make_stale: Any, single: bool
) -> None:
    """Refused by both entry points, and assume_current does not lift it.

    MUTATION (verified RED): drop the analysis.db comparison from ``check_run_pair_currency`` ->
    the re-extracted-after-the-hunt case diffs."""
    w = _two(tmp_path)
    make_stale(w)
    w.atlas.commit()
    _stub(monkeypatch, w)
    with pytest.raises(ConfigError, match="run_b"):
        if single:
            driver.run_version_diff(w.atlas, "run_a", "run_b", "liba", config=Config())
        else:
            _full(w, assume_current=True)
    assert w.atlas.execute("SELECT COUNT(*) FROM diff_meta").fetchone()[0] == 0


@pytest.mark.parametrize(
    ("setup", "commit"),
    [
        ("UPDATE run SET build_hash = 'mixed:2'", _COMMIT),
        ("UPDATE run SET hunt_commit = 'unknown'", _COMMIT),
        ("UPDATE run SET hunt_commit = 'facefeed', build_hash = 'pv1'", UNKNOWN_VERSION),
    ],
)
def test_what_cannot_be_confirmed_only_warns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, setup: str, commit: str
) -> None:
    w = _two(tmp_path)
    w.atlas.execute(setup)
    w.atlas.commit()
    _stub(monkeypatch, w, commit=commit)
    fs = _full(w)
    assert [o.error for o in fs.outcomes] == [None]
    assert fs.warnings


def test_a_confirmed_current_pair_diffs_without_warnings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    w = _two(tmp_path, hunt_commit=_COMMIT)
    w.atlas.execute("UPDATE run SET build_hash = ?", (_PV,))
    w.atlas.commit()
    _stub(monkeypatch, w)
    fs = _full(w)
    assert [o.error for o in fs.outcomes] == [None] and fs.warnings == ()


def _rehunted_by_other_code(w: _World, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub(monkeypatch, w, commit="deadbeef")


def _skewed(w: _World, monkeypatch: pytest.MonkeyPatch) -> None:
    w.atlas.execute("UPDATE run SET ghidra_version = '12.0' WHERE run_id = 'run_b'")
    w.atlas.commit()


@pytest.mark.parametrize(
    ("make_refused", "why"),
    [(_rehunted_by_other_code, "out of date"), (_skewed, "different tmap/Ghidra versions")],
)
def test_a_pair_with_nothing_left_to_diff_is_refused_all_the_same(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, make_refused: Any, why: str
) -> None:
    """Every binary already diffed: the pair is still refused, as the read side refuses it, rather
    than answered with "nothing to diff".

    MUTATION (verified RED): check the pair after the plan's early return -> the full diff returns
    an empty sweep."""
    w = _two(tmp_path, hunt_commit=_COMMIT)
    _stub(monkeypatch, w)
    _full(w)
    assert _plan(w).already_ok == ("liba",)
    make_refused(w, monkeypatch)
    with pytest.raises(ConfigError, match=why):
        _full(w)


def test_a_pair_with_nothing_left_to_diff_still_reports_its_warnings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    w = _two(tmp_path, hunt_commit=_COMMIT)
    _stub(monkeypatch, w)
    _full(w)
    _stub(monkeypatch, w, commit=UNKNOWN_VERSION)
    fs = _full(w)
    assert fs.outcomes == () and fs.warnings


# ── a stored candidate baseline survives a re-diff, or its loss is visible ────────────────────────


def _baselined(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> _World:
    """liba diffed, with its candidate baseline stored (needs both runs' hunt commit known)."""
    w = _two(tmp_path, hunt_commit=_COMMIT)
    _stub(monkeypatch, w)
    _full(w)
    assert so.persist_sink_overlay(w.atlas, _did()) > 0
    return w


def _baseline_rows(w: _World) -> int:
    return int(
        w.atlas.execute(
            "SELECT COUNT(*) FROM dimension_delta WHERE diff_id = ? AND subject_kind = 'candidate' "
            "AND overlay_version = ?",
            (_did(), so.sink_overlay_logic_version()),
        ).fetchone()[0]
    )


def test_a_rediff_stores_the_baseline_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MUTATION (verified RED): skip the re-store in ``_persist_success`` -> no baseline rows after
    the re-diff (the re-diff's delete_diff took them)."""
    w = _baselined(tmp_path, monkeypatch)
    n = _baseline_rows(w)
    _extraction(w)
    (oc,) = _full(w).outcomes
    assert oc.summary is not None and oc.summary.baseline == "restored"
    assert _baseline_rows(w) == n
    assert so.read_sink_overlay_baseline(w.atlas, _did())["stale_baseline"] is False


def test_a_refused_baseline_does_not_fail_the_diff_and_is_marked_until_stored_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The good row the re-diff committed says its baseline is gone (an ok row, so it shows in
    list_diffs, not among the blind spots); once the store is possible again, the next re-diff
    stores it and clears the mark.

    MUTATION (verified RED): drop the mark after the refused store -> the row reads as a diff
    that never had a baseline, and the next re-diff does not store one."""
    w = _baselined(tmp_path, monkeypatch)
    n = _baseline_rows(w)
    w.atlas.execute("UPDATE run SET hunt_commit = 'unknown' WHERE run_id = 'run_b'")
    _extraction(w)
    (oc,) = _full(w).outcomes
    assert oc.error is None and oc.summary is not None
    assert oc.summary.baseline == "not_restored"
    assert any("candidate baseline" in m for m in oc.summary.warnings)
    assert _row(w)["diff_ok"] == 1 and _baseline_rows(w) == 0
    assert _row(w)["baseline_dropped"] == 1
    (listed,) = diff_align.list_diffs(w.atlas)["diffs"]
    assert listed["baseline_dropped"] == 1
    assert diff_align.list_diff_blindspots(w.atlas)["blindspots"] == []
    w.atlas.execute("UPDATE run SET hunt_commit = ? WHERE run_id = 'run_b'", (_COMMIT,))
    w.atlas.commit()
    _ghidra(w)
    (oc,) = _full(w).outcomes
    assert oc.summary is not None and oc.summary.baseline == "restored"
    assert _row(w)["baseline_dropped"] == 0 and _baseline_rows(w) == n
    (listed,) = diff_align.list_diffs(w.atlas)["diffs"]
    assert listed["baseline_dropped"] == 0


def test_storing_the_baseline_directly_clears_the_mark(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MUTATION (verified RED): leave the mark alone in ``persist_sink_overlay`` -> a diff with a
    stored baseline still says it lost it."""
    w = _baselined(tmp_path, monkeypatch)
    w.atlas.execute("UPDATE run SET hunt_commit = 'unknown' WHERE run_id = 'run_b'")
    _extraction(w)
    _full(w)
    assert _row(w)["baseline_dropped"] == 1
    w.atlas.execute("UPDATE run SET hunt_commit = ? WHERE run_id = 'run_b'", (_COMMIT,))
    w.atlas.commit()
    assert so.persist_sink_overlay(w.atlas, _did()) > 0
    assert _row(w)["baseline_dropped"] == 0


def _baseline_rows_without_stamps(w: _World) -> list[tuple[Any, ...]]:
    """The stored candidate rows, less their ids and the run stamps a re-store rewrites."""
    rows = w.atlas.execute(
        "SELECT * FROM dimension_delta WHERE diff_id = ? AND subject_kind = 'candidate'", (_did(),)
    )
    cols = [d[0] for d in rows.description]
    stamps = {"id", "hunt_commit_a", "hunt_commit_b", "build_hash_a", "build_hash_b"}
    stamps |= {"hunt_instances_a", "hunt_instances_b"}
    keep = [i for i, c in enumerate(cols) if c not in stamps]
    return sorted(tuple(r[i] for i in keep) for r in rows)


def _rehunted_unchanged(w: _World, monkeypatch: pytest.MonkeyPatch, commit: str) -> None:
    """A re-hunt by another installed build that wrote the same output: only the commit moves."""
    w.atlas.execute("UPDATE run SET hunt_commit = ?", (commit,))
    w.atlas.commit()
    _stub(monkeypatch, w, commit=commit)


def test_an_unchanged_rehunt_refreshes_the_baseline_of_a_diff_left_as_it_is(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The diff is current (its inputs did not move) and is not re-run; its baseline, stamped with
    the old commit, reads stale. The full diff stores it again, though nothing is left to diff.

    MUTATION (verified RED): refresh after the "nothing to diff" return -> the baseline stays
    stale; skip the refresh -> the same."""
    w = _baselined(tmp_path, monkeypatch)
    before = _baseline_rows_without_stamps(w)
    _rehunted_unchanged(w, monkeypatch, "beadfeed")
    assert so.read_sink_overlay_baseline(w.atlas, _did())["stale_baseline"] is True
    fs = _full(w)
    assert fs.outcomes == () and fs.plan.already_ok == ("liba",)
    assert (fs.baselines_refreshed, fs.baselines_refresh_refused) == (("liba",), ())
    assert so.read_sink_overlay_baseline(w.atlas, _did())["stale_baseline"] is False
    assert _baseline_rows_without_stamps(w) == before


def test_assume_current_leaves_a_stale_baseline_stale(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With assume_current the plan did not compare the inputs, so an already-ok diff may not be
    current: stamping its baseline fresh would vouch for a diff nobody checked.

    MUTATION (verified RED): refresh regardless of assume_current -> the baseline reads fresh."""
    w = _baselined(tmp_path, monkeypatch)
    _rehunted_unchanged(w, monkeypatch, "beadfeed")
    fs = _full(w, assume_current=True)
    assert fs.baselines_refreshed == ()
    assert so.read_sink_overlay_baseline(w.atlas, _did())["stale_baseline"] is True


def test_a_refused_refresh_keeps_the_old_rows_and_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MUTATION (verified RED): drop the rows before the store is attempted -> the refused refresh
    leaves the diff with no baseline at all."""
    w = _baselined(tmp_path, monkeypatch)
    n = _baseline_rows(w)
    _rehunted_unchanged(w, monkeypatch, UNKNOWN_VERSION)
    fs = _full(w)
    assert (fs.baselines_refreshed, fs.baselines_refresh_refused) == ((), ("liba",))
    assert any("baseline" in m and "liba" in m for m in fs.warnings)
    assert _baseline_rows(w) == n
    assert so.read_sink_overlay_baseline(w.atlas, _did())["stale_baseline"] is True


def test_a_dropped_baseline_of_an_unchanged_diff_is_stored_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A re-diff that could not store the baseline marked it dropped; once storing is possible the
    next full diff stores it, although the diff itself is not re-run.

    MUTATION (verified RED): refresh only stale baselines -> the dropped one is never stored."""
    w = _baselined(tmp_path, monkeypatch)
    w.atlas.execute("UPDATE run SET hunt_commit = 'unknown' WHERE run_id = 'run_b'")
    _extraction(w)
    _full(w)
    assert _row(w)["baseline_dropped"] == 1 and _baseline_rows(w) == 0
    w.atlas.execute("UPDATE run SET hunt_commit = ? WHERE run_id = 'run_b'", (_COMMIT,))
    w.atlas.commit()
    fs = _full(w)
    assert fs.outcomes == () and fs.baselines_refreshed == ("liba",)
    assert _row(w)["baseline_dropped"] == 0 and _baseline_rows(w) > 0


def test_reading_an_absent_baseline_says_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MUTATION (verified RED): return the old ``stale_baseline: False`` shape for no rows -> the
    absent baseline reads as a current one."""
    w = _two(tmp_path)
    _stub(monkeypatch, w)
    _full(w)
    got = so.read_sink_overlay_baseline(w.atlas, _did())
    assert got["baseline_absent"] is True
    assert got["stale_baseline"] is None and got["rows"] is None


def test_a_failed_rediff_marks_the_dropped_baseline_until_a_success_restores_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MUTATION (verified RED): always write ``baseline_dropped=0`` in ``_record_diff_failure`` ->
    the blind spot does not say a baseline was lost; and drop the carry-forward of an earlier mark
    -> the second failure forgets it."""
    w = _baselined(tmp_path, monkeypatch)
    _extraction(w)
    w.fail.add("liba")
    _full(w)
    assert _row(w)["baseline_dropped"] == 1 and _baseline_rows(w) == 0
    (spot,) = diff_align.list_diff_blindspots(w.atlas)["blindspots"]
    assert spot["baseline_dropped"] == 1
    _full(w)  # fails again at the same content: still marked
    assert _row(w)["baseline_dropped"] == 1
    w.fail.clear()
    (oc,) = _full(w).outcomes
    assert oc.summary is not None and oc.summary.baseline == "restored"
    assert _row(w)["baseline_dropped"] == 0 and _baseline_rows(w) > 0


def test_a_failure_after_a_content_change_still_marks_the_dropped_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A successful re-diff of changed content stores the baseline again, so a failure in between
    must not decide whether it comes back: it is marked, and the next success stores it.

    MUTATION (verified RED): mark only at the same content -> the failure after the content change
    marks nothing and the baseline never comes back."""
    w = _baselined(tmp_path, monkeypatch)
    _set_binary(w, "b", "liba", "sha256", _sha("e"))
    so_b = next(p for p, s in w.so_sha.items() if s == _sha("b"))
    w.so_sha[so_b] = _sha("e")
    w.fail.add("liba")
    _full(w)
    assert _row(w)["baseline_dropped"] == 1 and _baseline_rows(w) == 0
    w.fail.clear()
    (oc,) = _full(w).outcomes
    assert oc.summary is not None and oc.summary.baseline == "restored"
    assert _row(w)["baseline_dropped"] == 0 and _baseline_rows(w) > 0


def test_an_interrupt_after_the_new_rows_commit_leaves_the_loss_marked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A re-diff commits its new rows, then stores the baseline again in a second transaction. An
    interrupt between the two must leave the row saying the baseline is gone (and the next re-diff
    stores it), which is why the mark is written in the SAME transaction as the new rows.

    MUTATION: drop the ``baseline_dropped = 1`` written with the new rows -> the committed row says
    0 while no baseline rows exist -> RED."""
    w = _baselined(tmp_path, monkeypatch)
    _extraction(w)

    def _interrupted(*_a: Any, **_kw: Any) -> int:
        raise KeyboardInterrupt

    monkeypatch.setattr(driver, "persist_sink_overlay", _interrupted)
    fs = _full(w)
    assert fs.cancelled is True
    assert _baseline_rows(w) == 0  # the re-diff's rows replaced the old ones, baseline not back
    assert _row(w)["baseline_dropped"] == 1


def test_a_sqlite_error_restoring_the_baseline_keeps_the_good_diff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The new rows are already committed when the baseline is stored again. A sqlite error there
    (a lock, say) is that step's failure only: the diff stays a success with its baseline marked
    dropped, not a failed row recomputed next time.

    MUTATION: catch only TreasureMapError around the baseline restore -> the sqlite error reaches
    the per-binary handler, which records the good diff as failed -> RED."""
    w = _baselined(tmp_path, monkeypatch)
    _extraction(w)

    def _locked(*_a: Any, **_kw: Any) -> int:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(driver, "persist_sink_overlay", _locked)
    (oc,) = _full(w).outcomes
    assert oc.summary is not None, f"the good diff was turned into a failure: {oc.error}"
    assert oc.summary.baseline == "not_restored"
    row = _row(w)
    assert (row["diff_ok"], row["baseline_dropped"]) == (1, 1)


# ── the CLI passes --assume-current through ──────────────────────────────────────────────────────


def test_the_cli_passes_assume_current_through(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from treasure_map.cli.main import main

    seen: dict[str, Any] = {}

    def fake_full(atlas: Any, a: str, b: str, **kw: Any) -> driver.FullDiffSummary:
        seen.update(kw)
        plan = driver.FullDiffPlan((), (), (), ())
        return driver.FullDiffSummary(plan, (), cancelled=False, warnings=("a note",))

    monkeypatch.setattr(driver, "run_full_diff", fake_full)
    _two(tmp_path)  # the command reads both run rows before it diffs
    res = CliRunner().invoke(
        main,
        ["diff", "--before", "run_a", "--after", "run_b", "--assume-current"]
        + ["--atlas", str(tmp_path / "atlas.db")],
    )
    assert res.exit_code == 0, res.output
    assert seen["assume_current"] is True
    assert "a note" in res.output


def _summary(binary: str, changed: int, unchanged: int, undetermined: int) -> driver.DiffSummary:
    return driver.DiffSummary(
        diff_id=_did(binary),
        binary=binary,
        matched_pairs=1,
        version_skew=False,
        delta_layer_changed=changed,
        delta_layer_unchanged=unchanged,
        delta_undetermined=undetermined,
        warnings=(),
    )


def test_the_cli_prints_each_binarys_function_split_and_the_pairs_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ Each diffed binary's line is its functions as the view's facts split them — no string-keyed
    edge counts, and 'no scoped signal' never written as noise; a diff that did not run prints
    BLIND SPOT, never zeros. The roll-up names what no diff of the pair covers, with the binaries
    byte-identical in both runs kept apart (a pointer to the scan map, never a blind spot).

    MUTATION: print the edge counts as before -> RED; print counts for the failed diff -> RED;
    drop the undetermined pairs' proposed readings from the line -> RED;
    treat identical binaries as not covered -> RED."""
    from treasure_map.cli.main import main
    from treasure_map.lib.query import diff_align, patch_view

    states = {
        _did("liba"): {
            "withheld": False,
            "aligned": 9,
            "unchanged": 5,
            "changed": {"total": 3, "with_scoped_sink_delta": 1, "no_scoped_signal": 2},
            "unverified": {
                "total": 1,
                "identical_text_unverified": 0,
                "identical_callee_unverified": 1,
                "unavailable": 0,
            },
            "identical_text_unverified_by_body": {"structure_differs": 0, "unknown": 0},
            "no_body": 0,
            "alignment_undetermined": 2,
            "alignment_undetermined_reading": {
                "identical_unique": 1,
                "identical_not_unique": 0,
                "identical_callee_unverified": 0,
                "identical_text_unverified": 0,
                "differs": 1,
                "no_body": 0,
                "unavailable": 0,
            },
            "one_sided": {"b": {"unmatched_analysis_complete": 4}},
        },
        _did("libb"): {"withheld": True, "banners": ["diff_undetermined:diff_failed"]},
    }
    monkeypatch.setattr(patch_view, "function_states", lambda atlas, did: states.get(did))
    coverage = {
        "failed_diffs": [],
        "not_diffed_binaries": {},
        "identical_binaries": {"b": {"binaries": 7, "candidates": 30}},
        "all_candidate_binaries_covered": True,
    }
    monkeypatch.setattr(diff_align, "list_diffs", lambda *a, **k: {"coverage": coverage})

    def fake_full(atlas: Any, a: str, b: str, **kw: Any) -> driver.FullDiffSummary:
        oks = (
            driver.BinaryDiffOutcome("liba", _summary("liba", 2, 1, 0), None),
            driver.BinaryDiffOutcome("libb", _summary("libb", 0, 0, 0), None),
        )
        for i, o in enumerate(oks, start=1):
            kw["on_outcome"](i, len(oks), o)
        plan = driver.FullDiffPlan(("liba", "libb", "libc"), (), (), (), to_diff=("liba", "libb"))
        return driver.FullDiffSummary(plan, oks, cancelled=False, baselines_refreshed=("libc",))

    monkeypatch.setattr(driver, "run_full_diff", fake_full)
    _two(tmp_path)  # the command reads both run rows before it diffs
    res = CliRunner().invoke(
        main,
        ["diff", "--before", "run_a", "--after", "run_b", "--atlas", str(tmp_path / "atlas.db")],
    )
    assert res.exit_code == 0, res.output
    assert (
        "liba: 9 aligned: 5 unchanged, 3 changed (1 with a scoped sink delta, 2 no scoped "
        "signal), 1 unverified, 0 no body; 2 alignment undetermined (read: 1 identical_unique, "
        "1 differs); no counterpart — B 4 unmatched_analysis_complete" in res.output
    )
    assert "libb: BLIND SPOT (did not diff)" in res.output
    assert "edges changed" not in res.output and "noise" not in res.output
    assert "7 candidate-holding binaries are byte-identical in both runs" in res.output
    assert "tmap triage run_b" in res.output
    assert "every candidate-holding binary is diffed or byte-identical" in res.output
    assert "baselines refreshed (unchanged diffs): 1, 0 refused" in res.output


_STATES = {
    "withheld": False,
    "aligned": 9,
    "unchanged": 5,
    "changed": {"total": 3, "with_scoped_sink_delta": 1, "no_scoped_signal": 2},
    "unverified": {
        "total": 1,
        "identical_text_unverified": 0,
        "identical_callee_unverified": 1,
        "unavailable": 0,
    },
    "identical_text_unverified_by_body": {"structure_differs": 0, "unknown": 0},
    "no_body": 0,
    "alignment_undetermined": 2,
    "alignment_undetermined_reading": {
        "identical_unique": 2,
        "identical_not_unique": 0,
        "identical_callee_unverified": 0,
        "identical_text_unverified": 0,
        "differs": 0,
        "no_body": 0,
        "unavailable": 0,
    },
    "one_sided": {},
}


def _cli_full_diff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    states: Any,
    coverage: dict[str, Any] | None,
    **summary: Any,
) -> Any:
    """``tmap diff`` over two binaries, liba and libb, both diffed ok; ``states`` stands in for
    function_states and ``coverage`` for the run pair's coverage."""
    from treasure_map.cli.main import main
    from treasure_map.lib.query import patch_view

    monkeypatch.setattr(patch_view, "function_states", states)
    monkeypatch.setattr(diff_align, "list_diffs", lambda *a, **k: {"coverage": coverage})

    def fake_full(atlas: Any, a: str, b: str, **kw: Any) -> driver.FullDiffSummary:
        oks = (
            driver.BinaryDiffOutcome("liba", _summary("liba", 0, 0, 0), None),
            driver.BinaryDiffOutcome("libb", _summary("libb", 0, 0, 0), None),
        )
        for i, o in enumerate(oks, start=1):
            kw["on_outcome"](i, len(oks), o)
        plan = driver.FullDiffPlan(("liba", "libb"), (), (), (), to_diff=("liba", "libb"))
        return driver.FullDiffSummary(plan, oks, cancelled=False, **summary)

    monkeypatch.setattr(driver, "run_full_diff", fake_full)
    _two(tmp_path)  # the command reads both run rows before it diffs
    return CliRunner().invoke(
        main,
        ["diff", "--before", "run_a", "--after", "run_b", "--atlas", str(tmp_path / "atlas.db")],
    )


def test_a_function_split_that_cannot_be_read_does_not_stop_the_diff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ Each binary's line is printed from inside the diff's loop. Reading one binary's function
    split failing is said on that line — its diff is stored — and the diff goes on to the next
    binary; it never ends the run. The hunt-mark line reports the diffs left as they are.

    MUTATION: call function_states without the guard -> liba's error ends the command -> RED."""

    def states(atlas: Any, did: str) -> dict[str, Any]:
        if did == _did("liba"):
            raise RuntimeError("view could not be built")
        return _STATES

    res = _cli_full_diff(
        tmp_path,
        monkeypatch,
        states,
        None,
        hunt_marks_restamped=("libc",),
        hunt_marks_left=("libd", "libe"),
    )
    assert res.exit_code == 0, res.output
    assert (
        "[1/2] liba: functions unreadable (RuntimeError: view could not be built) — the diff "
        "itself is stored; see get_diff_meta" in res.output
    )
    assert "[2/2] libb: 9 aligned: 5 unchanged" in res.output
    assert "diffed        : 2 ok" in res.output
    assert "hunt marks    : 1 refreshed, 2 left (digest moved or run changed)" in res.output


def test_the_cli_says_a_failed_diff_leaves_the_pair_uncovered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Display only: the coverage it is handed says a diff failed, and the roll-up says the pair is
    not covered (the rule itself is held in test_diff_review). No hunt marks moved, no line.

    MUTATION: print the covered sentence whatever the flag says -> RED."""
    coverage = {
        "failed_diffs": [_did("libc")],
        "not_diffed_binaries": {},
        "identical_binaries": {},
        "all_candidate_binaries_covered": False,
    }
    res = _cli_full_diff(tmp_path, monkeypatch, lambda atlas, did: _STATES, coverage)
    assert res.exit_code == 0, res.output
    assert "NOT every candidate-holding binary is covered" in res.output
    assert "every candidate-holding binary is diffed or byte-identical" not in res.output
    assert "hunt marks" not in res.output


def test_the_diff_listing_counts_functions_and_leaves_edges_to_their_view(tmp_path: Path) -> None:
    """The listing leads with functions, says similarity 1 is not 'unchanged', and points at
    get_diff_deltas for the string-keyed edges rather than counting them.

    MUTATION: describe the rows as edge counts again -> RED."""
    from treasure_map import mcp_app

    note = diff_align._LIST_DIFFS_NOTE
    assert "FUNCTIONS" in note and "Similarity 1 is NOT 'unchanged'" in note
    assert "get_diff_deltas" in note and "switchable view" in note and "layer_changed" not in note
    doc = mcp_app.make_tools(tmp_path / "x.db")["list_diffs"].__doc__ or ""
    assert "get_diff_deltas" in doc and "switchable view" in doc
    assert "layer_changed / layer_unchanged" not in doc


# ── what code and which toolchain computed a diff (no hand-bumped version) ─────────────────────


def _two_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> _World:
    """liba exported by the extension's builder, libb by the fallback builder, both diffed."""
    w = _world(
        tmp_path,
        {"liba": (_sha("a"), _PV), "libb": (_sha("c"), _PV)},
        {"liba": (_sha("b"), _PV), "libb": (_sha("d"), _PV)},
    )
    _stub(monkeypatch, w)
    _full(w)
    for binary, builder in (("liba", "extension"), ("libb", "fallback")):
        h = code_version.export_code_hash(builder)
        w.atlas.execute(
            "UPDATE diff_meta SET export_builder_a = ?, export_builder_b = ?, "
            "export_code_hash_a = ?, export_code_hash_b = ? WHERE diff_id = ?",
            (builder, builder, h, h, _did(binary)),
        )
    w.atlas.commit()
    assert _plan(w).already_ok == ("liba", "libb")
    return w


def _scripts_changed(monkeypatch: pytest.MonkeyPatch, *, which: str) -> None:
    """The export script files as they would hash after an edit to ``which``."""
    real = code_version.export_code_hash

    def changed(builder: str | None) -> str:
        if which == "fallback" and builder == "extension":
            return real(builder)  # the extension path does not take the fallback builder
        return "edited-" + real(builder)

    monkeypatch.setattr(driver, "export_code_hash", changed)
    monkeypatch.setattr(diff_align, "export_code_hash", changed)


def _listed_reasons(w: _World) -> dict[str, tuple[bool | None, str | None]]:
    return {
        r["binary"]: (r["source_stale"], r["source_stale_reason"])
        for r in diff_align.list_diffs(w.atlas)["diffs"]
    }


def test_an_edit_to_the_fallback_builder_reruns_only_the_fallback_exports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MUTATION (verified RED): compare one export hash for every diff, whatever its path -> the
    extension export is re-diffed too."""
    w = _two_paths(tmp_path, monkeypatch)
    _scripts_changed(monkeypatch, which="fallback")
    plan = _plan(w)
    assert (plan.to_diff, plan.already_ok) == (("libb",), ("liba",))
    assert _listed_reasons(w) == {"liba": (False, None), "libb": (True, "diff_logic_changed")}


def test_an_edit_to_the_export_script_reruns_every_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    w = _two_paths(tmp_path, monkeypatch)
    _scripts_changed(monkeypatch, which="export")
    assert _plan(w).to_diff == ("liba", "libb")
    assert set(_listed_reasons(w).values()) == {(True, "diff_logic_changed")}


def test_an_edit_to_the_diff_code_reruns_every_diff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MUTATION (verified RED): leave the code version out of the plan's comparison -> nothing
    is re-diffed."""
    w = _two_paths(tmp_path, monkeypatch)
    monkeypatch.setattr(driver, "diff_code_version", lambda: "src-other")
    monkeypatch.setattr(diff_align, "diff_code_version", lambda: "src-other")
    assert _plan(w).to_diff == ("liba", "libb")
    assert set(_listed_reasons(w).values()) == {(True, "diff_logic_changed")}


def test_an_edit_to_the_overlay_logic_restores_every_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The baseline's version is the overlay code's hash: another hash reads stale, and the next
    full diff stores it again by the current code, without re-diffing.

    MUTATION (verified RED): keep a hand-written version -> the stored baseline still reads
    current."""
    w = _baselined(tmp_path, monkeypatch)
    monkeypatch.setattr(so, "sink_overlay_logic_version", lambda: "src-other")
    got = so.read_sink_overlay_baseline(w.atlas, _did())
    assert got["stale_baseline"] is True
    fs = _full(w)
    assert fs.outcomes == () and fs.baselines_refreshed == ("liba",)
    assert so.read_sink_overlay_baseline(w.atlas, _did())["stale_baseline"] is False
    versions = {
        r[0]
        for r in w.atlas.execute(
            "SELECT overlay_version FROM dimension_delta WHERE subject_kind = 'candidate'"
        )
    }
    assert versions == {"src-other"}


_TOOLS = toolchain.Toolchain("11.4.3", "11.4.3", "BinDiff 8 (@568181968, Sep 25 2023)")


def _installed(monkeypatch: pytest.MonkeyPatch, tools: toolchain.Toolchain | None) -> None:
    monkeypatch.setattr(toolchain, "detect_toolchain", lambda config: tools)
    monkeypatch.setattr(toolchain, "_current", [tools])


def test_a_diff_records_its_toolchain_and_an_upgrade_reruns_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MUTATION (verified RED): leave the toolchain out of the plan's comparison -> the upgraded
    BinDiff re-diffs nothing; out of the read side -> the diff reads current."""
    w = _two(tmp_path)
    _stub(monkeypatch, w)
    _installed(monkeypatch, _TOOLS)
    _full(w)
    row = _row(w)
    assert (row["toolchain_ghidra"], row["toolchain_bindiff"]) == ("11.4.3", _TOOLS.bindiff)
    (listed,) = diff_align.list_diffs(w.atlas)["diffs"]
    assert (listed["source_stale"], listed["toolchain_checked"]) == (False, True)
    _installed(monkeypatch, toolchain.Toolchain("11.4.3", "11.4.3", "BinDiff 9"))
    assert _plan(w, toolchain=toolchain.detect_toolchain(Config())).to_diff == ("liba",)
    (listed,) = diff_align.list_diffs(w.atlas)["diffs"]
    assert (listed["source_stale"], listed["source_stale_reason"]) == (True, "toolchain_changed")
    assert diff_align.get_diff_meta(w.atlas, _did())["source_stale_reason"] == "toolchain_changed"


def test_a_toolchain_that_cannot_be_read_is_said_and_decides_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No Ghidra configured on the reading machine: the diff is neither stale nor re-diffed on
    that account, and every answer says the toolchain was not checked.

    MUTATION (verified RED): compare an unreadable toolchain as None -> every diff reads
    toolchain_changed and is re-diffed."""
    w = _two(tmp_path)
    _stub(monkeypatch, w)
    _installed(monkeypatch, _TOOLS)
    _full(w)
    _installed(monkeypatch, None)
    assert _plan(w, toolchain=None).already_ok == ("liba",)
    (listed,) = diff_align.list_diffs(w.atlas)["diffs"]
    assert (listed["source_stale"], listed["toolchain_checked"]) == (False, False)
    meta = diff_align.get_diff_meta(w.atlas, _did())
    assert (meta["source_stale"], meta["toolchain_checked"]) == (False, False)


# ── the golden diff: what the diff code writes for a fixed input ─────────────────────────────────

_GOLDEN_TABLES = (
    "diff_meta",
    "function_alignment",
    "function_presence",
    "instruction_match",
    "dimension_delta",
    "dimension_capability_state",
)
# row ids and timestamps are not output, and neither are the stamps of the code and toolchain that
# computed it (they change with any edit to that code, whatever the output)
_GOLDEN_SKIP = frozenset(
    {
        "id",
        "created_at",
        "diff_code_version",
        "export_code_hash_a",
        "export_code_hash_b",
        "toolchain_ghidra",
        "toolchain_binexport",
        "toolchain_bindiff",
    }
)
# The digest of the golden diff's output. An output regression test: the version stamped on a diff
# is a hash of the code itself (lib/diff/code_version), not this value.
_GOLDEN_OUTPUT = "0f7ac1cdb02b"


def _golden_analysis(path: Path, sha: str, side: str) -> None:
    """The diffed binary's functions on one side, at the fixture's real addresses."""
    walk = "0x101314" if side == "a" else "0x101325"
    walk_call = "0x101318" if side == "a" else "0x101329"
    conn = open_db(path)
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256, arch, pass_version, ghidra_version, "
        "ghidra_ok, last_seen_at) VALUES (1, 'libshapes.so', 'lib/libshapes.so', ?, "
        "'x86:LE:64:default', 'pvgolden', '11.4.3', 1, '2026-01-01T00:00:00')",
        (sha,),
    )

    def tok(name: str, op_addr: str) -> str:
        return json.dumps([{"call_token": name, "op_addr": op_addr, "opcode": 7, "text_off": 0}])

    funcs = [
        ("dispatch", "0x101249", "int dispatch(int c){ return c; }", 42, None),
        ("stable_sum", "0x101273", "int stable_sum(int *v){ return 0; }", 51, None),
        ("stable_dup", "0x1012a6", "char *stable_dup(char *s){ memcpy(d,s,n); }", 61,
         tok("memcpy", "0x1012b1")),
        ("sub_101159", "0x101159", "void sub_101159(void){}", 12, None),
        ("changed_walk", walk, "int changed_walk(int *p){ strlen(p); }", 40,
         tok("strlen", walk_call)),
        ("orphan", "0x101400", "", 64, None),  # unmatched, a real decompile gap
        ("tiny", "0x101500", "", 2, None),  # unmatched, a skipped micro-function
    ]  # fmt: skip
    if side == "b":
        funcs.append(("extra_b", "0x101600", "int extra_b(void){ return 1; }", 30, None))
    for name, addr, pc, size, tokens in funcs:
        conn.execute(
            "INSERT INTO functions (binary_id, name, address, pseudocode, size_bytes, call_tokens) "
            "VALUES (1, ?, ?, ?, ?, ?)",
            (name, addr, pc, size, tokens),
        )
    conn.commit()
    conn.close()


def _golden_atlas(tmp_path: Path) -> sqlite3.Connection:
    con = sqlite3.connect(f"file:{_FIXTURE}?mode=ro", uri=True)
    sha_a, sha_b = (r[0] for r in con.execute("SELECT hash FROM file ORDER BY id"))
    con.close()
    atlas = open_atlas(tmp_path / "atlas.db")
    atlas.execute(
        "INSERT INTO pattern (source_class, sink_class, call_sequence_shape, "
        "structural_fingerprint, fingerprint_algo_version) VALUES "
        "('external_input', 'cmd', 's->s', 'fp', 'v1')"
    )
    for side, sha in (("a", sha_a), ("b", sha_b)):
        run = f"run_{side}"
        fw = tmp_path / f"fw_{side}"
        (fw / "lib").mkdir(parents=True)
        (fw / "lib" / "libshapes.so").write_bytes(b"\x7fELF")
        _golden_analysis(tmp_path / f"{side}.db", sha, side)
        begin_run(
            atlas, run, analysis_db_path=str(tmp_path / f"{side}.db"), firmware_path=str(fw),
            tool_version="0.0.1", ghidra_version="11.4.3",
        )  # fmt: skip
        walk = "00101314" if side == "a" else "00101325"
        refs = [
            (f"{run}#x:001012a6@cmd@0x00000b", None),  # stable_dup's call at 0x1012b1
            (f"{run}#x:{walk}@cmd@0x000004", None),  # changed_walk's call
            (f"{run}#x:00101273@cmd", json.dumps({"callsite_addr": "0010128a"})),  # degraded
        ]
        for ref, fe in refs:
            atlas.execute(
                "INSERT INTO instance (pattern_id, evidence_ref, source_run_id, "
                "binary_content_hash, binary_path, sink_anchor, flow_evidence) "
                "VALUES (1, ?, ?, ?, 'lib/libshapes.so', 'system', ?)",
                (ref, run, sha, fe),
            )
        beta = "do_beta" if side == "a" else "do_beta2"
        for func, addr, key, callee in (
            ("dispatch", "00101249", "alpha", "do_alpha"),  # same both sides -> unchanged
            ("stable_sum", "00101273", "beta", beta),  # callee differs -> changed
            ("sub_101159", "00101159", "gamma", "do_gamma"),  # low-confidence pair -> undetermined
        ):
            atlas.execute(
                "INSERT INTO string_keyed_edge (source_run_id, binary, from_function, "
                "from_func_addr, key, mechanism, callee_name, callee_kind, completeness_status) "
                "VALUES (?, 'libshapes.so', ?, ?, ?, 'strcmp_gate', ?, 'direct', 'complete')",
                (run, func, addr, key, callee),
            )
        atlas.execute(
            "INSERT INTO run_capability (run_id, capability, present) "
            "VALUES (?, 'reachability.string_keyed_edge', 1)",
            (run,),
        )
        finish_run(atlas, run, hunt_instances=3)
    atlas.execute("UPDATE run SET scanned_at = '2026-01-01 00:00:00'")
    atlas.commit()
    return atlas


def _golden_digest(atlas: sqlite3.Connection, diff_id: str) -> str:
    """A digest of every row the diff wrote for ``diff_id``. A NULL column is left out of its row,
    so a column added to a table later (and not written by the diff) does not move the digest."""
    out: dict[str, list[str]] = {}
    for table in _GOLDEN_TABLES:
        cur = atlas.execute(f"SELECT * FROM {table} WHERE diff_id = ?", (diff_id,))  # noqa: S608
        cols = [d[0] for d in cur.description]
        out[table] = sorted(
            json.dumps(
                {
                    c: v
                    for c, v in zip(cols, row, strict=True)
                    if c not in _GOLDEN_SKIP and v is not None
                },
                sort_keys=True,
            )
            for row in cur
        )
    blob = json.dumps(out, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def test_the_golden_diff_writes_what_it_wrote(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The real fixture ``.BinDiff`` plus hand-encoded BinExport files, through the whole persist
    path (layer-0 parse, instruction matches, call-site facts, layer-2 deltas). The digest of what
    it writes must equal ``_GOLDEN_OUTPUT``: a change to the diff code that changes this output on
    purpose updates it here; one that does not mean to fails.

    MUTATION (verified RED): change layer2's opaque state summary prefix (``callees=``) -> the
    digest moves and this fails; likewise renaming a call identity kind in lib/diff/callsite_facts.
    """
    atlas = _golden_atlas(tmp_path)

    def binexport(so_path: Path, cfg: Any, out: Path, side: str, timeout: int) -> Path:
        walk_call = 0x101318 if side == "a" else 0x101329
        p = out / f"{side}.BinExport"
        p.write_bytes(_insn(0x1012B1, (0x101080,)) + _insn(walk_call, (0x101070,)))
        return p

    monkeypatch.setattr(driver, "_check_toolchain", lambda config: None)
    monkeypatch.setattr(driver, "_current_pass_version", lambda: "pvgolden")
    monkeypatch.setattr(driver, "_installed_commit", lambda: UNKNOWN_VERSION)
    monkeypatch.setattr(driver, "_run_binexport", binexport)
    monkeypatch.setattr(driver, "_run_bindiff", lambda ea, eb, out, t: _FIXTURE)
    summary = driver.run_version_diff(atlas, "run_a", "run_b", "libshapes.so", config=Config())
    did = summary.diff_id

    def count(sql: str) -> int:
        return int(atlas.execute(sql, (did,)).fetchone()[0])

    # the golden input must reach every part of the output, or the digest would not follow it
    assert count("SELECT COUNT(*) FROM function_alignment WHERE diff_id = ?") > 0
    assert count("SELECT COUNT(*) FROM function_presence WHERE diff_id = ?") > 0
    assert count("SELECT COUNT(*) FROM instruction_match WHERE diff_id = ?") >= 3
    assert (
        count(
            "SELECT COUNT(*) FROM instruction_match WHERE diff_id = ? "
            'AND facts_a LIKE \'%"kind"%\' AND facts_b LIKE \'%"targets": ["%\''
        )
        > 0
    )
    meta = atlas.execute(
        "SELECT callsite_facts_a, callsite_facts_b, version_skew FROM diff_meta WHERE diff_id = ?",
        (did,),
    ).fetchone()
    assert tuple(meta) == ("read", "read", 0)
    kinds = {
        r[0]
        for r in atlas.execute(
            "SELECT delta_kind FROM dimension_delta WHERE diff_id = ? AND subject_kind = 'edge'",
            (did,),
        )
    }
    assert kinds == {"layer_changed", "layer_unchanged", "delta_undetermined"}
    assert count("SELECT COUNT(*) FROM dimension_capability_state WHERE diff_id = ?") > 0

    digest = _golden_digest(atlas, did)
    assert digest[:12] == _GOLDEN_OUTPUT, (
        f"the diff code's output for the golden input changed to {digest[:12]}; if intended, "
        "update _GOLDEN_OUTPUT (stored diffs read as stale through the code hash either way)"
    )
