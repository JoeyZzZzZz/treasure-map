# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Toolchain failure buckets, and the functions an export could not hold as they are.

Covers the driver's structured failure kinds (each set where a step fails, never read back out of a
message that also carries argv and paths), the report a BinExport run leaves beside its file, and
how layer 0, layer 2 and the sink overlay treat the functions that report lists: undetermined,
never aligned, unmatched-complete, changed, unchanged or persisted. The Java side (the flow-graph
repair and the fallback builder) runs only against a real Ghidra and is not exercised here.
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from tests.unit.lib.binexport_seed import archive_exports
from treasure_map.lib.analyze import ghidra_runner
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.writer import begin_run, finish_run
from treasure_map.lib.config.config import Config
from treasure_map.lib.diff import driver
from treasure_map.lib.diff.driver import DiffToolchainError
from treasure_map.lib.diff.export_report import (
    DEGENERATE_BLOCK_SOURCE,
    ExportReportError,
    parse_export_report,
)
from treasure_map.lib.diff.layer0 import make_diff_id
from treasure_map.lib.query import diff_align
from treasure_map.lib.query import sink_overlay as so
from treasure_map.lib.storage.connection import open_db

_PV = "pv1"
_GV = "11.4.3"
_COMMIT = "facefeed"
_DID = make_diff_id("run_a", "run_b", "liba")

# ── each toolchain step tags its own failure ─────────────────────────────────────────────────────


def _fake_run(
    seen: list[list[str]],
    *,
    rc: int = 0,
    stdout: bytes = b"",
    stderr: bytes = b"",
    writes: tuple[Path, ...] = (),
    raises: BaseException | None = None,
    files: dict[Path, bytes] | None = None,
) -> Any:
    def run(cmd: list[str], **_kw: Any) -> subprocess.CompletedProcess[bytes]:
        seen.append(cmd)
        if raises is not None:
            raise raises
        for p in writes:
            p.write_bytes(b"\x01")
        for p, body in (files or {}).items():
            p.write_bytes(body)
        return subprocess.CompletedProcess(cmd, rc, stdout, stderr)

    return run


@pytest.fixture
def headless(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(ghidra_runner, "find_headless", lambda cfg: tmp_path / "analyzeHeadless")
    monkeypatch.setattr(driver, "_find_bindiff", lambda: tmp_path / "bindiff")
    # The BinExport step runs through _run_killable (its own process group, killed whole on a
    # timeout), which has subprocess.run's contract. Route it to whatever subprocess.run is when
    # the call happens, so each test's fake stands in for both steps; _run_killable itself is
    # covered by test_run_killable.
    monkeypatch.setattr(
        driver,
        "_run_killable",
        lambda cmd, env, timeout: subprocess.run(cmd, env=env, timeout=timeout),  # noqa: S603
    )


def _export(tmp_path: Path, name: str = "liba.so") -> Path:
    so_path = tmp_path / name
    so_path.write_bytes(b"\x7fELF")
    return so_path


@pytest.mark.usefixtures("headless")
def test_an_export_that_wrote_nothing_is_no_file_whatever_its_argv_says(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MUTATION (verified RED): classify by the message again -> the argv's
    ``-analysisTimeoutPerFile`` (and the library's name) make it a timeout."""
    seen: list[list[str]] = []
    monkeypatch.setattr(subprocess, "run", _fake_run(seen))
    so_path = _export(tmp_path, "libnetfilter_cttimeout.so.1")
    with pytest.raises(DiffToolchainError) as ei:
        driver._run_binexport(so_path, Config(), tmp_path, "a", 300)
    assert "-analysisTimeoutPerFile" in seen[0] and "timeout" in str(ei.value)
    assert driver._classify_failure_reason(ei.value) == driver.FAIL_BINEXPORT_NO_FILE


@pytest.mark.usefixtures("headless")
def test_an_export_without_its_report_is_no_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[list[str]] = []
    monkeypatch.setattr(subprocess, "run", _fake_run(seen, writes=(tmp_path / "a.BinExport",)))
    with pytest.raises(DiffToolchainError) as ei:
        driver._run_binexport(_export(tmp_path), Config(), tmp_path, "a", 300)
    assert ei.value.kind == driver.FAIL_BINEXPORT_NO_FILE
    # the report path is handed to the script right after the export path
    i = seen[0].index(str(tmp_path / "a.BinExport"))
    assert seen[0][i + 1] == str(tmp_path / "a.export_report.json")


@pytest.mark.usefixtures("headless")
@pytest.mark.parametrize("step", ["binexport", "bindiff"])
def test_a_step_that_ran_out_of_time_is_a_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, step: str
) -> None:
    seen: list[list[str]] = []
    expired = subprocess.TimeoutExpired(["x"], 1)
    monkeypatch.setattr(subprocess, "run", _fake_run(seen, raises=expired))
    with pytest.raises(DiffToolchainError) as ei:
        if step == "binexport":
            driver._run_binexport(_export(tmp_path), Config(), tmp_path, "a", 300)
        else:
            driver._run_bindiff(tmp_path / "a.BinExport", tmp_path / "b.BinExport", tmp_path, 300)
    assert driver._classify_failure_reason(ei.value) == driver.FAIL_TIMEOUT


@pytest.mark.usefixtures("headless")
def test_a_crashed_export_of_a_library_named_for_timeouts_is_a_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[list[str]] = []
    monkeypatch.setattr(subprocess, "run", _fake_run(seen, rc=1, stdout=b"analysis timeout"))
    with pytest.raises(DiffToolchainError) as ei:
        driver._run_binexport(
            _export(tmp_path, "libnetfilter_cttimeout.so.1"), Config(), tmp_path, "a", 300
        )
    assert driver._classify_failure_reason(ei.value) == driver.FAIL_BINEXPORT_CRASH


_TIMED_OUT = (
    b"ERROR (HeadlessAnalyzer) REPORT: Analysis timed out at 10 seconds. Processing not completed "
    b"for file: file:///x/liba.so\n"
)


def _complete_export(tmp_path: Path) -> tuple[Path, ...]:
    return (tmp_path / "a.BinExport", tmp_path / "a.export_report.json")


@pytest.mark.usefixtures("headless")
@pytest.mark.parametrize("where", ["stdout", "log"])
def test_an_export_of_an_analysis_that_timed_out_is_a_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, where: str
) -> None:
    """Ghidra stops analysing at -analysisTimeoutPerFile, runs the export script anyway and exits
    0: the export is complete as a file and describes a half-analysed program.

    MUTATION (verified RED): drop the check -> the export is returned as a success; look at stdout
    only -> the case where only the -log file holds the line is returned as a success."""
    seen: list[list[str]] = []
    files = {tmp_path / "a.ghidra.log": _TIMED_OUT if where == "log" else b"INFO ok\n"}
    stdout = _TIMED_OUT if where == "stdout" else b"INFO ok\n"
    monkeypatch.setattr(
        subprocess,
        "run",
        _fake_run(seen, stdout=stdout, writes=_complete_export(tmp_path), files=files),
    )
    with pytest.raises(DiffToolchainError) as ei:
        driver._run_binexport(_export(tmp_path), Config(), tmp_path, "a", 10)
    assert ei.value.kind == driver.FAIL_TIMEOUT
    assert "analysis" in str(ei.value).lower()


@pytest.mark.usefixtures("headless")
def test_an_analysis_that_finished_is_not_a_timeout_whatever_it_is_named(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only Ghidra's own timed-out line counts: the library's name and the -analysisTimeoutPerFile
    flag in argv do not.

    MUTATION (verified RED): match any "timeout" in the output -> this export is refused."""
    seen: list[list[str]] = []
    stdout = b"INFO REPORT: Analysis succeeded for file: file:///x/libnetfilter_cttimeout.so.1\n"
    monkeypatch.setattr(
        subprocess, "run", _fake_run(seen, stdout=stdout, writes=_complete_export(tmp_path))
    )
    so_path = _export(tmp_path, "libnetfilter_cttimeout.so.1")
    assert driver._run_binexport(so_path, Config(), tmp_path, "a", 300) == tmp_path / "a.BinExport"
    assert "-analysisTimeoutPerFile" in seen[0]


@pytest.mark.usefixtures("headless")
def test_a_timed_out_analysis_without_an_export_is_still_a_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The timeout says more about why than the missing file does.

    MUTATION (verified RED): check for the file before the timeout -> binexport_no_file."""
    seen: list[list[str]] = []
    monkeypatch.setattr(subprocess, "run", _fake_run(seen, stdout=_TIMED_OUT))
    with pytest.raises(DiffToolchainError) as ei:
        driver._run_binexport(_export(tmp_path), Config(), tmp_path, "a", 10)
    assert ei.value.kind == driver.FAIL_TIMEOUT


@pytest.mark.usefixtures("headless")
@pytest.mark.parametrize(
    ("rc", "stderr", "expected"),
    [
        (
            1,
            b"Error: AttachFlowGraph: couldn't find call graph node for flow graph 00000000",
            driver.FAIL_BINDIFF_FLOWGRAPH,
        ),
        (1, b"E flow_graph.cc:85] Could not find basic block: 00410004", "bindiff_flowgraph"),
        (1, b"Error: failed to read the primary file", driver.FAIL_BINDIFF),
        (0, b"", driver.FAIL_BINDIFF),  # exited 0, wrote no .BinDiff
    ],
)
def test_bindiff_is_bucketed_on_its_own_output_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rc: int, stderr: bytes, expected: str
) -> None:
    """The argv names ``.BinExport`` files in a directory whose name holds every flow-graph word;
    none of it moves the bucket.

    MUTATION (verified RED): bucket on the whole message -> the generic failure becomes
    binexport_ghidra_crash / bindiff_flowgraph."""
    out = tmp_path / "binexport flow graph basic block"
    out.mkdir()
    seen: list[list[str]] = []
    monkeypatch.setattr(subprocess, "run", _fake_run(seen, rc=rc, stderr=stderr))
    with pytest.raises(DiffToolchainError) as ei:
        driver._run_bindiff(out / "a.BinExport", out / "b.BinExport", out, 300)
    assert driver._classify_failure_reason(ei.value) == expected
    assert (out / "bindiff.log").read_bytes() == stderr


# ── the export report ─────────────────────────────────────────────────────────────────────────


def _report(
    builder: str = "fallback",
    added: int = 0,
    dropped: tuple[int, ...] = (),
    degenerate: tuple[int, ...] = (),
) -> dict[str, Any]:
    return {
        "builder": builder,
        "entry_addresses_added": added,
        "flow_graphs_dropped": len(dropped),
        "dropped_functions": list(dropped),
        "degenerate_functions": list(degenerate),
    }


def test_the_report_is_parsed_into_normalized_entries() -> None:
    r = parse_export_report(json.dumps(_report(dropped=(0x3000,), degenerate=(0x1000, 0x3000))))
    assert r.dropped_functions == {"00003000"} and r.degenerate_functions == {
        "00001000",
        "00003000",
    }
    # a dropped flow graph wins: the function is not in BinDiff's input at all
    assert r.gaps() == {"00001000": "degenerate_block", "00003000": "flow_graph_dropped"}


@pytest.mark.parametrize(
    "bad",
    [
        "not json",
        json.dumps({**_report(), "builder": "other"}),
        json.dumps({**_report(dropped=(0x3000,)), "flow_graphs_dropped": 2}),
        json.dumps({**_report(), "entry_addresses_added": True}),
        json.dumps({**_report(), "degenerate_functions": [-1]}),
        json.dumps({k: v for k, v in _report().items() if k != "dropped_functions"}),
    ],
)
def test_a_malformed_report_is_refused(bad: str) -> None:
    with pytest.raises(ExportReportError):
        parse_export_report(bad)


# ── a two-run world (as in test_diff_currency, with three functions per side) ───────────────────

_TOKENS = json.dumps([{"call_token": "system", "op_addr": "0x1010", "opcode": 7, "text_off": 0}])


@dataclass
class _World:
    tmp: Path
    atlas: sqlite3.Connection
    so_sha: dict[str, str] = field(default_factory=dict)
    reports: dict[str, Any] = field(default_factory=dict)  # side -> report dict, or raw text
    vertex0: int = 0
    pairs: tuple[tuple[int, int], ...] = ((0x1000, 0x1000), (0x2000, 0x2000))
    insn_b: int = 0x1010


def _sha(c: str) -> str:
    return c * 64


def _analysis(w: _World, side: str, sha: str, funcs: dict[int, str]) -> Path:
    path = w.tmp / f"{side}.db"
    conn = open_db(path)
    so_path = w.tmp / f"{side}-liba-{sha[:8]}"
    so_path.write_bytes(b"\x7fELF")
    w.so_sha[str(so_path)] = sha
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256, arch, pass_version, ghidra_version, "
        "ghidra_ok, last_seen_at) VALUES (1, 'liba', ?, ?, 'ARM:LE:32:v7', ?, ?, 1, "
        "'2026-01-01T00:00:00')",
        (str(so_path), sha, _PV, _GV),
    )
    for addr, name in funcs.items():
        conn.execute(
            "INSERT INTO functions (binary_id, name, address, pseudocode, size_bytes, call_tokens) "
            "VALUES (1, ?, ?, 'void f(void){ system(x); }', 64, ?)",
            (name, hex(addr), _TOKENS if addr == 0x1000 else None),
        )
    conn.commit()
    conn.close()
    archive_exports(path)
    return path


def _hunt(w: _World, run: str, sha: str) -> None:
    """A candidate at caller+0x10 and a gate edge in caller whose callee is helper."""
    a = w.atlas
    if a.execute("SELECT COUNT(*) FROM pattern").fetchone()[0] == 0:
        a.execute(
            "INSERT INTO pattern (source_class, sink_class, call_sequence_shape, "
            "structural_fingerprint, fingerprint_algo_version) VALUES "
            "('external_input', 'cmd', 's->s', 'fp', 'v1')"
        )
    pid = a.execute("SELECT pattern_id FROM pattern").fetchone()[0]
    a.execute(
        "INSERT INTO instance (pattern_id, evidence_ref, source_run_id, binary_content_hash, "
        "binary_path, sink_anchor) VALUES (?, ?, ?, ?, 'liba', 'system')",
        (pid, f"{run}#{sha[:8]}:00001000@cmd@0x000010", run, sha),
    )
    a.execute(
        "INSERT INTO string_keyed_edge (source_run_id, binary, from_function, from_func_addr, "
        "key, mechanism, callee_name, callee_addr, callee_kind, completeness_status) VALUES "
        "(?, 'liba', 'caller', '00001000', 'mode', 'strcmp_gate', NULL, '00002000', 'direct', "
        "'complete')",
        (run,),
    )
    a.execute(
        "INSERT INTO run_capability (run_id, capability, present) "
        "VALUES (?, 'reachability.string_keyed_edge', 1)",
        (run,),
    )
    finish_run(a, run, hunt_commit=_COMMIT, hunt_instances=1)


def _world(tmp_path: Path, **kw: Any) -> _World:
    w = _World(tmp_path, open_atlas(tmp_path / "atlas.db"), **kw)
    funcs = {
        "a": {0x1000: "caller", 0x2000: "helper", 0x3000: "gone"},
        "b": {0x1000: "caller", 0x2000: "helper"},
    }
    for side, sha in (("a", _sha("a")), ("b", _sha("b"))):
        run = f"run_{side}"
        db = _analysis(w, side, sha, funcs[side])
        begin_run(w.atlas, run, analysis_db_path=str(db), tool_version="0.0.1", ghidra_version=_GV)
        _hunt(w, run, sha)
    w.atlas.execute("UPDATE run SET build_hash = ?", (_PV,))
    w.atlas.commit()
    return w


def _bindiff(w: _World, path: Path, sha_a: str, sha_b: str) -> Path:
    con = sqlite3.connect(path)
    con.execute(
        "CREATE TABLE function (id INTEGER PRIMARY KEY, address1 BIGINT, name1 TEXT, "
        "address2 BIGINT, name2 TEXT, similarity DOUBLE, confidence DOUBLE, "
        "basicblocks INTEGER, edges INTEGER, instructions INTEGER)"
    )
    for i, (addr_a, addr_b) in enumerate(w.pairs, start=1):
        con.execute(
            "INSERT INTO function VALUES (?, ?, 'f', ?, 'f', 0.98, 0.97, 3, 2, 20)",
            (i, addr_a, addr_b),
        )
    con.execute(
        "CREATE TABLE basicblock (id INT, functionid INT, address1 BIGINT, address2 BIGINT)"
    )
    con.execute("INSERT INTO basicblock VALUES (1, 1, ?, ?)", w.pairs[0])
    con.execute("CREATE TABLE instruction (basicblockid INT, address1 BIGINT, address2 BIGINT)")
    con.execute("INSERT INTO instruction VALUES (1, ?, ?)", (0x1010, w.insn_b))
    con.execute("CREATE TABLE file (id INT, filename TEXT, hash CHARACTER(40))")
    con.executemany(
        "INSERT INTO file VALUES (?, ?, ?)", [(1, "before", sha_a), (2, "after", sha_b)]
    )
    con.commit()
    con.close()
    return path


def _stub(monkeypatch: pytest.MonkeyPatch, w: _World) -> None:
    """The toolchain steps stubbed; compute_diff itself runs, so it reads each side's report and
    BinDiff's log from where the real steps leave them."""
    monkeypatch.setattr(driver, "_check_toolchain", lambda config: None)
    monkeypatch.setattr(driver, "_current_pass_version", lambda: _PV)
    monkeypatch.setattr(driver, "_installed_commit", lambda: _COMMIT)

    def binexport(stored: Any, out: Path, side: str) -> Path:
        sha = stored.meta["sha256"]  # the seeded meta names its binary (tests binexport_seed)
        so_path = next(p for p, s in w.so_sha.items() if s == sha)
        (out / f"{side}.so").write_text(so_path)
        p = out / f"{side}.BinExport"
        p.write_bytes(b"")
        rep = w.reports.get(side)
        if rep is not None:
            text = rep if isinstance(rep, str) else json.dumps(rep)
            (out / f"{side}.export_report.json").write_text(text)
        return p

    def bindiff(ea: Path, eb: Path, out: Path, timeout: int) -> Path:
        so_a, so_b = (out / "a.so").read_text(), (out / "b.so").read_text()
        log = b"BinDiff 8\n" + b"E flow_graph.cc:85] Could not find basic block: 0000beef\n" * (
            w.vertex0
        )
        (out / "bindiff.log").write_bytes(log)
        return _bindiff(w, out / "x.BinDiff", w.so_sha[so_a], w.so_sha[so_b])

    monkeypatch.setattr(driver, "_obtain_export", binexport)
    monkeypatch.setattr(driver, "_run_bindiff", bindiff)


def _diff(w: _World) -> driver.DiffSummary:
    return driver.run_version_diff(w.atlas, "run_a", "run_b", "liba", config=Config())


def _meta(w: _World) -> sqlite3.Row:
    w.atlas.row_factory = sqlite3.Row
    row = w.atlas.execute("SELECT * FROM diff_meta WHERE diff_id = ?", (_DID,)).fetchone()
    assert row is not None
    return row  # type: ignore[no-any-return]


def _alignment(w: _World) -> dict[str, tuple[str, str | None, str | None]]:
    return {
        a: (state, ga, gb)
        for a, state, ga, gb in w.atlas.execute(
            "SELECT addr_a, alignment_state, export_gap_a, export_gap_b FROM function_alignment "
            "WHERE diff_id = ?",
            (_DID,),
        )
    }


def _presence(w: _World) -> dict[tuple[str, str], tuple[str, str | None]]:
    return {
        (side, addr): (state, gap)
        for side, addr, state, gap in w.atlas.execute(
            "SELECT side, addr, presence_state, export_gap FROM function_presence "
            "WHERE diff_id = ?",
            (_DID,),
        )
    }


def _edges(w: _World) -> list[tuple[str, str, str | None]]:
    return [
        tuple(r)
        for r in w.atlas.execute(
            "SELECT subject_key, delta_kind, undetermined_reason FROM dimension_delta "
            "WHERE diff_id = ? AND subject_kind = 'edge' ORDER BY subject_key",
            (_DID,),
        )
    ]


def _overlay(w: _World) -> list[tuple[str | None, str | None, str, str | None]]:
    rows = so.compute_sink_overlay(w.atlas, _DID).rows
    return sorted(
        ((r.a_ref, r.b_ref, r.presence, r.presence_reason) for r in rows),
        key=lambda x: tuple(v or "" for v in x),
    )


# ── the functions a report lists ────────────────────────────────────────────────────────────────


def test_without_a_report_nothing_is_recorded_or_marked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reference reading of the world: every subject determined."""
    w = _world(tmp_path)
    _stub(monkeypatch, w)
    _diff(w)
    m = _meta(w)
    assert m["export_builder_a"] is None and m["export_degenerate_functions_a"] is None
    assert _alignment(w)["00001000"] == ("aligned", None, None)
    assert _presence(w)[("a", "00003000")] == ("unmatched_analysis_complete", None)
    assert [k for _s, k, _r in _edges(w)] == ["layer_unchanged"]
    assert [p for _a, _b, p, _r in _overlay(w)] == ["persisted"]
    assert diff_align.list_diff_blindspots(w.atlas)["partial"] == []


def test_a_report_with_nothing_to_report_changes_no_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An export the repair left untouched diffs exactly as before; only the counts are new."""
    worlds = []
    for i, rep in enumerate((None, _report(builder="extension"))):
        w = _world(tmp_path / str(i))
        if rep is not None:
            w.reports = {"a": rep, "b": rep}
        _stub(monkeypatch, w)
        _diff(w)
        worlds.append(w)
    plain, repaired = worlds
    for read in (_alignment, _presence, _edges, _overlay):
        assert read(plain) == read(repaired)  # type: ignore[operator]
    m = _meta(repaired)
    assert (m["export_builder_a"], m["export_entry_addresses_added_a"]) == ("extension", 0)
    assert (m["export_flow_graphs_dropped_b"], m["export_degenerate_functions_b"]) == (0, 0)
    assert m["bindiff_vertex0_fallbacks"] == 0
    assert diff_align.list_diff_blindspots(repaired.atlas)["partial"] == []


def test_a_dropped_function_is_unmatched_and_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MUTATION (verified RED): ignore the gap in ``_presence_state`` -> the function reads
    unmatched_analysis_complete, a determined absence."""
    w = _world(tmp_path, reports={"a": _report(builder="extension", dropped=(0x3000,))})
    _stub(monkeypatch, w)
    _diff(w)
    assert _presence(w)[("a", "00003000")] == (
        "unmatched_analysis_incomplete",
        "flow_graph_dropped",
    )
    assert _meta(w)["export_flow_graphs_dropped_a"] == 1


def test_a_degenerate_function_is_never_aligned_and_nothing_on_it_is_determined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """caller holds the candidate and the edge. Marked on side a, the pair is undetermined, and
    so are the edge and both sides' overlay rows, with the reason that names the export.

    MUTATION (verified RED): drop the forced state in ``parse_bindiff`` -> the pair reads aligned
    and the candidate persisted; drop the gap guard in layer 2, or the gap check in the overlay's
    ``_verdict`` -> the rows name a low-confidence alignment instead of the export."""
    w = _world(tmp_path, reports={"a": _report(degenerate=(0x1000,))})
    _stub(monkeypatch, w)
    _diff(w)
    assert _alignment(w)["00001000"] == ("alignment_undetermined", "degenerate_block", None)
    assert _alignment(w)["00002000"] == ("aligned", None, None)
    assert _edges(w) == [
        ("liba|strcmp_gate|mode|00001000", "delta_undetermined", DEGENERATE_BLOCK_SOURCE)
    ]
    assert {(p, r) for _a, _b, p, r in _overlay(w)} == {
        ("presence_undetermined", DEGENERATE_BLOCK_SOURCE)
    }
    m = _meta(w)
    assert (m["export_builder_a"], m["export_degenerate_functions_a"]) == ("fallback", 1)
    assert m["alignment_undetermined"] == 1


def test_a_degenerate_callee_makes_the_edge_undetermined_but_not_the_caller(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """helper is only the edge's callee: the edge rests on it, the candidate in caller does not.

    MUTATION (verified RED): check only the edge's own function in ``_export_gap_guard`` -> the
    edge reads unchanged."""
    w = _world(tmp_path, reports={"b": _report(degenerate=(0x2000,))})
    _stub(monkeypatch, w)
    _diff(w)
    assert [(k, r) for _s, k, r in _edges(w)] == [("delta_undetermined", DEGENERATE_BLOCK_SOURCE)]
    assert [p for _a, _b, p, _r in _overlay(w)] == ["persisted"]


def _add_degraded_candidates(w: _World) -> None:
    """One more candidate per side in caller, located in the text but not pinned to an address:
    the overlay compares those per (function, sink class) on a degraded key row."""
    pid = w.atlas.execute("SELECT pattern_id FROM pattern").fetchone()[0]
    for run, sha in (("run_a", _sha("a")), ("run_b", _sha("b"))):
        w.atlas.execute(
            "INSERT INTO instance (pattern_id, evidence_ref, source_run_id, binary_content_hash, "
            "binary_path, sink_anchor, flow_evidence) VALUES (?, ?, ?, ?, 'liba', 'system', ?)",
            (pid, f"{run}#{sha[:8]}:00001000@cmd", run, sha, '{"callsite_located": false}'),
        )
    w.atlas.execute("UPDATE run SET hunt_instances = 2")
    w.atlas.commit()


@pytest.mark.parametrize("report", [None, _report(degenerate=(0x1000,))])
def test_a_degraded_key_row_on_a_listed_function_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, report: dict[str, Any] | None
) -> None:
    """MUTATION (verified RED): skip the gap check in the overlay's ``_key_row`` -> the degraded
    row names the low-confidence alignment instead of the export."""
    w = _world(tmp_path, reports={"a": report} if report else {})
    _add_degraded_candidates(w)
    _stub(monkeypatch, w)
    _diff(w)
    rows = so.compute_sink_overlay(w.atlas, _DID).rows
    (key_row,) = [r for r in rows if r.key_granularity == "degraded_out_of_body"]
    if report is None:
        assert (key_row.presence, key_row.presence_reason) == ("persisted", None)
    else:
        assert (key_row.presence, key_row.presence_reason) == (
            "presence_undetermined",
            DEGENERATE_BLOCK_SOURCE,
        )


@pytest.mark.parametrize("side", ["a", "b"])
@pytest.mark.parametrize("addr", [0x1000, 0x2000, 0x3000])
@pytest.mark.parametrize("kind", ["degenerate", "dropped"])
def test_nothing_resting_on_a_listed_function_reads_determined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, side: str, addr: int, kind: str
) -> None:
    """Whatever function is listed, on either side, by either kind: it is never aligned or
    unmatched-complete, and no edge or overlay row resting on it is changed, unchanged or
    persisted.

    MUTATION (verified RED): drop the forced state in ``parse_bindiff`` -> a listed function's
    pair reads aligned and the candidate in it persisted."""
    rep = _report(degenerate=(addr,)) if kind == "degenerate" else _report(dropped=(addr,))
    w = _world(tmp_path, reports={side: rep})
    _stub(monkeypatch, w)
    _diff(w)
    key = f"{addr:08x}"
    aligned = {
        a: s
        for a, s in w.atlas.execute(
            "SELECT addr_a, alignment_state FROM function_alignment WHERE diff_id = ? AND "
            f"addr_{side} = ?",  # noqa: S608 -- side is a literal
            (_DID, key),
        )
    }
    assert set(aligned.values()) <= {"alignment_undetermined"}
    assert _presence(w).get((side, key), ("unmatched_analysis_incomplete", None))[0] == (
        "unmatched_analysis_incomplete"
    )
    gated = {"00001000", "00002000"}  # the edge's function and its callee
    if key in gated:
        assert all(k == "delta_undetermined" for _s, k, _r in _edges(w))
    if key == "00001000":  # the candidate's function
        assert all(p == "presence_undetermined" for _a, _b, p, _r in _overlay(w))


def test_partial_blind_spots_list_a_diff_that_succeeded_with_gaps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    w = _world(
        tmp_path,
        reports={"a": _report(dropped=(0x3000,), degenerate=(0x1000,))},
        vertex0=2,
    )
    _stub(monkeypatch, w)
    _diff(w)
    got = diff_align.list_diff_blindspots(w.atlas)
    assert got["blindspots"] == []
    (row,) = got["partial"]
    assert row["diff_id"] == _DID and row["marked_rows"] == 2
    assert (row["export_flow_graphs_dropped_a"], row["export_degenerate_functions_a"]) == (1, 1)
    assert row["bindiff_vertex0_fallbacks"] == 2
    assert diff_align.get_diff_meta(w.atlas, _DID)["meta"]["export_builder_a"] == "fallback"
    pair = diff_align.align_by_a(w.atlas, _DID, "0x1000")["pairs"][0]
    assert pair["export_gap_a"] == "degenerate_block"
    gone = diff_align.align_by_a(w.atlas, _DID, "0x3000")
    assert gone["found"] is False and gone["export_gap"] == "flow_graph_dropped"


def test_an_unreadable_report_fails_the_diff_as_no_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A report that cannot be read lists functions nobody can then mark: the diff fails rather
    than read them as determined."""
    w = _world(tmp_path, reports={"b": "{not json"})
    _stub(monkeypatch, w)
    with pytest.raises(DiffToolchainError):
        _diff(w)
    m = _meta(w)
    assert (m["diff_ok"], m["diff_status_reason"]) == (0, driver.FAIL_BINEXPORT_NO_FILE)


def test_a_gap_on_one_side_marks_only_that_sides_unmatched_function(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """helper is unmatched on both sides; only side b's export dropped it.

    MUTATION (verified RED): compute side b's presence with side a's gaps -> b's helper reads
    unmatched_analysis_complete."""
    w = _world(tmp_path, pairs=((0x1000, 0x1000),), reports={"b": _report(dropped=(0x2000,))})
    _stub(monkeypatch, w)
    _diff(w)
    assert _presence(w)[("b", "00002000")] == (
        "unmatched_analysis_incomplete",
        "flow_graph_dropped",
    )
    assert _presence(w)[("a", "00002000")] == ("unmatched_analysis_complete", None)


def test_an_edge_only_side_b_has_is_checked_against_side_bs_gaps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Side b alone has a gate in helper, and side b's helper is degenerate: the edge rests on it.

    MUTATION (verified RED): check side a's subject only -> the edge reads
    completeness_not_complete, naming a symptom instead of the export."""
    w = _world(tmp_path, reports={"b": _report(degenerate=(0x2000,))})
    w.atlas.execute(
        "INSERT INTO string_keyed_edge (source_run_id, binary, from_function, from_func_addr, "
        "key, mechanism, callee_name, callee_addr, callee_kind, completeness_status) VALUES "
        "('run_b', 'liba', 'helper', '00002000', 'other', 'strcmp_gate', 'puts', NULL, "
        "'import', 'complete')"
    )
    w.atlas.commit()
    _stub(monkeypatch, w)
    _diff(w)
    only_b = [(k, r) for s, k, r in _edges(w) if "|other|" in s]
    assert only_b == [("delta_undetermined", DEGENERATE_BLOCK_SOURCE)]


def test_a_degraded_key_row_checks_the_other_sides_function_too(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The pair marking puts both halves of a marked pair among the gaps, so this side's function
    is normally marked whenever its counterpart is. The key row checks the counterpart on its own
    as well; this pins that check with only the other half marked.

    MUTATION (verified RED): check only this side's function in ``_key_row`` -> the row names the
    low-confidence alignment instead of the export."""
    w = _world(tmp_path, reports={"b": _report(degenerate=(0x1000,))})
    _add_degraded_candidates(w)
    _stub(monkeypatch, w)
    _diff(w)
    monkeypatch.setattr(so, "load_export_gaps", lambda atlas, did: (set(), {"00001000"}))
    rows = so.compute_sink_overlay(w.atlas, _DID).rows
    (key_row,) = [r for r in rows if r.key_granularity == "degraded_out_of_body"]
    assert (key_row.presence, key_row.presence_reason) == (
        "presence_undetermined",
        DEGENERATE_BLOCK_SOURCE,
    )


def test_a_diff_with_only_degenerate_functions_is_a_partial_blind_spot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A rebuilt export may hold degenerate blocks and drop no flow graph.

    MUTATION (verified RED): count only dropped flow graphs for 'partial' -> the diff is missing."""
    w = _world(tmp_path, reports={"a": _report(degenerate=(0x1000,))})
    _stub(monkeypatch, w)
    _diff(w)
    (row,) = diff_align.list_diff_blindspots(w.atlas)["partial"]
    assert row["diff_id"] == _DID and row["export_flow_graphs_dropped_a"] == 0
    assert row["export_degenerate_functions_a"] == 1


# ── a pair outside the inventory ────────────────────────────────────────────────────────────────


def test_a_counterpart_outside_the_inventory_is_counted_and_nothing_on_it_is_determined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BinDiff pairs A's caller with a B function tmap does not list (0x5000). It is counted as
    out of inventory; the edge in caller cannot verify its counterpart region (layer 2's
    completeness check), and the candidate's matched instruction carries no candidate: both
    undetermined."""
    w = _world(tmp_path, pairs=((0x1000, 0x5000), (0x2000, 0x2000)), insn_b=0x5010)
    _stub(monkeypatch, w)
    _diff(w)
    assert _meta(w)["out_of_inventory_b"] == 1
    a_edge = [(k, r) for s, k, r in _edges(w) if s.endswith("|00001000")]
    assert a_edge == [("delta_undetermined", "completeness_not_complete")]
    rows = so.compute_sink_overlay(w.atlas, _DID).rows
    a_rows = [r for r in rows if r.a_ref is not None]
    assert a_rows and all(r.presence == "presence_undetermined" for r in a_rows)
