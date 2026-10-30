# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""A scan exports each binary in the session of its extraction (Spec 2): the runner's judgement of
the export, the phase-2 re-run of an export that failed, the archive the pipeline keeps and the
row it writes, and which already-extracted binaries the next scan re-runs for their export.

Zero real data: a fake analyzeHeadless (the subprocess is replaced) or a fake ``run_ghidra`` that
writes what the three post-scripts would, over the shared ELF fixture.
"""

from __future__ import annotations

import gzip
import json
import sqlite3
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from tests.unit.lib.test_ghidra_runner import _good_json, _make_runner, _write_small_elf
from tests.unit.lib.test_pipeline import _e2e_cfg, _firmware, _ghidra, _state
from treasure_map.lib.analyze import ghidra_runner
from treasure_map.lib.analyze.db_ingest import ExportCheck, _export_redo, toolchain_changed
from treasure_map.lib.analyze.elf_inventory import ElfRecord
from treasure_map.lib.analyze.ghidra_runner import GhidraResult, GhidraRunner, export_paths
from treasure_map.lib.analyze.pipeline import AnalyzeResult, run_analyze
from treasure_map.lib.analyze.stub_resolve import resolve_stubs, stub_table_marker
from treasure_map.lib.binexport_archive import archive_names
from treasure_map.lib.export_stamp import ScanExtension
from treasure_map.lib.storage.connection import open_db
from treasure_map.lib.workspace.workspace import Workspace

MODULE = "treasure_map.lib.analyze.ghidra_runner"
_EXT = ScanExtension(Path("/ext/BinExport"), "11.4.3+lib:000000000000", None, None)


def _report(degraded: int = 0) -> dict[str, Any]:
    addrs = [0x1000 + 4 * i for i in range(degraded)]
    return {
        "builder": "fallback",
        "mode": "scan",
        "functions_before_build": 3,
        "functions_after_build": 3,
        "entry_addresses_added": 0,
        "flow_graphs_dropped": 0,
        "dropped_functions": [],
        "degenerate_functions": [],
        "operand_markup_degraded": {
            "instructions": degraded,
            "instruction_addresses": addrs,
            "functions": [0x1000] if degraded else [],
        },
    }


# ── the runner: one session, three scripts, and what the export came to ───────────────────────


def _session(
    tmp_path: Path,
    *,
    extension: ScanExtension | None = _EXT,
    write_json: bool = True,
    export: dict[str, Any] | None = None,
    log: str = "",
    rc: int = 0,
    timed_out: bool = False,
    timeout: int = 60,
) -> tuple[GhidraResult, dict[str, Any]]:
    """One _run_once over a fake analyzeHeadless; ``export`` is the report it writes (with the
    export file) or None for no export file. Returns the result and what the launch was given."""
    out_dir = tmp_path / "output"
    out_dir.mkdir(parents=True, exist_ok=True)
    binary = tmp_path / "httpd"
    _write_small_elf(binary)
    seen: dict[str, Any] = {}

    def fake_sub(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        seen.update(cmd=cmd, env=dict(env), timeout=timeout, cwd=cwd)
        d = Path(env["OUTPUT_DIR"])
        if write_json:
            (d / f"httpd_{env['SHA8']}_ghidra.json").write_text(_good_json(env))
        exp, rep = export_paths(d, binary, env["SHA8"])
        if export is not None:
            exp.write_bytes(b"\x08\x01export bytes")
            rep.write_text(json.dumps(export))
        (d / f"httpd_{env['SHA8']}.log").write_text(
            log + ("INFO  REPORT: Analysis timed out at 60 seconds\n" if timed_out else "")
        )
        return rc, ""

    runner = _make_runner(tmp_path)
    runner.set_extension(extension)
    with patch(f"{MODULE}._run_subprocess", fake_sub):
        result = runner.run_ghidra(
            binary, out_dir, timeout=timeout, arch="x86:LE:64:default", sha8="deadbeef", retry=False
        )
    return result, seen


def test_the_session_runs_promotion_extraction_then_the_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ One session: PromoteUndefined, ExportFunctions, then ExportBinExport in its scan mode with
    the export and report paths; the export scripts' directory is searched beside the extraction's;
    the wall clock is T + 60 + E with E = T; the JVM runs in a directory of its own and without
    XDG_CONFIG_HOME (every Ghidra setting stays in its temporary home).

    MUTATION (verified RED): drop the export budget from the wall clock -> RED; leave the scan mode
    argument out -> RED; launch without a working directory -> RED; keep XDG_CONFIG_HOME -> RED."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    result, seen = _session(tmp_path, export=_report(), timeout=100)
    cmd = seen["cmd"]
    posts = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-postScript"]
    assert posts == ["PromoteUndefined.java", "ExportFunctions.java", "ExportBinExport.java"]
    i = cmd.index("ExportBinExport.java")
    assert cmd[i + 3] == "scan" and cmd[i + 1].endswith(".BinExport")
    assert ";" in cmd[cmd.index("-scriptPath") + 1]
    assert seen["timeout"] == 100 + 60 + 100
    assert seen["cwd"] is not None
    assert "XDG_CONFIG_HOME" not in seen["env"]
    # the decompile retries share half the analysis budget (the wall clock carries E besides)
    assert seen["env"]["TMAP_DECOMPILE_RETRY_BUDGET_S"] == "50"
    assert (result.export_status, result.export_budget) == ("ok", 100)
    assert result.export_file is not None and result.export_file.name.endswith(".BinExport")


def test_without_the_extension_no_export_is_attempted(tmp_path: Path) -> None:
    """No BinExport available: the scan runs exactly as an extraction (no export script, the wall
    clock T + 60) and records extension_missing — decided before the JVM, never from its log."""
    result, seen = _session(tmp_path, extension=None)
    assert "ExportBinExport.java" not in seen["cmd"]
    assert seen["timeout"] == 60 + 60
    assert result.success and result.export_status == "extension_missing"
    assert seen["env"]["TMAP_DECOMPILE_RETRY_BUDGET_S"] == "30"


def test_an_operand_written_in_its_default_form_reads_degraded(tmp_path: Path) -> None:
    result, _ = _session(tmp_path, export=_report(degraded=2))
    assert result.export_status == "degraded"
    assert result.export_report is not None


def test_a_missing_export_names_the_exception_the_log_shows(tmp_path: Path) -> None:
    """The extraction succeeded and the export left no file: failed:<exception: message> from this
    attempt's log (analyzeHeadless exits 0 when a post-script throws)."""
    log = (
        "INFO  SCRIPT: /x/ExportBinExport.java (HeadlessAnalyzer)\n"
        "ERROR ExportBinExport.java> java.lang.IllegalStateException: flow graph mismatch\n"
    )
    result, _ = _session(tmp_path, export=None, log=log)
    assert result.success is True
    assert result.export_status == "failed:IllegalStateException: flow graph mismatch"
    assert result.export_file is None


def test_a_failed_extraction_never_keeps_its_sessions_export(tmp_path: Path) -> None:
    """F2: the analysis timed out — the post-scripts still ran and wrote an export, which describes
    a half analysis: the binary is scan_failed:timeout and the export is not handed over.

    MUTATION (verified RED): keep a usable export whatever the extraction did -> RED."""
    result, _ = _session(tmp_path, export=_report(), timed_out=True)
    assert result.success is False
    assert result.export_status == "scan_failed:timeout"
    assert result.export_file is None


def test_a_user_settings_extension_is_linked_into_the_jvm_home(tmp_path: Path) -> None:
    """The copy in the user settings directory is linked (symbolically) into the temporary user
    home the JVM runs under, before it starts."""
    from tests.unit.lib.test_export_stamp import _extension
    from tests.unit.lib.test_export_stamp import _ghidra as _ghidra_home
    from treasure_map.lib import export_stamp as es

    home = _ghidra_home(tmp_path / "g")
    user = tmp_path / "user"
    copy = _extension(
        user / ".config" / "ghidra" / "ghidra_11.4.3_PUBLIC" / "Extensions" / "BinExport"
    )
    ext = es.scan_extension(home, environ={}, user_home=user)
    seen: dict[str, Any] = {}

    def fake_sub(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        jvm_home = Path(env["JAVA_TOOL_OPTIONS"].split("-Duser.home=")[1].split()[0])
        link = jvm_home / ".config" / "ghidra" / "ghidra_11.4.3_PUBLIC" / "Extensions" / "BinExport"
        seen["linked"] = link.is_symlink() and link.resolve() == copy.resolve()
        return 1, ""

    binary = tmp_path / "httpd"
    _write_small_elf(binary)
    runner = GhidraRunner(
        ghidra_runner.GhidraConfig(), headless=home / "support" / "analyzeHeadless"
    )
    runner.set_extension(ext)
    with patch(f"{MODULE}._run_subprocess", fake_sub):
        runner.run_ghidra(
            binary, tmp_path / "o", timeout=60, arch="x", sha8="deadbeef", retry=False
        )
    assert seen["linked"] is True


# ── phase 2: an export that failed is run once more, at the doubled budget ────────────────────


class _Sessions:
    """A fake run_ghidra: per binary, a list of outcomes, one per call ("ok", "failed:timeout",
    "failed:other", "scan_failed")."""

    def __init__(self, plan: dict[str, list[str]]) -> None:
        self.plan = {k: list(v) for k, v in plan.items()}
        self.calls: list[tuple[str, int]] = []

    def __call__(
        self,
        runner: Any,
        binary: Path,
        output_dir: Path,
        timeout: int,
        arch: str,
        sha8: str = "",
        retry: bool = True,
    ) -> GhidraResult:
        self.calls.append((binary.name, timeout))
        outcome = self.plan[binary.name].pop(0)
        if outcome == "scan_failed":
            return GhidraResult(
                binary=binary,
                output_file=None,
                success=False,
                elapsed=0.0,
                reason="timeout",
                timeout_budget=timeout,
                export_status="scan_failed:timeout",
                export_budget=timeout,
            )
        stubs = resolve_stubs(binary)
        data = {
            "pass_version": runner.pass_version(),
            "sha8": sha8,
            "stub_marker": stub_table_marker(None if stubs is None else stubs.names),
            "functions": [{"name": "f", "address": "00101000", "size": 64, "callees": []}],
            "imports": [],
            "exports": [],
            "strings": [],
        }
        out = output_dir / f"{binary.name}_{sha8}_ghidra.json"
        out.write_text(json.dumps(data))
        exp, rep = export_paths(output_dir, binary, sha8)
        usable = outcome == "ok"
        if usable:
            exp.write_bytes(b"export of " + binary.name.encode() + str(timeout).encode())
            rep.write_text(json.dumps(_report()))
        return GhidraResult(
            binary=binary,
            output_file=out,
            success=True,
            elapsed=0.0,
            analysis_status="ok",
            function_count=1,
            export_status="ok" if usable else outcome.replace("failed:other", "failed:Boom"),
            export_file=exp if usable else None,
            export_report_file=rep if usable else None,
            export_report=_report() if usable else None,
            export_budget=timeout,
        )


def _recs(tmp_path: Path, names: tuple[str, ...]) -> list[ElfRecord]:
    out = []
    for i, n in enumerate(names):
        p = tmp_path / n
        _write_small_elf(p)
        out.append(ElfRecord(path=p, name=n, arch="x", elf_type="executable", sha256=f"{i}" * 64))
    return out


@pytest.mark.parametrize(
    ("second", "expect"),
    [
        ("ok", ("ok", False, "phase2")),
        ("failed:timeout", ("failed:timeout", True, "phase2")),
        ("scan_failed", ("failed:timeout", True, "phase1")),
    ],
)
def test_an_export_cut_off_in_phase_one_is_rerun_once_at_the_doubled_budget(
    tmp_path: Path, second: str, expect: tuple[str, bool, str]
) -> None:
    """★ Phase 1 extracted the binary and its export was cut off: the extraction is final at once
    (on_final), and the binary runs once more in phase 2 at the doubled budget. on_export reports
    it: a whole new session when the re-run extracted and exported (its extraction replaces phase
    1's); only the export outcome when its export failed again (the re-run's, with its budget); and
    when the re-run's extraction failed, phase 1's export outcome and budget stand (the re-run's
    export is dropped with its extraction).

    MUTATION (verified RED): finalize only failures in phase 2 (no export re-run) -> RED; record the
    re-run's budget when its extraction failed -> RED."""
    (rec,) = _recs(tmp_path, ("svc",))
    sessions = _Sessions({"svc": ["failed:timeout", second]})
    finals: list[GhidraResult] = []
    exports: list[GhidraResult] = []
    runner = _make_runner(tmp_path)
    with patch.object(GhidraRunner, "run_ghidra", lambda self, *a, **k: sessions(self, *a, **k)):
        with patch.object(ghidra_runner, "validate_registry", lambda p: None):
            runner.run_all(
                [rec],
                tmp_path / "out",
                on_final=lambda r, x: finals.append(x),
                on_export=lambda r, x: exports.append(x),
            )
    base = runner._config.headless_timeout_seconds
    budgets = {"phase1": base, "phase2": min(1800, 2 * base)}
    assert [t for _n, t in sessions.calls] == [budgets["phase1"], budgets["phase2"]]
    assert len(finals) == 1 and finals[0].export_status == "failed:timeout"
    (settled,) = exports
    status, export_only, which = expect
    assert (settled.export_status, settled.export_only) == (status, export_only)
    assert settled.export_budget == budgets[which]


def test_a_non_timeout_export_failure_also_gets_its_one_rerun(tmp_path: Path) -> None:
    """A failure other than a timeout (a transient read fault of the export) is re-run once in
    phase 2 as well; succeeding then, it is stored whole."""
    (rec,) = _recs(tmp_path, ("svc",))
    sessions = _Sessions({"svc": ["failed:other", "ok"]})
    exports: list[GhidraResult] = []
    runner = _make_runner(tmp_path)
    with patch.object(GhidraRunner, "run_ghidra", lambda self, *a, **k: sessions(self, *a, **k)):
        with patch.object(ghidra_runner, "validate_registry", lambda p: None):
            runner.run_all(
                [rec],
                tmp_path / "out",
                on_final=lambda r, x: None,
                on_export=lambda r, x: exports.append(x),
            )
    assert len(sessions.calls) == 2
    assert exports[0].export_status == "ok" and exports[0].export_only is False


# ── the pipeline: the archive first, then the row, in the stamp's transaction ─────────────────


def _with_extension(home: Path) -> None:
    ext = home / "Ghidra" / "Extensions" / "BinExport"
    (ext / "lib").mkdir(parents=True, exist_ok=True)
    (ext / "extension.properties").write_text("version=11.4.3\n")
    (ext / "lib" / "BinExport.jar").write_bytes(b"jar")


def _scan(fs: Path, ws_dir: Path, home: Path, sessions: _Sessions, **kw: Any) -> AnalyzeResult:
    with patch.object(GhidraRunner, "run_ghidra", lambda self, *a, **k: sessions(self, *a, **k)):
        with Workspace(ws_dir) as ws:
            return run_analyze(fs, ws, _e2e_cfg(home), **kw)


def _exports(db: Path) -> dict[str, tuple[str | None, dict[str, Any] | None]]:
    conn = open_db(db)
    try:
        return {
            r["name"]: (r["binexport_status"], json.loads(r["binexport_scan_meta"] or "null"))
            for r in conn.execute(
                "SELECT name, binexport_status, binexport_scan_meta FROM binaries"
            )
        }
    finally:
        conn.close()


def test_a_usable_export_is_archived_and_recorded_with_what_made_it(tmp_path: Path) -> None:
    """★ The export and its report are gzip-compressed into binexport/ beside analysis.db, named by
    (sha256, pass_version); the row records ok and a meta naming the archive, the export hash and
    the budget; the raw export files are gone from the output directory.

    MUTATION (verified RED): skip the archive -> no file -> RED; leave the export stamp out of the
    ingest -> status NULL -> RED."""
    from tests.unit.lib.test_pipeline import _NAMES

    fs = _firmware(tmp_path)
    home = _ghidra(tmp_path)
    _with_extension(home)
    result = _scan(fs, tmp_path / "ws", home, _Sessions({n: ["ok"] for n in _NAMES}))
    got = _exports(tmp_path / "ws" / "analysis.db")
    assert {s for s, _m in got.values()} == {"ok"}
    status, meta = got[_NAMES[0]]
    assert meta is not None and meta["builder"] == "fallback" and meta["export_hash"]
    archived = tmp_path / "ws" / "binexport" / meta["archive"]
    assert archived.is_file() and gzip.decompress(archived.read_bytes()).startswith(b"export of")
    sha = _state(tmp_path / "ws" / "analysis.db")[_NAMES[0]]["sha256"]
    stem = archive_names(sha, meta["pass_version"])[0].removesuffix(".BinExport.gz")
    assert meta["archive"].startswith(stem + "_") and meta["archive"].endswith(".BinExport.gz")
    assert not list((tmp_path / "ws" / "ghidra_output").glob("*.BinExport"))
    assert result.exports_by_status == {"ok": len(_NAMES)}


def test_a_scan_without_the_extension_records_extension_missing_and_does_not_rerun(
    tmp_path: Path,
) -> None:
    """★ No extension: the scan succeeds, its binaries read extension_missing, and the next scan —
    still without it — re-runs none of them (the same answer would come back after a full
    re-analysis); once the extension is there, they are re-run.

    MUTATION (verified RED): re-run extension_missing whatever the extension -> dirty on the second
    scan -> RED."""
    from tests.unit.lib.test_pipeline import _NAMES

    fs = _firmware(tmp_path)
    home = _ghidra(tmp_path)

    def missing() -> _Sessions:
        s = _Sessions({n: ["ok"] for n in _NAMES})
        real = s.__call__

        def call(*a: Any, **k: Any) -> GhidraResult:
            r = real(*a, **k)
            r.export_status, r.export_file, r.export_report_file = "extension_missing", None, None
            return r

        s.__call__ = call  # type: ignore[method-assign]
        return s

    first = missing()
    with patch.object(
        GhidraRunner, "run_ghidra", lambda self, *a, **k: first.__call__(self, *a, **k)
    ):
        with Workspace(tmp_path / "ws") as ws:
            run_analyze(fs, ws, _e2e_cfg(home))
    assert {s for s, _m in _exports(tmp_path / "ws" / "analysis.db").values()} == {
        "extension_missing"
    }
    again = _scan(fs, tmp_path / "ws", home, _Sessions({}))
    assert again.dirty_count == 0
    _with_extension(home)
    redo = _scan(fs, tmp_path / "ws", home, _Sessions({n: ["ok"] for n in _NAMES}))
    assert redo.dirty_count == len(_NAMES)


def test_a_rescan_of_an_upgraded_binary_that_fails_drops_its_earlier_rows(tmp_path: Path) -> None:
    """Q-5. A binary extracted by another Ghidra than this scan's is re-extracted; when that fails,
    its old rows go (read as having no extraction), never served as this decompiler's.

    MUTATION (verified RED): keep the rows on that failure -> functions still there -> RED."""
    from tests.unit.lib.test_pipeline import _NAMES

    fs = _firmware(tmp_path)
    home = _ghidra(tmp_path, "11.0")
    _with_extension(home)
    _scan(fs, tmp_path / "ws", home, _Sessions({n: ["ok"] for n in _NAMES}))
    home = _ghidra(tmp_path, "11.1")  # the decompiler upgraded in place
    target = _NAMES[0]
    plan = {n: ["ok"] for n in _NAMES}
    plan[target] = ["scan_failed", "scan_failed"]
    _scan(fs, tmp_path / "ws", home, _Sessions(plan))
    st = _state(tmp_path / "ws" / "analysis.db")[target]
    assert (st["ghidra_ok"], st["pass_version"], st["functions"]) == (0, None, [])
    assert _exports(tmp_path / "ws" / "analysis.db")[target][0] == "scan_failed:timeout"


# ── the next scan: which extracted binaries are re-run for their export ───────────────────────


def _db(tmp_path: Path, rows: list[tuple[str, str | None, dict[str, Any] | None]]) -> Path:
    db = tmp_path / "analysis.db"
    conn = open_db(db)
    for sha, status, meta in rows:
        conn.execute(
            "INSERT INTO binaries (name, sha256, ghidra_ok, binexport_status, binexport_scan_meta) "
            "VALUES (?, ?, 1, ?, ?)",
            (sha[:4], sha, status, json.dumps(meta) if meta is not None else None),
        )
    conn.commit()
    conn.close()
    return db


def _archive(dest: Path, sha: str) -> dict[str, Any]:
    dest.mkdir(parents=True, exist_ok=True)
    exp, rep = archive_names(sha, "pv")
    (dest / exp).write_bytes(gzip.compress(b"export"))
    (dest / rep).write_bytes(gzip.compress(b"{}"))
    return {"export_hash": "H", "archive": exp, "report_archive": rep, "budget_seconds": 300}


@pytest.mark.parametrize(
    ("status", "meta_kind", "available", "expect"),
    [
        (None, None, True, "no_export_recorded"),
        ("ok", "intact", True, None),
        ("ok", "moved", True, "export_hash_changed"),
        ("ok", "moved", False, None),  # no extension here: an export cannot be re-made
        ("ok", "missing", True, "archive_missing"),
        ("ok", "truncated", True, "archive_missing"),
        ("ok", "missing", False, "archive_missing"),  # the status is corrected either way
        ("degraded", "intact", True, None),
        ("extension_missing", None, False, None),
        ("extension_missing", None, True, "extension_now_available"),
        ("failed:archive_error", None, True, "archive_error"),
        ("failed:archive_error", None, False, None),
        ("failed:Boom", "intact", True, None),
        ("failed:Boom", "moved", True, "export_hash_changed"),
        ("failed:timeout", "small_budget", True, "export_budget_larger"),
        ("failed:timeout", "same_budget", True, None),
        ("failed:timeout", "same_budget", False, None),
    ],
)
def test_which_exports_a_scan_remakes(
    tmp_path: Path, status: str | None, meta_kind: str | None, available: bool, expect: str | None
) -> None:
    """★ Per recorded status, when an already-extracted binary is re-scanned for its export: the
    recorded status never outlives its archive (red line), an export hash that moved re-makes it,
    a timeout only at a larger budget, any other failure only with other code, and nothing is
    re-run for an export this scan could not make.

    MUTATION (verified RED): trust an ok status without checking its archive -> RED; re-run
    failed:timeout at the same budget -> RED; ignore the export hash -> RED."""
    sha = "a" * 64
    dest = tmp_path / "binexport"
    meta: dict[str, Any] | None = None
    if meta_kind is not None:
        meta = _archive(dest, sha)
        if meta_kind == "moved":
            meta["export_hash"] = "OLD"
        elif meta_kind == "missing":
            (dest / meta["archive"]).unlink()
        elif meta_kind == "truncated":
            data = (dest / meta["archive"]).read_bytes()
            (dest / meta["archive"]).write_bytes(data[: len(data) // 2])
        elif meta_kind == "small_budget":
            meta["budget_seconds"] = 60
        elif meta_kind == "same_budget":
            meta["budget_seconds"] = 600  # what phase 2 gave it: the doubled base of 300
    db = _db(tmp_path, [(sha, status, meta)])
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF" + b"\0" * 100)  # small: the retry budget is 2 x 300
    rec = ElfRecord(path=binary, name="bin", arch="x", elf_type="executable", sha256=sha)
    check = ExportCheck("H" if available else None, dest, 300)
    conn = open_db(db)
    try:
        redo = _export_redo(conn, [rec], {sha}, check)
    finally:
        conn.close()
    assert redo.get(sha) == expect


def test_an_upgraded_decompiler_redoes_its_binaries_on_a_plain_scan(tmp_path: Path) -> None:
    """U-1. A plain scan (no --reanalyze) re-extracts every binary another Ghidra produced — both
    versions known; an unknown on either side decides nothing.

    MUTATION (verified RED): keep the check to --reanalyze only -> nothing re-runs -> RED."""
    db = tmp_path / "analysis.db"
    conn = open_db(db)
    for sha, gv in (("a" * 64, "11.4.2"), ("b" * 64, "11.4.3"), ("c" * 64, "unknown")):
        conn.execute(
            "INSERT INTO binaries (name, sha256, ghidra_ok, ghidra_version) VALUES (?, ?, 1, ?)",
            (sha[:4], sha, gv),
        )
    conn.commit()
    try:
        shas = ["a" * 64, "b" * 64, "c" * 64]
        assert toolchain_changed(conn, shas, "11.4.3") == {"a" * 64}
        assert toolchain_changed(conn, shas, "unknown") == set()
        assert toolchain_changed(conn, shas, None) == set()
    finally:
        conn.close()


def test_an_older_analysis_db_opens_with_the_export_columns_unset(tmp_path: Path) -> None:
    """A database from before exports opens with binexport_status / binexport_scan_meta and the
    decompile columns present and NULL — read as "no export" (re-scanned once)."""
    db = tmp_path / "old.db"
    raw = sqlite3.connect(db)
    raw.execute("CREATE TABLE binaries (id INTEGER PRIMARY KEY, name TEXT, sha256 TEXT UNIQUE)")
    raw.execute(
        "CREATE TABLE functions "
        "(id INTEGER PRIMARY KEY, binary_id INTEGER, name TEXT, address TEXT)"
    )
    raw.execute("INSERT INTO binaries (name, sha256) VALUES ('old', 'x')")
    raw.commit()
    raw.close()
    conn = open_db(db)
    try:
        row = conn.execute("SELECT binexport_status, binexport_scan_meta FROM binaries").fetchone()
        assert tuple(row) == (None, None)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(functions)")}
        assert {"decompile_status", "decompile_retried"} <= cols
    finally:
        conn.close()


def test_a_timeout_is_retried_once_under_another_decompiler(tmp_path: Path) -> None:
    """A binary that timed out at the budget this scan would give is skipped — unless the Ghidra it
    timed out under (recorded with its outcome) is not this scan's: another decompiler is a
    different attempt. Unrecorded or unknown versions compare nothing.

    MUTATION (verified RED): drop the decompiler comparison -> still skipped -> RED."""
    from treasure_map.lib.analyze.db_ingest import _timeout_skips

    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF" + b"\0" * 100)
    sha = "a" * 64
    rec = ElfRecord(path=binary, name="bin", arch="x", elf_type="executable", sha256=sha)
    conn = open_db(tmp_path / "analysis.db")
    conn.execute(
        "INSERT INTO binaries (name, sha256, ghidra_ok, ghidra_status_reason, timeout_budget, "
        "timeout_pass_version, binexport_scan_meta) VALUES ('bin', ?, 0, 'timeout', 600, 'pv', ?)",
        (sha, json.dumps({"ghidra_version": "11.4.2"})),
    )
    conn.commit()
    try:

        def skipped(gv: str | None) -> bool:
            return sha in _timeout_skips(
                conn, [rec], pass_version="pv", timeout_base=300, ghidra_version=gv
            )

        assert skipped("11.4.2") is True
        assert skipped("11.4.3") is False
        assert skipped("unknown") is True and skipped(None) is True
    finally:
        conn.close()


def test_the_scan_says_how_many_binaries_cannot_be_diffed(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The scan's summary counts the exports by status, and says on stderr how many binaries have
    no usable export — naming the extension when that is why.

    MUTATION (verified RED): count extension_missing as diffable -> no warning -> RED."""
    from treasure_map.cli.analyze_cli import _report_exports

    _report_exports({"ok": 2, "degraded": 1, "extension_missing": 3}, "no BinExport extension at x")
    out = capsys.readouterr()
    assert "exports (for tmap diff): 1 degraded, 3 extension_missing, 2 ok" in out.out
    assert "3 binaries have no usable export" in out.err and "tmap init" in out.err
    _report_exports({"ok": 2}, None)
    assert capsys.readouterr().err == ""


def test_an_archive_is_never_overwritten_in_place(tmp_path: Path) -> None:
    """Each archive written gets names of its own (a session part): re-archiving a binary writes
    beside the files its row names, so an interrupt before the new row is committed leaves the old
    row with its own, intact files.

    MUTATION (verified RED): drop the session part from the names -> the second write lands on the
    first -> RED."""
    from treasure_map.lib.binexport_archive import write_archive

    exp, rep = tmp_path / "x.BinExport", tmp_path / "x.export_report.json"
    exp.write_bytes(b"first")
    rep.write_text("{}")
    dest = tmp_path / "binexport"
    first = write_archive(exp, rep, dest, "a" * 64, "pv")
    exp.write_bytes(b"second")
    second = write_archive(exp, rep, dest, "a" * 64, "pv")
    assert first.export_name != second.export_name
    assert gzip.decompress((dest / first.export_name).read_bytes()) == b"first"


def test_the_rescan_tier_counts_what_a_scan_would_remake_of_the_current_firmware(
    tmp_path: Path,
) -> None:
    """★ stale_exports counts only the firmware's current binaries (a row the last scan did not see
    is no longer there to re-scan — counting it kept a run "out of date" forever), and counts an
    ok status whose archive is gone and an archive that could not be written, which a scan
    re-makes.

    MUTATION (verified RED): read every binaries row -> the vanished one counts -> RED; leave
    archive_error out -> RED."""
    from treasure_map.lib.binexport_archive import stale_exports

    dest = tmp_path / "binexport"
    good = _archive(dest, "a" * 64)
    good["export_hash"] = "H"
    gone = _archive(dest, "b" * 64)
    gone["export_hash"] = "H"
    (dest / gone["archive"]).unlink()
    db = tmp_path / "analysis.db"
    conn = open_db(db)
    for sha, status, meta, seen in (
        ("a" * 64, "ok", good, "now"),
        ("b" * 64, "ok", gone, "now"),
        ("c" * 64, "failed:archive_error", {"export_hash": "H"}, "now"),
        ("d" * 64, None, None, "before"),  # no longer in the firmware
    ):
        conn.execute(
            "INSERT INTO binaries (name, sha256, ghidra_ok, binexport_status, binexport_scan_meta, "
            "last_seen_at) VALUES (?, ?, 1, ?, ?, ?)",
            (
                sha[:4],
                sha,
                status,
                json.dumps(meta) if meta else None,
                "2026-10-30" if seen == "now" else "2026-01-01",
            ),
        )
    conn.commit()
    conn.close()
    assert stale_exports(str(db), "H") == (2, 3)
    assert stale_exports(str(db), None) == (1, 3)  # without the extension: only the gone archive
