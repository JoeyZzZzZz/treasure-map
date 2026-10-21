# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""`tmap diff`: the two runs as roles, and bringing a run that is out of date current first.

Zero real data: every run, binary and hash is synthetic. The atlas, each run's analysis.db and its
firmware root are built in the test's own home. The rescan and the diff itself are replaced by
recording stand-ins, because what is under test is the order of decisions — what is refused before
anything runs, what is rescanned, what is said about it, and what happens after — not the scan or
the aligner.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner, Result

from treasure_map.cli import hunt_cli
from treasure_map.cli.main import main
from treasure_map.lib.analyze import ghidra_runner
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.config.config import load_config
from treasure_map.lib.diff import driver
from treasure_map.lib.diff.layer0 import make_diff_id
from treasure_map.lib.errors import ConfigError
from treasure_map.lib.rescan_version import CodeStamp
from treasure_map.lib.storage.connection import open_db
from treasure_map.version import UNKNOWN_VERSION

BUILD = "beefbeefbeefbeef"
OLD_BUILD = "facefeedfacefeed"
COMMIT = "c" * 40
OLD_COMMIT = "d" * 40
SHA = {"libx": "a" * 64, "liby": "b" * 64}
SEEN = "2026-01-01 00:00:00"


class Env:
    """An atlas with runs, each with an analysis.db under the configured workspace_dir and a
    firmware root; the running pipeline is ``BUILD`` and the running install ``COMMIT``."""

    def __init__(self, tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.tmp = tmp
        self.mp = monkeypatch
        self.ws_dir = load_config(None).workspace_dir
        self.atlas_path = tmp / "atlas.db"
        open_atlas(self.atlas_path).close()
        self.rescans: list[dict[str, Any]] = []
        self.diffs: list[tuple[str, ...]] = []
        # What the stand-in rescan does: "fix" brings each run it is given current, "fail" says it
        # failed and changes nothing (what the real one does on a failure), or an exception.
        self.rescan_does: Any = "fix"
        self.after_fix: dict[str, Any] = {}
        self.diff_raises: Exception | None = None
        self.full_cancelled = False
        self.running(build=BUILD, commit=COMMIT)
        monkeypatch.setattr(hunt_cli, "rescan", self._rescan)
        monkeypatch.setattr(driver, "run_full_diff", self._full)
        monkeypatch.setattr(driver, "run_version_diff", self._single)

    def running(self, *, build: str, commit: str) -> None:
        """The extraction pipeline and install that are running, as both the CLI and the driver
        read them."""
        self.mp.setattr(ghidra_runner, "current_pass_version", lambda: build)
        self.mp.setattr(driver, "_current_pass_version", lambda: build)
        self.mp.setattr(hunt_cli, "installed_commit", lambda: commit)
        self.mp.setattr(driver, "_installed_commit", lambda: commit)
        self.commit = commit

    # ── building the world ──

    def run(
        self,
        run_id: str,
        *,
        build: str | None = BUILD,
        db_build: str | list[str] | None = None,
        hunt_commit: str | None = COMMIT,
        hunt_instances: int | None = 0,
        scan_status: str = "complete",
        firmware: str = "present",
        under_workspace_dir: bool = True,
        binaries: tuple[str, ...] = ("libx",),
    ) -> None:
        """One run. ``db_build`` is what its analysis.db holds (default: the run's own build; a
        list gives one pass version per binary); ``firmware`` is present / gone / none."""
        base = self.ws_dir if under_workspace_dir else self.tmp / "elsewhere"
        db = base / run_id / "analysis.db"
        db.parent.mkdir(parents=True, exist_ok=True)
        conn = open_db(db)
        builds = db_build if isinstance(db_build, list) else [db_build or build] * len(binaries)
        for name, pv in zip(binaries, builds, strict=True):
            conn.execute(
                "INSERT INTO binaries (name, path, sha256, pass_version, last_seen_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (name, f"/lib/{name}", SHA[name], pv, SEEN),
            )
        conn.commit()
        conn.close()
        fw: str | None = None
        if firmware != "none":
            fw_dir = self.tmp / "fw" / run_id
            if firmware == "present":
                fw_dir.mkdir(parents=True)
            fw = str(fw_dir)
        atlas = open_atlas(self.atlas_path)
        atlas.execute(
            "INSERT INTO run (run_id, analysis_db_path, firmware_path, build_hash, hunt_commit, "
            "hunt_instances, scan_status, tool_version, ghidra_version, binaries) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, '0.0.1', 'ghidra-x', ?)",
            (run_id, str(db), fw, build, hunt_commit, hunt_instances, scan_status, len(binaries)),
        )
        atlas.commit()
        atlas.close()

    def diff_row(self, run_a: str, run_b: str, binary: str = "libx") -> str:
        did = make_diff_id(run_a, run_b, binary)
        atlas = open_atlas(self.atlas_path)
        atlas.execute(
            "INSERT INTO diff_meta (diff_id, run_a_id, run_b_id, binary_a, binary_b, diff_ok) "
            "VALUES (?, ?, ?, ?, ?, 1)",
            (did, run_a, run_b, binary, binary),
        )
        atlas.commit()
        atlas.close()
        return did

    def diff_ids(self) -> list[tuple[str, str, str]]:
        atlas = open_atlas(self.atlas_path)
        try:
            return [
                (r[0], r[1], r[2])
                for r in atlas.execute(
                    "SELECT diff_id, run_a_id, run_b_id FROM diff_meta ORDER BY diff_id"
                )
            ]
        finally:
            atlas.close()

    def set_run(self, run_id: str, **cols: Any) -> None:
        atlas = open_atlas(self.atlas_path)
        sets = ", ".join(f"{c} = ?" for c in cols)
        atlas.execute(f"UPDATE run SET {sets} WHERE run_id = ?", (*cols.values(), run_id))
        atlas.commit()
        atlas.close()

    def instance(self, run_id: str) -> None:
        atlas = open_atlas(self.atlas_path)
        cur = atlas.execute(
            "INSERT INTO pattern (source_class, sink_class, call_sequence_shape, "
            "structural_fingerprint, fingerprint_algo_version) "
            "VALUES ('external_input', 'cmd', 'source->sink', ?, 'v1')",
            (f"fp_{run_id}",),
        )
        atlas.execute(
            "INSERT INTO instance (pattern_id, evidence_ref, source_run_id) VALUES (?, ?, ?)",
            (cur.lastrowid, f"{run_id}#deadbeef:cafe@cmd", run_id),
        )
        atlas.commit()
        atlas.close()

    # ── the stand-ins ──

    def _rescan(
        self,
        run_ids: tuple[str, ...],
        force: bool,
        dry_run: bool,
        config: Path | None,
        atlas_path: Path | None,
    ) -> None:
        self.rescans.append(
            {"run_ids": run_ids, "force": force, "dry_run": dry_run, "atlas_path": atlas_path}
        )
        if isinstance(self.rescan_does, BaseException):
            raise self.rescan_does
        if self.rescan_does == "fail":
            print("  FAILED: something broke")
            return
        for rid in run_ids:
            atlas = open_atlas(self.atlas_path)
            db = atlas.execute(
                "SELECT analysis_db_path FROM run WHERE run_id = ?", (rid,)
            ).fetchone()[0]
            atlas.close()
            adb = sqlite3.connect(db)
            adb.execute(
                "UPDATE binaries SET pass_version = ?", (ghidra_runner.current_pass_version(),)
            )
            adb.commit()
            adb.close()
            self.set_run(
                rid,
                build_hash=ghidra_runner.current_pass_version(),
                hunt_commit=self.commit,
                scan_status="complete",
                **self.after_fix,
            )

    def _full(self, atlas: sqlite3.Connection, run_a: str, run_b: str, **kw: Any) -> Any:
        self.diffs.append((run_a, run_b))
        if self.diff_raises is not None:
            raise self.diff_raises
        return driver.FullDiffSummary(
            driver.FullDiffPlan((), (), (), ()), (), cancelled=self.full_cancelled
        )

    def _single(
        self, atlas: sqlite3.Connection, run_a: str, run_b: str, binary: str, **kw: Any
    ) -> Any:
        self.diffs.append((run_a, run_b, binary))
        if self.diff_raises is not None:
            raise self.diff_raises
        did = make_diff_id(run_a, run_b, binary)
        atlas.execute(
            "INSERT OR REPLACE INTO diff_meta (diff_id, run_a_id, run_b_id, binary_a, binary_b, "
            "diff_ok) VALUES (?, ?, ?, ?, ?, 1)",
            (did, run_a, run_b, binary, binary),
        )
        atlas.commit()
        return driver.DiffSummary(
            diff_id=did,
            binary=binary,
            matched_pairs=1,
            version_skew=False,
            delta_layer_changed=0,
            delta_layer_unchanged=0,
            delta_undetermined=0,
            warnings=(),
        )

    # ── running the command ──

    def tmap(self, *args: str) -> Result:
        return CliRunner().invoke(main, ["diff", *args, "--atlas", str(self.atlas_path)])

    def diff(self, before: str = "old", after: str = "new", *extra: str) -> Result:
        return self.tmap("--before", before, "--after", after, *extra)


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Env:
    return Env(tmp_path, monkeypatch)


def _stale_hunt(env: Env, run_id: str = "new", **kw: Any) -> None:
    env.run(run_id, hunt_commit=OLD_COMMIT, **kw)


def _refused_before_anything(env: Env, res: Result, *, rows: list[Any] | None = None) -> None:
    assert res.exit_code != 0, res.output
    assert env.rescans == [] and env.diffs == []
    if rows is not None:
        assert env.diff_ids() == rows


_HC = "src-hunthunthunthunt"
_SC = '{"code":"src-pipe","config":{"xref_fold_edge_threshold":25000},"deps":{"pyelftools":"0.33"}}'


def test_the_diff_plan_judges_new_stamp_runs_by_their_code_stamp(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``tmap diff``'s rescan plan (``_diff_rescan_plan``) reads the CODE STAMP of a new-stamp run,
    not its commit: a pair whose stamps match the running code is diffed with no rescan even though
    their commits differ, and a run whose scan stamp has moved is rescanned first. The other
    diff-cli tests build only stampless runs (commit fallback), leaving this branch untested (audit
    G01).

    MUTATION: in ``_diff_rescan_plan`` judge against a bogus current stamp -> the matching pair is
    rescanned/refused though its stamps match, and the no-rescan assert goes RED.
    """
    monkeypatch.setattr(
        hunt_cli.rescan_version, "current_code_stamp", lambda _cfg: CodeStamp(hunt=_HC, scan=_SC)
    )
    env.run("old")
    env.run("new")
    # both current by code stamp, commits differing from each other and from the install
    env.set_run("old", hunt_code_version=_HC, scan_stamp=_SC, hunt_commit="commit0old")
    env.set_run("new", hunt_code_version=_HC, scan_stamp=_SC, hunt_commit="commit0new")
    res = env.diff("old", "new", "--binary", "libx")
    assert res.exit_code == 0, res.output
    assert env.rescans == [], "matching code stamps must not trigger a rescan"
    assert env.diffs == [("old", "new", "libx")]

    # the after-side's scan stamp has moved on one config leaf -> it is rescanned first
    env.rescans.clear()
    env.diffs.clear()
    env.after_fix = {"hunt_code_version": _HC, "scan_stamp": _SC}
    env.set_run("new", scan_stamp=_SC.replace("25000", "10000"))
    res2 = env.diff("old", "new", "--binary", "libx")
    assert res2.exit_code == 0, res2.output
    assert [r["run_ids"] for r in env.rescans] == [("new",)], (
        "a moved scan stamp is rescanned first"
    )


# ── the roles ────────────────────────────────────────────────────────────────────────────────


def test_before_is_side_a_and_after_side_b_in_any_option_order(env: Env) -> None:
    """MUTATION (verified RED): swap the two sides where the command hands them to the diff ->
    the stored row reads run_a_id = the --after run."""
    env.run("old")
    env.run("new")
    res = env.diff("old", "new", "--binary", "libx")
    assert res.exit_code == 0, res.output
    assert env.diff_ids() == [(make_diff_id("old", "new", "libx"), "old", "new")]
    again = env.tmap("--after", "new", "--before", "old", "--binary", "libx")
    assert again.exit_code == 0, again.output
    assert env.diff_ids() == [(make_diff_id("old", "new", "libx"), "old", "new")]
    assert env.diffs == [("old", "new", "libx")] * 2


def test_the_positional_form_is_refused_with_the_command_that_replaces_it(env: Env) -> None:
    """Exit 2 with a command ready to copy, every value quoted for the shell and every other option
    carried over. Nothing is opened: no rescan, no diff, no row.

    MUTATION (verified RED): make --before / --after required at the click layer -> click refuses
    first with its own "Missing option" and no command to copy. MUTATION (verified RED): accept the
    two values as the roles -> exit 0. MUTATION (verified RED): leave the other options out of the
    suggestion -> no --binary in it."""
    env.run("old")
    env.run("new")
    before = env.diff_ids()
    res = env.tmap("old", "new", "--binary", "a b", "--force")
    assert res.exit_code == 2, res.output
    assert "tmap diff --before old --after new --binary 'a b' --force --atlas " in res.output
    _refused_before_anything(env, res, rows=before)


@pytest.mark.parametrize("args", [["old"], ["old", "new", "extra"]])
def test_a_positional_form_that_is_not_two_runs_gets_the_usage_line(
    env: Env, args: list[str]
) -> None:
    res = env.tmap(*args)
    assert res.exit_code == 2, res.output
    assert "usage: tmap diff --before <run_id> --after <run_id> [options]" in res.output
    assert "--before old" not in res.output
    _refused_before_anything(env, res)


def test_both_roles_are_required(env: Env) -> None:
    res = env.tmap("--before", "old")
    assert res.exit_code == 2, res.output
    assert "both --before and --after are required." in res.output
    _refused_before_anything(env, res)


def test_a_driver_refusal_says_which_option_each_side_is(env: Env) -> None:
    env.run("old")
    env.run("new")
    env.diff_raises = ConfigError("run B 'new' is something")
    res = env.diff()
    assert res.exit_code != 0
    assert "ConfigError: run B 'new' is something (A = --before, B = --after)" in res.output


# ── swapped roles ────────────────────────────────────────────────────────────────────────────


def test_diffs_recorded_the_other_way_round_refuse_before_anything_runs(env: Env) -> None:
    """The pair is recorded as (new, old); asking for (old, new) is refused before the stale run
    is rescanned, with --no-rescan too; --allow-reverse lets it through and changes nothing else.

    MUTATION (verified RED): check the roles after the rescan -> the rescan runs first.
    MUTATION (verified RED): only warn -> the diff runs. MUTATION (verified RED): skip the check
    under --no-rescan -> the stale refusal is given instead."""
    env.run("old")
    _stale_hunt(env, "new")
    did = env.diff_row("new", "old")
    rows = env.diff_ids()
    res = env.diff()
    _refused_before_anything(env, res, rows=rows)
    assert "1 diffs already exist with these runs the other way round" in res.output
    assert f"`{did}`" in res.output and "--allow-reverse" in res.output

    res = env.diff("old", "new", "--no-rescan")
    _refused_before_anything(env, res, rows=rows)
    assert "the other way round" in res.output

    res = env.diff("old", "new", "--allow-reverse")
    assert res.exit_code == 0, res.output
    assert [r["run_ids"] for r in env.rescans] == [("new",)]
    assert env.diffs == [("old", "new")]


# ── what is refused before anything runs ─────────────────────────────────────────────────────


@pytest.mark.parametrize("stale_side", ["before", "after"])
def test_every_refusal_comes_before_any_rescan(env: Env, stale_side: str) -> None:
    """One side's analysis.db holds another extraction than its run row, the other is out of date:
    refused, and nothing is rescanned — whichever side is checked first.

    MUTATION (verified RED): rescan each run as soon as it is found out of date -> the stale
    before-side is rescanned before the after-side is refused."""
    if stale_side == "before":
        _stale_hunt(env, "old")
        env.run("new", db_build=OLD_BUILD)
    else:
        env.run("old", db_build=OLD_BUILD)
        _stale_hunt(env, "new")
    res = env.diff()
    _refused_before_anything(env, res)
    assert "now holds extraction" in res.output


def test_a_mistyped_binary_is_refused_before_a_rescan(env: Env) -> None:
    """MUTATION (verified RED): leave the binary to the diff -> the rescan runs first."""
    env.run("old")
    _stale_hunt(env, "new")
    res = env.diff("old", "new", "--binary", "nope")
    _refused_before_anything(env, res)
    assert "run 'old': the .so file for binary 'nope' cannot be located" in res.output
    assert "not in this run's binaries" in res.output


@pytest.mark.parametrize("no_rescan", [False, True])
def test_a_scan_that_did_not_finish_is_refused_not_rescanned(env: Env, no_rescan: bool) -> None:
    """Shaped like an interrupted scan: the extraction stamp is current, the hunt stamp and count
    were cleared when it started, and the old candidates are still in the table. Nothing reads it
    as out of date, so it would otherwise be diffed as it is.

    MUTATION (verified RED): only warn -> the diff runs. MUTATION (verified RED): rescan it -> the
    rescan runs."""
    env.run("old")
    env.run("new", hunt_commit=None, hunt_instances=None, scan_status="in_progress")
    env.instance("new")
    res = env.diff("old", "new", *(["--no-rescan"] if no_rescan else []))
    _refused_before_anything(env, res)
    assert "scan_status=in_progress" in res.output and "`tmap rescan new`" in res.output


def test_an_extraction_that_moved_after_the_hunt_is_refused(env: Env) -> None:
    """MUTATION (verified RED): rescan it instead -> the rescan runs."""
    env.run("old")
    env.run("new", db_build=OLD_BUILD)
    res = env.diff()
    _refused_before_anything(env, res)
    assert "`tmap rescan --force new` re-hunts it." in res.output
    assert "(A = --before, B = --after)" in res.output


def test_a_run_with_no_firmware_root_is_refused_with_its_remedy(env: Env) -> None:
    env.run("old")
    _stale_hunt(env, "new", firmware="none")
    res = env.diff()
    _refused_before_anything(env, res)
    assert "this run recorded no firmware root, so it cannot be re-read automatically" in res.output


def test_a_firmware_root_that_is_gone_is_refused_with_how_to_put_it_back(env: Env) -> None:
    """MUTATION (verified RED): answer with the run's stock remedy -> it offers `tmap rescan new`
    as if the directory were there to re-read."""
    env.run("old")
    _stale_hunt(env, "new", firmware="gone")
    res = env.diff()
    _refused_before_anything(env, res)
    assert "no longer exists" in res.output
    assert "`tmap scan <firmware-root> -w new --run-id new`" in res.output
    assert "tmap rescan new` re-reads" not in res.output


def test_a_workspace_outside_the_configured_base_is_refused(env: Env) -> None:
    """MUTATION (verified RED): leave it to the rescan -> the rescan runs."""
    env.run("old")
    _stale_hunt(env, "new", under_workspace_dir=False)
    res = env.diff()
    _refused_before_anything(env, res)
    assert "is not under the configured workspace_dir" in res.output


def test_no_rescan_refuses_a_run_that_is_out_of_date(env: Env) -> None:
    """MUTATION (verified RED): rescan under --no-rescan too -> the rescan runs."""
    env.run("old")
    _stale_hunt(env, "new")
    res = env.diff("old", "new", "--no-rescan")
    _refused_before_anything(env, res)
    assert "ConfigError: run B 'new' is out of date (hunt)" in res.output
    assert "(A = --before, B = --after)" in res.output


# ── what cannot be confirmed either way is diffed as it is ───────────────────────────────────


@pytest.mark.parametrize(
    "case", ["install_records_no_commit", "mixed_extraction", "hunt_unstamped"]
)
def test_a_run_that_cannot_be_confirmed_is_diffed_as_it_is(env: Env, case: str) -> None:
    """Warned about by run and role, diffed, never rescanned — not on a second diff either.

    MUTATION (verified RED): rescan what cannot be confirmed -> the rescan runs."""
    env.run("old")
    if case == "install_records_no_commit":
        env.running(build=BUILD, commit=UNKNOWN_VERSION)
        env.run("new")
        expected = "could not compare hunt commit"
    elif case == "mixed_extraction":
        env.run("new", build="mixed:2", db_build=[BUILD, OLD_BUILD], binaries=("libx", "liby"))
        expected = "could not compare extraction hash"
    else:
        env.run("new", hunt_commit=None)
        expected = "could not compare hunt commit"
    for _ in range(2):
        res = env.diff()
        assert res.exit_code == 0, res.output
        assert f"warning: run 'new' (--after): {expected}" in res.output
        assert "Not rescanned" in res.output
    assert env.rescans == []
    assert env.diffs == [("old", "new")] * 2


def test_an_install_with_no_commit_still_rescans_a_stale_extraction(env: Env) -> None:
    """No commit hides the hunt comparison only; the extraction is still compared.

    MUTATION (verified RED): treat a missing install commit as hiding both -> no rescan."""
    env.running(build=BUILD, commit=UNKNOWN_VERSION)
    env.run("old")
    env.run("new", build=OLD_BUILD)
    res = env.diff()
    assert res.exit_code == 0, res.output
    assert [r["run_ids"] for r in env.rescans] == [("new",)]
    assert "will write this run's hunt_commit as unknown" in res.output
    assert env.diffs == [("old", "new")]


# ── the rescan ───────────────────────────────────────────────────────────────────────────────


def test_a_stale_hunt_is_rescanned_once_and_said_in_full(env: Env) -> None:
    """Only the run proven out of date goes to the rescan; what it is, what it costs and what it
    does to other diffs is said before it starts; then the diff runs.

    MUTATION (verified RED): hand both runs to the rescan -> run_ids holds both. MUTATION (verified
    RED): say the hunt tier's other diffs read source_stale -> that sentence appears."""
    env.run("old")
    _stale_hunt(env, "new")
    res = env.diff()
    assert res.exit_code == 0, res.output
    assert env.rescans == [
        {"run_ids": ("new",), "force": False, "dry_run": False, "atlas_path": env.atlas_path}
    ]
    out = res.output
    assert "run 'new' (--after) is out of date" in out
    assert hunt_cli._TIER_LABEL["hunt"] in out and hunt_cli._TIER_COST["hunt"] in out
    # An old run (no recorded code stamp) is offered for rescan with the generic code-stamp reason;
    # the human wording that `tmap diff`'s rescan plan prints for it.
    assert "hunted before tmap recorded what it ran" in out
    assert "will have their stored baseline read as stale" in out
    assert "will read as source_stale" not in out
    assert hunt_cli._REKEY_WARNING not in out
    assert out.index("is out of date") < out.index("Atlas:")
    assert env.diffs == [("old", "new")]


def test_a_stale_extraction_says_refs_may_be_rekeyed(env: Env) -> None:
    """MUTATION (verified RED): drop the re-key line -> it is missing."""
    env.run("old")
    env.run("new", build=OLD_BUILD)
    res = env.diff()
    assert res.exit_code == 0, res.output
    assert hunt_cli._TIER_LABEL["extraction"] in res.output
    assert hunt_cli._REKEY_WARNING in res.output
    assert "other diffs involving this run will read as source_stale" in res.output
    assert [r["run_ids"] for r in env.rescans] == [("new",)]


def test_a_whole_scan_says_refs_may_be_rekeyed(env: Env) -> None:
    """MUTATION (verified RED): say it on the extraction tier only -> missing here."""
    env.run("old")
    _stale_hunt(env, "new")
    env.mp.setattr(
        hunt_cli, "_rescan_reason", lambda run, **kw: ("incomplete", "the scan has to run again")
    )
    res = env.diff()
    assert res.exit_code == 0, res.output
    assert hunt_cli._TIER_LABEL["incomplete"] in res.output
    assert hunt_cli._REKEY_WARNING in res.output


def test_a_hunt_with_no_stored_extraction_says_the_decompiler_runs(env: Env) -> None:
    """The hunt tier, but the analysis.db holds no extraction: the rescan rebuilds it.

    MUTATION (verified RED): word it as a plain re-hunt -> no re-key line, the baseline sentence."""
    env.run("old")
    _stale_hunt(env, "new", binaries=())
    res = env.diff()
    assert res.exit_code == 0, res.output
    assert hunt_cli._TIER_LABEL["hunt"] in res.output
    assert hunt_cli._REKEY_WARNING in res.output
    assert "will read as source_stale" in res.output
    assert "stored baseline read as stale" not in res.output


@pytest.mark.parametrize(("binary", "others"), [(None, 1), ("libx", 2)])
def test_other_diffs_count_everything_this_command_does_not_rerun(
    env: Env, binary: str | None, others: int
) -> None:
    """A full diff re-runs every diff of the pair in this direction; one binary re-runs that one
    only, so the pair's other binary counts as left behind. A diff of the run with a third run
    always counts.

    MUTATION (verified RED): leave out only the --binary diff in both modes -> the full diff counts
    the pair's other binary. MUTATION (verified RED): leave out the whole pair in both modes ->
    the --binary diff misses it."""
    env.run("old", binaries=("libx", "liby"))
    _stale_hunt(env, "new", binaries=("libx", "liby"))
    env.run("third")
    env.diff_row("old", "new", "libx")
    env.diff_row("old", "new", "liby")
    env.diff_row("third", "new", "libx")
    res = env.diff("old", "new", *(["--binary", binary] if binary else []))
    assert res.exit_code == 0, res.output
    assert f"  {others} other diffs involving this run will" in res.output


def test_a_rescan_that_did_not_bring_the_run_current_refuses_the_diff(env: Env) -> None:
    """The rescan reports a failure and returns normally: the run is read again, found still out
    of date, and the diff is refused — without a second rescan.

    MUTATION (verified RED): skip the look after the rescan -> the diff runs."""
    env.run("old")
    _stale_hunt(env, "new")
    env.rescan_does = "fail"
    res = env.diff()
    assert res.exit_code != 0
    assert "still out of date after the rescan" in res.output
    assert "Not rescanning again" in res.output and "(A = --before, B = --after)" in res.output
    assert len(env.rescans) == 1 and env.diffs == []


def test_versions_that_differ_after_the_rescan_need_force(env: Env) -> None:
    """MUTATION (verified RED): do not compare versions after the rescan -> the diff runs."""
    env.run("old")
    _stale_hunt(env, "new")
    env.after_fix = {"ghidra_version": "ghidra-y"}
    res = env.diff()
    assert res.exit_code != 0
    assert "after the rescan, the two runs were produced by different" in res.output
    assert env.diffs == []
    _stale_hunt(env, "newer")
    res = env.diff("old", "newer", "--force")
    assert res.exit_code == 0, res.output
    assert env.diffs == [("old", "newer")]


@pytest.mark.parametrize(
    "interrupt", [SystemExit(130), KeyboardInterrupt()], ids=["decompile", "hunt"]
)
def test_an_interrupted_rescan_stops_before_the_diff(env: Env, interrupt: BaseException) -> None:
    """MUTATION (verified RED): catch only SystemExit -> the hunt stage's interrupt escapes."""
    env.run("old")
    _stale_hunt(env, "new")
    rows = env.diff_ids()
    env.rescan_does = interrupt
    res = env.diff()
    assert res.exit_code == 130, res.output
    assert "Rescan interrupted; the diff did not start. `tmap rescan new`" in res.output
    assert env.diffs == [] and env.diff_ids() == rows


def test_another_exit_from_the_rescan_is_not_an_interrupt(env: Env) -> None:
    env.run("old")
    _stale_hunt(env, "new")
    env.rescan_does = SystemExit(2)
    res = env.diff()
    assert res.exit_code == 2
    assert "Rescan interrupted" not in res.output and env.diffs == []


def test_an_interrupted_full_diff_does_not_exit_zero(env: Env) -> None:
    """The completed binaries are kept, but a run that did not finish is not a success.

    MUTATION: drop the cancelled exit after the full-diff roll-up -> RED (exit 0)."""
    env.run("old")
    env.run("new")
    env.full_cancelled = True
    res = env.diff()
    assert "Interrupted" in res.output
    assert res.exit_code == 130, res.output


def test_a_partial_rescan_does_not_stop_the_diff(env: Env) -> None:
    """Some runs failing to refresh is not an interrupt: the diff goes on, and the recheck after
    the rescan names whatever is still stale.

    MUTATION: treat RESCAN_PARTIAL_EXIT like any other exit (re-raise it) -> RED."""
    env.run("old")
    _stale_hunt(env, "new")
    env.rescan_does = SystemExit(hunt_cli.RESCAN_PARTIAL_EXIT)
    res = env.diff()
    assert "Rescan interrupted" not in res.output
    assert "after the rescan" in res.output, res.output  # the recheck ran and named what is stale
    assert res.exit_code != hunt_cli.RESCAN_PARTIAL_EXIT, res.output
