# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Binaries held by one run of a pair only (lib/query/binary_presence): taken out of the blind
spots when the other run provably holds nothing like them, listed with their candidates and the
recorded references to them, and judged one by one on the run pair.

Zero real data. The fixture keeps the real path forms: a binary's recorded path is absolute (it
carries the run's unpack directory), a non-binary file's and a symlink's are relative to the
firmware root.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from treasure_map import mcp_app
from treasure_map.cli import hunt_cli
from treasure_map.lib import overlay
from treasure_map.lib.analyze.ghidra_runner import current_pass_version
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.errors import ConfigError
from treasure_map.lib.query import binary_presence as bp
from treasure_map.lib.query import diff_align as da
from treasure_map.lib.query import diff_review as dr
from treasure_map.lib.query import patch_view as pv
from treasure_map.lib.storage.connection import open_db
from treasure_map.version import UNKNOWN_VERSION

PAIR = "runA::runB"
DIFF = "runA::runB::libx"


def _sha(c: str) -> str:
    return c * 64


class World:
    """Two runs, each with its analysis.db and firmware root; one diffed binary (libx)."""

    def __init__(self, tmp: Path) -> None:
        self.path = tmp / "atlas.db"
        self.atlas = open_atlas(self.path)
        self.atlas.execute("PRAGMA synchronous = OFF")
        self.root = {"a": str(tmp / "fwA" / "squashfs-root"), "b": str(tmp / "fwB" / "root")}
        self.run = {"a": "runA", "b": "runB"}
        self.adb: dict[str, sqlite3.Connection] = {}
        self.db_path: dict[str, Path] = {}
        self._n = 0
        for side in ("a", "b"):
            db = tmp / f"analysis_{side}.db"
            conn = open_db(db)
            conn.execute("PRAGMA synchronous = OFF")
            self.adb[side] = conn
            self.db_path[side] = db
            self.atlas.execute(
                "INSERT INTO run (run_id, hunt_commit, build_hash, hunt_instances, "
                "analysis_db_path, firmware_path) VALUES (?, 'facade', ?, 10, ?, ?)",
                (self.run[side], current_pass_version(), str(db), self.root[side]),
            )
        self.binary("a", "lib/libx", _sha("1"))
        self.binary("b", "lib/libx", _sha("2"))
        self.atlas.execute(
            "INSERT INTO diff_meta (diff_id, run_a_id, run_b_id, binary_a, binary_b, sha256_a, "
            "sha256_b, diff_ok, version_skew) VALUES (?, 'runA', 'runB', 'libx', 'libx', ?, ?, "
            "1, 0)",
            (DIFF, _sha("1"), _sha("2")),
        )

    def binary(self, side: str, rel: str, sha: str, name: str | None = None) -> str:
        path = f"{self.root[side]}/{rel}"
        self.adb[side].execute(
            "INSERT INTO binaries (name, path, sha256, last_seen_at) VALUES (?, ?, ?, 't1')",
            (name or rel.rsplit("/", 1)[-1], path, sha),
        )
        return path

    def cand(self, side: str, rel: str, sha: str, sink_class: str = "cmd", n: int = 1) -> list[str]:
        """``n`` candidates of a binary not diffed (it holds them; no diff names its hash)."""
        refs = []
        for _ in range(n):
            self._n += 1
            ref = f"{self.run[side]}#{sha[:8]}:{self._n:08x}@{sink_class}@0x10"
            self.atlas.execute(
                "INSERT INTO instance (pattern_id, evidence_ref, source_run_id, "
                "binary_content_hash, binary_path, sink_anchor) VALUES (?, ?, ?, ?, ?, 'x')",
                (self._pattern(sink_class), ref, self.run[side], sha, f"{self.root[side]}/{rel}"),
            )
            refs.append(ref)
        return refs

    def _pattern(self, sink_class: str) -> int:
        row = self.atlas.execute(
            "SELECT pattern_id FROM pattern WHERE sink_class = ?", (sink_class,)
        ).fetchone()
        if row is not None:
            return int(row[0])
        cur = self.atlas.execute(
            "INSERT INTO pattern (source_class, sink_class, call_sequence_shape, "
            "structural_fingerprint, fingerprint_algo_version) VALUES "
            "('external_input', ?, 's->k', ?, 'v1')",
            (sink_class, f"fp_{sink_class}"),
        )
        return int(cur.lastrowid or 0)

    def file(self, side: str, rel: str, sha: str, kind: str = "shell_script") -> int:
        cur = self.adb[side].execute(
            "INSERT INTO non_binary_files (kind, name, path, sha256) VALUES (?, ?, ?, ?)",
            (kind, rel.rsplit("/", 1)[-1], rel, sha),
        )
        return int(cur.lastrowid or 0)

    def symlink(self, side: str, rel: str) -> None:
        self.adb[side].execute(
            "INSERT INTO fs_symlinks (link_path, link_name, target_raw, resolved) "
            "VALUES (?, ?, 'busybox', 1)",
            (rel, rel.rsplit("/", 1)[-1]),
        )

    def call(self, side: str, file_id: int, command: str, line: int) -> None:
        self.adb[side].execute(
            "INSERT INTO script_calls (file_id, command, raw_line, line_number) "
            "VALUES (?, ?, ?, ?)",
            (file_id, command, f"{command} status", line),
        )

    def endpoint(self, side: str, file_id: int, path: str) -> None:
        self.adb[side].execute(
            "INSERT INTO web_endpoints (file_id, asset_type, method, path, source) "
            "VALUES (?, 'html', 'GET', ?, 'xhr')",
            (file_id, path),
        )

    def commit(self) -> None:
        for conn in (self.atlas, *self.adb.values()):
            conn.commit()


def _build(w: World) -> None:
    """A: app.cgi alone (two candidates: cmd, copy); three that the other run holds something like
    (a file, a symlink, a binary of the same name elsewhere); two binaries named dup at two paths.
    B: qctl alone, called by a script A does not have; libqctl.so alone, which "qctl" must not
    match; tool1 / tool2 / tool3 alone, each called by a script whose state on A differs; app2.cgi
    alone, named by a web endpoint with a query."""
    w.binary("a", "web/app/app.cgi", _sha("3"))
    w.cand("a", "web/app/app.cgi", _sha("3"), "cmd")
    w.cand("a", "web/app/app.cgi", _sha("3"), "copy")
    for rel, sha in (("www/blind.cgi", "4"), ("bin/linked", "5"), ("sbin/samename", "6")):
        w.binary("a", rel, _sha(sha))
        w.cand("a", rel, _sha(sha))
    w.file("b", "www/blind.cgi", _sha("7"), "web_asset")
    w.symlink("b", "bin/linked")
    w.binary("b", "usr/sbin/samename", _sha("8"))
    for rel, sha in (("a/dup", "9"), ("b/dup", "a")):
        w.binary("a", rel, _sha(sha))
        w.cand("a", rel, _sha(sha))
    for rel, sha in (
        ("bin/qctl", "b"),
        ("lib/libqctl.so", "c"),
        ("usr/bin/tool1", "d"),
        ("usr/bin/tool2", "e"),
        ("usr/bin/tool3", "f"),
        ("www/cgi-bin/app2.cgi", "0"),
    ):
        w.binary("b", rel, _sha(sha))
        w.cand("b", rel, _sha(sha))
    info = w.file("b", "usr/sbin/info.sh", "51" * 32)
    w.call("b", info, "qctl", 360)
    same = w.file("b", "etc/init.sh", "52" * 32)
    w.call("b", same, "/usr/bin/tool1", 7)
    w.file("a", "etc/init.sh", "52" * 32)  # the same content on A
    rc = w.file("b", "etc/rc.sh", "53" * 32)
    w.call("b", rc, "tool2", 12)
    rc_a = w.file("a", "etc/rc.sh", "54" * 32)
    w.call("a", rc_a, "other_tool", 3)  # A records calls of this file, none of tool2
    other = w.file("b", "etc/other.sh", "55" * 32)
    w.call("b", other, "tool3", 4)
    w.file("a", "etc/other.sh", "56" * 32)  # A holds the file, records nothing of it
    page = w.file("b", "www/index.html", "57" * 32, "web_asset")
    w.endpoint("b", page, "/cgi-bin/app2.cgi?cur_time=")
    w.commit()


@pytest.fixture(autouse=True)
def _servable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mcp_app, "_installed_commit", lambda: UNKNOWN_VERSION)
    monkeypatch.setattr(
        pv,
        "diff_source_staleness",
        lambda atlas, diff_id: {
            "source_stale": False,
            "source_stale_reason": None,
            "toolchain_checked": True,
        },
    )
    pv._clear_view_caches()


@pytest.fixture
def world(tmp_path: Path) -> World:
    w = World(tmp_path)
    _build(w)
    return w


def _presence(w: World) -> bp.Presence:
    return bp.find_presence(w.atlas, "runA", "runB")


def _by_rel(p: bp.Presence) -> dict[tuple[str, str], bp.PresentBinary]:
    return {(b.tag, b.rel_path): b for b in p.items}


def _anchor(tag: str, rel: str) -> str:
    return dr.binary_presence_anchor("runA", "runB", tag, rel)


def _fresh_files(run_a: str, run_b: str) -> dict[str, Any]:
    return {"source_stale": False, "source_stale_reason": None}


# ── which binaries one run holds alone ─────────────────────────────────────────────────────────


def test_a_binary_is_one_sided_only_when_the_other_run_holds_nothing_like_it(world: World) -> None:
    """★ A binary no diff covers is binary_presence only when the other run holds no binary of its
    content, name or path, no non-binary file at its path and no symlink at its path — each one of
    those keeps it a blind spot, and the blind spots no longer name the ones moved out.

    MUTATION (verified RED, 1 failed each): skip the non-binary file check -> blind.cgi moves ->
    RED; skip the symlink check -> linked moves -> RED; match a counterpart binary by path only ->
    samename moves -> RED; compare the absolute paths across runs -> every binary moves -> RED."""
    p = _presence(world)
    assert set(_by_rel(p)) == {
        ("a_only", "web/app/app.cgi"),
        ("a_only", "a/dup"),
        ("a_only", "b/dup"),
        ("b_only", "bin/qctl"),
        ("b_only", "lib/libqctl.so"),
        ("b_only", "usr/bin/tool1"),
        ("b_only", "usr/bin/tool2"),
        ("b_only", "usr/bin/tool3"),
        ("b_only", "www/cgi-bin/app2.cgi"),
    }
    app = _by_rel(p)[("a_only", "web/app/app.cgi")]
    assert (app.name, app.sha256, app.candidates, app.by_class) == (
        "app.cgi",
        _sha("3"),
        2,
        {"cmd": 1, "copy": 1},
    )
    blind, _same = da.split_not_diffed(
        da.not_diffed_binaries(world.atlas, "runA", "runB", exclude=p.excluded)
    )
    assert blind == {
        "a": {
            "binary_not_diffed": {
                "binaries": 3,
                "candidates": 3,
                "names": ["blind.cgi", "linked", "samename"],
            }
        }
    }


def test_two_binaries_of_one_name_get_two_anchors(world: World) -> None:
    """Two binaries named alike at two paths are two subjects, each anchored by its own path."""
    p = _presence(world)
    anchors = {p.anchor(b) for b in p.items if b.name == "dup"}
    assert anchors == {_anchor("a_only", "a/dup"), _anchor("a_only", "b/dup")}


@pytest.mark.parametrize("broken", ["unreadable", "no_root", "no_table"])
def test_an_unread_other_run_keeps_every_binary_a_blind_spot(
    world: World, tmp_path: Path, broken: str
) -> None:
    """Nothing is proven absent from a run that was not read: its analysis.db unreadable, its
    firmware root unrecorded, or a table missing — every binary of the other side stays a blind
    spot, and so does every binary of that run itself (its path cannot be placed under its root,
    nor its references read).

    MUTATION (verified RED, 1 failed): read an unreadable run as holding nothing -> RED. (Without
    the missing-table check the read of that table fails and reads unreadable the same way: an
    equivalent mutation, kept as a guard.)"""
    if broken == "unreadable":
        world.atlas.execute(
            "UPDATE run SET analysis_db_path = ? WHERE run_id = 'runB'", ("/no.db",)
        )
    elif broken == "no_root":
        world.atlas.execute("UPDATE run SET firmware_path = NULL WHERE run_id = 'runB'")
    else:
        world.adb["b"].execute("DROP TABLE fs_symlinks")
    world.commit()
    assert _presence(world).items == []


def test_a_binary_whose_path_is_not_under_its_root_stays_a_blind_spot(world: World) -> None:
    """A binary recorded outside its own run's firmware root cannot be placed: blind spot."""
    world.atlas.execute("UPDATE run SET firmware_path = '/elsewhere/root' WHERE run_id = 'runA'")
    world.commit()
    assert not [b for b in _presence(world).items if b.tag == "a_only"]


# ── referenced_by ─────────────────────────────────────────────────────────────────────────────


def test_each_reference_carries_its_state_on_the_other_run(world: World) -> None:
    """★ The recorded references to a binary in its own run, each with its state on the other run:
    present (the same file there has the same content), not_recorded (the file is there and its
    records hold no such call), undetermined (the file is there and nothing of it is recorded),
    file_absent (no such file). A command with a path matches by its basename; a web endpoint by
    its path's last segment, query left off.

    MUTATION (verified RED, 1 failed each): match by substring -> libqctl.so is named by the
    qctl call -> RED; read a file with no records as not_recorded -> RED; keep the endpoint's query
    in its last segment -> app2.cgi has no reference -> RED."""
    by = _by_rel(_presence(world))
    assert by[("b_only", "bin/qctl")].referenced_by == [
        {
            "path": "usr/sbin/info.sh",
            "kind": "script_call",
            "line_number": 360,
            "other_side": "file_absent",
        }
    ]
    assert by[("b_only", "lib/libqctl.so")].referenced_by == []
    assert by[("b_only", "usr/bin/tool1")].referenced_by[0]["other_side"] == "present"
    assert by[("b_only", "usr/bin/tool2")].referenced_by[0]["other_side"] == "not_recorded"
    assert by[("b_only", "usr/bin/tool3")].referenced_by[0]["other_side"] == "undetermined"
    assert by[("b_only", "www/cgi-bin/app2.cgi")].referenced_by == [
        {"path": "www/index.html", "kind": "web_endpoint", "other_side": "file_absent"}
    ]


def test_a_reference_on_an_unread_other_run_is_only_undetermined() -> None:
    """With the other run unread, a reference's state there can only be undetermined.

    MUTATION (verified RED, 1 failed): read an unread run's missing file as file_absent -> RED."""
    own = bp._RunDb("/r", script_calls={"etc/x.sh": [("qctl", 1)]}, files={"etc/x.sh": "aa"})
    other = bp._RunDb("/s", error="analysis_db_unreadable")
    refs = bp._referenced_by(own, other, "qctl")
    assert [r["other_side"] for r in refs] == ["undetermined"]


def test_an_empty_reference_list_still_says_what_it_is(world: World) -> None:
    """No recorded reference: an empty list with its note, never a missing field."""
    block = bp.presence_block(_presence(world), {})
    (app,) = [b for b in block["a_only"] if b["name"] == "app.cgi"]
    assert app["referenced_by"] == [] and app["referenced_by_note"] == bp.REFERENCED_BY_NOTE
    assert app["anchor_ref"] == _anchor("a_only", "web/app/app.cgi")
    assert app["review_state"] == "none"
    assert block["basis"] == bp.BASIS


# ── coverage, progress, meta and the CLI ──────────────────────────────────────────────────────


def test_coverage_keeps_one_sided_binaries_apart_and_uncovered(world: World) -> None:
    """list_diffs' coverage lists them under binary_presence, out of not_diffed_binaries, and says
    no diff covers them (all_candidate_binaries_covered false).

    MUTATION (verified RED, 1 failed): leave presence out of ``all_candidate_binaries_covered`` ->
    RED."""
    cov = da.list_diffs(world.atlas, "runA", "runB")["coverage"]
    names = {b["name"] for side in ("a_only", "b_only") for b in cov["binary_presence"][side]}
    assert {"app.cgi", "qctl"} <= names
    assert "app.cgi" not in str(cov["not_diffed_binaries"])
    for name in ("blind.cgi", "linked", "samename"):  # no blind spot left: only presence
        world.adb["a"].execute("DELETE FROM binaries WHERE path LIKE ?", (f"%/{name}",))
        world.atlas.execute("DELETE FROM instance WHERE binary_path LIKE ?", (f"%/{name}",))
    world.commit()
    cov = da.list_diffs(world.atlas, "runA", "runB")["coverage"]
    assert (cov["failed_diffs"], cov["not_diffed_binaries"]) == ([], {})
    assert cov["all_candidate_binaries_covered"] is False


def _progress(w: World, **kw: Any) -> dict[str, Any]:
    return overlay.list_overlays(w.atlas, anchor_kind="diff_subject", run_id=PAIR, **kw)[
        "review_progress"
    ]


def _judge_all(w: World, tags: tuple[str, ...]) -> None:
    for b in _presence(w).items:
        if b.tag in tags:
            overlay.annotate_diff(
                w.atlas,
                anchor_ref=_presence(w).anchor(b),
                verdict="change_inconclusive",
                rationale="read its candidates; next: its callers",
                run_pair=PAIR,
            )


@pytest.mark.parametrize("side", ["a_only", "b_only"])
def test_an_unjudged_one_sided_binary_keeps_the_run_pair_incomplete(
    world: World, side: str
) -> None:
    """★ Each one-sided binary is in the denominator: unjudged, the run pair is not complete,
    whichever side holds it; judged, it no longer holds it back.

    MUTATION (verified RED, 2 failed): leave the binary_presence items out of the progress ->
    RED."""
    for name in ("blind.cgi", "linked", "samename"):  # the blind spots go: only presence is left
        world.adb["a"].execute("DELETE FROM binaries WHERE path LIKE ?", (f"%/{name}",))
        world.atlas.execute("DELETE FROM instance WHERE binary_path LIKE ?", (f"%/{name}",))
    world.commit()
    other = "b_only" if side == "a_only" else "a_only"
    _judge_all(world, (other,))
    progress = _progress(world)
    assert progress["blind_spots"]["not_diffed_binaries"] == {}
    assert progress["complete"] is False
    assert progress["by_bucket"]["binary_presence"]["none"] > 0
    _judge_all(world, (side,))
    assert _progress(world)["complete"] is True


def test_the_meta_counts_each_side(world: World) -> None:
    """get_diff_meta (and so start_diff_review's meta) counts each side's binaries, candidates and
    the unjudged ones."""
    meta = da.get_diff_meta(world.atlas, DIFF)
    counts = meta["binary_presence"]
    assert counts["a_only"] == {"binaries": 3, "candidates": 4, "not_looked_at": 3}
    assert counts["b_only"] == {"binaries": 6, "candidates": 6, "not_looked_at": 6}
    _judge_all(world, ("a_only",))
    assert da.get_diff_meta(world.atlas, DIFF)["binary_presence"]["a_only"]["not_looked_at"] == 0
    start = mcp_app.make_tools(world.path)["start_diff_review"](DIFF)
    assert start["meta"]["binary_presence"]["b_only"]["binaries"] == 6


def test_the_cli_prints_what_each_side_holds_alone(
    world: World, capsys: pytest.CaptureFixture[str]
) -> None:
    """The diff command's coverage lines say what each run holds alone.

    MUTATION (verified RED, 1 failed): drop the only-in lines -> RED."""
    hunt_cli._echo_coverage(da.list_diffs(world.atlas, "runA", "runB")["coverage"], "x")
    out = capsys.readouterr().out
    assert "only in A     : 3 binaries / 4 candidates, 3 not looked at — " in out
    assert "web/app/app.cgi" in out and "only in B     : 6 binaries / 6 candidates" in out


# ── judging one ───────────────────────────────────────────────────────────────────────────────


def test_a_judgement_is_written_on_the_run_pair_and_reads_back(world: World) -> None:
    """★ A binary_presence judgement goes on the run pair (lib and the MCP batch alike) and reads
    back on list_overlays against the pair — never as a gone diff or an unresolved anchor; with the
    runs read current it is concluded.

    MUTATION (verified RED, 1 failed each): read binary_presence rows through ``_diff_of`` ->
    source_diff_gone -> RED; drop the batch's presence branch -> the batch is refused -> RED."""
    app = _anchor("a_only", "web/app/app.cgi")
    res = overlay.annotate_diff(
        world.atlas,
        anchor_ref=app,
        verdict="changed_real",
        rationale="a cgi only the older build ships",
        run_pair=PAIR,
    )
    assert res.action == "inserted"
    batch = mcp_app.make_tools(world.path)["annotate_diff_batch"](
        annotations=[
            {
                "anchor_ref": _anchor("b_only", "bin/qctl"),
                "verdict": "change_inconclusive",
                "rationale": "read; next: its script",
            }
        ],
        run_pair=PAIR,
    )
    assert batch.get("written") is True, batch
    out = overlay.list_overlays(
        world.atlas, anchor_kind="diff_subject", run_id=PAIR, file_staleness=_fresh_files
    )
    rows = {r["anchor_ref"]: r for r in out["overlays"]}
    for anchor in (app, _anchor("b_only", "bin/qctl")):
        r = rows[anchor]
        assert r["basis_state"] == "unchanged", r
        assert r["source_stale_reason"] != "source_diff_gone"
        assert (r["diff_id"], r["run_pair"], r["subject_kind"]) == (None, PAIR, "binary_presence")
    assert rows[app]["review_state"] == "concluded"


def test_a_judgement_with_a_diff_id_is_refused(world: World) -> None:
    """No binary diff covers such a binary: naming one is refused, pointing at run_pair (lib, MCP,
    a batch item under diff_id, and promote's entry lookup alike).

    MUTATION (verified RED, 1 failed): drop the binary_presence refusal from the diff's anchor
    check (``_check_anchor``) -> promote refuses with another message -> RED."""
    app = _anchor("a_only", "web/app/app.cgi")
    with pytest.raises(ConfigError, match="pass run_pair"):
        overlay.annotate_diff(
            world.atlas, anchor_ref=app, verdict="changed_real", rationale="x", diff_id=DIFF
        )
    tools = mcp_app.make_tools(world.path)
    one = tools["annotate_diff"](
        anchor_ref=app, verdict="changed_real", rationale="x", diff_id=DIFF
    )
    assert one["written"] is False and "run_pair" in one["error"]
    batch = tools["annotate_diff_batch"](
        annotations=[{"anchor_ref": app, "verdict": "changed_real", "rationale": "x"}],
        diff_id=DIFF,
    )
    assert batch["written"] is False and "run_pair" in str(batch["errors"])
    # promote reads its entry through the diff's anchor check, which names run_pair too
    with pytest.raises(ConfigError, match="pass run_pair"):
        overlay.promote(
            world.atlas,
            diff_id=DIFF,
            entry_id=app,
            row_ref="runA#33333333:00000001@cmd@0x10",
            verdict="inconclusive",
            rationale="x",
        )


def test_a_moved_basis_or_a_stale_run_reads_needs_recheck(world: World) -> None:
    """The basis is the binary's facts: a candidate added moves it (needs_recheck); and with either
    run read stale the judgement reads stale.

    MUTATION (verified RED, 1 failed each): leave the candidates out of the basis -> unchanged ->
    RED; ignore the staleness reading -> concluded -> RED."""
    app = _anchor("a_only", "web/app/app.cgi")
    overlay.annotate_diff(
        world.atlas, anchor_ref=app, verdict="changed_real", rationale="x", run_pair=PAIR
    )

    def row(staleness: Any = _fresh_files) -> dict[str, Any]:
        out = overlay.list_overlays(
            world.atlas, anchor_kind="diff_subject", run_id=PAIR, file_staleness=staleness
        )
        return next(r for r in out["overlays"] if r["anchor_ref"] == app)

    assert row()["review_state"] == "concluded"
    stale = row(lambda a, b: {"source_stale": True, "source_stale_reason": "stale_scan:runA"})
    assert (stale["review_state"], stale["source_stale"]) == ("needs_recheck", True)
    world.cand("a", "web/app/app.cgi", _sha("3"), "format")
    world.commit()
    moved = row()
    assert moved["review_state"] == "needs_recheck"
    assert set(moved["basis_moved"]) == {"candidates", "candidates_by_sink_class"}


def test_checked_cites_its_own_anchor_or_its_own_candidates(world: World) -> None:
    """★ A no_real_change on such a binary cites its own anchor, or an evidence_ref of one of its
    candidates in its own run; another binary's candidate is refused by name.

    MUTATION (verified RED, 1 failed each): accept any evidence_ref of the run -> the other
    binary's candidate passes -> RED; refuse the binary's own candidate -> RED."""
    app = _anchor("a_only", "web/app/app.cgi")
    own = world.atlas.execute(
        "SELECT evidence_ref FROM instance WHERE binary_path LIKE '%/app.cgi' LIMIT 1"
    ).fetchone()[0]
    theirs = world.atlas.execute(
        "SELECT evidence_ref FROM instance WHERE binary_path LIKE '%/a/dup' LIMIT 1"
    ).fetchone()[0]
    for cited in ([app], [own]):
        try:
            overlay.annotate_diff(
                world.atlas,
                anchor_ref=app,
                verdict="no_real_change",
                rationale="x",
                verdict_basis={"why_unchanged": "a debug cgi", "checked": cited},
                run_pair=PAIR,
            )
        except ConfigError as exc:
            pytest.fail(f"{cited} was refused: {exc}")
    with pytest.raises(ConfigError, match="not a candidate of app.cgi"):
        overlay.annotate_diff(
            world.atlas,
            anchor_ref=app,
            verdict="no_real_change",
            rationale="x",
            verdict_basis={"why_unchanged": "x", "checked": [theirs]},
            run_pair=PAIR,
        )
    with pytest.raises(ConfigError, match="at least one item that resolves"):
        overlay.annotate_diff(
            world.atlas,
            anchor_ref=app,
            verdict="no_real_change",
            rationale="x",
            verdict_basis={"why_unchanged": "x", "checked": ["read it by hand"]},
            run_pair=PAIR,
        )
